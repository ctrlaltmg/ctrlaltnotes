// SPDX-License-Identifier: AGPL-3.0-only
//! Cryptographic primitives (vault format v1). Nothing is hand-rolled: every primitive comes
//! from the RustCrypto crates.
//!
//! password --NFKC--> Argon2id(salt, m, t, p) --> KEK (32 B)
//! KEK --ChaCha20-Poly1305--> wraps a random 256-bit vault master key (MK)
//! recovery key (256-bit random) --HKDF--> second KEK wrapping the same MK
//! Every object is its own file:
//!     subkey = HKDF-SHA256(MK, salt = per-file random 32 B, info = "ctrlaltnotes/v1/obj/" + type)
//!     file   = MAGIC | type | object-id | file_salt | nonce | AEAD(subkey, padded JSON)
//!     AAD    = MAGIC | type | object-id | file_salt   (binds the ciphertext to its id and type)
#![allow(deprecated)] // generic-array 0.14 `from_slice` deprecation notices (API pinned on purpose)

use crate::error::{cannot_unlock, corrupt, malformed, Result, VaultError};
use crate::json::canonical;
use argon2::{Algorithm, Argon2, Params, Version};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Nonce,
};
use hkdf::Hkdf;
use serde_json::Value;
use sha2::Sha256;
use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroizing;

pub const MAGIC: &[u8; 4] = b"CAN1";
pub const TYPE_NOTE: u8 = b'N';
pub const TYPE_FOLDER: u8 = b'F';
pub const TYPE_STATE: u8 = b'S';

/// Plaintext is padded to a multiple of this (length hiding).
pub const PAD_BLOCK: usize = 1024;
/// Hard cap on any object file we will read.
pub const MAX_FILE_BYTES: usize = 8 * 1024 * 1024;
pub const HEADER_LEN: usize = 4 + 1 + 16 + 32 + 12;
pub const AAD_LEN: usize = 4 + 1 + 16 + 32;
pub const TAG_LEN: usize = 16;

pub const MIN_PASSWORD_CHARS: usize = 12;
pub const MAX_PASSWORD_CHARS: usize = 1024;

/// Argon2id parameters. `m` is in KiB.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KdfParams {
    pub m: u32,
    pub t: u32,
    pub p: u32,
}

/// Default: 64 MiB, 3 passes, 4 lanes (stronger than the OWASP minimum).
pub const KDF_DEFAULT: KdfParams = KdfParams {
    m: 65536,
    t: 3,
    p: 4,
};
/// OWASP Password Storage Cheat Sheet minimum (also the enforced floor).
pub const KDF_MIN: KdfParams = KdfParams {
    m: 19456,
    t: 2,
    p: 1,
};
const M_BOUNDS: (i64, i64) = (19456, 1_048_576); // floor / DoS ceiling
const T_BOUNDS: (i64, i64) = (2, 20);
const P_BOUNDS: (i64, i64) = (1, 16);

/// KDF block as stored in `vault.json`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Kdf {
    pub alg: String,
    pub m: u32,
    pub t: u32,
    pub p: u32,
    pub salt: String,
}

impl Kdf {
    pub fn params(&self) -> Result<KdfParams> {
        validate_kdf(&self.alg, self.m as i64, self.t as i64, self.p as i64)
    }
}

// ---------- randomness / encoding ----------
pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    // Fail closed: without OS randomness we must never continue.
    getrandom::getrandom(&mut b).expect("operating-system randomness unavailable");
    b
}

pub fn b64e(b: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(b)
}

pub fn b64d(s: &str) -> Result<Vec<u8>> {
    if s.len() > (1 << 20) {
        return Err(malformed());
    }
    URL_SAFE_NO_PAD
        .decode(s.trim_end_matches('='))
        .map_err(|_| malformed())
}

pub fn is_hex32(s: &str) -> bool {
    s.len() == 32
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// `<32 lowercase hex>.can`
pub fn is_obj_name(n: &str) -> bool {
    n.len() == 36 && n.ends_with(".can") && n.get(..32).is_some_and(is_hex32)
}

// ---------- password / KDF ----------
pub fn normalize_password(pw: &str) -> Result<Zeroizing<Vec<u8>>> {
    // NIST SP 800-63B: normalise Unicode (NFKC) before use.
    let norm: Zeroizing<String> = Zeroizing::new(pw.nfkc().collect::<String>());
    let n = norm.chars().count();
    if !(MIN_PASSWORD_CHARS..=MAX_PASSWORD_CHARS).contains(&n) {
        return Err(VaultError::other(format!(
            "password must be {MIN_PASSWORD_CHARS}-{MAX_PASSWORD_CHARS} characters"
        )));
    }
    Ok(Zeroizing::new(norm.as_bytes().to_vec()))
}

/// Reject malformed, too-weak (downgrade) or absurdly large (DoS) KDF parameters.
pub fn validate_kdf(alg: &str, m: i64, t: i64, p: i64) -> Result<KdfParams> {
    if alg != "argon2id" {
        return Err(VaultError::other("unsupported KDF"));
    }
    let ok = |v: i64, b: (i64, i64)| v >= b.0 && v <= b.1;
    if !ok(m, M_BOUNDS) || !ok(t, T_BOUNDS) || !ok(p, P_BOUNDS) || m < 8 * p {
        return Err(VaultError::other("KDF parameters out of allowed range"));
    }
    Ok(KdfParams {
        m: m as u32,
        t: t as u32,
        p: p as u32,
    })
}

pub fn derive_kek(password: &str, salt: &[u8], kdf: &Kdf) -> Result<Zeroizing<[u8; 32]>> {
    let kp = kdf.params()?;
    if salt.len() < 16 {
        return Err(malformed());
    }
    let pw = normalize_password(password)?;
    let params = Params::new(kp.m, kp.t, kp.p, Some(32))
        .map_err(|_| VaultError::other("KDF parameters out of allowed range"))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = Zeroizing::new([0u8; 32]);
    argon
        .hash_password_into(&pw, salt, &mut out[..])
        .map_err(|_| VaultError::other("key derivation failed"))?;
    Ok(out)
}

pub fn hkdf(ikm: &[u8], salt: &[u8], info: &[u8]) -> Zeroizing<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut out = Zeroizing::new([0u8; 32]);
    hk.expand(info, &mut out[..])
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    out
}

// ---------- AEAD ----------
fn aead_encrypt(key: &[u8], nonce: &[u8; 12], msg: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| VaultError::other("internal key error"))?;
    cipher
        .encrypt(Nonce::from_slice(nonce), Payload { msg, aad })
        .map_err(|_| VaultError::other("encryption failed"))
}

fn aead_decrypt(key: &[u8], nonce: &[u8], ct: &[u8], aad: &[u8]) -> Option<Vec<u8>> {
    if nonce.len() != 12 {
        return None;
    }
    let cipher = ChaCha20Poly1305::new_from_slice(key).ok()?;
    cipher
        .decrypt(Nonce::from_slice(nonce), Payload { msg: ct, aad })
        .ok()
}

// ---------- key wrapping ----------
pub fn wrap_key(kek: &[u8], mk: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    let nonce = random_bytes::<12>();
    let ct = aead_encrypt(kek, &nonce, mk, aad)?;
    let mut out = nonce.to_vec();
    out.extend_from_slice(&ct);
    Ok(out)
}

pub fn unwrap_key(kek: &[u8], blob: &[u8], aad: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    if blob.len() != 12 + 32 + TAG_LEN {
        return Err(cannot_unlock());
    }
    let pt =
        Zeroizing::new(aead_decrypt(kek, &blob[..12], &blob[12..], aad).ok_or_else(cannot_unlock)?);
    if pt.len() != 32 {
        return Err(cannot_unlock());
    }
    let mut k = Zeroizing::new([0u8; 32]);
    k.copy_from_slice(&pt);
    Ok(k)
}

// ---------- object sealing ----------
fn pad(plain: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(plain.len() + 4 + PAD_BLOCK);
    v.extend_from_slice(&(plain.len() as u32).to_be_bytes());
    v.extend_from_slice(plain);
    let rem = v.len() % PAD_BLOCK;
    if rem != 0 {
        v.resize(v.len() + PAD_BLOCK - rem, 0);
    }
    v
}

fn unpad(padded: &[u8]) -> Result<&[u8]> {
    if padded.len() < 4 {
        return Err(corrupt());
    }
    let n = u32::from_be_bytes([padded[0], padded[1], padded[2], padded[3]]) as usize;
    if n > padded.len() - 4 {
        return Err(corrupt());
    }
    Ok(&padded[4..4 + n])
}

fn subkey(mk: &[u8], salt: &[u8], typ: u8) -> Zeroizing<[u8; 32]> {
    let mut info = b"ctrlaltnotes/v1/obj/".to_vec();
    info.push(typ);
    hkdf(mk, salt, &info)
}

fn valid_type(t: u8) -> bool {
    t == TYPE_NOTE || t == TYPE_FOLDER || t == TYPE_STATE
}

pub fn seal(mk: &[u8], typ: u8, id_hex: &str, obj: &Value) -> Result<Vec<u8>> {
    if !valid_type(typ) || !is_hex32(id_hex) {
        return Err(VaultError::other("bad object"));
    }
    let oid = hex::decode(id_hex).map_err(|_| VaultError::other("bad object"))?;
    let salt = random_bytes::<32>();
    let nonce = random_bytes::<12>();
    let mut aad = Vec::with_capacity(AAD_LEN);
    aad.extend_from_slice(MAGIC);
    aad.push(typ);
    aad.extend_from_slice(&oid);
    aad.extend_from_slice(&salt);
    let plaintext = Zeroizing::new(pad(&canonical(obj)));
    let key = subkey(mk, &salt, typ);
    let ct = aead_encrypt(&key[..], &nonce, &plaintext, &aad)?;
    let mut out = aad;
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    if out.len() > MAX_FILE_BYTES {
        return Err(VaultError::other("object too large"));
    }
    Ok(out)
}

/// Authenticate + decrypt. Returns (type, id_hex, object). Never panics on hostile input.
pub fn open_sealed(mk: &[u8], data: &[u8]) -> Result<(u8, String, Value)> {
    if data.len() < HEADER_LEN + TAG_LEN + 4 || data.len() > MAX_FILE_BYTES {
        return Err(corrupt());
    }
    if &data[..4] != MAGIC {
        return Err(corrupt());
    }
    let typ = data[4];
    let oid = &data[5..21];
    let salt = &data[21..53];
    let nonce = &data[53..65];
    let ct = &data[65..];
    if !valid_type(typ) {
        return Err(corrupt());
    }
    let key = subkey(mk, salt, typ);
    let padded =
        Zeroizing::new(aead_decrypt(&key[..], nonce, ct, &data[..AAD_LEN]).ok_or_else(corrupt)?);
    let body = unpad(&padded)?;
    let obj: Value = serde_json::from_slice(body).map_err(|_| corrupt())?;
    if !obj.is_object() {
        return Err(corrupt());
    }
    Ok((typ, hex::encode(oid), obj))
}
