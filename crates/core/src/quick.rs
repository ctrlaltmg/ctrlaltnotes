// SPDX-License-Identifier: AGPL-3.0-only
//! Quick unlock slot: unlock with a hardware security key or a platform authenticator
//! (fingerprint / Face / Windows Hello) instead of typing the password.
//!
//! How it works (WebAuthn PRF / CTAP2 hmac-secret):
//!   * the authenticator derives a 32-byte secret that only it can produce (after user
//!     presence/verification) from a per-slot salt;
//!   * kek = HKDF-SHA256(secret, salt = vault id, info = "ctrlaltnotes/v1/quick");
//!   * the master key is wrapped under that kek (ChaCha20-Poly1305) and stored in
//!     `quick.json` in the LOCAL vault folder. That file is never synced; the secret is never stored.
//!
//! The password and recovery key keep working. Changing the password deletes the slot.
use crate::crypto::{self, b64d, b64e, hkdf, is_hex32};
use crate::error::{cannot_unlock, Result, VaultError};
use crate::fsutil::{read_capped, write_atomic};
use crate::json::{canonical, get_i64, get_str, vi, vs};
use crate::vault::{parse_header, Vault};
use serde_json::{Map, Value};
use std::fs;
use std::path::Path;

const FILE: &str = "quick.json";
const MAX_FILE: usize = 16 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QuickMeta {
    /// authenticator credential id (base64url, public)
    pub cred_id: String,
    /// PRF salt (base64url, 32 bytes, public)
    pub salt: String,
    /// WebAuthn relying-party id the credential belongs to
    pub rp_id: String,
    pub label: String,
}

fn bad() -> VaultError {
    VaultError::other("invalid input")
}

impl QuickMeta {
    pub fn validate(&self) -> Result<()> {
        let id = b64d(&self.cred_id).map_err(|_| bad())?;
        let salt = b64d(&self.salt).map_err(|_| bad())?;
        let rp_ok = !self.rp_id.is_empty()
            && self.rp_id.len() <= 253
            && self
                .rp_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-');
        if id.is_empty()
            || id.len() > 1024
            || salt.len() != 32
            || !rp_ok
            || self.label.chars().count() > 64
            || self.label.chars().any(|c| c.is_control())
        {
            return Err(bad());
        }
        Ok(())
    }

    fn aad(&self, vault_id: &str) -> Vec<u8> {
        let mut m = Map::new();
        m.insert("vault_id".to_string(), vs(vault_id));
        m.insert("cred_id".to_string(), vs(&self.cred_id));
        m.insert("salt".to_string(), vs(&self.salt));
        m.insert("rp_id".to_string(), vs(&self.rp_id));
        m.insert("label".to_string(), vs(&self.label));
        let mut out = canonical(&Value::Object(m));
        out.extend_from_slice(b"quick");
        out
    }
}

fn kek(secret: &[u8], vault_id: &str) -> Result<zeroize::Zeroizing<[u8; 32]>> {
    if secret.len() != 32 {
        return Err(bad());
    }
    let vid = hex::decode(vault_id).map_err(|_| bad())?;
    Ok(hkdf(secret, &vid, b"ctrlaltnotes/v1/quick"))
}

/// Delete the slot (no-op if none).
pub fn remove(root: &Path) -> Result<()> {
    match fs::remove_file(root.join(FILE)) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
    }
}

/// Public metadata of the enrolled slot, if any. Needs no secret (it is what the page needs in
/// order to ask the authenticator).
pub fn info(root: &Path) -> Result<Option<QuickMeta>> {
    let raw = match read_capped(&root.join(FILE), MAX_FILE) {
        Ok(r) => r,
        Err(_) => return Ok(None),
    };
    Ok(parse(&raw).ok().map(|(m, _, _)| m))
}

fn parse(raw: &[u8]) -> Result<(QuickMeta, String, Vec<u8>)> {
    let v: Value = serde_json::from_slice(raw).map_err(|_| bad())?;
    let m = v.as_object().ok_or_else(bad)?;
    if get_i64(m, "version") != Some(1) {
        return Err(bad());
    }
    let vault_id = get_str(m, "vault_id").ok_or_else(bad)?;
    if !is_hex32(vault_id) {
        return Err(bad());
    }
    let meta = QuickMeta {
        cred_id: get_str(m, "cred_id").ok_or_else(bad)?.to_string(),
        salt: get_str(m, "salt").ok_or_else(bad)?.to_string(),
        rp_id: get_str(m, "rp_id").ok_or_else(bad)?.to_string(),
        label: get_str(m, "label").ok_or_else(bad)?.to_string(),
    };
    meta.validate()?;
    let wrap = b64d(get_str(m, "wrap").ok_or_else(bad)?)?;
    Ok((meta, vault_id.to_string(), wrap))
}

impl Vault {
    /// Enrol a quick-unlock slot (vault must be unlocked; the caller must have re-verified the
    /// password). Replaces any existing slot.
    pub fn quick_enroll(&self, secret: &[u8], meta: &QuickMeta) -> Result<()> {
        let mk = self.key()?;
        meta.validate()?;
        let vault_id = self.header().vault_id.clone();
        let k = kek(secret, &vault_id)?;
        let wrap = crypto::wrap_key(&k[..], &mk[..], &meta.aad(&vault_id))?;
        let mut m = Map::new();
        m.insert("version".to_string(), vi(1));
        m.insert("vault_id".to_string(), vs(&vault_id));
        m.insert("cred_id".to_string(), vs(&meta.cred_id));
        m.insert("salt".to_string(), vs(&meta.salt));
        m.insert("rp_id".to_string(), vs(&meta.rp_id));
        m.insert("label".to_string(), vs(&meta.label));
        m.insert("wrap".to_string(), vs(&b64e(&wrap)));
        write_atomic(&self.root().join(FILE), &canonical(&Value::Object(m)))
    }

    pub fn quick_remove(&self) -> Result<()> {
        self.key()?;
        remove(self.root())
    }

    /// Unlock with the authenticator-derived secret. Errors are the same generic error as a
    /// wrong password.
    pub fn unlock_quick(path: &Path, secret: &[u8]) -> Result<Vault> {
        let header = parse_header(&read_capped(&path.join("vault.json"), 65536)?)?;
        let raw = read_capped(&path.join(FILE), MAX_FILE).map_err(|_| cannot_unlock())?;
        let (meta, vault_id, wrap) = parse(&raw).map_err(|_| cannot_unlock())?;
        if vault_id != header.vault_id {
            return Err(cannot_unlock());
        }
        let k = kek(secret, &vault_id).map_err(|_| cannot_unlock())?;
        let mk = crypto::unwrap_key(&k[..], &wrap, &meta.aad(&vault_id))?;
        Vault::open_with_key(path, mk, header)
    }
}
