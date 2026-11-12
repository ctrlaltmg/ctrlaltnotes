// SPDX-License-Identifier: AGPL-3.0-only
//! Known-answer tests: prove the primitives are the standard ones (RFC vectors).
use argon2::{Algorithm, Argon2, AssociatedData, ParamsBuilder, Version};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Nonce,
};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};

fn unhex(s: &str) -> Vec<u8> {
    hex::decode(s).unwrap()
}

#[test]
fn kat_sha256_abc() {
    assert_eq!(
        hex::encode(Sha256::digest(b"abc")),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}

#[test]
fn kat_hkdf_rfc5869_case1() {
    let ikm = [0x0bu8; 22];
    let salt: Vec<u8> = (0u8..13).collect();
    let info: Vec<u8> = (0xf0u8..0xfa).collect();
    let mut okm = [0u8; 42];
    Hkdf::<Sha256>::new(Some(&salt), &ikm)
        .expand(&info, &mut okm)
        .unwrap();
    assert_eq!(
        hex::encode(okm),
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
    );
    // our wrapper is exactly HKDF-SHA256 with a 32-byte output
    let ours = ctrlaltnotes_core::crypto::hkdf(&ikm, &salt, &info);
    assert_eq!(&ours[..], &okm[..32]);
}

#[test]
fn kat_chacha20poly1305_rfc8439_2_8_2() {
    let key: Vec<u8> = (0x80u8..0xa0).collect();
    let nonce = unhex("070000004041424344454647");
    let aad = unhex("50515253c0c1c2c3c4c5c6c7");
    let pt = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    let c = ChaCha20Poly1305::new_from_slice(&key).unwrap();
    #[allow(deprecated)]
    let ct = c
        .encrypt(Nonce::from_slice(&nonce), Payload { msg: pt, aad: &aad })
        .unwrap();
    assert_eq!(hex::encode(&ct[..16]), "d31a8d34648e60db7b86afbc53ef7ec2");
    assert_eq!(
        hex::encode(&ct[ct.len() - 16..]),
        "1ae10b594f09e26a7e902ecbd0600691"
    );
}

#[test]
fn kat_argon2id_rfc9106() {
    let ad = [4u8; 12];
    let params = ParamsBuilder::new()
        .m_cost(32)
        .t_cost(3)
        .p_cost(4)
        .output_len(32)
        .data(AssociatedData::new(&ad).unwrap())
        .build()
        .unwrap();
    let secret = [3u8; 8];
    let a = Argon2::new_with_secret(&secret, Algorithm::Argon2id, Version::V0x13, params).unwrap();
    let mut out = [0u8; 32];
    a.hash_password_into(&[1u8; 32], &[2u8; 16], &mut out)
        .unwrap();
    assert_eq!(
        hex::encode(out),
        "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659"
    );
}
