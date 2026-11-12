// SPDX-License-Identifier: AGPL-3.0-only
mod common;
use common::*;
use ctrlaltnotes_core::crypto::{self, MAGIC};
use ctrlaltnotes_core::Vault;
use tempfile::tempdir;

fn one_note(dir: &std::path::Path) -> (Vault, String) {
    let (mut v, _) = new_vault(dir);
    let id = v.create_note("title", "secret body", None).unwrap();
    (v, id)
}

#[test]
fn every_single_byte_flip_in_an_object_is_detected() {
    let d = tempdir().unwrap();
    let p = d.path().join("v");
    let (mut v, _) = one_note(&p);
    let f = objects(&p).remove(0);
    let good = std::fs::read(&f).unwrap();
    for i in 0..good.len() {
        let mut bad = good.clone();
        bad[i] ^= 0x01;
        std::fs::write(&f, &bad).unwrap();
        let rejected = v.reload().unwrap();
        assert_eq!(rejected.len(), 1, "flip at byte {i} was accepted");
    }
    std::fs::write(&f, &good).unwrap();
    assert!(v.reload().unwrap().is_empty());
}

#[test]
fn truncation_and_extension_are_detected() {
    let d = tempdir().unwrap();
    let p = d.path().join("v");
    let (mut v, _) = one_note(&p);
    let f = objects(&p).remove(0);
    let good = std::fs::read(&f).unwrap();
    for cut in [0, 1, 4, 20, 53, 64, 65, 80, good.len() - 1] {
        std::fs::write(&f, &good[..cut]).unwrap();
        assert_eq!(v.reload().unwrap().len(), 1, "truncation to {cut}");
    }
    let mut longer = good.clone();
    longer.push(0);
    std::fs::write(&f, &longer).unwrap();
    assert_eq!(v.reload().unwrap().len(), 1);
}

#[test]
fn swapping_object_files_is_detected() {
    let d = tempdir().unwrap();
    let p = d.path().join("v");
    let (mut v, _) = new_vault(&p);
    v.create_note("a", "AAAA", None).unwrap();
    v.create_note("b", "BBBB", None).unwrap();
    let fs = objects(&p);
    let (x, y) = (
        std::fs::read(&fs[0]).unwrap(),
        std::fs::read(&fs[1]).unwrap(),
    );
    std::fs::write(&fs[0], &y).unwrap();
    std::fs::write(&fs[1], &x).unwrap();
    assert_eq!(
        v.reload().unwrap().len(),
        2,
        "id inside AAD must not match renamed file"
    );
}

#[test]
fn object_from_another_vault_is_rejected() {
    let d = tempdir().unwrap();
    let (_a, _) = one_note(&d.path().join("a"));
    let (mut b, _) = new_vault(&d.path().join("b"));
    let src = objects(&d.path().join("a")).remove(0);
    std::fs::copy(
        &src,
        d.path().join("b/objects").join(src.file_name().unwrap()),
    )
    .unwrap();
    assert_eq!(b.reload().unwrap().len(), 1);
}

#[test]
fn header_tampering_is_detected() {
    let d = tempdir().unwrap();
    let p = d.path().join("v");
    new_vault(&p);
    let good = std::fs::read_to_string(p.join("vault.json")).unwrap();
    // downgrade KDF cost, change rev, change vault id, swap wrap: all must fail to unlock
    for (from, to) in [
        ("\"t\":2", "\"t\":3"),
        ("\"m\":19456", "\"m\":19457"),
        ("\"header_rev\":1", "\"header_rev\":2"),
        ("\"version\":1", "\"version\":2"),
    ] {
        assert!(good.contains(from), "{from}");
        std::fs::write(p.join("vault.json"), good.replacen(from, to, 1)).unwrap();
        assert!(Vault::unlock(&p, Some(PW), None).is_err(), "tamper {from}");
    }
    std::fs::write(p.join("vault.json"), &good).unwrap();
    assert!(Vault::unlock(&p, Some(PW), None).is_ok());
}

#[test]
fn kdf_bounds_enforced() {
    assert!(crypto::validate_kdf("argon2id", 19456, 2, 1).is_ok());
    assert!(
        crypto::validate_kdf("argon2id", 19455, 2, 1).is_err(),
        "m floor"
    );
    assert!(
        crypto::validate_kdf("argon2id", 19456, 1, 1).is_err(),
        "t floor"
    );
    assert!(
        crypto::validate_kdf("argon2id", 19456, 2, 0).is_err(),
        "p floor"
    );
    assert!(
        crypto::validate_kdf("argon2id", 1_048_577, 2, 1).is_err(),
        "m ceiling (DoS)"
    );
    assert!(
        crypto::validate_kdf("argon2id", 19456, 21, 1).is_err(),
        "t ceiling"
    );
    assert!(
        crypto::validate_kdf("argon2id", 19456, 2, 17).is_err(),
        "p ceiling"
    );
    assert!(
        crypto::validate_kdf("argon2i", 19456, 2, 1).is_err(),
        "only argon2id"
    );
    assert!(crypto::validate_kdf("argon2id", -1, 2, 1).is_err());
}

#[test]
fn every_write_uses_fresh_salt_and_nonce() {
    let d = tempdir().unwrap();
    let p = d.path().join("v");
    let (mut v, id) = one_note(&p);
    let f = p.join("objects").join(format!("{id}.can"));
    let mut seen = std::collections::HashSet::new();
    for i in 0..20 {
        v.update_note(&id, Some(&format!("same {}", i % 2)), None)
            .unwrap();
        let b = std::fs::read(&f).unwrap();
        assert_eq!(&b[..4], MAGIC);
        assert!(seen.insert(b[21..65].to_vec()), "salt+nonce reused");
    }
}

#[test]
fn ciphertext_length_hides_small_differences() {
    let d = tempdir().unwrap();
    let p = d.path().join("v");
    let (mut v, id) = one_note(&p);
    let f = p.join("objects").join(format!("{id}.can"));
    v.update_note(&id, Some("a"), None).unwrap();
    let l1 = std::fs::metadata(&f).unwrap().len();
    v.update_note(&id, Some(&"b".repeat(300)), None).unwrap();
    let l2 = std::fs::metadata(&f).unwrap().len();
    assert_eq!(l1, l2, "padding to 1 KiB blocks");
}

#[test]
fn files_contain_no_plaintext_or_titles() {
    let d = tempdir().unwrap();
    let p = d.path().join("v");
    let (mut v, _) = new_vault(&p);
    v.create_folder("FOLDERSECRET", None).unwrap();
    v.create_note("TITLESECRET", "BODYSECRET", None).unwrap();
    v.lock();
    let mut all = vec![];
    fn walk(d: &std::path::Path, a: &mut Vec<Vec<u8>>) {
        for e in std::fs::read_dir(d).unwrap() {
            let e = e.unwrap().path();
            if e.is_dir() {
                walk(&e, a)
            } else {
                a.push(std::fs::read(e).unwrap())
            }
        }
    }
    walk(&p, &mut all);
    for b in all {
        let s = String::from_utf8_lossy(&b);
        assert!(!s.contains("SECRET"));
    }
}

#[test]
fn oversize_object_file_is_rejected_without_reading_it_all() {
    let d = tempdir().unwrap();
    let p = d.path().join("v");
    let (mut v, _) = new_vault(&p);
    let big = p.join("objects").join(format!("{}.can", "a".repeat(32)));
    std::fs::write(&big, vec![0u8; crypto::MAX_FILE_BYTES + 10]).unwrap();
    assert_eq!(v.reload().unwrap().len(), 1);
}

#[test]
fn hostile_random_files_never_panic() {
    let d = tempdir().unwrap();
    let p = d.path().join("v");
    let (mut v, _) = new_vault(&p);
    let mut rng = Rng(0x0123_4567_89ab_cdef);
    for i in 0..200 {
        let len = rng.below(300);
        let mut b: Vec<u8> = (0..len).map(|_| rng.next() as u8).collect();
        if i % 2 == 0 && b.len() > 4 {
            b[..4].copy_from_slice(MAGIC);
        }
        std::fs::write(p.join("objects").join(format!("{:032x}.can", i)), &b).unwrap();
    }
    assert_eq!(v.reload().unwrap().len(), 200);
}

#[test]
fn non_object_names_are_ignored_not_parsed() {
    let d = tempdir().unwrap();
    let p = d.path().join("v");
    let (mut v, _) = new_vault(&p);
    std::fs::write(p.join("objects/notes.txt"), b"x").unwrap();
    std::fs::write(
        p.join("objects/../objects/UPPER0000000000000000000000000000.can"),
        b"x",
    )
    .unwrap();
    assert!(v.reload().unwrap().is_empty());
}

#[test]
fn lock_wipes_decrypted_content() {
    let d = tempdir().unwrap();
    let (mut v, id) = one_note(&d.path().join("v"));
    v.lock();
    assert!(v.objects().is_empty());
    assert!(v.get_note(&id).is_err());
}

#[test]
fn no_temp_files_left_behind() {
    let d = tempdir().unwrap();
    let p = d.path().join("v");
    let (mut v, _) = new_vault(&p);
    for i in 0..10 {
        v.create_note(&format!("n{i}"), "x", None).unwrap();
    }
    for dir in [p.clone(), p.join("objects")] {
        for e in std::fs::read_dir(dir).unwrap() {
            let n = e.unwrap().file_name().to_string_lossy().into_owned();
            assert!(!n.contains(".tmp"), "leftover temp file {n}");
        }
    }
}

#[cfg(unix)]
#[test]
fn files_are_private_on_unix() {
    use std::os::unix::fs::PermissionsExt;
    let d = tempdir().unwrap();
    let p = d.path().join("v");
    let (_v, id) = one_note(&p);
    let mode = |q: &std::path::Path| std::fs::metadata(q).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&p), 0o700);
    assert_eq!(mode(&p.join("objects").join(format!("{id}.can"))), 0o600);
    assert_eq!(mode(&p.join("vault.json")), 0o600);
}

/// Static guard: forbid weak / home-grown primitives and unsafe code in the shipped sources.
#[test]
fn source_has_no_weak_primitives_or_unsafe() {
    let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    for e in std::fs::read_dir(src).unwrap() {
        let path = e.unwrap().path();
        let text = std::fs::read_to_string(&path).unwrap().to_lowercase();
        // built from pieces so this test file does not trip itself
        for bad in [
            ["md", "5"].concat(),
            ["sha", "1("].concat(),
            ["ra", "nd::"].concat(),
            ["ecb", ""].concat(),
            ["unsafe", " {"].concat(),
            ["unwrap", "()"].concat() + "//prod",
        ] {
            assert!(!text.contains(&bad), "{path:?} contains {bad}");
        }
    }
}

// ------------------------------------------------------------------ quick unlock
#[test]
fn quick_unlock_roundtrip_and_failure_modes() {
    use ctrlaltnotes_core::quick::QuickMeta;
    let d = tempdir().unwrap();
    let p = d.path().join("v");
    let (v, id) = one_note(&p);
    let meta = QuickMeta {
        cred_id: crypto::b64e(&[7u8; 40]),
        salt: crypto::b64e(&[9u8; 32]),
        rp_id: "localhost".into(),
        label: "YubiKey".into(),
    };
    let secret = [0x42u8; 32];
    v.quick_enroll(&secret, &meta).unwrap();
    assert_eq!(ctrlaltnotes_core::quick::info(&p).unwrap().unwrap(), meta);
    let u = Vault::unlock_quick(&p, &secret).unwrap();
    assert_eq!(u.get_note(&id).unwrap().body, "secret body");
    // wrong secret, wrong length, no slot
    assert!(Vault::unlock_quick(&p, &[0x43u8; 32])
        .err()
        .unwrap()
        .is_auth());
    assert!(Vault::unlock_quick(&p, &[0x42u8; 31]).is_err());
    drop(u);
    // tampering with public metadata (AAD-bound) breaks it
    let f = p.join("quick.json");
    let good = std::fs::read_to_string(&f).unwrap();
    std::fs::write(&f, good.replace("YubiKey", "Evil")).unwrap();
    assert!(Vault::unlock_quick(&p, &secret).is_err());
    std::fs::write(&f, &good).unwrap();
    assert!(Vault::unlock_quick(&p, &secret).is_ok());
    // a slot copied to another vault is useless
    let (_o, _) = new_vault(&d.path().join("other"));
    std::fs::copy(&f, d.path().join("other/quick.json")).unwrap();
    assert!(Vault::unlock_quick(&d.path().join("other"), &secret).is_err());
    // password change deletes the slot
    let mut v2 = Vault::unlock(&p, Some(PW), None).unwrap();
    v2.change_password(PW, "a brand new password 123", None)
        .unwrap();
    assert!(ctrlaltnotes_core::quick::info(&p).unwrap().is_none());
    assert!(Vault::unlock_quick(&p, &secret).is_err());
}

#[test]
fn quick_meta_is_validated() {
    use ctrlaltnotes_core::quick::QuickMeta;
    let d = tempdir().unwrap();
    let (v, _) = one_note(&d.path().join("v"));
    let good = QuickMeta {
        cred_id: crypto::b64e(&[1u8; 16]),
        salt: crypto::b64e(&[2u8; 32]),
        rp_id: "localhost".into(),
        label: "k".into(),
    };
    assert!(v.quick_enroll(&[1u8; 32], &good).is_ok());
    for bad in [
        QuickMeta {
            salt: crypto::b64e(&[2u8; 31]),
            ..good.clone()
        },
        QuickMeta {
            cred_id: String::new(),
            ..good.clone()
        },
        QuickMeta {
            rp_id: "evil.com/x".into(),
            ..good.clone()
        },
        QuickMeta {
            label: "a\nb".into(),
            ..good.clone()
        },
        QuickMeta {
            label: "x".repeat(65),
            ..good.clone()
        },
    ] {
        assert!(v.quick_enroll(&[1u8; 32], &bad).is_err());
    }
    assert!(
        v.quick_enroll(&[1u8; 16], &good).is_err(),
        "secret must be 32 bytes"
    );
}

// ------------------------------------------------------------------ password policy
#[test]
fn password_policy_follows_nist_800_63b() {
    use ctrlaltnotes_core::policy::check_new_password as chk;
    // accepted: long passphrases, spaces, unicode, no composition rules needed
    for ok in [
        "Tangerine Lantern Walrus Quartz 92",
        "mdhzwqpelktjnvbrxy",
        "contraseña muy larga y rara",
        "日本語のパスフレーズです長い文章",
        "purple-giraffe-teapot-nine",
        "Quartz lantern 7 harbor plum",
    ] {
        assert!(chk(ok).is_ok(), "{ok}");
    }
    // rejected: too short (even if "complex"), famous / common, trivial patterns
    for bad in [
        "Aa1!Aa1!Aa1!",
        "short",
        "correct horse battery staple",
        "passwordpassword",
        "password1234567890",
        "qwertyuiopasdfghjkl",
        "aaaaaaaaaaaaaaaa",
        "abababababababab",
        "abcdefghijklmnop",
        "123456789012345",
        "ctrlaltnotes12345",
        "1234567890123456",
        // pentest F-14: weak-but-long shapes
        "Summer2024Summer",
        "Passw0rd!Passw0rd!",
        "1357924680135792",
        "zaq12wsxcde34rfv",
        "P@ssw0rd2024!!!!",
        "Welcome2024!!!!!",
        "Winter2025Winter2025",
        "1qaz2wsx3edc4rfv",
    ] {
        assert!(chk(bad).is_err(), "{bad}");
    }
    assert!(chk(&"x".repeat(1025)).is_err());
}
