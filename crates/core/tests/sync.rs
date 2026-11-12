// SPDX-License-Identifier: AGPL-3.0-only
mod common;
use common::*;
use ctrlaltnotes_core::{join_from_bundle, sync_bundle, sync_folder, Vault};
use tempfile::tempdir;

fn two_devices() -> (tempfile::TempDir, Vault, Vault, std::path::PathBuf) {
    let d = tempdir().unwrap();
    let cloud = d.path().join("cloud");
    let (mut a, _) = new_vault(&d.path().join("a"));
    sync_folder(&mut a, &cloud).unwrap();
    let mut b = Vault::join(&d.path().join("b"), &cloud, PW).unwrap();
    sync_folder(&mut b, &cloud).unwrap();
    (d, a, b, cloud)
}

#[test]
fn notes_propagate_between_devices() {
    let (_d, mut a, mut b, cloud) = two_devices();
    let n = a.create_note("from A", "hello", None).unwrap();
    let r = sync_folder(&mut a, &cloud).unwrap();
    assert_eq!(r.pushed.len(), 1);
    let r = sync_folder(&mut b, &cloud).unwrap();
    assert_eq!(r.pulled.len(), 1);
    assert_eq!(b.get_note(&n).unwrap().body, "hello");
    // edit on B comes back to A
    b.update_note(&n, Some("edited on B"), None).unwrap();
    sync_folder(&mut b, &cloud).unwrap();
    sync_folder(&mut a, &cloud).unwrap();
    assert_eq!(a.get_note(&n).unwrap().body, "edited on B");
}

#[test]
fn cloud_folder_only_holds_ciphertext() {
    let (_d, mut a, _b, cloud) = two_devices();
    a.create_note("TOPSECRETTITLE", "TOPSECRETBODY", None)
        .unwrap();
    sync_folder(&mut a, &cloud).unwrap();
    for e in std::fs::read_dir(cloud.join("objects")).unwrap() {
        let bytes = std::fs::read(e.unwrap().path()).unwrap();
        assert!(!String::from_utf8_lossy(&bytes).contains("TOPSECRET"));
    }
    let h = std::fs::read_to_string(cloud.join("vault.json")).unwrap();
    assert!(!h.contains("TOPSECRET"));
    assert!(
        !cloud.join("state.can").exists(),
        "device-local state must never be uploaded"
    );
}

#[test]
fn concurrent_edits_create_conflict_copy_not_data_loss() {
    let (_d, mut a, mut b, cloud) = two_devices();
    let n = a.create_note("doc", "base", None).unwrap();
    sync_folder(&mut a, &cloud).unwrap();
    sync_folder(&mut b, &cloud).unwrap();
    a.update_note(&n, Some("edit from A"), None).unwrap();
    b.update_note(&n, Some("edit from B"), None).unwrap();
    sync_folder(&mut a, &cloud).unwrap();
    let rb = sync_folder(&mut b, &cloud).unwrap();
    sync_folder(&mut a, &cloud).unwrap();
    assert_eq!(rb.conflicts.len(), 1);
    let bodies: Vec<String> = a
        .search("edit from")
        .unwrap()
        .iter()
        .map(|e| a.get_note(&e.id).unwrap().body)
        .collect();
    assert!(bodies.contains(&"edit from A".to_string()));
    assert!(bodies.contains(&"edit from B".to_string()));
}

#[test]
fn edit_beats_delete() {
    let (_d, mut a, mut b, cloud) = two_devices();
    let n = a.create_note("doc", "base", None).unwrap();
    sync_folder(&mut a, &cloud).unwrap();
    sync_folder(&mut b, &cloud).unwrap();
    a.delete(&n).unwrap();
    b.update_note(&n, Some("kept alive"), None).unwrap();
    sync_folder(&mut a, &cloud).unwrap();
    sync_folder(&mut b, &cloud).unwrap();
    sync_folder(&mut a, &cloud).unwrap();
    assert_eq!(a.get_note(&n).unwrap().body, "kept alive");
}

#[test]
fn deletes_propagate() {
    let (_d, mut a, mut b, cloud) = two_devices();
    let n = a.create_note("doc", "x", None).unwrap();
    sync_folder(&mut a, &cloud).unwrap();
    sync_folder(&mut b, &cloud).unwrap();
    a.delete(&n).unwrap();
    sync_folder(&mut a, &cloud).unwrap();
    sync_folder(&mut b, &cloud).unwrap();
    assert!(b.get_note(&n).is_err());
}

#[test]
fn tampered_remote_file_is_reported_and_never_trusted() {
    let (_d, mut a, mut b, cloud) = two_devices();
    a.create_note("doc", "good", None).unwrap();
    sync_folder(&mut a, &cloud).unwrap();
    let f = objects(&cloud.parent().unwrap().join("cloud"));
    let mut bytes = std::fs::read(&f[0]).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    std::fs::write(&f[0], &bytes).unwrap();
    let r = sync_folder(&mut b, &cloud).unwrap();
    assert_eq!(r.errors.len(), 1);
    assert!(b.list_tree().unwrap().notes.is_empty());
    assert_eq!(
        std::fs::read(&f[0]).unwrap(),
        bytes,
        "tampered remote file must not be overwritten"
    );
}

#[test]
fn foreign_vault_folder_is_refused() {
    let d = tempdir().unwrap();
    let cloud = d.path().join("cloud");
    let (mut a, _) = new_vault(&d.path().join("a"));
    let (mut other, _) = new_vault(&d.path().join("other"));
    sync_folder(&mut a, &cloud).unwrap();
    assert!(sync_folder(&mut other, &cloud).is_err());
}

#[test]
fn stray_cloud_copies_are_ignored() {
    let (_d, mut a, _b, cloud) = two_devices();
    a.create_note("doc", "x", None).unwrap();
    sync_folder(&mut a, &cloud).unwrap();
    let f = objects(&cloud);
    std::fs::copy(&f[0], cloud.join("objects").join("abc (1).can")).unwrap();
    let r = sync_folder(&mut a, &cloud).unwrap();
    assert_eq!(r.ignored.len(), 1);
}

#[test]
fn password_change_propagates_to_other_device() {
    let (d, mut a, b, cloud) = two_devices();
    let n = a.create_note("doc", "x", None).unwrap();
    a.change_password(PW, "brand new password 99", None)
        .unwrap();
    sync_folder(&mut a, &cloud).unwrap();
    drop(b);
    let mut b = Vault::unlock(&d.path().join("b"), Some(PW), None).unwrap();
    sync_folder(&mut b, &cloud).unwrap();
    b.lock();
    // the old password still opens B's local header until the new one is staged; the new password must work
    let b2 = Vault::unlock(&d.path().join("b"), Some("brand new password 99"), None);
    assert!(
        b2.is_ok(),
        "new password must unlock on device B after sync"
    );
    let mut b2 = b2.unwrap();
    sync_folder(&mut b2, &cloud).unwrap();
    assert_eq!(b2.get_note(&n).unwrap().body, "x");
}

#[test]
fn bundle_roundtrip_and_tamper_detection() {
    let d = tempdir().unwrap();
    let bundle = d.path().join("notes.canb");
    let (mut a, _) = new_vault(&d.path().join("a"));
    let n = a.create_note("doc", "bundle body", None).unwrap();
    sync_bundle(&mut a, &bundle).unwrap();
    let mut b = join_from_bundle(&d.path().join("b"), &bundle, PW).unwrap();
    assert_eq!(b.get_note(&n).unwrap().body, "bundle body");
    b.update_note(&n, Some("changed"), None).unwrap();
    sync_bundle(&mut b, &bundle).unwrap();
    sync_bundle(&mut a, &bundle).unwrap();
    assert_eq!(a.get_note(&n).unwrap().body, "changed");
    // any flipped byte breaks the bundle (checksum + AEAD)
    let raw = std::fs::read(&bundle).unwrap();
    for i in (0..raw.len()).step_by(37) {
        let mut x = raw.clone();
        x[i] ^= 0x40;
        std::fs::write(&bundle, &x).unwrap();
        let r = sync_bundle(&mut a, &bundle);
        if let Ok(rep) = r {
            assert!(rep.pulled.is_empty(), "flip at {i} accepted");
        }
        // local data must be unaffected either way
        assert_eq!(a.get_note(&n).unwrap().body, "changed");
    }
}

#[test]
fn bundle_hostile_inputs_do_not_panic() {
    let d = tempdir().unwrap();
    let (mut a, _) = new_vault(&d.path().join("a"));
    let bundle = d.path().join("x.canb");
    let mut rng = Rng(0x1234_5678_9abc_def1);
    for len in [0usize, 1, 4, 8, 64, 1000] {
        let junk: Vec<u8> = (0..len).map(|_| rng.next() as u8).collect();
        std::fs::write(&bundle, &junk).unwrap();
        assert!(sync_bundle(&mut a, &bundle).is_err());
        assert!(join_from_bundle(&d.path().join(format!("j{len}")), &bundle, PW).is_err());
    }
    // magic + absurd object count
    let mut v = b"CANB".to_vec();
    v.extend_from_slice(&u32::MAX.to_be_bytes());
    v.extend_from_slice(&[0u8; 64]);
    std::fs::write(&bundle, &v).unwrap();
    assert!(sync_bundle(&mut a, &bundle).is_err());
}

#[test]
fn random_operations_converge() {
    let (_d, mut a, mut b, cloud) = two_devices();
    let mut rng = Rng(0xdead_beef_cafe_f00d);
    let mut ids: Vec<String> = vec![];
    for step in 0..60 {
        let dev = if rng.below(2) == 0 { &mut a } else { &mut b };
        match rng.below(4) {
            0 => ids.push(
                dev.create_note(&format!("n{step}"), &format!("body {step}"), None)
                    .unwrap(),
            ),
            1 if !ids.is_empty() => {
                let i = ids[rng.below(ids.len())].clone();
                let _ = dev.update_note(&i, Some(&format!("e{step}")), None);
            }
            2 if !ids.is_empty() => {
                let i = ids[rng.below(ids.len())].clone();
                let _ = dev.delete(&i);
            }
            _ => {
                let _ = dev.create_folder(&format!("f{step}"), None);
            }
        }
        if rng.below(5) == 0 {
            sync_folder(&mut a, &cloud).unwrap();
            sync_folder(&mut b, &cloud).unwrap();
        }
    }
    for _ in 0..3 {
        sync_folder(&mut a, &cloud).unwrap();
        sync_folder(&mut b, &cloud).unwrap();
    }
    let norm = |v: &Vault| {
        let mut x: Vec<(String, String)> = v
            .objects()
            .values()
            .filter(|o| !o.deleted)
            .map(|o| {
                (
                    o.id.clone(),
                    format!("{:?}{:?}{:?}", o.title, o.name, o.body),
                )
            })
            .collect();
        x.sort();
        x
    };
    assert_eq!(norm(&a), norm(&b), "devices diverged");
}

// ------------------------------------------------------------ pentest regressions

/// F-01: a planted header with an absurd revision / KDF cost must never be staged.
#[test]
fn hostile_remote_header_is_never_staged() {
    let (d, mut a, _b, cloud) = two_devices();
    let raw = std::fs::read_to_string(cloud.join("vault.json")).unwrap();
    let good = raw.clone();
    let forged = raw
        .replace("\"header_rev\":1,", "\"header_rev\":999999,")
        .replace("\"m\":19456", "\"m\":1048576");
    assert_ne!(forged, raw, "test must actually forge something");
    std::fs::write(cloud.join("vault.json"), &forged).unwrap();
    let _ = sync_folder(&mut a, &cloud);
    assert!(
        !d.path().join("a").join("vault.json.pending").exists(),
        "implausible header was staged"
    );
    // unlock still works instantly and the remote header was repaired
    assert!(Vault::unlock(&d.path().join("a"), Some(PW), None).is_ok());
    assert_eq!(
        std::fs::read_to_string(cloud.join("vault.json")).unwrap(),
        good
    );
}

/// F-02: replaying an old object version must not resurrect a deleted note.
#[test]
fn replayed_old_version_does_not_resurrect_deleted_note() {
    let (_d, mut a, mut b, cloud) = two_devices();
    let n = a.create_note("doc", "v1", None).unwrap();
    sync_folder(&mut a, &cloud).unwrap();
    sync_folder(&mut b, &cloud).unwrap();
    let file = cloud.join("objects").join(format!("{n}.can"));
    let old = std::fs::read(&file).unwrap();
    a.update_note(&n, Some("v2"), None).unwrap();
    sync_folder(&mut a, &cloud).unwrap();
    sync_folder(&mut b, &cloud).unwrap();
    a.delete(&n).unwrap();
    sync_folder(&mut a, &cloud).unwrap();
    sync_folder(&mut b, &cloud).unwrap();
    assert!(b.get_note(&n).is_err());
    // attacker / buggy provider restores the oldest version
    std::fs::write(&file, &old).unwrap();
    sync_folder(&mut b, &cloud).unwrap();
    sync_folder(&mut a, &cloud).unwrap();
    for v in [&a, &b] {
        assert!(v.get_note(&n).is_err(), "deleted note came back");
        let t = v.list_tree().unwrap();
        assert!(t.notes.is_empty(), "replay created a ghost/conflict note");
    }
}

#[cfg(unix)]
#[test]
fn fifo_in_sync_folder_does_not_hang() {
    let (_d, mut a, _b, cloud) = two_devices();
    let fifo = cloud
        .join("objects")
        .join(format!("{}.can", "ab".repeat(16)));
    let ok = std::process::Command::new("mkfifo").arg(&fifo).status();
    if !ok.map(|s| s.success()).unwrap_or(false) {
        return; // no mkfifo available
    }
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = sync_folder(&mut a, &cloud);
        let _ = tx.send(());
    });
    assert!(
        rx.recv_timeout(std::time::Duration::from_secs(10)).is_ok(),
        "sync blocked on a FIFO"
    );
}

#[cfg(unix)]
#[test]
fn symlinked_remote_objects_dir_is_refused() {
    let (d, mut a, _b, cloud) = two_devices();
    let outside = d.path().join("outside");
    std::fs::create_dir_all(&outside).unwrap();
    std::fs::remove_dir_all(cloud.join("objects")).unwrap();
    std::os::unix::fs::symlink(&outside, cloud.join("objects")).unwrap();
    a.create_note("x", "y", None).unwrap();
    assert!(sync_folder(&mut a, &cloud).is_err());
    assert_eq!(
        std::fs::read_dir(&outside).unwrap().count(),
        0,
        "wrote through symlink"
    );
}
