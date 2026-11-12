// SPDX-License-Identifier: AGPL-3.0-only
mod common;
use common::*;
use ctrlaltnotes_core::{Vault, VaultError};
use tempfile::tempdir;

#[test]
fn create_unlock_roundtrip() {
    let d = tempdir().unwrap();
    let p = d.path().join("v");
    let (mut v, rec) = new_vault(&p);
    let f = v.create_folder("Work", None).unwrap();
    let sub = v.create_folder("Projects", Some(&f)).unwrap();
    let n = v
        .create_note("Plan", "# Hello 🔐\nbody", Some(&sub))
        .unwrap();
    v.lock();
    assert!(!v.is_unlocked());
    assert!(rec.len() > 40);
    let v2 = Vault::unlock(&p, Some(PW), None).unwrap();
    let note = v2.get_note(&n).unwrap();
    assert_eq!(note.title, "Plan");
    assert_eq!(note.body, "# Hello 🔐\nbody");
    assert_eq!(note.parent.as_deref(), Some(sub.as_str()));
    let t = v2.list_tree().unwrap();
    assert_eq!(t.folders[0].name, "Work");
    assert_eq!(t.folders[0].folders[0].notes[0].title, "Plan");
}

#[test]
fn wrong_password_is_generic_auth_error() {
    let d = tempdir().unwrap();
    let p = d.path().join("v");
    new_vault(&p);
    let e = Vault::unlock(&p, Some("wrong password entirely"), None)
        .err()
        .unwrap();
    assert!(e.is_auth());
    assert_eq!(e.to_string(), "could not unlock");
}

#[test]
fn recovery_key_unlocks_and_bad_one_fails() {
    let d = tempdir().unwrap();
    let p = d.path().join("v");
    let (_v, rec) = new_vault(&p);
    assert!(Vault::unlock(&p, None, Some(&rec)).is_ok());
    assert!(Vault::unlock(
        &p,
        None,
        Some(&rec.replace(|c: char| c.is_ascii_alphabetic(), "A"))
    )
    .is_err());
    assert!(Vault::unlock(&p, None, None).is_err());
}

#[test]
fn password_policy() {
    let d = tempdir().unwrap();
    assert!(Vault::create(&d.path().join("a"), "short", Some(FAST)).is_err());
    assert!(!d.path().join("a").join("vault.json").exists());
    let long = "x".repeat(1025);
    assert!(Vault::create(&d.path().join("b"), &long, Some(FAST)).is_err());
}

#[test]
fn cannot_create_twice() {
    let d = tempdir().unwrap();
    let p = d.path().join("v");
    new_vault(&p);
    assert!(Vault::create(&p, PW, Some(FAST)).is_err());
}

#[test]
fn locked_vault_refuses_everything() {
    let d = tempdir().unwrap();
    let (mut v, _) = new_vault(&d.path().join("v"));
    let n = v.create_note("a", "b", None).unwrap();
    v.lock();
    assert!(v.create_note("x", "y", None).is_err());
    assert!(v.create_folder("x", None).is_err());
    assert!(v.get_note(&n).is_err());
    assert!(v.update_note(&n, Some("z"), None).is_err());
    assert!(v.list_tree().is_err());
    assert!(v.search("a").is_err());
    assert!(v.delete(&n).is_err());
    assert!(v.objects().is_empty());
}

#[test]
fn update_move_rename_delete_search() {
    let d = tempdir().unwrap();
    let (mut v, _) = new_vault(&d.path().join("v"));
    let f1 = v.create_folder("A", None).unwrap();
    let f2 = v.create_folder("B", None).unwrap();
    let n = v
        .create_note("Groceries", "milk and eggs", Some(&f1))
        .unwrap();
    v.update_note(&n, Some("milk, eggs, tea"), Some("Shopping"))
        .unwrap();
    assert_eq!(v.get_note(&n).unwrap().title, "Shopping");
    assert_eq!(v.search("TEA").unwrap().len(), 1);
    assert_eq!(v.search("shopping").unwrap().len(), 1);
    assert!(v.search("zzz").unwrap().is_empty());
    v.move_item(&n, Some(&f2)).unwrap();
    assert_eq!(v.get_note(&n).unwrap().parent.as_deref(), Some(f2.as_str()));
    v.rename_folder(&f2, "Renamed").unwrap();
    v.delete(&f2).unwrap(); // cascades to the note
    assert!(v.get_note(&n).is_err());
    assert!(v.search("tea").unwrap().is_empty());
}

#[test]
fn folder_cycles_are_rejected() {
    let d = tempdir().unwrap();
    let (mut v, _) = new_vault(&d.path().join("v"));
    let a = v.create_folder("A", None).unwrap();
    let b = v.create_folder("B", Some(&a)).unwrap();
    let c = v.create_folder("C", Some(&b)).unwrap();
    assert!(v.move_item(&a, Some(&c)).is_err());
    assert!(v.move_item(&a, Some(&a)).is_err());
}

#[test]
fn input_validation() {
    let d = tempdir().unwrap();
    let (mut v, _) = new_vault(&d.path().join("v"));
    assert!(v.create_note("t", "b", Some("not-an-id")).is_err());
    assert!(v.create_note("t", "b", Some(&"0".repeat(32))).is_err());
    assert!(v.create_folder("", None).is_err() || v.create_folder("  ", None).is_ok());
    assert!(v.create_note(&"t".repeat(201), "b", None).is_err());
    assert!(v.get_note("../../etc/passwd").is_err());
}

#[test]
fn change_password_rewraps_without_reencrypting() {
    let d = tempdir().unwrap();
    let p = d.path().join("v");
    let (mut v, old_rec) = new_vault(&p);
    let n = v.create_note("t", "secret", None).unwrap();
    let before: Vec<Vec<u8>> = objects(&p)
        .iter()
        .map(|f| std::fs::read(f).unwrap())
        .collect();
    assert!(v
        .change_password("wrong wrong wrong", "new password 1234", None)
        .is_err());
    v.change_password(PW, "new password 1234", None).unwrap();
    let new_rec = v.new_recovery_key().unwrap().to_string();
    assert_ne!(new_rec, old_rec);
    let after: Vec<Vec<u8>> = objects(&p)
        .iter()
        .map(|f| std::fs::read(f).unwrap())
        .collect();
    assert_eq!(
        before, after,
        "objects must not be touched (O(1) password change)"
    );
    v.lock();
    assert!(Vault::unlock(&p, Some(PW), None).is_err());
    assert!(
        Vault::unlock(&p, None, Some(&old_rec)).is_err(),
        "old recovery key must die"
    );
    let v2 = Vault::unlock(&p, Some("new password 1234"), None).unwrap();
    assert_eq!(v2.get_note(&n).unwrap().body, "secret");
    assert!(Vault::unlock(&p, None, Some(&new_rec)).is_ok());
}

#[test]
fn nfkc_password_normalisation() {
    let d = tempdir().unwrap();
    let p = d.path().join("v");
    // "é" precomposed vs "e"+combining accent must be the same password
    let composed = "caf\u{e9}-caf\u{e9}-caf\u{e9}";
    let decomposed = "cafe\u{301}-cafe\u{301}-cafe\u{301}";
    Vault::create(&p, composed, Some(FAST)).unwrap();
    assert!(Vault::unlock(&p, Some(decomposed), None).is_ok());
}

#[test]
fn export_markdown_sanitises_names() {
    let d = tempdir().unwrap();
    let (mut v, _) = new_vault(&d.path().join("v"));
    let f = v.create_folder("../evil", None).unwrap();
    v.create_note("CON", "x", Some(&f)).unwrap();
    v.create_note("a/b\\c:d*e?", "y", None).unwrap();
    v.create_note("same", "1", None).unwrap();
    v.create_note("same", "2", None).unwrap();
    let out = d.path().join("out");
    assert_eq!(v.export_markdown(&out).unwrap(), 4);
    fn walk(p: &std::path::Path, acc: &mut Vec<std::path::PathBuf>) {
        for e in std::fs::read_dir(p).unwrap() {
            let e = e.unwrap().path();
            if e.is_dir() {
                walk(&e, acc)
            } else {
                acc.push(e)
            }
        }
    }
    let mut files = vec![];
    walk(&out, &mut files);
    assert_eq!(files.len(), 4);
    for f in &files {
        assert!(f.starts_with(&out), "escaped export dir: {f:?}");
        let name = f.file_name().unwrap().to_string_lossy().to_uppercase();
        assert!(!name.starts_with("CON."), "windows reserved name");
    }
    assert!(!d.path().join("evil").exists());
}

#[test]
fn error_type_is_cloneable_and_generic() {
    let e = VaultError::Auth("could not unlock");
    assert_eq!(e.clone(), e);
}

#[test]
fn selective_export_includes_only_chosen_items() {
    use std::collections::HashSet;
    let d = tempdir().unwrap();
    let (mut v, _) = new_vault(&d.path().join("v"));
    let work = v.create_folder("Work", None).unwrap();
    let proj = v.create_folder("Projects", Some(&work)).unwrap();
    let a = v.create_note("A", "aaa", Some(&proj)).unwrap();
    let _b = v.create_note("B", "bbb", Some(&work)).unwrap();
    let home = v.create_folder("Home", None).unwrap();
    let _c = v.create_note("C", "ccc", Some(&home)).unwrap();
    let _d = v.create_note("D", "ddd", None).unwrap();
    let files = |dir: &std::path::Path| {
        let mut out = vec![];
        fn walk(p: &std::path::Path, base: &std::path::Path, o: &mut Vec<String>) {
            for e in std::fs::read_dir(p).unwrap() {
                let e = e.unwrap().path();
                if e.is_dir() {
                    walk(&e, base, o)
                } else {
                    o.push(
                        e.strip_prefix(base)
                            .unwrap()
                            .to_string_lossy()
                            .replace('\\', "/"),
                    )
                }
            }
        }
        walk(dir, dir, &mut out);
        out.sort();
        out
    };
    // one note deep in the tree: ancestors are created, nothing else is exported
    let o1 = d.path().join("o1");
    let sel: HashSet<String> = [a.clone()].into_iter().collect();
    assert_eq!(v.export_selected(&o1, Some(&sel)).unwrap(), 1);
    assert_eq!(files(&o1), vec!["Work/Projects/A.md"]);
    // a folder brings everything inside it
    let o2 = d.path().join("o2");
    let sel: HashSet<String> = [work.clone()].into_iter().collect();
    assert_eq!(v.export_selected(&o2, Some(&sel)).unwrap(), 2);
    assert_eq!(files(&o2), vec!["Work/B.md", "Work/Projects/A.md"]);
    // root-level note + other folder
    let o3 = d.path().join("o3");
    let sel: HashSet<String> = [home.clone(), _d.clone()].into_iter().collect();
    assert_eq!(v.export_selected(&o3, Some(&sel)).unwrap(), 2);
    assert_eq!(files(&o3), vec!["D.md", "Home/C.md"]);
    // empty selection and unknown ids export nothing / are refused
    assert!(v
        .export_selected(&d.path().join("o4"), Some(&HashSet::new()))
        .is_err());
    let unknown: HashSet<String> = ["0".repeat(32)].into_iter().collect();
    assert_eq!(
        v.export_selected(&d.path().join("o5"), Some(&unknown))
            .unwrap(),
        0
    );
    // everything
    assert_eq!(v.export_selected(&d.path().join("o6"), None).unwrap(), 4);
}

// ------------------------------------------------------------ pentest regressions
#[test]
fn folder_cycles_from_concurrent_moves_never_hide_content() {
    // Two devices each move a folder into the other; after sync both parent links point at
    // each other. The tree must still show every folder and note.
    use tempfile::tempdir;
    let d = tempdir().unwrap();
    let (mut v, _) = new_vault(&d.path().join("v"));
    let a = v.create_folder("A", None).unwrap();
    let b = v.create_folder("B", None).unwrap();
    let n = v.create_note("inside", "x", Some(&a)).unwrap();
    // forge the cyclic state the way a merge would
    v.force_parent_for_test(&a, Some(&b));
    v.force_parent_for_test(&b, Some(&a));
    let t = v.list_tree().unwrap();
    fn count(f: &[ctrlaltnotes_core::FolderNode]) -> (usize, usize) {
        f.iter().fold((0, 0), |(a, b), x| {
            let (c, d) = count(&x.folders);
            (a + 1 + c, b + x.notes.len() + d)
        })
    }
    let (folders, notes) = count(&t.folders);
    assert_eq!(folders, 2, "both folders visible exactly once");
    assert_eq!(notes + t.notes.len(), 1, "note {n} still reachable");
}

#[test]
fn nesting_depth_is_capped_on_create() {
    use tempfile::tempdir;
    let d = tempdir().unwrap();
    let (mut v, _) = new_vault(&d.path().join("v"));
    let mut parent: Option<String> = None;
    let mut failed = false;
    for _ in 0..80 {
        match v.create_folder("f", parent.as_deref()) {
            Ok(id) => parent = Some(id),
            Err(_) => {
                failed = true;
                break;
            }
        }
    }
    assert!(failed, "unbounded nesting allowed");
}

#[test]
fn export_never_overwrites_and_names_never_collide() {
    use tempfile::tempdir;
    let d = tempdir().unwrap();
    let (mut v, _) = new_vault(&d.path().join("v"));
    v.create_folder("x.md", None).unwrap();
    v.create_note("x", "note body", None).unwrap();
    v.create_note("X", "other body", None).unwrap();
    let out = d.path().join("out");
    assert_eq!(v.export_markdown(&out).unwrap(), 2);
    let again = v.export_markdown(&out).unwrap(); // second export into the same place
    assert_eq!(again, 2);
    let names: Vec<String> = std::fs::read_dir(&out)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().to_lowercase())
        .collect();
    eprintln!("NAMES {names:?}");
    assert_eq!(names.len(), 6); // nothing overwritten
    let mut u = names.clone();
    u.sort();
    u.dedup();
    assert_eq!(u.len(), names.len());
}
