// SPDX-License-Identifier: AGPL-3.0-only
use ctrlaltnotes_core::KDF_MIN;
use ctrlaltnotes_service::{ApiError, Service, ServiceConfig, SyncKind, SyncTarget};
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::Duration;
use tempfile::tempdir;

const PW: &str = "Tangerine Lantern Walrus Quartz 92";

fn cfg(dir: &std::path::Path) -> ServiceConfig {
    let mut c = ServiceConfig::new(dir.join("vault"));
    c.kdf = Some(KDF_MIN);
    c
}

fn call(s: &Service, cmd: &str, a: Value) -> Result<Value, ApiError> {
    s.dispatch(cmd, &a, None)
}

fn setup() -> (tempfile::TempDir, Arc<Service>) {
    let d = tempdir().unwrap();
    let s = Service::new(cfg(d.path()));
    (d, s)
}

#[test]
fn first_run_flow_create_in_ui() {
    let (_d, s) = setup();
    let st = call(&s, "status", json!({})).unwrap();
    assert_eq!(st["exists"], Value::Bool(false));
    let r = call(&s, "create_vault", json!({"password": PW})).unwrap();
    assert!(r["recovery_key"].as_str().unwrap().len() > 40);
    let st = call(&s, "status", json!({})).unwrap();
    assert_eq!(st["exists"], Value::Bool(true));
    assert_eq!(st["unlocked"], Value::Bool(true));
    assert_eq!(
        call(&s, "create_vault", json!({"password": PW}))
            .unwrap_err()
            .wire(),
        "vault already exists"
    );
}

#[test]
fn weak_password_is_rejected_and_nothing_is_created() {
    let (d, s) = setup();
    assert!(call(&s, "create_vault", json!({"password": "short"})).is_err());
    assert!(!d.path().join("vault/vault.json").exists());
}

#[test]
fn everything_but_status_unlock_is_locked_when_locked() {
    let (_d, s) = setup();
    call(&s, "create_vault", json!({"password": PW})).unwrap();
    call(&s, "lock", json!({})).unwrap();
    for (c, a) in [
        ("tree", json!({})),
        ("get_note", json!({"id": "0".repeat(32)})),
        ("create_note", json!({"title": "x"})),
        ("create_folder", json!({"name": "x"})),
        ("update_note", json!({"id": "0".repeat(32), "body": "x"})),
        ("search", json!({"query": "x"})),
        ("delete_item", json!({"id": "0".repeat(32)})),
        (
            "change_password",
            json!({"old": PW, "new": "another long password"}),
        ),
        ("sync_now", json!({})),
    ] {
        let e = call(&s, c, a).unwrap_err();
        assert!(
            matches!(e, ApiError::Locked | ApiError::Bad(_)),
            "{c}: {e:?}"
        );
    }
    assert_eq!(call(&s, "tree", json!({})).unwrap_err(), ApiError::Locked);
}

#[test]
fn note_lifecycle_through_the_api() {
    let (_d, s) = setup();
    call(&s, "create_vault", json!({"password": PW})).unwrap();
    let f = call(&s, "create_folder", json!({"name": "Work"})).unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    let n = call(
        &s,
        "create_note",
        json!({"title": "Plan", "body": "# hi", "parent": f}),
    )
    .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    let note = call(&s, "get_note", json!({"id": n})).unwrap();
    assert_eq!(note["body"], Value::String("# hi".into()));
    call(&s, "update_note", json!({"id": n, "body": "# changed"})).unwrap();
    assert_eq!(
        call(&s, "search", json!({"query": "changed"}))
            .unwrap()
            .as_array()
            .unwrap()
            .len(),
        1
    );
    call(&s, "delete_item", json!({"id": n})).unwrap();
    assert!(call(&s, "get_note", json!({"id": n})).is_err());
}

#[test]
fn input_validation_rejects_wrong_types_and_bad_ids() {
    let (_d, s) = setup();
    call(&s, "create_vault", json!({"password": PW})).unwrap();
    assert!(call(&s, "create_note", json!({"title": 5})).is_err());
    assert!(call(&s, "create_note", json!({"parent": "../../x"})).is_err());
    assert!(call(&s, "create_folder", json!({"name": ["a"]})).is_err());
    assert!(s.dispatch("create_note", &json!([1, 2]), None).is_err());
    assert_eq!(
        call(&s, "no_such_command", json!({})).unwrap_err(),
        ApiError::NotFound
    );
}

#[test]
fn unlock_backoff_after_three_failures_and_recovery_after() {
    let (_d, s) = setup();
    let rec = call(&s, "create_vault", json!({"password": PW})).unwrap()["recovery_key"]
        .as_str()
        .unwrap()
        .to_string();
    call(&s, "lock", json!({})).unwrap();
    for _ in 0..3 {
        assert!(call(&s, "unlock", json!({"password": "wrong password here"})).is_err());
    }
    match call(&s, "unlock", json!({"password": PW})).unwrap_err() {
        ApiError::Throttled(n) => assert!((1..=2).contains(&n)),
        e => panic!("expected throttle, got {e:?}"),
    }
    assert!(
        call(&s, "unlock", json!({"recovery": rec})).is_err(),
        "throttle applies to every unlock path"
    );
    std::thread::sleep(Duration::from_millis(2100));
    call(&s, "unlock", json!({"password": PW})).unwrap();
    assert_eq!(
        call(&s, "status", json!({})).unwrap()["unlocked"],
        Value::Bool(true)
    );
}

#[test]
fn wrong_password_error_is_generic() {
    let (_d, s) = setup();
    call(&s, "create_vault", json!({"password": PW})).unwrap();
    call(&s, "lock", json!({})).unwrap();
    assert_eq!(
        call(&s, "unlock", json!({"password": "wrong password here"}))
            .unwrap_err()
            .wire(),
        "could not unlock"
    );
}

#[test]
fn idle_auto_lock_wipes_and_status_polling_does_not_extend_it() {
    let d = tempdir().unwrap();
    let mut c = cfg(d.path());
    c.idle_lock = Duration::from_millis(600);
    let s = Service::new(c);
    call(&s, "create_vault", json!({"password": PW})).unwrap();
    for _ in 0..8 {
        std::thread::sleep(Duration::from_millis(150));
        call(&s, "status", json!({})).unwrap(); // polling must NOT reset the idle timer
    }
    assert_eq!(
        call(&s, "status", json!({})).unwrap()["unlocked"],
        Value::Bool(false)
    );
    assert_eq!(call(&s, "tree", json!({})).unwrap_err(), ApiError::Locked);
}

#[test]
fn auto_lock_setting_overrides_the_host_default_and_never_disables_it() {
    let d = tempdir().unwrap();
    let mut c = cfg(d.path());
    c.idle_lock = Duration::from_millis(400);
    let s = Service::new(c);
    call(&s, "create_vault", json!({"password": PW})).unwrap();
    call(&s, "set_settings", json!({"auto_lock": 0})).unwrap();
    std::thread::sleep(Duration::from_millis(900));
    assert_eq!(
        call(&s, "status", json!({})).unwrap()["unlocked"],
        Value::Bool(true),
        "'never' must keep the vault unlocked past the host default"
    );
    call(&s, "set_settings", json!({"auto_lock": 60})).unwrap();
    std::thread::sleep(Duration::from_millis(900));
    assert_eq!(
        call(&s, "status", json!({})).unwrap()["unlocked"],
        Value::Bool(true),
        "a 60 s setting replaces the 400 ms host default"
    );
}

#[test]
fn touch_keeps_the_session_alive() {
    let d = tempdir().unwrap();
    let mut c = cfg(d.path());
    c.idle_lock = Duration::from_millis(700);
    let s = Service::new(c);
    call(&s, "create_vault", json!({"password": PW})).unwrap();
    for _ in 0..6 {
        std::thread::sleep(Duration::from_millis(200));
        call(&s, "touch", json!({})).unwrap();
    }
    assert_eq!(
        call(&s, "status", json!({})).unwrap()["unlocked"],
        Value::Bool(true)
    );
}

#[test]
fn change_password_flow() {
    let (_d, s) = setup();
    call(&s, "create_vault", json!({"password": PW})).unwrap();
    assert!(call(
        &s,
        "change_password",
        json!({"old": "nope nope nope nope", "new": "second long password"})
    )
    .is_err());
    let r = call(
        &s,
        "change_password",
        json!({"old": PW, "new": "second long password"}),
    )
    .unwrap();
    assert!(r["recovery_key"].as_str().unwrap().len() > 40);
    call(&s, "lock", json!({})).unwrap();
    assert!(call(&s, "unlock", json!({"password": PW})).is_err());
    call(&s, "unlock", json!({"password": "second long password"})).unwrap();
}

#[test]
fn paths_only_come_from_the_host_never_from_the_ui() {
    let (d, s) = setup();
    call(&s, "create_vault", json!({"password": PW})).unwrap();
    // a hostile page smuggling a path in the JSON is ignored: no host_path => refused
    assert!(call(
        &s,
        "export_markdown",
        json!({"path": d.path().join("x").to_str().unwrap()})
    )
    .is_err());
    assert!(call(
        &s,
        "set_sync",
        json!({"kind": "folder", "path": d.path().to_str().unwrap()})
    )
    .is_err());
    assert!(!d.path().join("x").exists());
}

#[test]
fn sync_folder_via_host_path_and_persisted_settings() {
    let d = tempdir().unwrap();
    let mut c = cfg(d.path());
    c.settings_path = Some(d.path().join("settings.json"));
    c.can_pick_paths = true;
    let s = Service::new(c);
    call(&s, "create_vault", json!({"password": PW})).unwrap();
    call(&s, "create_note", json!({"title": "a", "body": "b"})).unwrap();
    let cloud = d.path().join("cloud");
    std::fs::create_dir_all(&cloud).unwrap();
    s.dispatch("set_sync", &json!({"kind": "folder"}), Some(&cloud))
        .unwrap();
    let r = call(&s, "sync_now", json!({})).unwrap();
    assert_eq!(r["pushed"].as_i64(), Some(1));
    // settings survive a restart
    let mut c2 = cfg(d.path());
    c2.settings_path = Some(d.path().join("settings.json"));
    let s2 = Service::new(c2);
    let st = call(&s2, "status", json!({})).unwrap();
    assert_eq!(st["sync"], Value::String("folder".into()));
    // the sync target may not live inside the local vault
    let inside = d.path().join("vault").join("objects");
    assert!(s
        .dispatch("set_sync", &json!({"kind": "folder"}), Some(&inside))
        .is_err());
    call(&s, "clear_sync", json!({})).unwrap();
    assert_eq!(call(&s, "status", json!({})).unwrap()["sync"], Value::Null);
}

#[test]
fn join_vault_from_cloud_folder_and_bundle() {
    let d = tempdir().unwrap();
    let a = Service::new({
        let mut c = ServiceConfig::new(d.path().join("a"));
        c.kdf = Some(KDF_MIN);
        c.can_pick_paths = true;
        c
    });
    call(&a, "create_vault", json!({"password": PW})).unwrap();
    call(&a, "create_note", json!({"title": "shared", "body": "x"})).unwrap();
    let cloud = d.path().join("cloud");
    a.dispatch("set_sync", &json!({"kind": "folder"}), Some(&cloud))
        .unwrap_err(); // dir must exist
    std::fs::create_dir_all(&cloud).unwrap();
    a.dispatch("set_sync", &json!({"kind": "folder"}), Some(&cloud))
        .unwrap();
    call(&a, "sync_now", json!({})).unwrap();

    let b = Service::new(ServiceConfig::new(d.path().join("b")));
    assert!(b
        .dispatch(
            "join_vault",
            &json!({"kind": "folder", "password": "wrong password here"}),
            Some(&cloud)
        )
        .is_err());
    b.dispatch(
        "join_vault",
        &json!({"kind": "folder", "password": PW}),
        Some(&cloud),
    )
    .unwrap();
    assert_eq!(
        call(&b, "search", json!({"query": "shared"}))
            .unwrap()
            .as_array()
            .unwrap()
            .len(),
        1
    );

    // bundle
    let bundle = d.path().join("notes.canb");
    a.dispatch("set_sync", &json!({"kind": "bundle"}), Some(&bundle))
        .unwrap();
    call(&a, "sync_now", json!({})).unwrap();
    let c = Service::new(ServiceConfig::new(d.path().join("c")));
    c.dispatch(
        "join_vault",
        &json!({"kind": "bundle", "password": PW}),
        Some(&bundle),
    )
    .unwrap();
    assert_eq!(
        call(&c, "search", json!({"query": "shared"}))
            .unwrap()
            .as_array()
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn fixed_sync_override_cannot_be_changed_by_the_ui() {
    let d = tempdir().unwrap();
    let cloud = d.path().join("cloud");
    std::fs::create_dir_all(&cloud).unwrap();
    let mut c = cfg(d.path());
    c.sync_override = Some(SyncTarget {
        kind: SyncKind::Folder,
        path: cloud.clone(),
    });
    c.can_pick_paths = true;
    let s = Service::new(c);
    call(&s, "create_vault", json!({"password": PW})).unwrap();
    assert!(s
        .dispatch("set_sync", &json!({"kind": "folder"}), Some(d.path()))
        .is_err());
    assert!(call(&s, "clear_sync", json!({})).is_err());
    call(&s, "sync_now", json!({})).unwrap();
}

#[test]
fn export_markdown_with_host_path() {
    let (d, s) = setup();
    call(&s, "create_vault", json!({"password": PW})).unwrap();
    call(&s, "create_note", json!({"title": "n", "body": "hello"})).unwrap();
    let out = d.path().join("export");
    let r = s
        .dispatch("export_markdown", &json!({}), Some(&out))
        .unwrap();
    assert_eq!(r["count"].as_i64(), Some(1));
}

#[test]
fn error_wire_strings() {
    assert_eq!(ApiError::Locked.wire(), "locked");
    assert_eq!(ApiError::Throttled(7).wire(), "throttled:7");
    assert_eq!(ApiError::Cancelled.wire(), "cancelled");
}

#[test]
fn new_passwords_must_meet_the_policy_but_old_ones_still_unlock() {
    let (_d, s) = setup();
    for weak in [
        "short",
        "correct horse battery staple",
        "passwordpassword",
        "Aa1!Aa1!Aa1!",
    ] {
        assert!(
            call(&s, "create_vault", json!({"password": weak})).is_err(),
            "{weak}"
        );
    }
    call(&s, "create_vault", json!({"password": PW})).unwrap();
    assert!(call(
        &s,
        "change_password",
        json!({"old": PW, "new": "qwertyuiopasdfghjkl"})
    )
    .is_err());
    call(
        &s,
        "change_password",
        json!({"old": PW, "new": "Basalt Marmot Cobalt Ferry 41"}),
    )
    .unwrap();
}

#[test]
fn settings_default_persist_and_validate() {
    let d = tempdir().unwrap();
    let mut c = cfg(d.path());
    c.settings_path = Some(d.path().join("s.json"));
    let s = Service::new(c);
    let st = call(&s, "status", json!({})).unwrap();
    assert_eq!(
        st["settings"]["auto_sync"],
        Value::Bool(true),
        "auto-sync defaults to on"
    );
    assert_eq!(st["settings"]["live_preview"], Value::Bool(true));
    assert_eq!(st["settings"]["toolbar"], Value::Bool(true));
    assert_eq!(
        st["settings"]["auto_lock"].as_i64(),
        Some(300),
        "default auto-lock is 5 minutes"
    );
    assert_eq!(
        st["settings"]["start_note"],
        json!("blank"),
        "the app opens on a blank page by default"
    );
    call(&s, "create_vault", json!({"password": PW})).unwrap();
    call(
        &s,
        "set_settings",
        json!({"auto_sync": false, "live_preview": false, "sync_interval": 120, "start_note": "last", "auto_lock": 600}),
    )
    .unwrap();
    for bad in [
        json!({"auto_sync": "yes"}),
        json!({"sync_interval": 1}),
        json!({"sync_interval": 99999}),
        json!({"unknown": true}),
        json!({"toolbar": 1}),
        json!({"start_note": "first"}),
        json!({"start_note": true}),
        json!({"auto_lock": 30}),
        json!({"auto_lock": 7201}),
        json!({"auto_lock": -1}),
        json!({"auto_lock": "5"}),
    ] {
        assert!(call(&s, "set_settings", bad).is_err());
    }
    let mut c2 = cfg(d.path());
    c2.settings_path = Some(d.path().join("s.json"));
    let s2 = Service::new(c2);
    let st = call(&s2, "status", json!({})).unwrap();
    assert_eq!(st["settings"]["auto_sync"], Value::Bool(false));
    assert_eq!(st["settings"]["live_preview"], Value::Bool(false));
    assert_eq!(st["settings"]["sync_interval"].as_i64(), Some(120));
    assert_eq!(st["settings"]["start_note"], json!("last"));
    assert_eq!(st["settings"]["auto_lock"].as_i64(), Some(600));
    assert_eq!(
        st["idle_lock"].as_i64(),
        Some(600),
        "status reports the effective auto-lock"
    );
    // settings cannot be changed while locked
    call(&s, "lock", json!({})).unwrap();
    assert_eq!(
        call(&s, "set_settings", json!({"toolbar": false})).unwrap_err(),
        ApiError::Locked
    );
}

#[test]
fn quick_unlock_end_to_end() {
    use ctrlaltnotes_core::crypto::b64e;
    let (_d, s) = setup();
    call(&s, "create_vault", json!({"password": PW})).unwrap();
    call(&s, "create_note", json!({"title": "t", "body": "b"})).unwrap();
    assert_eq!(
        call(&s, "quick_info", json!({})).unwrap()["enrolled"],
        Value::Bool(false)
    );
    let secret = b64e(&[5u8; 32]);
    let args = |pw: &str| json!({"password": pw, "secret": secret.clone(), "cred_id": b64e(&[1u8; 20]), "salt": b64e(&[2u8; 32]), "rp_id": "localhost", "label": "YubiKey"});
    assert!(
        call(&s, "quick_enroll", args("wrong wrong wrong wrong")).is_err(),
        "enrolling requires the password"
    );
    call(&s, "quick_enroll", args(PW)).unwrap();
    let info = call(&s, "quick_info", json!({})).unwrap();
    assert_eq!(info["enrolled"], Value::Bool(true));
    assert_eq!(info["rp_id"], Value::String("localhost".into()));
    assert!(
        !info
            .as_object()
            .unwrap()
            .iter()
            .any(|(k, _)| k == "secret" || k == "wrap"),
        "quick_info must not leak key material"
    );
    assert_eq!(
        call(&s, "status", json!({})).unwrap()["quick"],
        Value::Bool(true)
    );
    call(&s, "lock", json!({})).unwrap();
    assert!(call(&s, "unlock_quick", json!({"secret": b64e(&[6u8; 32])})).is_err());
    call(&s, "unlock_quick", json!({"secret": secret})).unwrap();
    assert_eq!(
        call(&s, "search", json!({"query": "t"}))
            .unwrap()
            .as_array()
            .unwrap()
            .len(),
        1
    );
    call(&s, "quick_remove", json!({})).unwrap();
    call(&s, "lock", json!({})).unwrap();
    assert!(call(&s, "unlock_quick", json!({"secret": b64e(&[5u8; 32])})).is_err());
}

#[test]
fn quick_unlock_failures_are_throttled_like_passwords() {
    use ctrlaltnotes_core::crypto::b64e;
    let (_d, s) = setup();
    call(&s, "create_vault", json!({"password": PW})).unwrap();
    let secret = b64e(&[5u8; 32]);
    call(&s, "quick_enroll", json!({"password": PW, "secret": secret, "cred_id": b64e(&[1u8; 20]), "salt": b64e(&[2u8; 32]), "rp_id": "localhost", "label": "k"})).unwrap();
    call(&s, "lock", json!({})).unwrap();
    for _ in 0..3 {
        assert!(call(&s, "unlock_quick", json!({"secret": b64e(&[9u8; 32])})).is_err());
    }
    assert!(matches!(
        call(&s, "unlock_quick", json!({"secret": secret})).unwrap_err(),
        ApiError::Throttled(_)
    ));
}

#[test]
fn selective_export_through_the_api() {
    let (d, s) = setup();
    call(&s, "create_vault", json!({"password": PW})).unwrap();
    let f = call(&s, "create_folder", json!({"name": "Keep"})).unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    call(
        &s,
        "create_note",
        json!({"title": "in", "body": "x", "parent": f}),
    )
    .unwrap();
    call(&s, "create_note", json!({"title": "out", "body": "y"})).unwrap();
    let out = d.path().join("exp");
    let r = s
        .dispatch("export_markdown", &json!({"ids": [f]}), Some(&out))
        .unwrap();
    assert_eq!(r["count"].as_i64(), Some(1));
    assert!(out.join("Keep/in.md").exists() && !out.join("out.md").exists());
    for bad in [
        json!({"ids": Vec::<serde_json::Value>::new()}),
        json!({"ids": ["../../x"]}),
        json!({"ids": "all"}),
        json!({"ids": [5]}),
    ] {
        assert!(s
            .dispatch("export_markdown", &bad, Some(&d.path().join("e2")))
            .is_err());
    }
}

// ------------------------------------------------------------ pentest regressions
#[test]
fn change_password_and_quick_enroll_cannot_be_used_as_password_oracles() {
    let (_d, s) = setup();
    call(&s, "create_vault", json!({"password": PW})).unwrap();
    let new = "Marble Orchard Cinder Violet 41";
    for _ in 0..3 {
        let e = call(
            &s,
            "change_password",
            json!({"old": "wrong wrong wrong wrong", "new": new}),
        )
        .unwrap_err();
        assert!(!matches!(e, ApiError::Throttled(_)));
    }
    // even the RIGHT old password is refused while throttled
    match call(&s, "change_password", json!({"old": PW, "new": new})) {
        Err(ApiError::Throttled(_)) => {}
        other => panic!("expected throttle, got {other:?}"),
    }
    let enroll = json!({"password": PW, "secret": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "cred_id": "AAAA", "salt": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "rp_id": "localhost"});
    match call(&s, "quick_enroll", enroll) {
        Err(ApiError::Throttled(_)) => {}
        other => panic!("expected throttle, got {other:?}"),
    }
}

#[test]
fn stored_sync_target_inside_vault_dir_is_ignored() {
    let d = tempdir().unwrap();
    let vault = d.path().join("vault");
    std::fs::create_dir_all(vault.join("objects")).unwrap();
    let settings = d.path().join("settings.json");
    let evil = vault.join("objects");
    std::fs::write(
        &settings,
        format!(
            "{{\"sync_kind\":\"folder\",\"sync_path\":\"{}\"}}",
            evil.to_str().unwrap()
        ),
    )
    .unwrap();
    let mut c = cfg(d.path());
    c.settings_path = Some(settings);
    let s = Service::new(c);
    let st = call(&s, "status", json!({})).unwrap();
    assert_eq!(
        st["sync"],
        Value::Null,
        "tampered settings target was accepted: {:?}",
        st["sync"]
    );
}

// ------------------------------------------------------------ web export download
#[test]
fn export_download_returns_one_md_or_a_valid_zip() {
    let (_d, s) = setup();
    call(&s, "create_vault", json!({"password": PW})).unwrap();
    let f = call(&s, "create_folder", json!({"name": "Work"})).unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    let n1 = call(
        &s,
        "create_note",
        json!({"title": "Plan", "body": "# plan", "parent": f}),
    )
    .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    let n2 = call(&s, "create_note", json!({"title": "Solo", "body": "alone"})).unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    // nothing selected is an error
    let none: Vec<Value> = Vec::new();
    assert!(call(&s, "export_download", json!({"ids": none})).is_err());
    // one root note -> the raw markdown file
    let r = call(&s, "export_download", json!({"ids": [n2.as_str()]})).unwrap();
    assert_eq!(r["name"], json!("Solo.md"));
    assert_eq!(r["mime"], json!("text/markdown"));
    // a folder -> zip with folder entry + file; check the structure by hand
    let r = call(
        &s,
        "export_download",
        json!({"ids": [f.clone(), n2.clone()]}),
    )
    .unwrap();
    assert!(r["name"]
        .as_str()
        .unwrap()
        .starts_with("ctrlaltnotes-export-"));
    assert_eq!(r["count"], json!(2));
    let bytes = ctrlaltnotes_core::crypto::b64d(r["data"].as_str().unwrap()).unwrap();
    assert_eq!(&bytes[..4], &[0x50, 0x4b, 3, 4]);
    let eocd = bytes.len() - 22;
    assert_eq!(&bytes[eocd..eocd + 4], &[0x50, 0x4b, 5, 6]);
    assert_eq!(u16::from_le_bytes([bytes[eocd + 10], bytes[eocd + 11]]), 3); // Work/, Work/Plan.md, Solo.md
    let text = String::from_utf8_lossy(&bytes);
    assert!(text.contains("Work/Plan.md") && text.contains("# plan") && text.contains("Solo.md"));
    // ids must be 32 hex characters
    assert!(call(&s, "export_download", json!({"ids": ["../../etc"]})).is_err());
    // locked vault refuses
    call(&s, "lock", json!({})).unwrap();
    assert!(call(&s, "export_download", json!({"ids": [n1]})).is_err());
}

// ------------------------------------------------------------ theme + vault folder switching

fn desktop_cfg(d: &std::path::Path) -> ServiceConfig {
    let mut c = cfg(d);
    c.can_pick_paths = true;
    c.settings_path = Some(d.join("settings.json"));
    c.app_state_path = Some(d.join("app.json"));
    c
}

fn pick(s: &Service, cmd: &str, p: &std::path::Path) -> Result<Value, ApiError> {
    s.dispatch(cmd, &json!({}), Some(p))
}

#[test]
fn theme_defaults_to_dark_persists_and_is_validated() {
    let d = tempdir().unwrap();
    let s = Service::new(desktop_cfg(d.path()));
    assert_eq!(call(&s, "status", json!({})).unwrap()["theme"], "dark");
    // allowed while locked (it is not secret), validated strictly
    assert!(call(&s, "set_theme", json!({"theme": "neon"})).is_err());
    assert!(call(&s, "set_theme", json!({"theme": 1})).is_err());
    call(&s, "set_theme", json!({"theme": "light"})).unwrap();
    drop(s);
    let s2 = Service::new(desktop_cfg(d.path()));
    assert_eq!(call(&s2, "status", json!({})).unwrap()["theme"], "light");
    call(&s2, "set_theme", json!({"theme": "system"})).unwrap();
    assert_eq!(call(&s2, "status", json!({})).unwrap()["theme"], "system");
}

#[test]
fn open_vault_folder_needs_a_host_picker() {
    let d = tempdir().unwrap();
    let s = Service::new(cfg(d.path())); // web-like host: cannot pick paths
    let other = d.path().join("other");
    std::fs::create_dir(&other).unwrap();
    assert!(pick(&s, "open_vault_folder", &other).is_err());
    assert!(call(&s, "use_default_vault", json!({})).is_err());
    let s = Service::new(desktop_cfg(d.path()));
    // the path never comes from the JSON arguments
    let r = s.dispatch(
        "open_vault_folder",
        &json!({"path": other.to_str().unwrap()}),
        None,
    );
    assert!(r.is_err());
}

#[test]
fn open_vault_folder_accepts_only_empty_folders_or_vaults() {
    let d = tempdir().unwrap();
    let s = Service::new(desktop_cfg(d.path()));
    let busy = d.path().join("busy");
    std::fs::create_dir(&busy).unwrap();
    std::fs::write(busy.join("taxes.pdf"), b"x").unwrap();
    assert!(pick(&s, "open_vault_folder", &busy).is_err());
    assert!(!busy.join("vault.json").exists());
    let file = d.path().join("plain-file");
    std::fs::write(&file, b"x").unwrap();
    assert!(pick(&s, "open_vault_folder", &file).is_err());
    assert!(pick(
        &s,
        "open_vault_folder",
        std::path::Path::new("relative/dir")
    )
    .is_err());
    #[cfg(unix)]
    {
        let real = d.path().join("real");
        std::fs::create_dir(&real).unwrap();
        let link = d.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert!(pick(&s, "open_vault_folder", &link).is_err());
    }
    // hidden files (e.g. .DS_Store) do not count as content
    let fresh = d.path().join("fresh");
    std::fs::create_dir(&fresh).unwrap();
    std::fs::write(fresh.join(".DS_Store"), b"x").unwrap();
    pick(&s, "open_vault_folder", &fresh).unwrap();
    let st = call(&s, "status", json!({})).unwrap();
    assert_eq!(st["exists"], false);
    assert_eq!(st["vault_custom"], true);
    assert_eq!(st["vault_label"], "fresh");
}

#[test]
fn switching_vaults_keeps_each_vault_separate_and_remembers_the_choice() {
    let d = tempdir().unwrap();
    let s = Service::new(desktop_cfg(d.path()));
    call(&s, "create_vault", json!({"password": PW})).unwrap();
    call(&s, "set_settings", json!({"toolbar": false})).unwrap();
    let cloud = d.path().join("cloud");
    std::fs::create_dir(&cloud).unwrap();
    s.dispatch("set_sync", &json!({"kind": "folder"}), Some(&cloud))
        .unwrap();
    call(&s, "create_note", json!({"title": "in default"})).unwrap();

    // refused while a vault is open
    let work = d.path().join("work");
    std::fs::create_dir(&work).unwrap();
    assert!(pick(&s, "open_vault_folder", &work).is_err());
    call(&s, "lock", json!({})).unwrap();
    // the sync target of the current vault is not a working vault
    assert!(pick(&s, "open_vault_folder", &cloud).is_err());

    pick(&s, "open_vault_folder", &work).unwrap();
    let st = call(&s, "status", json!({})).unwrap();
    assert_eq!(st["exists"], false);
    assert_eq!(
        st["sync"],
        Value::Null,
        "sync target must not leak into another vault"
    );
    assert_eq!(st["settings"]["toolbar"], true, "preferences are per vault");
    call(&s, "create_vault", json!({"password": PW})).unwrap();
    assert!(work.join("vault.json").exists());
    let tree = call(&s, "tree", json!({})).unwrap();
    assert!(!tree.to_string().contains("in default"));
    call(&s, "lock", json!({})).unwrap();
    drop(s);

    // remembered across restarts
    let s = Service::new(desktop_cfg(d.path()));
    let st = call(&s, "status", json!({})).unwrap();
    assert_eq!(st["vault_custom"], true);
    assert_eq!(st["exists"], true);

    // back to the default vault: its own sync target and preferences come back
    call(&s, "use_default_vault", json!({})).unwrap();
    let st = call(&s, "status", json!({})).unwrap();
    assert_eq!(st["vault_custom"], false);
    assert_eq!(st["sync"], "folder");
    assert_eq!(st["settings"]["toolbar"], false);
    call(&s, "unlock", json!({"password": PW})).unwrap();
    assert!(call(&s, "tree", json!({}))
        .unwrap()
        .to_string()
        .contains("in default"));
}

#[test]
fn switching_vaults_does_not_reset_the_unlock_throttle() {
    let d = tempdir().unwrap();
    let s = Service::new(desktop_cfg(d.path()));
    call(&s, "create_vault", json!({"password": PW})).unwrap();
    call(&s, "lock", json!({})).unwrap();
    for _ in 0..3 {
        let _ = call(&s, "unlock", json!({"password": "wrong wrong wrong wrong"}));
    }
    let empty = d.path().join("empty");
    std::fs::create_dir(&empty).unwrap();
    pick(&s, "open_vault_folder", &empty).unwrap();
    call(&s, "use_default_vault", json!({})).unwrap();
    assert!(matches!(
        call(&s, "unlock", json!({"password": PW})),
        Err(ApiError::Throttled(_))
    ));
}

#[test]
fn tampered_app_state_falls_back_to_the_default_vault() {
    let d = tempdir().unwrap();
    let busy = d.path().join("busy");
    std::fs::create_dir(&busy).unwrap();
    std::fs::write(busy.join("secret.txt"), b"x").unwrap();
    std::fs::write(
        d.path().join("app.json"),
        format!(
            "{{\"theme\":\"<script>\",\"vault_dir\":{}}}",
            serde_json::to_string(busy.to_str().unwrap()).unwrap()
        ),
    )
    .unwrap();
    let s = Service::new(desktop_cfg(d.path()));
    let st = call(&s, "status", json!({})).unwrap();
    assert_eq!(st["vault_custom"], false);
    assert_eq!(st["theme"], "dark");
    call(&s, "create_vault", json!({"password": PW})).unwrap();
    assert!(!busy.join("vault.json").exists());
}
