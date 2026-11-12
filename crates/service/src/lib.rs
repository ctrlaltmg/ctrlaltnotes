// SPDX-License-Identifier: AGPL-3.0-only
//! The application backend, written once and used by BOTH front ends:
//!   * `ctrlaltnotes-server`  (web version: HTTP -> `Service::dispatch`)
//!   * `app`                 (native macOS / Windows / Linux apps: IPC -> `Service::dispatch`)
//!
//! Every UI action is a command name + JSON arguments. Commands that need a file-system path
//! (join a cloud vault, choose the sync target, export) receive that path from the *host*
//! (a native OS dialog in the desktop app), never from the JSON sent by the UI, so a
//! compromised page can never make the backend read or write arbitrary files.
#![forbid(unsafe_code)]

use ctrlaltnotes_core::crypto::{b64d, KdfParams};
use ctrlaltnotes_core::fsutil::{mkdir_private, read_capped, write_atomic};
use ctrlaltnotes_core::json::{canonical, vs, JMap};
use ctrlaltnotes_core::policy;
use ctrlaltnotes_core::quick::{self, QuickMeta};
use ctrlaltnotes_core::vault::FolderNode;
use ctrlaltnotes_core::{
    join_from_bundle, sync_bundle, sync_folder, NoteEntry, Tree, Vault, VaultError,
};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

/// Errors as seen by a front end. `wire()` is the exact string sent to the UI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApiError {
    Locked,
    /// Too many failed unlocks; retry after N seconds.
    Throttled(u64),
    /// The user dismissed a native dialog.
    Cancelled,
    NotFound,
    Bad(String),
    Internal,
}

impl ApiError {
    pub fn wire(&self) -> String {
        match self {
            ApiError::Locked => "locked".to_string(),
            ApiError::Throttled(n) => format!("throttled:{n}"),
            ApiError::Cancelled => "cancelled".to_string(),
            ApiError::NotFound => "not found".to_string(),
            ApiError::Bad(m) => m.clone(),
            ApiError::Internal => "internal error".to_string(),
        }
    }
}

impl From<VaultError> for ApiError {
    fn from(e: VaultError) -> Self {
        let m = e.to_string();
        if m == "vault is locked" {
            ApiError::Locked
        } else {
            ApiError::Bad(m)
        }
    }
}

fn bad() -> ApiError {
    ApiError::Bad("invalid input".to_string())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SyncKind {
    Folder,
    Bundle,
}

impl SyncKind {
    fn name(self) -> &'static str {
        match self {
            SyncKind::Folder => "folder",
            SyncKind::Bundle => "bundle",
        }
    }
    fn parse(s: &str) -> Option<SyncKind> {
        match s {
            "folder" => Some(SyncKind::Folder),
            "bundle" => Some(SyncKind::Bundle),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SyncTarget {
    pub kind: SyncKind,
    pub path: PathBuf,
}

pub struct ServiceConfig {
    /// Where the local encrypted vault lives.
    pub vault_dir: PathBuf,
    /// Where the sync target choice is remembered (desktop). `None` = not persisted.
    pub settings_path: Option<PathBuf>,
    /// Host can show native pickers (desktop app). The web host cannot.
    pub can_pick_paths: bool,
    /// Fixed sync target (web host, from launch flags). Overrides persisted settings.
    pub sync_override: Option<SyncTarget>,
    pub idle_lock: Duration,
    /// Tests use a cheaper KDF. `None` = production default (Argon2id 64 MiB / t=3 / p=4).
    pub kdf: Option<KdfParams>,
    /// App-wide state that is not tied to one vault: the colour theme and the vault folder the
    /// user chose instead of `vault_dir` (desktop). `None` = nothing persisted (web, tests).
    /// Settings of a chosen vault live next to this file in `vaults/<hash>.json`.
    pub app_state_path: Option<PathBuf>,
}

/// Colour theme of the UI. Dark is the default.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Theme {
    Dark,
    Light,
    System,
}

impl Theme {
    pub fn name(self) -> &'static str {
        match self {
            Theme::Dark => "dark",
            Theme::Light => "light",
            Theme::System => "system",
        }
    }
    pub fn parse(s: &str) -> Option<Theme> {
        match s {
            "dark" => Some(Theme::Dark),
            "light" => Some(Theme::Light),
            "system" => Some(Theme::System),
            _ => None,
        }
    }
}

impl ServiceConfig {
    pub fn new(vault_dir: PathBuf) -> ServiceConfig {
        ServiceConfig {
            vault_dir,
            settings_path: None,
            can_pick_paths: false,
            sync_override: None,
            idle_lock: Duration::from_secs(300),
            kdf: None,
            app_state_path: None,
        }
    }

    /// Settings file for a vault the user picked: `<app state dir>/vaults/<sha256(path)>.json`.
    /// Each vault keeps its own sync target and preferences.
    fn vault_settings_path(&self, dir: &Path) -> Option<PathBuf> {
        let base = self.app_state_path.as_deref()?.parent()?;
        let digest = Sha256::digest(dir.as_os_str().as_encoded_bytes());
        Some(base.join("vaults").join(format!("{}.json", hex16(&digest))))
    }

    /// Load a vault's settings + sync target. The file is not authenticated, so a stored
    /// target gets the same checks as one picked now, or it is dropped.
    fn load_vault_settings(
        &self,
        vault_dir: &Path,
        settings_path: Option<&Path>,
    ) -> (Settings, Option<SyncTarget>) {
        let (stored, settings) = match settings_path {
            Some(p) => load_settings(p),
            None => (None, Settings::default()),
        };
        let stored = stored.filter(|t| sync_path_ok(vault_dir, t.kind, &t.path));
        (settings, self.sync_override.clone().or(stored))
    }
}

/// First 16 bytes of a digest as lowercase hex.
fn hex16(d: &[u8]) -> String {
    d.iter().take(16).map(|b| format!("{b:02x}")).collect()
}

/// A folder the user may use as a vault: an absolute path to a real directory (not a symlink)
/// that is either empty (a new vault is created there) or already holds a vault.
/// Returns the canonical path.
fn vault_folder_ok(path: &Path) -> Result<PathBuf, ApiError> {
    let refuse = |m: &str| Err(ApiError::Bad(m.to_string()));
    if !path.is_absolute() {
        return refuse("choose a folder");
    }
    match std::fs::symlink_metadata(path) {
        Ok(md) if md.file_type().is_dir() => {}
        _ => return refuse("choose a folder"),
    }
    let Ok(dir) = path.canonicalize() else {
        return refuse("choose a folder");
    };
    if let Ok(md) = std::fs::symlink_metadata(dir.join("vault.json")) {
        return if md.file_type().is_file() {
            Ok(dir)
        } else {
            refuse("not a CtrlAltNotes vault")
        };
    }
    // No vault yet: only an empty folder (hidden files such as .DS_Store are ignored), so a
    // vault is never scattered into Documents or a home folder by mistake.
    let Ok(mut entries) = std::fs::read_dir(&dir) else {
        return refuse("choose a folder");
    };
    let busy = entries.any(|e| {
        e.map(|e| !e.file_name().to_string_lossy().starts_with('.'))
            .unwrap_or(true)
    });
    if busy {
        return refuse("choose an empty folder or one that already holds a CtrlAltNotes vault");
    }
    Ok(dir)
}

fn same_place(a: &Path, b: &Path) -> bool {
    let c = |p: &Path| p.canonicalize().unwrap_or_else(|_| p.to_path_buf());
    c(a) == c(b)
}

fn load_app_state(path: &Path) -> (Theme, Option<PathBuf>) {
    let Ok(raw) = read_capped(path, 16384) else {
        return (Theme::Dark, None);
    };
    let Ok(Value::Object(m)) = serde_json::from_slice::<Value>(&raw) else {
        return (Theme::Dark, None);
    };
    let theme = m
        .get("theme")
        .and_then(|t| t.as_str())
        .and_then(Theme::parse)
        .unwrap_or(Theme::Dark);
    let dir = m
        .get("vault_dir")
        .and_then(|d| d.as_str())
        .map(PathBuf::from);
    (theme, dir)
}

/// User preferences (not secret). Stored in the settings file next to the sync target.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Settings {
    /// Sync automatically (default on; only has an effect when a sync target is set).
    pub auto_sync: bool,
    /// Seconds between automatic syncs.
    pub sync_interval: u64,
    /// Show the rendered Markdown next to the editor and update it while typing.
    pub live_preview: bool,
    /// Show the formatting toolbar (bold, italic, ...).
    pub toolbar: bool,
    /// What the main window shows right after unlocking: `blank` (nothing selected) or
    /// `last` (the most recently edited note).
    pub start_note: String,
    /// Idle time in seconds before the vault locks itself: `0` = never, otherwise 60..=7200.
    /// `None` = not chosen yet, use the host's default (`Config::idle_lock`).
    pub auto_lock: Option<u64>,
}

/// Accepted range of [`Settings::auto_lock`] in seconds (besides `0` = never).
pub const AUTO_LOCK_RANGE: std::ops::RangeInclusive<i64> = 60..=7200;

/// The accepted values of [`Settings::start_note`].
pub const START_NOTE_VALUES: [&str; 2] = ["blank", "last"];

impl Default for Settings {
    fn default() -> Self {
        Settings {
            auto_sync: true,
            sync_interval: 60,
            live_preview: true,
            toolbar: true,
            start_note: "blank".to_string(),
            auto_lock: None,
        }
    }
}

struct Inner {
    /// The vault folder in use: `cfg.vault_dir`, or one the user picked.
    vault_dir: PathBuf,
    /// Settings file of the vault in use (`None` = not persisted).
    settings_path: Option<PathBuf>,
    theme: Theme,
    settings: Settings,
    vault: Option<Vault>,
    last: Instant,
    fails: u32,
    locked_until: Option<Instant>,
    sync: Option<SyncTarget>,
}

pub struct Service {
    cfg: ServiceConfig,
    inner: Mutex<Inner>,
}

impl Service {
    pub fn new(cfg: ServiceConfig) -> Arc<Service> {
        let (theme, picked) = match cfg.app_state_path.as_deref() {
            Some(p) => load_app_state(p),
            None => (Theme::Dark, None),
        };
        // The app-state file is not authenticated either: a stored folder must pass the same
        // checks as a freshly picked one, or the default vault is used.
        let picked = picked.and_then(|d| vault_folder_ok(&d).ok());
        let (vault_dir, settings_path) = match picked {
            Some(d) => {
                let sp = cfg.vault_settings_path(&d);
                (d, sp)
            }
            None => (cfg.vault_dir.clone(), cfg.settings_path.clone()),
        };
        let (settings, sync) = cfg.load_vault_settings(&vault_dir, settings_path.as_deref());
        let svc = Arc::new(Service {
            cfg,
            inner: Mutex::new(Inner {
                vault_dir,
                settings_path,
                theme,
                settings,
                vault: None,
                last: Instant::now(),
                fails: 0,
                locked_until: None,
                sync,
            }),
        });
        // Idle auto-lock watchdog. Holds only a Weak reference so dropping the service stops it.
        let weak = Arc::downgrade(&svc);
        std::thread::spawn(move || loop {
            std::thread::sleep(Duration::from_millis(250));
            match weak.upgrade() {
                Some(s) => s.tick(),
                None => break,
            }
        });
        svc
    }

    fn lock_inner(&self) -> MutexGuard<'_, Inner> {
        // A panic in another thread must not brick the app: recover the guard.
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Lock the vault (wipes keys + decrypted content) if idle for too long.
    pub fn tick(&self) {
        let mut g = self.lock_inner();
        let limit = match g.settings.auto_lock {
            Some(0) => None, // the user chose "never"
            Some(secs) => Some(Duration::from_secs(secs)),
            None => Some(self.cfg.idle_lock),
        };
        if g.vault.is_some() && limit.is_some_and(|l| g.last.elapsed() > l) {
            if let Some(v) = g.vault.as_mut() {
                v.lock();
            }
            g.vault = None;
        }
    }

    /// Lock immediately (window closed, app quitting).
    pub fn lock_now(&self) {
        let mut g = self.lock_inner();
        if let Some(v) = g.vault.as_mut() {
            v.lock();
        }
        g.vault = None;
    }

    pub fn can_pick_paths(&self) -> bool {
        self.cfg.can_pick_paths
    }

    fn vault_exists(g: &Inner) -> bool {
        g.vault_dir.join("vault.json").exists()
    }

    fn check_throttle(g: &Inner) -> Result<(), ApiError> {
        if let Some(until) = g.locked_until {
            let now = Instant::now();
            if now < until {
                return Err(ApiError::Throttled((until - now).as_secs() + 1));
            }
        }
        Ok(())
    }

    fn record_unlock_result<T>(g: &mut Inner, r: &Result<T, VaultError>) {
        match r {
            Ok(_) => {
                g.fails = 0;
                g.locked_until = None;
            }
            Err(e) if e.is_auth() => {
                g.fails += 1;
                if g.fails >= 3 {
                    let secs = (1u64 << (g.fails - 3).min(20)).min(300);
                    g.locked_until = Some(Instant::now() + Duration::from_secs(secs));
                }
            }
            Err(_) => {}
        }
    }

    fn vault_mut(g: &mut Inner) -> Result<&mut Vault, ApiError> {
        match g.vault.as_mut() {
            Some(v) if v.is_unlocked() => Ok(v),
            _ => Err(ApiError::Locked),
        }
    }

    fn set_vault(g: &mut Inner, v: Vault) {
        if let Some(old) = g.vault.as_mut() {
            old.lock();
        }
        g.vault = Some(v);
    }

    /// Make `dir` the vault in use: lock whatever is open, load that vault's own settings and
    /// sync target, remember the choice. The unlock throttle is NOT reset, so switching
    /// folders cannot be used to get more password guesses.
    fn switch_vault(&self, g: &mut Inner, dir: PathBuf) -> Result<(), ApiError> {
        if let Some(v) = g.vault.as_mut() {
            v.lock();
        }
        g.vault = None;
        let settings_path = if dir == self.cfg.vault_dir {
            self.cfg.settings_path.clone()
        } else {
            self.cfg.vault_settings_path(&dir)
        };
        let (settings, sync) = self.cfg.load_vault_settings(&dir, settings_path.as_deref());
        g.vault_dir = dir;
        g.settings_path = settings_path;
        g.settings = settings;
        g.sync = sync;
        self.save_app_state(g)
    }

    fn save_app_state(&self, g: &Inner) -> Result<(), ApiError> {
        let Some(p) = &self.cfg.app_state_path else {
            return Ok(());
        };
        if let Some(dir) = p.parent() {
            mkdir_private(dir)?;
        }
        let mut m = Map::new();
        m.insert("theme".to_string(), vs(g.theme.name()));
        if g.vault_dir != self.cfg.vault_dir {
            let s = g
                .vault_dir
                .to_str()
                .ok_or_else(|| ApiError::Bad("unsupported path".to_string()))?;
            m.insert("vault_dir".to_string(), vs(s));
        }
        write_atomic(p, &canonical(&Value::Object(m)))?;
        Ok(())
    }

    fn persist_sync(&self, g: &mut Inner, target: Option<SyncTarget>) -> Result<(), ApiError> {
        g.sync = target;
        self.save_all(g)
    }

    fn save_all(&self, g: &Inner) -> Result<(), ApiError> {
        if let Some(sp) = &g.settings_path {
            // a fixed (launch-flag) target is never written to the settings file
            let t = if self.cfg.sync_override.is_some() {
                None
            } else {
                g.sync.as_ref()
            };
            save_settings(sp, t, &g.settings)?;
        }
        Ok(())
    }

    /// Execute one UI command. `host_path` is a path chosen by the HOST (native dialog); it is
    /// never taken from `args`.
    pub fn dispatch(
        &self,
        cmd: &str,
        args: &Value,
        host_path: Option<&Path>,
    ) -> Result<Value, ApiError> {
        let a: &JMap = args.as_object().ok_or_else(bad)?;
        let mut guard = self.lock_inner();
        let g: &mut Inner = &mut guard;
        // `status` is polled by the UI and automatic background sync (`sync_now` with
        // `auto: true`) runs on a timer: neither may keep an idle vault unlocked.
        let background =
            cmd == "status" || (cmd == "sync_now" && a.get("auto") == Some(&Value::Bool(true)));
        if !background {
            g.last = Instant::now();
        }
        match cmd {
            "status" => Ok(self.status(g)),
            "touch" => Ok(ok()),

            "create_vault" => {
                if Self::vault_exists(g) {
                    return Err(ApiError::Bad("vault already exists".to_string()));
                }
                let pw = req_str(a, "password")?;
                policy::check_new_password(pw)?;
                let (v, recovery) = Vault::create(&g.vault_dir, pw, self.cfg.kdf)?;
                Self::set_vault(g, v);
                Ok(obj(vec![("recovery_key", vs(&recovery))]))
            }
            "unlock" => {
                Self::check_throttle(g)?;
                let pw = opt_str(a, "password")?;
                let rec = opt_str(a, "recovery")?;
                let r = Vault::unlock(&g.vault_dir, pw, rec);
                Self::record_unlock_result(g, &r);
                Self::set_vault(g, r?);
                Ok(ok())
            }
            "join_vault" => {
                Self::check_throttle(g)?;
                if Self::vault_exists(g) {
                    return Err(ApiError::Bad("vault already exists".to_string()));
                }
                let kind = SyncKind::parse(req_str(a, "kind")?).ok_or_else(bad)?;
                let path =
                    host_path.ok_or_else(|| ApiError::Bad("not available here".to_string()))?;
                let pw = req_str(a, "password")?;
                let r = match kind {
                    SyncKind::Folder => Vault::join(&g.vault_dir, path, pw).and_then(|mut v| {
                        sync_folder(&mut v, path)?;
                        Ok(v)
                    }),
                    SyncKind::Bundle => join_from_bundle(&g.vault_dir, path, pw),
                };
                Self::record_unlock_result(g, &r);
                let v = r?;
                Self::set_vault(g, v);
                self.persist_sync(
                    g,
                    Some(SyncTarget {
                        kind,
                        path: path.to_path_buf(),
                    }),
                )?;
                Ok(ok())
            }
            // ---- app-wide preference and the vault folder (both allowed while locked)
            "set_theme" => {
                g.theme = Theme::parse(req_str(a, "theme")?).ok_or_else(bad)?;
                self.save_app_state(g)?;
                Ok(ok())
            }
            "open_vault_folder" => {
                if !self.cfg.can_pick_paths {
                    return Err(ApiError::Bad("not available here".to_string()));
                }
                if g.vault.as_ref().is_some_and(|v| v.is_unlocked()) {
                    return Err(ApiError::Bad("lock the vault first".to_string()));
                }
                let path =
                    host_path.ok_or_else(|| ApiError::Bad("not available here".to_string()))?;
                let dir = vault_folder_ok(path)?;
                // picking the default folder by hand is the same as going back to it
                let dir = if same_place(&dir, &self.cfg.vault_dir) {
                    self.cfg.vault_dir.clone()
                } else {
                    dir
                };
                // the cloud copy is a sync target, not a working vault
                if g.sync.as_ref().is_some_and(|t| same_place(&t.path, &dir)) {
                    return Err(ApiError::Bad(
                        "this folder is your sync target; choose another folder".to_string(),
                    ));
                }
                self.switch_vault(g, dir)?;
                Ok(ok())
            }
            "use_default_vault" => {
                if !self.cfg.can_pick_paths {
                    return Err(ApiError::Bad("not available here".to_string()));
                }
                if g.vault.as_ref().is_some_and(|v| v.is_unlocked()) {
                    return Err(ApiError::Bad("lock the vault first".to_string()));
                }
                let d = self.cfg.vault_dir.clone();
                self.switch_vault(g, d)?;
                Ok(ok())
            }

            "lock" => {
                if let Some(v) = g.vault.as_mut() {
                    v.lock();
                }
                g.vault = None;
                Ok(ok())
            }
            "change_password" => {
                Self::vault_mut(g)?; // must be unlocked
                let new = req_str(a, "new")?;
                let old = req_str(a, "old")?;
                policy::check_new_password(new)?;
                // `old` is a password guess: it shares the unlock throttle so this command
                // cannot be used as a free oracle by someone at an unlocked, unattended session.
                Self::check_throttle(g)?;
                let r = Self::vault_mut(g)?.change_password(old, new, None);
                Self::record_unlock_result(g, &r);
                r?;
                let v = Self::vault_mut(g)?;
                let rec = v.new_recovery_key().unwrap_or("").to_string();
                Ok(obj(vec![("recovery_key", vs(&rec))]))
            }

            "tree" => Ok(tree_value(&Self::vault_mut(g)?.list_tree()?)),
            "get_note" => {
                let n = Self::vault_mut(g)?.get_note(req_str(a, "id")?)?;
                Ok(obj(vec![
                    ("id", vs(&n.id)),
                    ("title", vs(&n.title)),
                    ("body", vs(&n.body)),
                    ("parent", opt_value(&n.parent)),
                    ("created", num(n.created)),
                    ("modified", num(n.modified)),
                ]))
            }
            "create_note" => {
                let id = Self::vault_mut(g)?.create_note(
                    opt_str(a, "title")?.unwrap_or(""),
                    opt_str(a, "body")?.unwrap_or(""),
                    opt_id(a, "parent")?,
                )?;
                Ok(obj(vec![("id", vs(&id))]))
            }
            "create_folder" => {
                let id = Self::vault_mut(g)?
                    .create_folder(opt_str(a, "name")?.unwrap_or(""), opt_id(a, "parent")?)?;
                Ok(obj(vec![("id", vs(&id))]))
            }
            "update_note" => {
                Self::vault_mut(g)?.update_note(
                    req_str(a, "id")?,
                    opt_str(a, "body")?,
                    opt_str(a, "title")?,
                )?;
                Ok(ok())
            }
            "rename_folder" => {
                Self::vault_mut(g)?.rename_folder(req_str(a, "id")?, req_str(a, "name")?)?;
                Ok(ok())
            }
            "move_item" => {
                Self::vault_mut(g)?.move_item(req_str(a, "id")?, opt_id(a, "parent")?)?;
                Ok(ok())
            }
            "delete_item" => {
                Self::vault_mut(g)?.delete(req_str(a, "id")?)?;
                Ok(ok())
            }
            "search" => {
                let q: String = req_str(a, "query")?.chars().take(200).collect();
                let hits = Self::vault_mut(g)?.search(&q)?;
                Ok(Value::Array(hits.iter().map(entry_value).collect()))
            }

            "sync_now" => {
                let target = g
                    .sync
                    .clone()
                    .ok_or_else(|| ApiError::Bad("no sync target configured".to_string()))?;
                let v = Self::vault_mut(g)?;
                let rep = match target.kind {
                    SyncKind::Folder => sync_folder(v, &target.path)?,
                    SyncKind::Bundle => sync_bundle(v, &target.path)?,
                };
                Ok(obj(vec![
                    ("pushed", num(rep.pushed.len() as i64)),
                    ("pulled", num(rep.pulled.len() as i64)),
                    ("conflicts", num(rep.conflicts.len() as i64)),
                    ("errors", num(rep.errors.len() as i64)),
                ]))
            }
            "set_sync" => {
                let kind = SyncKind::parse(req_str(a, "kind")?).ok_or_else(bad)?;
                let path =
                    host_path.ok_or_else(|| ApiError::Bad("not available here".to_string()))?;
                if self.cfg.sync_override.is_some() {
                    return Err(ApiError::Bad(
                        "sync target is fixed for this session".to_string(),
                    ));
                }
                Self::check_sync_path(g, kind, path)?;
                self.persist_sync(
                    g,
                    Some(SyncTarget {
                        kind,
                        path: path.to_path_buf(),
                    }),
                )?;
                Ok(ok())
            }
            "clear_sync" => {
                if self.cfg.sync_override.is_some() {
                    return Err(ApiError::Bad(
                        "sync target is fixed for this session".to_string(),
                    ));
                }
                self.persist_sync(g, None)?;
                Ok(ok())
            }
            "export_markdown" => {
                let path =
                    host_path.ok_or_else(|| ApiError::Bad("not available here".to_string()))?;
                let sel = parse_ids(a)?;
                let n = Self::vault_mut(g)?.export_selected(path, sel.as_ref())?;
                Ok(obj(vec![("count", num(n as i64))]))
            }
            // Web version: the browser cannot choose a folder, so the selection comes back as a
            // download (one .md, or a .zip) and the browser saves it to the Downloads folder.
            "export_download" => {
                let sel = parse_ids(a)?;
                let entries = Self::vault_mut(g)?.export_entries(sel.as_ref())?;
                let files: Vec<&(String, Vec<u8>)> =
                    entries.iter().filter(|(n, _)| !n.ends_with('/')).collect();
                let count = files.len();
                let (name, mime, bytes) = if entries.len() == 1 && files.len() == 1 {
                    (files[0].0.clone(), "text/markdown", files[0].1.clone())
                } else {
                    let secs = (ctrlaltnotes_core::vault::now_ms() / 1000).max(0);
                    let day = civil_date(secs);
                    (
                        format!("ctrlaltnotes-export-{day}.zip"),
                        "application/zip",
                        ctrlaltnotes_core::zip::build(&entries, secs)?,
                    )
                };
                Ok(obj(vec![
                    ("name", vs(&name)),
                    ("mime", vs(mime)),
                    ("count", num(count as i64)),
                    ("data", vs(&ctrlaltnotes_core::crypto::b64e(&bytes))),
                ]))
            }

            "set_settings" => {
                Self::vault_mut(g)?;
                let mut st = g.settings.clone();
                for (k, v) in a.iter() {
                    match (k.as_str(), v) {
                        ("auto_sync", Value::Bool(b)) => st.auto_sync = *b,
                        ("live_preview", Value::Bool(b)) => st.live_preview = *b,
                        ("toolbar", Value::Bool(b)) => st.toolbar = *b,
                        ("start_note", Value::String(x))
                            if START_NOTE_VALUES.contains(&x.as_str()) =>
                        {
                            st.start_note = x.clone()
                        }
                        ("auto_lock", n) => {
                            let n = n.as_i64().ok_or_else(bad)?;
                            if n != 0 && !AUTO_LOCK_RANGE.contains(&n) {
                                return Err(bad());
                            }
                            st.auto_lock = Some(n as u64);
                        }
                        ("sync_interval", n) => {
                            let n = n.as_i64().ok_or_else(bad)?;
                            if !(15..=3600).contains(&n) {
                                return Err(bad());
                            }
                            st.sync_interval = n as u64;
                        }
                        _ => return Err(bad()),
                    }
                }
                g.settings = st;
                self.save_all(g)?;
                Ok(ok())
            }

            // ---- quick unlock (security key / fingerprint via WebAuthn PRF)
            "quick_info" => Ok(match quick::info(&g.vault_dir)? {
                Some(m) => obj(vec![
                    ("enrolled", Value::Bool(true)),
                    ("cred_id", vs(&m.cred_id)),
                    ("salt", vs(&m.salt)),
                    ("rp_id", vs(&m.rp_id)),
                    ("label", vs(&m.label)),
                ]),
                None => obj(vec![("enrolled", Value::Bool(false))]),
            }),
            "quick_enroll" => {
                let password = req_str(a, "password")?;
                let secret = b64d(req_str(a, "secret")?).map_err(|_| bad())?;
                let meta = QuickMeta {
                    cred_id: req_str(a, "cred_id")?.to_string(),
                    salt: req_str(a, "salt")?.to_string(),
                    rp_id: req_str(a, "rp_id")?.to_string(),
                    label: opt_str(a, "label")?.unwrap_or("Security key").to_string(),
                };
                meta.validate()?;
                // adding a way in requires proving you know the password right now; the guess
                // is throttled like any unlock attempt
                Self::check_throttle(g)?;
                let r = Self::vault_mut(g)?.verify_password(password);
                Self::record_unlock_result(g, &r);
                r?;
                Self::vault_mut(g)?.quick_enroll(&secret, &meta)?;
                Ok(ok())
            }
            "quick_remove" => {
                Self::vault_mut(g)?.quick_remove()?;
                Ok(ok())
            }
            "unlock_quick" => {
                Self::check_throttle(g)?;
                let secret = b64d(req_str(a, "secret")?).map_err(|_| bad())?;
                let r = Vault::unlock_quick(&g.vault_dir, &secret);
                Self::record_unlock_result(g, &r);
                Self::set_vault(g, r?);
                Ok(ok())
            }
            _ => Err(ApiError::NotFound),
        }
    }

    fn status(&self, g: &Inner) -> Value {
        let (sync, label) = match &g.sync {
            Some(t) => (
                vs(t.kind.name()),
                vs(&t
                    .path
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default()),
            ),
            None => (Value::Null, Value::Null),
        };
        obj(vec![
            ("exists", Value::Bool(Self::vault_exists(g))),
            (
                "unlocked",
                Value::Bool(g.vault.as_ref().is_some_and(|v| v.is_unlocked())),
            ),
            ("sync", sync),
            ("sync_label", label),
            ("can_pick", Value::Bool(self.cfg.can_pick_paths)),
            ("theme", vs(g.theme.name())),
            (
                "vault_custom",
                Value::Bool(g.vault_dir != self.cfg.vault_dir),
            ),
            (
                "vault_label",
                vs(&g
                    .vault_dir
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default()),
            ),
            (
                "idle_lock",
                num(g
                    .settings
                    .auto_lock
                    .unwrap_or(self.cfg.idle_lock.as_secs().max(1)) as i64),
            ),
            (
                "quick",
                Value::Bool(matches!(quick::info(&g.vault_dir), Ok(Some(_)))),
            ),
            (
                "settings",
                settings_value(&g.settings, self.cfg.idle_lock.as_secs().max(1)),
            ),
        ])
    }

    /// The sync target must not be (or live inside) the local vault directory.
    fn check_sync_path(g: &Inner, kind: SyncKind, path: &Path) -> Result<(), ApiError> {
        if sync_path_ok(&g.vault_dir, kind, path) {
            Ok(())
        } else {
            Err(ApiError::Bad(
                "choose an existing location outside the local vault".to_string(),
            ))
        }
    }
}

/// A sync target must not be (or live inside) the local vault directory, and a folder target
/// must already exist as a real directory.
fn sync_path_ok(vault_dir: &Path, kind: SyncKind, path: &Path) -> bool {
    let vault = vault_dir
        .canonicalize()
        .unwrap_or_else(|_| vault_dir.to_path_buf());
    let probe = if kind == SyncKind::Folder {
        path.to_path_buf()
    } else {
        path.parent().map(|p| p.to_path_buf()).unwrap_or_default()
    };
    let probe = probe.canonicalize().unwrap_or(probe);
    if probe.starts_with(&vault) {
        return false;
    }
    !(kind == SyncKind::Folder && !path.is_dir())
}

/// `ids` argument of the export commands: absent/null = everything, else 32-hex ids.
fn parse_ids(a: &JMap) -> Result<Option<std::collections::HashSet<String>>, ApiError> {
    match a.get("ids") {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Array(items)) if items.len() <= 100_000 => {
            let mut set = std::collections::HashSet::new();
            for i in items {
                match i.as_str() {
                    Some(x) if ctrlaltnotes_core::crypto::is_hex32(x) => {
                        set.insert(x.to_string());
                    }
                    _ => return Err(bad()),
                }
            }
            Ok(Some(set))
        }
        _ => Err(bad()),
    }
}

/// YYYY-MM-DD (UTC) for a unix timestamp.
fn civil_date(secs: i64) -> String {
    let z = secs.div_euclid(86_400) + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02}")
}

// ------------------------------------------------------------ JSON helpers
fn ok() -> Value {
    obj(vec![("ok", Value::Bool(true))])
}

fn num(n: i64) -> Value {
    ctrlaltnotes_core::json::vi(n)
}

fn obj(items: Vec<(&str, Value)>) -> Value {
    let mut m = Map::new();
    for (k, v) in items {
        m.insert(k.to_string(), v);
    }
    Value::Object(m)
}

fn opt_value(s: &Option<String>) -> Value {
    match s {
        Some(x) => vs(x),
        None => Value::Null,
    }
}

fn req_str<'a>(a: &'a JMap, k: &str) -> Result<&'a str, ApiError> {
    match a.get(k) {
        Some(Value::String(s)) => Ok(s.as_str()),
        _ => Err(bad()),
    }
}

fn opt_str<'a>(a: &'a JMap, k: &str) -> Result<Option<&'a str>, ApiError> {
    match a.get(k) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => Ok(Some(s.as_str())),
        _ => Err(bad()),
    }
}

/// Optional id: must look like a 32-hex object id.
fn opt_id<'a>(a: &'a JMap, k: &str) -> Result<Option<&'a str>, ApiError> {
    match opt_str(a, k)? {
        Some(s) if !ctrlaltnotes_core::crypto::is_hex32(s) => Err(bad()),
        other => Ok(other),
    }
}

fn entry_value(n: &NoteEntry) -> Value {
    obj(vec![
        ("id", vs(&n.id)),
        ("title", vs(&n.title)),
        ("modified", num(n.modified)),
    ])
}

fn folder_value(f: &FolderNode) -> Value {
    obj(vec![
        ("id", vs(&f.id)),
        ("name", vs(&f.name)),
        (
            "folders",
            Value::Array(f.folders.iter().map(folder_value).collect()),
        ),
        (
            "notes",
            Value::Array(f.notes.iter().map(entry_value).collect()),
        ),
    ])
}

fn tree_value(t: &Tree) -> Value {
    obj(vec![
        (
            "folders",
            Value::Array(t.folders.iter().map(folder_value).collect()),
        ),
        (
            "notes",
            Value::Array(t.notes.iter().map(entry_value).collect()),
        ),
    ])
}

/// Serialise a response exactly as sent to the UI (sorted keys, ASCII only).
pub fn to_json(v: &Value) -> String {
    String::from_utf8_lossy(&canonical(v)).into_owned()
}

// ------------------------------------------------------------ settings persistence
fn settings_value(st: &Settings, default_lock_secs: u64) -> Value {
    obj(vec![
        ("auto_sync", Value::Bool(st.auto_sync)),
        ("sync_interval", num(st.sync_interval as i64)),
        ("live_preview", Value::Bool(st.live_preview)),
        ("toolbar", Value::Bool(st.toolbar)),
        ("start_note", vs(&st.start_note)),
        (
            "auto_lock",
            num(st.auto_lock.unwrap_or(default_lock_secs) as i64),
        ),
    ])
}

fn load_settings(path: &Path) -> (Option<SyncTarget>, Settings) {
    let mut st = Settings::default();
    let Ok(raw) = read_capped(path, 65536) else {
        return (None, st);
    };
    let Ok(v) = serde_json::from_slice::<Value>(&raw) else {
        return (None, st);
    };
    let Some(m) = v.as_object() else {
        return (None, st);
    };
    if let Some(Value::Bool(b)) = m.get("auto_sync") {
        st.auto_sync = *b;
    }
    if let Some(Value::Bool(b)) = m.get("live_preview") {
        st.live_preview = *b;
    }
    if let Some(Value::Bool(b)) = m.get("toolbar") {
        st.toolbar = *b;
    }
    if let Some(x) = m.get("start_note").and_then(|x| x.as_str()) {
        if START_NOTE_VALUES.contains(&x) {
            st.start_note = x.to_string();
        }
    }
    if let Some(n) = m.get("auto_lock").and_then(|n| n.as_i64()) {
        if n == 0 || AUTO_LOCK_RANGE.contains(&n) {
            st.auto_lock = Some(n as u64);
        }
    }
    if let Some(n) = m.get("sync_interval").and_then(|n| n.as_i64()) {
        if (15..=3600).contains(&n) {
            st.sync_interval = n as u64;
        }
    }
    let target = (|| {
        let kind = SyncKind::parse(m.get("sync_kind")?.as_str()?)?;
        let p = m.get("sync_path")?.as_str()?;
        Some(SyncTarget {
            kind,
            path: PathBuf::from(p),
        })
    })();
    (target, st)
}

fn save_settings(path: &Path, t: Option<&SyncTarget>, st: &Settings) -> Result<(), ApiError> {
    if let Some(dir) = path.parent() {
        mkdir_private(dir)?;
    }
    let mut m = Map::new();
    if let Some(t) = t {
        let p = t
            .path
            .to_str()
            .ok_or_else(|| ApiError::Bad("unsupported path".to_string()))?;
        m.insert("sync_kind".to_string(), vs(t.kind.name()));
        m.insert("sync_path".to_string(), vs(p));
    }
    m.insert("auto_sync".to_string(), Value::Bool(st.auto_sync));
    m.insert("sync_interval".to_string(), num(st.sync_interval as i64));
    m.insert("live_preview".to_string(), Value::Bool(st.live_preview));
    m.insert("toolbar".to_string(), Value::Bool(st.toolbar));
    m.insert("start_note".to_string(), vs(&st.start_note));
    if let Some(n) = st.auto_lock {
        m.insert("auto_lock".to_string(), num(n as i64));
    }
    write_atomic(path, &canonical(&Value::Object(m)))?;
    Ok(())
}
