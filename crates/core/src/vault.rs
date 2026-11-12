// SPDX-License-Identifier: AGPL-3.0-only
//! Encrypted vault: notes (Markdown) organised in folders/subfolders.
//!
//! On disk (identical layout locally and in the synced cloud folder):
//!     vault.json            header: KDF params + wrapped master key (safe to be public)
//!     objects/<32hex>.can    one AEAD-sealed file per note / folder (random ids; no names leak)
//!     state.can              device-local sync state (never uploaded)
//! Folder names, note titles, Markdown bodies and the tree structure exist only inside sealed
//! objects. Nothing plaintext is ever written to disk (search is in-memory).

use crate::crypto::{
    self, b64d, b64e, hkdf, is_hex32, is_obj_name, normalize_password, random_bytes, Kdf,
    KdfParams, KDF_DEFAULT, TYPE_FOLDER, TYPE_NOTE, TYPE_STATE,
};
use crate::error::{cannot_unlock, corrupt, malformed, Result, VaultError};
use crate::fsutil::{mkdir_private, read_capped, write_atomic};
use crate::json::{canonical, get_bool, get_i64, get_str, vi, vs, JMap};
use serde_json::{Map, Value};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use unicode_normalization::UnicodeNormalization;
use zeroize::{Zeroize, Zeroizing};

pub const FORMAT: &str = "ctrlaltnotes-vault";
pub const VERSION: i64 = 1;
pub const MAX_BODY_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_NAME_CHARS: usize = 200;
pub const STATE_ID: &str = "00000000000000000000000000000000";
const MAX_HEADER_BYTES: usize = 65536;
const MAX_TREE_DEPTH: usize = 128;
/// New folders/moves may not nest deeper than this (display/export tolerate more).
const MAX_NEW_DEPTH: usize = 64;
const WIN_RESERVED: [&str; 22] = [
    "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
    "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
];

pub fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

// ---------------------------------------------------------------- header
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Header {
    pub format: String,
    pub version: i64,
    pub vault_id: String,
    pub header_rev: i64,
    pub kdf: Kdf,
    pub wrap_pw: String,
    pub wrap_rec: String,
}

fn kdf_value(k: &Kdf) -> Value {
    let mut m = Map::new();
    m.insert("alg".to_string(), vs(&k.alg));
    m.insert("m".to_string(), vi(k.m as i64));
    m.insert("t".to_string(), vi(k.t as i64));
    m.insert("p".to_string(), vi(k.p as i64));
    m.insert("salt".to_string(), vs(&k.salt));
    Value::Object(m)
}

fn header_value(h: &Header) -> Value {
    let mut m = Map::new();
    m.insert("format".to_string(), vs(&h.format));
    m.insert("version".to_string(), vi(h.version));
    m.insert("vault_id".to_string(), vs(&h.vault_id));
    m.insert("header_rev".to_string(), vi(h.header_rev));
    m.insert("kdf".to_string(), kdf_value(&h.kdf));
    m.insert("wrap_pw".to_string(), vs(&h.wrap_pw));
    m.insert("wrap_rec".to_string(), vs(&h.wrap_rec));
    Value::Object(m)
}

/// Is a not-yet-authenticated header from the sync folder plausible enough to even try?
/// Rejects absurd revisions and KDF costs above both our current and the default cost, so a
/// hostile file cannot make unlock burn gigabytes of Argon2 memory or pin the remote header.
pub(crate) fn pending_acceptable(candidate: &Header, current: &Header) -> bool {
    let c = &candidate.kdf;
    let k = &current.kdf;
    candidate.vault_id == current.vault_id
        && candidate.header_rev > current.header_rev
        && candidate.header_rev <= current.header_rev + 1000
        && c.m <= k.m.max(crypto::KDF_DEFAULT.m)
        && c.t <= k.t.max(crypto::KDF_DEFAULT.t)
        && c.p <= k.p.max(crypto::KDF_DEFAULT.p)
}

pub fn header_bytes(h: &Header) -> Vec<u8> {
    canonical(&header_value(h))
}

/// AAD for the two key wraps. Covers format, version, vault id, revision and KDF params, so
/// downgrading the KDF or transplanting another vault's header makes unwrap fail.
fn header_aad(h: &Header, label: &[u8]) -> Vec<u8> {
    let mut m = Map::new();
    m.insert("format".to_string(), vs(&h.format));
    m.insert("version".to_string(), vi(h.version));
    m.insert("vault_id".to_string(), vs(&h.vault_id));
    m.insert("header_rev".to_string(), vi(h.header_rev));
    m.insert("kdf".to_string(), kdf_value(&h.kdf));
    let mut out = canonical(&Value::Object(m));
    out.extend_from_slice(label);
    out
}

pub fn parse_header(raw: &[u8]) -> Result<Header> {
    let bad = || VaultError::other("malformed vault header");
    if raw.len() > MAX_HEADER_BYTES {
        return Err(bad());
    }
    let v: Value = serde_json::from_slice(raw).map_err(|_| bad())?;
    let m = v.as_object().ok_or_else(bad)?;
    if get_str(m, "format") != Some(FORMAT) || get_i64(m, "version") != Some(VERSION) {
        return Err(VaultError::other("unsupported vault"));
    }
    let vault_id = get_str(m, "vault_id").ok_or_else(bad)?;
    if !is_hex32(vault_id) {
        return Err(bad());
    }
    let header_rev = get_i64(m, "header_rev").ok_or_else(bad)?;
    if header_rev < 0 {
        return Err(bad());
    }
    let km: &JMap = m.get("kdf").and_then(|k| k.as_object()).ok_or_else(bad)?;
    let alg = get_str(km, "alg").unwrap_or("");
    let (mi, ti, pi) = (
        get_i64(km, "m").unwrap_or(-1),
        get_i64(km, "t").unwrap_or(-1),
        get_i64(km, "p").unwrap_or(-1),
    );
    let kp = crypto::validate_kdf(alg, mi, ti, pi)?;
    let salt = get_str(km, "salt").ok_or_else(bad)?;
    if b64d(salt)?.len() < 16 {
        return Err(bad());
    }
    let wrap_pw = get_str(m, "wrap_pw").ok_or_else(bad)?;
    let wrap_rec = get_str(m, "wrap_rec").ok_or_else(bad)?;
    b64d(wrap_pw)?;
    b64d(wrap_rec)?;
    Ok(Header {
        format: FORMAT.to_string(),
        version: VERSION,
        vault_id: vault_id.to_string(),
        header_rev,
        kdf: Kdf {
            alg: "argon2id".to_string(),
            m: kp.m,
            t: kp.t,
            p: kp.p,
            salt: salt.to_string(),
        },
        wrap_pw: wrap_pw.to_string(),
        wrap_rec: wrap_rec.to_string(),
    })
}

// ---------------------------------------------------------------- recovery key
const B32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

fn b32_encode(data: &[u8]) -> String {
    let mut out = String::new();
    let mut buf: u32 = 0;
    let mut bits: u32 = 0;
    for &b in data {
        buf = (buf << 8) | b as u32;
        bits += 8;
        while bits >= 5 {
            out.push(B32[((buf >> (bits - 5)) & 31) as usize] as char);
            bits -= 5;
        }
        buf &= (1u32 << bits) - 1;
    }
    if bits > 0 {
        out.push(B32[((buf << (5 - bits)) & 31) as usize] as char);
    }
    out
}

fn b32_decode(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut buf: u32 = 0;
    let mut bits: u32 = 0;
    for c in s.bytes() {
        let v = B32.iter().position(|&x| x == c)? as u32;
        buf = (buf << 5) | v;
        bits += 5;
        if bits >= 8 {
            out.push((buf >> (bits - 8)) as u8);
            bits -= 8;
            buf &= (1u32 << bits) - 1;
        }
    }
    Some(out)
}

fn fmt_recovery(raw: &[u8]) -> String {
    let s = b32_encode(raw);
    s.as_bytes()
        .chunks(4)
        .map(|c| String::from_utf8_lossy(c).into_owned())
        .collect::<Vec<_>>()
        .join("-")
}

fn recovery_kek(recovery_key: &str, vault_id: &str) -> Result<Zeroizing<[u8; 32]>> {
    let cleaned: String = recovery_key
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .flat_map(|c| c.to_uppercase())
        .collect();
    let raw = Zeroizing::new(b32_decode(&cleaned).ok_or_else(cannot_unlock)?);
    if raw.len() != 32 {
        return Err(cannot_unlock());
    }
    let vid = hex::decode(vault_id).map_err(|_| malformed())?;
    Ok(hkdf(&raw, &vid, b"ctrlaltnotes/v1/recovery"))
}

fn unwrap_with(
    h: &Header,
    password: Option<&str>,
    recovery_key: Option<&str>,
) -> Result<Zeroizing<[u8; 32]>> {
    if let Some(pw) = password {
        let kek = crypto::derive_kek(pw, &b64d(&h.kdf.salt)?, &h.kdf)?;
        return crypto::unwrap_key(&kek[..], &b64d(&h.wrap_pw)?, &header_aad(h, b"pw"));
    }
    if let Some(rk) = recovery_key {
        let kek = recovery_kek(rk, &h.vault_id)?;
        return crypto::unwrap_key(&kek[..], &b64d(&h.wrap_rec)?, &header_aad(h, b"rec"));
    }
    Err(cannot_unlock())
}

fn build_header(
    vault_id: &str,
    rev: i64,
    kp: KdfParams,
    mk: &[u8],
    password: &str,
    rec_raw: &[u8],
) -> Result<Header> {
    let kdf = Kdf {
        alg: "argon2id".to_string(),
        m: kp.m,
        t: kp.t,
        p: kp.p,
        salt: b64e(&random_bytes::<16>()),
    };
    kdf.params()?; // validate (floor / ceiling) before spending time on Argon2
    let mut h = Header {
        format: FORMAT.to_string(),
        version: VERSION,
        vault_id: vault_id.to_string(),
        header_rev: rev,
        kdf,
        wrap_pw: String::new(),
        wrap_rec: String::new(),
    };
    let kek = crypto::derive_kek(password, &b64d(&h.kdf.salt)?, &h.kdf)?;
    h.wrap_pw = b64e(&crypto::wrap_key(&kek[..], mk, &header_aad(&h, b"pw"))?);
    let vid = hex::decode(vault_id).map_err(|_| malformed())?;
    let rkek = hkdf(rec_raw, &vid, b"ctrlaltnotes/v1/recovery");
    h.wrap_rec = b64e(&crypto::wrap_key(&rkek[..], mk, &header_aad(&h, b"rec"))?);
    Ok(h)
}

// ---------------------------------------------------------------- objects
/// A note or a folder (decrypted form).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Obj {
    pub id: String,
    /// "note" or "folder"
    pub kind: String,
    pub parent: Option<String>,
    pub title: Option<String>, // notes
    pub body: Option<String>,  // notes
    pub name: Option<String>,  // folders
    pub deleted: bool,
    pub created: i64,
    pub modified: i64,
    /// Hybrid logical clock: (wall ms, counter, device id)
    pub hlc: (i64, i64, String),
}

impl Obj {
    pub fn to_value(&self) -> Value {
        let mut m = Map::new();
        m.insert("id".to_string(), vs(&self.id));
        m.insert("type".to_string(), vs(&self.kind));
        m.insert(
            "parent".to_string(),
            match &self.parent {
                Some(p) => vs(p),
                None => Value::Null,
            },
        );
        if let Some(t) = &self.title {
            m.insert("title".to_string(), vs(t));
        }
        if let Some(b) = &self.body {
            m.insert("body".to_string(), vs(b));
        }
        if let Some(n) = &self.name {
            m.insert("name".to_string(), vs(n));
        }
        m.insert("deleted".to_string(), Value::Bool(self.deleted));
        m.insert("created".to_string(), vi(self.created));
        m.insert("modified".to_string(), vi(self.modified));
        m.insert(
            "hlc".to_string(),
            Value::Array(vec![vi(self.hlc.0), vi(self.hlc.1), vs(&self.hlc.2)]),
        );
        Value::Object(m)
    }

    /// Strict validation (defence in depth: only holders of the key can author these).
    fn from_value(v: &Value, typ: u8, oid: &str) -> Result<Obj> {
        let m = v.as_object().ok_or_else(corrupt)?;
        let kind = if typ == TYPE_NOTE { "note" } else { "folder" };
        if get_str(m, "type") != Some(kind) || get_str(m, "id") != Some(oid) {
            return Err(corrupt());
        }
        let parent = match m.get("parent") {
            None | Some(Value::Null) => None,
            Some(Value::String(s)) if is_hex32(s) => Some(s.clone()),
            _ => return Err(corrupt()),
        };
        let name_ok = |s: &str| s.chars().count() <= MAX_NAME_CHARS;
        let (mut title, mut body, mut name) = (None, None, None);
        if kind == "note" {
            let t = get_str(m, "title").ok_or_else(corrupt)?;
            let b = get_str(m, "body").ok_or_else(corrupt)?;
            if !name_ok(t) || b.len() > MAX_BODY_BYTES {
                return Err(corrupt());
            }
            title = Some(t.to_string());
            body = Some(b.to_string());
        } else {
            let n = get_str(m, "name").ok_or_else(corrupt)?;
            if !name_ok(n) {
                return Err(corrupt());
            }
            name = Some(n.to_string());
        }
        let deleted = get_bool(m, "deleted").ok_or_else(corrupt)?;
        let created = get_i64(m, "created").ok_or_else(corrupt)?;
        let modified = get_i64(m, "modified").ok_or_else(corrupt)?;
        let hv = m
            .get("hlc")
            .and_then(|h| h.as_array())
            .ok_or_else(corrupt)?;
        if hv.len() != 3 {
            return Err(corrupt());
        }
        let hlc = (
            hv[0].as_i64().ok_or_else(corrupt)?,
            hv[1].as_i64().ok_or_else(corrupt)?,
            hv[2].as_str().ok_or_else(corrupt)?.to_string(),
        );
        if hlc.2.chars().count() > 64 {
            return Err(corrupt());
        }
        Ok(Obj {
            id: oid.to_string(),
            kind: kind.to_string(),
            parent,
            title,
            body,
            name,
            deleted,
            created,
            modified,
            hlc,
        })
    }

    fn typ(&self) -> u8 {
        if self.kind == "note" {
            TYPE_NOTE
        } else {
            TYPE_FOLDER
        }
    }
}

fn clean_name(name: &str, what: &str) -> Result<String> {
    let n = name.trim();
    if n.chars().count() > MAX_NAME_CHARS || n.chars().any(|c| (c as u32) < 32 || c as u32 == 127) {
        return Err(VaultError::other(format!("invalid {what}")));
    }
    Ok(if n.is_empty() {
        "Untitled".to_string()
    } else {
        n.to_string()
    })
}

// ---------------------------------------------------------------- device-local sync state
#[derive(Clone, Debug, Default)]
pub(crate) struct SyncState {
    pub device_id: String,
    pub hlc: (i64, i64),
    pub synced: BTreeMap<String, (i64, i64, String)>,
}

impl SyncState {
    fn to_value(&self) -> Value {
        let mut m = Map::new();
        m.insert("device_id".to_string(), vs(&self.device_id));
        m.insert(
            "hlc".to_string(),
            Value::Array(vec![vi(self.hlc.0), vi(self.hlc.1)]),
        );
        let mut s = Map::new();
        for (k, (a, b, c)) in &self.synced {
            s.insert(k.clone(), Value::Array(vec![vi(*a), vi(*b), vs(c)]));
        }
        m.insert("synced".to_string(), Value::Object(s));
        Value::Object(m)
    }

    fn from_value(v: &Value) -> SyncState {
        let mut st = SyncState::default();
        let Some(m) = v.as_object() else { return st };
        if let Some(d) = get_str(m, "device_id") {
            st.device_id = d.chars().take(64).collect();
        }
        if let Some(h) = m.get("hlc").and_then(|h| h.as_array()) {
            if h.len() == 2 {
                if let (Some(a), Some(b)) = (h[0].as_i64(), h[1].as_i64()) {
                    st.hlc = (a, b);
                }
            }
        }
        if let Some(s) = m.get("synced").and_then(|s| s.as_object()) {
            for (k, val) in s.iter() {
                if !is_hex32(k) {
                    continue;
                }
                if let Some(a) = val.as_array() {
                    if a.len() == 3 {
                        if let (Some(x), Some(y), Some(z)) =
                            (a[0].as_i64(), a[1].as_i64(), a[2].as_str())
                        {
                            st.synced.insert(k.clone(), (x, y, z.to_string()));
                        }
                    }
                }
            }
        }
        st
    }
}

// ---------------------------------------------------------------- public result types
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NoteEntry {
    pub id: String,
    pub title: String,
    pub modified: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FolderNode {
    pub id: String,
    pub name: String,
    pub folders: Vec<FolderNode>,
    pub notes: Vec<NoteEntry>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Tree {
    pub folders: Vec<FolderNode>,
    pub notes: Vec<NoteEntry>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NoteData {
    pub id: String,
    pub title: String,
    pub body: String,
    pub parent: Option<String>,
    pub created: i64,
    pub modified: i64,
}

// ---------------------------------------------------------------- the vault
pub struct Vault {
    pub(crate) root: PathBuf,
    pub(crate) mk: Option<Zeroizing<[u8; 32]>>,
    pub(crate) header: Header,
    pub(crate) state: SyncState,
    pub(crate) objs: BTreeMap<String, Obj>,
    new_recovery: Option<String>,
}

impl Vault {
    // ------------------------------------------------------------ lifecycle
    pub(crate) fn open_with_key(
        root: &Path,
        mk: Zeroizing<[u8; 32]>,
        header: Header,
    ) -> Result<Vault> {
        let mut v = Vault {
            root: root.to_path_buf(),
            mk: Some(mk),
            header,
            state: SyncState::default(),
            objs: BTreeMap::new(),
            new_recovery: None,
        };
        v.load_state()?;
        v.reload()?;
        Ok(v)
    }

    /// Create a brand-new vault. Returns the vault and the **recovery key** (show it once).
    pub fn create(path: &Path, password: &str, kdf: Option<KdfParams>) -> Result<(Vault, String)> {
        if path.join("vault.json").exists() {
            return Err(VaultError::other("vault already exists"));
        }
        normalize_password(password)?; // fail fast on a bad password, before touching disk
        mkdir_private(path)?;
        mkdir_private(&path.join("objects"))?;
        let mk = Zeroizing::new(random_bytes::<32>());
        let rec_raw = Zeroizing::new(random_bytes::<32>());
        let vault_id = hex::encode(random_bytes::<16>());
        let header = build_header(
            &vault_id,
            1,
            kdf.unwrap_or(KDF_DEFAULT),
            &mk[..],
            password,
            &rec_raw[..],
        )?;
        write_atomic(&path.join("vault.json"), &header_bytes(&header))?;
        let v = Vault::open_with_key(path, mk, header)?;
        Ok((v, fmt_recovery(&rec_raw[..])))
    }

    /// Unlock with the password or the recovery key.
    pub fn unlock(
        path: &Path,
        password: Option<&str>,
        recovery_key: Option<&str>,
    ) -> Result<Vault> {
        let mut header = parse_header(&read_capped(&path.join("vault.json"), MAX_HEADER_BYTES)?)?;
        let pending = path.join("vault.json.pending");
        let mut mk: Option<Zeroizing<[u8; 32]>> = None;
        if pending.exists() {
            // A header from a password change made on another device: adopt it only if it
            // authenticates under the user's own secret.
            if let Ok(raw) = read_capped(&pending, MAX_HEADER_BYTES) {
                if let Ok(ph) = parse_header(&raw) {
                    if pending_acceptable(&ph, &header) {
                        if let Ok(k) = unwrap_with(&ph, password, recovery_key) {
                            write_atomic(&path.join("vault.json"), &header_bytes(&ph))?;
                            let _ = fs::remove_file(&pending);
                            header = ph;
                            mk = Some(k);
                        }
                    }
                }
            }
        }
        let mk = match mk {
            Some(k) => k,
            None => unwrap_with(&header, password, recovery_key)?,
        };
        Vault::open_with_key(path, mk, header)
    }

    /// Set up a new device from a synced cloud folder that already contains a vault.
    pub fn join(path: &Path, remote_dir: &Path, password: &str) -> Result<Vault> {
        let raw = read_capped(&remote_dir.join("vault.json"), MAX_HEADER_BYTES)?;
        parse_header(&raw)?;
        if path.join("vault.json").exists() {
            return Err(VaultError::other("vault already exists"));
        }
        mkdir_private(path)?;
        mkdir_private(&path.join("objects"))?;
        write_atomic(&path.join("vault.json"), &raw)?;
        match Vault::unlock(path, Some(password), None) {
            Ok(v) => Ok(v),
            Err(e) => {
                let _ = fs::remove_file(path.join("vault.json"));
                Err(e)
            }
        }
    }

    /// Wipe the key (guaranteed by `zeroize`) and all decrypted content from memory.
    pub fn lock(&mut self) {
        self.mk = None; // Zeroizing<[u8;32]> wipes on drop
        for o in self.objs.values_mut() {
            if let Some(b) = o.body.as_mut() {
                b.zeroize();
            }
            if let Some(t) = o.title.as_mut() {
                t.zeroize();
            }
            if let Some(n) = o.name.as_mut() {
                n.zeroize();
            }
        }
        self.objs.clear();
        self.state = SyncState::default();
        self.new_recovery = None;
    }

    pub fn is_unlocked(&self) -> bool {
        self.mk.is_some()
    }

    pub(crate) fn key(&self) -> Result<Zeroizing<[u8; 32]>> {
        match &self.mk {
            Some(k) => Ok(Zeroizing::new(**k)),
            None => Err(VaultError::other("vault is locked")),
        }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn header(&self) -> &Header {
        &self.header
    }

    pub fn objects_dir(&self) -> PathBuf {
        self.root.join("objects")
    }

    /// All decrypted objects (including tombstones). Empty while locked.
    pub fn objects(&self) -> &BTreeMap<String, Obj> {
        &self.objs
    }

    // ------------------------------------------------------------ credentials
    /// Re-authenticate: true only if `password` is the vault password (used before adding
    /// a new way to unlock). Costs one Argon2 evaluation.
    pub fn verify_password(&self, password: &str) -> Result<()> {
        self.key()?;
        unwrap_with(&self.header, Some(password), None).map(|_| ())
    }

    /// Re-wrap the master key under a new password; no object is re-encrypted (O(1)).
    /// A NEW recovery key is issued (see `new_recovery_key`).
    pub fn change_password(
        &mut self,
        old_password: &str,
        new_password: &str,
        kdf: Option<KdfParams>,
    ) -> Result<()> {
        let key = self.key()?; // must be unlocked
        unwrap_with(&self.header, Some(old_password), None)?; // proves possession of old password
        let rec_raw = Zeroizing::new(random_bytes::<32>());
        let kp = match kdf {
            Some(k) => k,
            None => self.header.kdf.params()?,
        };
        let new = build_header(
            &self.header.vault_id,
            self.header.header_rev + 1,
            kp,
            &key[..],
            new_password,
            &rec_raw[..],
        )?;
        write_atomic(&self.root.join("vault.json"), &header_bytes(&new))?;
        // A password change is usually a response to a suspected leak: drop every quick-unlock
        // slot (security key / biometrics) so it has to be re-enrolled on purpose.
        crate::quick::remove(&self.root)?;
        self.header = new;
        self.new_recovery = Some(fmt_recovery(&rec_raw[..]));
        Ok(())
    }

    /// Recovery key issued by the last `change_password` (show once, then discard).
    pub fn new_recovery_key(&self) -> Option<&str> {
        self.new_recovery.as_deref()
    }

    // ------------------------------------------------------------ persistence
    fn load_state(&mut self) -> Result<()> {
        let key = self.key()?;
        let p = self.root.join("state.can");
        let mut st = SyncState::default();
        if p.exists() {
            if let Ok(data) = read_capped(&p, crypto::MAX_FILE_BYTES) {
                if let Ok((typ, oid, val)) = crypto::open_sealed(&key[..], &data) {
                    if typ == TYPE_STATE && oid == STATE_ID {
                        st = SyncState::from_value(&val);
                    }
                }
            }
        }
        if st.device_id.is_empty() {
            st.device_id = hex::encode(random_bytes::<4>());
        }
        self.state = st;
        Ok(())
    }

    pub(crate) fn save_state(&self) -> Result<()> {
        let key = self.key()?;
        let sealed = crypto::seal(&key[..], TYPE_STATE, STATE_ID, &self.state.to_value())?;
        write_atomic(&self.root.join("state.can"), &sealed)
    }

    /// Authenticate + decrypt + validate one object file.
    pub fn read_object_file(&self, path: &Path) -> Result<Obj> {
        let data = read_capped(path, crypto::MAX_FILE_BYTES)?;
        let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("");
        self.parse_object_bytes(stem, &data)
    }

    /// Authenticate + decrypt + validate already-loaded object bytes whose file name stem is
    /// `stem`. Sync uses this so the bytes it verifies are exactly the bytes it later copies.
    pub fn parse_object_bytes(&self, stem: &str, data: &[u8]) -> Result<Obj> {
        let key = self.key()?;
        let (typ, oid, val) = crypto::open_sealed(&key[..], data)?;
        // anti file-swap / rename: the id inside the AEAD-protected header must match the name
        if typ == TYPE_STATE || stem != oid {
            return Err(corrupt());
        }
        Obj::from_value(&val, typ, &oid)
    }

    /// (Re)load all objects from disk. Returns the names of unreadable files.
    pub fn reload(&mut self) -> Result<Vec<String>> {
        self.key()?;
        self.objs.clear();
        let mut bad = Vec::new();
        let dir = self.objects_dir();
        if dir.is_dir() {
            let mut names: Vec<String> = fs::read_dir(&dir)?
                .filter_map(|e| e.ok())
                .filter_map(|e| e.file_name().into_string().ok())
                .collect();
            names.sort();
            for n in names {
                if !is_obj_name(&n) {
                    continue;
                }
                match self.read_object_file(&dir.join(&n)) {
                    Ok(o) => {
                        self.objs.insert(o.id.clone(), o);
                    }
                    Err(_) => bad.push(n),
                }
            }
        }
        Ok(bad)
    }

    pub(crate) fn object_bytes(&self, oid: &str) -> Result<Vec<u8>> {
        if !is_hex32(oid) {
            return Err(VaultError::other("bad object id"));
        }
        read_capped(
            &self.objects_dir().join(format!("{oid}.can")),
            crypto::MAX_FILE_BYTES,
        )
    }

    pub(crate) fn store_raw(&self, oid: &str, data: &[u8]) -> Result<()> {
        if !is_hex32(oid) {
            return Err(VaultError::other("bad object id"));
        }
        write_atomic(&self.objects_dir().join(format!("{oid}.can")), data)
    }

    // ------------------------------------------------------------ hybrid logical clock
    fn tick(&mut self) -> (i64, i64, String) {
        let (w, c) = self.state.hlc;
        let now = now_ms();
        let (w2, c2) = if now > w { (now, 0) } else { (w, c + 1) };
        self.state.hlc = (w2, c2);
        (w2, c2, self.state.device_id.clone())
    }

    pub(crate) fn observe_hlc(&mut self, h: &(i64, i64, String)) {
        if (h.0, h.1) > self.state.hlc {
            self.state.hlc = (h.0, h.1);
        }
    }

    fn put(&mut self, mut o: Obj) -> Result<Obj> {
        let key = self.key()?; // refuse (error) when locked, before touching any state
        o.hlc = self.tick();
        o.modified = o.hlc.0;
        let sealed = crypto::seal(&key[..], o.typ(), &o.id, &o.to_value())?;
        self.store_raw(&o.id, &sealed)?;
        self.objs.insert(o.id.clone(), o.clone());
        self.save_state()?;
        Ok(o)
    }

    // ------------------------------------------------------------ tree operations
    fn live(&self, oid: Option<&str>, kind: &str) -> Result<&Obj> {
        self.key()?;
        match oid.and_then(|i| self.objs.get(i)) {
            Some(o) if !o.deleted && o.kind == kind => Ok(o),
            _ => Err(VaultError::other(format!("{kind} not found"))),
        }
    }

    fn check_parent(&self, parent: Option<&str>) -> Result<()> {
        self.key()?; // every mutator calls this first: locked vault => error
        if let Some(p) = parent {
            self.live(Some(p), "folder")?;
            let mut depth = 1usize;
            let mut cur = self.objs.get(p).and_then(|o| o.parent.as_deref());
            while let Some(c) = cur {
                depth += 1;
                if depth > MAX_NEW_DEPTH {
                    return Err(VaultError::other("folders are nested too deeply"));
                }
                cur = self.objs.get(c).and_then(|o| o.parent.as_deref());
            }
        }
        Ok(())
    }

    pub fn create_folder(&mut self, name: &str, parent: Option<&str>) -> Result<String> {
        self.check_parent(parent)?;
        let id = hex::encode(random_bytes::<16>());
        let now = now_ms();
        self.put(Obj {
            id: id.clone(),
            kind: "folder".to_string(),
            parent: parent.map(|p| p.to_string()),
            title: None,
            body: None,
            name: Some(clean_name(name, "name")?),
            deleted: false,
            created: now,
            modified: now,
            hlc: (0, 0, String::new()),
        })?;
        Ok(id)
    }

    pub fn create_note(&mut self, title: &str, body: &str, parent: Option<&str>) -> Result<String> {
        self.check_parent(parent)?;
        if body.len() > MAX_BODY_BYTES {
            return Err(VaultError::other("note too large"));
        }
        let id = hex::encode(random_bytes::<16>());
        let now = now_ms();
        self.put(Obj {
            id: id.clone(),
            kind: "note".to_string(),
            parent: parent.map(|p| p.to_string()),
            title: Some(clean_name(title, "title")?),
            body: Some(body.to_string()),
            name: None,
            deleted: false,
            created: now,
            modified: now,
            hlc: (0, 0, String::new()),
        })?;
        Ok(id)
    }

    pub fn get_note(&self, oid: &str) -> Result<NoteData> {
        let n = self.live(Some(oid), "note")?;
        Ok(NoteData {
            id: n.id.clone(),
            title: n.title.clone().unwrap_or_default(),
            body: n.body.clone().unwrap_or_default(),
            parent: n.parent.clone(),
            created: n.created,
            modified: n.modified,
        })
    }

    pub fn update_note(
        &mut self,
        oid: &str,
        body: Option<&str>,
        title: Option<&str>,
    ) -> Result<()> {
        let mut n = self.live(Some(oid), "note")?.clone();
        if let Some(b) = body {
            if b.len() > MAX_BODY_BYTES {
                return Err(VaultError::other("note too large"));
            }
            n.body = Some(b.to_string());
        }
        if let Some(t) = title {
            n.title = Some(clean_name(t, "title")?);
        }
        self.put(n)?;
        Ok(())
    }

    pub fn rename_folder(&mut self, oid: &str, name: &str) -> Result<()> {
        let mut f = self.live(Some(oid), "folder")?.clone();
        f.name = Some(clean_name(name, "name")?);
        self.put(f)?;
        Ok(())
    }

    pub fn move_item(&mut self, oid: &str, new_parent: Option<&str>) -> Result<()> {
        self.key()?;
        let o = match self.objs.get(oid) {
            Some(o) if !o.deleted => o.clone(),
            _ => return Err(VaultError::other("not found")),
        };
        self.check_parent(new_parent)?;
        if o.kind == "folder" {
            // cycle prevention: walk up from the destination
            let mut cur: Option<String> = new_parent.map(|s| s.to_string());
            let mut guard = 0usize;
            while let Some(c) = cur {
                if c == oid {
                    return Err(VaultError::other("cannot move a folder into itself"));
                }
                guard += 1;
                if guard > 10_000 {
                    return Err(VaultError::other("folder tree too deep"));
                }
                cur = self.objs.get(&c).and_then(|x| x.parent.clone());
            }
        }
        let mut o = o;
        o.parent = new_parent.map(|s| s.to_string());
        self.put(o)?;
        Ok(())
    }

    /// Tombstone (needed so deletes sync). Content is wiped from the tombstone.
    pub fn delete(&mut self, oid: &str) -> Result<()> {
        self.key()?;
        match self.objs.get(oid) {
            Some(o) if !o.deleted => {}
            _ => return Err(VaultError::other("not found")),
        }
        let mut todo = vec![oid.to_string()];
        let mut seen: Vec<String> = Vec::new();
        let mut seen_set: HashSet<String> = HashSet::new();
        while let Some(cur) = todo.pop() {
            if !seen_set.insert(cur.clone()) {
                continue;
            }
            seen.push(cur.clone());
            for (i, c) in &self.objs {
                if c.parent.as_deref() == Some(cur.as_str()) && !c.deleted {
                    todo.push(i.clone());
                }
            }
        }
        for i in seen {
            let mut t = match self.objs.get(&i) {
                Some(x) => x.clone(),
                None => continue,
            };
            t.deleted = true;
            if t.kind == "note" {
                t.body = Some(String::new());
                t.title = Some(String::new());
            } else {
                t.name = Some(String::new());
            }
            self.put(t)?;
        }
        Ok(())
    }

    pub fn list_tree(&self) -> Result<Tree> {
        self.key()?;
        let live: Vec<&Obj> = self.objs.values().filter(|o| !o.deleted).collect();
        let folders: HashSet<&str> = live
            .iter()
            .filter(|o| o.kind == "folder")
            .map(|o| o.id.as_str())
            .collect();
        let eff = effective_parents(&live, &folders);
        let (f, n) = build_tree(&live, &folders, &eff, None, 0);
        Ok(Tree {
            folders: f,
            notes: n,
        })
    }

    /// In-memory only. No plaintext index is ever persisted.
    pub fn search(&self, query: &str) -> Result<Vec<NoteEntry>> {
        self.key()?;
        let q = query.to_lowercase();
        let mut hits: Vec<NoteEntry> = self
            .objs
            .values()
            .filter(|o| o.kind == "note" && !o.deleted)
            .filter(|o| {
                o.title.as_deref().unwrap_or("").to_lowercase().contains(&q)
                    || o.body.as_deref().unwrap_or("").to_lowercase().contains(&q)
            })
            .map(|o| NoteEntry {
                id: o.id.clone(),
                title: o.title.clone().unwrap_or_default(),
                modified: o.modified,
            })
            .collect();
        hits.sort_by_cached_key(|a| a.title.to_lowercase());
        Ok(hits)
    }

    // ------------------------------------------------------------ plaintext export
    /// Write a plaintext `.md` tree. Names are sanitised so nothing can escape `dest`.
    /// `selected = None` exports everything; otherwise only the listed notes/folders
    /// (a selected folder includes everything inside it; ancestors are created as needed).
    /// WARNING: the result is NOT encrypted.
    pub fn export_markdown(&self, dest: &Path) -> Result<usize> {
        self.export_selected(dest, None)
    }

    pub fn export_selected(
        &self,
        dest: &Path,
        selected: Option<&HashSet<String>>,
    ) -> Result<usize> {
        self.key()?;
        let tree = self.list_tree()?;
        let (folders, notes) = match selected {
            None => (tree.folders, tree.notes),
            Some(sel) => {
                if sel.is_empty() {
                    return Err(VaultError::other("nothing selected"));
                }
                prune(&tree.folders, &tree.notes, sel, false)
            }
        };
        mkdir_private(dest)?;
        let dest = dest.canonicalize()?;
        let mut count = 0usize;
        self.export_node(&folders, &notes, &dest, &dest, &mut count, 0)?;
        Ok(count)
    }

    /// The same selection as `export_selected`, but as in-memory entries (`name/` = folder)
    /// for the web version's download. Names are sanitised and unique exactly like on disk.
    pub fn export_entries(
        &self,
        selected: Option<&HashSet<String>>,
    ) -> Result<Vec<(String, Vec<u8>)>> {
        self.key()?;
        let tree = self.list_tree()?;
        let (folders, notes) = match selected {
            None => (tree.folders, tree.notes),
            Some(sel) => {
                if sel.is_empty() {
                    return Err(VaultError::other("nothing selected"));
                }
                prune(&tree.folders, &tree.notes, sel, false)
            }
        };
        let mut out = Vec::new();
        let mut total = 0usize;
        self.collect_node(&folders, &notes, "", &mut out, &mut total, 0)?;
        Ok(out)
    }

    fn collect_node(
        &self,
        folders: &[FolderNode],
        notes: &[NoteEntry],
        prefix: &str,
        out: &mut Vec<(String, Vec<u8>)>,
        total: &mut usize,
        depth: usize,
    ) -> Result<()> {
        if depth > MAX_TREE_DEPTH {
            return Err(VaultError::other("folder tree too deep"));
        }
        let mut used: HashSet<String> = HashSet::new();
        for f in folders {
            let name = safe_name(&f.name, "", None, &mut used);
            let sub = format!("{prefix}{name}/");
            out.push((sub.clone(), Vec::new()));
            self.collect_node(&f.folders, &f.notes, &sub, out, total, depth + 1)?;
        }
        for n in notes {
            let name = safe_name(&n.title, ".md", None, &mut used);
            let body = self
                .objs
                .get(&n.id)
                .and_then(|o| o.body.clone())
                .unwrap_or_default();
            *total += body.len();
            if *total > 32 * 1024 * 1024 {
                return Err(VaultError::other("the selection is too large to download"));
            }
            out.push((format!("{prefix}{name}.md"), body.into_bytes()));
        }
        Ok(())
    }

    fn export_node(
        &self,
        folders: &[FolderNode],
        notes: &[NoteEntry],
        dir: &Path,
        root: &Path,
        count: &mut usize,
        depth: usize,
    ) -> Result<()> {
        if depth > MAX_TREE_DEPTH {
            return Err(VaultError::other("folder tree too deep"));
        }
        // Names already on disk count as taken (case-insensitively: macOS/Windows volumes are),
        // so an export can never overwrite or merge into what is there.
        let mut used: HashSet<String> = fs::read_dir(dir)
            .map(|rd| {
                rd.filter_map(|e| e.ok())
                    .map(|e| e.file_name().to_string_lossy().to_lowercase())
                    .collect()
            })
            .unwrap_or_default();
        for f in folders {
            let sub = dir.join(safe_name(&f.name, "", Some(dir), &mut used));
            mkdir_private(&sub)?;
            self.export_node(&f.folders, &f.notes, &sub, root, count, depth + 1)?;
        }
        for n in notes {
            let file = dir.join(format!(
                "{}.md",
                safe_name(&n.title, ".md", Some(dir), &mut used)
            ));
            if file.parent() != Some(dir) || !file.starts_with(root) {
                return Err(VaultError::other("unsafe export path"));
            }
            let body = self
                .objs
                .get(&n.id)
                .and_then(|o| o.body.clone())
                .unwrap_or_default();
            write_atomic(&file, body.as_bytes())?;
            *count += 1;
        }
        Ok(())
    }
}

impl Drop for Vault {
    fn drop(&mut self) {
        self.lock();
    }
}

/// Keep only selected notes/folders (plus the folders needed to reach them).
fn prune(
    folders: &[FolderNode],
    notes: &[NoteEntry],
    sel: &HashSet<String>,
    inherited: bool,
) -> (Vec<FolderNode>, Vec<NoteEntry>) {
    let keep_notes: Vec<NoteEntry> = notes
        .iter()
        .filter(|n| inherited || sel.contains(&n.id))
        .cloned()
        .collect();
    let mut keep_folders = Vec::new();
    for f in folders {
        let all = inherited || sel.contains(&f.id);
        let (sub_f, sub_n) = prune(&f.folders, &f.notes, sel, all);
        if all || !sub_f.is_empty() || !sub_n.is_empty() {
            keep_folders.push(FolderNode {
                id: f.id.clone(),
                name: f.name.clone(),
                folders: sub_f,
                notes: sub_n,
            });
        }
    }
    (keep_folders, keep_notes)
}

fn parent_key<'a>(o: &'a Obj, folders: &HashSet<&str>) -> Option<&'a str> {
    match o.parent.as_deref() {
        Some(p) if folders.contains(p) => Some(p),
        _ => None, // orphans (parent deleted/missing after a sync) surface at the root
    }
}

/// Parent of every live folder after repairing what concurrent moves on two devices can
/// produce: cycles (A in B and B in A) and absurdly deep chains. The offending link is
/// treated as "at the root" so nothing silently disappears from the tree.
fn effective_parents<'a>(
    live: &[&'a Obj],
    folders: &HashSet<&'a str>,
) -> HashMap<&'a str, Option<&'a str>> {
    let mut eff: HashMap<&'a str, Option<&'a str>> = live
        .iter()
        .filter(|o| o.kind == "folder")
        .map(|o| (o.id.as_str(), parent_key(o, folders)))
        .collect();
    for _ in 0..=eff.len() {
        let mut changed = false;
        let ids: Vec<&str> = eff.keys().copied().collect();
        for start in ids {
            let mut seen: HashSet<&str> = HashSet::new();
            let mut cur = start;
            loop {
                if !seen.insert(cur) || seen.len() > MAX_NEW_DEPTH + 32 {
                    eff.insert(cur, None);
                    changed = true;
                    break;
                }
                match eff.get(cur).copied().flatten() {
                    Some(p) => cur = p,
                    None => break,
                }
            }
        }
        if !changed {
            break;
        }
    }
    eff
}

fn build_tree(
    live: &[&Obj],
    folders: &HashSet<&str>,
    eff: &HashMap<&str, Option<&str>>,
    fid: Option<&str>,
    depth: usize,
) -> (Vec<FolderNode>, Vec<NoteEntry>) {
    if depth > MAX_TREE_DEPTH {
        return (Vec::new(), Vec::new());
    }
    let mut kids: Vec<&Obj> = live
        .iter()
        .copied()
        .filter(|o| {
            o.kind == "folder"
                && eff.get(o.id.as_str()).copied().flatten() == fid
                && Some(o.id.as_str()) != fid
        })
        .collect();
    kids.sort_by_key(|o| o.name.clone().unwrap_or_default().to_lowercase());
    let mut notes: Vec<&Obj> = live
        .iter()
        .copied()
        .filter(|o| o.kind == "note" && parent_key(o, folders) == fid)
        .collect();
    notes.sort_by_key(|o| o.title.clone().unwrap_or_default().to_lowercase());
    let fnodes = kids
        .iter()
        .map(|k| {
            let (f, n) = build_tree(live, folders, eff, Some(k.id.as_str()), depth + 1);
            FolderNode {
                id: k.id.clone(),
                name: k.name.clone().unwrap_or_default(),
                folders: f,
                notes: n,
            }
        })
        .collect();
    let entries = notes
        .iter()
        .map(|n| NoteEntry {
            id: n.id.clone(),
            title: n.title.clone().unwrap_or_default(),
            modified: n.modified,
        })
        .collect();
    (fnodes, entries)
}

/// File-system-safe name (Windows + Unix): no separators, no reserved device names, unique.
fn safe_name(name: &str, ext: &str, dir: Option<&Path>, used: &mut HashSet<String>) -> String {
    let norm: String = name.nfkc().collect();
    let replaced: String = norm
        .chars()
        .map(|c| {
            if "<>:\"/\\|?*".contains(c) || (c as u32) < 32 || c as u32 == 127 {
                '_'
            } else {
                c
            }
        })
        .collect();
    let trim = |s: &str| s.trim_matches(|c| c == ' ' || c == '.').to_string();
    let mut s = trim(&replaced);
    if s.is_empty() {
        s = "Untitled".to_string();
    }
    s = trim(&s.chars().take(100).collect::<String>());
    if s.is_empty() {
        s = "Untitled".to_string();
    }
    let stem = s.split('.').next().unwrap_or("").to_uppercase();
    if WIN_RESERVED.contains(&stem.as_str()) {
        s = format!("_{s}");
    }
    // Unique among siblings (folders and notes share one namespace, case-insensitively, with
    // the extension included) and never overwriting something already on disk.
    let base = s.clone();
    let mut n = 1;
    while used.contains(&format!("{s}{ext}").to_lowercase())
        || dir.is_some_and(|d| fs::symlink_metadata(d.join(format!("{s}{ext}"))).is_ok())
    {
        n += 1;
        s = format!("{base} ({n})");
    }
    used.insert(format!("{s}{ext}").to_lowercase());
    s
}

#[cfg(any(test, feature = "test-hooks"))]
impl Vault {
    /// Test hook: set a parent link without the cycle checks (simulates a merged state).
    #[doc(hidden)]
    pub fn force_parent_for_test(&mut self, oid: &str, parent: Option<&str>) {
        if let Some(o) = self.objs.get_mut(oid) {
            o.parent = parent.map(|s| s.to_string());
        }
    }
}
