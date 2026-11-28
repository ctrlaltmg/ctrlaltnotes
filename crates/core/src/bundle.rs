// SPDX-License-Identifier: AGPL-3.0-only
//! Single-file sync backend ("bundle").
//!
//! Some clouds (notably Proton Drive on phones, which exposes no third-party sync API) can only
//! store/open one file at a time. A bundle packs the *already-encrypted* vault folder (header +
//! object files) into one file, so any "Save to / Open from" file picker can carry it.
//!
//! ```text
//! bundle = MAGIC | count(u32 BE) | { kind(u8) len(u32 BE) bytes }* | SHA-256(everything before)
//! ```
//!
//! * Confidentiality / authenticity come only from the per-object AEAD; the trailing SHA-256 is an
//!   accident detector (truncated download), NOT a security control.
//! * Object file names are derived from the id inside each object header, never from
//!   attacker-controlled names, so a hostile bundle cannot write outside the staging directory.
//! * Merging reuses `sync_folder`, so there is exactly one merge implementation.
use crate::crypto::{is_obj_name, random_bytes, HEADER_LEN, MAGIC, MAX_FILE_BYTES};
use crate::error::{Result, VaultError};
use crate::fsutil::{mkdir_private, read_capped, write_atomic};
use crate::sync::{sync_folder, SyncReport};
use crate::vault::{parse_header, Vault};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};

pub const BUNDLE_MAGIC: &[u8; 4] = b"CANB";
pub const MAX_OBJECTS: usize = 100_000;
pub const MAX_BUNDLE_BYTES: usize = 1024 * 1024 * 1024;
const KIND_HEADER: u8 = 0;
const KIND_OBJECT: u8 = 1;

fn invalid() -> VaultError {
    VaultError::other("not a valid bundle")
}

/// Temporary staging directory, removed on drop (also on error paths).
struct Staging(PathBuf);

impl Staging {
    fn new(parent: &Path) -> Result<Staging> {
        let p = parent.join(format!("snb-{}", hex::encode(random_bytes::<8>())));
        mkdir_private(&p)?;
        Ok(Staging(p))
    }
}

impl Drop for Staging {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn pack(remote: &Path) -> Result<Vec<u8>> {
    let header = read_capped(&remote.join("vault.json"), 65536)?;
    let mut objects: Vec<Vec<u8>> = Vec::new();
    let objdir = remote.join("objects");
    if objdir.is_dir() {
        let mut names: Vec<String> = fs::read_dir(&objdir)?
            .filter_map(|e| e.ok())
            .filter_map(|e| e.file_name().into_string().ok())
            .collect();
        names.sort();
        for n in names {
            if is_obj_name(&n) {
                objects.push(read_capped(&objdir.join(&n), MAX_FILE_BYTES)?);
            }
        }
    }
    let mut out = Vec::new();
    out.extend_from_slice(BUNDLE_MAGIC);
    out.extend_from_slice(&(objects.len() as u32).to_be_bytes());
    out.push(KIND_HEADER);
    out.extend_from_slice(&(header.len() as u32).to_be_bytes());
    out.extend_from_slice(&header);
    for o in &objects {
        out.push(KIND_OBJECT);
        out.extend_from_slice(&(o.len() as u32).to_be_bytes());
        out.extend_from_slice(o);
    }
    let digest = Sha256::digest(&out);
    out.extend_from_slice(&digest);
    Ok(out)
}

pub(crate) fn unpack(blob: &[u8], dest: &Path) -> Result<()> {
    if blob.len() < 4 + 4 + 32 || &blob[..4] != BUNDLE_MAGIC || blob.len() > MAX_BUNDLE_BYTES {
        return Err(invalid());
    }
    let (body, digest) = blob.split_at(blob.len() - 32);
    if Sha256::digest(body).as_slice() != digest {
        return Err(VaultError::other("bundle is truncated or corrupted"));
    }
    let count = u32::from_be_bytes([body[4], body[5], body[6], body[7]]) as usize;
    if count > MAX_OBJECTS {
        return Err(VaultError::other("bundle too large"));
    }
    mkdir_private(&dest.join("objects"))?;
    let mut pos = 8usize;
    let mut seen_header = false;
    let mut objects = 0usize;
    while pos < body.len() {
        if pos + 5 > body.len() {
            return Err(invalid());
        }
        let kind = body[pos];
        let n = u32::from_be_bytes([body[pos + 1], body[pos + 2], body[pos + 3], body[pos + 4]])
            as usize;
        pos += 5;
        let end = pos.checked_add(n).ok_or_else(invalid)?;
        if n > MAX_FILE_BYTES || end > body.len() {
            return Err(invalid());
        }
        let data = &body[pos..end];
        pos = end;
        if kind == KIND_HEADER && !seen_header {
            parse_header(data)?;
            write_atomic(&dest.join("vault.json"), data)?;
            seen_header = true;
        } else if kind == KIND_OBJECT {
            if data.len() < HEADER_LEN || &data[..4] != MAGIC {
                return Err(invalid());
            }
            let oid = hex::encode(&data[5..21]); // name comes from the object's own (AEAD-bound) id
            write_atomic(&dest.join("objects").join(format!("{oid}.can")), data)?;
            objects += 1;
        } else {
            return Err(invalid());
        }
    }
    if !seen_header || objects != count {
        return Err(invalid());
    }
    Ok(())
}

/// Set up a new device from a bundle file (e.g. one downloaded from Proton Drive).
pub fn join_from_bundle(path: &Path, bundle_path: &Path, password: &str) -> Result<Vault> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    mkdir_private(parent)?;
    let stage = Staging::new(parent)?;
    let remote = stage.0.join("remote");
    mkdir_private(&remote)?;
    unpack(&read_capped(bundle_path, MAX_BUNDLE_BYTES)?, &remote)?;
    let mut v = Vault::join(path, &remote, password)?;
    sync_bundle(&mut v, bundle_path)?;
    Ok(v)
}

/// Merge the bundle file (if it exists) into the vault, then rewrite it with the merged result.
pub fn sync_bundle(vault: &mut Vault, bundle_path: &Path) -> Result<SyncReport> {
    vault.key()?;
    let stage = Staging::new(&vault.root)?;
    let remote = stage.0.join("remote");
    mkdir_private(&remote)?;
    if bundle_path.exists() {
        unpack(&read_capped(bundle_path, MAX_BUNDLE_BYTES)?, &remote)?;
    }
    let rep = sync_folder(vault, &remote)?;
    write_atomic(bundle_path, &pack(&remote)?)?;
    Ok(rep)
}
