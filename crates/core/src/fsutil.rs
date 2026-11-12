// SPDX-License-Identifier: AGPL-3.0-only
//! Crash-safe, owner-only file helpers.
use crate::crypto::random_bytes;
use crate::error::{Result, VaultError};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;

/// Create a directory (and parents) readable only by the owner (0700 on Unix).
pub fn mkdir_private(path: &Path) -> Result<()> {
    let mut b = fs::DirBuilder::new();
    b.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        b.mode(0o700);
    }
    b.create(path).map_err(VaultError::from)
}

fn open_private_new(path: &Path) -> std::io::Result<File> {
    let mut o = OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    o.open(path)
}

/// tmp file in the same directory -> fsync -> rename -> fsync directory.
/// The old file survives any crash; no plaintext is ever written.
pub fn write_atomic(path: &Path, data: &[u8]) -> Result<()> {
    let dir = path
        .parent()
        .ok_or_else(|| VaultError::other("invalid path"))?;
    let tmp = dir.join(format!(".tmp-{}", hex::encode(random_bytes::<8>())));
    let written = (|| -> std::io::Result<()> {
        let mut f = open_private_new(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
        Ok(())
    })();
    if let Err(e) = written {
        let _ = fs::remove_file(&tmp);
        return Err(VaultError::from(e));
    }
    if let Err(e) = fs::rename(&tmp, path) {
        let _ = fs::remove_file(&tmp);
        return Err(VaultError::from(e));
    }
    #[cfg(unix)]
    {
        if let Ok(d) = File::open(dir) {
            let _ = d.sync_all();
        }
    }
    Ok(())
}

/// Read a file, refusing anything larger than `cap` bytes (DoS guard for hostile cloud files).
pub fn read_capped(path: &Path, cap: usize) -> Result<Vec<u8>> {
    // Only plain files: a FIFO/device would block forever, a symlink could point anywhere.
    let md = std::fs::symlink_metadata(path)?;
    if !md.file_type().is_file() {
        return Err(VaultError::other("not a regular file"));
    }
    let f = File::open(path)?;
    let len = f.metadata()?.len();
    if len > cap as u64 {
        return Err(VaultError::other("file too large"));
    }
    let mut buf = Vec::new();
    let mut limited = f.take(cap as u64 + 1);
    limited.read_to_end(&mut buf)?;
    if buf.len() > cap {
        return Err(VaultError::other("file too large"));
    }
    Ok(buf)
}
