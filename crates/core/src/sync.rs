// SPDX-License-Identifier: AGPL-3.0-only
//! Folder-based sync. The "remote" is just a directory that a cloud client mirrors
//! (Proton Drive, iCloud Drive, Dropbox, Syncthing, ...). It only ever holds ciphertext.
//!
//! Merge rules per object id (hybrid logical clock = (wall_ms, counter, device)):
//!   * identical clock                       -> nothing to do
//!   * only one side changed since last sync -> higher clock wins, copied to the other side
//!   * both changed, same content            -> higher clock wins
//!   * live vs tombstone                     -> live wins (an edit never silently loses to a delete)
//!   * both edited a note, different content -> higher clock wins, loser kept as a "conflict copy"
//!   * both changed a folder                 -> higher clock wins
//!
//! Unreadable / tampered / foreign remote files are reported and skipped: never trusted and
//! never overwritten.

use crate::crypto::{is_obj_name, MAX_FILE_BYTES};
use crate::error::{Result, VaultError};
use crate::fsutil::{mkdir_private, read_capped, write_atomic};
use crate::vault::{header_bytes, now_ms, parse_header, pending_acceptable, Obj, Vault};
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fs;
use std::path::Path;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SyncReport {
    pub pushed: Vec<String>,
    pub pulled: Vec<String>,
    /// ids of conflict copies created
    pub conflicts: Vec<String>,
    /// remote files that failed authentication
    pub errors: Vec<String>,
    /// stray files (e.g. cloud "name (1)" copies)
    pub ignored: Vec<String>,
}

fn same_content(a: &Obj, b: &Obj) -> bool {
    a.kind == b.kind
        && a.parent == b.parent
        && a.title == b.title
        && a.name == b.name
        && a.body == b.body
        && a.deleted == b.deleted
}

pub fn sync_folder(vault: &mut Vault, remote_dir: &Path) -> Result<SyncReport> {
    vault.key()?;
    let mut rep = SyncReport::default();
    let robj = remote_dir.join("objects");
    mkdir_private(remote_dir)?;
    if fs::symlink_metadata(&robj).is_ok_and(|m| m.file_type().is_symlink()) {
        return Err(VaultError::other(
            "remote objects folder is not a plain directory",
        ));
    }
    mkdir_private(&robj)?;

    // ---- header (vault identity + password-change propagation)
    let lh = vault.header.clone();
    let rpath = remote_dir.join("vault.json");
    if !rpath.exists() {
        write_atomic(&rpath, &header_bytes(&lh))?;
    } else {
        let rh = parse_header(&read_capped(&rpath, 65536)?)?;
        if rh.vault_id != lh.vault_id {
            return Err(VaultError::other(
                "remote folder belongs to a different vault",
            ));
        }
        if rh.header_rev > lh.header_rev {
            if pending_acceptable(&rh, &lh) {
                // Can't verify the new wrap without the password: stage it; unlock() adopts it
                // only if it authenticates under the user's own secret.
                write_atomic(&vault.root.join("vault.json.pending"), &header_bytes(&rh))?;
            } else {
                // Implausible header (absurd revision or KDF cost): a hostile or broken file.
                // Never stage it; repair the remote with our own header instead.
                write_atomic(&rpath, &header_bytes(&lh))?;
            }
        } else if rh.header_rev < lh.header_rev {
            write_atomic(&rpath, &header_bytes(&lh))?;
        }
    }

    // ---- read remote objects (keep the exact verified bytes: no re-read, no TOCTOU)
    let mut remote_objs: BTreeMap<String, (Obj, Vec<u8>)> = BTreeMap::new();
    let mut blocked: HashSet<String> = HashSet::new();
    let mut names: Vec<String> = fs::read_dir(&robj)?
        .filter_map(|e| e.ok())
        .filter_map(|e| e.file_name().into_string().ok())
        .collect();
    names.sort();
    for name in names {
        if !is_obj_name(&name) {
            rep.ignored.push(name);
            continue;
        }
        let p = robj.join(&name);
        let stem = name[..32].to_string();
        match read_capped(&p, MAX_FILE_BYTES) {
            Ok(bytes) => match vault.parse_object_bytes(&stem, &bytes) {
                Ok(o) => {
                    remote_objs.insert(o.id.clone(), (o, bytes));
                }
                Err(_) => {
                    rep.errors.push(name);
                    blocked.insert(stem);
                }
            },
            Err(_) => {
                rep.errors.push(name);
                blocked.insert(stem);
            }
        }
    }

    let local_objs: BTreeMap<String, Obj> = vault.objs.clone();
    let all_ids: BTreeSet<String> = local_objs
        .keys()
        .cloned()
        .chain(remote_objs.keys().cloned())
        .collect();

    for oid in all_ids {
        if blocked.contains(&oid) {
            continue;
        }
        let l = local_objs.get(&oid);
        let r = remote_objs.get(&oid).map(|(o, _)| o);
        let winner_is_local = match (l, r) {
            (Some(_), None) => true,
            (None, Some(_)) => false,
            (None, None) => continue,
            (Some(l), Some(r)) => {
                if l.hlc == r.hlc {
                    vault.state.synced.insert(oid.clone(), l.hlc.clone());
                    continue;
                }
                let base = vault.state.synced.get(&oid).cloned();
                let both_changed = base.as_ref() != Some(&l.hlc) && base.as_ref() != Some(&r.hlc);
                // Clocks only move forward. A side that is OLDER than the last state we synced
                // is a replayed/rolled-back copy (e.g. a cloud provider restoring an old file
                // version): it must never win, resurrect a deletion or spawn a fake conflict.
                if base.as_ref().is_some_and(|b| r.hlc < *b) && l.hlc >= *base.as_ref().unwrap() {
                    true
                } else if base.as_ref().is_some_and(|b| l.hlc < *b)
                    && r.hlc >= *base.as_ref().unwrap()
                {
                    false
                } else if both_changed && !same_content(l, r) {
                    if l.deleted != r.deleted {
                        !l.deleted // live beats tombstone
                    } else {
                        let local_wins = l.hlc > r.hlc;
                        if l.kind == "note" && !l.deleted {
                            let loser = if local_wins { r } else { l };
                            conflict_copy(vault, loser, &robj, &mut rep)?;
                        }
                        local_wins
                    }
                } else {
                    l.hlc > r.hlc
                }
            }
        };
        if winner_is_local {
            let bytes = vault.object_bytes(&oid)?;
            write_atomic(&robj.join(format!("{oid}.can")), &bytes)?;
            if let Some(l) = local_objs.get(&oid) {
                vault.state.synced.insert(oid.clone(), l.hlc.clone());
            }
            rep.pushed.push(oid);
        } else if let Some((ro, bytes)) = remote_objs.get(&oid) {
            write_atomic(&vault.objects_dir().join(format!("{oid}.can")), bytes)?;
            vault.state.synced.insert(oid.clone(), ro.hlc.clone());
            vault.observe_hlc(&ro.hlc);
            rep.pulled.push(oid);
        }
    }

    vault.save_state()?;
    vault.reload()?;
    Ok(rep)
}

/// Keep the losing side of an edit conflict as a visible, separate note.
fn conflict_copy(vault: &mut Vault, loser: &Obj, robj: &Path, rep: &mut SyncReport) -> Result<()> {
    let mut parent = loser.parent.clone();
    if let Some(p) = &parent {
        match vault.objs.get(p) {
            Some(po) if !po.deleted => {}
            _ => parent = None,
        }
    }
    let dev: String = loser.hlc.2.chars().take(8).collect();
    let title: String = loser
        .title
        .clone()
        .unwrap_or_default()
        .chars()
        .take(140)
        .collect();
    let name = format!("{} (conflict {} {})", title, dev, utc_stamp());
    let cid = vault.create_note(
        &name,
        loser.body.as_deref().unwrap_or(""),
        parent.as_deref(),
    )?;
    // create_note() wrote it locally; make it visible to this sync pass
    let bytes = vault.object_bytes(&cid)?;
    write_atomic(&robj.join(format!("{cid}.can")), &bytes)?;
    if let Some(o) = vault.objs.get(&cid) {
        let h = o.hlc.clone();
        vault.state.synced.insert(cid.clone(), h);
    }
    rep.conflicts.push(cid.clone());
    rep.pushed.push(cid);
    Ok(())
}

/// "YYYY-MM-DD HH:MM" in UTC without any date library.
fn utc_stamp() -> String {
    let secs = now_ms() / 1000;
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (h, mi) = (rem / 3600, (rem % 3600) / 60);
    // civil-from-days (Howard Hinnant)
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02} {h:02}:{mi:02}")
}
