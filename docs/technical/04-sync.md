---
title: Sync engine
description: Folder and single-file sync, the hybrid logical clock, conflict handling and what hostile cloud files cannot do.
order: 4
---
# Sync engine

The cloud holds ciphertext only. Any client that mirrors a folder works: Proton Drive, iCloud Drive, Dropbox, OneDrive, Syncthing.

## Targets

| Target | Description |
|---|---|
| **Folder** | A directory that mirrors the vault's `vault.json` and `objects/` |
| **Bundle (`.canb`)** | A single file (`CANB` container) holding the same objects. Good for providers that handle one file better |

## Automatic by default

`Settings.auto_sync` is **true** by default and only acts once a target exists. The UI schedules `sync_now {auto:true}` every `sync_interval` seconds (15 to 3600, default 60) while the vault is unlocked and the editor is idle. There is no Sync button; the switch lives in **Settings → Sync**.

Background calls (`status`, `sync_now` with `auto:true`) do **not** reset the idle timer, so an unattended unlocked vault still auto-locks.

## Merge rules

Every object carries a hybrid logical clock `hlc = (wall_ms, counter, device)`.

1. Objects only on one side are copied.
2. If both sides have the object and the contents are equal, nothing happens.
3. `state.can` remembers the clock last seen in sync (`base`).
4. If only one side moved past `base`, that side wins.
5. If **both** moved and contents differ:
    * **Notes**: the newer (by clock) wins; the other becomes a **conflict copy** (a new note), so no text is lost.
    * **Live vs tombstone**: live wins (an edit beats a delete).
6. A side **older than `base`** is a replay or rollback and never wins (see [pentest F-02](14-pentest-report.md)).

## Trust rules for remote files

* Every remote file is parsed and authenticated before use. Failures are **reported and skipped**, never overwritten.
* Only regular files are read (no FIFOs, devices or symlinks), with size caps.
* A symlinked `objects/` directory is refused.
* A remote `vault.json` from a different vault is refused ("foreign vault").
* A newer remote header is staged as `vault.json.pending` only if it is plausible: same vault id, revision at most +1000, KDF cost no higher than `max(local, default)`. Otherwise sync repairs the remote from the local header.
* The bytes verified are the bytes copied.

## Password change propagation

Device A changes the password (header_rev+1). Device B's next sync stages the new header. B adopts it **only when the user unlocks with a secret that authenticates against it**. A hostile file therefore cannot lock the user out.

## Reports

`SyncReport` lists `pushed`, `pulled`, `conflicts` and `problems`. The UI shows a short status line (`Synced 10:42`).
