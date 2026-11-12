---
title: Known limits
description: Honest list of what the design does not protect against.
order: 15
---
# Known limits

## By design

* Anyone who controls your **unlocked** computer (malware, screen capture, keylogger) defeats any local encryption.
* **Metadata leaks** through sync: number of notes, sizes (rounded to 1 KiB) and modification times of files.
* **Export writes plaintext** on purpose.
* Concurrent offline edits to one note make a **conflict copy**, not a merge.
* Unsigned builds show OS warnings; there is no auto-update.
* Not independently audited. The password and recovery key cannot be reset.

## Found by the pentest and documented

* **No whole-vault rollback detection.** Whoever controls the folder can serve an older, internally consistent copy of everything. Per-object replay is blocked; a complete rollback is not detectable without a trusted counter.
* **A password change does not rotate the master key.** Someone holding an old `vault.json` plus the old password (or the recovery key) can still open the vault. After a leak, create a new vault and move the notes.
* **Plaintext may remain in process memory** after lock (no `mlock`, no core-dump suppression, ordinary Rust strings).
* A corrupt or hostile file in the sync folder is **reported and skipped**; sync repairs the header only when the garbage is newer and implausible.
* The web launch token is the only credential once unlocked. Windows exclusive port binding is not used.
* Losing `state.can` causes spurious conflict copies on the next sync (nothing is lost).
* The quick-unlock slot survives a password change made on **another** device; the `localhost` relying-party id is shared by all ports.
* A body near the 4 MiB limit can fail to save because JSON escaping can triple its size.
* A raised Argon2 cost above the default does not propagate automatically to a second device (staged headers are capped at `max(local, default)`).
* Android and iOS are **not** part of this Rust edition.
