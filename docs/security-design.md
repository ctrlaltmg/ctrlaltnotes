# CtrlAltNotes: security design and verification status

Fuller, edited documentation lives in [`technical/`](technical/) and is published on the website.

## Cryptography (all from audited RustCrypto crates; nothing hand-rolled)
* Password → **Argon2id** (64 MiB, t=3, p=4; floor 19 MiB/t=2/p=1 = OWASP minimum; DoS ceilings on read) → key-encryption key.
* A random 256-bit **master key** is wrapped (ChaCha20-Poly1305) twice: by the password key and by a 256-bit **recovery key**
  (HKDF-SHA256). Changing the password re-wraps one key; no note is re-encrypted.
* Every note/folder is its own file: per-file random salt → HKDF subkey → **ChaCha20-Poly1305**, fresh nonce each write,
  AAD = magic|type|object-id|salt (binds ciphertext to its id/type: swapping/renaming files is detected). Plaintext padded to 1 KiB blocks.
* The vault header is authenticated as AAD of both key wraps (KDF-downgrade / rollback of parameters is detected).
* Passwords are NFKC-normalised (NIST SP 800-63B). NEW passwords must be >= 15 characters, are checked against a blocklist of common/famous
  passwords and trivial patterns, with no composition rules and no expiry (SP 800-63B-4). Existing shorter passwords (12+) still unlock.
* **Quick unlock (security key / fingerprint)**: WebAuthn PRF (CTAP2 hmac-secret). The authenticator yields a 32-byte secret after user
  verification; kek = HKDF(secret, vault id, "ctrlaltnotes/v1/quick") wraps the master key in the LOCAL file `quick.json` (never synced, AAD binds
  vault id, credential id, salt, rp id, label). Enrolling requires re-entering the password. Failed quick unlocks share the password back-off.
  Changing the password deletes the slot. Keys live in `Zeroizing` memory and are wiped on lock; `#![forbid(unsafe_code)]` in all crates.

## Sync
Cloud storage only ever holds ciphertext. Hybrid-logical-clock merge; live beats tombstone; concurrent note edits keep a
"conflict copy"; tampered/foreign files are reported and never trusted or overwritten; verified bytes are the bytes copied.

## Settings, sync and export
* Preferences (auto-sync, interval, auto-lock, live preview, toolbar, start-up note) are non-secret and stored in a plain settings file next to the vault. Auto-sync is
  ON by default; background sync (`sync_now` with `auto:true`) and `status` polling do not reset the idle timer.
* Export lets the user choose folders/notes; a selected folder includes its contents; only ids chosen in the UI are sent. Desktop: the destination
  comes from a native dialog. Web: no path is accepted; the server returns a single `.md` or a stored `.zip` (std-only writer, 32 MiB / 20,000
  entry caps) that the browser saves to Downloads. Output is plaintext by design.
* The UI has no Sync button: sync is an on/off switch plus interval in Settings.
* Theme (dark/light/system) and the chosen vault folder are app-wide, in `app.json` (desktop) or `<vault>-app.json` (web). Unauthenticated, so
  re-validated on load: an unknown theme falls back to dark; a stored vault folder must still be a real directory that holds `vault.json` or is
  empty, else the default vault is used.
* Vault folder switching (desktop only): the path comes from a native dialog opened in Rust; refused while unlocked (in the shell and in the
  service); absolute, non-symlink directory; empty (dot-files ignored) or containing a regular-file `vault.json`; never the current sync target.
  Each vault has its own settings file `vaults/<sha256(path)[:16]>.json`, so sync targets never cross vaults. The unlock throttle is not reset by
  a switch.

## Hosts
* **Desktop**: no server, no port. One IPC command; file dialogs are opened by Rust, paths never come from the page. CSP forbids remote and inline content.
* **Web**: 127.0.0.1 only, 256-bit launch token (URL fragment) + constant-time check, Host/Origin pinning, JSON-only POST,
  header/body/connection limits, no chunked encoding, strict CSP, no CORS, no caching. No API takes a path.
* Unlock back-off after 3 failures; idle auto-lock (status polling does not extend it; the user can choose 1–120 minutes, and **Never**, which keeps the vault unlocked until Lock, close or quit; the choice is stored in the plain settings file); decrypted DOM cleared on lock.

## Known limits (be aware)
* Anyone who controls your unlocked computer (malware, screen capture, keylogger) defeats any local encryption.
* Sync metadata leaks: number of notes, sizes (rounded to 1 KiB), modification times of files.
* Not independently audited. The recovery key and password cannot be reset by anyone.
* Two devices editing the same note offline produce a conflict copy rather than a merge.
* Unsigned builds show OS warnings; the app has no auto-update.
* Export writes plaintext by design.

## Penetration test (summary; details in `docs/pentest-report.md`)
A red-team pass (independent agent + manual checks) found 19 issues. Fixed in code, each with a regression test: hostile remote
header / KDF-cost planting, replay of old object versions, FIFO and symlink tricks in the sync folder, password-oracle commands,
folder cycles / deep nesting, export name collisions and overwrites, weak 15+ character passwords, slowloris, launch token in the
opener's argv, `[::1]` port squatting, Markdown ReDoS / recursion, mailto query pre-fill, tampered settings file, overly broad Tauri
opener permission. Documented, not "fixed": see the limits below.

## Known limits found by the pentest
* **No whole-vault rollback detection.** A cloud provider (or whoever controls the folder) can serve an older, internally consistent copy
  of everything; per-object replay is blocked, a complete rollback is not detectable without a trusted counter.
* **A password change does not rotate the master key.** Someone who kept an old `vault.json` plus the OLD password (or the recovery key)
  can still open the vault. If a password leaked, create a new vault and move the notes.
* Plaintext of opened notes can remain in process memory after lock (no `mlock`, no core-dump suppression; Rust `String`s are not
  zeroized). Disable crash dumps / swap if that matters to you.
* A corrupt or hostile file in the sync folder is reported and skipped; a garbage remote `vault.json` stays until repaired (sync restores
  it from the local header only when the garbage is newer and implausible).
* The web version's launch token is the only credential once the vault is unlocked; protect the terminal/URL. Windows has no exclusive
  port bind in this build.
* Losing `state.can` (device-local sync state) causes spurious conflict copies on the next sync (nothing is lost).
* The quick-unlock slot survives a password change made on another device and its `rp_id` (`localhost`) is shared by all ports.
* A body near the 4 MiB limit can fail to save, because JSON escaping can triple its size.
* Argon2 cost of a staged header from another device is capped at max(local cost, default): intentionally raising the cost on one
  device above the default will not propagate to a second device automatically.

## Release gate
`scripts/check.sh` (and CI on Linux/macOS/Windows): rustfmt, `clippy --workspace --all-targets -D warnings`, `cargo test --release`, `cargo audit`,
`node --check ui/*.js`. `#![forbid(unsafe_code)]` in every crate and binary. `cargo audit`: no vulnerabilities; 5 warnings (unmaintained/unsound),
all in Tauri's Linux GTK/WebKitGTK/D-Bus chain, not called by CtrlAltNotes code.

## Verification status (honest)
Current: the release gate passes on macOS with the real crypto crates (RFC known-answer and NFKC tests included); the macOS app is built and used.
Windows and Linux desktop bundles not yet built on those systems.

Original authoring sandbox (WITHOUT internet access), kept for the record:
* `core` + `service` + `server`: compiled with rustc 1.97, `clippy` clean, all Rust tests passed (run `cargo test` for the current count), plus **90 browser checks** and an 18-case Markdown robustness check of the real UI
  against the real server binary. To make that possible the real crypto crates were replaced by stand-ins (real SHA-256/HKDF/HMAC/Base64,
  but a FAKE cipher, a FAKE Argon2 and identity Unicode normalisation).
* NOT executed there (need the real crates, so they run on your machine): RFC known-answer tests (`crates/core/tests/kat.rs`), the NFKC test, and any behaviour that depends on real cipher/KDF output.
  Compile-compatibility of `crates/core/src/crypto.rs` with the real argon2 0.5 / chacha20poly1305 0.10 APIs was written from their documentation but never compiled.
* The Tauri app (`app/`) was never compiled or launched. Expect possible small compile fixes on first `cargo tauri build`.
* Windows was never run.
