---
title: Security model
description: What is protected, from whom, and by which control.
order: 13
---
# Security model

## What CtrlAltNotes protects

Note titles, bodies, folder names and the folder structure, **at rest** and **in the cloud**.

## Adversaries

| Adversary | Can do | Cannot do |
|---|---|---|
| **Cloud provider / anyone with the synced folder** | See the number, rounded size and modification time of files; delete, replace or replay files | Read content; forge a file that authenticates; silently change a note |
| **Someone who steals the vault folder** | Try passwords offline (Argon2id 64 MiB, t=3, p=4 slows this) | Read notes without the password or recovery key |
| **Other local users or processes** (web version) | Connect to localhost | Use the API without the 256-bit token; read it from `ps`; rebind DNS |
| **Malicious note content** | Attempt XSS, ReDoS, huge input | Execute script, load remote content, freeze the UI |
| **Malware on the unlocked computer** | Everything | Out of scope |

## Controls

* Key hierarchy and AEAD binding: see [Cryptography](03-cryptography.md) and [Vault format](02-vault-format.md).
* Unlock back-off after 3 failures on every path that tests a secret.
* Idle auto-lock (5 min), lock on close and quit; keys in `Zeroizing`; the DOM is cleared on lock.
* `#![forbid(unsafe_code)]` in all crates, including the desktop shell and the web binary.
* Vault folder switching: the path comes only from a native dialog; refused while unlocked; only empty folders or existing vaults; never the current sync target; symlinks refused; the stored choice is re-validated at start; the unlock throttle is kept across switches.
* Release gate (`scripts/check.sh`, also in CI): `rustfmt`, `clippy --all-targets -D warnings`, release tests, `cargo audit` (RustSec), JavaScript syntax check.
* Private file permissions; atomic writes.
* Web host and CSP: see [Web host](07-web-host.md).
* Desktop: no server, no open port, one IPC command, native dialogs in Rust, scoped permissions.
* Password policy (NIST SP 800-63B-4): [details](05-password-policy.md).
* Selection-based export; destination chosen natively; exported plaintext is the user's responsibility.

## Standards followed

NIST SP 800-63B-4 (passwords), OWASP password storage guidance (Argon2id minimums), RFC 9106, RFC 8439, RFC 5869, WebAuthn Level 3 PRF / CTAP2 hmac-secret, and the OWASP ASVS ideas for the local web surface.

!!! warning "Not independently audited"
    The project follows current standards and was penetration-tested by the author's process ([report](14-pentest-report.md)), but it has **not** been audited by a third party.

## Recovery

The password and recovery key cannot be reset by anyone. Losing both loses the vault.
