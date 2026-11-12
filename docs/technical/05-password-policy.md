---
title: Password policy
description: The rules for new passwords, following NIST SP 800-63B-4.
order: 5
---
# Password policy

Implemented in `crates/core/src/policy.rs` and enforced in the **service** (not just the UI) for `create_vault` and `change_password`. Unlocking an **existing** vault is never subject to the policy, so older passwords keep working.

## Rules

* Length: **15 to 1024 characters** after NFKC normalisation.
* **No composition rules** (no "must contain a symbol"), **no expiry**. Spaces and any Unicode are allowed; pasting is allowed.
* Rejected:
    * famous or common passwords and phrases (blocklist, e.g. `password`, `correcthorsebatterystaple`),
    * fewer than 8 distinct characters,
    * periodic repeats (`abababab…`), mostly sequential runs (`abcdefgh…`),
    * digits only (`1357924680135792`),
    * a repeated block, even truncated (`Summer2024Summer`, `Passw0rd!Passw0rd!`),
    * keyboard and alphabet walks covering 60 % or more (`zaq12wsxcde34rfv`, `1qaz2wsx3edc4rfv`),
    * a common word plus a few digits or symbols, after leetspeak folding (`P@ssw0rd2024!!!!`).

## Generator

The UI **Generate** button creates a 22-character random password using `crypto.getRandomValues` with rejection sampling over a 61-symbol alphabet without look-alike characters.

## Throttling

After 3 failed unlocks the service imposes an exponential back-off (1 s doubling, capped at 300 s). The same throttle covers `unlock`, `unlock_quick`, `change_password` (old password) and `quick_enroll` (password), so none of them is a free guessing oracle.

## Tests

`crates/core/tests/security.rs::password_policy_follows_nist_800_63b` lists accepted and rejected examples. Add yours there.
