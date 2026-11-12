---
title: Security key and fingerprint unlock
description: WebAuthn PRF (CTAP2 hmac-secret) wrapped around the master key.
order: 6
---
# Security key and fingerprint unlock

## Mechanism

1. The UI asks the authenticator (YubiKey, Touch ID, Windows Hello) to create a credential with the **WebAuthn PRF extension**.
2. The authenticator returns a 32-byte secret after **user verification**. It is never stored.
3. The backend derives `KEK_q = HKDF(secret, salt = vault_id bytes, info = "ctrlaltnotes/v1/quick")` and wraps the master key into the **local** file `quick.json`.
4. To unlock, the UI evaluates the PRF again with the stored credential id and salt; the backend unwraps the master key.

## Binding

The wrap's AAD binds `vault_id`, `cred_id`, `salt`, `rp_id` and `label`. Metadata is validated on read (lengths, characters).

## Rules

* Enrolling requires the **current password** (`verify_password`, throttled).
* Failed quick unlocks share the password back-off.
* `change_password` deletes the slot.
* The slot is device-local and never synced.
* `rpId` is `location.hostname`, so a slot created at `localhost` is shared by all ports of `localhost` (see [Known limits](15-known-limits.md)).

## Platform support

| Host | Status |
|---|---|
| Web version in Chrome / Edge / Safari at `http://localhost:PORT` | Works; tested with Chromium's virtual authenticator |
| Windows app (WebView2) | Expected to work; not run |
| macOS app (WKWebView) | May be blocked: WebAuthn in apps needs signing and entitlements |

Native Touch ID via the Keychain would need a signed build. A third-party Tauri biometry plugin was evaluated and **not** used because its API could not be verified and it requires signing.

## UI

`ui/quick.js` exposes `CANQuick.supported / enroll / getSecret`. Errors (`NotAllowedError`, `NotSupportedError`, `SecurityError`) are translated into plain sentences.
