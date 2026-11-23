---
title: Architecture overview
description: How core, service, the two hosts and the single UI fit together.
order: 1
---
# Architecture overview

CtrlAltNotes is one Rust backend with one front end, packaged three ways.

```text
            ┌───────────────┐        ┌────────────────────┐
  ui/ ───►  │ Tauri window  │  IPC   │                    │
 (HTML/JS)  │ rpc(cmd,args) ├───────►│  ctrlaltnotes-      │──► core: Vault / sync / bundle / crypto
            └───────────────┘        │  service           │       │
            ┌───────────────┐  HTTP  │  Service::dispatch │       ▼
  ui/ ───►  │ browser       ├───────►│  (single entry)    │   vault dir (ciphertext files)
            │ POST /api/cmd │ Bearer └────────────────────┘
            └───────────────┘
```

## Workspace layout

| Crate / folder | Role | Notes |
|---|---|---|
| `crates/core/` | Vault format, crypto, sync (folder + bundle), password policy, quick-unlock slot, ZIP writer | `#![forbid(unsafe_code)]`; no I/O outside the vault and sync directories |
| `crates/service/` | `Service::dispatch(cmd, args, host_path)`: the **only** entry point | Throttling, idle lock, settings, command validation |
| `crates/server/` | Web host: hardened `std`-only HTTP server on loopback | Binary `ctrlaltnotes-web` |
| `app/` | Native macOS/Windows/Linux shell (Tauri 2) | One IPC command, `rpc` |
| `ui/` | The one front end: HTML, CSS, vanilla JS, no framework, no build step | Shared by both hosts |
| `brand/` | Script that generates every icon and logo | `make_brand.py` |

The website (ctrlaltnotes.com: landing page and the published version of these docs) is maintained separately and is not part of the application.

## Layers and trust boundaries

1. **UI**: untrusted input producer. It renders notes with DOM APIs only (no `innerHTML`) and never receives a file path.
2. **Host**: transports one JSON command at a time. The Tauri host opens native dialogs itself; the web host binds loopback and demands a bearer token.
3. **Service**: validates every argument, enforces that the vault is unlocked, applies the unlock back-off and the idle lock.
4. **Core**: all cryptography and file formats.

## Transport abstraction

`ui/api.js` picks the transport at load time:

* Tauri window: `invoke('rpc', { cmd, args })`
* Browser: `POST /api/<cmd>` with `Authorization: Bearer <launch token>`

Errors reach the UI as plain strings: `locked`, `throttled:N`, `cancelled`, or a short message.

## Data at rest

```text
<vault dir>/
  vault.json            header: KDF parameters + two wrapped copies of the master key
  objects/<32hex>.can    one encrypted file per note or folder (and tombstones)
  state.can              device-local sync state (never uploaded)
  quick.json            device-local security-key slot (never uploaded)
  vault.json.pending    header staged from another device after a password change
```

See [Vault format](02-vault-format.md) for the bytes.
