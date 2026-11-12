---
title: Web host
description: The hardened localhost HTTP server, its protections and its command-line options.
order: 7
---
# Web host

`crates/server/` is a tiny, dependency-free (`std` only) HTTP/1.1 server. It exists so the web version can run with no installer.

## Running it

```bash
cargo run --release -p ctrlaltnotes-server
# or the built binary:
./target/release/ctrlaltnotes-web [OPTIONS]
```

| Option | Meaning |
|---|---|
| `--vault <DIR>` | Where the encrypted vault lives (default: per-user data folder; keeps the legacy `CtrlAltNotes` folder name) |
| `--sync-folder <DIR>` | Folder mirrored by your cloud client |
| `--sync-file <FILE>` | Single-file (bundle) sync target |
| `--port <N>` | Fixed port (default: random free port) |
| `--idle-lock <SECS>` | Auto-lock after this many idle seconds (default 300, minimum 10) |
| `--no-open` | Do not open the browser |

The vault password is **never** a command-line argument; it is created in the page.

Preferences are stored next to the vault folder: `<vault>-settings.json` (per-vault settings) and `<vault>-app.json` (theme). The web version cannot switch vault folders from the page; start it with another `--vault` instead.

## What it prints

`http://localhost:PORT/#<64 hex token>`. The token is in the **fragment**, so the browser never sends it; `api.js` moves it into memory and clears the address bar.

## Protections

| Threat | Control |
|---|---|
| Other machines | Binds `127.0.0.1` and best-effort `[::1]` on the same port |
| Other local pages / DNS rebinding | `Host` pinned to `127.0.0.1:PORT` or `localhost:PORT`; `Origin` must match when present |
| Other local processes | 256-bit launch token, constant-time compare |
| Token leakage via `ps` | Browser is opened with a private 0600 temp page that redirects, not with the token in argv |
| CSRF | JSON-only `POST` with a bearer token; no cookies; no CORS headers ever |
| XSS | CSP `default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'`; no inline script or style |
| Request smuggling | No chunked encoding, single `Content-Length`, no obsolete folding, no pipelining |
| Resource exhaustion | Header ≤ 16 KiB, body ≤ 6 MiB, ≤ 32 connections, per-read and whole-request deadline (slowloris) |
| Path attacks | No API accepts a path; paths come only from launch flags |

Static files (`/`, `app.css`, `app.js`, `md.js`, `api.js`, `quick.js`, logos and icons) are compiled into the binary.

## Not covered

* The token is the only credential once the vault is unlocked: protect your terminal and the printed URL.
* Windows exclusive port binding is not used.
