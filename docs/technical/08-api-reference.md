---
title: Command API reference
description: Every command accepted by Service::dispatch, with arguments and results.
order: 8
---
# Command API reference

Every host calls the same function:

```rust
Service::dispatch(cmd: &str, args: &Value, host_path: Option<&Path>) -> Result<Value, ApiError>
```

* Web: `POST /api/<cmd>`, body = JSON object, header `Authorization: Bearer <token>`, `Content-Type: application/json`.
* Desktop: `invoke('rpc', { cmd, args })`.

Commands other than `status`, `touch`, `create_vault`, `unlock`, `unlock_quick`, `join_vault`, `quick_info` need an **unlocked** vault and otherwise fail with `locked`.

## Errors

| Wire string | Meaning |
|---|---|
| `locked` | The vault is locked; the UI returns to the unlock screen |
| `throttled:N` | Too many failed attempts; retry in N seconds |
| `cancelled` | The user closed a native dialog |
| other text | A short, non-sensitive message (`invalid input`, `vault already exists`, …) |

HTTP status codes: 200, 400 (bad request), 401 (token), 403 (host/origin), 404, 405, 413, 415. The error body is `{"error": "<wire string>"}`.

## Session and vault

| Command | Arguments | Result |
|---|---|---|
| `status` | none | `{exists, unlocked, sync, sync_label, can_pick, theme, vault_custom, vault_label, idle_lock, quick, settings}` |
| `touch` | none | `{ok}`; resets the idle timer |
| `create_vault` | `password` | `{recovery_key}`; applies the [password policy](05-password-policy.md) |
| `unlock` | `password` **or** `recovery` | `{ok}` |
| `unlock_quick` | `secret` (b64url, 32 bytes) | `{ok}` |
| `join_vault` | `kind` (`folder`/`bundle`), `password`; path from native dialog | `{ok}` (desktop only) |
| `lock` | none | `{ok}` |
| `change_password` | `old`, `new` | `{recovery_key}` (new); throttled; removes the quick slot |
| `open_vault_folder` | none; path from native dialog | `{ok}` (desktop only, vault must be locked). Folder must be absolute, a real directory (not a symlink), and either contain `vault.json` or be empty (dot-files ignored). The current sync target is refused. Locks, loads that vault's own settings and sync target, remembers the choice. Does **not** reset the unlock throttle |
| `use_default_vault` | none | `{ok}` (desktop only, vault must be locked); back to the host's default vault folder |

## Notes and folders

| Command | Arguments | Result |
|---|---|---|
| `tree` | none | nested `{folders:[{id,name,folders,notes}], notes:[{id,title,modified}]}` |
| `get_note` | `id` | `{id,title,body,parent,created,modified}` |
| `create_note` | `title?`, `body?`, `parent?` | `{id}` |
| `create_folder` | `name`, `parent?` | `{id}` (nesting ≤ 64) |
| `update_note` | `id`, `body?`, `title?` | `{ok}` |
| `rename_folder` | `id`, `name` | `{ok}` |
| `move_item` | `id`, `parent` (or null) | `{ok}`; refuses cycles |
| `delete_item` | `id` | `{ok}`; writes a tombstone so deletes sync |
| `search` | `query` (≤ 200 chars) | list of `{id,title,modified}`; in memory only |

`id` and `parent` are 32 lowercase hex characters.

## Sync

| Command | Arguments | Result |
|---|---|---|
| `sync_now` | `auto?` (bool) | report `{pushed,pulled,conflicts,problems,…}`; `auto:true` does not reset the idle timer |
| `set_sync` | `kind`; path from native dialog | `{ok}` (desktop) |
| `clear_sync` | none | `{ok}` |

## Settings

`set_theme` takes `theme` = `"dark"` (default), `"light"` or `"system"`. Allowed while locked (not secret); stored app-wide, not per vault. `status.theme` reports it.

`set_settings` accepts any of: `auto_sync` (bool), `sync_interval` (15–3600), `live_preview` (bool), `toolbar` (bool), `start_note` (`"blank"` or `"last"`), `auto_lock` (seconds: `0` = never, otherwise 60–7200). Defaults: `true`, `60`, `true`, `true`, `"blank"`, the host's idle limit (300 s). `status.settings.auto_lock` and `status.idle_lock` report the effective value; `0` means never. With `start_note = "last"` the UI opens the most recently modified note after unlocking. `status.settings` returns the current values.

## Export

| Command | Arguments | Result |
|---|---|---|
| `export_markdown` | `ids` (32-hex array; absent = everything); folder from native dialog | `{count}` (desktop) |
| `export_download` | `ids` | `{name, mime, count, data}` where `data` is base64url; a single note returns the `.md`, anything else a `.zip` (≤ 32 MiB) |

A selected folder includes everything inside it. An empty `ids` array is an error.

## Security key

| Command | Arguments | Result |
|---|---|---|
| `quick_info` | none | `{enrolled, cred_id, salt, rp_id, label}` |
| `quick_enroll` | `password`, `secret`, `cred_id`, `salt`, `rp_id`, `label?` | `{ok}`; password check is throttled |
| `quick_remove` | none | `{ok}` |

## Example

```bash
# the token is printed in the URL after '#'
curl -s -X POST http://localhost:PORT/api/status \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" -d '{}'
```
