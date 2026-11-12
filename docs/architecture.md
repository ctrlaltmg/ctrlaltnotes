# CtrlAltNotes architecture

See [`technical/01-overview.md`](technical/01-overview.md) for the full version.

```
            ┌───────────────┐        ┌────────────────────┐
  ui/ ───►  │ Tauri window  │  IPC   │                    │
 (HTML/JS)  │ rpc(cmd,args) ├───────►│  ctrlaltnotes-      │──► core: Vault / sync / bundle / crypto
            └───────────────┘        │  service           │       │
            ┌───────────────┐  HTTP  │  Service::dispatch │       ▼
  ui/ ───►  │ browser       ├───────►│  (single entry)    │   vault dir (ciphertext files)
            │ POST /api/cmd │ Bearer └────────────────────┘
            └───────────────┘
```
* `ui/api.js` picks the transport (Tauri `invoke` or `fetch`); the UI code is identical.
* Commands: status, touch, create_vault, unlock, join_vault, lock, change_password, tree, get_note, create_note, create_folder,
  update_note, rename_folder, move_item, delete_item, search, sync_now, set_sync, clear_sync, export_markdown, export_download (web),
  set_settings, set_theme, open_vault_folder / use_default_vault (desktop), quick_* (security key).
* Errors reach the UI as plain strings: `locked`, `throttled:N`, `cancelled`, or a short message.
* On-disk layout: `vault.json` (header), `objects/<32hex>.can`, `state.can` (device-local, never uploaded), optional `vault.json.pending`.
