---
title: Changelog
description: What changed in each version.
order: 18
---
# Changelog

## Unreleased

* **Theme setting** (Settings → Appearance, first option): Dark (default), Light, or Match system. Stored app-wide; applied before first paint by `theme.js`.
* **Open a different vault folder** from the create and unlock screens (desktop). Each vault keeps its own settings and sync target; the choice is remembered; **Use the default vault** goes back.
* **Linux** desktop app: `.deb`, `.rpm` and AppImage bundles from the same backend.
* Collapsed sidebar shows the app icon at the top.
* Fix: highlighted inline code (`==`code`==`) was unreadable in the dark theme and grey in the light theme; content inside a highlight now keeps the yellow background and dark text.
* Release gate `scripts/check.sh` and a CI workflow (Linux, macOS, Windows); `forbid(unsafe_code)` extended to the desktop shell and the web binary.
* User guide rewritten in plain language.

## 0.1.0

* New **When the app opens** setting (blank page or last edited note). Live preview and toolbar are switched on or off in Settings only.
* **Live preview is a side-by-side editor**: Markdown on the left, the formatted note on the right. Turned off in Settings, only the Markdown editor shows. The **Preview** button shows only the rendered text.
* **Selectable auto-lock**: 1 to 120 minutes, or Never (Settings → Security).
* **Sidebar**: logo spans the sidebar at a fixed width; the sidebar can be resized (280 px up to a quarter of the window) and collapsed to a strip. New note / New folder are right-click options only.
* **Drag and drop** of notes and folders between folders and to the top level.
* The top bar has only Preview and Settings; Lock sits at the bottom of the sidebar.
* Single product name everywhere: crates, vault format labels (`ctrlaltnotes-vault`, `CAN1`), object files (`.can`), data folder and app identifier. There is no compatibility layer for earlier prototypes.
* Website and documentation moved to their own folder, `ctrlaltnotes-website/`, separate from the application.
* Renamed to **CtrlAltNotes**; new notes icon and logo; icons regenerated for every platform.
* Sync button removed; automatic sync is a switch in **Settings** (on by default).
* Settings in a popup window; live Markdown preview; optional formatting toolbar with extended syntax (tables, task lists, underline, highlight).
* Selective export; the web version downloads the selection as `.md` or `.zip` through the browser.
* Security key / fingerprint unlock (WebAuthn PRF).
* New password policy (NIST SP 800-63B-4).
* Editor scrollbars hidden; wheel, touch and keyboard scrolling kept.
* Penetration-test fixes (see the [report](14-pentest-report.md)).
* Fix: dialogs had no background and export checkboxes stretched across the dialog.
* Web binary renamed to `ctrlaltnotes-web`.
