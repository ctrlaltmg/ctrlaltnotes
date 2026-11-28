---
title: Changelog
description: What changed in each version.
order: 18
---
# Changelog

## Unreleased

* **Fuzzing** of the parsers that read untrusted files (`crates/core/fuzz`, 6 targets, CI workflow `fuzz`).
* Fix (found by fuzzing): some floating-point numbers in JSON came back one digit different after encrypting and decrypting an object. JSON is now parsed exactly (`serde_json` `float_roundtrip`). The app itself stores no floats, so no vault was affected.
* Fix: the Code block button mangled selected text that contained `$'`, `$&` or `` $` `` (for example shell snippets).

## 0.1.0-alpha.1

First public release, for testing. Not code-signed yet; verify downloads as described in [Install and open](../guide/02-install-and-open.md).


* **Hardening** (see [Hardening checklist](19-hardening.md)):
  * desktop window: no default Tauri permissions, frozen JavaScript prototypes, navigation guard;
  * Rust: overflow checks in release builds, workspace lints, exact toolchain pin;
  * CI: every GitHub Action pinned to a commit SHA, OpenSSF Scorecard;
  * website: Trusted Types, COEP and Origin-Agent-Cluster headers, a check that fails on any third-party load.
  * dependencies: `url` 2.5.9 (RUSTSEC-2026-0592, stack overflow on nested `blob:` URLs) and `cookie` 0.18.3 (RUSTSEC-2026-0594, used inside Tauri).
* **Website:** Markdown version of the home page for AI agents; shorter titles and description; features now list Linux, themes and multiple vaults.
* Fix: docs search showed no results because of a wrong field name.
* **Theme setting** (Settings → Appearance, first option): Dark (default), Light, or Match system. Stored app-wide; applied before first paint by `theme.js`.
* **Open a different vault folder** from the create and unlock screens (desktop). Each vault keeps its own settings and sync target; the choice is remembered; **Use the default vault** goes back.
* **Linux** desktop app: `.deb`, `.rpm` and AppImage bundles from the same backend.
* Collapsed sidebar shows the app icon at the top.
* Fix: highlighted inline code (`==`code`==`) was unreadable in the dark theme and grey in the light theme; content inside a highlight now keeps the yellow background and dark text.
* Release gate `scripts/check.sh` and a CI workflow (Linux, macOS, Windows); `forbid(unsafe_code)` extended to the desktop shell and the web binary.
* User guide rewritten in plain language.

## Development before the first release

* New **When the app opens** setting (blank page or last edited note). Live preview and toolbar are switched on or off in Settings only.
* **Live preview is a side-by-side editor**: Markdown on the left, the formatted note on the right. Turned off in Settings, only the Markdown editor shows. The **Preview** button shows only the rendered text.
* **Selectable auto-lock**: 1 to 120 minutes, or Never (Settings → Security).
* **Sidebar**: logo spans the sidebar at a fixed width; the sidebar can be resized (280 px up to a quarter of the window) and collapsed to a strip. New note / New folder are right-click options only.
* **Drag and drop** of notes and folders between folders and to the top level.
* The top bar has only Preview and Settings; Lock sits at the bottom of the sidebar.
* Single product name everywhere: crates, vault format labels (`ctrlaltnotes-vault`, `CAN1`), object files (`.can`), data folder and app identifier. There is no compatibility layer for earlier prototypes.
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
