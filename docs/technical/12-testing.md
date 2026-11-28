---
title: Testing
description: Test suites, what each proves, and what was and was not run in the authoring environment.
order: 12
---
# Testing

| Suite | Where | What it proves |
|---|---|---|
| Core unit + integration | `crates/core/tests/` (`vault`, `sync`, `security`, `kat`) | Format, sync convergence, password policy, quick-unlock binding, RFC known answers |
| Service | `crates/service/tests/service.rs` | Command validation, throttling, settings, quick unlock, export, locked-state refusals |
| Server | `crates/server/tests/http.rs` | 17 raw-socket tests: headers, token, Host/Origin, smuggling, limits, slowloris, IPv6 bind |
| Browser end-to-end | `tests/e2e_ui.py` | 92 checks of the real UI against the real server binary (Playwright, WebAuthn virtual authenticator) |
| Markdown robustness | `tests/md_robustness.py` | Adversarial notes render quickly and never throw |
| Fuzzing | `crates/core/fuzz/` (`cargo fuzz`, 6 targets) | Vault header, `.can` objects, seal/open round trip, padding, bundle files, password and base64 input: no panic, no wrong result on any bytes. CI workflow `fuzz`: 2 min per target on changes, 10 min weekly |

## Running

```bash
cargo test
pip install playwright && playwright install chromium
cargo build -p ctrlaltnotes-server
python3 tests/e2e_ui.py target/debug/ctrlaltnotes-web
python3 tests/md_robustness.py
```

Fuzzing needs a nightly compiler (only for the fuzzers; the apps use the pinned stable one):

```bash
rustup toolchain install nightly-2026-11-28 --profile minimal && cargo install cargo-fuzz --version 0.13.2 --locked   # once
cd crates/core/fuzz && cargo +nightly-2026-11-28 fuzz run bundle_unpack -- -max_total_time=60   # any target: cargo fuzz list
```

A failing input is saved under `crates/core/fuzz/artifacts/`. Fix the bug, add it as a regular test (see `crates/core/tests/json_roundtrip.rs`), then rerun the target.

## Release gate

```bash
cargo install cargo-audit --locked   # once
./scripts/check.sh
```

Runs `cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --release`, `cargo audit` and `node --check ui/*.js`, and stops on the first failure. `.github/workflows/ci.yml` runs the same on Linux, macOS and Windows for every push and pull request, and builds the desktop crate on each.

`cargo audit` currently reports no vulnerabilities. It does report five warnings (unmaintained or unsound crates), all in Tauri's Linux GTK/WebKitGTK/D-Bus dependency chain (`glib 0.18`, `zbus`/`zvariant`, `proc-macro-error`); none are called by CtrlAltNotes code. They clear when Tauri moves to gtk-rs 0.20+.

## Verification status (honest)

* On macOS with the real crypto crates: the full release gate passes, including the RFC known-answer tests and the NFKC test.
* The macOS desktop app is built and used day to day.
* The backend type-checks for `x86_64-unknown-linux-gnu`. The Linux and Windows desktop bundles have not yet been built on those systems (CI covers the build).
