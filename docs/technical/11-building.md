---
title: Building and running
description: Toolchains, commands and outputs for the tests, the web version, the Mac app, the Windows app and the Linux app.
order: 11
---
# Building and running

## Get the source

```bash
git clone https://github.com/ctrlaltmg/ctrlaltnotes.git
cd ctrlaltnotes
```

Requirements: [Rust](https://rustup.rs). The exact compiler version is pinned in `rust-toolchain.toml`; `rustup` installs it automatically the first time you run `cargo` in the folder. All commands below run in the repository root.

Prefer a ready-made build? Download a release and verify it as described in [Install and open](../guide/02-install-and-open.md).

## Release gate (before every commit and release)

```bash
./scripts/check.sh
```

See [Testing](12-testing.md#release-gate). CI runs the same checks.

## Tests

```bash
cargo test
```

Builds and tests `core`, `service` and `server` (the desktop shell is excluded from `default-members` on purpose). The first run downloads crates. This executes the RFC known-answer tests, the NFKC test against the **real** crypto crates.

Use `cargo test --release` to speed up Argon2.

## Web version

Options of the web binary (vault folder, sync target, port, idle lock) are listed in [Web host](07-web-host.md#running-it).

```bash
cargo run --release -p ctrlaltnotes-server
cargo build --release -p ctrlaltnotes-server   # → target/release/ctrlaltnotes-web
```

## macOS app

```bash
xcode-select --install
cargo install tauri-cli --version "^2" --locked
cargo tauri build            # → target/release/bundle/macos and dmg
cargo tauri dev              # live development
```

Universal binary:

```bash
rustup target add aarch64-apple-darwin x86_64-apple-darwin
cargo tauri build --target universal-apple-darwin
```

Unsigned app: System Settings → Privacy & Security → **Open Anyway** after the first launch attempt, or `xattr -dr com.apple.quarantine /Applications/CtrlAltNotes.app` for an app you built or verified yourself.

## Windows app

Build on Windows (Tauri does not reliably cross-compile Windows installers from a Mac).

1. Visual Studio Build Tools with **Desktop development with C++**.
2. Rust (`x86_64-pc-windows-msvc`).
3. WebView2 is part of Windows 10/11; the installer bundles the bootstrapper. For a fully offline installer set `"webviewInstallMode": {"type": "offlineInstaller"}` (about +130 MB).

```powershell
cargo install tauri-cli --version "^2" --locked
cargo tauri build            # → target\release\bundle\nsis and msi
```

A GitHub Actions `windows-latest` runner can run the same commands.

## Linux app

Build on Linux (x86_64 or aarch64). Tauri uses the system **WebKitGTK 4.1** webview, so the build needs its development headers.

Debian / Ubuntu 22.04+:

```bash
sudo apt install build-essential curl file pkg-config libssl-dev \
  libwebkit2gtk-4.1-dev libgtk-3-dev libayatana-appindicator3-dev librsvg2-dev libxdo-dev
```

Fedora:

```bash
sudo dnf install gcc pkgconf-pkg-config openssl-devel webkit2gtk4.1-devel gtk3-devel librsvg2-devel libxdo-devel
```

Arch:

```bash
sudo pacman -S --needed base-devel webkit2gtk-4.1 gtk3 librsvg xdotool openssl
```

Then:

```bash
cargo install tauri-cli --version "^2" --locked
cargo tauri build            # → target/release/bundle/deb, rpm and appimage
cargo tauri build --bundles appimage   # only the AppImage
```

The `.deb` and `.rpm` declare WebKitGTK 4.1 and GTK 3 as dependencies (`bundle.linux` in `tauri.conf.json`). The AppImage carries its own libraries. A GitHub Actions `ubuntu-22.04` runner can run the same commands after the `apt install` line.

The app sets `WEBKIT_DISABLE_DMABUF_RENDERER=1` at start (unless you set it yourself) because the DMA-BUF renderer leaves the window blank on many NVIDIA drivers. Start it with `WEBKIT_DISABLE_DMABUF_RENDERER=0` to opt back in.

## Regenerating assets

```bash
python3 brand/make_brand.py          # app icons and logos (needs rsvg-convert, Pillow, fontTools)
```

## Dependency pins

`argon2 = 0.5.3`, `chacha20poly1305 = 0.10.1`, `hkdf = 0.12`, `sha2 = 0.10`, `getrandom = 0.2`, `base64 = 0.22`. Do not bump the first two to their 0.6 / 0.11 lines without porting `crates/core/src/crypto.rs`.

## Releases

Releases are built only by `.github/workflows/release.yml`, never on a laptop:

1. Update the version in every `Cargo.toml` and in `app/tauri.conf.json`, and add the changelog entry. Run `./scripts/check.sh`.
2. Commit, then create a **signed** tag and push it: `git tag -s v0.1.0-alpha.1 -m "v0.1.0-alpha.1"`, then `git push origin v0.1.0-alpha.1`.
3. The workflow:
   * runs the tests on macOS, Windows and Linux;
   * builds the macOS universal `.dmg`, the Windows NSIS installer, the Linux `.deb`, `.rpm` and AppImage, and the web binaries;
   * writes `SHA256SUMS` and a CycloneDX SBOM;
   * creates a build-provenance attestation for every file;
   * opens a **draft pre-release**.
4. Review the draft (files, notes), then publish it.

The Windows build produces only the NSIS installer: the MSI format can't carry a pre-release version such as `-alpha.1`. Code signing (Apple Developer ID with notarization, Windows Authenticode) is not set up yet; until it is, users verify downloads with `gh attestation verify` or `SHA256SUMS`.
