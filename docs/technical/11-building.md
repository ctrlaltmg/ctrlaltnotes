---
title: Building and running
description: Toolchains, commands and outputs for the tests, the web version, the Mac app, the Windows app and the Linux app.
order: 11
---
# Building and running

Requirements: Rust stable 1.80 or newer.

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

Unsigned app: right-click → Open, or `xattr -dr com.apple.quarantine /Applications/CtrlAltNotes.app`.

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
# in ctrlaltnotes-app/ (also refreshes ../ctrlaltnotes-website/site/assets)
python3 brand/make_brand.py          # icons + logos (needs rsvg-convert, Pillow, fontTools)

# in ctrlaltnotes-website/
python3 docs-src/build.py            # docs site → site/docs
```

## Dependency pins

`argon2 = 0.5.3`, `chacha20poly1305 = 0.10.1`, `hkdf = 0.12`, `sha2 = 0.10`, `getrandom = 0.2`, `base64 = 0.22`. Do not bump the first two to their 0.6 / 0.11 lines without porting `crates/core/src/crypto.rs`.
