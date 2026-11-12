# Contributing

Thank you for helping. Because CtrlAltNotes protects people's private notes, every change goes
through the same checks, and changes to cryptography get extra review.

## Before you start

* **Security issues**: do not open an issue. Follow [`SECURITY.md`](SECURITY.md).
* **Bugs and ideas**: open an issue first so the approach can be agreed before you write code.
* **Code contributions**: see [Licensing of contributions](#licensing-of-contributions) below.

## Development setup

```bash
# Rust (stable, 1.80+): https://rustup.rs
cargo install cargo-audit cargo-deny --locked
brew install gitleaks            # or see https://github.com/gitleaks/gitleaks
cargo test                       # backend tests
cargo run -p ctrlaltnotes-server # web version
cargo install tauri-cli --version "^2" --locked
cargo tauri dev                  # desktop app
```

Linux needs the WebKitGTK packages listed in [`docs/technical/11-building.md`](docs/technical/11-building.md).

## The release gate

Every commit must pass:

```bash
./scripts/check.sh
```

It runs rustfmt, clippy with warnings as errors, the release-mode tests, `cargo audit`,
`cargo deny` (licenses, sources, advisories), a gitleaks secret scan and a JavaScript syntax
check. CI runs the same on Linux, macOS and Windows; a pull request cannot be merged while it fails.

## Rules for changes

* No `unsafe` code (`#![forbid(unsafe_code)]` everywhere).
* New dependencies need a reason in the pull request, a license on the `deny.toml` allow-list, and
  should be widely used and maintained. Fewer dependencies is better.
* Anything that touches `crates/core/src/crypto.rs`, the vault format or sync needs a test and an
  update to the matching page in `docs/technical/`.
* The UI never builds HTML from strings; paths are never accepted from the page.
* Update `docs/technical/18-changelog.md` for user-visible changes.

## Commits

* Sign your commits (SSH or GPG): `main` only accepts signed commits.
* Add a `Signed-off-by:` line (`git commit -s`), certifying the
  [Developer Certificate of Origin](https://developercertificate.org/).
* Write the subject in the imperative ("Add theme setting"), 72 characters or less.

## Licensing of contributions

The project is licensed under **AGPL-3.0-only**. The apps are also distributed through the Apple
App Store and Google Play, whose terms are not compatible with the AGPL for code owned by third
parties. Projects in the same situation (for example Signal) therefore ask contributors to sign a
Contributor License Agreement.

Until a CLA is published in this repository, **external code contributions cannot be merged**.
Issues, bug reports, reproductions, documentation feedback and security reports are very welcome.
