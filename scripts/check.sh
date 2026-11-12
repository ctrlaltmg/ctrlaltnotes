#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Release gate: run before every commit and every build you ship. CI runs the same steps.
# Fails on: formatting drift, any clippy warning, any failing test, any known vulnerability
# in Cargo.lock, a dependency license that is not AGPL-compatible, a committed secret, a JavaScript
# syntax error in ui/.
set -euo pipefail
cd "$(dirname "$0")/.."

step() { printf '\n== %s\n' "$1"; }

step "rustfmt"
cargo fmt --all -- --check

step "clippy (all crates, all targets, warnings are errors)"
cargo clippy --workspace --all-targets --locked -- -D warnings

step "tests (release: real Argon2 cost)"
cargo test --workspace --exclude ctrlaltnotes-desktop --release --locked

step "dependency advisories (RustSec)"
if command -v cargo-audit >/dev/null 2>&1; then
  cargo audit
else
  echo "cargo-audit missing: cargo install cargo-audit --locked" >&2
  exit 1
fi

step "dependency policy: licenses, sources, bans (cargo-deny)"
if command -v cargo-deny >/dev/null 2>&1; then
  cargo deny --locked check licenses bans sources advisories
else
  echo "cargo-deny missing: cargo install cargo-deny --locked" >&2
  exit 1
fi

step "secrets in the working tree (gitleaks)"
if command -v gitleaks >/dev/null 2>&1; then
  gitleaks dir . --no-banner --redact --exit-code 1 >/dev/null
  if [ -d .git ]; then gitleaks git . --no-banner --redact --exit-code 1 >/dev/null; fi
else
  echo "gitleaks missing: brew install gitleaks (or see https://github.com/gitleaks/gitleaks)" >&2
  exit 1
fi

step "UI JavaScript syntax"
for f in ui/*.js; do node --check "$f"; done

printf '\nAll checks passed.\n'
