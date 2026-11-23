---
title: Hardening checklist
description: Every security control in the app, the web host, the website and the supply chain, how each is verified, and what is still open.
order: 19
---
# Hardening checklist

This page lists every hardening measure, where it lives and how it is checked. "Open" items are known gaps, in priority order.

## Desktop app (Tauri)

| Control | Where | Checked by |
|---|---|---|
| Strict CSP: `default-src 'none'`, scripts and styles only from the app, no inline code, IPC only | `app/tauri.conf.json` | Tauri enforces it at runtime |
| **Least-privilege capabilities**: no `core:default`. The page can call only the app's own `rpc` command and open http(s)/mailto links in the system browser | `app/capabilities/default.json` | Build-time ACL check |
| **Frozen JavaScript prototypes** (`freezePrototype`) against prototype pollution | `app/tauri.conf.json` | Runtime |
| **Navigation guard**: the window can only show the bundled UI. Any navigation elsewhere is refused, so a remote page can never end up next to the IPC bridge | `app/src/main.rs` (`navigation_allowed`) | Code review |
| File paths only from native dialogs opened in Rust, never from the page | `app/src/main.rs`, `crates/service` | Service tests |
| One IPC entry point; every command validated in the service | `crates/service` | 31 service tests |
| Keys wiped on lock, idle, window close and quit (`zeroize`); decrypted DOM cleared | `crates/core`, `ui/app.js` | Tests and review |
| No dev tools in release builds | Tauri default (no `devtools` feature) | Build config |
| UI builds every node with `createElement`/`textContent`; no HTML from strings | `ui/*.js` | Review; `md_robustness.py` |

## Rust code

| Control | Where |
|---|---|
| `unsafe_code = "forbid"` for every crate and binary | `Cargo.toml` `[workspace.lints]`, crate attributes |
| Clippy with warnings as errors; `dbg!`, `todo!`, `unimplemented!` and `mem::forget` denied | `scripts/check.sh`, `[workspace.lints.clippy]` |
| **Integer overflow checks kept in release builds** | `[profile.release] overflow-checks = true` |
| `panic = "abort"`, LTO, stripped symbols | `[profile.release]` |
| Exact compiler version for reproducible builds | `rust-toolchain.toml` |
| RFC known-answer tests for the cryptography; NIST password policy tests; penetration-test regression tests | `crates/core/tests` |

## Web host (`ctrlaltnotes-web`)

Loopback only, a random launch token, Host and Origin checks, request size and time limits, a strict CSP and security headers, no path accepted from the page. See [Web host](07-web-host.md) and the [pentest report](14-pentest-report.md).

## Supply chain and repository

| Control | Where |
|---|---|
| `cargo audit` (RustSec) and `cargo deny` (licenses AGPL-compatible, crates.io only, advisories) on every build | `scripts/check.sh`, CI |
| Secret scanning: gitleaks in the release gate, a pre-commit hook, and CI over the full history | `.gitleaks.toml`, CI |
| **Every GitHub Action pinned to a full commit SHA**; Dependabot updates them | `.github/workflows/*.yml`, `.github/dependabot.yml` |
| Rust installed by `rustup` from `rust-toolchain.toml`, so no third-party setup action is needed | CI |
| Read-only workflow token; checkout keeps no credentials; job timeouts | CI |
| OpenSSF Scorecard published to the Security tab | `.github/workflows/scorecard.yml` |
| Signed commits and tags; ruleset on `main` (signatures, linear history, PR, all checks) | GitHub settings |
| Private vulnerability reporting, coordinated disclosure | `SECURITY.md` |

## Website (ctrlaltnotes.com)

| Control | Checked by |
|---|---|
| **No third-party loads**: every script, style, image, font and frame comes from the site itself | `tools/check_site.py` in CI |
| **No cookies, no analytics, no trackers**; search runs in the browser | `check_site.py`, privacy policy |
| CSP in every page and as a header: `default-src 'self'`, no inline code, `object-src 'none'`, `frame-ancestors 'none'`, **Trusted Types required** (no HTML-string sinks in any script) | `check_site.py`; tested in Chromium |
| HSTS (2 years, subdomains; preload after a stable period), `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, a restrictive `Permissions-Policy`, COOP, CORP, COEP, `Origin-Agent-Cluster` | `site/_headers` (Cloudflare Pages); MDN Observatory |
| DNSSEC, SPF `-all`, DMARC `p=reject`, null MX, domain verified on GitHub against takeover | Cloudflare DNS; internet.nl |
| `security.txt` pointing to private reporting | `/.well-known/security.txt` |

### Search engines and AI agents
* **Search engines:**
  * a unique title (≤ 60 characters where possible), description, canonical link, Open Graph and Twitter cards on every page;
  * structured data: SoftwareApplication, SoftwareSourceCode, Organization, WebSite with SearchAction, FAQ, TechArticle and breadcrumbs;
  * a sitemap with real modification dates, a 404 page, and dimensions on images.
* **AI agents:**
  * `robots.txt` allows search and AI crawlers;
  * `/llms.txt` is generated from the docs;
  * `/llms-full.txt` holds all the docs in one file;
  * **every page, including the home page, has a Markdown version** at its URL plus `.md`, announced with `<link rel="alternate" type="text/markdown">`.

## Open items

1. **Independent security audit** before calling the app production-ready (Open Technology Fund Red Team Lab or OSTIF can fund it).
2. **Fuzzing** of the parsers that read untrusted cloud files (vault header, object files, bundle, ZIP writer input, Markdown renderer) with `cargo fuzz`.
3. **Release integrity**:
   * build in CI only;
   * code signing (Apple Developer ID and notarization, Windows Authenticode);
   * `SHA256SUMS`, build provenance (`actions/attest-build-provenance`), an SBOM (`cargo cyclonedx`), and binaries built with `cargo auditable`.
4. **Trusted Types in the desktop window**: the UI already has no HTML sinks. Enable `require-trusted-types-for 'script'` once it has been tested on WebView2 (Windows) and WebKitGTK (Linux).
5. **Tauri isolation pattern**: deliberately not used. It defends against compromised frontend dependencies, and the UI has none, while the CSP, ACL and single command already restrict IPC. Revisit if a frontend dependency is ever added.
6. **macOS App Sandbox**: would need security-scoped bookmarks for the vault and sync folders. Revisit for a Mac App Store build.
7. **HSTS preload** once the site has been stable on HTTPS for a few weeks.
8. **Smaller hero media**: replace the animated GIFs with short MP4/WebM videos with poster frames. That cuts about 1.9 MB of GIFs and improves Largest Contentful Paint.
