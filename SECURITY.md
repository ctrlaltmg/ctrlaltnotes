# Security policy

CtrlAltNotes is an end-to-end encrypted notes app. Security reports are the most important
issues we receive and are handled before anything else.

## Reporting a vulnerability

**Do not open a public issue, discussion or pull request for a vulnerability.**

Report it privately through GitHub:
**Security → Advisories → Report a vulnerability**
(<https://github.com/ctrlaltmg/ctrlaltnotes/security/advisories/new>).

Please include:

* the affected version or commit, and platform (macOS, Windows, Linux, web version);
* steps to reproduce or a proof of concept;
* the impact you expect (for example: plaintext disclosure, key recovery, code execution in the
  window, bypass of the unlock throttle).

## What to expect

| Step | Target |
|---|---|
| Acknowledgement | within 72 hours |
| First assessment (confirmed or not, severity) | within 7 days |
| Fix released for critical and high issues | within 90 days, usually much sooner |
| Public advisory | after a fix is available, with credit if you want it |

We follow coordinated disclosure. If a report is not acted on within these times, you are free to
publish after notifying us.

## Scope

In scope: everything in this repository: `crates/core` (cryptography, vault format, sync),
`crates/service`, `crates/server` (the localhost web host), `app/` (desktop shell), `ui/`.

Out of scope: an attacker who controls the unlocked computer (malware, a keylogger), lost
passwords or recovery keys, denial of service from your own cloud provider. See
[`docs/technical/13-security-model.md`](docs/technical/13-security-model.md) and
[`docs/technical/15-known-limits.md`](docs/technical/15-known-limits.md).

## Supported versions

Only the latest release receives security fixes until 1.0.

## Verifying releases

Release artifacts are built in GitHub Actions from a signed tag and published with SHA-256 checksums
and build provenance attestations. Verify a download with:

```bash
gh attestation verify <file> --repo ctrlaltmg/ctrlaltnotes
```
