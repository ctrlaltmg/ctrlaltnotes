---
title: Cryptography
description: Algorithms, key hierarchy, and why each choice was made.
order: 3
---
# Cryptography

All primitives come from audited **RustCrypto** crates. Nothing is hand-rolled.

| Purpose | Algorithm | Crate | Standard |
|---|---|---|---|
| Password → key | **Argon2id** (default 64 MiB, t=3, p=4) | `argon2` 0.5 | RFC 9106 |
| Authenticated encryption | **ChaCha20-Poly1305** | `chacha20poly1305` 0.10 | RFC 8439 |
| Key derivation | **HKDF-SHA256** | `hkdf` 0.12, `sha2` | RFC 5869 |
| Randomness | OS CSPRNG | `getrandom` 0.2 | |
| Password normalisation | Unicode **NFKC** | `unicode-normalization` | NIST SP 800-63B |

!!! warning "Pinned versions"
    `argon2` 0.6 and `chacha20poly1305` 0.11 have different APIs. Do not bump these crates without porting `crates/core/src/crypto.rs`.

## Key hierarchy

```text
password ──NFKC──► Argon2id(salt) ──► KEK_pw ──unwrap──┐
recovery key (256-bit) ──HKDF("…/recovery")──► KEK_rec ─┤──► master key (MK, 256-bit random)
security key secret ─HKDF(vault_id,"…/quick")► KEK_q ───┘        │
                                                                 ▼
                                          per-object subkey = HKDF(MK, file salt, "…/obj/<type>")
                                                                 │
                                                  ChaCha20-Poly1305(nonce, AAD = first 53 bytes)
```

* The **master key** is random and never derived from the password, so a password change re-wraps one key and re-encrypts **no** note (O(1)).
* A new **recovery key** is issued on every password change.
* Per-file subkeys mean a nonce collision in one file cannot affect another.

## Why these defaults

* **Argon2id** resists GPU and ASIC guessing; 64 MiB / t=3 / p=4 is above the OWASP minimum (19 MiB / t=2 / p=1).
* **ChaCha20-Poly1305** is fast in software on every platform (no AES hardware needed) and misuse-resistant enough with random 96-bit nonces under per-file subkeys.
* **AAD binding** ties ciphertext to its object id and type, so swapping or renaming files is detected.

## Memory hygiene

Keys are held in `Zeroizing` buffers and wiped on lock. See [Known limits](15-known-limits.md) for what is **not** covered (decrypted note text in process memory, no `mlock`).

## Verification

* RFC known-answer tests for HKDF, ChaCha20-Poly1305 and Argon2id (`crates/core/tests/kat.rs`).
* NFKC password test.

These need the real crates, so they run on your machine with `cargo test`.
