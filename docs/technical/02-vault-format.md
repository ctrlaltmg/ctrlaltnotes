---
title: Vault format v1
description: Exact layout of the header, object files and plaintext, as implemented in `crates/core/src`.
order: 2
---
# Vault format v1

The format is defined by `crates/core/src` and exercised by the tests in `crates/core/tests`.

## Header (`vault.json`)

Canonical JSON: sorted keys, compact separators, ASCII-escaped.

```json
{
  "format": "ctrlaltnotes-vault",
  "version": 1,
  "vault_id": "<32 hex>",
  "header_rev": 1,
  "kdf": { "alg": "argon2id", "m": 65536, "t": 3, "p": 4, "salt": "<b64url>" },
  "wrap_pw": "<b64url>",
  "wrap_rec": "<b64url>"
}
```

* `header_rev` increases on every password change and is part of the authenticated data.
* KDF parameters are validated on read: floor `m=19456 KiB, t=2, p=1` (OWASP minimum), ceilings `m=1,048,576, t=20, p=16` so a hostile file cannot demand gigabytes.
* The header is the AAD of both key wraps. Changing any field (a KDF downgrade, a swapped vault id) makes unwrap fail.

## Object file (`objects/<id>.can`)

```text
offset  size  field
0       4     magic "CAN1"
4       1     type (note, folder, ...)
5       16    object id
21      32    per-file random salt
53      12    nonce
65      ...   ciphertext || 16-byte Poly1305 tag
```

* **AAD** = the first 53 bytes (magic, type, id, salt).
* **Subkey** = HKDF-SHA256(master key, salt = the 32-byte file salt, info = `"ctrlaltnotes/v1/obj/" + type`).
* **Cipher**: ChaCha20-Poly1305 with a fresh random nonce on every write.

## Plaintext

`u32 length || canonical JSON`, padded with zeros to a multiple of 1 KiB, so file sizes only reveal rounded lengths.

The JSON holds: `id`, `kind`, `parent`, `title` / `body` (notes) or `name` (folders), `deleted`, `created`, `modified`, and the hybrid logical clock `hlc = [wall_ms, counter, device]`.

Limits: body ≤ 4 MiB; names and titles are cleaned (control characters, length).

## Device-local files

| File | Content | Synced? |
|---|---|---|
| `state.can` | Which clock value of every object was last in sync (used to detect concurrent edits) | **Never** |
| `quick.json` | Security-key slot: wrapped master key + credential metadata | **Never** |
| `vault.json.pending` | A newer header seen in the sync folder, adopted at the next unlock only if it authenticates | Written by sync |

Writes are atomic (temp file + rename) and files/folders are created with private permissions (`0600` / `0700` on Unix).
