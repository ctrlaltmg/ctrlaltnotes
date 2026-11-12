// SPDX-License-Identifier: AGPL-3.0-only
//! CtrlAltNotes core: end-to-end encrypted Markdown vault (format v1).
//!
//! * `crypto`  – Argon2id, HKDF-SHA256, ChaCha20-Poly1305, sealed object files
//! * `vault`   – folders / notes, unlock / lock, recovery key, password change, export
//! * `sync`    – hybrid-logical-clock merge against a folder mirrored by any cloud client
//! * `bundle`  – single-file sync target (for clouds/pickers that handle one file at a time)
//!
#![forbid(unsafe_code)]

pub mod bundle;
pub mod crypto;
pub mod error;
pub mod fsutil;
pub mod json;
pub mod policy;
pub mod quick;
pub mod sync;
pub mod vault;
pub mod zip;

pub use bundle::{join_from_bundle, sync_bundle};
pub use crypto::{KdfParams, KDF_DEFAULT, KDF_MIN};
pub use error::{Result, VaultError};
pub use sync::{sync_folder, SyncReport};
pub use vault::{FolderNode, NoteData, NoteEntry, Obj, Tree, Vault};
