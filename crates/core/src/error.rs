// SPDX-License-Identifier: AGPL-3.0-only
use std::fmt;

/// Every failure. Messages are deliberately generic (no oracle for attackers, no paths leaked).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VaultError {
    /// Wrong password/key or tampered data (indistinguishable by design).
    Auth(&'static str),
    Other(String),
}

pub type Result<T> = std::result::Result<T, VaultError>;

impl VaultError {
    pub fn other(msg: impl Into<String>) -> Self {
        VaultError::Other(msg.into())
    }
    pub fn is_auth(&self) -> bool {
        matches!(self, VaultError::Auth(_))
    }
}

impl fmt::Display for VaultError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VaultError::Auth(m) => f.write_str(m),
            VaultError::Other(m) => f.write_str(m),
        }
    }
}

impl std::error::Error for VaultError {}

impl From<std::io::Error> for VaultError {
    fn from(_e: std::io::Error) -> Self {
        VaultError::Other("file operation failed".to_string())
    }
}

pub(crate) fn corrupt() -> VaultError {
    VaultError::Auth("corrupt object")
}

pub(crate) fn cannot_unlock() -> VaultError {
    VaultError::Auth("could not unlock")
}

pub(crate) fn malformed() -> VaultError {
    VaultError::Other("malformed vault data".to_string())
}
