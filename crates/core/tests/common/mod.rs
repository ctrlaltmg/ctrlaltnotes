// SPDX-License-Identifier: AGPL-3.0-only
#![allow(dead_code)]
use ctrlaltnotes_core::{KdfParams, Vault, KDF_MIN};
use std::path::{Path, PathBuf};

pub const PW: &str = "correct horse battery staple";
pub const FAST: KdfParams = KDF_MIN;

pub fn new_vault(dir: &Path) -> (Vault, String) {
    Vault::create(dir, PW, Some(FAST)).expect("create")
}

pub fn objects(dir: &Path) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = std::fs::read_dir(dir.join("objects"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|e| e == "can"))
        .collect();
    v.sort();
    v
}

/// Deterministic xorshift PRNG for reproducible fuzz-style tests.
pub struct Rng(pub u64);
impl Rng {
    pub fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    pub fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}
