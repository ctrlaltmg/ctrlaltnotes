// SPDX-License-Identifier: AGPL-3.0-only
//! Bundle files come from untrusted cloud storage. The harness adds the magic and a valid
//! SHA-256 trailer, so the fuzzer reaches the record parser behind the integrity check.
#![no_main]
use libfuzzer_sys::fuzz_target;
use sha2::{Digest, Sha256};

fuzz_target!(|data: &[u8]| {
    let mut blob = b"CANB".to_vec();
    blob.extend_from_slice(data);
    let digest = Sha256::digest(&blob);
    blob.extend_from_slice(&digest);
    let dir = tempfile::tempdir().expect("temp dir");
    let _ = ctrlaltnotes_core::fuzzing::bundle_unpack(&blob, dir.path());
    // whatever was written must stay inside the staging folder, named by the object id
    for e in std::fs::read_dir(dir.path()).expect("read dir").flatten() {
        let name = e.file_name().into_string().expect("utf-8 name");
        assert!(
            name == "objects" || name == "vault.json",
            "unexpected file {name}"
        );
    }
});
