// SPDX-License-Identifier: AGPL-3.0-only
//! The padding check runs on every decrypted object: the result must stay inside the input.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(body) = ctrlaltnotes_core::fuzzing::unpad(data) {
        assert!(body.len() + 4 <= data.len());
    }
});
