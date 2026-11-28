// SPDX-License-Identifier: AGPL-3.0-only
//! vault.json comes from the sync folder: any bytes must be rejected cleanly, never panic.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = ctrlaltnotes_core::vault::parse_header(data);
});
