// SPDX-License-Identifier: AGPL-3.0-only
//! .can object files come from the sync folder: framing and authentication must reject any
//! bytes without panicking.
#![no_main]
use libfuzzer_sys::fuzz_target;

const KEY: [u8; 32] = [7; 32];

fuzz_target!(|data: &[u8]| {
    let _ = ctrlaltnotes_core::crypto::open_sealed(&KEY, data);
});
