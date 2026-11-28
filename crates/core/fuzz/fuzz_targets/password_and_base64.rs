// SPDX-License-Identifier: AGPL-3.0-only
//! Password policy and base64 decoding see user and file input: no panics on any string.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|s: &str| {
    let _ = ctrlaltnotes_core::policy::check_new_password(s);
    let _ = ctrlaltnotes_core::crypto::normalize_password(s);
    let _ = ctrlaltnotes_core::crypto::b64d(s);
});
