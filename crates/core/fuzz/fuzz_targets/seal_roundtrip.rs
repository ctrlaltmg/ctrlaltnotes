// SPDX-License-Identifier: AGPL-3.0-only
//! Any JSON object that can be sealed must open again to exactly the same object
//! (padding, canonical JSON and the envelope agree with each other).
#![no_main]
use ctrlaltnotes_core::crypto::{open_sealed, seal, TYPE_FOLDER, TYPE_NOTE, TYPE_STATE};
use libfuzzer_sys::fuzz_target;

const KEY: [u8; 32] = [9; 32];
const ID: &str = "00112233445566778899aabbccddeeff";

fuzz_target!(|data: &[u8]| {
    let Some((&t, json)) = data.split_first() else {
        return;
    };
    let typ = [TYPE_NOTE, TYPE_FOLDER, TYPE_STATE][usize::from(t) % 3];
    let Ok(obj) = serde_json::from_slice::<serde_json::Value>(json) else {
        return;
    };
    if !obj.is_object() {
        return;
    }
    if let Ok(sealed) = seal(&KEY, typ, ID, &obj) {
        let (t2, id2, obj2) = open_sealed(&KEY, &sealed).expect("a sealed object must open");
        assert_eq!((t2, id2.as_str(), &obj2), (typ, ID, &obj));
    }
});
