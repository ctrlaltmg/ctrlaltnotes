// SPDX-License-Identifier: AGPL-3.0-only
//! Regression tests for findings of the fuzz targets in crates/core/fuzz.
use ctrlaltnotes_core::crypto::{open_sealed, seal, TYPE_NOTE};
use serde_json::{json, Value};

/// seal_roundtrip: a float written by canonical JSON must read back as the same number
/// (serde_json needs `float_roundtrip` for exact parsing).
#[test]
fn sealed_object_keeps_floats_exactly() {
    let raw = br#"{"x":16666666666666666666666666332.66666666,"y":0.1,"z":-2.5e-308}"#;
    let obj: Value = serde_json::from_slice(raw).unwrap();
    let key = [9u8; 32];
    let id = "00112233445566778899aabbccddeeff";
    let (_, _, back) = open_sealed(&key, &seal(&key, TYPE_NOTE, id, &obj).unwrap()).unwrap();
    assert_eq!(back, obj);
    assert_eq!(
        back,
        json!({"x": 1.6666666666666667e28, "y": 0.1, "z": -2.5e-308})
    );
}
