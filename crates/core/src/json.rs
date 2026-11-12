// SPDX-License-Identifier: AGPL-3.0-only
//! Thin helpers over `serde_json::Value`. Objects are converted by hand (no derive) so every
//! field is validated explicitly, and a canonical serializer gives byte-stable output
//! (sorted keys, no whitespace, ASCII-only escapes).
use serde_json::{Map, Number, Value};

pub type JMap = Map<String, Value>;

pub fn vs(s: &str) -> Value {
    Value::String(s.to_string())
}

pub fn vi(n: i64) -> Value {
    Value::Number(Number::from(n))
}

pub fn get_str<'a>(m: &'a JMap, k: &str) -> Option<&'a str> {
    m.get(k).and_then(|v| v.as_str())
}

pub fn get_i64(m: &JMap, k: &str) -> Option<i64> {
    m.get(k).and_then(|v| v.as_i64())
}

pub fn get_bool(m: &JMap, k: &str) -> Option<bool> {
    m.get(k).and_then(|v| v.as_bool())
}

pub fn canonical(v: &Value) -> Vec<u8> {
    let mut out = String::new();
    write_value(v, &mut out);
    out.into_bytes()
}

fn write_value(v: &Value, out: &mut String) {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => out.push_str(&n.to_string()),
        Value::String(s) => write_str(s, out),
        Value::Array(a) => {
            out.push('[');
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_value(x, out);
            }
            out.push(']');
        }
        Value::Object(m) => {
            let mut items: Vec<(&String, &Value)> = m.iter().collect();
            items.sort_by(|a, b| a.0.cmp(b.0));
            out.push('{');
            for (i, (k, x)) in items.into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_str(k, out);
                out.push(':');
                write_value(x, out);
            }
            out.push('}');
        }
    }
}

fn write_str(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 || (c as u32) > 0x7e => {
                let mut buf = [0u16; 2];
                for unit in c.encode_utf16(&mut buf).iter() {
                    out.push_str(&format!("\\u{:04x}", unit));
                }
            }
            c => out.push(c),
        }
    }
    out.push('"');
}
