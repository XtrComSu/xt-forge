//! Python-compatible JSON serialization (length/escape accurate).
//!
//! `shortcuts.py` budgets by `len(json.dumps(x, ensure_ascii=False))`, so the
//! Rust side needs the same separators (", " / ": ") and escaping rules to
//! produce identical token estimates. Key order does not affect length.

use serde_json::Value;

pub fn escape_into(s: &str, out: &mut String, ascii: bool) {
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c if ascii && (c as u32) > 0x7f => {
                let cp = c as u32;
                if cp <= 0xffff {
                    out.push_str(&format!("\\u{:04x}", cp));
                } else {
                    let v = cp - 0x10000;
                    let hi = 0xd800 + (v >> 10);
                    let lo = 0xdc00 + (v & 0x3ff);
                    out.push_str(&format!("\\u{:04x}\\u{:04x}", hi, lo));
                }
            }
            c => out.push(c),
        }
    }
}

pub fn dumps(v: &Value, ascii: bool, sep: &str, kv: &str) -> String {
    let mut out = String::new();
    write_val(v, &mut out, ascii, sep, kv);
    out
}

/// Python `json.dumps` defaults: separators ", " and ": ", ensure_ascii=False.
pub fn py_dumps(v: &Value) -> String {
    dumps(v, false, ", ", ": ")
}

/// Python `json.dumps(..., separators=(",", ":"), sort_keys=True)` (ascii on).
pub fn py_dumps_min(v: &Value) -> String {
    dumps(v, true, ",", ":")
}

fn write_val(v: &Value, out: &mut String, ascii: bool, sep: &str, kv: &str) {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => out.push_str(&n.to_string()),
        Value::String(s) => {
            out.push('"');
            escape_into(s, out, ascii);
            out.push('"');
        }
        Value::Array(a) => {
            out.push('[');
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.push_str(sep);
                }
                write_val(x, out, ascii, sep, kv);
            }
            out.push(']');
        }
        Value::Object(m) => {
            out.push('{');
            for (i, (k, x)) in m.iter().enumerate() {
                if i > 0 {
                    out.push_str(sep);
                }
                out.push('"');
                escape_into(k, out, ascii);
                out.push('"');
                out.push_str(kv);
                write_val(x, out, ascii, sep, kv);
            }
            out.push('}');
        }
    }
}

/// Token estimate used across compress/shortcuts: ceil(chars/4).
pub fn tokens(text: &str) -> usize {
    (text.chars().count() + 3) / 4
}
