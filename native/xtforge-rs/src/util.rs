//! Shared output helpers (mirrors xtforge/cli/common.py `_out`).

use serde_json::{json, Value};

use crate::args::Parsed;

pub fn print_pretty(v: &Value) {
    println!("{}", serde_json::to_string_pretty(v).unwrap());
}

/// `_out(args, obj, human)`: JSON mode prints the object; otherwise the human
/// line when given, else the pretty object.
pub fn out(p: &Parsed, v: &Value, human: Option<String>) -> i32 {
    out_with(p, v, human, 0)
}

/// `_out(args, obj, human, code)`: same, with an explicit exit code.
pub fn out_with(p: &Parsed, v: &Value, human: Option<String>, code: i32) -> i32 {
    if p.json {
        print_pretty(v);
    } else if let Some(h) = human {
        println!("{h}");
    } else {
        print_pretty(v);
    }
    code
}

/// Exception-path handler from xtforge/cli/__main__.
pub fn fail(json_mode: bool, msg: &str, code: i32) -> i32 {
    if json_mode {
        print_pretty(&json!({"ok": false, "error": msg}));
    } else {
        eprintln!("error: {msg}");
    }
    code
}
