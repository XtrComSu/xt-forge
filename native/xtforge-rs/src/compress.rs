//! Compression CLI (mirrors xtforge/core/compress/passes.py + legend.py).

use std::collections::HashMap;
use std::io::Read;
use std::sync::OnceLock;

use regex::Regex;
use serde_json::{json, Value};

use crate::args::Parsed;
use crate::pyjson;
use crate::util;

macro_rules! static_re {
    ($name:ident, $pat:expr) => {
        fn $name() -> &'static Regex {
            static R: OnceLock<Regex> = OnceLock::new();
            R.get_or_init(|| Regex::new($pat).expect("static regex"))
        }
    };
}

static_re!(high_value_re, r"(?i)ERROR|FAIL|Traceback|assert|Exception|panic:|FATAL|error:|warning:");
static_re!(ansi_re, r"\x1b\[[0-9;?]*[ -/]*[@-~]");
static_re!(ws_run_re, r"[ \t]{2,}");
static_re!(progress_re, r"^[\s|/\-\\.=+*#▓▒░█▁▂▃▄▅▆▇]*\d{1,4}(?:\.\d+)?%[\s|/\-\\.=+*#▓▒░█▁▂▃▄▅▆▇]*$");
static_re!(spinner_re, r"^[\s|/\-\\.█▁▂▃▄▅▆▇]+$");
static_re!(stack_frame_re, r#"^\s*File "(.+?)", line (\d+), in (.+)$"#);
static_re!(frame_summary_re, r"^\s*\[\d+ frames\]$");
static_re!(more_frames_re, r"^\s*…\+\d+ more frames$");
static_re!(summarized_frame_re, r"^\s+\S+:\d+ in \S+$");
static_re!(diff_plus_re, r"(?m)^\+\+\+ b/(.+)$");
static_re!(stat_line_re, r"^(\d+) files? changed");
static_re!(word_re, r"\w+");
static_re!(token_re, r"[A-Za-z0-9_./\\\-]{8,}");

fn est_tokens(text: &str) -> usize {
    (text.chars().count() + 3) / 4
}

fn is_high_value(line: &str) -> bool {
    high_value_re().is_match(line)
}

fn strip_ansi(text: &str) -> String {
    ansi_re().replace_all(text, "").to_string()
}

fn collapse_whitespace(line: &str) -> String {
    let line = line.trim_end();
    let trimmed_start = line.trim_start_matches([' ', '\t']);
    let lead = line.len() - trimmed_start.len();
    let body = ws_run_re().replace_all(line.trim(), " ").to_string();
    if !body.is_empty() || lead == 0 {
        format!("{}{}", " ".repeat(lead), body)
    } else {
        body
    }
}

fn collapse_repeats(lines: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        let line = &lines[i];
        let mut n = 1;
        let mut j = i + 1;
        while j < lines.len() && lines[j] == *line {
            n += 1;
            j += 1;
        }
        if n > 1 && !is_high_value(line) {
            out.push(format!("{line} ×{n}"));
        } else if n > 1 {
            out.push(format!("{line} ×{n} (error line preserved)"));
        } else {
            out.push(line.clone());
        }
        i = j;
    }
    out
}

fn drop_noise(lines: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    let mut blanks = 0;
    for line in lines {
        if line.trim().is_empty() {
            blanks += 1;
            if blanks <= 1 {
                out.push(String::new());
            }
            continue;
        }
        blanks = 0;
        if !is_high_value(line) && (progress_re().is_match(line) || spinner_re().is_match(line)) {
            continue;
        }
        out.push(line.clone());
    }
    out
}

fn minify_json(text: &str) -> String {
    let stripped = text.trim();
    let Some(first) = stripped.chars().next() else {
        return text.to_string();
    };
    if first != '[' && first != '{' {
        return text.to_string();
    }
    match serde_json::from_str::<Value>(stripped) {
        Ok(v) => pyjson::py_dumps_min(&v),
        Err(_) => text.to_string(),
    }
}

fn pass_l1(text: &str) -> Value {
    let original = text;
    let lines: Vec<String> = strip_ansi(original).split('\n').map(String::from).collect();
    let lines: Vec<String> = lines.iter().map(|l| collapse_whitespace(l)).collect();
    let lines = drop_noise(&lines);
    let lines = collapse_repeats(&lines);
    let lines: Vec<String> = lines.iter().map(|l| minify_json(l)).collect();
    let mut out = lines.join("\n");
    while out.contains("\n\n\n") {
        out = out.replace("\n\n\n", "\n\n");
    }
    let out = out.trim_matches('\n').to_string();
    let ratio = if original.is_empty() {
        1.0
    } else {
        out.chars().count() as f64 / original.chars().count() as f64
    };
    json!({
        "text": out, "level": "L1", "ratio": ratio,
        "tokens_before": est_tokens(original), "tokens_after": est_tokens(&out)
    })
}

fn l2_input(text: &str) -> String {
    pass_l1(text)["text"].as_str().unwrap_or("").to_string()
}

fn summarize_stack(text: &str) -> String {
    let lines: Vec<&str> = text.split('\n').collect();
    let mut sig: Option<String> = None;
    let mut frames: Vec<String> = Vec::new();
    for line in lines {
        if let Some(c) = stack_frame_re().captures(line) {
            frames.push(format!("  {}:{} in {}", &c[1], &c[2], &c[3]));
        } else if is_high_value(line) && !line.starts_with("  File") && sig.is_none() {
            sig = Some(line.trim().to_string());
        }
    }
    let mut out: Vec<String> = Vec::new();
    if let Some(s) = sig {
        out.push(s);
    }
    if !frames.is_empty() {
        out.push(format!("  [{} frames]", frames.len()));
        out.extend(frames.iter().take(3).cloned());
        if frames.len() > 3 {
            out.push(format!("  …+{} more frames", frames.len() - 3));
        }
    }
    out.join("\n")
}

fn head_tail_stats(text: &str, head: usize, tail: usize) -> String {
    let lines: Vec<&str> = text.split('\n').collect();
    let total = lines.len();
    if total <= head + tail + 2 {
        return text.to_string();
    }
    let mut keep: Vec<String> = lines[..head].iter().map(|s| s.to_string()).collect();
    keep.push(format!("… [{} lines elided] …", total - head - tail));
    keep.extend(lines[total - tail..].iter().map(|s| s.to_string()));
    keep.join("\n")
}

fn diff_stat(text: &str) -> Option<String> {
    let stripped = text.trim_start();
    if !(stripped.starts_with("diff --git") || stripped.starts_with("--- ") || stripped.starts_with("+++ ")) {
        return None;
    }
    let files: Vec<String> = diff_plus_re()
        .captures_iter(text)
        .map(|c| c[1].to_string())
        .collect();
    let changed: Vec<String> = text
        .split('\n')
        .filter(|l| stat_line_re().is_match(l))
        .map(String::from)
        .collect();
    let mut out = changed;
    out.push(format!("files: {}", files.len()));
    out.extend(files.iter().take(10).map(|f| format!("  {f}")));
    Some(out.join("\n"))
}

fn pass_l2(text: &str) -> Value {
    let original = text;
    let pre = l2_input(original);
    let out = if pre.contains("Traceback (most recent call last)") && pre.contains("  File \"") {
        summarize_stack(&pre)
    } else if pre.contains("Traceback (most recent call last)") {
        let kept: Vec<String> = pre
            .split('\n')
            .filter(|l| {
                l.contains("Traceback")
                    || is_high_value(l)
                    || frame_summary_re().is_match(l)
                    || more_frames_re().is_match(l)
                    || summarized_frame_re().is_match(l)
            })
            .map(String::from)
            .collect();
        if kept.is_empty() {
            pre.clone()
        } else {
            kept.join("\n")
        }
    } else {
        match diff_stat(&pre) {
            Some(s) => s,
            None => head_tail_stats(&strip_ansi(&pre), 10, 5),
        }
    };
    let mut kept: Vec<String> = Vec::new();
    for l in pre.split('\n') {
        if !is_high_value(l) {
            continue;
        }
        let stripped = l.trim();
        if stripped.is_empty() || out.contains(stripped) {
            continue;
        }
        if frame_summary_re().is_match(l) || more_frames_re().is_match(l)
            || stack_frame_re().is_match(l)
        {
            continue;
        }
        if !kept.iter().any(|k| k == stripped) {
            kept.push(stripped.to_string());
        }
    }
    let out = if kept.is_empty() {
        out
    } else {
        format!("{}\n{}", out, kept.join("\n"))
    };
    let ratio = if original.is_empty() {
        1.0
    } else {
        out.chars().count() as f64 / original.chars().count() as f64
    };
    json!({
        "text": out, "level": "L2", "ratio": ratio,
        "tokens_before": est_tokens(original), "tokens_after": est_tokens(&out),
        "error_lines_kept": kept.len() + 1
    })
}

pub fn compress(text: &str, level: &str) -> Value {
    match level {
        "L0" => json!({
            "text": text, "level": "L0", "ratio": 1.0,
            "tokens_before": est_tokens(text), "tokens_after": est_tokens(text)
        }),
        "L1" => pass_l1(text),
        "L2" => {
            let l2 = pass_l2(text);
            pass_l1(l2["text"].as_str().unwrap_or(""))
        }
        "L3" => pass_l2(text),
        _ => pass_l1(text),
    }
}

fn line_stats(text: &str) -> Value {
    let lines: Vec<&str> = text.split('\n').collect();
    let hv = lines.iter().filter(|l| is_high_value(l)).count();
    let joined = lines.join(" ");
    let mut counts: HashMap<String, usize> = HashMap::new();
    let mut order: Vec<String> = Vec::new();
    for m in word_re().find_iter(&joined) {
        let w = m.as_str().to_string();
        if !counts.contains_key(&w) {
            order.push(w.clone());
        }
        *counts.entry(w).or_insert(0) += 1;
    }
    let mut words: Vec<(String, usize)> = order
        .into_iter()
        .map(|w| {
            let c = counts[&w];
            (w, c)
        })
        .collect();
    words.sort_by(|a, b| b.1.cmp(&a.1));
    let top: Vec<Value> = words.iter().take(5).map(|(w, c)| json!([w, c])).collect();
    json!({
        "lines": lines.len(), "chars": text.chars().count(),
        "tokens": est_tokens(text), "high_value_lines": hv, "top_words": top
    })
}

fn apply_legend(text: &str) -> Value {
    let src = text;
    let (body, trailing) = if let Some(stripped) = src.strip_suffix('\n') {
        (stripped.to_string(), "\n")
    } else {
        (src.to_string(), "")
    };
    let token_re = token_re();
    let mut counts: HashMap<String, usize> = HashMap::new();
    let mut order: Vec<String> = Vec::new();
    for m in token_re.find_iter(&body) {
        let s = m.as_str().to_string();
        if !counts.contains_key(&s) {
            order.push(s.clone());
        }
        *counts.entry(s).or_insert(0) += 1;
    }
    let mut cands: Vec<(String, usize)> = order
        .into_iter()
        .filter_map(|s| {
            let c = counts[&s];
            if c >= 3 {
                Some((s, c))
            } else {
                None
            }
        })
        .collect();
    cands.sort_by(|a, b| {
        let ka = a.1 * a.0.chars().count();
        let kb = b.1 * b.0.chars().count();
        kb.cmp(&ka).then(a.0.cmp(&b.0))
    });
    if cands.is_empty() {
        return json!({"text": src, "legend": {}, "replaced": 0});
    }
    let mut out = body;
    let mut legend: Vec<(String, String)> = Vec::new();
    for (i, (s, _c)) in cands.iter().enumerate() {
        let alias = format!("§{}", i + 1);
        out = out.replace(s, &alias);
        legend.push((alias, s.clone()));
    }
    let legend_line = format!(
        "LEGEND: {}",
        legend
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join(" | ")
    );
    let legend_map: serde_json::Map<String, Value> = legend
        .iter()
        .map(|(k, v)| (k.clone(), json!(v)))
        .collect();
    json!({
        "text": format!("{legend_line}\n{out}{trailing}"),
        "legend": Value::Object(legend_map),
        "replaced": legend.len()
    })
}

pub fn run(p: &Parsed) -> Option<i32> {
    // `compress` is the one noun whose "verb" slot is the level positional.
    let level = p.verb.clone().unwrap_or_else(|| "L1".to_string());
    if !matches!(level.as_str(), "L0" | "L1" | "L2" | "L3") {
        return None; // argparse would reject; python fallback prints its error
    }
    let text = if let Some(t) = p.fstr("text") {
        t
    } else if let Some(path) = p.fstr("path") {
        match std::fs::read_to_string(&path) {
            Ok(t) => t,
            Err(e) => return Some(util::fail(p.json, &format!("{e}"), 1)),
        }
    } else {
        let mut buf = String::new();
        let _ = std::io::stdin().read_to_string(&mut buf);
        buf
    };
    if p.fbool("legend") {
        let res = apply_legend(&text);
        return Some(util::out(p, &res, None));
    }
    let mut res = compress(&text, &level);
    if p.fbool("stats") {
        res["stats"] = line_stats(&text);
    }
    let human = res["text"].as_str().unwrap_or("").to_string();
    Some(util::out(p, &res, Some(human)))
}
