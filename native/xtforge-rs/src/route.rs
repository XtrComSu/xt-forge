//! Route CLI (mirrors xtforge/core/route/{tools,shortcuts,reference}.py and
//! the live xtscan/xtdigest output shapes).

use std::collections::HashSet;
use std::path::Path;
use std::time::Instant;

use regex::Regex;
use serde_json::{json, Value};

use crate::args::Parsed;
use crate::guard;
use crate::pyjson;
use crate::util;

const DEFAULT_IGNORE: &[&str] = &[
    "node_modules", ".git", "__pycache__", ".cache", "dist", "build", ".venv",
];

fn ignored(name: &str) -> bool {
    DEFAULT_IGNORE.contains(&name)
}

struct Entry {
    path: String,
    is_dir: bool,
    size: u64,
    mtime: i64,
}

fn mtime_of(md: &std::fs::Metadata) -> i64 {
    md.modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn envelope(ok: bool, data: Value, err: Option<String>, ms: i64, truncated: bool) -> Value {
    json!({"ok": ok, "data": data, "err": err, "ms": ms, "truncated": truncated})
}

/// xtscan-family tools apply `_clip` to their data (tools.py `_clip`).
fn envelope_tool(ok: bool, data: Value, err: Option<String>) -> Value {
    let (d, trunc) = clip(data);
    envelope(ok, d, err, 0, trunc)
}

fn clip(v: Value) -> (Value, bool) {
    let text = pyjson::py_dumps(&v);
    if text.chars().count() <= 16000 {
        (v, false)
    } else {
        (
            json!({
                "_clipped": true,
                "_preview": text.chars().take(8000).collect::<String>(),
                "_note": "output exceeded 4000 tokens"
            }),
            true,
        )
    }
}

fn chars_take(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}

/// xtscan-style recursive walk (sorted names, immediate descent, `more` count).
fn walk(base: &str, depth: i64, max_depth: i64, max: usize,
        out: &mut Vec<Entry>, more: &mut usize) {
    if out.len() >= max {
        *more += 1;
        return;
    }
    let Ok(rd) = std::fs::read_dir(base) else {
        return;
    };
    let mut names: Vec<String> = rd
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().to_string())
        .filter(|n| n != "." && n != ".." && !ignored(n))
        .collect();
    names.sort();
    for n in names {
        if out.len() >= max {
            *more += 1;
            continue;
        }
        let full = format!("{base}/{n}");
        let Ok(md) = std::fs::metadata(&full) else {
            continue;
        };
        let is_dir = md.is_dir();
        out.push(Entry {
            path: full.clone(),
            is_dir,
            size: if is_dir { 0 } else { md.len() },
            mtime: mtime_of(&md),
        });
        if is_dir && depth < max_depth {
            walk(&full, depth + 1, max_depth, max, out, more);
        }
    }
}

fn walk_full(base: &str) -> Vec<Entry> {
    let mut out = Vec::new();
    let mut more = 0usize;
    walk(base, 1, 64, usize::MAX, &mut out, &mut more);
    out
}

/// reference.py walk_py semantics (LIFO stack, lstat) for shortcut budgeting.
fn walk_py(root: &str, max_depth: i64, limit: Option<usize>) -> Vec<Entry> {
    let mut out: Vec<Entry> = Vec::new();
    let mut stack: Vec<(String, i64)> = vec![(root.to_string(), 0)];
    while let Some((d, depth)) = stack.pop() {
        if depth > max_depth {
            continue;
        }
        let Ok(rd) = std::fs::read_dir(&d) else {
            continue;
        };
        let mut names: Vec<String> = rd
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().to_string())
            .collect();
        names.sort();
        for n in names {
            if ignored(&n) {
                continue;
            }
            let full = format!("{d}/{n}");
            let Ok(md) = std::fs::symlink_metadata(&full) else {
                continue;
            };
            let is_dir = md.is_dir();
            out.push(Entry {
                path: full.clone(),
                is_dir,
                size: if is_dir { 0 } else { md.len() },
                mtime: mtime_of(&md),
            });
            if is_dir {
                stack.push((full, depth + 1));
            }
            if let Some(l) = limit {
                if out.len() >= l {
                    return out;
                }
            }
        }
    }
    out
}

fn dir_size(base: &str) -> u64 {
    let Ok(rd) = std::fs::read_dir(base) else {
        return 0;
    };
    let mut total = 0u64;
    for e in rd.filter_map(|e| e.ok()) {
        let n = e.file_name().to_string_lossy().to_string();
        if n == "." || n == ".." {
            continue;
        }
        let full = format!("{base}/{n}");
        let Ok(md) = std::fs::metadata(&full) else {
            continue;
        };
        if md.is_dir() {
            if !ignored(&n) {
                total += dir_size(&full);
            }
        } else {
            total += md.len();
        }
    }
    total
}

fn getline_lines(data: &str) -> Vec<String> {
    let mut lines: Vec<String> = data.split('\n').map(String::from).collect();
    if lines.last().map(|s| s.is_empty()).unwrap_or(false) {
        lines.pop();
    }
    lines
}

fn splitlines_py(data: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut cur = String::new();
    let mut chars = data.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\n' => {
                out.push(std::mem::take(&mut cur));
            }
            '\r' => {
                if chars.peek() == Some(&'\n') {
                    chars.next();
                }
                out.push(std::mem::take(&mut cur));
            }
            c => cur.push(c),
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

fn read_text_lossy(path: &str, limit_chars: Option<usize>) -> Option<String> {
    let bytes = std::fs::read(path).ok()?;
    let text = String::from_utf8_lossy(&bytes).to_string();
    Some(match limit_chars {
        Some(n) => chars_take(&text, n),
        None => text,
    })
}

fn hash_bytes(data: &[u8]) -> u64 {
    fn mix(mut h: u64, mut k: u64) -> u64 {
        k = k.wrapping_mul(0xff51afd7ed558ccd);
        k ^= k >> 33;
        k = k.wrapping_mul(0xc4ceb9fe1a85ec53);
        k ^= k >> 29;
        h ^= k;
        h.wrapping_mul(0x100000001b3).wrapping_add(0x165667b19e3779f9)
    }
    let mut h = 0xcbf29ce484222325u64 ^ data.len() as u64;
    let mut i = 0;
    while i + 8 <= data.len() {
        let k = u64::from_le_bytes(data[i..i + 8].try_into().unwrap());
        h = mix(h, k);
        i += 8;
    }
    let mut tail = 0u64;
    while i < data.len() {
        tail = (tail << 8) | data[i] as u64;
        i += 1;
    }
    mix(h, tail)
}

// ---------- handlers ----------

fn route_tree(canon: &Path, depth: i64, max_items: usize) -> Value {
    let mut base = canon.to_string_lossy().to_string();
    if base.ends_with('/') {
        base.pop();
    }
    let mut entries = Vec::new();
    let mut more = 0usize;
    walk(&base, 1, depth, max_items, &mut entries, &mut more);
    let arr: Vec<Value> = entries
        .iter()
        .map(|e| json!({"path": e.path, "dir": e.is_dir, "size": e.size}))
        .collect();
    json!({"root": base, "entries": arr, "shown": entries.len(), "more": more})
}

fn route_find(canon: &Path, name: Option<&str>, regex_pat: Option<&str>,
              type_: Option<&str>, min_size: i64, limit: usize) -> Result<Value, String> {
    let rx = match regex_pat {
        Some(p) if !p.is_empty() => Some(Regex::new(p).map_err(|e| e.to_string())?),
        _ => None,
    };
    let entries = walk_full(&canon.to_string_lossy());
    let mut results: Vec<Value> = Vec::new();
    for e in entries {
        if results.len() >= limit {
            break;
        }
        let name_ok = name.map(|g| guard::fnmatch(g, &e.path)).unwrap_or(true);
        let re_ok = rx.as_ref().map(|r| r.is_match(&e.path)).unwrap_or(true);
        let type_ok = match type_ {
            Some(t) if !t.is_empty() => {
                if t == "d" { e.is_dir } else { !e.is_dir }
            }
            _ => true,
        };
        let size_ok = min_size < 0 || e.size >= min_size as u64;
        if name_ok && re_ok && type_ok && size_ok {
            results.push(json!({"path": e.path, "size": e.size, "mtime": e.mtime}));
        }
    }
    Ok(json!({
        "root": canon.to_string_lossy(), "results": results, "shown": results.len()
    }))
}

fn route_grep(canon: &Path, pattern: &str, glob_pat: Option<&str>, context: usize,
              limit: usize) -> Result<Value, String> {
    let rx = Regex::new(pattern).map_err(|e| e.to_string())?;
    let entries = walk_full(&canon.to_string_lossy());
    let mut matches: Vec<Value> = Vec::new();
    'outer: for e in entries {
        if e.is_dir {
            continue;
        }
        if let Some(g) = glob_pat {
            if !guard::fnmatch(g, &e.path) {
                continue;
            }
        }
        let Ok(bytes) = std::fs::read(&e.path) else {
            continue;
        };
        let probe = &bytes[..bytes.len().min(4096)];
        if probe.contains(&0u8) {
            continue;
        }
        let data = String::from_utf8_lossy(&bytes).to_string();
        let lines = getline_lines(&data);
        for (i, line) in lines.iter().enumerate() {
            if rx.is_match(line) {
                let mut m = serde_json::Map::new();
                m.insert("path".into(), json!(e.path));
                m.insert("line".into(), json!(i + 1));
                m.insert("text".into(), json!(line));
                let mut before = String::new();
                for b in (i.saturating_sub(context))..i {
                    before.push_str(&format!("{}:{}\n", b + 1, lines[b]));
                }
                let mut after = String::new();
                for a in (i + 1)..(i + 1 + context).min(lines.len()) {
                    after.push_str(&format!("{}:{}\n", a + 1, lines[a]));
                }
                if !before.is_empty() {
                    before.pop();
                    m.insert("before".into(), json!(before));
                }
                if !after.is_empty() {
                    after.pop();
                    m.insert("after".into(), json!(after));
                }
                matches.push(Value::Object(m));
                if matches.len() >= limit {
                    break 'outer;
                }
            }
        }
    }
    Ok(json!({
        "root": canon.to_string_lossy(), "pattern": pattern,
        "matches": matches, "shown": matches.len()
    }))
}

fn route_du(canon: &Path, top: usize) -> Value {
    let p = canon.to_string_lossy().to_string();
    let mut items: Vec<(u64, String)> = Vec::new();
    match std::fs::metadata(canon) {
        Ok(md) if md.is_dir() => {
            if let Ok(rd) = std::fs::read_dir(canon) {
                let mut names: Vec<String> = rd
                    .filter_map(|e| e.ok())
                    .map(|e| e.file_name().to_string_lossy().to_string())
                    .filter(|n| n != "." && n != ".." && !ignored(n))
                    .collect();
                names.sort();
                for n in names {
                    let full = format!("{p}/{n}");
                    let Ok(m) = std::fs::metadata(&full) else {
                        continue;
                    };
                    let sz = if m.is_dir() { dir_size(&full) } else { m.len() };
                    items.push((sz, full));
                }
            }
        }
        Ok(md) => items.push((md.len(), p.clone())),
        Err(_) => {}
    }
    items.sort_by(|a, b| b.0.cmp(&a.0));
    items.truncate(top);
    let arr: Vec<Value> = items
        .iter()
        .map(|(s, path)| json!({"path": path, "size": s}))
        .collect();
    json!({"path": p, "top": arr})
}

fn route_recent(canon: &Path, minutes: i64, limit: usize) -> Value {
    let entries = walk_full(&canon.to_string_lossy());
    let cutoff = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
        - minutes * 60;
    let mut recent: Vec<&Entry> = entries
        .iter()
        .filter(|e| !e.is_dir && e.mtime >= cutoff)
        .collect();
    recent.sort_by(|a, b| b.mtime.cmp(&a.mtime));
    recent.truncate(limit);
    let arr: Vec<Value> = recent
        .iter()
        .map(|e| json!({"path": e.path, "mtime": e.mtime, "size": e.size}))
        .collect();
    json!({"root": canon.to_string_lossy(), "recent": arr, "shown": arr.len()})
}

fn route_peek(canon: &Path, mode: &str, start: i64, count: i64) -> Value {
    if canon.is_dir() {
        return route_tree(canon, 1, 200);
    }
    let path = canon.to_string_lossy().to_string();
    let Some(data) = read_text_lossy(&path, None) else {
        return json!({"error": "not_found", "path": path});
    };
    let lines = getline_lines(&data);
    if mode == "outline" {
        let mut blank = 0usize;
        let mut comment = 0usize;
        let mut code = 0usize;
        for l in &lines {
            let t = l.trim_start_matches([' ', '\t', '\r']);
            if t.is_empty() {
                blank += 1;
            } else if t.starts_with('#') || t.starts_with("//") {
                comment += 1;
            } else {
                code += 1;
            }
        }
        let bytes = std::fs::read(&path).unwrap_or_default();
        json!({
            "path": path, "total_lines": lines.len(), "blank": blank,
            "comment": comment, "code": code,
            "digest": format!("{:016x}", hash_bytes(&bytes))
        })
    } else {
        let start = start.max(1);
        let mut sel: Vec<String> = Vec::new();
        let mut n = start;
        while n < start + count && n <= lines.len() as i64 {
            sel.push(format!("{}:{}", n, lines[(n - 1) as usize]));
            n += 1;
        }
        json!({
            "path": path, "start": start, "total_lines": lines.len(), "lines": sel
        })
    }
}

// ---------- shortcuts ----------

const PRIORITY: &[&str] = &["README", "pyproject", "package.json", "tsconfig", "PROGRESS", "VERSION"];

fn project_files(base: &Path) -> Vec<String> {
    let entries = walk_py(&base.to_string_lossy(), 4, Some(1000));
    let mut files: Vec<String> = entries
        .iter()
        .filter(|e| !e.is_dir)
        .filter(|e| guard::is_denied_name(&e.path).is_none())
        .map(|e| e.path.clone())
        .collect();
    let base_str = base.to_string_lossy().to_string();
    files.sort_by(|a, b| {
        let ka = priority_key(a);
        let kb = priority_key(b);
        ka.cmp(&kb)
            .then(parts_len(a).cmp(&parts_len(b)))
            .then(a.cmp(b))
    });
    let _ = base_str;
    files
}

fn priority_key(path: &str) -> bool {
    let name = Path::new(path)
        .file_name()
        .map(|s| s.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    !PRIORITY.iter().any(|x| name.starts_with(&x.to_lowercase()))
}

fn parts_len(path: &str) -> usize {
    Path::new(path).components().count()
}

fn directory_lines(base: &Path, files: &[String], budget: usize) -> Vec<String> {
    let mut lines = vec![format!("ROOT {}", base.to_string_lossy())];
    let mut dirs: Vec<String> = Vec::new();
    for f in files {
        let rel = Path::new(f)
            .parent()
            .and_then(|p| p.strip_prefix(base).ok())
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_default();
        if !dirs.contains(&rel) {
            dirs.push(rel);
        }
    }
    dirs.sort();
    for directory in dirs.iter().take(80) {
        let candidate = format!("DIR {}", if directory.is_empty() { "." } else { directory });
        let mut probe = lines.clone();
        probe.push(candidate.clone());
        if pyjson::tokens(&probe.join("\n")) > budget {
            break;
        }
        lines.push(candidate);
    }
    lines
}

fn context_excerpts(base: &Path, files: &[String], lines: &[String], budget: usize,
                    cap: usize) -> Vec<String> {
    let mut excerpts: Vec<String> = Vec::new();
    let mut used = pyjson::tokens(&lines.join("\n"));
    for path in files {
        if excerpts.len() >= cap || used >= budget {
            break;
        }
        let canon = match guard::read_guard(path) {
            Ok(c) => c,
            Err(_) => continue,
        };
        let limit = 6000.min((budget - used) * 4);
        let Some(text) = read_text_lossy(&canon.to_string_lossy(), Some(limit)) else {
            continue;
        };
        if text.is_empty() || text.chars().take(2000).any(|c| c == '\0') {
            continue;
        }
        let rel = canon
            .strip_prefix(base)
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_else(|_| canon.to_string_lossy().to_string());
        let mut excerpt = format!("FILE {rel}\n{}", text.trim());
        excerpt = chars_take(&excerpt, (budget - used) * 4);
        if excerpt.is_empty() {
            break;
        }
        excerpts.push(excerpt);
        used += pyjson::tokens(excerpts.last().unwrap());
    }
    excerpts
}

fn payload_tokens(data: &mut Value) -> usize {
    let mut estimate = 0usize;
    for _ in 0..3 {
        data["estimated_tokens"] = json!(estimate);
        estimate = pyjson::tokens(&pyjson::py_dumps(data));
    }
    data["estimated_tokens"] = json!(estimate);
    estimate
}

fn route_context(root: &str, token_budget: i64, file_limit: i64) -> Value {
    let base = match guard::read_guard(root) {
        Ok(b) => b,
        Err(d) => return envelope(false, Value::Null, Some(format!("{}: {}", d.code, d.reason)), 0, false),
    };
    if !base.is_dir() {
        return envelope(false, Value::Null, Some("not_a_directory".into()), 0, false);
    }
    let budget = token_budget.clamp(32, 4000) as usize;
    let files = project_files(&base);
    let lines = directory_lines(&base, &files, budget);
    let cap = file_limit.clamp(1, 40) as usize;
    let mut excerpts = context_excerpts(&base, &files, &lines, budget, cap);
    let mut output = lines
        .iter()
        .chain(excerpts.iter())
        .cloned()
        .collect::<Vec<_>>()
        .join("\n");
    while pyjson::tokens(&output) > budget && !excerpts.is_empty() {
        excerpts.pop();
        output = lines
            .iter()
            .chain(excerpts.iter())
            .cloned()
            .collect::<Vec<_>>()
            .join("\n");
    }
    if pyjson::tokens(&output) > budget {
        output = String::new();
    }
    let mut data = json!({
        "root": base.to_string_lossy(), "files": files.len(),
        "context": output, "estimated_tokens": 0, "token_budget": budget
    });
    let mut estimate = payload_tokens(&mut data);
    while estimate > budget && !excerpts.is_empty() {
        excerpts.pop();
        data["context"] = json!(lines
            .iter()
            .chain(excerpts.iter())
            .cloned()
            .collect::<Vec<_>>()
            .join("\n"));
        estimate = payload_tokens(&mut data);
    }
    if estimate > budget {
        data["context"] = json!("");
        estimate = payload_tokens(&mut data);
    }
    data["estimated_tokens"] = json!(estimate);
    envelope(true, data, None, 0, false)
}

fn route_batch_peek(paths: &[String], token_budget: i64, lines_per_file: i64) -> Value {
    let budget = token_budget.clamp(32, 4000) as usize;
    let line_cap = lines_per_file.clamp(1, 200) as usize;
    let mut output: Vec<Value> = Vec::new();
    let mut used = 0usize;
    for raw in paths.iter().take(30) {
        let path = match guard::read_guard(raw) {
            Ok(p) => p,
            Err(d) => {
                output.push(json!({"path": raw, "ok": false, "err": d.code}));
                continue;
            }
        };
        if !path.is_file() {
            output.push(json!({"path": path.to_string_lossy(), "ok": false, "err": "not_a_file"}));
            continue;
        }
        let text = read_text_lossy(&path.to_string_lossy(), Some(budget.saturating_sub(used) * 4))
            .unwrap_or_default();
        let selected = splitlines_py(&text)
            .iter()
            .take(line_cap)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n");
        let mut item = json!({"path": path.to_string_lossy(), "ok": true, "text": selected});
        let mut candidate = output.clone();
        candidate.push(item.clone());
        if pyjson::tokens(&pyjson::py_dumps(&json!(candidate))) > budget {
            let remaining = (budget * 4)
                .saturating_sub(pyjson::py_dumps(&json!(output)).chars().count())
                .saturating_sub(64);
            item["text"] = json!(chars_take(&selected, remaining));
            candidate = output.clone();
            candidate.push(item.clone());
            if pyjson::tokens(&pyjson::py_dumps(&json!(candidate))) > budget {
                break;
            }
        }
        output.push(item);
        used = pyjson::tokens(&pyjson::py_dumps(&json!(output)));
    }
    let mut data = json!({
        "files": output, "estimated_tokens": used, "token_budget": budget
    });
    while payload_tokens(&mut data) > budget && !data["files"].as_array().map(|a| a.is_empty()).unwrap_or(true) {
        data["files"].as_array_mut().unwrap().pop();
    }
    let est = payload_tokens(&mut data);
    data["estimated_tokens"] = json!(est);
    envelope(true, data, None, 0, false)
}

fn route_errors(path: &str, max_lines: i64, token_budget: i64) -> Value {
    let canon = match guard::read_guard(path) {
        Ok(c) => c,
        Err(d) => return envelope(false, Value::Null, Some(format!("{}: {}", d.code, d.reason)), 0, false),
    };
    if !canon.is_file() {
        return envelope(false, Value::Null, Some("not_a_file".into()), 0, false);
    }
    let Some(text) = read_text_lossy(&canon.to_string_lossy(), Some(2_000_000)) else {
        return envelope(false, Value::Null, Some("not_a_file".into()), 0, false);
    };
    if text.chars().take(4096).any(|c| c == '\0') {
        return envelope(false, Value::Null, Some("binary_file".into()), 0, false);
    }
    let cap = max_lines.clamp(1, 200) as usize;
    let budget = token_budget.clamp(32, 4000) as usize;
    let re = Regex::new(r"(?i)\b(error|failed|failure|exception|traceback|fatal|assert)\b")
        .expect("static regex");
    let lines = splitlines_py(&text);
    let matches: Vec<usize> = lines
        .iter()
        .enumerate()
        .filter(|(_, l)| re.is_match(l))
        .map(|(i, _)| i)
        .collect();
    let mut combined: Vec<(i64, String)> = Vec::new();
    for &i in &matches {
        combined.push((i as i64 + 1, lines[i].clone()));
    }
    for &i in &matches {
        if i > 0 {
            combined.push((i as i64, lines[i - 1].clone()));
        }
        if i + 1 < lines.len() {
            combined.push((i as i64 + 2, lines[i + 1].clone()));
        }
    }
    let mut seen: HashSet<(i64, String)> = HashSet::new();
    let mut kept: Vec<String> = Vec::new();
    let mut truncated = false;
    for (number, line) in combined {
        if !seen.insert((number, line.clone())) {
            continue;
        }
        if kept.len() >= cap {
            truncated = true;
            break;
        }
        let item = format!("{number}: {line}");
        let mut probe = kept.clone();
        probe.push(item.clone());
        if pyjson::tokens(&probe.join("\n")) > budget {
            if re.is_match(&line) && kept.is_empty() {
                kept.push(chars_take(&item, budget * 4));
            }
            truncated = true;
            break;
        }
        kept.push(item);
    }
    let data = json!({
        "path": canon.to_string_lossy(), "lines": kept, "matches": matches.len(),
        "estimated_tokens": pyjson::tokens(&kept.join("\n")), "token_budget": budget
    });
    envelope(true, data, None, 0, truncated)
}

// ---------- entry ----------

pub fn run(p: &Parsed) -> Option<i32> {
    let verb = p.verb.as_deref()?;
    if !matches!(
        verb,
        "tree" | "find" | "grep" | "peek" | "du" | "recent" | "context"
            | "batch-peek" | "errors"
    ) {
        return None;
    }
    let t0 = Instant::now();
    let result = match verb {
        "tree" => {
            let raw = p.pos(0).unwrap_or(".");
            let depth = p.fint("depth", 2);
            let max = p.fint("max", 200) as usize;
            match guard::read_guard(raw) {
                Err(d) => envelope(false, Value::Null, Some(format!("{}: {}", d.code, d.reason)), 0, false),
                Ok(canon) => {
                    if !canon.exists() {
                        envelope(false, Value::Null, Some(format!("not_found: {}", canon.to_string_lossy())), 0, false)
                    } else {
                        envelope_tool(true, route_tree(&canon, depth, max), None)
                    }
                }
            }
        }
        "find" => {
            let raw = p.pos(0).unwrap_or(".");
            let name = p.fstr("name").or_else(|| p.pos(1).map(String::from));
            let regex_pat = p.fstr("regex");
            let type_ = p.fstr("type");
            let min_size = p.fint("min-size", -1);
            let limit = p.fint("limit", 50) as usize;
            match guard::read_guard(raw) {
                Err(d) => envelope(false, Value::Null, Some(format!("{}: {}", d.code, d.reason)), 0, false),
                Ok(canon) => match route_find(&canon, name.as_deref(), regex_pat.as_deref(),
                                              type_.as_deref(), min_size, limit) {
                    Ok(data) => envelope_tool(true, data, None),
                    Err(e) => envelope(false, Value::Null, Some(e), 0, false),
                },
            }
        }
        "grep" => {
            let raw = p.pos(0).unwrap_or(".");
            let pattern = p.fstr("pattern").or_else(|| p.fstr("regex")).unwrap_or_default();
            let glob_pat = p.fstr("glob");
            let context = p.fint("context", 1) as usize;
            let limit = p.fint("limit", 50) as usize;
            match guard::read_guard(raw) {
                Err(d) => envelope(false, Value::Null, Some(format!("{}: {}", d.code, d.reason)), 0, false),
                Ok(canon) => match route_grep(&canon, &pattern, glob_pat.as_deref(), context, limit) {
                    Ok(data) => envelope_tool(true, data, None),
                    Err(e) => envelope(false, Value::Null, Some(e), 0, false),
                },
            }
        }
        "peek" => {
            let raw = p.pos(0).unwrap_or(".");
            let mode = p.fstr("mode").unwrap_or_else(|| "head".into());
            let start = p.fint("start", 1);
            let count = p.fint("count", 50);
            match guard::read_guard(raw) {
                Err(d) => envelope(false, Value::Null, Some(format!("{}: {}", d.code, d.reason)), 0, false),
                Ok(canon) => {
                    if !canon.exists() {
                        envelope(false, Value::Null, Some(format!("not_found: {}", canon.to_string_lossy())), 0, false)
                    } else {
                        envelope_tool(true, route_peek(&canon, &mode, start, count), None)
                    }
                }
            }
        }
        "du" => {
            let raw = p.pos(0).unwrap_or(".");
            let top = p.fint("top", 15) as usize;
            match guard::read_guard(raw) {
                Err(d) => envelope(false, Value::Null, Some(format!("{}: {}", d.code, d.reason)), 0, false),
                Ok(canon) => {
                    if !canon.exists() {
                        return Some(util::fail(
                            p.json,
                            &format!("[Errno 2] No such file or directory: '{}'", canon.display()),
                            1,
                        ));
                    }
                    envelope_tool(true, route_du(&canon, top), None)
                }
            }
        }
        "recent" => {
            let roots: Vec<String> = if !p.flist("paths").is_empty() {
                p.flist("paths")
            } else if let Some(x) = p.pos(0) {
                vec![x.to_string()]
            } else {
                vec![".".to_string()]
            };
            let minutes = p.fint("minutes", 60);
            let limit = p.fint("limit", 30) as usize;
            let mut out: Vec<Value> = Vec::new();
            for r in roots {
                match guard::read_guard(&r) {
                    Err(d) => out.push(json!({"root": r, "error": d.reason})),
                    Ok(canon) => out.push(route_recent(&canon, minutes, limit)),
                }
            }
            envelope_tool(true, Value::Array(out), None)
        }
        "context" => {
            if p.fstr("query").is_some() || p.fbool("symbols") {
                return None;
            }
            let root = p.pos(0).unwrap_or(".");
            let budget = p.fint("token-budget", 1200);
            let file_limit = p.fint("file-limit", 12);
            route_context(root, budget, file_limit)
        }
        "batch-peek" => {
            let mut paths = p.flist("paths");
            if paths.is_empty() {
                if let Some(x) = p.pos(0) {
                    paths.push(x.to_string());
                }
            }
            let budget = p.fint("token-budget", 1200);
            let lines_per_file = p.fint("lines-per-file", 30);
            route_batch_peek(&paths, budget, lines_per_file)
        }
        "errors" => {
            let raw = p.pos(0).unwrap_or("");
            let max_lines = p.fint("max-lines", 40);
            let budget = p.fint("token-budget", 800);
            route_errors(raw, max_lines, budget)
        }
        _ => return None,
    };
    let ms = t0.elapsed().as_millis() as i64;
    let mut result = result;
    result["ms"] = json!(ms);
    Some(util::out(p, &result, None))
}
