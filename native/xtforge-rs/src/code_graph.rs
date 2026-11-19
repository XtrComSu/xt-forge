//! Persistent multi-language symbol & call/import graph (`code_graph.db`).

use std::collections::{HashMap, HashSet, VecDeque};
use std::path::Path;
use std::time::Instant;

use regex::Regex;
use rusqlite::{params, Connection};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::args::Parsed;
use crate::guard;
use crate::paths;
use crate::util;

const GRAPH_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS files (
  path TEXT PRIMARY KEY,
  lang TEXT NOT NULL,
  sha256 TEXT NOT NULL,
  mtime INTEGER NOT NULL,
  loc INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS symbols (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  file_path TEXT NOT NULL,
  name TEXT NOT NULL,
  fqname TEXT NOT NULL,
  kind TEXT NOT NULL,
  line INTEGER NOT NULL,
  signature TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_sym_file ON symbols(file_path);
CREATE INDEX IF NOT EXISTS idx_sym_name ON symbols(name);
CREATE TABLE IF NOT EXISTS edges (
  src_name TEXT NOT NULL,
  dst_name TEXT NOT NULL,
  rel TEXT NOT NULL,
  file_path TEXT NOT NULL,
  line INTEGER NOT NULL,
  UNIQUE(src_name, dst_name, rel, file_path, line)
);
CREATE INDEX IF NOT EXISTS idx_edge_src ON edges(src_name);
CREATE INDEX IF NOT EXISTS idx_edge_dst ON edges(dst_name);
"#;

const IGNORE_DIRS: &[&str] = &[
    "node_modules", ".git", "__pycache__", ".cache", "dist", "build", ".venv", "target",
];

fn detect_lang(p: &Path) -> Option<&'static str> {
    match p.extension().and_then(|e| e.to_str()).unwrap_or("").to_lowercase().as_str() {
        "py" | "pyi" => Some("python"),
        "rs" => Some("rust"),
        "go" => Some("go"),
        "js" | "mjs" | "jsx" => Some("javascript"),
        "ts" | "tsx" => Some("typescript"),
        "c" | "h" => Some("c"),
        "cc" | "cpp" | "hpp" => Some("cpp"),
        _ => None,
    }
}

fn open_graph_db(p: &Parsed, canon_root: &Path) -> Result<Connection, String> {
    let db_path = p.fstr("graph-db").unwrap_or_else(|| {
        let mut h = Sha256::new();
        h.update(canon_root.to_string_lossy().as_bytes());
        let dig = format!("{:x}", h.finalize());
        paths::xt_home()
            .join("code_graphs")
            .join(format!("{}.db", &dig[..16]))
            .to_string_lossy()
            .to_string()
    });
    if let Some(parent) = Path::new(&db_path).parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let mut last_err = String::new();
    for attempt in 0..10 {
        let conn = match Connection::open(&db_path) {
            Ok(c) => c,
            Err(e) => {
                last_err = e.to_string();
                std::thread::sleep(std::time::Duration::from_millis(25 * (attempt + 1)));
                continue;
            }
        };
        let _ = conn.busy_timeout(std::time::Duration::from_millis(5000));
        match conn
            .execute_batch("PRAGMA busy_timeout=5000; PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;")
            .and_then(|_| conn.execute_batch(GRAPH_SCHEMA))
        {
            Ok(()) => return Ok(conn),
            Err(e) => {
                let msg = e.to_string();
                last_err = msg.clone();
                if msg.contains("locked") || msg.contains("busy") {
                    std::thread::sleep(std::time::Duration::from_millis(25 * (attempt + 1)));
                    continue;
                }
                return Err(msg);
            }
        }
    }
    Err(last_err)
}

fn collect_files(root: &Path, out: &mut Vec<std::path::PathBuf>, cap: usize) {
    if out.len() >= cap {
        return;
    }
    let Ok(rd) = std::fs::read_dir(root) else {
        return;
    };
    let mut entries: Vec<_> = rd.filter_map(|e| e.ok()).collect();
    entries.sort_by_key(|e| e.file_name());
    for entry in entries {
        if out.len() >= cap {
            break;
        }
        let name = entry.file_name().to_string_lossy().to_string();
        if IGNORE_DIRS.contains(&name.as_str()) || name.starts_with('.') {
            continue;
        }
        let path = entry.path();
        if path.is_dir() {
            collect_files(&path, out, cap);
        } else if path.is_file() && detect_lang(&path).is_some() {
            out.push(path);
        }
    }
}

struct ParsedSym {
    name: String,
    kind: String,
    line: i64,
    sig: String,
}

struct ParsedEdge {
    src: String,
    dst: String,
    rel: String,
    line: i64,
}

fn parse_source(lang: &str, text: &str) -> (Vec<ParsedSym>, Vec<ParsedEdge>) {
    let re_py_def = Regex::new(r"^\s*(?:async\s+)?def\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(").unwrap();
    let re_py_cls = Regex::new(r"^\s*class\s+([A-Za-z_][A-Za-z0-9_]*)").unwrap();
    let re_rs_fn = Regex::new(r"^\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+([A-Za-z_][A-Za-z0-9_]*)").unwrap();
    let re_rs_ty = Regex::new(r"^\s*(?:pub(?:\([^)]*\))?\s+)?(?:struct|enum|trait)\s+([A-Za-z_][A-Za-z0-9_]*)").unwrap();
    let re_go_fn = Regex::new(r"^func\s+(?:\([^)]+\)\s+)?([A-Za-z_][A-Za-z0-9_]*)").unwrap();
    let re_go_ty = Regex::new(r"^type\s+([A-Za-z_][A-Za-z0-9_]*)").unwrap();
    let re_js_fn = Regex::new(r"^\s*(?:export\s+)?(?:async\s+)?function\s+([A-Za-z_$][A-Za-z0-9_$]*)").unwrap();
    let re_js_cls = Regex::new(r"^\s*(?:export\s+)?(?:abstract\s+)?(?:class|interface|type)\s+([A-Za-z_$][A-Za-z0-9_$]*)").unwrap();
    let re_imp = Regex::new(r"^\s*(?:from\s+([\w.]+)\s+import|import\s+([\w.]+)|use\s+([\w:]+))").unwrap();
    let re_call = Regex::new(r"\b([A-Za-z_][A-Za-z0-9_]{2,})\s*\(").unwrap();

    let skip_calls: HashSet<&str> = [
        "if", "for", "while", "switch", "match", "return", "sizeof", "typeof", "catch", "fn", "def", "func", "function",
    ]
    .into_iter()
    .collect();

    let mut syms = Vec::new();
    let mut edges = Vec::new();
    let mut current_fn = String::from("<module>");

    for (idx, line) in text.lines().enumerate() {
        let lineno = (idx + 1) as i64;
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with("//") {
            continue;
        }
        let mut decl_matched = false;
        match lang {
            "python" => {
                if let Some(c) = re_py_cls.captures(line) {
                    let n = c[1].to_string();
                    current_fn = n.clone();
                    syms.push(ParsedSym { name: n, kind: "class".into(), line: lineno, sig: trimmed.chars().take(100).collect() });
                    decl_matched = true;
                } else if let Some(c) = re_py_def.captures(line) {
                    let n = c[1].to_string();
                    current_fn = n.clone();
                    syms.push(ParsedSym { name: n, kind: "function".into(), line: lineno, sig: trimmed.chars().take(100).collect() });
                    decl_matched = true;
                }
            }
            "rust" => {
                if let Some(c) = re_rs_fn.captures(line) {
                    let n = c[1].to_string();
                    current_fn = n.clone();
                    syms.push(ParsedSym { name: n, kind: "function".into(), line: lineno, sig: trimmed.chars().take(100).collect() });
                    decl_matched = true;
                } else if let Some(c) = re_rs_ty.captures(line) {
                    let n = c[1].to_string();
                    syms.push(ParsedSym { name: n, kind: "type".into(), line: lineno, sig: trimmed.chars().take(100).collect() });
                    decl_matched = true;
                }
            }
            "go" => {
                if let Some(c) = re_go_fn.captures(line) {
                    let n = c[1].to_string();
                    current_fn = n.clone();
                    syms.push(ParsedSym { name: n, kind: "function".into(), line: lineno, sig: trimmed.chars().take(100).collect() });
                    decl_matched = true;
                } else if let Some(c) = re_go_ty.captures(line) {
                    let n = c[1].to_string();
                    syms.push(ParsedSym { name: n, kind: "type".into(), line: lineno, sig: trimmed.chars().take(100).collect() });
                    decl_matched = true;
                }
            }
            _ => {
                if let Some(c) = re_js_cls.captures(line) {
                    let n = c[1].to_string();
                    current_fn = n.clone();
                    syms.push(ParsedSym { name: n, kind: "class".into(), line: lineno, sig: trimmed.chars().take(100).collect() });
                    decl_matched = true;
                } else if let Some(c) = re_js_fn.captures(line) {
                    let n = c[1].to_string();
                    current_fn = n.clone();
                    syms.push(ParsedSym { name: n, kind: "function".into(), line: lineno, sig: trimmed.chars().take(100).collect() });
                    decl_matched = true;
                }
            }
        }

        if let Some(c) = re_imp.captures(line) {
            if let Some(m) = c.get(1).or_else(|| c.get(2)).or_else(|| c.get(3)) {
                edges.push(ParsedEdge {
                    src: current_fn.clone(),
                    dst: m.as_str().to_string(),
                    rel: "imports".into(),
                    line: lineno,
                });
            }
        }

        if !decl_matched {
            for c in re_call.captures_iter(line) {
                let callee = &c[1];
                if !skip_calls.contains(callee) && callee != current_fn {
                    edges.push(ParsedEdge {
                        src: current_fn.clone(),
                        dst: callee.to_string(),
                        rel: "calls".into(),
                        line: lineno,
                    });
                }
            }
        }
    }
    (syms, edges)
}

pub fn index_workspace(p: &Parsed, root_raw: &str) -> Result<Value, String> {
    let t0 = Instant::now();
    let canon = guard::read_guard(root_raw).map_err(|d| format!("{}: {}", d.code, d.reason))?;
    let mut conn = open_graph_db(p, &canon)?;

    let mut files = Vec::new();
    if canon.is_file() {
        files.push(canon.clone());
    } else {
        collect_files(&canon, &mut files, 1500);
    }

    let mut existing: HashMap<String, String> = HashMap::new();
    {
        let mut stmt = conn.prepare("SELECT path, sha256 FROM files").map_err(|e| e.to_string())?;
        let rows = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))).map_err(|e| e.to_string())?;
        for r in rows.flatten() {
            existing.insert(r.0, r.1);
        }
    }

    let mut seen_paths: HashSet<String> = HashSet::new();
    let tx = conn
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .map_err(|e| e.to_string())?;
    let mut updated_files = 0usize;
    let mut skipped_files = 0usize;
    let mut removed_files = 0usize;
    let mut changed_paths: Vec<String> = Vec::new();
    let mut removed_paths: Vec<String> = Vec::new();
    let mut total_syms = 0usize;
    let mut total_edges = 0usize;

    for f in &files {
        let Some(lang) = detect_lang(f) else { continue; };
        let Ok(bytes) = std::fs::read(f) else { continue; };
        if bytes.len() > 1_000_000 {
            continue;
        }
        let fstr = f.to_string_lossy().to_string();
        seen_paths.insert(fstr.clone());
        let mut h = Sha256::new();
        h.update(&bytes);
        let sha = format!("{:x}", h.finalize());
        if existing.get(&fstr) == Some(&sha) {
            skipped_files += 1;
            continue;
        }
        changed_paths.push(fstr.clone());
        let mtime = std::fs::metadata(f)
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        let text = String::from_utf8_lossy(&bytes);
        let loc = text.lines().count() as i64;
        let (syms, edges) = parse_source(lang, &text);

        let _ = tx.execute("DELETE FROM symbols WHERE file_path=?", params![&fstr]);
        let _ = tx.execute("DELETE FROM edges WHERE file_path=?", params![&fstr]);
        let _ = tx.execute(
            "INSERT INTO files(path,lang,sha256,mtime,loc) VALUES(?,?,?,?,?) ON CONFLICT(path) DO UPDATE SET lang=excluded.lang, sha256=excluded.sha256, mtime=excluded.mtime, loc=excluded.loc",
            params![&fstr, lang, &sha, mtime, loc],
        );

        for s in &syms {
            let _ = tx.execute(
                "INSERT INTO symbols(file_path,name,fqname,kind,line,signature) VALUES(?,?,?,?,?,?)",
                params![&fstr, &s.name, &s.name, &s.kind, s.line, &s.sig],
            );
            total_syms += 1;
        }
        for e in &edges {
            let _ = tx.execute(
                "INSERT OR IGNORE INTO edges(src_name,dst_name,rel,file_path,line) VALUES(?,?,?,?,?)",
                params![&e.src, &e.dst, &e.rel, &fstr, e.line],
            );
            total_edges += 1;
        }
        updated_files += 1;
    }

    // Invalidate & prune deleted, renamed, or moved files cleanly without manual rebuilds.
    let canon_str = canon.to_string_lossy().to_string();
    let canon_prefix = format!("{}/", canon_str.trim_end_matches('/'));
    for stale in existing.keys() {
        let under_root = stale == &canon_str || stale.starts_with(&canon_prefix);
        if !seen_paths.contains(stale) && (under_root || !Path::new(stale).exists()) {
            let _ = tx.execute("DELETE FROM symbols WHERE file_path=?", params![stale]);
            let _ = tx.execute("DELETE FROM edges WHERE file_path=?", params![stale]);
            let _ = tx.execute("DELETE FROM files WHERE path=?", params![stale]);
            removed_files += 1;
            removed_paths.push(stale.clone());
        }
    }
    tx.commit().map_err(|e| e.to_string())?;

    let db_syms: i64 = conn.query_row("SELECT COUNT(*) FROM symbols", [], |r| r.get(0)).unwrap_or(0);
    let db_edges: i64 = conn.query_row("SELECT COUNT(*) FROM edges", [], |r| r.get(0)).unwrap_or(0);

    Ok(json!({
        "ok": true,
        "root": canon.to_string_lossy(),
        "files_seen": files.len(),
        "files_updated": updated_files,
        "files_cached": skipped_files,
        "files_removed": removed_files,
        "stale_detected": updated_files > 0 || removed_files > 0,
        "stale_files": changed_paths.into_iter().take(20).collect::<Vec<_>>(),
        "removed_files": removed_paths.into_iter().take(20).collect::<Vec<_>>(),
        "new_symbols": total_syms,
        "new_edges": total_edges,
        "total_symbols": db_syms,
        "total_edges": db_edges,
        "ms": t0.elapsed().as_millis() as i64,
        "engine": "rust",
    }))
}

fn is_test_path(path_str: &str) -> bool {
    let low = path_str.to_ascii_lowercase().replace('\\', "/");
    if low.contains("/tests/") || low.contains("/test/") || low.starts_with("tests/") {
        return true;
    }
    let fname = Path::new(&low)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("");
    fname.starts_with("test_") || fname.ends_with("_test.py") || fname.ends_with("_test.rs") || fname.ends_with("_test.go") || fname.contains(".test.") || fname.contains(".spec.")
}

fn read_excerpt(file_path: &str, target_line: i64) -> String {
    let Ok(txt) = std::fs::read_to_string(file_path) else {
        return String::new();
    };
    let lines: Vec<&str> = txt.lines().collect();
    if lines.is_empty() || target_line <= 0 {
        return String::new();
    }
    let idx = (target_line - 1) as usize;
    let start = idx.saturating_sub(1);
    let end = (idx + 2).min(lines.len());
    (start..end)
        .map(|i| format!("{}: {}", i + 1, lines[i]))
        .collect::<Vec<_>>()
        .join("\n")
}

fn dotted_module(root: &str, file_path: &str) -> String {
    let r = Path::new(root).canonicalize().unwrap_or_else(|_| Path::new(root).to_path_buf());
    let f = Path::new(file_path);
    let rel = f.strip_prefix(&r).unwrap_or(f);
    let s = rel.to_string_lossy().replace('\\', "/");
    let no_ext = s.strip_suffix(".py").or_else(|| s.strip_suffix(".rs")).or_else(|| s.strip_suffix(".go")).unwrap_or(&s);
    no_ext.trim_end_matches("/__init__").replace('/', ".")
}

fn classify_caller_edge(file_path: &str, symbol: &str, def_modules: &[String]) -> (&'static str, &'static str) {
    let Ok(txt) = std::fs::read_to_string(file_path) else {
        return ("text_match_call", "medium");
    };
    for line in txt.lines() {
        let t = line.trim();
        if (t.starts_with("from ") || t.starts_with("import ") || t.starts_with("use ")) && t.contains(symbol) {
            if def_modules.is_empty() || def_modules.iter().any(|m| !m.is_empty() && t.contains(m)) {
                return ("import_resolved_call", "high");
            }
            return ("import_resolved_call", "high");
        }
        if t.starts_with("import ") && def_modules.iter().any(|m| !m.is_empty() && t.contains(m)) {
            return ("import_resolved_call", "high");
        }
    }
    // Check if caller file itself defines a shadowing local `def <symbol>` without importing.
    let def_pat_py = format!("def {symbol}(");
    let def_pat_rs = format!("fn {symbol}(");
    if txt.contains(&def_pat_py) || txt.contains(&def_pat_rs) {
        return ("local_same_file_call", "medium");
    }
    ("text_match_call", "medium")
}

fn is_builtin_callee(name: &str) -> bool {
    matches!(
        name,
        "get" | "int" | "str" | "float" | "bool" | "list" | "dict" | "set" | "tuple"
            | "len" | "append" | "extend" | "items" | "keys" | "values" | "pop" | "update"
            | "join" | "split" | "strip" | "lstrip" | "rstrip" | "lower" | "upper" | "replace"
            | "format" | "print" | "range" | "enumerate" | "zip" | "sorted" | "reversed"
            | "min" | "max" | "sum" | "abs" | "round" | "any" | "all" | "isinstance"
            | "hasattr" | "getattr" | "setattr" | "Exception" | "ValueError" | "RuntimeError"
            | "TypeError" | "KeyError" | "Path" | "Decimal" | "ROUND_HALF_UP"
    )
}

pub fn query_graph(p: &Parsed, symbol: &str, root_raw: &str, depth: usize) -> Result<Value, String> {
    let t0 = Instant::now();
    let canon = guard::read_guard(root_raw).map_err(|d| format!("{}: {}", d.code, d.reason))?;
    // Refresh incrementally while capturing pre-query staleness.
    let idx = index_workspace(p, root_raw)?;
    let conn = open_graph_db(p, &canon)?;

    // Support module-qualified dotted names like `pkg.mod.func`.
    let (mod_filter, query_sym) = match symbol.rsplit_once('.') {
        Some((m, s)) if !m.is_empty() && !s.is_empty() => (Some(m), s),
        _ => (None, symbol),
    };

    let mut all_defs = Vec::new();
    let mut def_modules: Vec<String> = Vec::new();
    {
        let mut stmt = conn
            .prepare("SELECT file_path, name, kind, line, signature FROM symbols WHERE name=? LIMIT 25")
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map(params![query_sym], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, i64>(3)?,
                    r.get::<_, String>(4)?,
                ))
            })
            .map_err(|e| e.to_string())?;
        for r in rows.flatten() {
            let is_test = is_test_path(&r.0);
            let module = dotted_module(root_raw, &r.0);
            if !is_test {
                def_modules.push(module.clone());
            }
            let excerpt = read_excerpt(&r.0, r.3);
            all_defs.push(json!({
                "file": r.0,
                "name": r.1,
                "kind": r.2,
                "line": r.3,
                "signature": r.4,
                "module": module,
                "is_test": is_test,
                "excerpt": excerpt,
            }));
        }
    }
    let defs: Vec<Value> = if let Some(mf) = mod_filter {
        let matched: Vec<Value> = all_defs
            .iter()
            .filter(|d| {
                let m = d["module"].as_str().unwrap_or("");
                m == mf || m.ends_with(&format!(".{mf}"))
            })
            .cloned()
            .collect();
        if matched.is_empty() { all_defs } else { matched }
    } else {
        all_defs
    };
    let mut defs = defs;
    if defs.is_empty() {
        let mut stmt = conn
            .prepare("SELECT file_path, name, kind, line, signature FROM symbols WHERE name LIKE ? LIMIT 25")
            .map_err(|e| e.to_string())?;
        let pat = format!("%{query_sym}%");
        let rows = stmt
            .query_map(params![pat], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, i64>(3)?,
                    r.get::<_, String>(4)?,
                ))
            })
            .map_err(|e| e.to_string())?;
        for r in rows.flatten() {
            let is_test = is_test_path(&r.0);
            let excerpt = read_excerpt(&r.0, r.3);
            defs.push(json!({
                "file": r.0,
                "name": r.1,
                "kind": r.2,
                "line": r.3,
                "signature": r.4,
                "module": dotted_module(root_raw, &r.0),
                "is_test": is_test,
                "excerpt": excerpt,
            }));
        }
    }

    let mut seen_up = HashSet::new();
    seen_up.insert(query_sym.to_string());
    let mut seen_down = HashSet::new();
    seen_down.insert(query_sym.to_string());
    let mut seen_caller_edges: HashSet<(String, String, String, i64)> = HashSet::new();
    let mut seen_callee_edges: HashSet<(String, String, String, i64)> = HashSet::new();

    let mut caller_q = VecDeque::new();
    caller_q.push_back((query_sym.to_string(), 0usize));
    let mut callee_q = VecDeque::new();
    callee_q.push_back((query_sym.to_string(), 0usize));

    let mut callers = Vec::new();
    let mut production_callers = Vec::new();
    let mut unresolved_candidates = Vec::new();
    let mut callees = Vec::new();

    while let Some((cur, d)) = caller_q.pop_front() {
        if d >= depth.max(1).min(4) {
            continue;
        }
        if let Ok(mut stmt) = conn.prepare("SELECT src_name, rel, file_path, line FROM edges WHERE dst_name=? LIMIT 40") {
            if let Ok(rows) = stmt.query_map(params![&cur], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, i64>(3)?,
                ))
            }) {
                for r in rows.flatten() {
                    if !seen_caller_edges.insert((r.0.clone(), cur.clone(), r.2.clone(), r.3)) {
                        continue;
                    }
                    let is_test = is_test_path(&r.2);
                    let (how, conf) = classify_caller_edge(&r.2, &cur, &def_modules);
                    let excerpt = read_excerpt(&r.2, r.3);
                    let item = json!({
                        "caller": r.0,
                        "target": cur,
                        "rel": r.1,
                        "file": r.2,
                        "line": r.3,
                        "hop": d + 1,
                        "is_test": is_test,
                        "how": how,
                        "confidence": conf,
                        "excerpt": excerpt,
                    });
                    if is_test || how == "local_same_file_call" {
                        let reason = if is_test { "test_file_caller" } else { "shadowed_local_definition" };
                        let mut cand = item;
                        cand["reason"] = json!(reason);
                        unresolved_candidates.push(cand);
                    } else {
                        production_callers.push(item);
                    }
                    callers.push(json!({
                        "caller": r.0,
                        "target": cur,
                        "file": r.2,
                        "line": r.3,
                        "is_test": is_test,
                    }));
                    if seen_up.insert(r.0.clone()) && d + 1 < depth {
                        caller_q.push_back((r.0, d + 1));
                    }
                }
            }
        }
    }

    while let Some((cur, d)) = callee_q.pop_front() {
        if d >= depth.max(1).min(4) {
            continue;
        }
        if let Ok(mut stmt) = conn.prepare("SELECT dst_name, rel, file_path, line FROM edges WHERE src_name=? LIMIT 40") {
            if let Ok(rows) = stmt.query_map(params![&cur], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, i64>(3)?,
                ))
            }) {
                for r in rows.flatten() {
                    if is_builtin_callee(&r.0) {
                        continue;
                    }
                    if !seen_callee_edges.insert((cur.clone(), r.0.clone(), r.2.clone(), r.3)) {
                        continue;
                    }
                    callees.push(json!({"caller": cur, "target": r.0, "rel": r.1, "file": r.2, "line": r.3, "hop": d + 1}));
                    if seen_down.insert(r.0.clone()) && d + 1 < depth {
                        callee_q.push_back((r.0, d + 1));
                    }
                }
            }
        }
    }

    let prod_defs = defs.iter().filter(|d| !d["is_test"].as_bool().unwrap_or(false)).count();
    let ambiguous = defs.len() > 1;
    let prod_ambiguous = prod_defs > 1;
    let ambiguity_reason: Value = if prod_ambiguous {
        json!("multiple_production_definitions")
    } else if ambiguous {
        json!("test_or_shadow_only")
    } else {
        Value::Null
    };
    let stale_detected = idx["stale_detected"].as_bool().unwrap_or(false);
    let follow_up = if prod_ambiguous {
        Some(format!("Multiple non-test definitions of '{query_sym}' found ({prod_defs}); inspect module imports to disambiguate."))
    } else if production_callers.is_empty() {
        Some("No import-resolved or text production callers found; consider route_grep if called dynamically or across languages.".to_string())
    } else {
        None
    };

    Ok(json!({
        "ok": true,
        "symbol": symbol,
        "depth": depth,
        "ambiguous": ambiguous,
        "production_ambiguous": prod_ambiguous,
        "ambiguity_reason": ambiguity_reason,
        "evidence_complete": !prod_ambiguous && !production_callers.is_empty() && !stale_detected,
        "definitions": defs,
        "production_callers": production_callers,
        "callers": callers,
        "unresolved_candidates": unresolved_candidates,
        "callees": callees,
        "index_status": {
            "stale_detected": stale_detected,
            "stale_files": idx["stale_files"],
            "files_updated": idx["files_updated"],
            "files_removed": idx["files_removed"],
            "refreshed": true,
        },
        "follow_up": follow_up,
        "ms": t0.elapsed().as_millis() as i64,
        "engine": "rust",
    }))
}

pub fn run(p: &Parsed) -> Option<i32> {
    let verb = p.verb.as_deref()?;
    match verb {
        "index" => {
            let root = p.pos(0).or_else(|| p.fstr("path").as_deref().map(|_| "")).unwrap_or(".");
            let target = p.fstr("path").unwrap_or_else(|| root.to_string());
            match index_workspace(p, &target) {
                Ok(val) => Some(util::out(p, &val, None)),
                Err(e) => Some(util::fail(p.json, &e, 1)),
            }
        }
        "graph" | "callers" => {
            let sym_opt = p.fstr("symbol").or_else(|| p.pos(0).map(String::from));
            let Some(sym) = sym_opt.filter(|s| !s.is_empty()) else {
                return Some(util::fail(
                    p.json,
                    "code graph requires <symbol> (e.g. xtforge code graph MyFunc . --depth 2)",
                    2,
                ));
            };
            let root = p.fstr("path")
                .or_else(|| if p.fstr("symbol").is_some() { p.pos(0).map(String::from) } else { p.pos(1).map(String::from) })
                .unwrap_or_else(|| ".".into());
            let depth = p.fint("depth", 2) as usize;
            match query_graph(p, &sym, &root, depth) {
                Ok(val) => Some(util::out(p, &val, None)),
                Err(e) => Some(util::fail(p.json, &e, 1)),
            }
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn index_and_query_python_graph() {
        let dir = std::env::temp_dir().join(format!("xt_cg_test_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("app.py"),
            "def helper(x):\n    return x + 1\n\ndef entry(y):\n    return helper(y)\n",
        )
        .unwrap();
        let db = dir.join("graph.db");
        let argv = vec![
            "code".into(),
            "index".into(),
            dir.to_string_lossy().to_string(),
            "--graph-db".into(),
            db.to_string_lossy().to_string(),
        ];
        let p = crate::args::parse(&argv);
        let idx = index_workspace(&p, dir.to_str().unwrap()).unwrap();
        assert_eq!(idx["ok"], true);
        assert!(idx["total_symbols"].as_i64().unwrap() >= 2);
        assert!(idx["total_edges"].as_i64().unwrap() >= 1);

        let qargv = vec![
            "code".into(),
            "graph".into(),
            "helper".into(),
            "--graph-db".into(),
            db.to_string_lossy().to_string(),
        ];
        let qp = crate::args::parse(&qargv);
        let g = query_graph(&qp, "helper", dir.to_str().unwrap(), 2).unwrap();
        assert_eq!(g["ok"], true);
        assert!(!g["callers"].as_array().unwrap().is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
