//! Flash memory CLI (mirrors xtforge/core/mem/flash.py + cli/flash_cmd.py).

use std::io::Read;
use std::path::PathBuf;

use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use crate::args::Parsed;
use crate::paths;
use crate::util;

const MAX_PER_SCOPE: usize = 256;
const MAX_ENTRY_BYTES: usize = 2048;

pub struct Flash {
    base: Option<PathBuf>,
}

fn sha256_hex(s: &str) -> String {
    let mut h = Sha256::new();
    h.update(s.as_bytes());
    format!("{:x}", h.finalize())
}

fn scope_file(scope: &str) -> PathBuf {
    let safe: String = scope
        .chars()
        .map(|c| if c.is_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
        .collect();
    paths::flash_dir().join(format!("scope-{safe}.jsonl"))
}

fn parse_tags(text: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for raw in text.split_whitespace() {
        if raw.starts_with('#') && raw.chars().count() > 1 {
            let tag = raw
                .trim_start_matches('#')
                .trim_matches(|c| ".,;:!?()[]{}\"'".contains(c));
            if !tag.is_empty() {
                out.push(tag.to_string());
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

fn auto_key(text: &str) -> String {
    format!("n{}", &sha256_hex(text)[..8])
}

fn key_id(key: &str) -> String {
    sha256_hex(key)[..10].to_string()
}

fn now_f64() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

fn atomic_write_text(path: &PathBuf, text: &str) {
    let _ = std::fs::create_dir_all(path.parent().unwrap_or(std::path::Path::new(".")));
    let tmp = path.with_file_name(format!(
        ".{}.{}.{}.tmp",
        path.file_name().map(|s| s.to_string_lossy().to_string()).unwrap_or_default(),
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0)
    ));
    if std::fs::write(&tmp, text.as_bytes()).is_ok() {
        if let Ok(f) = std::fs::File::open(&tmp) {
            let _ = f.sync_all();
        }
        if std::fs::rename(&tmp, path).is_err() {
            let _ = std::fs::remove_file(&tmp);
        }
    }
    if let Some(dir) = path.parent() {
        if let Ok(d) = std::fs::File::open(dir) {
            let _ = d.sync_all();
        }
    }
}

fn rec_str(rec: &Value, key: &str) -> String {
    rec.get(key)
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string()
}

fn rec_f64(rec: &Value, key: &str) -> f64 {
    rec.get(key).and_then(|v| v.as_f64()).unwrap_or(0.0)
}

fn rec_bool(rec: &Value, key: &str) -> bool {
    rec.get(key).and_then(|v| v.as_bool()).unwrap_or(false)
}

fn rec_tags(rec: &Value) -> Vec<String> {
    rec.get("tags")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
        .unwrap_or_default()
}

fn expired(rec: &Value, now: f64) -> bool {
    let ttl = rec.get("ttl_s").and_then(|v| v.as_f64()).unwrap_or(0.0);
    ttl != 0.0 && (now - rec_f64(rec, "ts")) > ttl
}

impl Flash {
    pub fn new(base: Option<String>) -> Self {
        Flash { base: base.map(PathBuf::from) }
    }

    fn path(&self, scope: &str) -> PathBuf {
        match &self.base {
            Some(b) => {
                let safe: String = scope
                    .chars()
                    .map(|c| if c.is_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
                    .collect();
                let _ = std::fs::create_dir_all(b);
                b.join(format!("scope-{safe}.jsonl"))
            }
            None => scope_file(scope),
        }
    }

    fn load(&self, scope: &str) -> Vec<Value> {
        let path = self.path(scope);
        let mut out = Vec::new();
        let Ok(text) = std::fs::read_to_string(&path) else {
            return out;
        };
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            if let Ok(Value::Object(map)) = serde_json::from_str::<Value>(line) {
                if map.get("id").map(|v| !v.is_null()).unwrap_or(false) {
                    out.push(Value::Object(map));
                }
            }
        }
        out
    }

    fn save(&self, scope: &str, entries: &[Value]) {
        let mut payload = String::new();
        for e in entries {
            payload.push_str(&serde_json::to_string(e).unwrap_or_default());
            payload.push('\n');
        }
        atomic_write_text(&self.path(scope), &payload);
    }

    fn evict(&self, entries: Vec<Value>) -> Vec<Value> {
        let now = now_f64();
        let alive: Vec<Value> = entries.into_iter().filter(|e| !expired(e, now)).collect();
        if alive.len() <= MAX_PER_SCOPE {
            return alive;
        }
        let mut pinned: Vec<Value> = Vec::new();
        let mut unpinned: Vec<Value> = Vec::new();
        for e in alive {
            if rec_bool(&e, "pin") {
                pinned.push(e);
            } else {
                unpinned.push(e);
            }
        }
        unpinned.sort_by(|a, b| rec_f64(a, "ts").partial_cmp(&rec_f64(b, "ts")).unwrap_or(std::cmp::Ordering::Equal));
        let room = MAX_PER_SCOPE.saturating_sub(pinned.len());
        let mut out = pinned;
        if room == 0 {
            if out.len() > MAX_PER_SCOPE {
                out = out.split_off(out.len() - MAX_PER_SCOPE);
            }
        } else if unpinned.len() > room {
            out.extend(unpinned.split_off(unpinned.len() - room));
        } else {
            out.extend(unpinned);
        }
        out
    }

    pub fn set(&self, value: &str, key: Option<&str>, scope: &str,
               tags: &[String], ttl_s: Option<i64>, src: &str) -> Result<Value, String> {
        if value.as_bytes().len() > MAX_ENTRY_BYTES {
            return Err(format!("entry exceeds {MAX_ENTRY_BYTES} bytes"));
        }
        let mut all_tags = parse_tags(value);
        for t in tags {
            if !t.trim().is_empty() && !all_tags.contains(t) {
                all_tags.push(t.clone());
            }
        }
        all_tags.sort();
        let k = key.map(String::from).unwrap_or_else(|| auto_key(value));
        let mut entries: Vec<Value> = self
            .load(scope)
            .into_iter()
            .filter(|e| rec_str(e, "k") != k)
            .collect();
        let mut map = Map::new();
        map.insert("id".into(), json!(key_id(&k)));
        map.insert("k".into(), json!(k));
        map.insert("v".into(), json!(value));
        map.insert("tags".into(), json!(all_tags));
        map.insert("ts".into(), json!(now_f64()));
        map.insert("ttl_s".into(), match ttl_s { Some(t) => json!(t), None => Value::Null });
        map.insert("pin".into(), json!(false));
        map.insert("src".into(), json!(src));
        let rec = Value::Object(map);
        entries.push(rec.clone());
        self.save(scope, &self.evict(entries));
        Ok(rec)
    }

    pub fn get(&self, key: &str, scope: &str) -> Option<Value> {
        let now = now_f64();
        for rec in self.load(scope) {
            if expired(&rec, now) {
                continue;
            }
            if rec_str(&rec, "k") == key || rec_str(&rec, "id") == key {
                return Some(rec);
            }
        }
        None
    }

    pub fn find(&self, query: &str, scope: &str, top: usize) -> Vec<Value> {
        let q = query.trim().to_lowercase();
        if q.is_empty() {
            return Vec::new();
        }
        let now = now_f64();
        let mut scored: Vec<(f64, f64, Value)> = Vec::new();
        for rec in self.load(scope) {
            if expired(&rec, now) {
                continue;
            }
            let k = rec_str(&rec, "k");
            let v = rec_str(&rec, "v");
            let hay = format!("{} {} {}", k, v, rec_tags(&rec).join(" ")).to_lowercase();
            let mut score = if k.to_lowercase() == q {
                100.0
            } else if hay.contains(&q) {
                50.0
            } else if k.to_lowercase().contains(&q) {
                25.0
            } else {
                q.split_whitespace().filter(|t| hay.contains(*t)).count() as f64
            };
            if rec_bool(&rec, "pin") {
                score += 5.0;
            }
            if score > 0.0 {
                scored.push((score, rec_f64(&rec, "ts"), rec));
            }
        }
        scored.sort_by(|a, b| {
            b.0.partial_cmp(&a.0)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then(b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal))
        });
        scored.into_iter().take(top).map(|(_, _, r)| r).collect()
    }

    pub fn list(&self, scope: &str, n: usize, pin_only: bool) -> Vec<Value> {
        let now = now_f64();
        let mut recs: Vec<Value> = self
            .load(scope)
            .into_iter()
            .filter(|r| !expired(r, now))
            .filter(|r| !pin_only || rec_bool(r, "pin"))
            .collect();
        recs.sort_by(|a, b| {
            let pa = !rec_bool(a, "pin");
            let pb = !rec_bool(b, "pin");
            pa.cmp(&pb)
                .then(rec_f64(b, "ts").partial_cmp(&rec_f64(a, "ts")).unwrap_or(std::cmp::Ordering::Equal))
        });
        recs.truncate(n);
        recs
    }

    pub fn pin(&self, key_or_id: &str, scope: &str) -> Option<Value> {
        let mut entries = self.load(scope);
        let now = now_f64();
        let mut found: Option<usize> = None;
        for (i, rec) in entries.iter().enumerate() {
            if expired(rec, now) {
                continue;
            }
            if rec_str(rec, "k") == key_or_id || rec_str(rec, "id") == key_or_id {
                found = Some(i);
                break;
            }
        }
        let i = found?;
        let new_pin = !rec_bool(&entries[i], "pin");
        if let Value::Object(map) = &mut entries[i] {
            map.insert("pin".into(), json!(new_pin));
        }
        self.save(scope, &entries);
        Some(entries[i].clone())
    }

    pub fn delete(&self, key_or_id: &str, scope: &str) -> bool {
        let entries = self.load(scope);
        let keep: Vec<Value> = entries
            .iter()
            .filter(|e| rec_str(e, "k") != key_or_id && rec_str(e, "id") != key_or_id)
            .cloned()
            .collect();
        if keep.len() == entries.len() {
            return false;
        }
        self.save(scope, &keep);
        true
    }

    #[allow(dead_code)] // kept for the confirm-token path (guard parity)
    pub fn clear(&self, scope: &str) -> usize {
        let entries = self.load(scope);
        self.save(scope, &[]);
        entries.len()
    }

    pub fn scopes(&self) -> Vec<String> {
        let d = match &self.base {
            Some(b) => b.clone(),
            None => paths::flash_dir(),
        };
        let mut out: Vec<String> = Vec::new();
        if let Ok(rd) = std::fs::read_dir(&d) {
            for e in rd.filter_map(|e| e.ok()) {
                let name = e.file_name().to_string_lossy().to_string();
                if let Some(rest) = name.strip_prefix("scope-") {
                    if let Some(stem) = rest.strip_suffix(".jsonl") {
                        out.push(stem.to_string());
                    }
                }
            }
        }
        out.sort();
        out
    }

    pub fn compact(&self, scope: &str) -> Value {
        let now = now_f64();
        let entries = self.load(scope);
        let alive: Vec<Value> = entries.iter().filter(|e| !expired(e, now)).cloned().collect();
        let dropped_expired = entries.len() - alive.len();
        let mut merged: Vec<Value> = Vec::new();
        let mut dropped_dupes = 0usize;
        for rec in alive {
            let k = rec_str(&rec, "k");
            if let Some(prev) = merged.iter_mut().find(|e| rec_str(e, "k") == k) {
                dropped_dupes += 1;
                if rec_f64(&rec, "ts") > rec_f64(prev, "ts") {
                    let prev_pin = rec_bool(prev, "pin");
                    if let Value::Object(map) = &rec {
                        let mut m = map.clone();
                        m.insert("pin".into(), json!(prev_pin || rec_bool(&rec, "pin")));
                        *prev = Value::Object(m);
                    }
                }
                continue;
            }
            merged.push(rec);
        }
        let before = merged.len();
        let out = self.evict(merged);
        self.save(scope, &out);
        json!({
            "before": before, "after": out.len(), "expired": dropped_expired,
            "dupes_merged": dropped_dupes, "evicted": before - out.len()
        })
    }

    pub fn stats(&self, scope: &str) -> Value {
        let entries = self.load(scope);
        let now = now_f64();
        let alive: Vec<&Value> = entries.iter().filter(|e| !expired(e, now)).collect();
        json!({
            "scope": scope, "total": entries.len(), "alive": alive.len(),
            "pinned": alive.iter().filter(|e| rec_bool(e, "pin")).count(),
            "max": MAX_PER_SCOPE
        })
    }
}

fn read_text_file(src: &str) -> Result<String, String> {
    if src == "-" {
        let mut buf = String::new();
        std::io::stdin()
            .read_to_string(&mut buf)
            .map_err(|e| format!("cannot read --text-file -: {e}"))?;
        return Ok(buf);
    }
    std::fs::read_to_string(src).map_err(|e| format!("cannot read --text-file {src}: {e}"))
}

fn py_bool(b: bool) -> &'static str {
    if b { "True" } else { "False" }
}

fn chars_take(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}

pub fn run(p: &Parsed) -> Option<i32> {
    let verb = p.verb.as_deref()?;
    if !matches!(verb, "set" | "get" | "list" | "pin" | "delete" | "compact" | "stats") {
        return None;
    }
    let scope = p.fstr("scope").unwrap_or_else(|| "global".into());
    let f = Flash::new(p.fstr("flash-base"));
    match verb {
        "set" => Some(cmd_set(p, &f, &scope)),
        "get" => Some(cmd_get(p, &f, &scope)),
        "list" => Some(cmd_list(p, &f, &scope)),
        "pin" => Some(cmd_pin(p, &f, &scope)),
        "delete" => Some(cmd_delete(p, &f, &scope)),
        "compact" => {
            let res = f.compact(&scope);
            Some(util::out(p, &res, Some("compacted".into())))
        }
        "stats" => Some(util::out(p, &f.stats(&scope), None)),
        _ => None,
    }
}

fn cmd_set(p: &Parsed, f: &Flash, scope: &str) -> i32 {
    let mut text = p.pos(0).unwrap_or("").to_string();
    if let Some(src) = p.fstr("text-file") {
        match read_text_file(&src) {
            Ok(t) => text = t,
            Err(e) => {
                let human = e.clone();
                return util::out_with(p, &json!({"ok": false, "err": e}), Some(human), 2);
            }
        }
    }
    if text.trim().is_empty() {
        return util::out_with(
            p,
            &json!({"ok": false, "err": "flash set requires text"}),
            Some("flash set requires text (usage: xtforge flash set \"note #tag\")".into()),
            2,
        );
    }
    let (key, val) = if text.contains('=') && !text.starts_with('#') {
        let (k, v) = text.split_once('=').unwrap();
        (Some(k.to_string()), v.to_string())
    } else {
        (None, text.clone())
    };
    let tags = p.flist("tag");
    let ttl = p.fstr("ttl").and_then(|s| s.parse::<i64>().ok());
    match f.set(&val, key.as_deref(), scope, &tags, ttl, "cli") {
        Ok(rec) => {
            let human = format!(
                "[{}] {} = {}",
                rec_str(&rec, "id"),
                rec_str(&rec, "k"),
                rec_str(&rec, "v")
            );
            util::out(p, &rec, Some(human))
        }
        Err(e) => util::fail(p.json, &e, 1),
    }
}

fn cmd_get(p: &Parsed, f: &Flash, scope: &str) -> i32 {
    let k = p.pos(1).or_else(|| p.pos(0)).unwrap_or("");
    if k.is_empty() {
        return util::out(p, &Value::Null, Some("not found".into()));
    }
    let rec = f.get(k, scope).or_else(|| f.find(k, scope, 3).into_iter().next());
    match rec {
        Some(r) => {
            let human = format!("{} = {}", rec_str(&r, "k"), rec_str(&r, "v"));
            util::out(p, &r, Some(human))
        }
        None => util::out(p, &Value::Null, Some("not found".into())),
    }
}

fn cmd_list(p: &Parsed, f: &Flash, scope: &str) -> i32 {
    let n = match p.fstr("n") {
        Some(s) => s.parse::<usize>().unwrap_or(10),
        None => {
            let t = p.pos(0).unwrap_or("");
            if !t.is_empty() && t.chars().all(|c| c.is_ascii_digit()) {
                t.parse::<usize>().unwrap_or(10)
            } else {
                10
            }
        }
    };
    let recs = f.list(scope, n, p.fbool("pin-only"));
    let human = recs
        .iter()
        .map(|r| format!("{} {}: {}", rec_str(r, "id"), rec_str(r, "k"), chars_take(&rec_str(r, "v"), 60)))
        .collect::<Vec<_>>()
        .join("\n");
    util::out(p, &json!(recs), Some(human))
}

fn cmd_pin(p: &Parsed, f: &Flash, scope: &str) -> i32 {
    let k = p.pos(1).or_else(|| p.pos(0)).unwrap_or("");
    match f.pin(k, scope) {
        Some(rec) => {
            let human = format!("pin={}", py_bool(rec_bool(&rec, "pin")));
            util::out(p, &rec, Some(human))
        }
        None => util::out(p, &Value::Null, Some("not found".into())),
    }
}

fn cmd_delete(p: &Parsed, f: &Flash, scope: &str) -> i32 {
    if p.fbool("all") {
        if !p.fbool("confirm") {
            let tok = issue_token("clear_scope", scope);
            let human = format!(
                "pass --confirm {} to clear {}",
                rec_str(&tok, "confirm_token"),
                scope
            );
            return util::out(p, &tok, Some(human));
        }
        // Tokens are in-process only (same semantics as guard.py `_TOKENS`),
        // so a confirm from a fresh process is always invalid — exactly what
        // Python does today.
        return util::fail(
            p.json,
            "confirm_token missing, expired, or already used",
            1,
        );
    }
    let k = p.pos(1).or_else(|| p.pos(0)).unwrap_or("");
    let ok = f.delete(k, scope);
    util::out(
        p,
        &json!({"deleted": ok}),
        Some(if ok { "deleted".into() } else { "not found".into() }),
    )
}

fn issue_token(action: &str, scope: &str) -> Value {
    let entropy = format!(
        "{}:{}:{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0),
        now_f64()
    );
    let tok = sha256_hex(&entropy)[..24].to_string();
    let path = crate::guard::canonical(scope).to_string_lossy().to_string();
    let mut inner = Map::new();
    inner.insert("action".into(), json!(action));
    inner.insert("path".into(), json!(path));
    inner.insert("scope".into(), json!(scope));
    inner.insert("issued".into(), json!(now_f64()));
    inner.insert("expires".into(), json!(now_f64() + 300.0));
    inner.insert("confirm_token".into(), Value::Null);
    let mut safe = Map::new();
    safe.insert(tok.clone(), Value::Object(inner));
    let mut text = serde_json::to_string(&Value::Object(safe)).unwrap_or_default();
    text.push('\n');
    atomic_write_text(&paths::cache_dir().join("tokens.json"), &text);
    json!({
        "confirm_token": tok, "action": action, "path": path,
        "expires_in": 300,
        "note": format!("re-run with --confirm {tok} to execute {action}")
    })
}
