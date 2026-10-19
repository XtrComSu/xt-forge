//! Universal memory (mirrors xtforge/core/mem/{store,search,export,write_policy,scopes}.py).

use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use regex::Regex;
use rusqlite::{params, Connection, OptionalExtension};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use unicode_normalization::UnicodeNormalization;

use crate::args::Parsed;
use crate::guard;
use crate::paths;
use crate::util;

pub const KINDS: &[&str] = &[
    "fact", "preference", "decision", "procedure", "snippet",
    "artifact_ref", "error_pattern", "person", "device",
];

const MIGRATION: &str = r#"
CREATE TABLE IF NOT EXISTS mem(
  id TEXT PRIMARY KEY,
  scope TEXT NOT NULL,
  kind TEXT NOT NULL,
  title TEXT NOT NULL DEFAULT '',
  body TEXT NOT NULL DEFAULT '',
  tags TEXT NOT NULL DEFAULT '',
  source TEXT NOT NULL DEFAULT '',
  created INT NOT NULL,
  updated INT NOT NULL,
  last_used INT NOT NULL DEFAULT 0,
  uses INT NOT NULL DEFAULT 0,
  pin INT NOT NULL DEFAULT 0,
  ttl INT,
  confidence REAL NOT NULL DEFAULT 1.0,
  supersedes TEXT,
  body_hash TEXT NOT NULL DEFAULT '',
  pending INT NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_mem_scope ON mem(scope);
CREATE INDEX IF NOT EXISTS idx_mem_kind ON mem(kind);
CREATE INDEX IF NOT EXISTS idx_mem_bh ON mem(body_hash);
CREATE INDEX IF NOT EXISTS idx_mem_pending ON mem(pending);
CREATE TABLE IF NOT EXISTS links(src TEXT, dst TEXT, rel TEXT);
CREATE INDEX IF NOT EXISTS idx_links_src ON links(src);
CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT);
"#;

const FTS_SCHEMA: &str = r#"
CREATE VIRTUAL TABLE IF NOT EXISTS mem_fts USING fts5(
  title, body, tags, content='mem', content_rowid='rowid'
);
CREATE TRIGGER IF NOT EXISTS mem_ai AFTER INSERT ON mem BEGIN
  INSERT INTO mem_fts(rowid,title,body,tags) VALUES(new.rowid,new.title,new.body,new.tags);
END;
CREATE TRIGGER IF NOT EXISTS mem_ad AFTER DELETE ON mem BEGIN
  INSERT INTO mem_fts(mem_fts,rowid,title,body,tags)
    VALUES('delete',old.rowid,old.title,old.body,old.tags);
END;
CREATE TRIGGER IF NOT EXISTS mem_au AFTER UPDATE ON mem BEGIN
  INSERT INTO mem_fts(mem_fts,rowid,title,body,tags)
    VALUES('delete',old.rowid,old.title,old.body,old.tags);
  INSERT INTO mem_fts(rowid,title,body,tags) VALUES(new.rowid,new.title,new.body,new.tags);
END;
"#;

const LIKE_FALLBACK_SCHEMA: &str =
    "CREATE TABLE IF NOT EXISTS mem_trgm(id TEXT PRIMARY KEY, trigrams TEXT NOT NULL);";

const EXPORT_COLUMNS: &[&str] = &[
    "id", "scope", "kind", "title", "body", "tags", "source", "created",
    "updated", "last_used", "uses", "pin", "ttl", "confidence", "supersedes",
    "body_hash", "pending",
];

fn static_re(name: &str) -> &'static Regex {
    static CACHE: OnceLock<std::sync::Mutex<std::collections::HashMap<String, &'static Regex>>> =
        OnceLock::new();
    let cache = CACHE.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()));
    let mut map = cache.lock().unwrap();
    if let Some(r) = map.get(name) {
        return r;
    }
    let r: &'static Regex = Box::leak(Box::new(Regex::new(name).expect("static regex")));
    map.insert(name.to_string(), r);
    r
}

fn secret_patterns() -> Vec<(&'static str, &'static Regex)> {
    vec![
        ("private_key", static_re(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
        ("aws_key", static_re(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
        ("github_token", static_re(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
        ("slack_token", static_re(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b")),
        ("anthropic_key", static_re(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b")),
        ("google_key", static_re(r"\bAIza[0-9A-Za-z_-]{35}\b")),
        ("jwt", static_re(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),
        ("bearer", static_re(r"(?i)\bbearer\s+[A-Za-z0-9._-]{20,}\b")),
        ("assign_secret", static_re(
            r#"(?i)\b(api[_-]?key|secret|passwd|password|token|access[_-]?key)\b\s*[:=]\s*['"]?[^\s'"]{8,}"#)),
        ("pg_url_pw", static_re(r"\b[a-z][a-z0-9+.-]*://[^\s:@/]+:[^\s:@/]{4,}@\S+")),
        ("openai_key", static_re(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b")),
    ]
}

pub fn redact(text: &str) -> (String, Vec<String>) {
    let mut kinds: Vec<String> = Vec::new();
    let mut out = text.to_string();
    for (kind, pat) in secret_patterns() {
        if pat.is_match(&out) {
            if !kinds.iter().any(|k| k == kind) {
                kinds.push(kind.to_string());
            }
            out = pat.replace_all(&out, "[REDACTED]").to_string();
        }
    }
    (out, kinds)
}

pub fn normalize_body(text: &str) -> String {
    let normalized: String = text.nfkc().collect();
    let punct = static_re(r"[^\w\s]");
    let ws = static_re(r"\s+");
    let t = punct.replace_all(&normalized, " ").to_lowercase();
    ws.replace_all(&t, " ").trim().to_string()
}

pub fn body_hash(text: &str) -> String {
    let mut h = Sha256::new();
    h.update(normalize_body(text).as_bytes());
    format!("{:x}", h.finalize())[..16].to_string()
}

fn tokenize(text: &str) -> std::collections::HashSet<String> {
    static_re(r"\w+")
        .find_iter(&normalize_body(text))
        .map(|m| m.as_str().to_string())
        .collect()
}

fn jaccard(a: &std::collections::HashSet<String>,
           b: &std::collections::HashSet<String>) -> f64 {
    if a.is_empty() || b.is_empty() {
        return 0.0;
    }
    let inter = a.intersection(b).count();
    let union = a.union(b).count();
    if union == 0 {
        0.0
    } else {
        inter as f64 / union as f64
    }
}

pub fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn now_f64() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

fn new_id() -> String {
    let mut h = Sha256::new();
    h.update(format!("{}:{}:{}", std::process::id(), now_f64(), rand_counter()).as_bytes());
    format!("{:x}", h.finalize())[..16].to_string()
}

fn rand_counter() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static C: AtomicU64 = AtomicU64::new(0);
    C.fetch_add(1, Ordering::Relaxed)
}

pub fn trigrams(text: &str) -> String {
    let t = format!(
        "  {}  ",
        text.chars()
            .map(|c| if c.is_alphanumeric() { c.to_lowercase().next().unwrap_or(c) } else { ' ' })
            .collect::<String>()
    );
    let chars: Vec<char> = t.chars().collect();
    let mut out: Vec<String> = Vec::new();
    for i in 0..chars.len().saturating_sub(2) {
        out.push(chars[i..i + 3].iter().collect());
    }
    out.join(" ")
}

fn row_to_json(row: &rusqlite::Row) -> rusqlite::Result<Value> {
    let mut map = Map::new();
    for i in 0..row.as_ref().column_count() {
        let name = row.as_ref().column_name(i)?.to_string();
        let v = match row.get_ref(i)? {
            rusqlite::types::ValueRef::Null => Value::Null,
            rusqlite::types::ValueRef::Integer(n) => json!(n),
            rusqlite::types::ValueRef::Real(f) => json!(f),
            rusqlite::types::ValueRef::Text(t) => json!(String::from_utf8_lossy(t)),
            rusqlite::types::ValueRef::Blob(_) => Value::Null,
        };
        map.insert(name, v);
    }
    Ok(Value::Object(map))
}

fn collect_rows(conn: &Connection, sql: &str, params: impl rusqlite::Params) -> Vec<Value> {
    let mut out = Vec::new();
    if let Ok(mut stmt) = conn.prepare(sql) {
        if let Ok(rows) = stmt.query_map(params, |r| row_to_json(r)) {
            for r in rows.flatten() {
                out.push(r);
            }
        }
    }
    out
}

pub struct Store {
    pub conn: Connection,
    pub fts: bool,
}

impl Store {
    pub fn open(path: &str, use_fts: Option<bool>) -> Result<Store, String> {
        if let Some(parent) = Path::new(path).parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let conn = Connection::open(path).map_err(|e| e.to_string())?;
        conn.execute_batch(
            "PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON;",
        )
        .map_err(|e| e.to_string())?;
        conn.execute_batch(MIGRATION).map_err(|e| e.to_string())?;
        let fts = match use_fts {
            Some(b) => b,
            None => conn
                .execute_batch(
                    "CREATE VIRTUAL TABLE temp.__fts_probe USING fts5(x); \
                     DROP TABLE temp.__fts_probe;",
                )
                .is_ok(),
        };
        if fts {
            conn.execute_batch(FTS_SCHEMA).map_err(|e| e.to_string())?;
            let _ = conn.execute_batch("INSERT INTO mem_fts(mem_fts) VALUES('rebuild');");
        } else {
            conn.execute_batch(LIKE_FALLBACK_SCHEMA).map_err(|e| e.to_string())?;
        }
        let mode = if fts { "fts5" } else { "like_trigram" };
        let _ = conn.execute(
            "INSERT INTO meta(k,v) VALUES('schema_version','1') \
             ON CONFLICT(k) DO UPDATE SET v=excluded.v", []);
        let _ = conn.execute(
            "INSERT INTO meta(k,v) VALUES('fts_mode',?) \
             ON CONFLICT(k) DO UPDATE SET v=excluded.v", params![mode]);
        Ok(Store { conn, fts })
    }

    fn index(&self, rec_id: &str, title: &str, body: &str, tags: &str) {
        if self.fts {
            return; // trigger-maintained
        }
        let _ = self.conn.execute(
            "INSERT INTO mem_trgm(id,trigrams) VALUES(?,?) \
             ON CONFLICT(id) DO UPDATE SET trigrams=excluded.trigrams",
            params![rec_id, trigrams(&format!("{title} {body} {tags}"))],
        );
    }

    fn drop_index(&self, rec_id: &str) {
        if self.fts {
            return;
        }
        let _ = self.conn.execute("DELETE FROM mem_trgm WHERE id=?", params![rec_id]);
    }

    fn policy(&self, body: &str, title: &str, scope: &str, kind: &str)
              -> (String, Vec<String>, Option<String>) {
        let (clean_body, kinds_b) = redact(body);
        let (_clean_title, kinds_t) = redact(title);
        let mut redact_kinds = kinds_b.clone();
        for k in kinds_t {
            if !redact_kinds.contains(&k) {
                redact_kinds.push(k);
            }
        }
        let mut notes: Vec<String> = redact_kinds.iter().map(|k| format!("redacted:{k}")).collect();
        let mut clean_body = clean_body;
        if clean_body.trim().is_empty() && !redact_kinds.is_empty() {
            clean_body = "[REDACTED]".to_string();
        }
        let bh = body_hash(&clean_body);
        let exact: Option<String> = self
            .conn
            .query_row("SELECT id FROM mem WHERE body_hash=? AND scope=? LIMIT 1",
                       params![bh, scope], |r| r.get(0))
            .optional()
            .unwrap_or(None);
        if let Some(target) = exact {
            notes.push(format!("dedupe_exact:{target}"));
            return (clean_body, notes, Some(target));
        }
        let toks = tokenize(&clean_body);
        let rows = collect_rows(
            &self.conn,
            "SELECT id, body FROM mem WHERE scope=? AND kind=? AND pending=0 LIMIT 200",
            params![scope, kind],
        );
        for r in rows {
            let other = tokenize(r.get("body").and_then(|v| v.as_str()).unwrap_or(""));
            if jaccard(&toks, &other) >= 0.8 {
                let id = r.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string();
                notes.push(format!("near_dup:{id}"));
                return (clean_body, notes, Some(id));
            }
        }
        (clean_body, notes, None)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn put(&self, scope: &str, kind: &str, title: &str, body: &str,
               tags: &[String], source: &str, confidence: f64, pending: bool,
               id: Option<&str>) -> Result<Value, String> {
        if !KINDS.contains(&kind) {
            return Err(format!("invalid kind {kind:?}; expected one of {KINDS:?}"));
        }
        let (clean_body, notes, target) = self.policy(body, title, scope, kind);
        let mut tag_set: Vec<String> = tags
            .iter()
            .map(|t| t.trim().to_string())
            .filter(|t| !t.is_empty())
            .collect();
        tag_set.sort();
        tag_set.dedup();
        let tag_str = tag_set.join(",");
        let ts = now();
        if let Some(target) = target {
            self.conn
                .execute(
                    "UPDATE mem SET body=?, title=CASE WHEN ?='' THEN title ELSE ? END, \
                     updated=?, confidence=MAX(confidence,?), supersedes=? WHERE id=?",
                    params![clean_body, title, title, ts, confidence, target, target],
                )
                .map_err(|e| e.to_string())?;
            self.index(&target, title, &clean_body, &tag_str);
            return Ok(json!({"id": target, "action": "superseded", "notes": notes}));
        }
        let rec_id = id.map(String::from).unwrap_or_else(new_id);
        self.conn
            .execute(
                "INSERT INTO mem(id,scope,kind,title,body,tags,source,created,updated,\
                 last_used,uses,pin,ttl,confidence,supersedes,body_hash,pending) \
                 VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                params![rec_id, scope, kind, title, clean_body, tag_str, source, ts, ts,
                        0, 0, 0, Option::<i64>::None, confidence, Option::<String>::None,
                        body_hash(&clean_body), if pending { 1 } else { 0 }],
            )
            .map_err(|e| e.to_string())?;
        self.index(&rec_id, title, &clean_body, &tag_str);
        Ok(json!({"id": rec_id, "action": "inserted", "notes": notes}))
    }

    pub fn get(&self, rec_id: &str) -> Option<Value> {
        self.conn
            .query_row("SELECT * FROM mem WHERE id=?", params![rec_id], |r| row_to_json(r))
            .optional()
            .unwrap_or(None)
    }

    pub fn forget(&self, rec_id: &str) -> bool {
        self.drop_index(rec_id);
        self.conn
            .execute("DELETE FROM mem WHERE id=?", params![rec_id])
            .map(|n| n > 0)
            .unwrap_or(false)
    }

    #[allow(dead_code)]
    pub fn touch(&self, rec_id: &str) {
        let _ = self.conn.execute(
            "UPDATE mem SET uses=uses+1, last_used=? WHERE id=?", params![now(), rec_id]);
    }

    #[allow(dead_code)]
    pub fn review(&self, action: &str, rec_id: &str) -> Result<Value, String> {
        let changed = match action {
            "promote" => self.conn.execute(
                "UPDATE mem SET pending=0, confidence=MAX(confidence,0.9), updated=? \
                 WHERE id=? AND pending=1", params![now(), rec_id]).unwrap_or(0),
            "drop" => self.conn.execute(
                "DELETE FROM mem WHERE id=? AND pending=1", params![rec_id]).unwrap_or(0),
            _ => return Err("action must be 'promote' or 'drop'".into()),
        };
        Ok(json!({"action": action, "id": rec_id, "changed": changed}))
    }

    pub fn pending(&self, limit: usize) -> Vec<Value> {
        collect_rows(
            &self.conn,
            "SELECT * FROM mem WHERE pending=1 ORDER BY created DESC LIMIT ?",
            params![limit as i64],
        )
    }

    pub fn list(&self, scope: Option<&str>, limit: usize, kind: Option<&str>,
                pending: Option<bool>) -> Vec<Value> {
        let mut q = String::from("SELECT * FROM mem WHERE 1=1");
        let mut args: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();
        if let Some(s) = scope {
            q.push_str(" AND scope=?");
            args.push(Box::new(s.to_string()));
        }
        if let Some(k) = kind {
            q.push_str(" AND kind=?");
            args.push(Box::new(k.to_string()));
        }
        if let Some(p) = pending {
            q.push_str(" AND pending=?");
            args.push(Box::new(if p { 1i64 } else { 0i64 }));
        }
        q.push_str(" ORDER BY pin DESC, updated DESC LIMIT ?");
        args.push(Box::new(limit as i64));
        let refs: Vec<&dyn rusqlite::ToSql> = args.iter().map(|b| b.as_ref()).collect();
        collect_rows(&self.conn, &q, refs.as_slice())
    }

    pub fn purge_expired(&self) -> usize {
        let ts = now();
        let rows = collect_rows(
            &self.conn,
            "SELECT id FROM mem WHERE ttl IS NOT NULL AND ttl > 0 AND ttl < ?",
            params![ts],
        );
        for r in &rows {
            if let Some(id) = r.get("id").and_then(|v| v.as_str()) {
                self.drop_index(id);
            }
        }
        self.conn
            .execute(
                "DELETE FROM mem WHERE ttl IS NOT NULL AND ttl > 0 AND ttl < ?",
                params![ts],
            )
            .unwrap_or(0)
    }

    #[allow(dead_code)]
    pub fn link(&self, src: &str, dst: &str, rel: &str) {
        let _ = self.conn.execute(
            "INSERT INTO links(src,dst,rel) VALUES(?,?,?)", params![src, dst, rel]);
    }
}

// ---------- scopes ----------

pub fn project_scope(path: &str) -> String {
    let resolved = guard::canonical(path);
    let mut h = Sha256::new();
    h.update(resolved.to_string_lossy().as_bytes());
    format!("project:{}", &format!("{:x}", h.finalize())[..12])
}

pub fn read_order(session_id: Option<&str>, workflow_id: Option<&str>,
                  project: Option<&str>) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(s) = session_id {
        out.push(format!("session:{s}"));
    }
    if let Some(w) = workflow_id {
        out.push(format!("workflow:{w}"));
    }
    if let Some(p) = project {
        out.push(project_scope(p));
    }
    out.push("global".to_string());
    out
}

// ---------- search ----------

fn est_tokens(text: &str) -> usize {
    (text.chars().count() + 3) / 4
}

pub fn inject_line(rec: &Value) -> String {
    let body = rec.get("body").and_then(|v| v.as_str()).unwrap_or("");
    let body: String = body.chars().take(300).collect();
    let body = body.replace('\n', " ");
    format!(
        "[MEM:{}|{}|{}] {}: {}",
        rec.get("id").and_then(|v| v.as_str()).unwrap_or(""),
        rec.get("kind").and_then(|v| v.as_str()).unwrap_or(""),
        rec.get("scope").and_then(|v| v.as_str()).unwrap_or(""),
        rec.get("title").and_then(|v| v.as_str()).unwrap_or(""),
        body
    )
}

fn fts_query(q: &str) -> String {
    let toks: Vec<String> = static_re(r"(?i)[a-z0-9_]{2,}")
        .find_iter(&q.to_lowercase())
        .map(|m| m.as_str().to_string())
        .collect();
    if toks.is_empty() {
        return String::new();
    }
    toks.iter().map(|t| format!("\"{t}\"")).collect::<Vec<_>>().join(" OR ")
}

fn scope_rank(scope: &str, order: &[String]) -> f64 {
    match order.iter().position(|s| s == scope) {
        Some(i) => (order.len() - i) as f64,
        None => 0.0,
    }
}

#[allow(clippy::too_many_arguments)]
pub fn search(store: &Store, query: &str, scopes: Option<Vec<String>>, k: usize,
              token_budget: usize, session_id: Option<&str>, workflow_id: Option<&str>,
              project: Option<&str>, explain: bool, kinds: Option<&[String]>,
              include_pending: bool) -> Value {
    let t = now_f64();
    let order = scopes.unwrap_or_else(|| read_order(session_id, workflow_id, project));
    let mut hits: Vec<Value> = Vec::new();
    let mut text_scores: std::collections::HashMap<String, f64> = std::collections::HashMap::new();

    if store.fts && !query.trim().is_empty() {
        let fq = fts_query(query);
        if !fq.is_empty() {
            let limit = std::cmp::max(k * 8, 50);
            let mut rowids: Vec<i64> = Vec::new();
            if let Ok(mut stmt) = store.conn.prepare(
                "SELECT rowid, bm25(mem_fts) AS rank FROM mem_fts \
                 WHERE mem_fts MATCH ? ORDER BY rank LIMIT ?") {
                if let Ok(rows) = stmt.query_map(params![fq, limit as i64], |r| {
                    Ok((r.get::<_, i64>(0)?, r.get::<_, f64>(1)?))
                }) {
                    for row in rows.flatten() {
                        rowids.push(row.0);
                        if let Some(rec) = store.conn
                            .query_row("SELECT * FROM mem WHERE rowid=?", params![row.0],
                                       |r| row_to_json(r))
                            .optional()
                            .unwrap_or(None)
                        {
                            if let Some(id) = rec.get("id").and_then(|v| v.as_str()) {
                                text_scores.insert(id.to_string(), -row.1);
                            }
                            hits.push(rec);
                        }
                    }
                }
            }
        }
    } else if !store.fts && !query.trim().is_empty() {
        let q_tr: std::collections::HashSet<String> =
            trigrams(query).split_whitespace().map(String::from).collect();
        for row in collect_rows(&store.conn, "SELECT * FROM mem LIMIT 2000", []) {
            let title = row.get("title").and_then(|v| v.as_str()).unwrap_or("");
            let body = row.get("body").and_then(|v| v.as_str()).unwrap_or("");
            let tags = row.get("tags").and_then(|v| v.as_str()).unwrap_or("");
            let cand: std::collections::HashSet<String> =
                trigrams(&format!("{title} {body} {tags}"))
                    .split_whitespace().map(String::from).collect();
            if cand.is_empty() {
                continue;
            }
            let inter = q_tr.intersection(&cand).count();
            if inter > 0 {
                let id = row.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string();
                text_scores.insert(id, inter as f64 / q_tr.union(&cand).count() as f64);
                hits.push(row);
            }
        }
    }

    if query.trim().is_empty() {
        let limit = std::cmp::max(k * 8, 50);
        let placeholders = vec!["?"; order.len()].join(",");
        let sql = format!(
            "SELECT * FROM mem WHERE scope IN ({placeholders}) \
             ORDER BY pin DESC, updated DESC LIMIT ?");
        let mut args: Vec<Box<dyn rusqlite::ToSql>> = order
            .iter().map(|s| Box::new(s.clone()) as Box<dyn rusqlite::ToSql>).collect();
        args.push(Box::new(limit as i64));
        let refs: Vec<&dyn rusqlite::ToSql> = args.iter().map(|b| b.as_ref()).collect();
        for row in collect_rows(&store.conn, &sql, refs.as_slice()) {
            if let Some(id) = row.get("id").and_then(|v| v.as_str()) {
                text_scores.insert(id.to_string(), 1.0);
            }
            hits.push(row);
        }
    }

    let mut scored: Vec<(f64, i64, i64, Value)> = Vec::new();
    for rec in hits {
        let scope = rec.get("scope").and_then(|v| v.as_str()).unwrap_or("");
        if !order.iter().any(|s| s == scope) {
            continue;
        }
        if !include_pending && rec.get("pending").and_then(|v| v.as_i64()).unwrap_or(0) != 0 {
            continue;
        }
        if let Some(ks) = kinds {
            let kind = rec.get("kind").and_then(|v| v.as_str()).unwrap_or("");
            if !ks.iter().any(|s| s == kind) {
                continue;
            }
        }
        let created = rec.get("created").and_then(|v| v.as_f64()).unwrap_or(t);
        let age_days = ((t - created) / 86400.0).max(0.0);
        let recency = (-age_days / 30.0).exp();
        let uses = rec.get("uses").and_then(|v| v.as_f64()).unwrap_or(0.0);
        let pin = if rec.get("pin").and_then(|v| v.as_i64()).unwrap_or(0) != 0 { 0.5 } else { 0.0 };
        let use_score = 0.15 * (uses + 1.0).ln();
        let scope_w = scope_rank(scope, &order) / std::cmp::max(1, order.len()) as f64;
        let id = rec.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let text = text_scores.get(&id).copied().unwrap_or(0.0);
        let total = text + pin + 0.35 * recency + use_score + 0.5 * scope_w;
        let mut rec = rec;
        if explain {
            if let Value::Object(map) = &mut rec {
                map.insert("_explain".into(), json!({
                    "text": (text * 10000.0).round() / 10000.0,
                    "recency": ((0.35 * recency) * 10000.0).round() / 10000.0,
                    "pin": (pin * 10000.0).round() / 10000.0,
                    "uses": (use_score * 10000.0).round() / 10000.0,
                    "scope": (scope_w * 10000.0).round() / 10000.0,
                    "total": (total * 10000.0).round() / 10000.0
                }));
            }
        }
        let pin_v = rec.get("pin").and_then(|v| v.as_i64()).unwrap_or(0);
        let updated = rec.get("updated").and_then(|v| v.as_i64()).unwrap_or(0);
        scored.push((total, pin_v, updated, rec));
    }
    scored.sort_by(|a, b| {
        b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal)
            .then(a.1.cmp(&b.1))
            .then(b.2.cmp(&a.2))
    });

    let mut results: Vec<Value> = Vec::new();
    let mut used = 0usize;
    for (_, _, _, rec) in &scored {
        let line = inject_line(rec);
        let cost = est_tokens(&line);
        if used + cost > token_budget && !results.is_empty() {
            break;
        }
        used += cost;
        results.push(json!({"record": rec, "line": line, "tokens": cost}));
        if results.len() >= k {
            break;
        }
    }
    json!({
        "results": results, "tokens_used": used,
        "fts_mode": if store.fts { "fts5" } else { "like_trigram" },
        "scopes": order, "truncated": scored.len() > results.len()
    })
}

// ---------- export / import / sync ----------

fn atomic_write_text(path: &Path, text: &str) {
    let _ = std::fs::create_dir_all(path.parent().unwrap_or(Path::new(".")));
    let tmp = path.with_file_name(format!(
        ".{}.{}.tmp",
        path.file_name().map(|s| s.to_string_lossy().to_string()).unwrap_or_default(),
        std::process::id()
    ));
    if std::fs::write(&tmp, text.as_bytes()).is_ok() {
        if let Ok(f) = std::fs::File::open(&tmp) {
            let _ = f.sync_all();
        }
        let _ = std::fs::rename(&tmp, path);
    }
}

fn json_line(v: &Value, ascii: bool, sort_keys: bool) -> String {
    if sort_keys {
        // BTreeMap-backed Map already serializes in sorted key order.
        let _ = ascii;
        serde_json::to_string(v).unwrap_or_default()
    } else {
        crate::pyjson::dumps(v, ascii, ", ", ": ")
    }
}

pub fn export_jsonl(store: &Store, path: &str, scopes: Option<Vec<String>>)
                    -> Result<Value, String> {
    let p = PathBuf::from(path);
    let mut lines: Vec<String> = Vec::new();
    let mut q = String::from("SELECT * FROM mem");
    let mut args: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();
    if let Some(sc) = &scopes {
        if !sc.is_empty() {
            let ph = vec!["?"; sc.len()].join(",");
            q.push_str(&format!(" WHERE scope IN ({ph})"));
            for s in sc {
                args.push(Box::new(s.clone()));
            }
        }
    }
    let refs: Vec<&dyn rusqlite::ToSql> = args.iter().map(|b| b.as_ref()).collect();
    let rows = collect_rows(&store.conn, &q, refs.as_slice());
    for r in &rows {
        let mut map = Map::new();
        for c in EXPORT_COLUMNS {
            map.insert((*c).to_string(), r.get(*c).cloned().unwrap_or(Value::Null));
        }
        lines.push(json_line(&Value::Object(map), false, true));
    }
    let header = json!({
        "xt_export": 1, "schema_version": 1, "ts": now(), "records": rows.len()
    });
    let mut payload = json_line(&header, true, true);
    payload.push('\n');
    if !lines.is_empty() {
        payload.push_str(&lines.join("\n"));
        payload.push('\n');
    }
    atomic_write_text(&p, &payload);
    Ok(json!({"path": p.to_string_lossy().to_string(), "records": rows.len()}))
}

fn parse_export(path: &str) -> Result<(Value, Vec<Value>), String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
    let mut header = Value::Null;
    let mut recs = Vec::new();
    for (lineno, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let obj: Value = serde_json::from_str(line)
            .map_err(|e| format!("{path}:{}: invalid JSON: {e}", lineno + 1))?;
        if lineno == 0 && obj.get("xt_export").is_some() {
            header = obj;
            continue;
        }
        if obj.is_object() {
            recs.push(obj);
        }
    }
    Ok((header, recs))
}

fn rec_get<'a>(rec: &'a Value, key: &str) -> &'a Value {
    rec.get(key).unwrap_or(&Value::Null)
}

pub fn import_jsonl(store: &Store, path: &str, on_conflict: &str) -> Result<Value, String> {
    let (header, recs) = parse_export(path)?;
    if header.is_null() {
        return Err(format!("{path}: missing xt_export header line"));
    }
    let mut inserted = 0;
    let mut updated = 0;
    let mut skipped = 0;
    let mut rejected = 0;
    for rec in &recs {
        let id = rec.get("id").and_then(|v| v.as_str()).unwrap_or("");
        let kind = rec.get("kind").and_then(|v| v.as_str()).unwrap_or("");
        if id.is_empty() || !KINDS.contains(&kind) {
            rejected += 1;
            continue;
        }
        let existing = store.get(id);
        if let Some(existing) = existing {
            let ex_up = existing.get("updated").and_then(|v| v.as_i64()).unwrap_or(0);
            let rc_up = rec.get("updated").and_then(|v| v.as_i64()).unwrap_or(0);
            if on_conflict == "newer" && ex_up >= rc_up {
                skipped += 1;
                continue;
            }
            let cols: Vec<&str> = EXPORT_COLUMNS.iter().filter(|c| **c != "id").copied().collect();
            let sets = cols.iter().map(|c| format!("{c}=?")).collect::<Vec<_>>().join(",");
            let mut args: Vec<Box<dyn rusqlite::ToSql>> = cols
                .iter()
                .map(|c| value_to_sql(rec_get(rec, c)))
                .collect();
            args.push(Box::new(id.to_string()));
            let refs: Vec<&dyn rusqlite::ToSql> = args.iter().map(|b| b.as_ref()).collect();
            store.conn
                .execute(&format!("UPDATE mem SET {sets} WHERE id=?"), refs.as_slice())
                .map_err(|e| e.to_string())?;
            store.index(id,
                        rec_get(rec, "title").as_str().unwrap_or(""),
                        rec_get(rec, "body").as_str().unwrap_or(""),
                        rec_get(rec, "tags").as_str().unwrap_or(""));
            updated += 1;
        } else {
            let cols: Vec<&str> = EXPORT_COLUMNS.to_vec();
            let ph = vec!["?"; cols.len()].join(",");
            let args: Vec<Box<dyn rusqlite::ToSql>> = cols
                .iter()
                .map(|c| value_to_sql(rec_get(rec, c)))
                .collect();
            let refs: Vec<&dyn rusqlite::ToSql> = args.iter().map(|b| b.as_ref()).collect();
            store.conn
                .execute(
                    &format!("INSERT INTO mem({}) VALUES({ph})", cols.join(",")),
                    refs.as_slice(),
                )
                .map_err(|e| e.to_string())?;
            store.index(id,
                        rec_get(rec, "title").as_str().unwrap_or(""),
                        rec_get(rec, "body").as_str().unwrap_or(""),
                        rec_get(rec, "tags").as_str().unwrap_or(""));
            inserted += 1;
        }
    }
    Ok(json!({"inserted": inserted, "updated": updated, "skipped": skipped,
              "rejected": rejected, "records": recs.len()}))
}

fn value_to_sql(v: &Value) -> Box<dyn rusqlite::ToSql> {
    match v {
        Value::Null => Box::new(Option::<String>::None),
        Value::Bool(b) => Box::new(if *b { 1i64 } else { 0i64 }),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Box::new(i)
            } else if let Some(f) = n.as_f64() {
                Box::new(f)
            } else {
                Box::new(Option::<String>::None)
            }
        }
        Value::String(s) => Box::new(s.clone()),
        other => Box::new(other.to_string()),
    }
}

pub fn sync(store: &Store, path: &str, conflict_log: Option<&str>) -> Result<Value, String> {
    let (_header, recs) = parse_export(path)?;
    let mut conflicts: Vec<Value> = Vec::new();
    for rec in &recs {
        let id = rec.get("id").and_then(|v| v.as_str()).unwrap_or("");
        let kind = rec.get("kind").and_then(|v| v.as_str()).unwrap_or("");
        if id.is_empty() || !KINDS.contains(&kind) {
            continue;
        }
        if let Some(existing) = store.get(id) {
            let ex_up = existing.get("updated").and_then(|v| v.as_i64()).unwrap_or(0);
            let rc_up = rec.get("updated").and_then(|v| v.as_i64()).unwrap_or(0);
            if ex_up != rc_up {
                conflicts.push(json!({"id": id, "local_updated": ex_up,
                                      "remote_updated": rc_up}));
            }
        }
    }
    if let Some(log) = conflict_log {
        let obj = json!({"ts": now(), "conflicts": conflicts});
        let mut text = serde_json::to_string(&obj).unwrap_or_default();
        text.push('\n');
        atomic_write_text(Path::new(log), &text);
    }
    let mut result = import_jsonl(store, path, "newer")?;
    result["conflicts"] = json!(conflicts.len());
    result["conflict_log"] = json!(conflict_log.map(String::from));
    Ok(result)
}

// ---------- CLI ----------

fn read_body_file(src: &str) -> Result<String, String> {
    if src == "-" {
        let mut buf = String::new();
        std::io::stdin()
            .read_to_string(&mut buf)
            .map_err(|e| format!("cannot read --body-file -: {e}"))?;
        return Ok(buf);
    }
    std::fs::read_to_string(src).map_err(|e| format!("cannot read --body-file {src}: {e}"))
}

fn open_store(p: &Parsed) -> Result<Store, String> {
    let db = p
        .fstr("db")
        .unwrap_or_else(|| paths::xt_home().join("mem.db").to_string_lossy().to_string());
    Store::open(&db, None)
}

pub fn run(p: &Parsed) -> Option<i32> {
    let verb = p.verb.as_deref()?;
    if !matches!(verb, "put" | "get" | "search" | "list" | "forget" | "review"
        | "purge" | "export" | "import" | "sync") {
        return None;
    }
    let store = match open_store(p) {
        Ok(s) => s,
        Err(e) => return Some(util::fail(p.json, &e, 1)),
    };
    let scope = p.fstr("scope").unwrap_or_else(|| "global".into());
    Some(match verb {
        "put" => cmd_put(p, &store, &scope),
        "get" => cmd_get(p, &store),
        "search" => cmd_search(p, &store),
        "list" => cmd_list(p, &store, &scope),
        "forget" => cmd_forget(p, &store),
        "review" => {
            let pending = store.pending(p.fint("k", 5) as usize);
            util::out(p, &json!({"pending": pending}), None)
        }
        "purge" => util::out(p, &json!({"purged": store.purge_expired()}), None),
        "export" => cmd_export(p, &store),
        "import" => cmd_import(p, &store),
        "sync" => cmd_sync(p, &store),
        _ => return None,
    })
}

fn cmd_put(p: &Parsed, store: &Store, scope: &str) -> i32 {
    let mut body = String::new();
    if let Some(src) = p.fstr("body-file") {
        match read_body_file(&src) {
            Ok(t) => body = t,
            Err(e) => return util::fail(p.json, &e, 1),
        }
    }
    if body.trim().is_empty() {
        if let Some(b) = p.fstr("body") {
            body = b;
        } else if let Some(v) = p.pos(0) {
            body = v.to_string();
        }
    }
    let body = body.trim().to_string();
    if body.is_empty() {
        let msg = "mem put requires --body or --body-file";
        return util::out_with(p, &json!({"ok": false, "error": msg}), Some(msg.into()), 1);
    }
    let tags = p.flist("tag");
    let kind = p.fstr("kind").unwrap_or_else(|| "fact".into());
    let title = p.fstr("title").unwrap_or_default();
    let source = p.fstr("source").unwrap_or_else(|| "cli".into());
    let confidence = p.fstr("confidence").and_then(|s| s.parse::<f64>().ok()).unwrap_or(1.0);
    match store.put(scope, &kind, &title, &body, &tags, &source, confidence, false, None) {
        Ok(res) => {
            let human = format!(
                "{} {}",
                res.get("action").and_then(|v| v.as_str()).unwrap_or(""),
                res.get("id").and_then(|v| v.as_str()).unwrap_or("")
            );
            util::out(p, &res, Some(human))
        }
        Err(e) => util::fail(p.json, &e, 1),
    }
}

fn cmd_get(p: &Parsed, store: &Store) -> i32 {
    let id = p.fstr("id").or_else(|| p.pos(0).map(String::from)).unwrap_or_default();
    match store.get(&id) {
        Some(rec) => {
            let human = serde_json::to_string_pretty(&rec).unwrap_or_default();
            util::out(p, &rec, Some(human))
        }
        None => util::out(p, &Value::Null, Some("not found".into())),
    }
}

fn cmd_search(p: &Parsed, store: &Store) -> i32 {
    let query = p.fstr("query").or_else(|| p.pos(0).map(String::from)).unwrap_or_default();
    if query.trim().is_empty() {
        let msg = "mem search requires a query";
        return util::out_with(p, &json!({"ok": false, "error": msg}), Some(msg.into()), 1);
    }
    let kinds = p.fstr("kind").map(|k| vec![k]);
    let out = search(
        store, &query, None, p.fint("k", 5) as usize, p.fint("budget", 800) as usize,
        p.fstr("session").as_deref(), p.fstr("workflow").as_deref(),
        p.fstr("project").as_deref(), p.fbool("explain"), kinds.as_deref(), false,
    );
    let human = out["results"]
        .as_array()
        .map(|a| a.iter().filter_map(|r| r.get("line").and_then(|v| v.as_str()))
            .collect::<Vec<_>>().join("\n"))
        .unwrap_or_default();
    util::out(p, &out, Some(human))
}

fn cmd_list(p: &Parsed, store: &Store, scope: &str) -> i32 {
    let kind = p.fstr("kind");
    let recs = store.list(Some(scope), p.fint("k", 5) as usize, kind.as_deref(), None);
    let human = recs
        .iter()
        .map(|r| format!(
            "[{}] {} {}",
            r.get("id").and_then(|v| v.as_str()).unwrap_or(""),
            r.get("kind").and_then(|v| v.as_str()).unwrap_or(""),
            r.get("title").and_then(|v| v.as_str()).unwrap_or("")
        ))
        .collect::<Vec<_>>()
        .join("\n");
    util::out(p, &json!(recs), Some(human))
}

fn cmd_forget(p: &Parsed, store: &Store) -> i32 {
    let id = p.fstr("id").or_else(|| p.pos(0).map(String::from)).unwrap_or_default();
    let ok = store.forget(&id);
    util::out(
        p,
        &json!({"forgot": ok}),
        Some(if ok { format!("forgot {id}") } else { "not found".into() }),
    )
}

fn cmd_export(p: &Parsed, store: &Store) -> i32 {
    let path = p.fstr("path").or_else(|| p.pos(0).map(String::from)).unwrap_or_default();
    let scope_arg = p.fstr("scope").unwrap_or_else(|| "global".into());
    let scopes = if scope_arg.is_empty() || scope_arg == "global" {
        None
    } else {
        Some(scope_arg.split(',').filter(|s| !s.is_empty()).map(String::from).collect())
    };
    match export_jsonl(store, &path, scopes) {
        Ok(res) => {
            let human = format!(
                "exported {} -> {}",
                res.get("records").and_then(|v| v.as_i64()).unwrap_or(0),
                res.get("path").and_then(|v| v.as_str()).unwrap_or("")
            );
            util::out(p, &res, Some(human))
        }
        Err(e) => util::fail(p.json, &e, 1),
    }
}

fn cmd_import(p: &Parsed, store: &Store) -> i32 {
    let path = p.fstr("path").or_else(|| p.pos(0).map(String::from)).unwrap_or_default();
    match import_jsonl(store, &path, "newer") {
        Ok(res) => util::out(p, &res, None),
        Err(e) => util::fail(p.json, &e, 1),
    }
}

fn cmd_sync(p: &Parsed, store: &Store) -> i32 {
    let path = p.fstr("path").or_else(|| p.pos(0).map(String::from)).unwrap_or_default();
    let log = p.fstr("conflicts");
    match sync(store, &path, log.as_deref()) {
        Ok(res) => util::out(p, &res, None),
        Err(e) => util::fail(p.json, &e, 1),
    }
}
