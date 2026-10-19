//! Boot-time recalibration (mirrors xtforge/core/calibrate.py).

use std::path::PathBuf;
use std::time::Instant;

use serde_json::{json, Map, Value};

use crate::args::Parsed;
use crate::flash::Flash;
use crate::mem::Store;
use crate::paths;
use crate::util;

pub fn current_boot_id() -> String {
    if let Ok(txt) = std::fs::read_to_string("/proc/sys/kernel/random/boot_id") {
        let t = txt.trim();
        if !t.is_empty() {
            return t.to_string();
        }
    }
    if let Ok(stat) = std::fs::read_to_string("/proc/stat") {
        for line in stat.lines() {
            if let Some(rest) = line.strip_prefix("btime ") {
                if let Some(btime) = rest.split_whitespace().next() {
                    return format!("btime-{btime}");
                }
            }
        }
    }
    if let Ok(up) = std::fs::read_to_string("/proc/uptime") {
        if let Some(u) = up.split_whitespace().next() {
            return format!("uptime-{u}");
        }
    }
    "unknown-boot".to_string()
}

pub fn boot_path() -> PathBuf {
    paths::cache_dir().join("boot.json")
}

pub fn read_boot() -> Option<Value> {
    let text = std::fs::read_to_string(boot_path()).ok()?;
    serde_json::from_str(&text).ok()
}

fn write_boot(rec: &Value) {
    let mut text = serde_json::to_string(rec).unwrap_or_default();
    text.push('\n');
    atomic_write_text(&boot_path(), &text);
}

fn atomic_write_text(path: &PathBuf, text: &str) {
    let _ = std::fs::create_dir_all(path.parent().unwrap_or(std::path::Path::new(".")));
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

fn now_f64() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

pub fn needs_calibration() -> Value {
    let boot_id = current_boot_id();
    let prev = read_boot();
    let prev_id = prev.as_ref().and_then(|p| p.get("boot_id")).and_then(|v| v.as_str());
    let reboot = prev_id.map(|p| p != boot_id).unwrap_or(true);

    let mut caps_stale = true;
    let caps_path = paths::cache_dir().join("caps.json");
    if let Ok(text) = std::fs::read_to_string(&caps_path) {
        if let Ok(caps) = serde_json::from_str::<Value>(&text) {
            if let Some(stamp) = caps.get("stamp").and_then(|v| v.as_f64()) {
                let age = now_f64() - stamp;
                let same_boot = match caps.get("boot_id").and_then(|v| v.as_str()) {
                    Some(b) => b == boot_id,
                    None => true, // pre-calibration cache
                };
                caps_stale = age >= 3600.0 || !same_boot;
            }
        }
    }

    let wal_present = paths::xt_home().join("mem.db-wal").exists()
        || paths::xt_home().join("mem.db-shm").exists();

    let needs = reboot || caps_stale || wal_present || prev.is_none();
    json!({
        "boot_id": boot_id,
        "prev_boot_id": prev_id,
        "reboot": reboot,
        "caps_stale": caps_stale,
        "wal_present": wal_present,
        "needs": needs
    })
}

fn sqlite_maintenance(path: &PathBuf) -> Value {
    let mut out = Map::new();
    out.insert("integrity".into(), Value::Null);
    out.insert("checkpoint".into(), Value::Null);
    out.insert("purged".into(), json!(0));
    out.insert("fts".into(), Value::Null);
    if !path.exists() {
        out.insert("integrity".into(), json!("no-db"));
        return Value::Object(out);
    }
    if let Ok(conn) = rusqlite::Connection::open(path) {
        let integrity: Option<String> = conn
            .query_row("PRAGMA integrity_check", [], |r| r.get(0))
            .ok();
        out.insert("integrity".into(), json!(integrity.unwrap_or_else(|| "unknown".into())));
        let chk: Option<(i64, i64, i64)> = conn
            .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?))
            })
            .ok();
        out.insert("checkpoint".into(), match chk {
            Some((a, b, c)) => json!([a, b, c]),
            None => Value::Null,
        });
    }
    match Store::open(&path.to_string_lossy(), None) {
        Ok(store) => {
            let purged = store.purge_expired();
            out.insert("purged".into(), json!(purged));
            if store.fts {
                let n_mem: i64 = store.conn
                    .query_row("SELECT COUNT(*) FROM mem", [], |r| r.get(0))
                    .unwrap_or(0);
                let n_fts: i64 = store.conn
                    .query_row("SELECT COUNT(*) FROM mem_fts", [], |r| r.get(0))
                    .unwrap_or(-1);
                let mut fts = Map::new();
                fts.insert("mem".into(), json!(n_mem));
                fts.insert("fts".into(), json!(n_fts));
                fts.insert("match".into(), json!(n_mem == n_fts));
                if n_mem != n_fts {
                    let _ = store.conn
                        .execute_batch("INSERT INTO mem_fts(mem_fts) VALUES('rebuild');");
                    fts.insert("rebuilt".into(), json!(true));
                }
                out.insert("fts".into(), Value::Object(fts));
            } else {
                out.insert("fts".into(), json!("like_trigram"));
            }
        }
        Err(e) => {
            out.insert("store_error".into(), json!(e));
        }
    }
    if let Ok(conn2) = rusqlite::Connection::open(path) {
        let _ = conn2.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);");
    }
    Value::Object(out)
}

fn flash_maintenance() -> Value {
    let f = Flash::new(None);
    let mut scopes = f.scopes();
    if scopes.is_empty() {
        scopes = vec!["global".to_string()];
    }
    let mut per_scope = Map::new();
    let mut totals = (0i64, 0i64, 0i64, 0i64);
    for scope in scopes {
        let res = f.compact(&scope);
        let stats = f.stats(&scope);
        let mut entry = match res {
            Value::Object(m) => m,
            other => {
                let mut m = Map::new();
                m.insert("error".into(), other);
                m
            }
        };
        entry.insert("stats".into(), stats);
        totals.0 += entry.get("expired").and_then(|v| v.as_i64()).unwrap_or(0);
        totals.1 += entry.get("dupes_merged").and_then(|v| v.as_i64()).unwrap_or(0);
        totals.2 += entry.get("evicted").and_then(|v| v.as_i64()).unwrap_or(0);
        totals.3 += 1;
        per_scope.insert(scope, Value::Object(entry));
    }
    json!({
        "totals": {"scopes": totals.3, "expired": totals.0,
                   "dupes_merged": totals.1, "evicted": totals.2},
        "scopes": per_scope
    })
}

fn binary_works(path: &PathBuf) -> bool {
    if !path.exists() {
        return false;
    }
    std::process::Command::new(path)
        .arg("--help")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn caps_probe(boot_id: &str) -> Value {
    let native_dir = paths::repo_root().join("native").join("build");
    let mut tools = Map::new();
    for t in ["xtscan", "xtdigest", "xtsqueeze"] {
        let backend = if binary_works(&native_dir.join(t)) { "native" } else { "python" };
        tools.insert(t.to_string(), json!(backend));
    }
    let ts = now_f64();
    let caps = json!({
        "ts": ts, "force_python": false,
        "native_dir": native_dir.to_string_lossy(),
        "tools": tools, "stamp": ts, "boot_id": boot_id
    });
    let mut text = serde_json::to_string(&caps).unwrap_or_default();
    text.push('\n');
    atomic_write_text(&paths::cache_dir().join("caps.json"), &text);
    caps
}

fn sync_drift() -> Value {
    let root = paths::repo_root();
    let python = std::env::var("XT_PYTHON")
        .unwrap_or_else(|_| "/data/data/com.termux/files/usr/bin/python3".to_string());
    let mut cmd = std::process::Command::new(python);
    cmd.args(["-m", "xtforge.cli", "sync", "--dry-run", "--json"])
        .current_dir(&root)
        .env("PYTHONPATH", root.to_string_lossy().to_string());
    match cmd.output() {
        Ok(out) if out.status.success() => {
            match serde_json::from_slice::<Value>(&out.stdout) {
                Ok(d) => json!({"would_write": d.get("would_write"), "unchanged": d.get("unchanged")}),
                Err(e) => json!({"error": e.to_string()}),
            }
        }
        Ok(out) => json!({"error": String::from_utf8_lossy(&out.stderr).trim()}),
        Err(e) => json!({"error": e.to_string()}),
    }
}

pub fn calibrate(force: bool) -> Value {
    let t0 = Instant::now();
    let boot_id = current_boot_id();
    let prev = read_boot();
    let prev_id = prev.as_ref().and_then(|p| p.get("boot_id")).and_then(|v| v.as_str());
    let reboot = prev_id.map(|p| p != boot_id).unwrap_or(true);
    let pre = needs_calibration();
    let skipped = !force && !pre.get("needs").and_then(|v| v.as_bool()).unwrap_or(true);
    let mut result = Map::new();
    result.insert("ok".into(), json!(true));
    result.insert("boot_id".into(), json!(boot_id));
    result.insert("prev_boot_id".into(), match prev_id {
        Some(p) => json!(p),
        None => Value::Null,
    });
    result.insert("reboot".into(), json!(reboot));
    result.insert("forced".into(), json!(force));
    result.insert("skipped".into(), json!(skipped));
    result.insert("ts".into(), json!(now_f64()));
    if skipped {
        result.insert("reason".into(), json!("fresh; no reboot, caps fresh, no WAL"));
        result.insert("ms".into(), json!(t0.elapsed().as_millis() as i64));
        return Value::Object(result);
    }
    let db = paths::xt_home().join("mem.db");
    result.insert("sqlite".into(), sqlite_maintenance(&db));
    result.insert("flash".into(), flash_maintenance());
    let caps = caps_probe(&boot_id);
    result.insert("caps".into(), json!({
        "tools": caps.get("tools"), "boot_id": boot_id
    }));
    result.insert("sync_drift".into(), sync_drift());
    let ms = t0.elapsed().as_millis() as i64;
    result.insert("ms".into(), json!(ms));
    write_boot(&json!({
        "boot_id": boot_id,
        "last_calibrated": now_f64(),
        "last_ms": ms,
        "reboot": reboot
    }));
    Value::Object(result)
}

pub fn status() -> Value {
    let pre = needs_calibration();
    let prev = read_boot();
    let mut out = match pre {
        Value::Object(m) => m,
        other => {
            let mut m = Map::new();
            m.insert("needs".into(), other);
            m
        }
    };
    out.insert("last_calibrated".into(),
               prev.as_ref().and_then(|p| p.get("last_calibrated")).cloned()
                   .unwrap_or(Value::Null));
    out.insert("boot_file".into(), json!(boot_path().to_string_lossy()));
    out.insert("db".into(), json!(paths::xt_home().join("mem.db").to_string_lossy()));
    Value::Object(out)
}

fn py_bool(b: bool) -> &'static str {
    if b { "True" } else { "False" }
}

pub fn run(p: &Parsed) -> Option<i32> {
    if p.fbool("status") {
        let st = status();
        let human = serde_json::to_string_pretty(&st).unwrap_or_default();
        return Some(util::out(p, &st, Some(human)));
    }
    let res = calibrate(p.fbool("force"));
    let skipped = res.get("skipped").and_then(|v| v.as_bool()).unwrap_or(false);
    let boot = res.get("boot_id").and_then(|v| v.as_str()).unwrap_or("");
    let reboot = res.get("reboot").and_then(|v| v.as_bool()).unwrap_or(false);
    let human = format!(
        "calibrate {} in {}ms boot={} reboot={}",
        if skipped { "skipped (fresh)" } else { "done" },
        res.get("ms").and_then(|v| v.as_i64()).unwrap_or(0),
        &boot[..boot.len().min(8)],
        py_bool(reboot)
    );
    Some(util::out(p, &res, Some(human)))
}
