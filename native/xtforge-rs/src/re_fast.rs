//! Stateful binary annotation overlay (re_overlay.db) + fast native Rust
//! Mach-O/ELF/PE header, entropy, packer, and XOR-string extraction.

use rusqlite::{params, Connection};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::args::Parsed;
use crate::guard;
use crate::paths;
use crate::util;

const OVERLAY_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS binaries (
  sha256 TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  format TEXT NOT NULL,
  size INTEGER NOT NULL,
  updated INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS annotations (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  sha256 TEXT NOT NULL,
  rva INTEGER NOT NULL,
  kind TEXT NOT NULL,
  orig_name TEXT NOT NULL DEFAULT '',
  new_name TEXT NOT NULL DEFAULT '',
  type_decl TEXT NOT NULL DEFAULT '',
  comment TEXT NOT NULL DEFAULT '',
  confidence REAL NOT NULL DEFAULT 1.0,
  updated INTEGER NOT NULL,
  UNIQUE(sha256, rva, kind)
);
CREATE INDEX IF NOT EXISTS idx_ann_sha ON annotations(sha256);
"#;

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn open_overlay_db() -> Result<Connection, String> {
    let p = paths::xt_home().join("re_overlay.db");
    let conn = Connection::open(&p).map_err(|e| e.to_string())?;
    conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;")
        .map_err(|e| e.to_string())?;
    conn.execute_batch(OVERLAY_SCHEMA).map_err(|e| e.to_string())?;
    Ok(conn)
}

fn sniff_fmt(data: &[u8]) -> &'static str {
    if data.starts_with(b"\x7fELF") {
        return "elf";
    }
    if data.starts_with(b"MZ") {
        return "pe";
    }
    if data.len() >= 4 {
        let m = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        if matches!(m, 0xFEEDFACE | 0xFEEDFACF | 0xCEFAEDFE | 0xCFFAEDFE | 0xCAFEBABE | 0xBEBAFECA) {
            return "macho";
        }
    }
    "raw"
}

fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let n = data.len() as f64;
    let mut h = 0.0;
    for c in counts {
        if c > 0 {
            let p = (c as f64) / n;
            h -= p * p.log2();
        }
    }
    (h * 1000.0).round() / 1000.0
}

fn sha256_hex(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    format!("{:x}", h.finalize())
}

fn parse_rva(s: &str) -> Result<i64, String> {
    let trimmed = s.trim();
    if let Some(hex) = trimmed.strip_prefix("0x").or_else(|| trimmed.strip_prefix("0X")) {
        i64::from_str_radix(hex, 16).map_err(|_| format!("invalid hex RVA: {s}"))
    } else {
        trimmed.parse::<i64>().map_err(|_| format!("invalid RVA: {s}"))
    }
}

fn macho_info(data: &[u8]) -> Value {
    if data.len() < 28 {
        return json!({"format": "macho", "error": "truncated header"});
    }
    let magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    let (bits, endian) = match magic {
        0xFEEDFACE => (32, "little"),
        0xFEEDFACF => (64, "little"),
        0xCEFAEDFE => (32, "big"),
        0xCFFAEDFE => (64, "big"),
        0xCAFEBABE | 0xBEBAFECA => (64, "fat"),
        _ => (0, "unknown"),
    };
    let cputype = if endian == "big" {
        u32::from_be_bytes([data[4], data[5], data[6], data[7]])
    } else {
        u32::from_le_bytes([data[4], data[5], data[6], data[7]])
    };
    let arch = match cputype & 0x00ffffff {
        7 => "x86",
        12 => "arm",
        _ => "other",
    };
    let ncmds = if endian == "big" {
        u32::from_be_bytes([data[16], data[17], data[18], data[19]])
    } else {
        u32::from_le_bytes([data[16], data[17], data[18], data[19]])
    };
    json!({
        "format": "macho",
        "bits": bits,
        "endian": endian,
        "arch": if bits == 64 && arch == "x86" { "x86_64" } else if bits == 64 && arch == "arm" { "arm64" } else { arch },
        "load_commands": ncmds,
    })
}

fn push_xor_hit(hits: &mut Vec<(usize, Value)>, key: u8, start: usize, run: &[u8]) {
    let s = String::from_utf8_lossy(run).to_string();
    let alpha = s.chars().filter(|c| c.is_ascii_alphanumeric()).count();
    let first = s.as_bytes()[0];
    let uniform = s.bytes().all(|b| b == first);
    if !uniform && alpha * 2 >= s.len() {
        hits.push((
            s.len(),
            json!({
                "hex_key": format!("0x{:02x}", key),
                "offset": format!("0x{:x}", start),
                "string": s,
            }),
        ));
    }
}

fn xor_strings(data: &[u8], min_len: usize) -> Vec<Value> {
    let mut hits: Vec<(usize, Value)> = Vec::new();
    let sample = &data[..data.len().min(512 * 1024)];
    for key in 1u8..=255 {
        let mut run = Vec::new();
        let mut start = 0usize;
        for (i, &b) in sample.iter().enumerate() {
            let dec = b ^ key;
            if (0x20..=0x7e).contains(&dec) {
                if run.is_empty() {
                    start = i;
                }
                run.push(dec);
            } else {
                if run.len() >= min_len {
                    push_xor_hit(&mut hits, key, start, &run);
                }
                run.clear();
            }
        }
        if run.len() >= min_len {
            push_xor_hit(&mut hits, key, start, &run);
        }
        if hits.len() >= 2000 {
            break;
        }
    }
    hits.sort_by(|a, b| b.0.cmp(&a.0));
    hits.into_iter().take(100).map(|(_, v)| v).collect()
}

fn cmd_annotate(p: &Parsed) -> i32 {
    let sub = p.pos(0).unwrap_or("list");
    let path_str = p.fstr("path").or_else(|| p.pos(1).map(String::from)).unwrap_or_default();
    if path_str.is_empty() {
        return util::fail(p.json, "re annotate requires <subverb> <binary_path>", 2);
    }
    let canon = match guard::read_guard(&path_str) {
        Ok(c) => c,
        Err(d) => return util::fail(p.json, &format!("{}: {}", d.code, d.reason), 1),
    };
    let bytes = match std::fs::read(&canon) {
        Ok(b) => b,
        Err(e) => return util::fail(p.json, &e.to_string(), 1),
    };
    let sha = sha256_hex(&bytes);
    let fmt = sniff_fmt(&bytes);
    let conn = match open_overlay_db() {
        Ok(c) => c,
        Err(e) => return util::fail(p.json, &e, 1),
    };
    let ts = now();
    let _ = conn.execute(
        "INSERT INTO binaries(sha256,name,format,size,updated) VALUES(?,?,?,?,?) ON CONFLICT(sha256) DO UPDATE SET updated=excluded.updated",
        params![&sha, canon.file_name().map(|s| s.to_string_lossy().to_string()).unwrap_or_default(), fmt, bytes.len() as i64, ts],
    );

    match sub {
        "rename" | "comment" | "type" => {
            let rva_str = p.fstr("rva").or_else(|| p.pos(2).map(String::from)).unwrap_or_else(|| "0".into());
            let rva = match parse_rva(&rva_str) {
                Ok(v) => v,
                Err(e) => return util::fail(p.json, &e, 2),
            };
            let new_name = p
                .fstr("name")
                .or_else(|| (sub == "rename").then(|| p.pos(3)).flatten().map(String::from))
                .unwrap_or_default();
            let orig_name = p.fstr("orig").unwrap_or_default();
            let comment = p
                .fstr("comment")
                .or_else(|| p.fstr("text"))
                .or_else(|| (sub == "comment").then(|| p.pos(3)).flatten().map(String::from))
                .unwrap_or_default();
            let type_decl = p
                .fstr("type-decl")
                .or_else(|| (sub == "type").then(|| p.pos(3)).flatten().map(String::from))
                .unwrap_or_default();
            let conf = p.fstr("confidence").and_then(|s| s.parse::<f64>().ok()).unwrap_or(1.0);
            let _ = conn.execute(
                "INSERT INTO annotations(sha256,rva,kind,orig_name,new_name,type_decl,comment,confidence,updated) VALUES(?,?,?,?,?,?,?,?,?)
                 ON CONFLICT(sha256,rva,kind) DO UPDATE SET new_name=excluded.new_name, orig_name=excluded.orig_name, type_decl=excluded.type_decl, comment=excluded.comment, confidence=excluded.confidence, updated=excluded.updated",
                params![&sha, rva, sub, &orig_name, &new_name, &type_decl, &comment, conf, ts],
            );
            util::out(
                p,
                &json!({
                    "ok": true,
                    "sha256": sha,
                    "rva": format!("0x{:x}", rva),
                    "kind": sub,
                    "name": new_name,
                    "comment": comment,
                    "type_decl": type_decl,
                }),
                None,
            )
        }
        "list" => {
            let mut stmt = conn.prepare("SELECT rva, kind, orig_name, new_name, type_decl, comment, confidence FROM annotations WHERE sha256=? ORDER BY rva").unwrap();
            let rows: Vec<Value> = stmt
                .query_map(params![&sha], |r| {
                    Ok(json!({
                        "rva": format!("0x{:x}", r.get::<_, i64>(0)?),
                        "kind": r.get::<_, String>(1)?,
                        "orig_name": r.get::<_, String>(2)?,
                        "new_name": r.get::<_, String>(3)?,
                        "type_decl": r.get::<_, String>(4)?,
                        "comment": r.get::<_, String>(5)?,
                        "confidence": r.get::<_, f64>(6)?,
                    }))
                })
                .unwrap()
                .flatten()
                .collect();
            util::out(p, &json!({"ok": true, "sha256": sha, "count": rows.len(), "annotations": rows}), None)
        }
        "export" => {
            let fmt_out = p.fstr("format").unwrap_or_else(|| "rizin".into());
            let mut stmt = conn.prepare("SELECT rva, kind, new_name, type_decl, comment FROM annotations WHERE sha256=? ORDER BY rva").unwrap();
            let rows: Vec<(i64, String, String, String, String)> = stmt
                .query_map(params![&sha], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)))
                .unwrap()
                .flatten()
                .collect();
            let mut script = Vec::new();
            for (rva, kind, name, ty, cmt) in &rows {
                match fmt_out.as_str() {
                    "ghidra" => {
                        if kind == "rename" && !name.is_empty() {
                            script.push(format!("createLabel(toAddr(0x{rva:x}), \"{name}\", True)"));
                        }
                        if !cmt.is_empty() {
                            script.push(format!("setEOLComment(toAddr(0x{rva:x}), \"{cmt}\")"));
                        }
                    }
                    "ida" => {
                        if kind == "rename" && !name.is_empty() {
                            script.push(format!("ida_name.set_name(0x{rva:x}, \"{name}\")"));
                        }
                        if !cmt.is_empty() {
                            script.push(format!("ida_bytes.set_cmt(0x{rva:x}, \"{cmt}\", 0)"));
                        }
                    }
                    _ => {
                        if kind == "rename" && !name.is_empty() {
                            script.push(format!("afn {name} @ 0x{rva:x}"));
                        }
                        if !ty.is_empty() {
                            script.push(format!("CCu {ty} @ 0x{rva:x}"));
                        }
                        if !cmt.is_empty() {
                            script.push(format!("CC {cmt} @ 0x{rva:x}"));
                        }
                    }
                }
            }
            util::out(p, &json!({"ok": true, "format": fmt_out, "sha256": sha, "script": script.join("\n")}), None)
        }
        _ => util::fail(p.json, &format!("unknown annotate subverb: {sub}"), 2),
    }
}

pub fn run(p: &Parsed) -> Option<i32> {
    let verb = p.verb.as_deref()?;
    match verb {
        "annotate" => Some(cmd_annotate(p)),
        "entropy" => {
            let raw = p.fstr("path").or_else(|| p.pos(0).map(String::from))?;
            let canon = match guard::read_guard(&raw) {
                Ok(c) => c,
                Err(d) => return Some(util::fail(p.json, &format!("{}: {}", d.code, d.reason), 1)),
            };
            let Ok(data) = std::fs::read(&canon) else {
                return None;
            };
            let ent = shannon_entropy(&data);
            let verdict = if ent >= 7.2 { "packed_or_encrypted" } else if ent >= 6.2 { "compressed_or_dense" } else { "normal" };
            let block_size = p.fint("block", 0) as usize;
            let count = p.fint("count", 32) as usize;
            let mut blocks = Vec::new();
            if block_size > 0 {
                for (idx, chunk) in data.chunks(block_size).take(count).enumerate() {
                    let be = shannon_entropy(chunk);
                    blocks.push(json!({"offset": format!("0x{:x}", idx * block_size), "entropy": be, "verdict": if be >= 7.2 { "high" } else { "ok" }}));
                }
            }
            Some(util::out(p, &json!({"ok": true, "path": canon.to_string_lossy(), "bytes": data.len(), "entropy": ent, "verdict": verdict, "blocks": blocks, "engine": "rust"}), None))
        }
        "strings" if p.fbool("xor") => {
            let raw = p.fstr("path").or_else(|| p.pos(0).map(String::from))?;
            let canon = match guard::read_guard(&raw) {
                Ok(c) => c,
                Err(d) => return Some(util::fail(p.json, &format!("{}: {}", d.code, d.reason), 1)),
            };
            let Ok(data) = std::fs::read(&canon) else { return None; };
            let min_len = p.fint("min-len", 4).max(2) as usize;
            let hits = xor_strings(&data, min_len);
            Some(util::out(p, &json!({"ok": true, "path": canon.to_string_lossy(), "xor_strings": hits, "engine": "rust"}), None))
        }
        "info" => {
            let raw = p.fstr("path").or_else(|| p.pos(0).map(String::from))?;
            let canon = match guard::read_guard(&raw) {
                Ok(c) => c,
                Err(_) => return None,
            };
            let Ok(data) = std::fs::read(&canon) else { return None; };
            if sniff_fmt(&data) == "macho" {
                let mut val = macho_info(&data);
                val["ok"] = json!(true);
                val["path"] = json!(canon.to_string_lossy());
                val["sha256"] = json!(sha256_hex(&data));
                return Some(util::out(p, &val, None));
            }
            None
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entropy_xor_macho_and_overlay() {
        let mut payload = vec![0u8; 64];
        for (i, b) in b"secret_endpoint_url".iter().enumerate() {
            payload[i] = b ^ 0x5A;
        }
        let ent = shannon_entropy(&payload);
        assert!(ent > 0.0);
        let hits = xor_strings(&payload, 6);
        assert!(hits
            .iter()
            .any(|h| h["string"].as_str().unwrap_or("").contains("secret_endpoint_url")));

        // 64-bit Mach-O little-endian header magic
        let mut macho = vec![0u8; 32];
        macho[0..4].copy_from_slice(&0xFEED_FACFu32.to_le_bytes());
        macho[4..8].copy_from_slice(&0x0100_0007u32.to_le_bytes());
        assert_eq!(sniff_fmt(&macho), "macho");
        let info = macho_info(&macho);
        assert_eq!(info["arch"], "x86_64");

        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(OVERLAY_SCHEMA).unwrap();
        let sha = sha256_hex(&payload);
        conn.execute(
            "INSERT INTO annotations(sha256,rva,kind,orig_name,new_name,type_decl,comment,confidence,updated)
             VALUES(?1,4096,'rename','sub_1000','decrypt_cfg','','',0.9,1)",
            params![&sha],
        )
        .unwrap();
        let new_name: String = conn
            .query_row("SELECT new_name FROM annotations WHERE sha256=?1", params![&sha], |r| r.get(0))
            .unwrap();
        assert_eq!(new_name, "decrypt_cfg");
    }
}
