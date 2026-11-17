//! Native Rust codec toolkit (hash, encode, decode, roundtrip, entropy).
//! Falls back to Python for algorithms/schemes not handled natively (`md5`,
//! `sha1`, `sha3_256`, `blake2*`, `base32`, `binary`, `inspect`, `hash --all`).

use serde_json::json;
use sha2::{Digest, Sha256, Sha512};

use crate::args::Parsed;
use crate::util;

const B64_STD: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const B64_URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

fn input_bytes(p: &Parsed) -> Result<Vec<u8>, String> {
    if let Some(path) = p.fstr("path") {
        return std::fs::read(&path).map_err(|e| e.to_string());
    }
    let raw = p
        .pos(0)
        .map(String::from)
        .or_else(|| p.fstr("text"))
        .unwrap_or_default();
    Ok(raw.into_bytes())
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn crc32_ieee(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

fn b64_encode(data: &[u8], url: bool) -> String {
    let table = if url { B64_URL } else { B64_STD };
    let mut out = String::with_capacity((data.len() * 4 + 2) / 3);
    let mut i = 0;
    while i < data.len() {
        let b0 = data[i] as u32;
        let rem = data.len() - i;
        let b1 = if rem > 1 { data[i + 1] as u32 } else { 0 };
        let b2 = if rem > 2 { data[i + 2] as u32 } else { 0 };
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(table[((n >> 18) & 0x3F) as usize] as char);
        out.push(table[((n >> 12) & 0x3F) as usize] as char);
        if rem > 1 {
            out.push(table[((n >> 6) & 0x3F) as usize] as char);
        }
        if rem > 2 {
            out.push(table[(n & 0x3F) as usize] as char);
        }
        i += 3;
    }
    out
}

fn b64_decode(text: &str, url: bool) -> Result<Vec<u8>, String> {
    let clean: String = text.trim().trim_end_matches('=').chars().filter(|c| !c.is_whitespace()).collect();
    if clean.len() % 4 == 1 {
        return Err("invalid base64 length".into());
    }
    let mut vals = Vec::with_capacity(clean.len());
    for b in clean.bytes() {
        let v = match b {
            b'A'..=b'Z' => b - b'A',
            b'a'..=b'z' => b - b'a' + 26,
            b'0'..=b'9' => b - b'0' + 52,
            b'+' if !url => 62,
            b'/' if !url => 63,
            b'-' if url => 62,
            b'_' if url => 63,
            // Python urlsafe_b64decode accepts both, standard rejects -/_ unless urlsafe; keep strict:
            b'+' | b'/' if url => {
                if b == b'+' { 62 } else { 63 }
            }
            _ => return Err(format!("invalid base64 character: {}", b as char)),
        };
        vals.push(v);
    }
    let mut out = Vec::with_capacity((vals.len() * 3) / 4);
    let mut i = 0;
    while i + 1 < vals.len() {
        let v0 = vals[i] as u32;
        let v1 = vals[i + 1] as u32;
        let rem = vals.len() - i;
        let v2 = if rem > 2 { vals[i + 2] as u32 } else { 0 };
        let v3 = if rem > 3 { vals[i + 3] as u32 } else { 0 };
        out.push(((v0 << 2) | (v1 >> 4)) as u8);
        if rem > 2 {
            out.push((((v1 & 0x0F) << 4) | (v2 >> 2)) as u8);
        }
        if rem > 3 {
            out.push((((v2 & 0x03) << 6) | v3) as u8);
        }
        i += 4;
    }
    Ok(out)
}

fn hex_decode(text: &str) -> Result<Vec<u8>, String> {
    let cleaned: String = text
        .chars()
        .filter(|c| !c.is_whitespace() && *c != ':' && *c != '-')
        .collect();
    if cleaned.len() % 2 != 0 {
        return Err("non-hexadecimal or odd-length hex string".into());
    }
    let mut out = Vec::with_capacity(cleaned.len() / 2);
    let bytes = cleaned.as_bytes();
    for pair in bytes.chunks_exact(2) {
        let hi = (pair[0] as char).to_digit(16).ok_or_else(|| "invalid hex digit".to_string())?;
        let lo = (pair[1] as char).to_digit(16).ok_or_else(|| "invalid hex digit".to_string())?;
        out.push(((hi << 4) | lo) as u8);
    }
    Ok(out)
}

fn url_encode(data: &[u8]) -> String {
    let s = String::from_utf8_lossy(data);
    let mut out = String::with_capacity(s.len());
    for b in s.as_bytes() {
        let is_unreserved = b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~');
        if is_unreserved {
            out.push(*b as char);
        } else {
            out.push_str(&format!("%{:02X}", b));
        }
    }
    out
}

fn url_decode(text: &str) -> Vec<u8> {
    let bytes = text.trim().as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(hi), Some(lo)) = (
                (bytes[i + 1] as char).to_digit(16),
                (bytes[i + 2] as char).to_digit(16),
            ) {
                out.push(((hi << 4) | lo) as u8);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    out
}

fn html_encode(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#x27;"),
            _ => out.push(ch),
        }
    }
    out
}

fn html_decode(text: &str) -> String {
    text.trim()
        .replace("&quot;", "\"")
        .replace("&#x27;", "'")
        .replace("&#39;", "'")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&")
}

fn rot13(text: &str) -> String {
    text.chars()
        .map(|ch| {
            if ch.is_ascii_uppercase() {
                (b'A' + (ch as u8 - b'A' + 13) % 26) as char
            } else if ch.is_ascii_lowercase() {
                (b'a' + (ch as u8 - b'a' + 13) % 26) as char
            } else {
                ch
            }
        })
        .collect()
}

fn encode_native(data: &[u8], scheme: &str) -> Option<String> {
    let out = match scheme {
        "base64" => b64_encode(data, false),
        "base64url" => b64_encode(data, true),
        "hex" => hex_lower(data),
        "url" => url_encode(data),
        "html" => html_encode(&String::from_utf8_lossy(data)),
        "rot13" => rot13(&String::from_utf8_lossy(data)),
        "upper" => String::from_utf8_lossy(data).to_uppercase(),
        "reverse" => String::from_utf8_lossy(data).chars().rev().collect(),
        _ => return None,
    };
    Some(out)
}

fn decode_native(text: &str, scheme: &str) -> Option<Result<Vec<u8>, String>> {
    let res = match scheme {
        "base64" => b64_decode(text, false),
        "base64url" => b64_decode(text, true),
        "hex" => hex_decode(text),
        "url" => Ok(url_decode(text)),
        "html" => Ok(html_decode(text).into_bytes()),
        "rot13" => Ok(rot13(text).into_bytes()),
        "upper" => Ok(text.to_lowercase().into_bytes()),
        "reverse" => Ok(text.chars().rev().collect::<String>().into_bytes()),
        _ => return None,
    };
    Some(res)
}

pub fn shannon(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let total = data.len() as f64;
    let mut val = 0.0f64;
    for &c in &counts {
        if c > 0 {
            let p = (c as f64) / total;
            val -= p * p.log2();
        }
    }
    if val == 0.0 { 0.0 } else { val }
}

fn round4(v: f64) -> f64 {
    (v * 10000.0).round() / 10000.0
}

fn verdict(v: f64) -> &'static str {
    if v >= 7.0 {
        "random_or_encrypted"
    } else if v >= 5.5 {
        "mixed"
    } else if v >= 3.5 {
        "structured"
    } else {
        "low"
    }
}

pub fn run(p: &Parsed) -> Option<i32> {
    let verb = p.verb.as_deref()?;
    match verb {
        "hash" => {
            if p.fbool("all") {
                return None;
            }
            let algo = p.fstr("algo").unwrap_or_else(|| "sha256".into());
            if !matches!(algo.as_str(), "sha256" | "sha512" | "crc32") {
                return None;
            }
            let data = match input_bytes(p) {
                Ok(d) => d,
                Err(e) => return Some(util::fail(p.json, &e, 1)),
            };
            let digest = match algo.as_str() {
                "sha256" => {
                    let mut h = Sha256::new();
                    h.update(&data);
                    hex_lower(&h.finalize())
                }
                "sha512" => {
                    let mut h = Sha512::new();
                    h.update(&data);
                    hex_lower(&h.finalize())
                }
                "crc32" => format!("{:08x}", crc32_ieee(&data)),
                _ => return None,
            };
            let payload = json!({
                "length": data.len(),
                "algorithm": algo,
                "digest": digest,
            });
            let human = format!("{digest}  ({}, {} bytes)", payload["algorithm"].as_str().unwrap_or(""), data.len());
            Some(util::out(p, &payload, Some(human)))
        }
        "encode" | "decode" | "roundtrip" => {
            let scheme = p.fstr("scheme").unwrap_or_else(|| "base64".into());
            // Native subset; `html` decoding arbitrary numeric entities or `base32`/`binary` falls back cleanly.
            if !matches!(scheme.as_str(), "base64" | "base64url" | "hex" | "url" | "rot13" | "upper" | "reverse") {
                return None;
            }
            let data = match input_bytes(p) {
                Ok(d) => d,
                Err(e) => return Some(util::fail(p.json, &e, 1)),
            };
            if verb == "encode" {
                let out = encode_native(&data, &scheme)?;
                let payload = json!({"scheme": scheme, "input_bytes": data.len(), "output": out});
                return Some(util::out(p, &payload, Some(out)));
            }
            if verb == "decode" {
                let text = String::from_utf8_lossy(&data).to_string();
                let decoded = match decode_native(&text, &scheme)? {
                    Ok(b) => b,
                    Err(e) => {
                        return Some(util::out_with(
                            p,
                            &json!({"ok": false, "error": e}),
                            Some(format!("error: {e}")),
                            2,
                        ));
                    }
                };
                let printable = decoded.iter().all(|&b| (32..127).contains(&b) || matches!(b, 9 | 10 | 13));
                let out_str = if printable {
                    Some(String::from_utf8_lossy(&decoded).to_string())
                } else {
                    None
                };
                let hex_str = if printable { None } else { Some(hex_lower(&decoded)) };
                let human = out_str.clone().unwrap_or_else(|| hex_str.clone().unwrap_or_default());
                let payload = json!({
                    "scheme": scheme,
                    "input_bytes": data.len(),
                    "bytes": decoded.len(),
                    "output": out_str,
                    "hex": hex_str,
                });
                return Some(util::out(p, &payload, Some(human)));
            }
            // roundtrip
            let encoded = encode_native(&data, &scheme)?;
            let decoded = decode_native(&encoded, &scheme)?.unwrap_or_default();
            let ok = decoded == data;
            let payload = json!({"scheme": scheme, "ok": ok, "bytes": data.len()});
            let human = format!("{scheme}: {}", if ok { "round-trips" } else { "BROKEN" });
            Some(util::out_with(p, &payload, Some(human), if ok { 0 } else { 1 }))
        }
        "entropy" => {
            let data = match input_bytes(p) {
                Ok(d) => d,
                Err(e) => return Some(util::fail(p.json, &e, 1)),
            };
            let overall = round4(shannon(&data));
            let overall_v = verdict(overall);
            let block = p.fint("block", 0);
            let limit = p.fint("limit", 32).max(1) as usize;
            let mut payload = json!({
                "length": data.len(),
                "entropy": overall,
                "bits_per_byte": overall,
                "verdict": overall_v,
            });
            let mut human = format!(
                "length   {} bytes\nentropy  {} bits/byte\nverdict  {}",
                data.len(), overall, overall_v
            );
            if block > 0 {
                let size = block.max(4) as usize;
                let mut blocks = Vec::new();
                for (idx, chunk) in data.chunks(size).enumerate() {
                    let val = round4(shannon(chunk));
                    let bv = verdict(val);
                    let offset = idx * size;
                    blocks.push(json!({
                        "offset": offset,
                        "size": chunk.len(),
                        "entropy": val,
                        "verdict": bv,
                    }));
                    human.push_str(&format!("\n  @{offset:>8} {val:>6} {bv}"));
                    if blocks.len() >= limit {
                        break;
                    }
                }
                payload["block_size"] = json!(size);
                payload["truncated"] = json!(data.len() > size * blocks.len());
                payload["blocks"] = json!(blocks);
            }
            Some(util::out(p, &payload, Some(human)))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codec_hash_roundtrip_entropy() {
        let mut h = Sha256::new();
        h.update(b"hello");
        assert_eq!(
            hex_lower(&h.finalize()),
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
        assert_eq!(format!("{:08x}", crc32_ieee(b"hello")), "3610a686");
        for scheme in ["base64", "base64url", "hex", "url", "rot13", "reverse"] {
            let enc = encode_native(b"xt-forge test!/+?", scheme).unwrap();
            let dec = decode_native(&enc, scheme).unwrap().unwrap();
            assert_eq!(dec, b"xt-forge test!/+?", "roundtrip failed for {scheme}");
        }
        assert_eq!(round4(shannon(b"aaaa")), 0.0);
        assert_eq!(verdict(0.0), "low");
    }
}
