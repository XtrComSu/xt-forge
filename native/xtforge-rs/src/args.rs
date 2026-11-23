//! CLI argument parsing mirroring the argparse surface of xtforge/cli.

use std::collections::HashMap;

pub struct Parsed {
    pub noun: Option<String>,
    pub verb: Option<String>,
    pub positionals: Vec<String>,
    pub flags: HashMap<String, Vec<String>>,
    pub json: bool,
    pub has_help: bool,
}

const VALUE_FLAGS: &[&str] = &[
    "db", "flash-base", "scope", "n", "tag", "ttl", "confirm", "text-file",
    "paths", "token-budget", "file-limit", "lines-per-file", "max-lines",
    "query", "pattern", "glob", "regex", "type", "min-size", "limit", "depth",
    "max", "context", "mode", "start", "count", "top", "minutes", "path",
    "text", "out", "run-id", "rounds", "criteria", "verify", "budget-tokens",
    "title", "body", "body-file", "kind", "source", "confidence", "session",
    "workflow", "project", "k", "budget", "conflicts", "style", "by", "on",
    "level", "from", "to", "var", "workdir", "phase", "id", "objective",
    "rva", "name", "orig", "comment", "type-decl", "format", "error-sig",
    "sig", "outcome", "binary", "reason", "threshold", "min-len", "engine",
    "server", "cmd", "prefix", "graph-db", "preset", "line", "col", "target",
    "max-bytes", "symbol", "block", "algo", "scheme", "window", "max-matches",
    "expected-file", "expected-line", "member", "arch", "bytes", "max-instructions", "max-functions",
];

const BOOL_FLAGS: &[&str] = &[
    "json", "all", "pin-only", "stats", "legend", "dry-run", "check", "force",
    "status", "explain", "diagnose", "pin", "symbols", "reveal", "xor", "web",
    "trust-on-first", "meta", "rank", "flow",
];

pub fn parse(argv: &[String]) -> Parsed {
    let mut flags: HashMap<String, Vec<String>> = HashMap::new();
    let mut positionals_raw: Vec<String> = Vec::new();
    let mut has_help = false;
    let mut i = 0;
    while i < argv.len() {
        let a = &argv[i];
        if a == "--" {
            positionals_raw.extend(argv[i + 1..].iter().cloned());
            break;
        }
        if a == "--help" || a == "-h" {
            has_help = true;
        }
        if let Some(rest) = a.strip_prefix("--") {
            let (name, inline) = match rest.split_once('=') {
                Some((n, v)) => (n.to_string(), Some(v.to_string())),
                None => (rest.to_string(), None),
            };
            if let Some(v) = inline {
                flags.entry(name).or_default().push(v);
            } else if BOOL_FLAGS.contains(&name.as_str()) {
                flags.entry(name).or_default().push("true".into());
            } else if VALUE_FLAGS.contains(&name.as_str()) && i + 1 < argv.len() {
                i += 1;
                flags.entry(name).or_default().push(argv[i].clone());
            } else {
                flags.entry(name).or_default().push("true".into());
            }
        } else if a == "-n" || a == "-d" {
            let name = if a == "-n" { "n" } else { "depth" };
            if i + 1 < argv.len() {
                i += 1;
                flags.entry(name.into()).or_default().push(argv[i].clone());
            }
        } else {
            positionals_raw.push(a.clone());
        }
        i += 1;
    }
    let json = flags.contains_key("json");
    let mut it = positionals_raw.into_iter();
    let noun = it.next();
    let verb = it.next();
    Parsed {
        noun,
        verb,
        positionals: it.collect(),
        flags,
        json,
        has_help,
    }
}

impl Parsed {
    pub fn fstr(&self, name: &str) -> Option<String> {
        self.flags.get(name).and_then(|v| v.last()).cloned()
    }
    pub fn fbool(&self, name: &str) -> bool {
        self.flags.contains_key(name)
    }
    pub fn fint(&self, name: &str, default: i64) -> i64 {
        self.fstr(name)
            .and_then(|s| s.parse::<i64>().ok())
            .unwrap_or(default)
    }
    pub fn flist(&self, name: &str) -> Vec<String> {
        self.flags.get(name).cloned().unwrap_or_default()
    }
    pub fn pos(&self, i: usize) -> Option<&str> {
        self.positionals.get(i).map(|s| s.as_str())
    }
}
