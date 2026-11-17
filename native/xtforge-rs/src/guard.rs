//! Safety guard (mirrors xtforge/core/route/guard.py read paths).

use std::path::{Path, PathBuf};

use crate::paths;

pub struct Denied {
    pub code: &'static str,
    pub reason: String,
}

pub const DENY_GLOBS: &[&str] = &[
    "*/.ssh/*", "*/.gnupg/*", "*.key", "*.pem", "*.pfx", "*.p12",
    "*/.env", "*/.env.*", "*/.aws/credentials", "*/.netrc", "*.keystore",
    "*/id_rsa*", "*/shadow", "*/.git-credentials",
];

const DEFAULT_ROOTS: &[&str] = &[
    "$HOME", "$HOME/storage/shared", "$HOME/xt-forge",
    "/tmp", "/var/tmp",
    "/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/lib", "/usr/lib64",
    "/lib", "/lib64", "/opt",
    "${PREFIX}/bin", "${PREFIX}/sbin", "${PREFIX}/lib", "${PREFIX}/share",
];

pub fn expand_vars(p: &str) -> String {
    let chars: Vec<char> = p.chars().collect();
    let mut out = String::new();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c == '~' && i == 0 {
            out.push_str(&paths::home().to_string_lossy());
            i += 1;
            continue;
        }
        if c == '$' {
            if i + 1 < chars.len() && chars[i + 1] == '{' {
                if let Some(end) = chars[i + 2..].iter().position(|&x| x == '}') {
                    let name: String = chars[i + 2..i + 2 + end].iter().collect();
                    match std::env::var(&name) {
                        Ok(v) => out.push_str(&v),
                        Err(_) => {
                            out.push_str(&format!("${{{}}}", name));
                        }
                    }
                    i = i + 2 + end + 1;
                    continue;
                }
            } else {
                let mut j = i + 1;
                while j < chars.len() && (chars[j].is_alphanumeric() || chars[j] == '_') {
                    j += 1;
                }
                if j > i + 1 {
                    let name: String = chars[i + 1..j].iter().collect();
                    match std::env::var(&name) {
                        Ok(v) => out.push_str(&v),
                        Err(_) => out.push_str(&format!("${}", name)),
                    }
                    i = j;
                    continue;
                }
            }
        }
        out.push(c);
        i += 1;
    }
    out
}

pub fn roots() -> Vec<PathBuf> {
    let raw: Vec<String> = match std::env::var("XT_ROOTS") {
        Ok(env) if !env.is_empty() => env.split(',').map(|s| s.to_string()).collect(),
        _ => DEFAULT_ROOTS.iter().map(|s| s.to_string()).collect(),
    };
    let mut out: Vec<PathBuf> = raw.iter()
        .filter(|r| !r.trim().is_empty())
        .map(|r| PathBuf::from(expand_vars(r.trim())))
        .filter(|p| {
            let s = p.to_string_lossy();
            !s.contains('$') && s != "/" && s != "" && s != "."
        })
        .collect();
    let h = paths::home();
    let mut cur = h.as_path();
    while let Some(parent) = cur.parent() {
        if cur.file_name().map_or(false, |n| n == ".dsh") {
            if !out.contains(&parent.to_path_buf()) {
                out.insert(0, parent.to_path_buf());
            }
            break;
        }
        cur = parent;
    }
    let repo = paths::repo_root();
    if !out.contains(&repo) {
        out.push(repo);
    }
    out
}

/// Resolve symlinks and `..` as far as the path exists (os.path.realpath).
pub fn canonical(p: &str) -> PathBuf {
    let expanded = PathBuf::from(expand_vars(p));
    if let Ok(c) = std::fs::canonicalize(&expanded) {
        return c;
    }
    let mut rest: Vec<std::ffi::OsString> = Vec::new();
    let mut cur = expanded.clone();
    loop {
        if let Ok(c) = std::fs::canonicalize(&cur) {
            let mut out = c;
            for r in rest.iter().rev() {
                out.push(r);
            }
            return out;
        }
        match cur.file_name() {
            Some(n) => {
                rest.push(n.to_os_string());
                if !cur.pop() {
                    return expanded;
                }
            }
            None => return expanded,
        }
    }
}

/// fnmatch(3)-style glob matching (no pathname semantics).
pub fn fnmatch(pattern: &str, name: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let n: Vec<char> = name.chars().collect();
    let (mut pi, mut ni) = (0usize, 0usize);
    let mut star: Option<(usize, usize)> = None;
    while ni < n.len() {
        if pi < p.len() {
            match p[pi] {
                '*' => {
                    star = Some((pi + 1, ni));
                    pi += 1;
                    continue;
                }
                '?' => {
                    pi += 1;
                    ni += 1;
                    continue;
                }
                '[' => {
                    if let Some((matched, next)) = match_class(&p, pi, n[ni]) {
                        if matched {
                            pi = next;
                            ni += 1;
                            continue;
                        }
                    } else if n[ni] == '[' {
                        pi += 1;
                        ni += 1;
                        continue;
                    }
                }
                c => {
                    if c == n[ni] {
                        pi += 1;
                        ni += 1;
                        continue;
                    }
                }
            }
        }
        match star {
            Some((sp, sn)) => {
                pi = sp;
                ni = sn + 1;
                star = Some((sp, sn + 1));
            }
            None => return false,
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

/// Match a `[...]` class starting at p[start] against ch.
/// Returns Some((matched, index_after_class)) or None when unterminated.
fn match_class(p: &[char], start: usize, ch: char) -> Option<(bool, usize)> {
    let mut i = start + 1;
    if i >= p.len() {
        return None;
    }
    let negate = p[i] == '!';
    if negate {
        i += 1;
    }
    let mut matched = false;
    let mut first = true;
    while i < p.len() {
        if p[i] == ']' && !first {
            return Some((matched != negate, i + 1));
        }
        first = false;
        if i + 2 < p.len() && p[i + 1] == '-' && p[i + 2] != ']' {
            if p[i] <= ch && ch <= p[i + 2] {
                matched = true;
            }
            i += 3;
        } else {
            if p[i] == ch {
                matched = true;
            }
            i += 1;
        }
    }
    None
}

pub fn is_denied_name(path: &str) -> Option<&'static str> {
    let base = Path::new(path)
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_default();
    for g in DENY_GLOBS {
        if fnmatch(g, path) || fnmatch(g, &base) {
            return Some(g);
        }
    }
    None
}

pub fn read_guard(path: &str) -> Result<PathBuf, Denied> {
    let canon = canonical(path);
    let mut allowed = false;
    for root in roots() {
        if canon.starts_with(&root) {
            allowed = true;
            break;
        }
    }
    if !allowed {
        return Err(Denied {
            code: "root_denied",
            reason: format!("path outside allowlisted roots: {}", canon.display()),
        });
    }
    if let Some(g) = is_denied_name(&canon.to_string_lossy()) {
        return Err(Denied {
            code: "deny_listed",
            reason: format!("deny-listed path ({g}): contents never exposed"),
        });
    }
    Ok(canon)
}
