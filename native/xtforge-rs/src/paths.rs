//! Filesystem layout + version resolution (mirrors xtforge/version.py).

use std::path::PathBuf;

pub fn home() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/"))
}

pub fn repo_root() -> PathBuf {
    if let Ok(r) = std::env::var("XT_ROOT") {
        return PathBuf::from(r);
    }
    if let Ok(exe) = std::env::current_exe() {
        let mut p = exe.clone();
        for _ in 0..6 {
            if p.join("VERSION").exists() {
                return p;
            }
            match p.parent() {
                Some(x) => p = x.to_path_buf(),
                None => break,
            }
        }
    }
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    if cwd.join("VERSION").exists() {
        return cwd;
    }
    cwd
}

pub fn xt_home() -> PathBuf {
    let base = std::env::var("XT_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| home().join(".xt-forge"));
    let _ = std::fs::create_dir_all(&base);
    base
}

pub fn flash_dir() -> PathBuf {
    let d = xt_home().join("flash");
    let _ = std::fs::create_dir_all(&d);
    d
}

pub fn cache_dir() -> PathBuf {
    let d = xt_home().join("cache");
    let _ = std::fs::create_dir_all(&d);
    d
}

/// (name, version, codename, "version-codename") from the repo VERSION file.
pub fn version_info() -> (String, String, String, String) {
    let mut name = "xt-forge".to_string();
    let mut version = "0.0.0".to_string();
    let mut codename = "unknown".to_string();
    if let Ok(text) = std::fs::read_to_string(repo_root().join("VERSION")) {
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some((k, v)) = line.split_once('=') {
                match k.trim() {
                    "name" => name = v.trim().to_string(),
                    "version" => version = v.trim().to_string(),
                    "codename" => codename = v.trim().to_string(),
                    _ => {}
                }
            }
        }
    }
    let full = format!("{}-{}", version, codename);
    (name, version, codename, full)
}
