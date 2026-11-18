//! xtforge-native — P1 native core (flash, route, compress) with exec-fallback
//! to the Python CLI for every noun it does not own yet.

mod args;
mod calibrate;
mod code_graph;
mod codec;
mod compress;
mod flash;
mod guard;
mod mem;
mod paths;
mod pyjson;
mod re_fast;
mod route;
mod scan_fast;
mod util;

use serde_json::json;

fn version_cmd(p: &args::Parsed) -> i32 {
    let (name, _v, codename, full) = paths::version_info();
    let xt_home = paths::xt_home().to_string_lossy().to_string();
    let obj = json!({
        "name": name, "version": full, "codename": codename, "xt_home": xt_home
    });
    util::out(p, &obj, Some(format!("{name} {full} (XT_HOME={xt_home})")))
}

fn resolve_python() -> String {
    if let Ok(py) = std::env::var("XT_PYTHON") {
        if !py.is_empty() {
            return py;
        }
    }
    #[cfg(windows)]
    {
        return "python".to_string();
    }
    #[cfg(not(windows))]
    {
        for candidate in &[
            "/opt/homebrew/bin/python3",
            "/usr/local/bin/python3",
            "/usr/bin/python3",
            "/data/data/com.termux/files/usr/bin/python3",
        ] {
            if std::path::Path::new(candidate).exists() {
                return candidate.to_string();
            }
        }
        "python3".to_string()
    }
}

fn exec_or_wait(mut cmd: std::process::Command) -> i32 {
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        let err = cmd.exec();
        eprintln!("error: cannot exec child: {err}");
        127
    }
    #[cfg(not(unix))]
    {
        match cmd.status() {
            Ok(s) => s.code().unwrap_or(1),
            Err(err) => {
                eprintln!("error: cannot spawn child: {err}");
                127
            }
        }
    }
}

fn python_fallback(argv: &[String]) -> i32 {
    let root = paths::repo_root();
    let python = resolve_python();
    let mut cmd = std::process::Command::new(python);
    cmd.arg("-m").arg("xtforge.cli").args(argv);
    cmd.current_dir(&root);
    let mut pp = root.to_string_lossy().to_string();
    let sep = if cfg!(windows) { ';' } else { ':' };
    if let Ok(existing) = std::env::var("PYTHONPATH") {
        if !existing.is_empty() {
            pp.push(sep);
            pp.push_str(&existing);
        }
    }
    cmd.env("PYTHONPATH", pp);
    if std::env::var_os("XT_HOME").is_none() {
        cmd.env("XT_HOME", paths::home().join(".xt-forge"));
    }
    exec_or_wait(cmd)
}

fn resolve_hub() -> Option<std::path::PathBuf> {
    if std::env::var("XT_NATIVE_HUB").ok().as_deref() == Some("0") {
        return None;
    }
    let hub_name = if cfg!(windows) { "xtforge-hub.exe" } else { "xtforge-hub" };
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let beside = dir.join(hub_name);
            if beside.is_file() {
                return Some(beside);
            }
        }
    }
    let root = paths::repo_root();
    let built = root.join("native").join("xtforge-go").join(hub_name);
    if built.is_file() {
        return Some(built);
    }
    None
}

fn hub_fallback(argv: &[String]) -> ! {
    if let Some(hub) = resolve_hub() {
        let mut cmd = std::process::Command::new(hub);
        cmd.args(argv);
        if std::env::var_os("XT_HOME").is_none() {
            cmd.env("XT_HOME", paths::home().join(".xt-forge"));
        }
        let code = exec_or_wait(cmd);
        std::process::exit(code);
    }
    std::process::exit(python_fallback(argv));
}

fn wants_hub(p: &args::Parsed) -> bool {
    let noun = p.noun.as_deref().unwrap_or("");
    let verb = p.verb.as_deref().unwrap_or("");
    match (noun, verb) {
        ("mcp", "audit" | "proxy" | "trust" | "connect" | "journal") => true,
        ("mcp", "serve") => p.fbool("meta"),
        ("code", "lsp") => true,
        ("re", "asar" | "netcap" | "apk" | "decompile" | "trace" | "checksec" | "capa") => true,
        ("intel", "sources" | "ip" | "cve" | "kev" | "search" | "hash" | "domain") => true,
        ("research", _) => true,
        ("loop", "schedule" | "list" | "stop" | "status") => true,
        ("guard", "mode") => true,
        _ => false,
    }
}

fn run() -> i32 {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let p = args::parse(&argv);
    if p.noun.is_none() && p.fbool("meta") {
        let mut hub_argv = vec!["mcp".to_string(), "serve".to_string()];
        hub_argv.extend(argv.clone());
        hub_fallback(&hub_argv);
    }
    if wants_hub(&p) && resolve_hub().is_some() {
        hub_fallback(&argv);
    }
    match p.noun.as_deref() {
        Some("flash") => {
            if let Some(code) = flash::run(&p) {
                return code;
            }
        }
        Some("route") => {
            if let Some(code) = route::run(&p) {
                return code;
            }
        }
        Some("compress") => {
            if let Some(code) = compress::run(&p) {
                return code;
            }
        }
        Some("mem") => {
            if let Some(code) = mem::run(&p) {
                return code;
            }
        }
        Some("code") => {
            if let Some(code) = code_graph::run(&p) {
                return code;
            }
        }
        Some("re") => {
            if let Some(code) = re_fast::run(&p) {
                return code;
            }
        }
        Some("scan") => {
            if let Some(code) = scan_fast::run(&p) {
                return code;
            }
        }
        Some("codec") => {
            if let Some(code) = codec::run(&p) {
                return code;
            }
        }
        Some("calibrate") => {
            if let Some(code) = calibrate::run(&p) {
                return code;
            }
        }
        Some("version") => return version_cmd(&p),
        _ => {}
    }
    python_fallback(&argv)
}

fn main() {
    // Die silently on broken pipes (like every POSIX CLI) instead of panicking
    // when output is piped into `head` or similar.
    #[cfg(unix)]
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }
    std::process::exit(run());
}
