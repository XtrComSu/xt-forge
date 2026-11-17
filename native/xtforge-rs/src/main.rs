//! xtforge-native — P1 native core (flash, route, compress) with exec-fallback
//! to the Python CLI for every noun it does not own yet.

mod args;
mod calibrate;
mod code_graph;
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
    for candidate in &[
        "/usr/bin/python3",
        "/data/data/com.termux/files/usr/bin/python3",
    ] {
        if std::path::Path::new(candidate).exists() {
            return candidate.to_string();
        }
    }
    "python3".to_string()
}

fn python_fallback(argv: &[String]) -> i32 {
    use std::os::unix::process::CommandExt;

    let root = paths::repo_root();
    let python = resolve_python();
    let mut cmd = std::process::Command::new(python);
    cmd.arg("-m").arg("xtforge.cli").args(argv);
    cmd.current_dir(&root);
    let mut pp = root.to_string_lossy().to_string();
    if let Ok(existing) = std::env::var("PYTHONPATH") {
        if !existing.is_empty() {
            pp.push(':');
            pp.push_str(&existing);
        }
    }
    cmd.env("PYTHONPATH", pp);
    if std::env::var_os("XT_HOME").is_none() {
        cmd.env("XT_HOME", paths::home().join(".xt-forge"));
    }
    let err = cmd.exec();
    eprintln!("error: cannot exec python: {err}");
    127
}

fn resolve_hub() -> Option<std::path::PathBuf> {
    if std::env::var("XT_NATIVE_HUB").ok().as_deref() == Some("0") {
        return None;
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let beside = dir.join("xtforge-hub");
            if beside.is_file() {
                return Some(beside);
            }
        }
    }
    let root = paths::repo_root();
    let built = root.join("native/xtforge-go/xtforge-hub");
    if built.is_file() {
        return Some(built);
    }
    None
}

fn hub_fallback(argv: &[String]) -> ! {
    use std::os::unix::process::CommandExt;
    if let Some(hub) = resolve_hub() {
        let mut cmd = std::process::Command::new(hub);
        cmd.args(argv);
        if std::env::var_os("XT_HOME").is_none() {
            cmd.env("XT_HOME", paths::home().join(".xt-forge"));
        }
        let _ = cmd.exec();
    }
    std::process::exit(python_fallback(argv));
}

fn wants_hub(p: &args::Parsed) -> bool {
    let noun = p.noun.as_deref().unwrap_or("");
    let verb = p.verb.as_deref().unwrap_or("");
    match (noun, verb) {
        ("mcp", "audit" | "proxy" | "trust") => true,
        ("mcp", "serve") => p.fbool("meta"),
        ("code", "lsp") => true,
        ("re", "asar" | "netcap" | "apk" | "decompile" | "trace") => true,
        ("research", _) => true,
        ("loop", "schedule" | "list" | "stop" | "status") => true,
        ("guard", "mode") => true,
        _ => false,
    }
}

fn run() -> i32 {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let p = args::parse(&argv);
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
    // Die silently on broken pipes (like every C CLI) instead of panicking
    // when output is piped into `head` or similar.
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }
    std::process::exit(run());
}
