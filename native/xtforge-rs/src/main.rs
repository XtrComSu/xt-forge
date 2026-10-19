//! xtforge-native — P1 native core (flash, route, compress) with exec-fallback
//! to the Python CLI for every noun it does not own yet.

mod args;
mod calibrate;
mod compress;
mod flash;
mod guard;
mod mem;
mod paths;
mod pyjson;
mod route;
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

fn python_fallback(argv: &[String]) -> i32 {
    use std::os::unix::process::CommandExt;

    let root = paths::repo_root();
    let python = std::env::var("XT_PYTHON")
        .unwrap_or_else(|_| "/data/data/com.termux/files/usr/bin/python3".to_string());
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

fn run() -> i32 {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let p = args::parse(&argv);
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
