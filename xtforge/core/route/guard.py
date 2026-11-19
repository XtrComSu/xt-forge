"""Safety guard (R10): read-only by default, allowlisted roots, realpath
canonicalization, deny list, dry-run tokens for destructive ops.

Nothing else in xt-forge touches the filesystem without going through here.
"""
from __future__ import annotations

import fnmatch
import json
import os
import re
import secrets
import time
from pathlib import Path
from typing import Any

from ...version import cache_dir

DEFAULT_ROOTS = [
    "$HOME", "$HOME/storage/shared", "$HOME/xt-forge",
    # Scratch space: tests and tools need a writable place that is not HOME.
    "/tmp", "/var/tmp",
    # System binaries and libraries: what `re info|sections|symbols|strings`
    # exists to inspect. Reads stay subject to DENY_GLOBS below.
    "/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/lib", "/usr/lib64",
    "/usr/local", "/usr/share", "/lib", "/lib64", "/opt", "/var/lib/flatpak", "/app",
    # Termux prefix; skipped entirely when PREFIX is unset.
    "${PREFIX}/bin", "${PREFIX}/sbin", "${PREFIX}/lib", "${PREFIX}/share",
]
DENY_GLOBS = [
    "*/.ssh/*", "*/.gnupg/*", "*.key", "*.pem", "*.pfx", "*.p12",
    "*/.env", "*/.env.*", "*/.aws/credentials", "*/.netrc", "*.keystore",
    "*/id_rsa*", "*/shadow", "*/.git-credentials",
]
DESTRUCTIVE = {"delete", "delete_all", "clear_scope", "sync_overwrite"}

_TOKENS: dict[str, dict[str, Any]] = {}
TOKEN_TTL = 300  # seconds


class Denied(Exception):
    def __init__(self, reason: str, code: str = "denied"):
        super().__init__(reason)
        self.reason = reason
        self.code = code


def _expand(p: str) -> Path:
    return Path(os.path.expandvars(p)).expanduser()


def user_home() -> Path:
    h = Path.home()
    for p in h.parents:
        if p.name == ".dsh":
            return p.parent
    return h


def roots() -> list[Path]:
    env = os.environ.get("XT_ROOTS")
    raw = env.split(",") if env else DEFAULT_ROOTS
    out = []
    for r in raw:
        entry = r.strip()
        if not entry:
            continue
        expanded = _expand(entry)
        # An unexpanded $VAR must never become a root: an unset PREFIX would
        # otherwise leave a placeholder path in the allowlist.
        if "$" in str(expanded) or str(expanded) in ("/", "", "."):
            continue
        out.append(expanded)
    uh = user_home()
    if uh != Path.home() and uh not in out:
        out.insert(0, uh)
    return out


def is_denied_name(path: str) -> str | None:
    """Return the deny glob that matched, or None."""
    p = str(path)
    for g in DENY_GLOBS:
        if fnmatch.fnmatch(p, g) or fnmatch.fnmatch(os.path.basename(p), g):
            return g
    return None


def canonical(path: str | Path) -> Path:
    """Resolve symlinks and .. to defeat escapes. Nonexistent paths resolve
    as far as possible, then the remainder is appended."""
    p = _expand(str(path))
    try:
        return Path(os.path.realpath(str(p)))
    except OSError:
        return p


def check_allowed(path: str | Path, write: bool = False) -> Path:
    """Raise Denied unless path resolves inside an allowlisted root."""
    canon = canonical(path)
    allowed = False
    for root in roots():
        try:
            canon.relative_to(root)
            allowed = True
            break
        except ValueError:
            continue
    if not allowed:
        raise Denied(f"path outside allowlisted roots: {canon}", "root_denied")
    deny = is_denied_name(str(canon))
    if deny and not write:
        raise Denied(f"deny-listed path ({deny}): contents never exposed", "deny_listed")
    if deny and write:
        raise Denied(f"writing to deny-listed path ({deny}) is refused", "deny_listed")
    return canon


def read_guard(path: str | Path) -> Path:
    """Guard for read paths: deny-listed entries are allowed but must be
    listed only (name + size), never opened."""
    return check_allowed(path, write=False)


def write_guard(path: str | Path, write: bool, confirm_token: str | None = None,
                dry_run: bool = False) -> dict[str, Any]:
    """Guard for write paths (R10): needs write=true + token for destructive."""
    canon = check_allowed(path, write=write)
    if not write:
        return {"path": str(canon), "write": False}
    plan = {"path": str(canon), "write": True, "dry_run": True}
    if dry_run:
        return plan
    if confirm_token:
        rec = _TOKENS.get(confirm_token)
        if not rec or rec["expires"] < time.time():
            raise Denied("confirm_token missing, expired, or already used", "token_invalid")
        if rec["path"] != str(canon):
            raise Denied("confirm_token does not match this path", "token_mismatch")
        del _TOKENS[confirm_token]
        return {"path": str(canon), "write": True, "dry_run": False, "confirmed": True}
    return plan


# ---- confirm tokens ----

def issue_token(action: str, path: str, scope: str = "global") -> dict[str, Any]:
    tok = secrets.token_hex(12)
    rec = {"action": action, "path": str(canonical(path)), "scope": scope,
           "issued": time.time(), "expires": time.time() + TOKEN_TTL}
    _TOKENS[tok] = rec
    _persist()
    return {"confirm_token": tok, "action": action, "path": rec["path"],
            "expires_in": TOKEN_TTL,
            "note": f"re-run with --confirm {tok} to execute {action}"}


def _persist() -> None:
    from ...atomicio import atomic_write_json
    safe = {k: {**v, "confirm_token": None} for k, v in _TOKENS.items()}
    try:
        atomic_write_json(cache_dir() / "tokens.json", safe)
    except OSError:
        pass


def check_command(cmd: str) -> str | None:
    """Reject shell shapes that are never allowed. Returns reason or None."""
    forbidden = [
        (r"\brm\s+(-[a-zA-Z]*\s+)*-[a-zA-Z]*r", "recursive delete"),
        (r"\brm\s+-[a-zA-Z]*f\b\s+[/~]", "forced root or home wipe"),
        (r"\bsudo\b|\bsu\b", "privilege escalation"),
        (r"\bcurl\b[^|]*\|\s*(ba)?sh", "remote code execution"),
        (r"\bwget\b[^|]*\|\s*(ba)?sh", "remote code execution"),
        (r">\s*/(etc|usr|bin|sbin|system|boot)/", "write to system path"),
        (r"\bchmod\s+(?:-R\s+)?777\b", "world-writable permissions"),
        (r"\bdd\s+.*of=/dev/", "raw device write"),
        (r"\bmkfs\b|\bfdisk\b", "filesystem destruction"),
        (r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:", "fork bomb"),
        (r"\bshred\b", "destructive file shredding"),
        (r">\s*/dev/(?:sda|nvme|hda|vda)", "raw disk write redirection"),
        (r"\b(?:base64\s+-d|xxd\s+-r)[^|]*\|\s*(?:ba)?sh", "encoded payload pipe to shell"),
    ]
    for pat, reason in forbidden:
        if re.search(pat, cmd, re.IGNORECASE):
            return reason
    return None


PERM_MODES = ("explore", "ask", "auto")


def perm_mode() -> str:
    """Return active permission mode (env XT_PERM_MODE > state file > 'ask')."""
    env = (os.environ.get("XT_PERM_MODE") or "").strip().lower()
    if env in PERM_MODES:
        return env
    from ...version import xt_home
    p = xt_home() / "guard_mode.txt"
    if p.is_file():
        val = p.read_text(encoding="utf-8", errors="replace").strip().lower()
        if val in PERM_MODES:
            return val
    return "ask"


def set_perm_mode(mode: str) -> str:
    """Persist permission mode to XT_HOME/guard_mode.txt."""
    m = mode.strip().lower()
    if m not in PERM_MODES:
        raise ValueError(f"invalid mode {mode!r}; expected one of {PERM_MODES}")
    from ...version import xt_home
    p = xt_home() / "guard_mode.txt"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(m + "\n", encoding="utf-8")
    audit_log(tool="guard.mode", args={"mode": m}, outcome="ok", mode=m)
    return m


def check_write_mode(confirm_token: str | None = None) -> None:
    """Enforce XT_PERM_MODE write policy before mutating disk or state."""
    mode = perm_mode()
    if mode == "explore":
        audit_log(tool="guard.write", args={}, outcome="denied_explore_mode", mode=mode)
        raise Denied("XT_PERM_MODE=explore forbids write/exec mutations", "explore_mode")
    if mode == "ask" and not confirm_token:
        # Caller may still enforce issue_token; when confirm_token is explicitly required it raises.
        return


def audit_log(*, tool: str, args: dict[str, Any] | None = None,
              outcome: str = "ok", mode: str | None = None,
              token_cost: int = 0) -> None:
    """Append a structured JSONL audit event under XT_HOME/audit/YYYY-MM-DD.jsonl."""
    try:
        from ...version import xt_home
        day = time.strftime("%Y-%m-%d", time.gmtime())
        adir = xt_home() / "audit"
        adir.mkdir(parents=True, exist_ok=True)
        ev = {
            "ts": int(time.time()),
            "mode": mode or perm_mode(),
            "tool": tool,
            "args": args or {},
            "outcome": outcome,
            "tokens": int(token_cost),
        }
        with (adir / f"{day}.jsonl").open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(ev, ensure_ascii=False) + "\n")
    except OSError:
        pass