"""Native reverse-engineering analysis: IOCs, disassembly, call graphs.

This is the alternative to bolting a 200-tool RE server onto the model. The
binutils already on the box (objdump, nm, readelf, strings) do the heavy
lifting; this module turns their output into structured, queryable results
behind three verbs instead of two hundred schemas.

    xtforge re ioc <binary>          indicators: IPs, domains, URLs, hashes
    xtforge re disasm <binary>       disassembly, by symbol or address range
    xtforge re graph <binary>        imports, exports, call sites

Everything degrades: no binutils means an honest "unavailable" with the
install hint, never a crash. All analysis is read-only.
"""
from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

from ..route import guard

MAX_OUTPUT = 2_000_000
TIMEOUT = 60
STRING_MIN = 5

# ------------------------------------------------------------------ indicators

IPV4 = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}"
                  r"(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
DOMAIN = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+"
                    r"(?:com|net|org|io|dev|ai|co|ru|cn|xyz|top|info|biz|edu|gov|mil)"
                    r"\b", re.IGNORECASE)
URL = re.compile(r"\b(?:https?|ftp)://[^\s\"'<>]{6,}", re.IGNORECASE)
CRED_URL = re.compile(
    r"\b[a-z][a-z0-9+.\-]*://([^\s:/@]{1,64}):([^\s:/@]{1,64})@"
    r"([^\s\"'<>]{4,})", re.IGNORECASE)
EMAIL = re.compile(r"\b[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}\b", re.IGNORECASE)
HEX_HASH = re.compile(r"\b(?:[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64})\b",
                      re.IGNORECASE)
CVE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
WIN_PATH = re.compile(r"\b[A-Za-z]:\\(?:[^\\/:*?\"<>|\r\n]+\\)*"
                      r"[^\\/:*?\"<>|\r\n]{2,}", re.IGNORECASE)
LINUX_PATH = re.compile(r"(?:^|[\s\"'<>])(/(?:usr|etc|var|opt|home|tmp|bin|sbin|lib|proc|sys)"
                        r"(?:/[^/\s\"'<>]{1,60}){1,8})\b", re.MULTILINE)
REG_KEY = re.compile(r"\bHKEY_[A-Z_]+(?:\\[^\\\s\"'<>]+){1,12}", re.IGNORECASE)
SKIP_DOMAINS = {"example.com", "example.org", "example.net", "localhost",
                "foo.com", "bar.com", "test.com", "w3.org", "apache.org",
                "gnu.org", "kernel.org", "github.com", "microsoft.com"}


def _strings(data: bytes, minimum: int = STRING_MIN) -> list[str]:
    pattern = re.compile(rb"[\x20-\x7e]{%d,}" % max(1, minimum))
    return [m.group().decode("ascii") for m in pattern.finditer(data)]


def _run(cmd: list[str], timeout: int = TIMEOUT) -> tuple[str, bool]:
    """Run a tool. Returns (output, available)."""
    if not shutil.which(cmd[0]):
        return "", False
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=timeout, errors="replace")
    except (OSError, subprocess.SubprocessError):
        return "", False
    out = (proc.stdout or "") + (proc.stderr or "")
    return out[:MAX_OUTPUT], True


def ioc(path: str | Path) -> dict[str, Any]:
    """Extract indicators of compromise from a binary or text file."""
    try:
        canon = guard.read_guard(path)
    except guard.Denied as exc:
        return {"ok": False, "err": f"{exc.code}: {exc.reason}"}
    if not canon.is_file():
        return {"ok": False, "err": "not_a_file", "path": str(canon)}
    try:
        data = canon.read_bytes()
    except OSError as exc:
        return {"ok": False, "err": str(exc)}

    text = "\n".join(_strings(data, 4))
    findings: dict[str, list[str]] = {
        "urls": [], "ips": [], "domains": [], "emails": [], "hashes": [],
        "cves": [], "windows_paths": [], "linux_paths": [],
        "registry_keys": [], "credential_urls": [],
    }

    def add(kind: str, value: str, limit: int = 40) -> None:
        bucket = findings[kind]
        if value not in bucket and len(bucket) < limit:
            bucket.append(value)

    for match in URL.finditer(text):
        add("urls", match.group(0))
    # Credentials leak into db:// and custom schemes too. The password is
    # masked on the way out: an IOC report must not become a secret store.
    cred_spans: list[tuple[int, int]] = []
    for match in CRED_URL.finditer(text):
        user, _secret, host = match.groups()
        cred_spans.append(match.span())
        add("credential_urls", f"{user}:***@{host.split()[0][:60]}")

    def inside_credentials(pos: int) -> bool:
        return any(start <= pos < end for start, end in cred_spans)

    for match in IPV4.finditer(text):
        value = match.group(0)
        if not value.startswith(("0.", "255.255.", "127.")):
            add("ips", value)
    for match in DOMAIN.finditer(text):
        value = match.group(0).lower()
        if value not in SKIP_DOMAINS:
            add("domains", value)
    for match in EMAIL.finditer(text):
        if inside_credentials(match.start()):
            continue          # that "address" is the password half of a URL
        add("emails", match.group(0))
    for match in HEX_HASH.finditer(text):
        add("hashes", match.group(0).lower())
    for match in CVE.finditer(text):
        add("cves", match.group(0).upper())
    for match in WIN_PATH.finditer(text):
        add("windows_paths", match.group(0))
    for match in LINUX_PATH.finditer(text):
        add("linux_paths", match.group(1))
    for match in REG_KEY.finditer(text):
        add("registry_keys", match.group(0))

    counts = {kind: len(values) for kind, values in findings.items()}
    return {"ok": True, "path": str(canon), "bytes": len(data),
            "counts": counts, "total": sum(counts.values()),
            "findings": findings,
            "note": ("indicators are leads, not verdicts: confirm before "
                     "acting on any of them")}


# ----------------------------------------------------------------- disassembly

_FUNC_LINE = re.compile(
    r"^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2} )+)\s*([a-z][a-z0-9.]*)(?:\s+(.*))?$",
    re.IGNORECASE)


def disasm(path: str | Path, symbol: str | None = None,
           start: str | None = None, count: int = 60,
           section: str | None = None) -> dict[str, Any]:
    """Disassemble via objdump, parsed into structured instructions."""
    try:
        canon = guard.read_guard(path)
    except guard.Denied as exc:
        return {"ok": False, "err": f"{exc.code}: {exc.reason}"}
    tool = shutil.which("objdump")
    if not tool:
        return {"ok": False, "err": "objdump not available",
                "hint": "install binutils (pkg install binutils)"}

    cmd = [tool, "-d", "--no-show-raw-insn" if False else "-d", str(canon)]
    if symbol:
        cmd = [tool, "-d", f"--disassemble={symbol}", str(canon)]
    elif section:
        cmd = [tool, "-d", f"--section={section}", str(canon)]
    out, available = _run(cmd, timeout=TIMEOUT)
    if not available:
        return {"ok": False, "err": "objdump failed"}

    instructions: list[dict[str, Any]] = []
    current_fn = ""
    for line in out.splitlines():
        header = re.match(r"^[0-9a-f]+\s+<([^>]+)>:\s*$", line.strip())
        if header:
            current_fn = header.group(1)
            continue
        match = _FUNC_LINE.match(line)
        if not match:
            continue
        address, raw, mnemonic, operands = match.groups()
        if start and int(address, 16) < int(start, 16):
            continue
        instructions.append({
            "address": address, "function": current_fn,
            "mnemonic": (mnemonic or "").lower(),
            "operands": (operands or "").strip(),
            "bytes": " ".join(raw.split()),
        })
        if len(instructions) >= max(1, int(count)):
            break

    mnemonics: dict[str, int] = {}
    for item in instructions:
        mnemonics[item["mnemonic"]] = mnemonics.get(item["mnemonic"], 0) + 1
    return {"ok": True, "path": str(canon), "symbol": symbol or "",
            "instructions": instructions, "count": len(instructions),
            "mnemonic_histogram": dict(sorted(mnemonics.items(),
                                              key=lambda kv: -kv[1])[:12])}


# ----------------------------------------------------------------------- graph

_CALL = re.compile(r"\b(?:callq?|bl|jal)\s+([0-9a-fx]+)(?:\s+<([^>]+)>)?",
                   re.IGNORECASE)


def graph(path: str | Path, max_calls: int = 200) -> dict[str, Any]:
    """Imports, exports and call sites — the map you need before reading."""
    try:
        canon = guard.read_guard(path)
    except guard.Denied as exc:
        return {"ok": False, "err": f"{exc.code}: {exc.reason}"}

    imports: list[dict[str, str]] = []
    exports: list[dict[str, str]] = []
    out, available = _run(["nm", "-D", str(canon)])
    if available:
        for line in out.splitlines():
            parts = line.split()
            # Defined: "<addr> <kind> <name>". Undefined (imports): "<kind> <name>".
            if len(parts) >= 3:
                kind, name = parts[1], parts[-1]
            elif len(parts) == 2:
                kind, name = parts[0], parts[1]
            else:
                continue
            entry = {"symbol": name, "kind": kind}
            if kind == "U":
                imports.append(entry)
            elif kind in {"T", "W", "B", "D", "R", "V"}:
                exports.append(entry)

    calls: list[dict[str, str]] = []
    disassembly, ok = _run(["objdump", "-d", str(canon)])
    if ok:
        current = ""
        for line in disassembly.splitlines():
            header = re.match(r"^[0-9a-f]+\s+<([^>]+)>:\s*$", line.strip())
            if header:
                current = header.group(1)
                continue
            for match in _CALL.finditer(line):
                target = (match.group(2) or match.group(1) or "").strip("<>")
                calls.append({"from_function": current, "target": target})
                if len(calls) >= max_calls:
                    break
            if len(calls) >= max_calls:
                break

    targets: dict[str, int] = {}
    for call in calls:
        targets[call["target"]] = targets.get(call["target"], 0) + 1
    hot = sorted(targets.items(), key=lambda kv: -kv[1])[:15]

    return {"ok": True, "path": str(canon),
            "imports": imports[:200], "exports": exports[:200],
            "import_count": len(imports), "export_count": len(exports),
            "call_sites": calls, "call_count": len(calls),
            "hot_targets": [{"target": t, "calls": n} for t, n in hot],
            "binutils": bool(available or ok)}


# ------------------------------------------------------------ multi-format dispatcher

def sniff_format(target: str | Path | bytes) -> str:
    """Detect binary format ('elf', 'pe', or 'unknown') from bytes or file header."""
    if isinstance(target, (bytes, bytearray)):
        prefix = bytes(target[:4])
    else:
        try:
            canon = guard.read_guard(target)
            if not canon.is_file():
                return "unknown"
            with canon.open("rb") as f:
                prefix = f.read(4)
        except (guard.Denied, OSError):
            return "unknown"

    if prefix.startswith(b"\x7fELF"):
        return "elf"
    if prefix.startswith(b"MZ"):
        return "pe"
    return "unknown"


def get_info(path: str | Path) -> dict[str, Any]:
    """Extract format-appropriate header and execution metadata."""
    fmt = sniff_format(path)
    if fmt == "pe":
        from .pe import PEFile, PeError
        try:
            pe = PEFile(path)
            info = pe.info()
            return {"ok": True, "path": str(path), **info}
        except PeError as exc:
            return {"ok": False, "err": str(exc), "path": str(path)}
    elif fmt == "elf":
        from . import elf
        try:
            info = elf.info(path)
            return {"ok": True, **info}
        except Exception as exc:
            return {"ok": False, "err": str(exc), "path": str(path)}
    return {"ok": False, "err": f"unrecognized binary format for {path}"}


def get_sections(path: str | Path) -> dict[str, Any]:
    """Extract section table with entropy for ELF or PE."""
    fmt = sniff_format(path)
    if fmt == "pe":
        from .pe import PEFile, PeError
        try:
            pe = PEFile(path)
            return {"ok": True, "path": str(path), "sections": pe.sections()}
        except PeError as exc:
            return {"ok": False, "err": str(exc), "path": str(path)}
    elif fmt == "elf":
        from . import elf
        try:
            return elf.sections(path)
        except Exception as exc:
            return {"ok": False, "err": str(exc), "path": str(path)}
    return {"ok": False, "err": f"unrecognized binary format for {path}"}


def get_symbols(path: str | Path, limit: int = 200) -> dict[str, Any]:
    """Extract exported or visible symbols for ELF or PE."""
    fmt = sniff_format(path)
    if fmt == "pe":
        from .pe import PEFile, PeError
        try:
            pe = PEFile(path)
            exps = pe.exports()
            symbols = [
                {
                    "name": exp["name"],
                    "rva": exp["rva"],
                    "ordinal": exp["ordinal"],
                    "kind": "export",
                }
                for exp in exps[:limit]
            ]
            return {"ok": True, "path": str(path), "symbols": symbols, "count": len(symbols)}
        except PeError as exc:
            return {"ok": False, "err": str(exc), "path": str(path)}
    elif fmt == "elf":
        from . import elf
        try:
            return elf.symbols(path, limit=limit)
        except Exception as exc:
            return {"ok": False, "err": str(exc), "path": str(path)}
    return {"ok": False, "err": f"unrecognized binary format for {path}"}

