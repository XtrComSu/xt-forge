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
    # Not ELF or PE. `re info` is the most basic question about a file, and the native
    # engine already answers it for every format it reads — so answer from there instead
    # of failing with a format complaint.
    if (fallback := _info_from_hub(path)) is not None:
        return fallback
    return {"ok": False, "err": f"unrecognized binary format for {path}",
            "error": f"unrecognized binary format for {path}"}


def _info_from_hub(path: str | Path) -> dict[str, Any] | None:
    """Header-level metadata for formats without a dedicated Python reader."""
    from . import sources

    return sources.info_from_hub(path)


def _sections_from_hub(path: str | Path) -> dict[str, Any] | None:
    """Section table for formats without a dedicated Python reader.

    The decision of *which* layer answers lives in `sources.py`, so format coverage is
    defined in one place rather than once per verb.
    """
    from . import sources

    rows = sources.sections_from_hub(path)
    if not rows:
        return None
    return {"ok": True, "path": str(path), "sections": rows, "engine": "xtforge-hub"}


def get_sections(path: str | Path) -> dict[str, Any]:
    """Extract section table with entropy for ELF or PE, or any format the hub reads."""
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
    # Not ELF or PE: try the native engine before giving up.
    if (fallback := _sections_from_hub(path)) is not None:
        return fallback
    return {"ok": False, "err": f"unrecognized binary format for {path}",
            "error": f"unrecognized binary format for {path}"}


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


def checksec(path: str | Path) -> dict[str, Any]:
    """Inspect binary security mitigations (ASLR, DEP, CFG, RELRO, Canaries, etc.)."""
    fmt = sniff_format(path)
    if fmt == "pe":
        from .pe import PEFile, PeError
        try:
            pe = PEFile(path)
            return {"ok": True, "path": str(path), "format": "pe", "mitigations": pe.checksec()}
        except PeError as exc:
            return {"ok": False, "err": str(exc), "path": str(path)}
    elif fmt == "elf":
        from . import elf
        try:
            return {"ok": True, "path": str(path), "format": "elf", "mitigations": elf.checksec(path)}
        except Exception as exc:
            return {"ok": False, "err": str(exc), "path": str(path)}
    return {"ok": False, "err": f"unrecognized binary format for {path}"}


# ------------------------------------------------------------ advanced string recovery

_STACK_BYTE_ATT = re.compile(
    r"movb\s+\$0x([0-9a-fA-F]+),\s*(-?0x[0-9a-fA-F]+|-?\d+)\(%[re]?[sb]p\)"
)
_STACK_BYTE_INTEL = re.compile(
    r"mov\s+BYTE\s+PTR\s+\[%?[re]?[sb]p\s*([+-]\s*0x[0-9a-fA-F]+|[+-]\s*\d+)\],\s*0x([0-9a-fA-F]+)",
    re.IGNORECASE
)


def extract_stack_strings(disasm_text: str, min_len: int = 4) -> list[dict[str, Any]]:
    """Heuristically reconstruct strings constructed via byte stores on the stack."""
    results: list[dict[str, Any]] = []
    current_fn = ""
    current_bytes: bytearray = bytearray()
    last_offset = None

    def flush():
        nonlocal current_bytes
        if len(current_bytes) >= min_len:
            # Extract ASCII strings
            for m in re.finditer(rb"[\x20-\x7e]{%d,}" % min_len, current_bytes):
                text = m.group().decode("ascii", "replace")
                results.append({"function": current_fn, "string": text, "bytes": len(text)})
        current_bytes = bytearray()

    for line in disasm_text.splitlines():
        header = re.match(r"^[0-9a-fA-F]+\s+<([^>]+)>:\s*$", line.strip())
        if header:
            flush()
            current_fn = header.group(1).split("+")[0]
            last_offset = None
            continue

        byte_val = None
        stack_offset = None

        m_att = _STACK_BYTE_ATT.search(line)
        if m_att:
            b_hex, off_str = m_att.groups()
            byte_val = int(b_hex, 16)
            stack_offset = int(off_str, 16) if ("0x" in off_str or "0X" in off_str) else int(off_str)
        else:
            m_intel = _STACK_BYTE_INTEL.search(line)
            if m_intel:
                off_str, b_hex = m_intel.groups()
                off_str = off_str.replace(" ", "")
                byte_val = int(b_hex, 16)
                stack_offset = int(off_str, 16) if ("0x" in off_str or "0X" in off_str) else int(off_str)

        if byte_val is not None and stack_offset is not None:
            if last_offset is not None and stack_offset != last_offset + 1:
                flush()
            current_bytes.append(byte_val)
            last_offset = stack_offset
        else:
            if current_bytes and not any(k in line for k in ("nop", "lea", "sub")):
                flush()
                last_offset = None

    flush()
    return results


def extract_xor_strings(data: bytes, min_len: int = 4, keys: list[int] | None = None) -> list[dict[str, Any]]:
    """Brute-force single-byte XOR keys to recover obfuscated strings."""
    results: list[dict[str, Any]] = []
    test_keys = keys or list(range(1, 256))
    pattern = re.compile(rb"[\x20-\x7e]{%d,}" % max(3, min_len))

    for k in test_keys:
        dec = bytes(b ^ k for b in data)
        pad_char = chr(k) if 32 <= k <= 126 else ""
        for m in pattern.finditer(dec):
            text = m.group().decode("ascii", "replace")
            if pad_char:
                text = text.strip(pad_char)
            # Filter low entropy / repetitive runs
            if len(text) >= min_len and len(set(text)) >= 3:
                results.append({
                    "key": k,
                    "hex_key": hex(k),
                    "offset": m.start(),
                    "string": text,
                    "length": len(text),
                })
                if len(results) >= 200:
                    return results

    return results


# ------------------------------------------------------------ syscalls & hooks

_SYSCALL_SSN = re.compile(r"mov(?:l)?\s+\$0x([0-9a-fA-F]+),\s*%eax|mov\s+eax,\s*0x([0-9a-fA-F]+)", re.IGNORECASE)


def scan_hooks_and_syscalls(disasm_text: str) -> dict[str, Any]:
    """Scan disassembly for raw syscall/SSN stubs and inline hook trampolines."""
    syscalls: list[dict[str, Any]] = []
    hooks: list[dict[str, Any]] = []

    current_fn = ""
    fn_insns: list[dict[str, str]] = []

    def check_fn():
        if not current_fn or not fn_insns:
            return

        # Check for inline hooks in the first 2 instructions
        first = fn_insns[0]
        second = fn_insns[1] if len(fn_insns) > 1 else None

        mnem1 = first["mnemonic"].lower()
        ops1 = first["operands"].lower()

        if mnem1.startswith("jmp"):
            hooks.append({
                "function": current_fn,
                "address": first["address"],
                "type": "direct_jmp",
                "target": ops1,
            })
        elif ("movabs" in mnem1 or "mov" in mnem1) and ("%rax" in ops1 or "rax" in ops1):
            if second and second["mnemonic"].lower().startswith("jmp"):
                hooks.append({
                    "function": current_fn,
                    "address": first["address"],
                    "type": "indirect_jmp_rax",
                    "target": ops1,
                })

        # Check for syscall stubs
        recent_ssn = None
        for ins in fn_insns:
            mnem = ins["mnemonic"].lower()
            ops = ins["operands"]

            m_ssn = _SYSCALL_SSN.search(f"{mnem} {ops}")
            if m_ssn:
                hex_val = m_ssn.group(1) or m_ssn.group(2)
                try:
                    recent_ssn = int(hex_val, 16)
                except ValueError:
                    recent_ssn = None

            if mnem in ("syscall", "sysenter", "int") and "0x2e" in ops or mnem == "syscall":
                syscalls.append({
                    "function": current_fn,
                    "address": ins["address"],
                    "ssn": recent_ssn,
                    "hex_ssn": hex(recent_ssn) if recent_ssn is not None else None,
                })

    for line in disasm_text.splitlines():
        header = re.match(r"^[0-9a-fA-F]+\s+<([^>]+)>:\s*$", line.strip())
        if header:
            check_fn()
            current_fn = header.group(1).split("+")[0]
            fn_insns = []
            continue

        m = _FUNC_LINE.match(line)
        if m:
            addr, _, mnem, ops = m.groups()
            fn_insns.append({
                "address": f"0x{addr.lower()}",
                "mnemonic": mnem or "",
                "operands": ops or "",
            })

    check_fn()
    return {
        "syscalls": syscalls,
        "syscall_count": len(syscalls),
        "hooks": hooks,
        "hook_count": len(hooks),
    }




