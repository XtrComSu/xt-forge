"""Read-only LLVM toolchain bridge for binary inspection.

Locates the shipped LLVM tools, runs them with bounded output, and parses
section/symbol listings. Every function degrades to an empty result or an
error dictionary when a tool is absent, unparseable or times out.
"""
from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

LLVM_TOOLS: dict[str, str] = {
    "objdump": "llvm-objdump",
    "readobj": "llvm-readobj",
    "nm": "llvm-nm",
    "otool": "llvm-otool",
    "dwarfdump": "llvm-dwarfdump",
}

MAX_OUTPUT = 2_000_000

# llvm-objdump: "  1 .text  00001a20  0000000000003040  TEXT"
_OBJDUMP_SECTION = re.compile(
    r"^\s*\d+\s+(?P<name>\S+)?\s*(?P<size>[0-9a-fA-F]+)\s+"
    r"(?P<addr>[0-9a-fA-F]+)\s*(?P<type>\S+)?\s*$"
)
# llvm-nm: "0000000000003040 T _start" / "                 U printf"
_NM_LINE = re.compile(
    r"^\s*(?P<addr>[0-9a-fA-F]+)?\s*(?P<type>[A-Za-z?])\s+"
    r"(?P<name>\S.*?)\s*$"
)


def tool_path(name: str) -> str | None:
    """Absolute path to a logical LLVM tool's binary, or None if absent."""
    binary = LLVM_TOOLS.get(name, name)
    try:
        return shutil.which(binary)
    except (TypeError, OSError, ValueError):
        return None


def available() -> dict[str, bool]:
    """Map each logical tool name to whether its binary is installed."""
    return {name: tool_path(name) is not None for name in LLVM_TOOLS}


def _truncate(value: Any) -> str:
    """Return bounded text from captured str/bytes output."""
    if isinstance(value, bytes):
        value = value.decode("utf-8", "replace")
    return (value or "")[:MAX_OUTPUT]


def run_tool(name: str, args: list[str], *, timeout: int = 60) -> dict[str, Any]:
    """Run a wrapped tool without shell=True; never raise on absence/timeout."""
    binary = LLVM_TOOLS.get(name, name)
    argv = [binary, *[str(arg) for arg in args]]
    result: dict[str, Any] = {
        "ok": False, "tool": name, "argv": argv,
        "stdout": "", "stderr": "", "code": None,
    }
    if not tool_path(binary):
        result["error"] = f"tool not found: {binary}"
        return result
    try:
        proc = subprocess.run(
            argv, capture_output=True, text=True, errors="replace",
            timeout=timeout, check=False,
        )
    except subprocess.TimeoutExpired as exc:
        result["stdout"] = _truncate(exc.stdout)
        result["stderr"] = _truncate(exc.stderr)
        result["error"] = f"timed out after {timeout}s: {binary}"
        return result
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        result["error"] = f"cannot run {binary}: {exc}"
        return result
    result["stdout"] = _truncate(proc.stdout)
    result["stderr"] = _truncate(proc.stderr)
    result["code"] = proc.returncode
    if proc.returncode != 0:
        result["error"] = f"{binary} exited with code {proc.returncode}"
        return result
    result["ok"] = True
    return result


def _is_file(path: str) -> bool:
    """True only for an existing regular file; never raises."""
    try:
        return Path(path).is_file()
    except (OSError, TypeError, ValueError):
        return False


def _number(text: str) -> int:
    """Parse a decimal or 0x-prefixed integer field."""
    try:
        return int(text, 16 if text.lower().startswith("0x") else 10)
    except ValueError:
        return 0


def _parse_objdump_sections(text: str) -> list[dict[str, Any]]:
    """Parse `Idx Name Size VMA Type` rows from llvm-objdump."""
    rows: list[dict[str, Any]] = []
    for line in text.splitlines():
        match = _OBJDUMP_SECTION.match(line)
        if not match:
            continue
        try:
            size = int(match.group("size"), 16)
            address = int(match.group("addr"), 16)
        except ValueError:
            continue
        rows.append({"name": (match.group("name") or "").strip(),
                     "address": address, "size": size})
    return rows


def _parse_readobj_sections(text: str) -> list[dict[str, Any]]:
    """Parse `Section { ... }` blocks from llvm-readobj.

    The field names differ by object format, and reading only the ELF/Mach-O
    spellings is what made a PE report `.text` at address 0 with size 0: COFF
    calls them `VirtualAddress` and `VirtualSize`, so the parser found no
    `Address:`/`Size:` line, defaulted both to 0, and returned a perfectly
    well-formed row full of zeros. A section that exists but claims to be empty
    and unmapped is worse than a missing one — it looks like an answer.

    COFF also prints a byte listing after the name (`Name: .text (2E 74 65 ...)`),
    which was being kept as part of the section name.
    """
    rows: list[dict[str, Any]] = []
    current: dict[str, Any] = {}
    in_section = False
    for line in text.splitlines():
        field = line.strip()
        if field == "Section {":
            in_section, current = True, {}
            continue
        if not in_section:
            continue
        if field == "}":
            if "name" in current:
                rows.append({"name": current["name"],
                             "address": current.get("address", 0),
                             "size": current.get("size", 0)})
            in_section, current = False, {}
            continue
        if field.startswith("Name:"):
            raw = field.split(":", 1)[1].strip()
            # Drop COFF's trailing byte listing: ".text (2E 74 65 78 74 ...)".
            current["name"] = re.sub(r"\s*\([0-9A-Fa-f ]*\)\s*$", "", raw).strip()
        elif field.startswith("VirtualAddress:"):
            current["address"] = _number(field.split(":", 1)[1].strip())
        elif field.startswith("Address:"):
            current["address"] = _number(field.split(":", 1)[1].strip())
        elif field.startswith("VirtualSize:"):
            current["size"] = _number(field.split(":", 1)[1].strip())
        elif field.startswith("Size:"):
            current["size"] = _number(field.split(":", 1)[1].strip())
    return rows


def sections(path: str) -> list[dict[str, Any]]:
    """Section headers as name/address/size dicts; [] if unavailable.

    `--macho` is deliberately NOT passed. llvm-objdump auto-detects the format
    from the file, and forcing the Mach-O reader makes it emit nothing at all for
    a PE or an ELF — while still exiting 0. `run_tool` treats returncode 0 as
    success, so the empty output fell through to the readobj fallback and the
    objdump path was dead for every non-Mach-O input without any error to show
    for it. Measured: plain `--section-headers` parses 3 PE rows and 29 ELF rows
    where `--macho --section-headers` parses 0 and 0, and both exit 0.
    """
    if not _is_file(path):
        return []
    result = run_tool("objdump", ["--section-headers", path])
    rows = _parse_objdump_sections(result["stdout"]) if result["ok"] else []
    if rows:
        return rows
    result = run_tool("readobj", ["--sections", path])
    return _parse_readobj_sections(result["stdout"]) if result["ok"] else []


def symbols(path: str) -> list[dict[str, Any]]:
    """Symbols as address/type/name dicts; undefined ones have no address."""
    if not _is_file(path):
        return []
    result = run_tool("nm", ["-a", "--no-sort", path])
    if not result["ok"]:
        return []
    rows: list[dict[str, Any]] = []
    for line in result["stdout"].splitlines():
        match = _NM_LINE.match(line)
        if not match:
            continue
        raw_addr = match.group("addr")
        try:
            address = int(raw_addr, 16) if raw_addr else None
        except ValueError:
            address = None
        symbol_type = match.group("type")
        if symbol_type == "U":
            address = None
        rows.append({"address": address, "type": symbol_type,
                     "name": match.group("name").strip()})
    return rows
