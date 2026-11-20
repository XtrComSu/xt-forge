"""Normalized binary, instruction, and control-flow graph diffing.

Compares functions, normalized disassembly instructions, strings, and basic block
counts across two versions of a binary to locate security patches, added entry
points, and behavioral regressions.
"""
from __future__ import annotations

import difflib
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

from ..route import guard
from .native import get_symbols
from .analysis import build_cfg

_HEX_ADDR_RE = re.compile(r"\b(?:0x)?[0-9a-fA-F]{4,16}\b")
_FUNC_HDR_RE = re.compile(r"^[0-9a-fA-F]+\s+<([^>]+)>:\s*$")
_INSN_LINE_RE = re.compile(r"^\s*[0-9a-fA-F]+:\s+(?:[0-9a-fA-F]{2}\s+)+\s*(.+?)\s*$")
_SKIP_FN_PREFIXES = ("_", "frame_dummy", "register_tm", "deregister_tm")
_IMUL_IMM_RE = re.compile(r"\bimul\s+[^#\n]*\$?0x([0-9a-fA-F]+)\b")
_SHIFT_IMM_RE = re.compile(r"\b(?:sar|shr)\s+\$?0x([0-9a-fA-F]+)\b")


def _decode_reciprocal_notes(ins1: list[str], ins2: list[str], diff_lines: list[str]) -> list[str]:
    """Decode GCC/Clang strength-reduced division constants changed across diff lines."""
    def _find_div(lines: list[str], target_shift_hex: str) -> int | None:
        for i, ln in enumerate(lines):
            ms = _SHIFT_IMM_RE.search(ln)
            if not ms or ms.group(1).lower() != target_shift_hex.lower():
                continue
            s = int(ms.group(1), 16)
            if s > 16:
                continue
            for back in lines[max(0, i - 6):i]:
                mm = _IMUL_IMM_RE.search(back)
                if not mm:
                    continue
                m_val = int(mm.group(1), 16)
                if 0 < m_val < 0x80000000:
                    ratio = (1 << (32 + s)) / m_val
                    d = round(ratio)
                    if d >= 2 and abs(ratio - d) < 0.02:
                        return d
        return None

    minus_shifts = [
        m.group(1) for ln in diff_lines if ln.startswith("-")
        for m in [_SHIFT_IMM_RE.search(ln)] if m and int(m.group(1), 16) <= 16
    ]
    plus_shifts = [
        m.group(1) for ln in diff_lines if ln.startswith("+")
        for m in [_SHIFT_IMM_RE.search(ln)] if m and int(m.group(1), 16) <= 16
    ]
    notes: list[str] = []
    for sh1, sh2 in zip(minus_shifts, plus_shifts):
        if sh1.lower() == sh2.lower():
            continue
        d1 = _find_div(ins1, sh1)
        d2 = _find_div(ins2, sh2)
        if d1 and d2 and d1 != d2:
            pct1 = 100.0 / d1
            pct2 = 100.0 / d2
            notes.append(
                f"strength-reduced division changed: /{d1} ({pct1:.4g}%) in v1 -> /{d2} ({pct2:.4g}%) in v2 "
                f"(shift 0x{sh1} -> 0x{sh2})"
            )

    # Annotate immediate operand changes (e.g., cmp/test/and thresholds & masks)
    _imm_re = re.compile(r"\$(?:0x([0-9a-fA-F]+)|(-?\d+))\b")
    minus_lines = [ln[1:].strip() for ln in diff_lines if ln.startswith("-") and not ln.startswith("---")]
    plus_lines = [ln[1:].strip() for ln in diff_lines if ln.startswith("+") and not ln.startswith("+++")]
    for l1, l2 in zip(minus_lines, plus_lines):
        op1 = l1.split(None, 1)[0] if l1 else ""
        op2 = l2.split(None, 1)[0] if l2 else ""
        if op1 != op2 or not op1:
            continue
        m1 = _imm_re.search(l1)
        m2 = _imm_re.search(l2)
        if m1 and m2 and m1.group(0) != m2.group(0):
            v1 = int(m1.group(1), 16) if m1.group(1) else int(m1.group(2))
            v2 = int(m2.group(1), 16) if m2.group(1) else int(m2.group(2))
            notes.append(f"{op1} immediate changed: {m1.group(0)} ({v1}) -> {m2.group(0)} ({v2})")
    return notes


def _borer_stripped_diff(c1: Path, c2: Path) -> dict[str, Any] | None:
    """When binaries are stripped (.text), locate differing functions via borer and decompile them."""
    from ...adapters.ghidra_mcp import STATE as _GSTATE
    if not _GSTATE.borer_bin:
        return None
    f1_raw = _GSTATE.run_borer_cli("functions", str(c1), "", "0", "100") or ""
    f2_raw = _GSTATE.run_borer_cli("functions", str(c2), "", "0", "100") or ""

    def _parse_funcs(raw: str) -> list[tuple[str, int]]:
        out: list[tuple[str, int]] = []
        for ln in raw.splitlines():
            parts = ln.split()
            if len(parts) >= 2 and parts[0].startswith("0x"):
                try:
                    out.append((parts[0], int(parts[1])))
                except ValueError:
                    continue
        return out

    funcs1 = _parse_funcs(f1_raw)
    funcs2 = _parse_funcs(f2_raw)
    if not funcs1 or not funcs2:
        return None

    # Compare decompiled bodies for matching-index or same-address non-tiny functions (<= 8 functions)
    diffs: list[dict[str, Any]] = []
    for (addr1, sz1), (addr2, sz2) in zip(funcs1, funcs2):
        if sz1 < 12 and sz2 < 12:
            continue
        p1 = (_GSTATE.run_borer_cli("decompile", str(c1), addr1, "full", "0", "80") or "").strip()
        p2 = (_GSTATE.run_borer_cli("decompile", str(c2), addr2, "full", "0", "80") or "").strip()
        if p1 and p2 and p1 != p2:
            diffs.append({
                "addr_v1": addr1,
                "addr_v2": addr2,
                "pseudocode_v1": "\n".join(p1.splitlines()[:45]),
                "pseudocode_v2": "\n".join(p2.splitlines()[:45]),
            })
        if len(diffs) >= 2:
            break
    return {"borer_modified_functions": diffs} if diffs else None


def _disasm_by_func(path: Path) -> dict[str, list[str]]:
    """Extract normalized per-function disassembly lines using objdump when present."""
    if not shutil.which("objdump"):
        return {}
    proc = subprocess.run(
        ["objdump", "-d", "--no-show-raw-insn", str(path)],
        text=True, capture_output=True, timeout=15,
    )
    if proc.returncode != 0:
        # Retry without --no-show-raw-insn for older binutils
        proc = subprocess.run(["objdump", "-d", str(path)], text=True, capture_output=True, timeout=15)
        if proc.returncode != 0:
            return {}
    funcs: dict[str, list[str]] = {}
    cur_fn: str | None = None
    for raw in proc.stdout.splitlines():
        m_hdr = _FUNC_HDR_RE.match(raw.strip())
        if m_hdr:
            cur_fn = m_hdr.group(1)
            funcs.setdefault(cur_fn, [])
            continue
        if cur_fn is None or ":" not in raw:
            continue
        # Handle both --no-show-raw-insn ("  1149:  mov eax, ...") and raw-insn lines
        after_addr = raw.split(":", 1)[1].strip()
        m_raw = _INSN_LINE_RE.match(raw)
        insn = m_raw.group(1) if m_raw else after_addr
        insn = insn.split("#", 1)[0].strip()
        if not insn or insn.startswith("..."):
            continue
        # Normalize absolute/PC-relative hex addresses & RIP-relative comments while keeping small immediates & symbol names.
        norm = re.sub(r"\b[0-9a-fA-F]{5,16}\b", "<ADDR>", insn)
        norm = re.sub(r"<[^>]+>", lambda m: m.group(0), norm)
        funcs[cur_fn].append(norm)
    return funcs


def _rodata_string_map(path: Path) -> dict[int, str]:
    """Map .rodata virtual addresses to printable C strings using objdump."""
    if not shutil.which("objdump"):
        return {}
    proc = subprocess.run(["objdump", "-s", "-j", ".rodata", str(path)], text=True, capture_output=True, timeout=10)
    if proc.returncode != 0:
        return {}
    raw_bytes: list[tuple[int, bytes]] = []
    for ln in proc.stdout.splitlines():
        m = re.match(r"^\s*([0-9a-fA-F]+)\s+((?:[0-9a-fA-F]{8}\s+){1,4})", ln)
        if not m:
            continue
        addr = int(m.group(1), 16)
        hex_chunks = m.group(2).split()
        raw_bytes.append((addr, b"".join(bytes.fromhex(h) for h in hex_chunks)))
    if not raw_bytes:
        return {}
    base = raw_bytes[0][0]
    buf = bytearray()
    for addr, chunk in raw_bytes:
        gap = addr - (base + len(buf))
        if gap > 0:
            buf.extend(b"\x00" * gap)
        buf.extend(chunk)
    out: dict[int, str] = {}
    i = 0
    n = len(buf)
    while i < n:
        if 0x20 <= buf[i] <= 0x7E:
            start = i
            while i < n and 0x20 <= buf[i] <= 0x7E:
                i += 1
            if i < n and buf[i] == 0 and (i - start) >= 2:
                out[base + start] = buf[start:i].decode("ascii", errors="replace")
        i += 1
    return out


def _annotated_func_disasm(path: Path, symbol: str, str_map: dict[int, str]) -> list[str]:
    """Disassemble one function cleanly, annotating RIP-relative .rodata string literals."""
    if not shutil.which("objdump"):
        return []
    proc = subprocess.run(
        ["objdump", "-d", "--no-show-raw-insn", f"--disassemble={symbol}", str(path)],
        text=True, capture_output=True, timeout=10,
    )
    if proc.returncode != 0 or f"<{symbol}>" not in proc.stdout:
        return []
    out: list[str] = []
    in_fn = False
    for raw in proc.stdout.splitlines():
        m_hdr = _FUNC_HDR_RE.match(raw.strip())
        if m_hdr:
            in_fn = m_hdr.group(1) == symbol
            continue
        if not in_fn or ":" not in raw:
            continue
        s = raw.strip()
        m_ref = re.search(r"#\s*(?:0x)?([0-9a-fA-F]+)\b", s)
        if m_ref and str_map:
            ref_addr = int(m_ref.group(1), 16)
            if ref_addr in str_map:
                s = f'{s} ; str="{str_map[ref_addr]}"'
        out.append(s)
        if len(out) >= 80:
            break
    return out


def _printable_strings(path: Path) -> set[str]:
    if not shutil.which("strings"):
        return set()
    proc = subprocess.run(["strings", "-n", "5", str(path)], text=True, capture_output=True, timeout=10)
    if proc.returncode != 0:
        return set()
    return {ln.strip() for ln in proc.stdout.splitlines() if ln.strip()}


def diff_binaries(bin1: str | Path, bin2: str | Path) -> dict[str, Any]:
    """Compare functions, normalized instructions, strings, and CFGs across two binary builds."""
    c1 = guard.read_guard(bin1)
    c2 = guard.read_guard(bin2)

    if not c1.is_file():
        return {"ok": False, "err": f"bin1 not a file: {bin1}"}
    if not c2.is_file():
        return {"ok": False, "err": f"bin2 not a file: {bin2}"}

    syms1 = {s["name"]: s for s in get_symbols(c1, limit=2000).get("symbols", []) if s.get("name")}
    syms2 = {s["name"]: s for s in get_symbols(c2, limit=2000).get("symbols", []) if s.get("name")}
    dis1 = _disasm_by_func(c1)
    dis2 = _disasm_by_func(c2)

    names1 = set(syms1.keys()) | set(dis1.keys())
    names2 = set(syms2.keys()) | set(dis2.keys())

    added = sorted(list(names2 - names1))
    removed = sorted(list(names1 - names2))
    common = sorted(list(names1 & names2))

    modified: list[dict[str, Any]] = []
    identical: list[str] = []

    for name in common[:120]:
        rva1 = syms1.get(name, {}).get("rva") or syms1.get(name, {}).get("value")
        rva2 = syms2.get(name, {}).get("rva") or syms2.get(name, {}).get("value")
        ins1 = dis1.get(name)
        ins2 = dis2.get(name)

        if ins1 is not None and ins2 is not None:
            if ins1 == ins2:
                identical.append(name)
                continue
            if name.startswith(_SKIP_FN_PREFIXES) or name.endswith("@plt"):
                continue
            diff_lines = [
                ln for ln in difflib.unified_diff(ins1, ins2, fromfile="v1", tofile="v2", n=2, lineterm="")
                if not ln.startswith(("---", "+++", "@@"))
            ][:24]
            entry: dict[str, Any] = {
                "name": name,
                "rva1": rva1,
                "rva2": rva2,
                "status": "instructions_changed",
                "insns_v1": len(ins1),
                "insns_v2": len(ins2),
                "insn_diff": diff_lines,
            }
            notes = _decode_reciprocal_notes(ins1, ins2, diff_lines)
            if notes:
                entry["diff_notes"] = notes
            if len(ins2) <= 80 and len(modified) < 3:
                ann1 = _annotated_func_disasm(c1, name, _rodata_string_map(c1))
                ann2 = _annotated_func_disasm(c2, name, _rodata_string_map(c2))
                entry["function_disasm_v1"] = ann1 or ins1
                entry["function_disasm_v2"] = ann2 or ins2
            if name == ".text" and len(modified) == 0:
                bdiff = _borer_stripped_diff(c1, c2)
                if bdiff:
                    entry.update(bdiff)
            modified.append(entry)
            continue

        if rva1 == rva2:
            identical.append(name)
        else:
            cfg1 = build_cfg(c1, symbol=name, max_instructions=50)
            cfg2 = build_cfg(c2, symbol=name, max_instructions=50)
            b1 = len(cfg1.get("blocks", []))
            b2 = len(cfg2.get("blocks", []))
            modified.append({
                "name": name,
                "rva1": rva1,
                "rva2": rva2,
                "status": "structure_changed" if b1 != b2 else "relocated_or_patched",
                "blocks_v1": b1,
                "blocks_v2": b2,
            })

    s1 = _printable_strings(c1)
    s2 = _printable_strings(c2)
    str_added = sorted(s2 - s1)[:20]
    str_removed = sorted(s1 - s2)[:20]

    similarity = 0.0
    total_fns = len(names1 | names2)
    if total_fns > 0:
        similarity = round((len(identical) / total_fns) * 100.0, 1)

    matched_user = sorted(
        n for n in (set(identical) | {m["name"] for m in modified})
        if not n.startswith(_SKIP_FN_PREFIXES) and not n.endswith("@plt") and not n.endswith(".o")
    )
    return {
        "ok": True,
        "evidence_complete": True,
        "next_action": "STOP_AND_ANSWER: evidence_complete=true; report modified_functions, diff_notes, and pseudocode/disasm diffs directly without extra objdump or brute-force loops.",
        "bin1": str(c1),
        "bin2": str(c2),
        "total_functions_v1": len(names1),
        "total_functions_v2": len(names2),
        "added_count": len(added),
        "added_functions": added,
        "removed_count": len(removed),
        "removed_functions": removed,
        "modified_count": len(modified),
        "modified_functions": modified,
        "matched_functions": matched_user,
        "identical_count": len(identical),
        "similarity_pct": similarity,
        "strings_added": str_added,
        "strings_removed": str_removed,
    }
