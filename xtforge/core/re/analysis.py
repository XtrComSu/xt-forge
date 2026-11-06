"""Dual-engine Control Flow Graph (CFG) and cross-reference analyzer.

Supports pure-Python basic block splitting over objdump disassembly (builtin)
and recursive-descent disassembly via rizin when available.
"""
from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

from ..route import guard
from .native import _run, sniff_format

CONDITIONAL_BRANCHES = {
    "je", "jne", "jz", "jnz", "ja", "jb", "jae", "jbe",
    "jg", "jge", "jl", "jle", "js", "jns", "jo", "jno",
    "jp", "jnp", "jc", "jnc", "loop", "loope", "loopne",
    "cbz", "cbnz", "tbz", "tbnz", "beq", "bne", "blt",
    "bge", "bltu", "bgeu",
}

UNCONDITIONAL_BRANCHES = {
    "jmp", "jmpq", "b", "j",
}

TERMINATORS = {
    "ret", "retq", "iret", "ud2", "hlt",
}

CALL_MNEMONICS = {
    "call", "callq", "bl", "jal",
}

_DISASM_LINE = re.compile(
    r"^\s*([0-9a-fA-F]+):\s+((?:[0-9a-fA-F]{2}\s+)+)\s*([a-zA-Z][a-zA-Z0-9._]*)(?:\s+(.*))?$"
)

_TARGET_ADDR = re.compile(
    r"(?:0x)?([0-9a-fA-F]+)(?:\s+<([^>]+)>)?$"
)


def _parse_raw_instructions(disasm_text: str, function_name: str | None = None) -> list[dict[str, Any]]:
    """Parse raw objdump lines into structured instruction records."""
    instructions: list[dict[str, Any]] = []
    current_fn = ""
    target_fn = function_name.strip("<>") if function_name else None

    for line in disasm_text.splitlines():
        header = re.match(r"^[0-9a-fA-F]+\s+<([^>]+)>:\s*$", line.strip())
        if header:
            current_fn = header.group(1).split("+")[0]
            continue

        if target_fn and current_fn and current_fn != target_fn:
            continue

        match = _DISASM_LINE.match(line)
        if not match:
            continue

        addr_str, raw_bytes, mnemonic, operands = match.groups()
        addr = int(addr_str, 16)
        mnem = (mnemonic or "").lower()
        ops = (operands or "").strip()

        # Extract branch target if present
        target_addr = None
        target_sym = None
        if mnem in CONDITIONAL_BRANCHES or mnem in UNCONDITIONAL_BRANCHES or mnem in CALL_MNEMONICS:
            tgt_match = _TARGET_ADDR.search(ops)
            if tgt_match:
                tgt_hex, tgt_label = tgt_match.groups()
                try:
                    target_addr = int(tgt_hex, 16)
                except ValueError:
                    target_addr = None
                if tgt_label:
                    target_sym = tgt_label.split("+")[0]

        instructions.append(
            {
                "address": addr,
                "hex_address": hex(addr),
                "bytes": " ".join(raw_bytes.split()),
                "mnemonic": mnem,
                "operands": ops,
                "function": current_fn,
                "target_address": target_addr,
                "target_symbol": target_sym,
            }
        )

    return instructions


def parse_blocks_from_disasm(
    disasm_text: str,
    function_name: str,
    base_addr: int | None = None,
    max_instructions: int = 250,
) -> dict[str, Any]:
    """Pure-Python basic block splitter and control flow reconstructor."""
    instructions = _parse_raw_instructions(disasm_text, function_name)
    if not instructions:
        return {
            "ok": True,
            "symbol": function_name,
            "engine": "builtin",
            "blocks": [],
            "edges": [],
            "total_instructions": 0,
            "truncated_instructions": False,
        }

    insn_addrs = {insn["address"]: idx for idx, insn in enumerate(instructions)}
    min_addr = instructions[0]["address"]
    max_addr = instructions[-1]["address"]

    # Step 1: Identify leaders
    leaders = {instructions[0]["address"]}

    for idx, insn in enumerate(instructions):
        mnem = insn["mnemonic"]
        target = insn["target_address"]

        # Jump target is a leader if within this function
        if (mnem in CONDITIONAL_BRANCHES or mnem in UNCONDITIONAL_BRANCHES) and target:
            if target in insn_addrs:
                leaders.add(target)

        # Instruction after a branch or terminator is a leader
        if (mnem in CONDITIONAL_BRANCHES or mnem in UNCONDITIONAL_BRANCHES or mnem in TERMINATORS):
            if idx + 1 < len(instructions):
                leaders.add(instructions[idx + 1]["address"])

    sorted_leaders = sorted(leaders)

    # Step 2: Partition instructions into blocks
    blocks: list[dict[str, Any]] = []
    addr_to_block_id: dict[int, str] = {}

    for i, leader_addr in enumerate(sorted_leaders):
        start_idx = insn_addrs[leader_addr]
        next_leader = sorted_leaders[i + 1] if i + 1 < len(sorted_leaders) else None
        end_idx = insn_addrs[next_leader] if next_leader else len(instructions)

        block_insns = instructions[start_idx:end_idx]
        block_id = f"b_{leader_addr:x}"
        addr_to_block_id[leader_addr] = block_id

        blocks.append(
            {
                "id": block_id,
                "start_rva": hex(leader_addr),
                "end_rva": hex(block_insns[-1]["address"]),
                "instruction_count": len(block_insns),
                "successors": [],
                "instructions": block_insns,
            }
        )

    # Step 3: Compute edges between blocks
    edges: list[dict[str, str]] = []

    for idx, block in enumerate(blocks):
        block_insns = block["instructions"]
        last_insn = block_insns[-1]
        mnem = last_insn["mnemonic"]
        target = last_insn["target_address"]
        next_block = blocks[idx + 1] if idx + 1 < len(blocks) else None

        if mnem in UNCONDITIONAL_BRANCHES:
            if target and target in addr_to_block_id:
                tgt_id = addr_to_block_id[target]
                edges.append({"from": block["id"], "to": tgt_id, "type": "unconditional"})
                block["successors"].append(tgt_id)
        elif mnem in CONDITIONAL_BRANCHES:
            # True branch
            if target and target in addr_to_block_id:
                tgt_id = addr_to_block_id[target]
                edges.append({"from": block["id"], "to": tgt_id, "type": "conditional_true"})
                block["successors"].append(tgt_id)
            # False fallthrough branch
            if next_block:
                edges.append({"from": block["id"], "to": next_block["id"], "type": "conditional_false"})
                block["successors"].append(next_block["id"])
        elif mnem in TERMINATORS:
            # Function return / exit, no fallthrough edge
            pass
        else:
            # Fallthrough to next block
            if next_block:
                edges.append({"from": block["id"], "to": next_block["id"], "type": "fallthrough"})
                block["successors"].append(next_block["id"])

    # Step 4: Context bounding
    total_insns = len(instructions)
    truncated = total_insns > max_instructions
    if truncated:
        for block in blocks:
            block["instructions"] = None

    return {
        "ok": True,
        "symbol": function_name,
        "engine": "builtin",
        "blocks": blocks,
        "edges": edges,
        "total_instructions": total_insns,
        "truncated_instructions": truncated,
        "hint": "use --max-instructions or xtforge re block <id> to fetch instruction bodies" if truncated else "",
    }


def parse_xrefs_from_disasm(disasm_text: str, target_symbol_or_addr: str | int) -> list[dict[str, Any]]:
    """Index callers and references to a specific function or address."""
    target_str = str(target_symbol_or_addr).lower().strip()
    target_hex = ""
    if isinstance(target_symbol_or_addr, int):
        target_hex = hex(target_symbol_or_addr).lower()
    elif target_str.startswith("0x"):
        target_hex = target_str

    xrefs: list[dict[str, Any]] = []
    current_fn = ""

    for line in disasm_text.splitlines():
        header = re.match(r"^[0-9a-fA-F]+\s+<([^>]+)>:\s*$", line.strip())
        if header:
            current_fn = header.group(1).split("+")[0]
            continue

        match = _DISASM_LINE.match(line)
        if not match:
            continue

        addr_str, _, mnemonic, operands = match.groups()
        mnem = (mnemonic or "").lower()
        ops = (operands or "").strip()

        # Check if line references target
        matched = False
        if target_str in ops.lower():
            matched = True
        elif target_hex and target_hex in ops.lower():
            matched = True

        if matched:
            xrefs.append(
                {
                    "caller": current_fn or "unknown",
                    "address": f"0x{addr_str.lower()}",
                    "mnemonic": mnem,
                    "operands": ops,
                }
            )

    return xrefs


def _build_cfg_rizin(canon: Path, symbol: str | None, rva: int | None, max_instructions: int) -> dict[str, Any] | None:
    """Attempt CFG extraction using rizin/radare2 JSON output."""
    tool = shutil.which("rizin") or shutil.which("radare2")
    if not tool:
        return None

    target_ref = symbol if symbol else (f"0x{rva:x}" if rva else "main")
    cmd = [tool, "-q", "-c", f"s {target_ref}; af; agj", str(canon)]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        if proc.returncode == 0 and proc.stdout.strip().startswith("["):
            import json
            graph_data = json.loads(proc.stdout)
            if graph_data:
                g = graph_data[0]
                blocks = []
                edges = []
                for b in g.get("blocks", []):
                    bid = f"b_{b.get('offset', 0):x}"
                    ops = b.get("ops", [])
                    succs = []
                    if "jump" in b:
                        succs.append(f"b_{b['jump']:x}")
                        edges.append({"from": bid, "to": f"b_{b['jump']:x}", "type": "jump"})
                    if "fail" in b:
                        succs.append(f"b_{b['fail']:x}")
                        edges.append({"from": bid, "to": f"b_{b['fail']:x}", "type": "conditional_false"})
                    blocks.append({
                        "id": bid,
                        "start_rva": hex(b.get("offset", 0)),
                        "end_rva": hex(b.get("offset", 0) + b.get("size", 0)),
                        "instruction_count": len(ops),
                        "successors": succs,
                        "instructions": ops if len(ops) <= max_instructions else None,
                    })
                return {
                    "ok": True,
                    "symbol": target_ref,
                    "engine": "rizin",
                    "blocks": blocks,
                    "edges": edges,
                    "total_instructions": sum(b["instruction_count"] for b in blocks),
                    "truncated_instructions": any(b["instructions"] is None for b in blocks),
                }
    except Exception:
        pass
    return None


def build_cfg(
    target: str | Path,
    symbol: str | None = None,
    rva: int | None = None,
    engine: str = "auto",
    max_instructions: int = 250,
) -> dict[str, Any]:
    """Reconstruct function basic block CFG using rizin or builtin objdump splitter."""
    try:
        canon = guard.read_guard(target)
    except guard.Denied as exc:
        return {"ok": False, "err": f"{exc.code}: {exc.reason}"}

    if not canon.is_file():
        return {"ok": False, "err": "not_a_file", "path": str(canon)}

    # Check rizin if requested or auto
    if engine in ("auto", "rizin"):
        rizin_res = _build_cfg_rizin(canon, symbol, rva, max_instructions)
        if rizin_res:
            return rizin_res
        if engine == "rizin":
            return {
                "ok": False,
                "err": "rizin not found or analysis failed",
                "hint": "install rizin (pkg install rizin) or use --engine builtin",
            }

    # Builtin engine via objdump
    objdump = shutil.which("objdump")
    if not objdump:
        return {
            "ok": False,
            "err": "objdump not found",
            "hint": "install binutils (apt install binutils)",
        }

    cmd = [objdump, "-d", str(canon)]
    if symbol:
        cmd = [objdump, "-d", f"--disassemble={symbol}", str(canon)]
    out, ok = _run(cmd, timeout=30)
    if not ok or not out.strip():
        return {"ok": False, "err": "disassembly failed"}

    fn_name = symbol or (hex(rva) if rva else "function")
    cfg = parse_blocks_from_disasm(out, fn_name, base_addr=rva, max_instructions=max_instructions)
    cfg["path"] = str(canon)
    return cfg


def get_block(
    target: str | Path,
    block_id: str,
    symbol: str | None = None,
    rva: int | None = None,
    engine: str = "auto",
) -> dict[str, Any]:
    """Fetch instructions for a single basic block on demand."""
    cfg = build_cfg(target, symbol=symbol, rva=rva, engine=engine, max_instructions=100_000)
    if not cfg.get("ok"):
        return cfg

    for b in cfg.get("blocks", []):
        if b["id"] == block_id:
            return {
                "ok": True,
                "block_id": block_id,
                "symbol": cfg.get("symbol"),
                "start_rva": b["start_rva"],
                "end_rva": b["end_rva"],
                "instruction_count": b["instruction_count"],
                "instructions": b.get("instructions", []),
                "successors": b.get("successors", []),
            }

    return {"ok": False, "err": f"block not found: {block_id}"}


def find_xrefs(target: str | Path, target_addr_or_symbol: int | str) -> dict[str, Any]:
    """Locate all cross-references calling or referencing target_addr_or_symbol."""
    try:
        canon = guard.read_guard(target)
    except guard.Denied as exc:
        return {"ok": False, "err": f"{exc.code}: {exc.reason}"}

    objdump = shutil.which("objdump")
    if not objdump:
        return {"ok": False, "err": "objdump not found"}

    out, ok = _run([objdump, "-d", str(canon)], timeout=45)
    if not ok:
        return {"ok": False, "err": "disassembly failed"}

    xrefs = parse_xrefs_from_disasm(out, target_addr_or_symbol)
    return {
        "ok": True,
        "path": str(canon),
        "target": str(target_addr_or_symbol),
        "count": len(xrefs),
        "xrefs": xrefs,
    }
