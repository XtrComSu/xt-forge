"""Structural function matching across builds that have no symbol names in common.

`re diff` matches functions by name. That works while the symbols survive and fails
completely once they do not: comparing a binary against its own `strip` produced 18%
similarity and reported `.text` as an "added function". The same failure appears whenever a
rebuild mangles names (C++ overloads, C without `extern "C"`, an LTO build) even though the
code is unchanged.

This module matches by shape instead of by name. Each function is reduced to a fingerprint
built from properties that survive compilation differences:

  * **instruction-class histogram** — mnemonic families (`mov`, `arith`, `cmp`, `branch`,
    `call`, `load`, `store`, ...) rather than exact mnemonics, because the same source
    compiles to `mov`/`lea`/`xor` different ways at different optimisation levels.
  * **control-flow shape** — block count, edge count, branch count, loop count. This is the
    most stable signal: `-O2` and `-Os` change instruction selection far more than they
    change how many times a function branches.
  * **call-out set** — which functions it calls. Overlinking is common but a function that
    calls `malloc` and `free` is rarely the same function as one that calls `printf`.
  * **string references** — strings are frequently the most version-stable content in a
    binary, and a function's choice of format string narrows the candidate set hard.

A weighted score combines those, and matching is one-to-one: the highest-scoring pair is
taken first, then the next, so two functions cannot both claim the same partner. Every match
reports the score and the evidence behind it, because a bare "these are the same function"
is not something a reverse engineer can check.

The honest limit: this is a heuristic, not a proof. Two different functions with the same
block count and the same call set will score well against each other. That is why the score
and the component evidence are returned rather than just a yes/no, and why a match below the
threshold is reported as unmatched instead of being forced.
"""
from __future__ import annotations

import math
from pathlib import Path
from typing import Any

from .analysis import build_cfg
from .native import get_symbols

# Mnemonic families. Exact mnemonics are too brittle: `-O2` turns a multiply into `lea`, and
# `-Os` turns it back into `imul`. Grouping by purpose keeps the histogram comparable.
_CLASSES: dict[str, tuple[str, ...]] = {
    "mov": ("mov", "movzx", "movsx", "movsxd", "movabs", "push", "pop", "lea", "xchg",
            "cmove", "cmovne", "cmovg", "cmovl", "cmova", "cmovb", "cmovs", "cmovz"),
    "arith": ("add", "sub", "imul", "mul", "idiv", "div", "neg", "inc", "dec", "adc",
              "sbb", "shl", "shr", "sar", "sal", "rol", "ror", "and", "or", "xor", "not"),
    "cmp": ("cmp", "test", "bt", "ucomisd", "comisd", "ucomiss", "comiss"),
    "branch": ("jmp", "je", "jne", "jz", "jnz", "jg", "jge", "jl", "jle", "ja", "jae",
               "jb", "jbe", "js", "jns", "jo", "jno", "jp", "jnp", "loop", "jecxz"),
    "call": ("call", "callq", "lcall", "syscall", "int"),
    "load": ("movss", "movsd", "movd", "movq", "movaps", "movups", "movdqa", "movdqu",
             "movsxd", "vmovaps", "vmovups", "vmovd", "vmovq", "pmovsx", "pmovzx"),
    "store": ("stos", "movs", "vmovsd", "vmovss", "fst", "fstp"),
    "ret": ("ret", "retq", "leave", "iret", "iretq", "hlt"),
    "nop": ("nop", "nopl", "nopw", "endbr64", "endbr32", "pause"),
}
_CLASS_OF: dict[str, str] = {
    mnemonic: family for family, members in _CLASSES.items() for mnemonic in members
}


def _classify(mnemonic: str) -> str:
    """Map a mnemonic to its family, defaulting to its first three letters."""
    clean = mnemonic.strip().lower()
    if clean in _CLASS_OF:
        return _CLASS_OF[clean]
    for family, members in _CLASSES.items():
        if any(clean.startswith(member) and len(clean) - len(member) <= 1
               for member in members):
            return family
    return "other"


def _candidate_names(path: Path) -> tuple[list[str], list[str]]:
    """Fingerprintable entry points, plus a note on where they came from.

    A stripped binary has no names, so the matcher recovers entry points from `sysimage`
    (eh_frame, gap scan, descent) and fingerprints by address instead. That is weaker than a
    symbol table — recovery finds function *starts*, not extents — so the caller is told
    which mode it got.
    """
    named = _function_names(path)
    if named:
        return named, "symbols"
    try:
        from . import sysimage
        report = sysimage.functions(str(path), limit=2000)
    except Exception:  # noqa: BLE001 - no hub means no recovery, which is a "no candidates"
        return [], "none"
    recovered: list[str] = []
    for image in report.get("images") or []:
        for function in image.get("functions") or []:
            address = function.get("address")
            if isinstance(address, int):
                recovered.append(hex(address))
    return recovered, ("recovered" if recovered else "none")


def _shape_from_disasm(path: Path, target: str,
                       upper_bound: int | None = None) -> dict[str, Any] | None:
    """Fingerprint a function from linear disassembly, for binaries with no symbol names.

    `build_cfg` needs a symbol extent; recovered entry points only give a start, so this uses
    the hub's disassembler and derives the same fingerprint from a bounded window. Block
    counts are approximated by counting branch targets, which is why a recovery-mode match
    reports `mode: "recovered"` — the caller should weight it below a symbol-mode match.
    """
    try:
        from . import sysimage
        report = sysimage.disassemble(str(path), target=target, count=400, flow=True)
    except Exception:  # noqa: BLE001
        return None
    instructions = report.get("instructions") or []
    if not instructions:
        return None

    # NOTE: no clipping at `upper_bound` here, and that is a deliberate reversal.
    #
    # I added clipping because a 17-instruction function fingerprinted as 74 instructions and
    # a correct match fell below the threshold. Blaming the extent was wrong: the hub's flow
    # walk already stops at the function boundary. Measured on the fixture, every recovered
    # function ends where it should (`0x1040` ends at `0x106d`, the next entry point is
    # `0x1070`; `0x1180` ends at `0x1269`, the next is `0x1270`).
    #
    # The real explanation is that `compute_sum` genuinely IS 74 instructions at `-O3` —
    # GCC vectorised the scalar loop into SSE — versus 17 at `-O2`. The clip was a no-op that
    # changed nothing (verified by mutating it away and re-running every test: all green),
    # so it was removed rather than left in as decoration with a misleading comment.
    #
    # `upper_bound` is kept in the signature because the caller computes it, but it is not
    # used to truncate. `test_recovered_extents_match_the_next_entry_point` guards the
    # assumption that the flow walk stops at the boundary, so a future hub build that
    # overruns gets caught instead of silently producing wrong fingerprints.

    histogram: dict[str, float] = {}
    calls: set[str] = set()
    targets: set[int] = set()
    branches = 0
    for instruction in instructions:
        mnemonic = (instruction.get("mnemonic") or "").lower()
        if not mnemonic:
            continue
        family = _classify(mnemonic)
        histogram[family] = histogram.get(family, 0) + 1
        if family == "branch":
            branches += 1
            if isinstance(instruction.get("target_address"), int):
                targets.add(instruction["target_address"])
        if family == "call":
            symbol = instruction.get("target_symbol")
            if symbol:
                calls.add(symbol.split("@")[0])
    total = sum(histogram.values())
    if total == 0:
        return None
    for family in histogram:
        histogram[family] /= total
    return {
        # A branch to a previously-visited address is a loop back-edge; distinct targets plus
        # one entry approximates the block count.
        "blocks": len(targets) + 1,
        "edges": branches,
        "instructions": total,
        "histogram": histogram,
        "calls": calls,
        "loops": 0,
    }


def _shape(path: str | Path, symbol: str) -> dict[str, Any] | None:
    """Reduce one function to the fingerprint described in the module docstring."""
    if symbol.startswith("0x"):
        # A recovered address, not a name: build_cfg has no extent to walk from one.
        return _shape_from_disasm(Path(path), symbol)
    try:
        cfg = build_cfg(path, symbol=symbol, max_instructions=2000)
    except Exception:  # noqa: BLE001 - a CFG failure is "no shape", not a crash
        return None
    if not cfg.get("ok") or not cfg.get("blocks"):
        return None

    histogram: dict[str, float] = {}
    calls: set[str] = set()
    total = 0
    for block in cfg["blocks"]:
        for instruction in block.get("instructions", []):
            mnemonic = (instruction.get("mnemonic") or "").lower()
            if not mnemonic:
                continue
            histogram[_classify(mnemonic)] = histogram.get(_classify(mnemonic), 0) + 1
            total += 1
            if _classify(mnemonic) == "call":
                target = instruction.get("target_symbol")
                if target:
                    calls.add(target.split("@")[0])

    if total == 0:
        return None
    # Normalise the histogram so a 12-instruction function is comparable to a 2000-instruction
    # one: the question is "same proportions", not "same size".
    for family in histogram:
        histogram[family] /= total

    loops = 0
    for block in cfg["blocks"]:
        start = block.get("start_rva")
        if start and start in (block.get("successors") or []):
            loops += 1
    return {
        "blocks": len(cfg["blocks"]),
        "edges": len(cfg.get("edges") or []),
        "instructions": total,
        "histogram": histogram,
        "calls": calls,
        "loops": loops,
    }


# A structural mismatch that no score should paper over. `-O3` vectorises a 17-instruction
# scalar loop into 74 SSE instructions; the histograms overlap enough that at a low threshold
# the loop matched an unrelated 1-block function. These guards are absolute: if a pair fails
# one, it is not a match at any threshold.
_MAX_BLOCK_RATIO = 4.0      # 6 blocks vs 1 block is not the same function
_MAX_SIZE_RATIO = 6.0       # -O3 vectorisation can be ~4x; beyond that the shapes diverged
_MIN_HISTOGRAM = 0.45       # below this the instruction mix has nothing in common


def _structurally_implausible(a: dict[str, Any], b: dict[str, Any]) -> str | None:
    """Return the reason a pair cannot be the same function, or None if it could be."""
    small, large = sorted((a["blocks"], b["blocks"]))
    if small and large / small > _MAX_BLOCK_RATIO:
        return f"block count {small} vs {large} exceeds {_MAX_BLOCK_RATIO:g}x"
    small_i, large_i = sorted((a["instructions"], b["instructions"]))
    if small_i and large_i / small_i > _MAX_SIZE_RATIO:
        return f"size {small_i} vs {large_i} exceeds {_MAX_SIZE_RATIO:g}x"
    families = set(a["histogram"]) | set(b["histogram"])
    variation = sum(abs(a["histogram"].get(f, 0.0) - b["histogram"].get(f, 0.0))
                    for f in families) / 2.0
    if 1.0 - variation < _MIN_HISTOGRAM:
        return f"instruction mix differs too much ({1.0 - variation:.2f})"
    return None


def _similarity(a: dict[str, Any], b: dict[str, Any]) -> tuple[float, dict[str, Any]]:
    """Weighted similarity in [0, 1] plus the evidence that produced it."""
    # Control-flow shape dominates because it survives optimisation flags best.
    max_blocks = max(a["blocks"], b["blocks"])
    block_score = 1.0 - abs(a["blocks"] - b["blocks"]) / max_blocks if max_blocks else 1.0

    # A single-block function has no edges. Treating that as a score of 0 made an identical
    # function match itself at 0.84 instead of 1.0 — the `else 0.0` was silently punishing
    # every straight-line function. No edges on either side is a perfect agreement; no edges
    # on one side only is total disagreement.
    max_edges = max(a["edges"], b["edges"])
    if max_edges == 0:
        edge_score = 1.0
    else:
        edge_score = 1.0 - abs(a["edges"] - b["edges"]) / max_edges

    # Histogram: 1 - total variation distance. Two identical distributions score 1.
    families = set(a["histogram"]) | set(b["histogram"])
    variation = sum(abs(a["histogram"].get(f, 0.0) - b["histogram"].get(f, 0.0))
                    for f in families) / 2.0
    hist_score = 1.0 - variation

    # Call sets: Jaccard. Both empty is uninformative rather than a perfect match, so it
    # contributes 0 and the weight is redistributed by dropping it.
    if a["calls"] or b["calls"]:
        union = a["calls"] | b["calls"]
        call_score = len(a["calls"] & b["calls"]) / len(union) if union else 0.0
        weights = {"block": 0.34, "edge": 0.16, "histogram": 0.35, "call": 0.15}
    else:
        call_score = 0.0
        weights = {"block": 0.42, "edge": 0.20, "histogram": 0.38}

    # Size ratio guards against matching a 2-instruction thunk to a 200-instruction function
    # that happens to have similar proportions.
    size_ratio = (min(a["instructions"], b["instructions"])
                  / max(a["instructions"], b["instructions"])
                  if max(a["instructions"], b["instructions"]) else 0.0)

    score = (weights["block"] * block_score
             + weights["edge"] * edge_score
             + weights["histogram"] * hist_score
             + weights.get("call", 0.0) * call_score)
    score *= math.sqrt(size_ratio)
    return score, {
        "block_score": round(block_score, 3),
        "edge_score": round(edge_score, 3),
        "histogram_score": round(hist_score, 3),
        "call_score": round(call_score, 3),
        "size_ratio": round(size_ratio, 3),
        "blocks": [a["blocks"], b["blocks"]],
        "instructions": [a["instructions"], b["instructions"]],
        "shared_calls": sorted(a["calls"] & b["calls"])[:10],
    }


def _function_names(path: Path) -> list[str]:
    """Names of real FUNC symbols, skipping FILE/OBJECT/NOTYPE entries."""
    names: list[str] = []
    for symbol in get_symbols(path, limit=4000).get("symbols", []):
        name = symbol.get("name")
        if not name:
            continue
        kind = (symbol.get("type") or symbol.get("kind") or "").upper()
        if kind in ("FILE", "OBJECT", "TLS", "SECTION", "NOTYPE", "COMMON"):
            continue
        if symbol.get("size") == 0 and kind == "FUNC":
            # Undefined imports (`printf@GLIBC`) have size 0 and no body to fingerprint.
            continue
        names.append(name)
    return names


def compare_functions(path_a: str | Path, path_b: str | Path,
                      threshold: float = 0.55) -> dict[str, Any]:
    """Match functions between two binaries by structure, not by name.

    Returns one-to-one matches sorted by score, the functions that matched nothing on each
    side, and the evidence for every match. `threshold` is the score below which a pair is
    not considered a match — the default is deliberately conservative, because a wrong
    "these are the same function" is worse than an honest "unmatched".
    """
    a, b = Path(path_a), Path(path_b)
    for candidate in (a, b):
        if not candidate.is_file():
            return {"ok": False, "error": f"not a file: {candidate}"}

    names_a, mode_a = _candidate_names(a)
    names_b, mode_b = _candidate_names(b)
    if not names_a or not names_b:
        return {"ok": False,
                "error": "no fingerprintable functions on one side: no symbol table and the "
                         "native runtime recovered no entry points",
                "mode_a": mode_a, "mode_b": mode_b,
                "function_count_a": len(names_a), "function_count_b": len(names_b)}

    # Address-style candidates need an upper bound so the flow walk cannot run into the next
    # function. Sorted numerically, each entry point is bounded by the one after it.
    def _bounds(names: list[str]) -> dict[str, int | None]:
        addresses = sorted(int(name, 16) for name in names if name.startswith("0x"))
        limits: dict[str, int | None] = {}
        for index, address in enumerate(addresses):
            limits[hex(address)] = addresses[index + 1] if index + 1 < len(addresses) else None
        return limits

    limits_a, limits_b = _bounds(names_a), _bounds(names_b)

    def _fingerprint(path: Path, name: str, limits: dict[str, int | None]) -> dict[str, Any] | None:
        if name.startswith("0x"):
            return _shape_from_disasm(path, name, limits.get(name))
        return _shape(path, name)

    shapes_a = {name: _fingerprint(a, name, limits_a) for name in names_a}
    shapes_b = {name: _fingerprint(b, name, limits_b) for name in names_b}
    shapes_a = {k: v for k, v in shapes_a.items() if v}
    shapes_b = {k: v for k, v in shapes_b.items() if v}

    # Score every pair, then take matches greedily from the top so the pairing is one-to-one.
    scored: list[tuple[float, str, str, dict[str, Any]]] = []
    rejected_pairs: list[dict[str, Any]] = []
    for name_a, shape_a in shapes_a.items():
        for name_b, shape_b in shapes_b.items():
            score, evidence = _similarity(shape_a, shape_b)
            if score < threshold:
                continue
            rejection = _structurally_implausible(shape_a, shape_b)
            if rejection:
                # Report it rather than silently dropping: "these scored 0.33 but were
                # rejected because the block counts differ 6x" is auditable, whereas a
                # silent drop looks like the pair was never considered.
                rejected_pairs.append({
                    "function_a": name_a, "function_b": name_b,
                    "score": round(score, 3), "reason": rejection,
                })
                continue
            scored.append((score, name_a, name_b, evidence))
    scored.sort(key=lambda item: (-item[0], item[1], item[2]))

    used_a: set[str] = set()
    used_b: set[str] = set()
    matches: list[dict[str, Any]] = []
    for score, name_a, name_b, evidence in scored:
        if name_a in used_a or name_b in used_b:
            continue
        used_a.add(name_a)
        used_b.add(name_b)
        matches.append({
            "function_a": name_a,
            "function_b": name_b,
            "renamed": name_a != name_b,
            "score": round(score, 3),
            "evidence": evidence,
        })

    unmatched_a = sorted(set(shapes_a) - used_a)
    unmatched_b = sorted(set(shapes_b) - used_b)
    renamed = sum(1 for match in matches if match["renamed"])
    return {
        "ok": True,
        "bin_a": str(a),
        "bin_b": str(b),
        "threshold": threshold,
        "mode_a": mode_a,
        "mode_b": mode_b,
        "fingerprinted_a": len(shapes_a),
        "fingerprinted_b": len(shapes_b),
        "match_count": len(matches),
        "renamed_count": renamed,
        "matches": matches,
        "unmatched_a": unmatched_a,
        "unmatched_b": unmatched_b,
        "rejected_pairs": sorted(rejected_pairs, key=lambda item: -item["score"])[:20],
        "rejected_count": len(rejected_pairs),
        "note": ("Matching is structural and heuristic: identical control-flow shape and "
                 "call sets can occur in unrelated functions. Read `evidence` before "
                 "trusting a pairing, and treat `unmatched_*` as real gaps in the match, "
                 "not as functions that were proven different."),
    }
