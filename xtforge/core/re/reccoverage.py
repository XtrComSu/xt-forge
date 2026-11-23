"""Score how much of a source project has been accounted for in the reconstruction ledger.

`re unknowns` is a ledger of open questions: each one is a topic declared unresolved, later
resolved or waived. That is necessary but not sufficient, because a ledger only knows about
questions somebody thought to record. It cannot tell you that a function exists in the source
and has never been mentioned at all — which is exactly the failure mode of a long
reconstruction, where attention goes to the hard parts and the boring remainder quietly never
gets written down.

This module closes that hole by starting from the *source* rather than the ledger:

  1. Find every function defined in the source tree (a deliberately shallow C-family parser —
     it looks for definitions of the form `type name(args) {`, not declarations).
  2. Classify each one as required or optional using the linkage the source declares:
     a `static` function is file-local and need not exist in the binary's ABI; a non-static
     one should.
  3. For each required function, decide whether the binary has it, and whether the ledger
     covers it.
  4. Report the fraction accounted for, naming what is missing.

The output distinguishes three states, because collapsing them is what makes coverage numbers
useless:

  * **covered** — present in the binary and recorded in the ledger.
  * **present_unrecorded** — the binary has it but nobody wrote down what was determined. This
    is the common case and the most misleading: the work is done, the evidence is not.
  * **absent** — required by the source, not found in the binary. Either dead code, inlined
    away, or a genuine gap.

`absent` is not automatically a failure: an optimising compiler removes functions, and a
`static` helper that got inlined is gone by design. That is why the source parse records
linkage — a missing `static` symbol is expected, a missing exported one is a finding.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from .native import get_symbols

MAX_FILES = 4000
MAX_FILE_BYTES = 2 * 1024 * 1024
SOURCE_SUFFIXES = (".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".m", ".mm")

# `type name(args) {` — the brace on the same line or the next non-blank line. Control-flow
# keywords are excluded because `if (x) {` matches the shape exactly.
_NOT_FUNCTIONS = frozenset({
    "if", "for", "while", "switch", "return", "sizeof", "do", "else", "case", "catch",
    "defined", "typeof", "alignof", "decltype", "static_assert", "__attribute__",
})

_DEFINITION_RE = re.compile(
    r"^[ \t]*"
    r"(?:(?P<static>static)\s+)?"
    r"(?:(?:inline|extern|const|volatile|unsigned|signed|struct|enum|union|class|"
    r"constexpr|register|virtual|explicit|friend)\s+)*"
    r"(?P<rtype>[A-Za-z_][A-Za-z0-9_ \*&:<>,\[\]]*?)"
    r"\s*\**\s*"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*"
    r"\((?P<args>[^;{}]*)\)\s*"
    r"(?:const\s*)?(?:noexcept\s*)?(?:override\s*)?\{",
    re.MULTILINE)


def _strip_comments_and_strings(text: str) -> str:
    """Remove comments and string literals so a `{` inside them cannot fake a definition."""
    text = re.sub(r"/\*.*?\*/", " ", text, flags=re.DOTALL)
    text = re.sub(r"//[^\n]*", " ", text)
    text = re.sub(r'"(?:[^"\\]|\\.)*"', '""', text)
    text = re.sub(r"'(?:[^'\\]|\\.)*'", "''", text)
    return text


def _source_functions(root: Path) -> tuple[dict[str, dict[str, Any]], list[str]]:
    """Every function definition in the tree, with its linkage and file."""
    found: dict[str, dict[str, Any]] = {}
    skipped: list[str] = []
    count = 0
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in SOURCE_SUFFIXES:
            continue
        count += 1
        if count > MAX_FILES:
            skipped.append(f"stopped after {MAX_FILES} source files")
            break
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                skipped.append(f"{path.name}: larger than {MAX_FILE_BYTES} bytes")
                continue
            text = path.read_text(errors="replace")
        except OSError as exc:
            skipped.append(f"{path.name}: {exc}")
            continue

        cleaned = _strip_comments_and_strings(text)
        for match in _DEFINITION_RE.finditer(cleaned):
            name = match.group("name")
            if name in _NOT_FUNCTIONS or name.startswith("__"):
                continue
            return_type = (match.group("rtype") or "").strip()
            if not return_type:
                continue
            # `foo(bar) {` at file scope in C is a macro-ish oddity; require a plausible type.
            if return_type in _NOT_FUNCTIONS:
                continue
            relative = path.relative_to(root).as_posix()
            entry = found.get(name)
            is_static = bool(match.group("static"))
            if entry is None:
                found[name] = {
                    "name": name,
                    "file": relative,
                    "line": cleaned[:match.start()].count("\n") + 1,
                    "linkage": "static" if is_static else "external",
                    "return_type": return_type,
                    "definitions": 1,
                }
            else:
                entry["definitions"] += 1
                # A name defined both static and non-static in one program: the external one
                # is the ABI, so keep the weaker claim (static) only if all are static.
                if not is_static:
                    entry["linkage"] = "external"
    return found, skipped


def _binary_functions(path: Path) -> set[str]:
    """Function names present in the binary, from the full symbol table when available."""
    names: set[str] = set()
    report = get_symbols(path, limit=200000)
    for symbol in report.get("symbols", []):
        name = symbol.get("name")
        if not name:
            continue
        kind = (symbol.get("type") or symbol.get("kind") or "").upper()
        if kind and kind not in ("FUNC", "NOTYPE", "IFUNC", "EXPORT", "GLOBAL"):
            continue
        # Strip version suffixes and leading underscores from ELF decoration.
        names.add(name.split("@")[0].lstrip("_"))
    return names


def _ledger_topics(binary: Path, db_path: str | Path | None) -> dict[str, str]:
    """Topics recorded against this binary, mapped to their state."""
    from . import obligations
    try:
        listing = obligations.list_unknowns(binary, db_path=db_path)
    except Exception:  # noqa: BLE001 - no ledger is an empty ledger, not a crash
        return {}
    topics: dict[str, str] = {}
    # `list_unknowns` returns the ledger under `entries`. Guessing at the key name meant the
    # first version of this function silently returned {} for a ledger that definitely had
    # three rows in it, and every function came back "present but unrecorded" — a coverage
    # score of 0% against a fully-recorded binary. Read the documented key, and read the
    # alternatives only as a fallback for older callers.
    rows = (listing.get("entries") or listing.get("unknowns")
            or listing.get("rows") or [])
    for row in rows:
        topic = row.get("topic")
        if topic:
            topics[topic] = row.get("state") or "open"
    return topics


def evaluate_coverage(binary: str | Path, source_root: str | Path,
                      db_path: str | Path | None = None) -> dict[str, Any]:
    """Score a reconstruction against a source project.

    Returns per-function status, the fraction of required functions accounted for, and the
    three lists that make the number actionable: what is present but unrecorded, what is
    absent, and what the source requires that the ledger never mentions.
    """
    bin_path = Path(binary)
    root = Path(source_root)
    if not bin_path.is_file():
        return {"ok": False, "error": f"binary not found: {bin_path}"}
    if not root.is_dir():
        return {"ok": False, "error": f"source root not found: {root}"}

    source_functions, skipped = _source_functions(root)
    if not source_functions:
        return {"ok": False,
                "error": f"no function definitions found under {root}",
                "skipped": skipped[:20]}

    binary_functions = _binary_functions(bin_path)
    topics = _ledger_topics(bin_path, db_path)

    rows: list[dict[str, Any]] = []
    counts = {"covered": 0, "present_unrecorded": 0, "absent": 0, "absent_expected": 0}
    for name, entry in sorted(source_functions.items()):
        in_binary = name in binary_functions
        topic_state = topics.get(name)
        if in_binary and topic_state:
            status = "covered"
        elif in_binary:
            status = "present_unrecorded"
        elif entry["linkage"] == "static":
            # A missing static function is usually inlined away; that is expected, not a gap.
            status = "absent_expected"
        else:
            status = "absent"
        counts[status] += 1
        rows.append({**entry, "in_binary": in_binary,
                     "ledger_state": topic_state, "status": status})

    required = counts["covered"] + counts["present_unrecorded"] + counts["absent"]
    accounted = counts["covered"]
    return {
        "ok": True,
        "binary": str(bin_path),
        "source_root": str(root),
        "source_functions": len(source_functions),
        "binary_functions": len(binary_functions),
        "ledger_topics": len(topics),
        "counts": counts,
        "required": required,
        "accounted": accounted,
        "coverage_pct": round(accounted / required * 100.0, 1) if required else 0.0,
        "present_pct": round((counts["covered"] + counts["present_unrecorded"])
                             / required * 100.0, 1) if required else 0.0,
        "present_unrecorded": [r["name"] for r in rows
                               if r["status"] == "present_unrecorded"][:200],
        "absent": [r["name"] for r in rows if r["status"] == "absent"][:200],
        "absent_expected": [r["name"] for r in rows
                            if r["status"] == "absent_expected"][:200],
        "unmentioned_in_ledger": [r["name"] for r in rows
                                  if r["ledger_state"] is None][:200],
        "rows": rows[:400],
        "skipped": skipped[:20],
        "note": ("`absent_expected` is a *static* function missing from the binary — usually "
                 "inlined, so it is excluded from the required denominator. `coverage_pct` "
                 "counts only functions both present in the binary and recorded in the "
                 "ledger; `present_pct` counts presence alone. The gap between the two is "
                 "the work that is done but undocumented."),
    }


def inspect(path: str | Path, **kwargs: Any) -> dict[str, Any]:
    return evaluate_coverage(path, **kwargs)
