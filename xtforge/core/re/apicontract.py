"""Grade a binary's exported API surface, and diff it against a baseline.

`re exports` lists symbols. That is inventory, not judgement: a hundred exported symbols is
neither good nor bad. The questions that matter before a release are *which of these should
not be exported* and *what changed since the last release that a consumer will notice*, and
neither is answerable from a flat list.

This module answers both.

**Exposure grading.** Every exported symbol is placed in a tier reflecting how hard it is to
remove later, because "exported by accident" and "exported on purpose" look identical in a
symbol table but have very different costs:

  * `forbidden` — the symbol matches a pattern that is essentially never intentional in a
    shipped library: a debug or test helper, a C++ template instantiation of a standard
    container, an internal-prefixed name that leaked into `.dynsym`.
  * `risky` — internal-looking names that are exported. A leading underscore on a non-libc
    name, a `detail`/`internal`/`impl` namespace.
  * `public` — everything else that is a defined, global, default-visibility symbol.

The tiers are heuristics and are reported as such. They are useful because they are cheap and
auditable, not because a pattern match is proof of intent.

**Contract diff.** Given a baseline (an earlier version, or a policy file listing the
approved surface), report:

  * `added` — new exports. A consumer sees a larger surface; usually fine, sometimes a leak.
  * `removed` — gone exports. This is a **breaking change** for anyone linking against them,
    and it is the finding that most often ships by accident.
  * `changed` — same name, different binding/visibility/type. A symbol going from `WEAK` to
    `GLOBAL`, or `DEFAULT` to `HIDDEN`, changes link behaviour without changing the name.

Removed and changed are graded by severity, because a removed `_ZSt…` (a std:: helper that was
never meant to be exported) is not the same event as a removed `SSL_new`.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from .native import get_symbols

# Symbol shapes that are essentially never a deliberate part of a shipped ABI.
_FORBIDDEN_PATTERNS: tuple[tuple[str, str], ...] = (
    (r"^_ZSt", "C++ standard-library template instantiation"),
    (r"^_ZNSt", "C++ standard-library template instantiation"),
    (r"^__gnu_cxx", "libstdc++ internal namespace"),
    (r"(?i)test", "test helper"),
    (r"(?i)mock", "test double"),
    (r"(?i)debug", "debug helper"),
    (r"(?i)assert", "assertion helper"),
    (r"^_?llvm\.", "compiler-internal symbol"),
    (r"^__asan_|^__ubsan_|^__tsan_|^__msan_", "sanitizer runtime hook"),
    (r"^__gcov", "coverage hook"),
    (r"^_GLOBAL__sub_I", "static initialiser thunk"),
)

# Internal-looking names. A leading underscore is normal for libc and for C++ mangling, so
# those are excluded before this tier is applied.
_RISKY_PATTERNS: tuple[tuple[str, str], ...] = (
    (r"(?i)(^|::|\b)(detail|internal|impl|private|hidden)($|::|\b)", "internal namespace"),
    (r"^_(?!Z|_)[A-Za-z]", "leading underscore on a non-libc name"),
    (r"(?i)_(impl|internal|detail)$", "internal suffix"),
)

# Prefixes that make a leading underscore ordinary rather than suspicious.
_CONVENTIONAL_UNDERSCORE = ("__", "_Z", "_ZN", "_ZT", "_ITM", "_Unwind", "_Py", "_IO",
                            "_obstack", "_dl_", "_rpc", "_pthread", "_sys_", "_exit",
                            "_main", "_init", "_fini", "_edata", "_end", "_start")


def _grade(name: str) -> tuple[str, str]:
    """Return (tier, reason) for one exported symbol."""
    for pattern, reason in _FORBIDDEN_PATTERNS:
        if re.search(pattern, name):
            return "forbidden", reason
    if name.startswith(_CONVENTIONAL_UNDERSCORE):
        return "public", "conventional underscore prefix"
    for pattern, reason in _RISKY_PATTERNS:
        if re.search(pattern, name):
            return "risky", reason
    return "public", "exported"


def _exported(path: Path) -> dict[str, dict[str, Any]]:
    """Defined, globally-visible symbols — the ones a consumer can actually link against.

    For ELF this means **`.dynsym` only**. `.symtab` also holds symbols from a relocatable
    object or an unstripped executable, and those are not part of any ABI: nothing can link
    against them dynamically. Reading `.symtab` made an audit of a plain `.o` report
    `only_static` as an exported symbol, while `nm -D` correctly reported no symbols at all.
    PE differs — its export directory is the ABI — and `get_symbols` labels those entries
    with `kind: "export"`, so they are accepted regardless of the table name.
    """
    report = get_symbols(path, limit=100000)
    tables = {str(name).lower() for name in (report.get("tables") or [])}
    dynamic_only = "symtab" in tables and "dynsym" not in tables
    surface: dict[str, dict[str, Any]] = {}
    for symbol in report.get("symbols", []):
        name = symbol.get("name")
        if not name:
            continue
        table = str(symbol.get("table") or "").lower()
        pe_export = str(symbol.get("kind") or "").lower() == "export"
        if not pe_export and (dynamic_only or (table and table != "dynsym")):
            # Static-table symbol: real, but not linkable, so not part of the contract.
            continue
        bind = (symbol.get("bind") or "").upper()
        # Undefined (shndx 0) symbols are imports, not exports.
        if symbol.get("shndx") in (0, "0"):
            continue
        if bind not in ("GLOBAL", "WEAK", "UNIQUE"):
            continue
        # PE exports have no bind; they are all global by definition.
        visibility = symbol.get("visibility")
        if isinstance(visibility, int) and visibility not in (0, 1):
            continue  # HIDDEN(2) / INTERNAL(3) are not part of the ABI
        surface[name] = {
            "name": name,
            "bind": bind or "GLOBAL",
            "type": symbol.get("type") or symbol.get("kind") or "NOTYPE",
            "visibility": visibility,
            "size": symbol.get("size"),
            "shndx": symbol.get("shndx"),
        }
    return surface


def audit_contract(path: str | Path,
                   baseline: str | Path | None = None) -> dict[str, Any]:
    """Grade the export surface, and optionally diff it against a baseline binary.

    `baseline` is another binary whose export surface is the approved one. Passing it turns
    this from an inventory into a release gate: removals become breaking changes and
    additions get a tier so a leaked `test_helper` stands out from a deliberate new API.
    """
    binary = Path(path)
    if not binary.is_file():
        return {"ok": False, "error": f"not a file: {binary}"}

    surface = _exported(binary)
    if not surface:
        return {"ok": False,
                "error": "no exported symbols: the binary is stripped of its dynamic "
                         "symbol table, or everything is hidden",
                "path": str(binary)}

    graded: list[dict[str, Any]] = []
    tiers = {"forbidden": 0, "risky": 0, "public": 0}
    for name, entry in surface.items():
        tier, reason = _grade(name)
        tiers[tier] += 1
        item = dict(entry)
        item["tier"] = tier
        item["why"] = reason
        graded.append(item)
    # Worst first: a reviewer reads the top of this list and should see the problems.
    order = {"forbidden": 0, "risky": 1, "public": 2}
    graded.sort(key=lambda item: (order[item["tier"]], item["name"]))

    result: dict[str, Any] = {
        "ok": True,
        "path": str(binary),
        "export_count": len(surface),
        "tiers": tiers,
        "findings": [item for item in graded if item["tier"] != "public"][:200],
        "surface_sample": [item["name"] for item in graded
                           if item["tier"] == "public"][:40],
        "note": ("Tiers are pattern heuristics, not proof of intent. A `forbidden` symbol is "
                 "worth a look, not a bug report. The baseline diff is the authoritative "
                 "part: a removed export breaks consumers, and that is measured, not "
                 "guessed."),
    }

    if baseline is not None:
        base_path = Path(baseline)
        if not base_path.is_file():
            result["baseline_error"] = f"not a file: {base_path}"
            return result
        base_surface = _exported(base_path)
        if not base_surface:
            result["baseline_error"] = "baseline has no exported symbols"
            return result

        added = sorted(set(surface) - set(base_surface))
        removed = sorted(set(base_surface) - set(surface))
        changed: list[dict[str, Any]] = []
        for name in sorted(set(surface) & set(base_surface)):
            before, after = base_surface[name], surface[name]
            differences = {
                key: [before.get(key), after.get(key)]
                for key in ("bind", "type", "visibility", "size")
                if before.get(key) != after.get(key)
            }
            if differences:
                changed.append({"name": name, "differences": differences,
                                "tier": _grade(name)[0]})

        # Severity: a removal is breaking for a consumer, but removing something that should
        # never have been exported is a fix. Grade it so the two do not blur together.
        breaking = [name for name in removed if _grade(name)[0] == "public"]
        cleanup = [name for name in removed if _grade(name)[0] != "public"]
        result["baseline"] = str(base_path)
        result["baseline_export_count"] = len(base_surface)
        result["added"] = added[:200]
        result["added_count"] = len(added)
        result["added_graded"] = [
            {"name": name, "tier": _grade(name)[0], "why": _grade(name)[1]}
            for name in added[:200]
        ]
        result["removed"] = removed[:200]
        result["removed_count"] = len(removed)
        result["breaking_removals"] = breaking[:200]
        result["breaking_removal_count"] = len(breaking)
        result["cleanup_removals"] = cleanup[:200]
        result["changed"] = changed[:200]
        result["changed_count"] = len(changed)
        result["compatible"] = not breaking and not changed
        result["verdict"] = (
            "breaking" if breaking or changed
            else "additive" if added
            else "identical")
    return result


def inspect(path: str | Path, **kwargs: Any) -> dict[str, Any]:
    return audit_contract(path, **kwargs)
