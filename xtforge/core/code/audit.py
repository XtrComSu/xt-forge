"""Multi-file static correctness & risk auditor for source trees."""
from __future__ import annotations

import ast
import os
import re
from pathlib import Path
from typing import Any

from ..route import guard

SKIP_DIRS = {
    ".git", ".hg", ".svn", "node_modules", "__pycache__", ".venv", "venv",
    "target", "dist", "build", "artifacts", ".pytest_cache", ".mypy_cache",
}
TEST_DIRS = {"test", "tests", "spec", "__tests__"}
CACHE_NAME_HINTS = ("cache", "memo", "totals", "summary", "snapshot", "index")
MUTATOR_PREFIXES = (
    "add_", "record_", "create_", "insert_", "update_", "delete_", "remove_",
    "post_", "apply_", "set_", "write_", "adjust_", "put_", "save_", "mutate_",
)
CLEAR_METHODS = {"clear", "pop", "popitem", "cache_clear", "invalidate", "reset", "discard"}
BOUNDARY_HINTS = (
    "date", "day", "time", "ts", "start", "end", "from", "to", "min", "max",
    "limit", "budget", "retry", "retries", "attempt", "cutoff", "until", "since",
    "before", "after", "bound", "window", "period", "age", "ttl", "expire",
)
ALLOC_HINTS = ("alloc", "prorat", "split", "share", "distribut", "portion", "ratio")


def _is_test_file(rel: str) -> bool:
    parts = [p.lower() for p in Path(rel).parts]
    if any(p in TEST_DIRS for p in parts[:-1]):
        return True
    name = parts[-1] if parts else ""
    return (
        name.startswith("test_")
        or name.endswith("_test.py")
        or name.endswith("_test.go")
        or name.endswith("_test.rs")
        or ".test." in name
        or ".spec." in name
    )


def _excerpt(lines: list[str], line_no: int, radius: int = 1) -> str:
    if not lines or line_no <= 0:
        return ""
    lo = max(0, line_no - 1 - radius)
    hi = min(len(lines), line_no + radius)
    return "\n".join(f"{i + 1}: {lines[i]}" for i in range(lo, hi))


def _node_source(lines: list[str], node: ast.AST, max_lines: int = 35) -> str:
    lineno = getattr(node, "lineno", 0)
    if not lines or lineno <= 0:
        return ""
    end_lineno = getattr(node, "end_lineno", lineno + 12) or (lineno + 12)
    lo = max(0, lineno - 1)
    hi = min(len(lines), lo + max_lines, end_lineno)
    return "\n".join(f"{i + 1}: {lines[i]}" for i in range(lo, hi))


def _unparse(node: ast.AST) -> str:
    try:
        return ast.unparse(node)
    except Exception:
        return ""


def _op_str(op: ast.cmpop) -> str:
    return {
        ast.Lt: "<",
        ast.LtE: "<=",
        ast.Gt: ">",
        ast.GtE: ">=",
        ast.Eq: "==",
        ast.NotEq: "!=",
        ast.In: "in",
        ast.NotIn: "not in",
    }.get(type(op), type(op).__name__)


def _has_dedup_guard(func: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    src = _unparse(func).lower()
    if any(k in src for k in ("seen", "dedup", "unique", "distinct", "set()", "dict.fromkeys")):
        return True
    for n in ast.walk(func):
        if isinstance(n, ast.SetComp):
            return True
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "set":
            return True
        if isinstance(n, ast.Subscript) and isinstance(n.ctx, ast.Store):
            return True
    return False


def _audit_python_file(rel: str, text: str, lines: list[str]) -> tuple[dict[str, Any], list[dict[str, Any]], dict[str, Any]]:
    """Audit one Python file via AST, returning (module_summary, findings, cache_info)."""
    findings: list[dict[str, Any]] = []
    mod_info: dict[str, Any] = {"file": rel, "functions": []}
    cache_vars: set[str] = set()
    cache_readers: list[dict[str, Any]] = []
    mutators_without_clear: list[dict[str, Any]] = []

    try:
        tree = ast.parse(text, filename=rel)
    except SyntaxError as exc:
        findings.append({
            "category": "syntax_error",
            "severity": "high",
            "file": rel,
            "line": exc.lineno or 1,
            "function": "<module>",
            "signal": f"SyntaxError: {exc.msg}",
            "excerpt": _excerpt(lines, exc.lineno or 1),
        })
        return mod_info, findings, {"caches": [], "readers": [], "mutators_without_clear": []}

    # Identify module-level mutable cache/memo/summary containers.
    for node in tree.body:
        targets: list[str] = []
        val: ast.AST | None = None
        if isinstance(node, ast.Assign):
            targets = [t.id for t in node.targets if isinstance(t, ast.Name)]
            val = node.value
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            targets = [node.target.id]
            val = node.value
        for name in targets:
            low = name.lower()
            if any(h in low for h in CACHE_NAME_HINTS) and isinstance(val, (ast.Dict, ast.Set, ast.List, ast.Call)):
                cache_vars.add(name)

    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        mod_info["functions"].append(f"{node.name}@L{node.lineno}")
        fn_low = node.name.lower()

        # 1) Mutable default arguments.
        fn_src = _node_source(lines, node)
        for dflt in list(node.args.defaults) + [d for d in node.args.kw_defaults if d is not None]:
            if isinstance(dflt, (ast.List, ast.Dict, ast.Set)):
                findings.append({
                    "category": "mutable_default",
                    "severity": "medium",
                    "file": rel,
                    "line": node.lineno,
                    "function": node.name,
                    "signal": f"mutable default literal {_unparse(dflt)} in signature",
                    "excerpt": _excerpt(lines, node.lineno),
                    "function_source": fn_src,
                })

        # 2) Nested-loop append / join fan-out without deduplication.
        has_dedup = _has_dedup_guard(node)
        for sub in ast.walk(node):
            if isinstance(sub, ast.For):
                for inner in ast.walk(sub):
                    if inner is sub:
                        continue
                    if isinstance(inner, ast.For):
                        # Check if inner loop appends/extends a list without dedup or break.
                        appends = [
                            c for c in ast.walk(inner)
                            if isinstance(c, ast.Call)
                            and isinstance(c.func, ast.Attribute)
                            and c.func.attr in ("append", "extend")
                        ]
                        has_break = any(isinstance(b, ast.Break) for b in ast.walk(inner))
                        if appends and not has_dedup and not has_break:
                            findings.append({
                                "category": "duplicate_aggregation",
                                "severity": "high",
                                "file": rel,
                                "line": appends[0].lineno,
                                "function": node.name,
                                "signal": (
                                    f"nested-loop .{appends[0].func.attr}() without deduplication/break; "
                                    "can emit duplicate rows on multi-match joins"
                                ),
                                "excerpt": _excerpt(lines, appends[0].lineno, radius=2),
                                "function_source": fn_src,
                            })
                            break

        # 3) Boundary / date / limit comparisons (< vs <=, > vs >=).
        for sub in ast.walk(node):
            if isinstance(sub, ast.Compare):
                cmp_text = _unparse(sub)
                low_cmp = cmp_text.lower()
                cmp_words = set(re.findall(r"[a-z]+", low_cmp))
                ops = [_op_str(o) for o in sub.ops]
                is_asym = ("<=" in ops and "<" in ops) or (">=" in ops and ">" in ops)
                is_zero_guard = (
                    len(sub.comparators) == 1
                    and isinstance(sub.comparators[0], ast.Constant)
                    and sub.comparators[0].value == 0
                )
                if (
                    any(o in ("<", "<=", ">", ">=") for o in ops)
                    and not (is_zero_guard and not is_asym)
                    and (is_asym or (cmp_words & set(BOUNDARY_HINTS)))
                ):
                    sev = "high" if (is_asym or (cmp_words & {"date", "end", "until", "max", "budget", "limit", "retry", "retries"})) else "medium"
                    findings.append({
                        "category": "boundary_comparison",
                        "severity": sev,
                        "file": rel,
                        "line": sub.lineno,
                        "function": node.name,
                        "signal": f"boundary comparison `{cmp_text}` ({'asymmetric bounds' if is_asym else 'check inclusive vs exclusive'})",
                        "excerpt": _excerpt(lines, sub.lineno),
                        "function_source": fn_src,
                    })

        # 4) Integer floor division / float round in allocation/proration logic.
        if any(h in fn_low for h in ALLOC_HINTS):
            for sub in ast.walk(node):
                if isinstance(sub, ast.BinOp) and isinstance(sub.op, ast.FloorDiv):
                    findings.append({
                        "category": "numeric_truncation",
                        "severity": "high",
                        "file": rel,
                        "line": sub.lineno,
                        "function": node.name,
                        "signal": f"integer floor division `{_unparse(sub)}` in allocation helper (can drop remainder)",
                        "excerpt": _excerpt(lines, sub.lineno),
                        "function_source": fn_src,
                    })

        # 5) Cache read / invalidation tracking inside this module.
        uses_cache: set[str] = set()
        clears_cache: set[str] = set()
        for sub in ast.walk(node):
            if isinstance(sub, ast.Name) and sub.id in cache_vars:
                uses_cache.add(sub.id)
            if isinstance(sub, ast.Call) and isinstance(sub.func, ast.Attribute):
                if sub.func.attr in CLEAR_METHODS and isinstance(sub.func.value, ast.Name) and sub.func.value.id in cache_vars:
                    clears_cache.add(sub.func.value.id)
            if isinstance(sub, ast.Delete):
                for tgt in sub.targets:
                    if isinstance(tgt, ast.Subscript) and isinstance(tgt.value, ast.Name) and tgt.value.id in cache_vars:
                        clears_cache.add(tgt.value.id)

        if uses_cache and not clears_cache and not fn_low.startswith(MUTATOR_PREFIXES):
            cache_readers.append({
                "file": rel,
                "line": node.lineno,
                "function": node.name,
                "caches": sorted(uses_cache),
                "function_source": fn_src,
            })
        if fn_low.startswith(MUTATOR_PREFIXES) and not clears_cache:
            mutators_without_clear.append({
                "file": rel,
                "line": node.lineno,
                "function": node.name,
                "excerpt": _excerpt(lines, node.lineno, radius=2),
                "function_source": fn_src,
            })

    # Pair cache readers with mutators in the same module that never clear/invalidate.
    if cache_vars and cache_readers and mutators_without_clear:
        reader_srcs = "\n\n".join(r.get("function_source", "") for r in cache_readers[:2] if r.get("function_source"))
        for mut in mutators_without_clear:
            findings.append({
                "category": "stale_cache",
                "severity": "high",
                "file": rel,
                "line": mut["line"],
                "function": mut["function"],
                "signal": (
                    f"mutator `{mut['function']}` does not invalidate module cache(s) "
                    f"{sorted(cache_vars)} read by {[r['function'] for r in cache_readers]}"
                ),
                "excerpt": mut["excerpt"],
                "function_source": mut.get("function_source", ""),
                "reader_source": reader_srcs,
            })

    return mod_info, findings, {
        "caches": sorted(cache_vars),
        "readers": cache_readers,
        "mutators_without_clear": mutators_without_clear,
    }


def audit_workspace(root_raw: str | Path = ".", *, max_findings: int = 25) -> dict[str, Any]:
    """Scan a workspace for structural correctness defects and return a compact report."""
    canon = guard.read_guard(root_raw)
    py_files: list[Path] = []
    if canon.is_file():
        if canon.suffix == ".py":
            py_files.append(canon)
    else:
        for cur, dirs, files in os.walk(canon):
            dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS and not d.startswith("."))
            for fname in sorted(files):
                if fname.endswith(".py"):
                    py_files.append(Path(cur) / fname)

    modules: list[dict[str, Any]] = []
    test_files: list[str] = []
    all_findings: list[dict[str, Any]] = []
    cache_readers_global: list[dict[str, Any]] = []
    mutators_global: list[dict[str, Any]] = []
    nonempty_init_files: list[str] = []
    dynamic_dispatch_files: list[str] = []
    audited_files: list[str] = []

    for fpath in py_files[:400]:
        rel = str(fpath.relative_to(canon)) if canon.is_dir() else fpath.name
        if _is_test_file(rel):
            test_files.append(rel)
            continue
        try:
            text = fpath.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        audited_files.append(rel)
        if Path(rel).name == "__init__.py" and text.strip():
            nonempty_init_files.append(rel)
        if any(tok in text for tok in ("getattr(", "importlib", "__all__", "globals()", "eval(", "exec(")):
            dynamic_dispatch_files.append(rel)
        lines = text.splitlines()
        mod_info, f_list, c_info = _audit_python_file(rel, text, lines)
        if mod_info["functions"]:
            modules.append(mod_info)
        all_findings.extend(f_list)
        cache_readers_global.extend(c_info["readers"])
        mutators_global.extend(c_info["mutators_without_clear"])

    # Cross-module stale-cache check: cache read in module A while mutator lives in module B
    # and never imports/calls invalidate/clear on module A's cache.
    if cache_readers_global and mutators_global:
        seen_stale_keys = {(f["file"], f["line"]) for f in all_findings if f["category"] == "stale_cache"}
        reader_summary = ", ".join(f"{r['file']}:{r['function']}({','.join(r['caches'])})" for r in cache_readers_global[:4])
        reader_srcs = "\n\n".join(r.get("function_source", "") for r in cache_readers_global[:2] if r.get("function_source"))
        for mut in mutators_global:
            if (mut["file"], mut["line"]) in seen_stale_keys:
                continue
            try:
                mtxt = (canon / mut["file"]).read_text(encoding="utf-8", errors="replace") if canon.is_dir() else ""
            except OSError:
                mtxt = ""
            if any(k in mtxt.lower() for k in ("invalidate", "cache_clear", ".clear(")):
                continue
            all_findings.append({
                "category": "stale_cache",
                "severity": "high",
                "file": mut["file"],
                "line": mut["line"],
                "function": mut["function"],
                "signal": f"mutator `{mut['function']}` does not invalidate cached totals read in [{reader_summary}]",
                "excerpt": mut["excerpt"],
                "function_source": mut.get("function_source", ""),
                "reader_source": reader_srcs,
            })

    sev_rank = {"high": 0, "medium": 1, "low": 2}
    all_findings.sort(key=lambda f: (sev_rank.get(f["severity"], 9), f["file"], f["line"]))
    # Deduplicate same (file, line, category).
    deduped: list[dict[str, Any]] = []
    seen_flc: set[tuple[str, int, str]] = set()
    for f in all_findings:
        key = (f["file"], int(f["line"]), f["category"])
        if key not in seen_flc:
            seen_flc.add(key)
            deduped.append(f)

    flagged_files = {f["file"] for f in deduped}
    clean_files = [m["file"] for m in modules if m["file"] not in flagged_files]
    audit_complete = len(py_files) <= 400

    return {
        "ok": True,
        "root": str(canon),
        "production_files": len(modules),
        "audited_files": audited_files,
        "files_skipped": max(0, len(py_files) - 400),
        "audit_complete": audit_complete,
        "evidence_complete": audit_complete and not bool(dynamic_dispatch_files),
        "clean_files": clean_files,
        "dynamic_dispatch_detected": bool(dynamic_dispatch_files),
        "dynamic_dispatch_files": dynamic_dispatch_files,
        "nonempty_init_files": nonempty_init_files,
        "test_files": test_files,
        "modules": modules,
        "finding_count": len(deduped),
        "findings": deduped[:max_findings],
    }
