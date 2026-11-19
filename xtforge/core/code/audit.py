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
CACHE_NAME_HINTS = ("_cache", "_memo", "cache_", "memo_", "_totals_cache", "_balance_cache")
MUTATOR_PREFIXES = (
    "add_", "record_", "create_", "insert_", "update_", "delete_", "remove_",
    "post_", "apply_", "set_", "write_", "adjust_", "put_", "save_", "mutate_",
)
CLEAR_METHODS = {"clear", "pop", "popitem", "cache_clear", "invalidate", "reset", "discard"}
DATE_WINDOW_HINTS = ("date", "day", "period", "window", "timestamp")
RETRY_COUNTER_HINTS = ("retries_used", "attempts_used", "tries_used", "retry_count", "attempt_count")
RETRY_LIMIT_HINTS = ("max_retries", "max_attempts", "retry_limit", "max_tries")
ALLOC_HINTS = ("alloc", "prorat", "split_amount", "distribute_cents", "apportion")


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
    return False


def _target_names(node: ast.AST) -> set[str]:
    if isinstance(node, ast.Name):
        return {node.id}
    if isinstance(node, (ast.Tuple, ast.List)):
        out: set[str] = set()
        for elt in node.elts:
            out |= _target_names(elt)
        return out
    return set()


def _is_mutable_cache_init(name: str, val: ast.AST | None) -> bool:
    low = name.lower()
    if not (
        any(h in low for h in CACHE_NAME_HINTS)
        or low in ("cache", "memo", "_cache", "_memo")
    ):
        return False
    if isinstance(val, (ast.Dict, ast.Set)):
        return True
    if isinstance(val, ast.Call):
        fn = _unparse(val.func).lower()
        return fn in ("dict", "set", "defaultdict", "ordereddict")
    return False


def _is_asymmetric_date_or_retry_bound(sub: ast.Compare, fn_name: str) -> tuple[bool, str]:
    """Return (is_bug, signal) only for high-confidence boundary defects, not normal guards."""
    cmp_text = _unparse(sub)
    low_cmp = cmp_text.lower()
    ops = [_op_str(o) for o in sub.ops]
    all_nodes = [sub.left, *sub.comparators]
    # Ignore numeric literal ranges like `0 <= idx < n` or `32 <= b < 127`.
    if any(isinstance(n, ast.Constant) and isinstance(n.value, (int, float)) for n in all_nodes):
        return False, ""

    # 1) Chained asymmetric interval comparison (`start_date <= x < end_date` or `from_date <= x < to_date`).
    is_asym_chain = (ops == ["<=", "<"] or ops == ["<", "<="] or ops == [">=", ">"] or ops == [">", ">="])
    if is_asym_chain:
        bound_names = " ".join(_unparse(n).lower() for n in (all_nodes[0], all_nodes[-1]))
        if any(h in bound_names or h in fn_name.lower() for h in DATE_WINDOW_HINTS):
            return True, f"asymmetric date/period window comparison `{cmp_text}` (one bound inclusive, one exclusive)"

    # 2) Off-by-one retry/attempt exhaustion (`retries_used <= max_retries` allowing max+1).
    if len(ops) == 1 and ops[0] in ("<=", ">="):
        left_s = _unparse(sub.left).lower()
        right_s = _unparse(sub.comparators[0]).lower()
        if ops[0] == "<=" and any(k in left_s for k in RETRY_COUNTER_HINTS) and any(k in right_s for k in RETRY_LIMIT_HINTS):
            return True, f"off-by-one retry exhaustion check `{cmp_text}` (`<=` allows one extra attempt past `{right_s}`)"
        if ops[0] == ">=" and any(k in right_s for k in RETRY_COUNTER_HINTS) and any(k in left_s for k in RETRY_LIMIT_HINTS):
            return True, f"off-by-one retry exhaustion check `{cmp_text}` (`>=` allows one extra attempt past `{left_s}`)"

    return False, ""


def _is_join_fanout_append(outer: ast.For, inner: ast.For, append_call: ast.Call) -> bool:
    """True when inner loop iterates an independent collection, matches against outer target, and appends outer fields."""
    inner_vars = _target_names(inner.target)
    outer_vars = _target_names(outer.target) - inner_vars
    if not outer_vars or not inner_vars:
        return False
    # If inner.iter derives directly from outer_vars (e.g. `for child in parent.items`), that is normal tree flattening.
    inner_iter_names = {n.id for n in ast.walk(inner.iter) if isinstance(n, ast.Name)}
    if inner_iter_names & outer_vars:
        return False
    # Must have an `if` join condition inside `inner` referencing both outer_vars and inner_vars.
    has_join_if = False
    for sub in ast.walk(inner):
        if isinstance(sub, ast.If):
            cond_names = {n.id for n in ast.walk(sub.test) if isinstance(n, ast.Name)}
            if (cond_names & outer_vars) and (cond_names & inner_vars):
                has_join_if = True
                break
    if not has_join_if:
        return False
    # And the `.append(...)` payload must reference `outer_vars` (duplicating the outer entity per inner match).
    arg_names = {n.id for a in append_call.args for n in ast.walk(a) if isinstance(n, ast.Name)}
    return bool(arg_names & outer_vars)


def _audit_python_file(rel: str, text: str, lines: list[str]) -> tuple[dict[str, Any], list[dict[str, Any]], dict[str, Any]]:
    """Audit one Python file via AST, returning (module_summary, findings, cache_info)."""
    findings: list[dict[str, Any]] = []
    mod_info: dict[str, Any] = {"file": rel, "functions": []}
    cache_vars: set[str] = set()
    state_vars: set[str] = set()
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

    # Identify module-level mutable cache containers vs backing state containers.
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
            if _is_mutable_cache_init(name, val):
                cache_vars.add(name)
            elif isinstance(val, (ast.Dict, ast.List, ast.Set, ast.Call)):
                state_vars.add(name)

    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        mod_info["functions"].append(f"{node.name}@L{node.lineno}")
        fn_low = node.name.lower()
        fn_src = _node_source(lines, node)

        # 1) Mutable default arguments that are mutated or returned across calls.
        pos_args = node.args.posonlyargs + node.args.args
        pos_pairs = list(zip(pos_args[-len(node.args.defaults):], node.args.defaults)) if node.args.defaults else []
        kw_pairs = [(a, d) for a, d in zip(node.args.kwonlyargs, node.args.kw_defaults) if d is not None]
        for arg_obj, dflt in pos_pairs + kw_pairs:
            if isinstance(dflt, (ast.List, ast.Dict, ast.Set)):
                pname = arg_obj.arg
                mutated = False
                for sub in ast.walk(node):
                    if isinstance(sub, ast.Call) and isinstance(sub.func, ast.Attribute) and isinstance(sub.func.value, ast.Name) and sub.func.value.id == pname:
                        if sub.func.attr in ("append", "extend", "insert", "pop", "remove", "clear", "update", "setdefault", "add", "discard"):
                            mutated = True
                            break
                    elif isinstance(sub, ast.Subscript) and isinstance(sub.value, ast.Name) and sub.value.id == pname and isinstance(sub.ctx, (ast.Store, ast.Del)):
                        mutated = True
                        break
                    elif isinstance(sub, ast.AugAssign) and isinstance(sub.target, ast.Name) and sub.target.id == pname:
                        mutated = True
                        break
                if mutated:
                    findings.append({
                        "category": "mutable_default",
                        "severity": "high",
                        "file": rel,
                        "line": node.lineno,
                        "function": node.name,
                        "signal": f"mutable default `{pname}={_unparse(dflt)}` is mutated in `{node.name}`, leaking state across calls",
                        "excerpt": _excerpt(lines, node.lineno),
                        "function_source": fn_src,
                    })

        # 2) Nested-loop relational join fan-out without deduplication.
        has_dedup = _has_dedup_guard(node)
        for sub in ast.walk(node):
            if isinstance(sub, ast.For):
                for inner in ast.walk(sub):
                    if inner is sub or not isinstance(inner, ast.For):
                        continue
                    appends = [
                        c for c in ast.walk(inner)
                        if isinstance(c, ast.Call)
                        and isinstance(c.func, ast.Attribute)
                        and c.func.attr in ("append", "extend")
                        and _is_join_fanout_append(sub, inner, c)
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
                                f"nested-loop join .{appends[0].func.attr}() on outer record without deduplication/break; "
                                "emits duplicate outer rows when multiple inner records match"
                            ),
                            "excerpt": _excerpt(lines, appends[0].lineno, radius=2),
                            "function_source": fn_src,
                        })
                        break

        # 3) High-confidence boundary comparisons (asymmetric date/period windows or off-by-one retry bounds).
        for sub in ast.walk(node):
            if isinstance(sub, ast.Compare):
                is_bug, sig = _is_asymmetric_date_or_retry_bound(sub, node.name)
                if is_bug:
                    findings.append({
                        "category": "boundary_comparison",
                        "severity": "high",
                        "file": rel,
                        "line": sub.lineno,
                        "function": node.name,
                        "signal": sig,
                        "excerpt": _excerpt(lines, sub.lineno),
                        "function_source": fn_src,
                    })

        # 4) Integer floor division truncation in allocation/proration helpers.
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

        # 4b) High-precision general Python AST defects (duplicate dict keys, assert tuple, literal `is`, unreachable code, late-binding loop closures).
        for sub in ast.walk(node):
            if isinstance(sub, ast.Dict):
                seen_k: set[Any] = set()
                for k in sub.keys:
                    if isinstance(k, ast.Constant) and isinstance(k.value, (str, int, float, bool)):
                        if k.value in seen_k:
                            findings.append({
                                "category": "duplicate_dict_key",
                                "severity": "high",
                                "file": rel,
                                "line": getattr(k, "lineno", node.lineno),
                                "function": node.name,
                                "signal": f"duplicate dictionary key `{k.value!r}` silently overwrites earlier entry",
                                "excerpt": _excerpt(lines, getattr(k, "lineno", node.lineno)),
                                "function_source": fn_src,
                            })
                        seen_k.add(k.value)
            elif isinstance(sub, ast.Assert) and isinstance(sub.test, ast.Tuple) and sub.test.elts:
                findings.append({
                    "category": "assert_tuple",
                    "severity": "high",
                    "file": rel,
                    "line": sub.lineno,
                    "function": node.name,
                    "signal": "assert on non-empty tuple `assert (x, msg)` is always truthy and never raises AssertionError",
                    "excerpt": _excerpt(lines, sub.lineno),
                    "function_source": fn_src,
                })
            elif isinstance(sub, ast.Compare):
                for op, comp in zip(sub.ops, sub.comparators):
                    if (
                        isinstance(op, (ast.Is, ast.IsNot))
                        and isinstance(comp, ast.Constant)
                        and isinstance(comp.value, (str, bytes, int, float))
                        and not isinstance(comp.value, bool)
                    ):
                        findings.append({
                            "category": "literal_identity_comparison",
                            "severity": "high",
                            "file": rel,
                            "line": sub.lineno,
                            "function": node.name,
                            "signal": f"identity comparison `is`/`is not` against literal `{comp.value!r}` in `{_unparse(sub)}`",
                            "excerpt": _excerpt(lines, sub.lineno),
                            "function_source": fn_src,
                        })
            elif isinstance(sub, ast.For):
                loop_vars = _target_names(sub.target)
                if loop_vars:
                    for child in ast.walk(sub):
                        if isinstance(child, ast.Lambda):
                            arg_names = {a.arg for a in child.args.args} | {a.arg for a in child.args.kwonlyargs}
                            body_names = {n.id for n in ast.walk(child.body) if isinstance(n, ast.Name)}
                            unbound = (body_names & loop_vars) - arg_names
                            # Only flag when lambda is stored/appended/returned rather than immediately called in-place
                            if unbound and any(isinstance(c, ast.Call) and isinstance(c.func, ast.Attribute) and c.func.attr == "append" and child in c.args for c in ast.walk(sub)):
                                findings.append({
                                    "category": "late_binding_closure",
                                    "severity": "high",
                                    "file": rel,
                                    "line": getattr(child, "lineno", sub.lineno),
                                    "function": node.name,
                                    "signal": f"lambda inside loop captures loop variable `{sorted(unbound)[0]}` by late binding; all closures see final iteration value",
                                    "excerpt": _excerpt(lines, getattr(child, "lineno", sub.lineno)),
                                    "function_source": fn_src,
                                })
            for block_attr in ("body", "orelse", "finalbody"):
                stmts = getattr(sub, block_attr, None)
                if isinstance(stmts, list):
                    for idx_s, stmt in enumerate(stmts[:-1]):
                        if isinstance(stmt, (ast.Return, ast.Raise, ast.Break, ast.Continue)):
                            nxt = stmts[idx_s + 1]
                            findings.append({
                                "category": "unreachable_code",
                                "severity": "medium",
                                "file": rel,
                                "line": getattr(nxt, "lineno", stmt.lineno),
                                "function": node.name,
                                "signal": f"unreachable statement after `{type(stmt).__name__.lower()}` at line {stmt.lineno}",
                                "excerpt": _excerpt(lines, getattr(nxt, "lineno", stmt.lineno)),
                                "function_source": fn_src,
                            })
                            break

        # 5) Same-module cache read / invalidation tracking.
        uses_cache: set[str] = set()
        clears_cache: set[str] = set()
        touches_state: set[str] = set()
        for sub in ast.walk(node):
            if isinstance(sub, ast.Name):
                if sub.id in cache_vars:
                    uses_cache.add(sub.id)
                elif sub.id in state_vars:
                    touches_state.add(sub.id)
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
                "state_vars": sorted(touches_state),
                "function_source": fn_src,
            })
        if fn_low.startswith(MUTATOR_PREFIXES) and touches_state and not clears_cache and not uses_cache:
            mutators_without_clear.append({
                "file": rel,
                "line": node.lineno,
                "function": node.name,
                "state_vars": sorted(touches_state),
                "excerpt": _excerpt(lines, node.lineno, radius=2),
                "function_source": fn_src,
            })

    # Pair cache readers with mutators in the SAME module that mutate shared backing state without invalidating cache.
    if cache_vars and cache_readers and mutators_without_clear:
        reader_srcs = "\n\n".join(r.get("function_source", "") for r in cache_readers[:2] if r.get("function_source"))
        reader_state = {sv for r in cache_readers for sv in r.get("state_vars", [])}
        for mut in mutators_without_clear:
            if reader_state and not (set(mut.get("state_vars", [])) & reader_state):
                continue
            findings.append({
                "category": "stale_cache",
                "severity": "high",
                "file": rel,
                "line": mut["line"],
                "function": mut["function"],
                "signal": (
                    f"mutator `{mut['function']}` updates `{','.join(mut['state_vars'])}` but does not invalidate "
                    f"module cache(s) {sorted(cache_vars)} read by {[r['function'] for r in cache_readers]}"
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
        mod_info, f_list, _ = _audit_python_file(rel, text, lines)
        if mod_info["functions"]:
            modules.append(mod_info)
        all_findings.extend(f_list)

    sev_rank = {"high": 0, "medium": 1, "low": 2}
    all_findings.sort(key=lambda f: (sev_rank.get(f["severity"], 9), f["file"], f["line"]))
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
