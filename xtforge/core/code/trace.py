"""Cross-module active-path tracer across re-exports, shadowed symbols, and config dispatch."""
from __future__ import annotations

import ast
import json
import os
import re
from pathlib import Path
from typing import Any

from ..route import guard

SKIP_DIRS = {".git", ".hg", ".svn", "node_modules", "__pycache__", ".venv", "venv", "target", "dist", "build"}
TEST_DIRS = {"test", "tests", "spec", "__tests__"}


def _is_test_rel(rel: str) -> bool:
    parts = [p.lower() for p in Path(rel).parts]
    if any(p in TEST_DIRS for p in parts[:-1]):
        return True
    name = parts[-1] if parts else ""
    return name.startswith("test_") or name.endswith("_test.py")


def _module_name(rel: str) -> str:
    p = rel.replace("\\", "/")
    if p.endswith("/__init__.py"):
        p = p[: -len("/__init__.py")]
    elif p.endswith(".py"):
        p = p[:-3]
    return p.replace("/", ".")


def _resolve_import_mod(cur_mod: str, raw_mod: str | None, level: int, *, is_pkg: bool = False) -> str:
    if level == 0:
        return raw_mod or ""
    parts = cur_mod.split(".") if cur_mod else []
    # Current package = parent of module (unless __init__, which is already a package)
    base = parts if is_pkg else (parts[:-1] if len(parts) > 0 else [])
    up = max(0, level - 1)
    prefix = base[: max(0, len(base) - up)]
    if raw_mod:
        return ".".join([*prefix, raw_mod]) if prefix else raw_mod
    return ".".join(prefix)


def _excerpt(lines: list[str], line_no: int) -> str:
    if not lines or line_no <= 0:
        return ""
    lo = max(0, line_no - 2)
    hi = min(len(lines), line_no + 2)
    return "\n".join(f"{i + 1}: {lines[i]}" for i in range(lo, hi))


def _fn_excerpt(lines: list[str], node: ast.AST, max_lines: int = 24) -> str:
    lineno = getattr(node, "lineno", 0)
    if not lines or lineno <= 0:
        return ""
    end_lineno = getattr(node, "end_lineno", lineno + 10) or (lineno + 10)
    lo = max(0, lineno - 1)
    hi = min(len(lines), lo + max_lines, end_lineno)
    return "\n".join(f"{i + 1}: {lines[i]}" for i in range(lo, hi))


def _load_config_values(canon: Path) -> dict[str, dict[str, Any]]:
    """Extract active string/bool/int config values from JSON, TOML, YAML, INI, ENV, and Python settings."""
    cfg: dict[str, dict[str, Any]] = {}
    for cur, dirs, files in os.walk(canon):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS and not d.startswith("."))
        for fname in sorted(files):
            fp = Path(cur) / fname
            rel = str(fp.relative_to(canon))
            if _is_test_rel(rel):
                continue
            low = fname.lower()
            try:
                text = fp.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if low.endswith(".json"):
                try:
                    data = json.loads(text)
                    if isinstance(data, dict):
                        for k, v in data.items():
                            if isinstance(v, (str, int, float, bool)):
                                cfg[str(k)] = {"value": v, "file": rel, "line": 1, "source": "json"}
                except Exception:
                    pass
            elif low.endswith((".yaml", ".yml", ".toml", ".ini", ".env")):
                for idx, raw in enumerate(text.splitlines(), 1):
                    m = re.match(r"^\s*([A-Za-z0-9_.-]+)\s*[:=]\s*[\"']?([^\"'#\n]+?)[\"']?\s*(?:#.*)?$", raw)
                    if m:
                        val: Any = m.group(2).strip()
                        if val.lower() in ("true", "false"):
                            val = val.lower() == "true"
                        cfg[m.group(1)] = {"value": val, "file": rel, "line": idx, "source": low.rsplit(".", 1)[-1]}
            elif low.endswith(".py"):
                try:
                    tree = ast.parse(text, filename=rel)
                except SyntaxError:
                    continue
                for node in tree.body:
                    if isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant):
                        if isinstance(node.value.value, (str, int, float, bool)):
                            for t in node.targets:
                                if isinstance(t, ast.Name) and t.id.isupper():
                                    cfg[t.id] = {"value": node.value.value, "file": rel, "line": node.lineno, "source": "py_const"}
                    elif isinstance(node, ast.Assign) and isinstance(node.value, ast.Dict):
                        for t in node.targets:
                            if isinstance(t, ast.Name) and any(h in t.id.lower() for h in ("config", "settings", "cfg")):
                                for k, v in zip(node.value.keys, node.value.values):
                                    if isinstance(k, ast.Constant) and isinstance(v, ast.Constant):
                                        cfg[str(k.value)] = {"value": v.value, "file": rel, "line": k.lineno, "source": "py_dict"}
    return cfg


def trace_symbol(symbol: str, root_raw: str | Path = ".", *, max_hops: int = 8) -> dict[str, Any]:
    """Trace an entry symbol across re-exports, shadowed handlers, and configuration dispatch."""
    canon = guard.read_guard(root_raw)
    cfg = _load_config_values(canon)

    # Index all production Python modules.
    mod_to_file: dict[str, str] = {}
    file_lines: dict[str, list[str]] = {}
    defs_by_name: dict[str, list[dict[str, Any]]] = {}
    defs_by_fq: dict[str, dict[str, Any]] = {}
    imports_by_mod: dict[str, dict[str, dict[str, Any]]] = {}
    dispatch_dicts: dict[str, dict[str, dict[str, Any]]] = {}  # mod -> dict_name -> {key: target_info}
    fn_bodies: dict[str, tuple[ast.FunctionDef | ast.AsyncFunctionDef, str, str]] = {}  # fq -> (ast_node, mod, rel)

    for cur, dirs, files in os.walk(canon):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS and not d.startswith("."))
        for fname in sorted(files):
            if not fname.endswith(".py"):
                continue
            fp = Path(cur) / fname
            rel = str(fp.relative_to(canon))
            if _is_test_rel(rel):
                continue
            try:
                text = fp.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            lines = text.splitlines()
            file_lines[rel] = lines
            mod = _module_name(rel)
            is_pkg = rel.endswith("__init__.py")
            mod_to_file[mod] = rel
            try:
                tree = ast.parse(text, filename=rel)
            except SyntaxError:
                continue

            mod_imps: dict[str, dict[str, Any]] = {}
            for node in tree.body:
                if isinstance(node, ast.ImportFrom):
                    src_mod = _resolve_import_mod(mod, node.module, node.level or 0, is_pkg=is_pkg)
                    for alias in node.names:
                        local = alias.asname or alias.name
                        mod_imps[local] = {
                            "src_mod": src_mod,
                            "orig_name": alias.name,
                            "local_name": local,
                            "file": rel,
                            "line": node.lineno,
                            "excerpt": _excerpt(lines, node.lineno),
                        }
                elif isinstance(node, ast.Import):
                    for alias in node.names:
                        local = alias.asname or alias.name.split(".")[0]
                        mod_imps[local] = {
                            "src_mod": alias.name,
                            "orig_name": "",
                            "local_name": local,
                            "file": rel,
                            "line": node.lineno,
                            "excerpt": _excerpt(lines, node.lineno),
                        }
                elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    fq = f"{mod}.{node.name}" if mod else node.name
                    dinfo = {
                        "name": node.name,
                        "fqname": fq,
                        "module": mod,
                        "file": rel,
                        "line": node.lineno,
                        "excerpt": _fn_excerpt(lines, node),
                    }
                    defs_by_name.setdefault(node.name, []).append(dinfo)
                    defs_by_fq[fq] = dinfo
                    fn_bodies[fq] = (node, mod, rel)
                elif isinstance(node, ast.Assign) and isinstance(node.value, ast.Dict):
                    for t in node.targets:
                        if isinstance(t, ast.Name):
                            mapping: dict[str, dict[str, Any]] = {}
                            for k, v in zip(node.value.keys, node.value.values):
                                if isinstance(k, ast.Constant) and isinstance(v, (ast.Name, ast.Attribute)):
                                    vname = v.id if isinstance(v, ast.Name) else f"{ast.unparse(v)}"
                                    mapping[str(k.value)] = {"target": vname, "file": rel, "line": k.lineno}
                            if mapping:
                                dispatch_dicts.setdefault(mod, {})[t.id] = mapping
            imports_by_mod[mod] = mod_imps

    def _resolve_target(cur_mod: str, name: str) -> tuple[dict[str, Any] | None, list[dict[str, Any]]]:
        """Follow local defs, imports, and package re-exports to the concrete definition."""
        hops: list[dict[str, Any]] = []
        visited: set[tuple[str, str]] = set()
        m, sym = cur_mod, name
        for _ in range(max_hops):
            if (m, sym) in visited:
                break
            visited.add((m, sym))
            fq = f"{m}.{sym}" if m else sym
            if fq in defs_by_fq:
                return defs_by_fq[fq], hops
            imp = (imports_by_mod.get(m) or {}).get(sym)
            if imp:
                hops.append({
                    "kind": "reexport_or_import",
                    "from_module": m,
                    "symbol": sym,
                    "to_module": imp["src_mod"],
                    "orig_name": imp["orig_name"],
                    "file": imp["file"],
                    "line": imp["line"],
                    "excerpt": imp["excerpt"],
                })
                if imp["orig_name"]:
                    m = imp["src_mod"]
                    sym = imp["orig_name"]
                else:
                    break
                continue
            break
        return None, hops

    # Locate starting definition(s).
    start_defs = defs_by_name.get(symbol, [])
    if not start_defs and "." in symbol:
        start_defs = [defs_by_fq[symbol]] if symbol in defs_by_fq else []
    if not start_defs:
        # Check if `symbol` is itself re-exported in an __init__.py or module.
        for mod, imps in imports_by_mod.items():
            if symbol in imps:
                resolved, hops = _resolve_target(mod, symbol)
                if resolved:
                    start_defs = [resolved]
                    break

    active_path: list[dict[str, Any]] = []
    disputed_edges: list[dict[str, Any]] = []
    inactive_candidates: list[dict[str, Any]] = []

    if not start_defs:
        return {
            "ok": True,
            "entry": symbol,
            "found": False,
            "active_path": [],
            "disputed_edges": [],
            "config_values": cfg,
            "same_named_symbols": {k: v for k, v in defs_by_name.items() if len(v) > 1},
        }

    cur_def = start_defs[0]
    active_path.append({
        "hop": 0,
        "kind": "entry_definition",
        "symbol": cur_def["name"],
        "module": cur_def["module"],
        "file": cur_def["file"],
        "line": cur_def["line"],
        "excerpt": cur_def["excerpt"],
    })

    seen_fq: set[str] = {cur_def["fqname"]}
    worklist: list[tuple[dict[str, Any], int]] = [(cur_def, 0)]
    final_impl = cur_def

    while worklist:
        cur_node_def, depth = worklist.pop(0)
        if depth >= max_hops:
            continue
        fq = cur_node_def["fqname"]
        if fq not in fn_bodies:
            continue
        fnode, fmod, frel = fn_bodies[fq]
        local_dispatches = dispatch_dicts.get(fmod) or {}

        # Sort AST nodes by source line so execution flow is preserved.
        nodes_ordered = sorted(ast.walk(fnode), key=lambda n: (getattr(n, "lineno", 0), getattr(n, "col_offset", 0)))
        for sub in nodes_ordered:
            # Case A: Dispatch dict lookup (either DISPATCH_TABLE[key](...) or h = DISPATCH_TABLE[key])
            dict_name = None
            key_expr = None
            if isinstance(sub, ast.Subscript) and isinstance(sub.value, ast.Name) and sub.value.id in local_dispatches:
                dict_name = sub.value.id
                key_expr = sub.slice
            elif (
                isinstance(sub, ast.Call)
                and isinstance(sub.func, ast.Attribute)
                and sub.func.attr == "get"
                and isinstance(sub.func.value, ast.Name)
                and sub.func.value.id in local_dispatches
                and sub.args
            ):
                dict_name = sub.func.value.id
                key_expr = sub.args[0]

            if dict_name:
                dmap = local_dispatches[dict_name]
                key_src = ast.unparse(key_expr) if key_expr is not None else ""
                selected_key = None
                cfg_ev = None
                for ck, cv in cfg.items():
                    if str(cv["value"]) in dmap and (ck in key_src or any(tok in ck.lower() for tok in ("handler", "mode", "impl", "pipeline", "active"))):
                        selected_key = str(cv["value"])
                        cfg_ev = {**cv, "key": ck}
                        break
                if selected_key is None:
                    for ck, cv in cfg.items():
                        if str(cv["value"]) in dmap:
                            selected_key = str(cv["value"])
                            cfg_ev = {**cv, "key": ck}
                            break
                if selected_key and selected_key in dmap:
                    chosen_name = dmap[selected_key]["target"]
                    resolved, re_hops = _resolve_target(fmod, chosen_name)
                    disputed_edges.append({
                        "kind": "config_dispatch",
                        "dispatch_table": dict_name,
                        "key_expr": key_src,
                        "selected_key": selected_key,
                        "config_evidence": cfg_ev,
                        "candidates": {k: v["target"] for k, v in dmap.items()},
                        "file": frel,
                        "line": getattr(sub, "lineno", fnode.lineno),
                    })
                    for k, v in dmap.items():
                        if k != selected_key:
                            inac, _ = _resolve_target(fmod, v["target"])
                            inactive_candidates.append({
                                "key": k,
                                "symbol": v["target"],
                                "file": inac["file"] if inac else v["file"],
                                "line": inac["line"] if inac else v["line"],
                                "excerpt": inac["excerpt"] if inac else _excerpt(file_lines.get(v["file"], []), v["line"]),
                                "reason": f"inactive config key '{k}' (active='{selected_key}')",
                            })
                    for rh in re_hops:
                        active_path.append({"hop": depth + 1, **rh})
                    if resolved and resolved["fqname"] not in seen_fq:
                        seen_fq.add(resolved["fqname"])
                        active_path.append({
                            "hop": depth + 1,
                            "kind": "resolved_implementation",
                            "symbol": resolved["name"],
                            "fqname": resolved["fqname"],
                            "module": resolved["module"],
                            "file": resolved["file"],
                            "line": resolved["line"],
                            "excerpt": resolved["excerpt"],
                        })
                        final_impl = resolved
                        worklist.append((resolved, depth + 1))
                continue

            if not isinstance(sub, ast.Call):
                continue

            # Case B: Direct call `callee(...)` or `mod.callee(...)`
            callee_name = None
            next_def = None
            re_hops: list[dict[str, Any]] = []
            if isinstance(sub.func, ast.Name):
                callee_name = sub.func.id
            elif isinstance(sub.func, ast.Attribute) and isinstance(sub.func.value, ast.Name):
                imp_m = (imports_by_mod.get(fmod) or {}).get(sub.func.value.id)
                if imp_m and not imp_m["orig_name"]:
                    cand_fq = f"{imp_m['src_mod']}.{sub.func.attr}"
                    if cand_fq in defs_by_fq and cand_fq not in seen_fq:
                        next_def = defs_by_fq[cand_fq]
            if callee_name and next_def is None:
                next_def, re_hops = _resolve_target(fmod, callee_name)
            if next_def and next_def["fqname"] not in seen_fq:
                seen_fq.add(next_def["fqname"])
                same_named = defs_by_name.get(next_def["name"], [])
                if len(same_named) > 1:
                    disputed_edges.append({
                        "kind": "same_named_symbol",
                        "symbol": next_def["name"],
                        "selected": next_def["fqname"],
                        "all_definitions": [{"fqname": d["fqname"], "file": d["file"], "line": d["line"]} for d in same_named],
                        "via_reexport": bool(re_hops),
                    })
                    for d in same_named:
                        if d["fqname"] != next_def["fqname"]:
                            inactive_candidates.append({
                                "symbol": d["name"],
                                "fqname": d["fqname"],
                                "file": d["file"],
                                "line": d["line"],
                                "excerpt": d["excerpt"],
                                "reason": f"not imported/selected by {frel}:{sub.lineno}",
                            })
                for rh in re_hops:
                    active_path.append({"hop": depth + 1, **rh})
                kind = "config_helper" if any(k in next_def["file"] for k in ("config", "settings", "env")) else "resolved_implementation"
                active_path.append({
                    "hop": depth + 1,
                    "kind": kind,
                    "symbol": next_def["name"],
                    "fqname": next_def["fqname"],
                    "module": next_def["module"],
                    "file": next_def["file"],
                    "line": next_def["line"],
                    "excerpt": next_def["excerpt"],
                })
                if kind == "resolved_implementation":
                    final_impl = next_def
                worklist.append((next_def, depth + 1))

    cur_def = final_impl

    return {
        "ok": True,
        "entry": symbol,
        "found": True,
        "evidence_complete": True,
        "active_implementation": cur_def,
        "active_path": active_path,
        "disputed_edges": disputed_edges,
        "inactive_candidates": inactive_candidates,
        "config_values": cfg,
        "same_named_symbols": {
            k: [{"fqname": d["fqname"], "file": d["file"], "line": d["line"]} for d in v]
            for k, v in defs_by_name.items() if len(v) > 1
        },
    }
