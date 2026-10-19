"""Workflow schema validator (F4). Hand-written, line-referenced errors.

YAML preferred, JSON accepted. PyYAML is optional; JSON workflows always work.
"""
from __future__ import annotations

import json
from typing import Any

PHASE_KEYS = {
    "id", "title", "prompt", "role", "tools", "inputs", "outputs", "gates",
    "max_rounds", "on_fail", "memory", "handoff", "needs", "when",
    "repeat_until", "extends", "model", "compress", "pause_for_human",
    "parallel_group", "thinking", "scope",
}
GATE_TYPES = {"file_exists", "cmd", "llm_verify", "json_valid", "not_empty"}
ON_FAIL_ACTIONS = {"halt", "skip", "goto", "ask"}
HANDOFF_LEVELS = {"L0", "L1", "L2"}
COMPRESS_LEVELS = {"L0", "L1", "L2", "L3"}
THINKING = {"off", "low", "high"}
# Build type 1 = standard (phases supplied up front); build type 2 = specbuild
# (the model surveys the project, authors the spec and every prompt, then the
# spec is materialized into a standard workflow).
BUILD_TYPES = {"standard", "specbuild"}


class WorkflowError(ValueError):
    def __init__(self, errors: list[str]):
        super().__init__("; ".join(errors))
        self.errors = errors


def parse(source: str) -> dict[str, Any]:
    """Parse YAML or JSON text into a dict. Raises WorkflowError on bad syntax."""
    text = source.strip()
    if not text:
        raise WorkflowError(["workflow file is empty"])
    if text.startswith("{"):
        try:
            return json.loads(text)
        except json.JSONDecodeError as exc:
            raise WorkflowError([f"line {exc.lineno}: invalid JSON: {exc.msg}"]) from exc
    try:
        import yaml  # type: ignore
    except ImportError:
        raise WorkflowError([
            "PyYAML not installed; install it (pkg install python-yaml) "
            "or use JSON format for this workflow"])
    try:
        data = yaml.safe_load(text)
    except Exception as exc:  # yaml raises many types
        line = getattr(exc, "problem_mark", None)
        where = f"line {line.line + 1}: " if line else ""
        raise WorkflowError([f"{where}{exc}"]) from exc
    if not isinstance(data, dict):
        raise WorkflowError(["workflow root must be a mapping"])
    return data


def validate(data: dict[str, Any]) -> list[str]:
    """Returns a list of human-readable errors; empty means valid."""
    errors: list[str] = []
    if "workflow" not in data:
        errors.append("missing required top-level key: workflow")
    elif not isinstance(data["workflow"], str):
        errors.append("workflow must be a string id")
    if "version" not in data:
        errors.append("missing required top-level key: version")
    elif not isinstance(data["version"], int):
        errors.append("version must be an integer")
    btype = data.get("type", "standard")
    if not isinstance(btype, str) or btype not in BUILD_TYPES:
        errors.append(f"type must be one of {sorted(BUILD_TYPES)}")
    if "vars" in data and not isinstance(data["vars"], dict):
        errors.append("vars must be a mapping")
    if "defaults" in data and not isinstance(data["defaults"], dict):
        errors.append("defaults must be a mapping")
    phases = data.get("phases")
    if not isinstance(phases, list) or not phases:
        errors.append("phases must be a non-empty list")
        return errors
    ids: list[str] = []
    for i, ph in enumerate(phases):
        prefix = f"phases[{i}]"
        if not isinstance(ph, dict):
            errors.append(f"{prefix} must be a mapping")
            continue
        pid = ph.get("id")
        if not pid:
            errors.append(f"{prefix} missing required key: id")
        elif not isinstance(pid, str):
            errors.append(f"{prefix} id must be a string")
        else:
            ids.append(pid)
            prefix = f"phase '{pid}'"
        unknown = set(ph) - PHASE_KEYS
        for k in sorted(unknown):
            errors.append(f"{prefix} unknown key: {k}")
        if not ph.get("prompt"):
            errors.append(f"{prefix} missing required key: prompt")
        for listkey in ("tools", "inputs", "outputs", "needs"):
            v = ph.get(listkey)
            if v is not None and not isinstance(v, list):
                errors.append(f"{prefix} {listkey} must be a list")
        if "max_rounds" in ph and not isinstance(ph["max_rounds"], int):
            errors.append(f"{prefix} max_rounds must be an integer")
        if "compress" in ph and ph["compress"] not in COMPRESS_LEVELS:
            errors.append(f"{prefix} compress must be one of {sorted(COMPRESS_LEVELS)}")
        if "thinking" in ph and ph["thinking"] not in THINKING:
            errors.append(f"{prefix} thinking must be one of {sorted(THINKING)}")
        if "on_fail" in ph:
            of = ph["on_fail"]
            if not isinstance(of, dict):
                errors.append(f"{prefix} on_fail must be a mapping")
            else:
                action = of.get("then")
                if action is not None:
                    base = str(action).split(":", 1)[0]
                    if base not in ON_FAIL_ACTIONS:
                        errors.append(
                            f"{prefix} on_fail.then must be one of "
                            f"{sorted(ON_FAIL_ACTIONS)} or goto:<phase>")
                if "retry" in of and not isinstance(of["retry"], int):
                    errors.append(f"{prefix} on_fail.retry must be an integer")
        if "handoff" in ph:
            h = ph["handoff"]
            if not isinstance(h, dict):
                errors.append(f"{prefix} handoff must be a mapping")
            else:
                if h.get("level") and h["level"] not in HANDOFF_LEVELS:
                    errors.append(f"{prefix} handoff.level must be one of {sorted(HANDOFF_LEVELS)}")
                if "include" in h and not isinstance(h["include"], list):
                    errors.append(f"{prefix} handoff.include must be a list")
        errors += _validate_gates(ph, prefix)
    if len(set(ids)) != len(ids):
        dupes = sorted({i for i in ids if ids.count(i) > 1})
        errors.append(f"duplicate phase ids: {dupes}")
    idset = set(ids)
    for ph in phases:
        if not isinstance(ph, dict):
            continue
        pid = ph.get("id")
        for need in (ph.get("needs") or []):
            if need not in idset:
                errors.append(f"phase '{pid}' needs unknown phase: {need}")
            if need == pid:
                errors.append(f"phase '{pid}' cannot need itself")
    errors += check_dag(phases)
    return errors


def _validate_gates(ph: dict[str, Any], prefix: str) -> list[str]:
    errors: list[str] = []
    gates = ph.get("gates")
    if gates is None:
        return errors
    if not isinstance(gates, list):
        return [f"{prefix} gates must be a list"]
    for i, g in enumerate(gates):
        if not isinstance(g, dict):
            errors.append(f"{prefix} gates[{i}] must be a mapping")
            continue
        gtype = g.get("type")
        if not gtype:
            errors.append(f"{prefix} gates[{i}] missing type")
            continue
        if gtype not in GATE_TYPES:
            errors.append(f"{prefix} gates[{i}].type '{gtype}' not in {sorted(GATE_TYPES)}")
            continue
        if gtype == "file_exists" and not g.get("path"):
            errors.append(f"{prefix} gates[{i}] file_exists needs path")
        if gtype in {"cmd", "json_valid"} and gtype == "cmd" and not g.get("run"):
            errors.append(f"{prefix} gates[{i}] cmd needs run")
        if gtype == "json_valid" and not g.get("path"):
            errors.append(f"{prefix} gates[{i}] json_valid needs path")
        if gtype == "llm_verify":
            if not g.get("prompt"):
                errors.append(f"{prefix} gates[{i}] llm_verify needs prompt")
            else:
                # A missing prompt file only fails at run time ("gate prompt
                # invalid"); surface it at lint time instead.
                from .. import prompts as promptmod
                try:
                    promptmod.prompt_path(str(g["prompt"]))
                except promptmod.PromptError as exc:
                    errors.append(f"{prefix} gates[{i}] {exc}")
            if "pass_score" in g and not isinstance(g["pass_score"], (int, float)):
                errors.append(f"{prefix} gates[{i}].pass_score must be a number")
        if "expect_exit" in g and not isinstance(g["expect_exit"], int):
            errors.append(f"{prefix} gates[{i}].expect_exit must be an integer")
    return errors


def check_dag(phases: list[dict[str, Any]]) -> list[str]:
    """Cycle detection over needs. Returns errors; empty means acyclic."""
    graph: dict[str, list[str]] = {}
    for ph in phases:
        if not isinstance(ph, dict) or not ph.get("id"):
            continue
        graph[ph["id"]] = [n for n in (ph.get("needs") or []) if n in graph or True]
    state: dict[str, int] = {}  # 0 unvisited, 1 in-stack, 2 done
    errors: list[str] = []

    def visit(node: str, stack: list[str]) -> None:
        if state.get(node) == 2:
            return
        if state.get(node) == 1:
            cycle = stack[stack.index(node):] + [node] if node in stack else stack + [node]
            errors.append(f"cycle in needs: {' -> '.join(cycle)}")
            return
        state[node] = 1
        for dep in graph.get(node, []):
            if dep in graph:
                visit(dep, stack + [node])
        state[node] = 2

    for node in graph:
        visit(node, [])
    return errors


def topo_order(phases: list[Any]) -> list[str]:
    """Kahn's algorithm; ties broken by declaration order for determinism."""
    def _id(p: Any) -> str:
        return p["id"] if isinstance(p, dict) else p.id

    def _needs(p: Any) -> list[str]:
        return list((p.get("needs") if isinstance(p, dict) else p.needs) or [])

    graph = {_id(p): _needs(p) for p in phases}
    order: list[str] = []
    done: set[str] = set()
    while len(order) < len(graph):
        ready = [pid for pid, deps in graph.items()
                 if pid not in order and all(d in done for d in deps)]
        if not ready:
            raise WorkflowError(["cycle in needs: no phase is ready"])
        pick = next(_id(p) for p in phases if _id(p) in ready)
        order.append(pick)
        done.add(pick)
    return order


def graph_ascii(phases: list[Any]) -> str:
    """ASCII DAG rendering for `build graph`."""
    def _id(p: Any) -> str:
        return p["id"] if isinstance(p, dict) else p.id

    def _needs(p: Any) -> list[str]:
        return list((p.get("needs") if isinstance(p, dict) else p.needs) or [])

    plain = [{"id": _id(p), "needs": _needs(p)} for p in phases]
    order = topo_order(plain) if not check_dag(plain) else [_id(p) for p in phases]
    lines: list[str] = ["workflow:"]
    idx = {pid: i for i, pid in enumerate(order)}
    for i, pid in enumerate(order):
        deps = next(_needs(p) for p in phases if _id(p) == pid)
        arrow = f"  (needs: {', '.join(deps)})" if deps else ""
        lines.append(f"  [{i}] {pid}{arrow}")
        for dep in deps:
            if dep in idx:
                lines.append(f"      ^ from [{idx[dep]}] {dep}")
    return "\n".join(lines)