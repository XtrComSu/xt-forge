"""Workflow loader (F4): YAML/JSON -> validated Workflow, safe templating.

`when:` conditions use a tiny comparison evaluator, never eval().
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ...version import project_root
from . import schema

WORKFLOW_DIRS = [project_root() / "workflows"]
_VAR = re.compile(r"\{\{\s*([a-zA-Z_][a-zA-Z0-9_.]*)\s*\}\}")
_CMP = re.compile(r"^\s*(?P<lhs>.+?)\s*(?P<op>==|!=|>=|<=|>|<)\s*(?P<rhs>.+?)\s*$")


class TemplateError(ValueError):
    pass


def _lookup(name: str, variables: dict[str, Any]) -> Any:
    cur: Any = variables
    for part in name.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return ""
    return cur


def render(template: str, variables: dict[str, Any]) -> str:
    """Substitute {{var}} / {{a.b}} references. Missing keys become empty."""
    return _VAR.sub(lambda m: str(_lookup(m.group(1), variables)), template or "")


def evaluate_condition(expr: str, variables: dict[str, Any]) -> bool:
    """Safe evaluator for `when:` — comparisons only, no eval(), no calls."""
    if not expr:
        return True
    rendered = render(expr, variables).strip()
    m = _CMP.match(rendered)
    if not m:
        val = _lookup(rendered, variables) if "{{" not in expr else rendered
        return bool(val)
    lhs = _coerce(m.group("lhs").strip())
    rhs = _coerce(m.group("rhs").strip())
    op = m.group("op")
    try:
        if op == "==":
            return lhs == rhs
        if op == "!=":
            return lhs != rhs
        if op == ">":
            return lhs > rhs
        if op == "<":
            return lhs < rhs
        if op == ">=":
            return lhs >= rhs
        if op == "<=":
            return lhs <= rhs
    except TypeError:
        return False
    return False


def _coerce(token: str) -> Any:
    t = token.strip().strip("'\"")
    if t.lower() in {"true", "yes"}:
        return True
    if t.lower() in {"false", "no"}:
        return False
    if t.lower() in {"null", "none", ""}:
        return None
    try:
        return int(t)
    except ValueError:
        pass
    try:
        return float(t)
    except ValueError:
        return t


@dataclass
class Phase:
    id: str
    title: str = ""
    prompt: str = ""
    role: str = "default"
    tools: list[str] = field(default_factory=list)
    inputs: list[str] = field(default_factory=list)
    outputs: list[str] = field(default_factory=list)
    gates: list[dict[str, Any]] = field(default_factory=list)
    max_rounds: int = 6
    on_fail: dict[str, Any] = field(default_factory=dict)
    memory: dict[str, Any] = field(default_factory=dict)
    handoff: dict[str, Any] = field(default_factory=dict)
    needs: list[str] = field(default_factory=list)
    when: str = ""
    repeat_until: str = ""
    model: str = "inherit"
    compress: str = "L2"
    pause_for_human: bool = False
    parallel_group: str = ""
    thinking: str = "low"
    scope: str = ""

    @property
    def gate_summary(self) -> str:
        if not self.gates:
            return "none"
        return ", ".join(str(g.get("type")) for g in self.gates)


@dataclass
class Workflow:
    id: str
    version: int
    vars: dict[str, Any]
    defaults: dict[str, Any]
    phases: list[Phase]
    type: str = "standard"
    path: Path | None = None

    def phase(self, pid: str) -> Phase | None:
        return next((p for p in self.phases if p.id == pid), None)

    def order(self) -> list[str]:
        return schema.topo_order(self.phases)

    def extend_vars(self, overrides: dict[str, Any]) -> dict[str, Any]:
        v = dict(self.vars)
        v.update({k: val for k, val in overrides.items() if val is not None})
        return v


def find_workflow(name: str) -> Path | None:
    """Locate a workflow file by id or path."""
    direct = Path(name)
    if direct.exists() and direct.is_file():
        return direct
    for d in WORKFLOW_DIRS:
        for ext in ("yaml", "yml", "json"):
            p = d / f"{name}.{ext}"
            if p.exists():
                return p
    return None


def list_workflows() -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    seen: set[str] = set()
    for d in WORKFLOW_DIRS:
        if not d.exists():
            continue
        for p in sorted(d.iterdir()):
            if p.stem.startswith("_"):
                continue
            if p.suffix in {".yaml", ".yml", ".json"} and p.stem not in seen:
                seen.add(p.stem)
                out.append({"id": p.stem, "path": str(p), "type": _type_of(p)})
    return out


def _type_of(path: Path) -> str:
    """Workflow build type: standard (1) or specbuild (2). Unreadable = unknown."""
    try:
        data = schema.parse(path.read_text(encoding="utf-8"))
    except (OSError, schema.WorkflowError, ValueError):
        return "unknown"
    btype = data.get("type", "standard")
    return btype if isinstance(btype, str) else "unknown"


def parse_phase(raw: dict[str, Any], defaults: dict[str, Any]) -> Phase:
    def d(key: str, fallback: Any) -> Any:
        if key in raw:
            return raw[key]
        return defaults.get(key, fallback)

    return Phase(
        id=raw["id"],
        title=raw.get("title", raw["id"]),
        prompt=raw["prompt"],
        role=raw.get("role", "default"),
        tools=list(raw.get("tools") or []),
        inputs=list(raw.get("inputs") or []),
        outputs=list(raw.get("outputs") or []),
        gates=list(raw.get("gates") or []),
        max_rounds=int(d("max_rounds", 6)),
        on_fail=dict(raw.get("on_fail") or {}),
        memory=dict(raw.get("memory") or {}),
        handoff=dict(raw.get("handoff") or {}),
        needs=list(raw.get("needs") or []),
        when=raw.get("when", ""),
        repeat_until=raw.get("repeat_until", ""),
        model=raw.get("model", defaults.get("model", "inherit")),
        compress=raw.get("compress", defaults.get("compress", "L2")),
        pause_for_human=bool(raw.get("pause_for_human", False)),
        parallel_group=raw.get("parallel_group", ""),
        thinking=raw.get("thinking", defaults.get("thinking", "low")),
        scope=raw.get("scope", ""),
    )


def load(path_or_name: str, overrides: dict[str, Any] | None = None,
         strict: bool = True) -> Workflow:
    path = find_workflow(path_or_name)
    if path is None:
        raise schema.WorkflowError([f"workflow not found: {path_or_name}"])
    data = schema.parse(path.read_text(encoding="utf-8"))
    errors = schema.validate(data)
    if errors and strict:
        raise schema.WorkflowError([f"{path.name}: {e}" for e in errors])
    defaults = data.get("defaults") or {}
    phases = [parse_phase(p, defaults) for p in data["phases"]]
    wf = Workflow(id=data["workflow"], version=int(data["version"]),
                  vars=dict(data.get("vars") or {}), defaults=defaults,
                  phases=phases, type=str(data.get("type", "standard")),
                  path=path)
    if overrides:
        wf.vars = wf.extend_vars(overrides)
    return wf


def parse_var_assignments(items: list[str]) -> dict[str, Any]:
    """--var k=v pairs into a dict."""
    out: dict[str, Any] = {}
    for item in items or []:
        if "=" not in item:
            raise TemplateError(f"--var expects k=v, got {item!r}")
        k, v = item.split("=", 1)
        out[k.strip()] = _coerce(v)
    return out


def phase_prompt(wf: Workflow, phase: Phase, handoff_packet: str = "",
                 extra_vars: dict[str, Any] | None = None,
                 handoff_block: str | None = None) -> str:
    """Render a phase prompt file with workflow vars + handoff packet.

    `handoff_packet` is a dict; `handoff_block` is already-rendered text.
    """
    from .. import prompts
    block = handoff_block
    if block is None and handoff_packet:
        from .handoff import to_prompt_block
        block = to_prompt_block(handoff_packet) if isinstance(handoff_packet, dict) \
            else str(handoff_packet)
    variables = dict(wf.vars)
    variables.update({
        "phase_id": phase.id, "phase_title": phase.title or phase.id,
        "role": phase.role, "product": wf.vars.get("product", "the product"),
        "outputs": ", ".join(phase.outputs) or "none",
        "gates_summary": phase.gate_summary,
        "scope": phase.scope or f"the {phase.title or phase.id} phase",
        "tools": ", ".join(phase.tools) or "default tools",
        "max_rounds": phase.max_rounds,
        "handoff": block or "(no handoff: first phase)",
    })
    if extra_vars:
        variables.update(extra_vars)
    return prompts.render(phase.prompt, **variables)


def validate_all(directory: str | Path | None = None) -> dict[str, list[str]]:
    """Validate every workflow file; returns {filename: [errors]}."""
    dirs = [Path(directory)] if directory else WORKFLOW_DIRS
    out: dict[str, list[str]] = {}
    for d in dirs:
        if not d.exists():
            continue
        for p in sorted(d.iterdir()):
            if p.suffix not in {".yaml", ".yml", ".json"} or p.stem.startswith("_"):
                continue
            try:
                data = schema.parse(p.read_text(encoding="utf-8"))
                errs = schema.validate(data)
            except schema.WorkflowError as exc:
                errs = exc.errors
            out[p.name] = errs
    return out