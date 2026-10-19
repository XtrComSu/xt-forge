"""Spec-build (build type 2): the model authors a build spec, we materialize it.

A specbuild run surveys the project, writes `spec.json` (which phases exist,
what each one owns, which gates prove it, which model/budget it gets) and the
PROMPT_SPEC file for every phase. This module is the deterministic half: it
validates that spec, checks every referenced prompt, and renders a workflow the
standard runner can execute.
"""
from __future__ import annotations

import importlib.util
import json
import re
from pathlib import Path
from typing import Any

from ...version import project_root
from . import schema

SPEC_VERSION = 1
SPEC_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]*")
REQUIRED_KEYS = ("spec", "version", "project", "phases")
SPEC_KEYS = set(REQUIRED_KEYS) | {"type", "vars", "defaults", "decisions"}
PROJECT_KEYS = {"name", "stack", "style", "root"}
MAX_PHASES = 32
DEFAULTS = {"model": "inherit", "max_rounds": 6, "compress": "L2",
            "thinking": "low", "reset": True, "budget_tokens": 120000}


class SpecError(ValueError):
    def __init__(self, errors: list[str]):
        super().__init__("; ".join(errors))
        self.errors = errors


def load_spec(path: str | Path) -> dict[str, Any]:
    p = Path(path)
    if not p.is_file():
        raise SpecError([f"spec not found: {p}"])
    try:
        data = schema.parse(p.read_text(encoding="utf-8"))
    except schema.WorkflowError as exc:
        raise SpecError(exc.errors) from exc
    if not isinstance(data, dict):
        raise SpecError([f"{p}: spec root must be a mapping"])
    return data


def validate_spec(data: dict[str, Any]) -> list[str]:
    """Spec-level errors; phase semantics are re-checked on the workflow."""
    errors: list[str] = []
    for key in REQUIRED_KEYS:
        if key not in data:
            errors.append(f"missing required key: {key}")
    for key in sorted(set(data) - SPEC_KEYS):
        errors.append(f"unknown key: {key}")
    sid = data.get("spec")
    if sid is not None:
        if not isinstance(sid, str) or not SPEC_ID_RE.fullmatch(sid):
            errors.append(f"spec must match {SPEC_ID_RE.pattern}, got {sid!r}")
    if data.get("version") not in (SPEC_VERSION, None):
        errors.append(f"version must be {SPEC_VERSION}")
    btype = data.get("type", "standard")
    if btype not in schema.BUILD_TYPES:
        errors.append(f"type must be one of {sorted(schema.BUILD_TYPES)}")
    project = data.get("project")
    if project is not None:
        if not isinstance(project, dict):
            errors.append("project must be a mapping")
        else:
            if not str(project.get("name") or "").strip():
                errors.append("project.name is required (what is being built?)")
            for key in sorted(set(project) - PROJECT_KEYS):
                errors.append(f"project unknown key: {key}")
            for key in sorted(set(project) & PROJECT_KEYS):
                if not isinstance(project[key], str):
                    errors.append(f"project.{key} must be a string")
    for key in ("vars", "defaults"):
        if key in data and not isinstance(data[key], dict):
            errors.append(f"{key} must be a mapping")
    if "decisions" in data and not isinstance(data["decisions"], list):
        errors.append("decisions must be a list of strings")
    phases = data.get("phases")
    if not isinstance(phases, list) or not phases:
        errors.append("phases must be a non-empty list")
        return errors
    if len(phases) > MAX_PHASES:
        errors.append(f"phases has {len(phases)} entries, max {MAX_PHASES}")
    ids: list[str] = []
    for i, ph in enumerate(phases):
        prefix = f"phases[{i}]"
        if not isinstance(ph, dict):
            errors.append(f"{prefix} must be a mapping")
            continue
        pid = ph.get("id")
        if not isinstance(pid, str) or not pid:
            errors.append(f"{prefix} missing required key: id")
        else:
            ids.append(pid)
            prefix = f"phase '{pid}'"
        if not str(ph.get("prompt") or "").strip():
            errors.append(f"{prefix} missing required key: prompt")
        if not str(ph.get("scope") or "").strip():
            errors.append(f"{prefix} missing required key: scope "
                          "(one line: what this phase owns)")
        if not str(ph.get("title") or "").strip():
            errors.append(f"{prefix} missing required key: title")
        unknown = set(ph) - schema.PHASE_KEYS
        for key in sorted(unknown):
            errors.append(f"{prefix} unknown key: {key}")
        if "outputs" in ph and not isinstance(ph["outputs"], list):
            errors.append(f"{prefix} outputs must be a list")
        if not ph.get("outputs"):
            errors.append(f"{prefix} outputs must name at least one artifact "
                          "(a phase with nothing to prove is not a phase)")
    if len(set(ids)) != len(ids):
        dupes = sorted({i for i in ids if ids.count(i) > 1})
        errors.append(f"duplicate phase ids: {dupes}")
    return errors


def check_prompts(data: dict[str, Any]) -> list[str]:
    """Every phase prompt must exist and pass PROMPT_SPEC."""
    from .. import prompts
    errors: list[str] = []
    for i, ph in enumerate(data.get("phases") or []):
        if not isinstance(ph, dict):
            continue
        pid = ph.get("id", f"phases[{i}]")
        name = ph.get("prompt")
        if not isinstance(name, str) or not name:
            continue
        try:
            path = prompts.prompt_path(name)
        except prompts.PromptError as exc:
            errors.append(f"phase '{pid}': {exc}")
            continue
        for problem in prompt_lint(path):
            errors.append(f"phase '{pid}' prompt {name}: {problem}")
    return errors


def prompt_lint(path: Path) -> list[str]:
    """PROMPT_SPEC problems for one file (empty list = passes)."""
    script = project_root() / "scripts" / "prompt_lint.py"
    try:
        spec = importlib.util.spec_from_file_location("_xt_prompt_lint", script)
        if spec is None or spec.loader is None:
            raise ImportError("no loader")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return list(mod.lint_file(path))
    except Exception as exc:  # linter broken must fail the gate, not pass it
        return [f"prompt linter unavailable: {exc}"]


def spec_to_workflow(data: dict[str, Any]) -> dict[str, Any]:
    """Render the spec as a workflow dict (schema.validate must accept it)."""
    project = data.get("project") or {}
    defaults = dict(DEFAULTS)
    defaults.update(data.get("defaults") or {})
    phases = []
    for raw in data.get("phases") or []:
        if not isinstance(raw, dict):
            continue
        ph = {k: v for k, v in raw.items() if k in schema.PHASE_KEYS}
        ph.setdefault("title", ph.get("id", ""))
        ph.setdefault("tools", [])
        ph.setdefault("inputs", [])
        ph.setdefault("outputs", [])
        ph.setdefault("gates", [])
        ph.setdefault("needs", [])
        ph.setdefault("handoff", {"to": "next-phase", "level": "L2",
                                  "include": ["outputs", "decisions",
                                              "open_questions"]})
        ph.setdefault("on_fail", {"retry": 1, "then": "halt"})
        phases.append(ph)
    vars_: dict[str, Any] = {"product": str(project.get("name") or "the product"),
                             "stack": str(project.get("stack") or ""),
                             "style": str(project.get("style") or ""),
                             "root": str(project.get("root") or ".")}
    vars_.update(data.get("vars") or {})
    wf: dict[str, Any] = {
        "workflow": str(data.get("spec") or "specbuild-out"),
        "version": 1,
        "type": str(data.get("type", "standard")),
        "vars": vars_,
        "defaults": defaults,
        "phases": phases,
    }
    if data.get("decisions"):
        wf["vars"]["spec_decisions"] = " | ".join(str(d) for d in data["decisions"])
    return wf


def default_out(spec_id: str) -> Path:
    return project_root() / "workflows" / f"{spec_id}.yaml"


def materialize(data: dict[str, Any], out: str | Path | None = None
                ) -> dict[str, Any]:
    """Validate + write the workflow. Raises SpecError with every problem."""
    errors = validate_spec(data)
    if not errors:
        errors += check_prompts(data)
    if errors:
        raise SpecError(errors)
    wf = spec_to_workflow(data)
    wf_errors = schema.validate(wf)
    if wf_errors:
        raise SpecError([f"materialized workflow: {e}" for e in wf_errors])
    target = Path(out) if out else default_out(str(data["spec"]))
    _write(target, wf)
    return {"ok": True, "spec": str(data["spec"]), "type": wf["type"],
            "out": str(target), "phases": [p["id"] for p in wf["phases"]]}


def check_only(data: dict[str, Any]) -> dict[str, Any]:
    """Validate spec + prompts and lint what the workflow WOULD be; writes nothing."""
    errors = validate_spec(data)
    if not errors:
        errors += check_prompts(data)
    wf = spec_to_workflow(data) if not errors else {}
    if wf:
        errors += [f"materialized workflow: {e}" for e in schema.validate(wf)]
    if errors:
        raise SpecError(errors)
    return {"ok": True, "spec": str(data["spec"]), "type": wf["type"],
            "phases": [p["id"] for p in wf["phases"]], "writes": False}


def _write(path: Path, wf: dict[str, Any]) -> None:
    from ...atomicio import atomic_write_text
    path.parent.mkdir(parents=True, exist_ok=True)
    text = None
    try:
        import yaml  # type: ignore
        text = yaml.safe_dump(wf, sort_keys=False, allow_unicode=True)
    except ImportError:
        text = json.dumps(wf, indent=2, ensure_ascii=False) + "\n"
    atomic_write_text(path, text)
