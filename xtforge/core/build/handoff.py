"""Handoff packets (F4): compact, budget-checked, machine-validatable."""
from __future__ import annotations

import json
from typing import Any

from ..compress import digest as dg
from ..compress.passes import est_tokens

REQUIRED_KEYS = ("from", "to", "objective", "decisions", "constraints",
                 "artifacts", "interfaces", "open_questions", "risks",
                 "next_actions", "digest")

LEVEL_BUDGET = {"L0": 3000, "L1": 2200, "L2": 1500}
DEFAULT_LEVEL = "L2"


def empty_packet(from_phase: str, to_phase: str, objective: str = "") -> dict[str, Any]:
    return {"from": from_phase, "to": to_phase, "objective": objective,
            "decisions": [], "constraints": [], "artifacts": [],
            "interfaces": [], "open_questions": [], "risks": [],
            "next_actions": [], "digest": dg.build(obj=objective or to_phase,
                                                   nxt="begin phase")}


def build_packet(from_phase: str, to_phase: str, phase_report: dict[str, Any],
                 level: str = DEFAULT_LEVEL, include: list[str] | None = None,
                 objective: str = "", extra_constraints: list[str] | None = None
                 ) -> dict[str, Any]:
    """Assemble a packet from a phase report. Budget-enforced and validated."""
    budget = LEVEL_BUDGET.get(level, LEVEL_BUDGET[DEFAULT_LEVEL])
    want = set(include or ["outputs", "decisions", "open_questions"])
    packet = empty_packet(from_phase, to_phase, objective)
    if "decisions" in want:
        packet["decisions"] = [str(d)[:160] for d in
                               (phase_report.get("decisions") or [])][:20]
    if extra_constraints:
        packet["constraints"] = [str(c)[:160] for c in extra_constraints][:20]
    if "outputs" in want:
        packet["artifacts"] = [
            {"path": o.get("path", ""), "digest": o.get("digest", "?"),
             "purpose": str(o.get("purpose", o.get("status", "")))[:80]}
            for o in (phase_report.get("outputs") or [])
            if isinstance(o, dict)][:30]
    packet["interfaces"] = [
        {"name": i.get("name", ""), "contract": str(i.get("contract", ""))[:200]}
        for i in (phase_report.get("interfaces") or [])
        if isinstance(i, dict)][:20]
    if "open_questions" in want:
        packet["open_questions"] = [str(q)[:160] for q in
                                    (phase_report.get("open_questions") or [])][:15]
    packet["risks"] = [str(r)[:160] for r in (phase_report.get("risks") or [])][:10]
    packet["next_actions"] = [str(a)[:160] for a in
                              (phase_report.get("next_actions") or [])][:10]
    files = [a["path"] for a in packet["artifacts"]]
    packet["digest"] = dg.build(
        obj=objective or packet.get("objective") or to_phase,
        done=f"{from_phase} complete" if from_phase else "none",
        files=",".join(files[:6]) if files else "none",
        decisions="; ".join(packet["decisions"][:3]) if packet["decisions"] else "none",
        errors=dg.tally_errors([str(e.get("sig", "")) for e in
                                (phase_report.get("errors") or [])
                                if isinstance(e, dict)]),
        nxt=packet["next_actions"][0] if packet["next_actions"] else "start phase",
        open_="; ".join(packet["open_questions"][:2]) if packet["open_questions"] else "none")
    trimmed, dropped = enforce_budget(packet, budget)
    trimmed["_budget_tokens"] = budget
    trimmed["_dropped"] = dropped
    return trimmed


def packet_tokens(packet: dict[str, Any]) -> int:
    return est_tokens(json.dumps(packet, ensure_ascii=False))


def enforce_budget(packet: dict[str, Any], budget: int) -> tuple[dict[str, Any], list[str]]:
    """Drop lowest-value fields until the packet fits. Never drops required keys."""
    out = dict(packet)
    dropped: list[str] = []
    for key in ("risks", "next_actions", "open_questions", "constraints"):
        if packet_tokens(out) <= budget:
            break
        if out.get(key):
            dropped.append(key)
            out[key] = []
    for key in ("interfaces", "artifacts"):
        while packet_tokens(out) > budget and out.get(key):
            dropped.append(f"{key}[-1]")
            out[key] = out[key][:-1]
    if packet_tokens(out) > budget and len(out.get("decisions") or []) > 1:
        out["decisions"] = out["decisions"][:1]
        dropped.append("decisions[extra]")
    out["digest"] = out.get("digest", "")[:400]
    return out, dropped


def validate(packet: dict[str, Any], budget: int | None = None) -> dict[str, Any]:
    """Validator: rejects packets missing keys or exceeding budget."""
    missing = [k for k in REQUIRED_KEYS if k not in packet]
    over = False
    tokens = packet_tokens(packet)
    if budget is not None and tokens > budget:
        over = True
    return {"valid": not missing and not over, "missing": missing,
            "over_budget": over, "tokens": tokens}


def incomplete(missing: list[str]) -> dict[str, Any]:
    return {"error": "phase_incomplete", "missing": missing}


def to_prompt_block(packet: dict[str, Any]) -> str:
    """Render the packet for injection into the next phase prompt."""
    if packet.get("error"):
        return f"HANDOFF PACKET: UNAVAILABLE — {packet.get('error')}: {', '.join(packet.get('missing', []))}"
    parts = [f"<handoff from=\"{packet['from']}\" to=\"{packet['to']}\">"]
    parts.append(f"OBJECTIVE: {packet.get('objective') or 'continue the build'}")
    if packet.get("decisions"):
        parts.append("DECISIONS:")
        parts += [f"  - {d}" for d in packet["decisions"]]
    if packet.get("constraints"):
        parts.append("CONSTRAINTS (must not be violated):")
        parts += [f"  - {c}" for c in packet["constraints"]]
    if packet.get("interfaces"):
        parts.append("INTERFACES:")
        parts += [f"  - {i['name']}: {i['contract']}" for i in packet["interfaces"]]
    if packet.get("artifacts"):
        parts.append("ARTIFACTS (by path):")
        parts += [f"  - {a['path']} [{a['digest']}] {a['purpose']}"
                  for a in packet["artifacts"]]
    if packet.get("open_questions"):
        parts.append("OPEN QUESTIONS:")
        parts += [f"  - {q}" for q in packet["open_questions"]]
    if packet.get("risks"):
        parts.append("RISKS:")
        parts += [f"  - {r}" for r in packet["risks"]]
    if packet.get("next_actions"):
        parts.append("NEXT ACTIONS:")
        parts += [f"  - {a}" for a in packet["next_actions"]]
    parts.append(f"DIGEST: {packet.get('digest', '')}")
    parts.append("</handoff>")
    return "\n".join(parts)