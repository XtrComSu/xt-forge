"""Recon workspace: a scoped findings ledger with reproducible reports.

Engagements generate notes, observations and findings faster than anyone
writes them up. This keeps the ledger as the source of truth and treats the
report as a build artifact: run it twice, get the same bytes.

    xtforge recon new example.com
    xtforge recon note example.com --text "cert expires in 12 days"
    xtforge recon finding example.com --severity high \
        --title "admin panel exposed" --evidence "https://example.com/admin"
    xtforge recon report example.com

Scope and safety:
- the target is a name, not a path: it is sanitised, so `../../etc` cannot
  escape the workspace
- every write lands under `$XT_HOME/recon/` and nowhere else
- the ledger is append-only JSONL, so history survives a rewrite
"""
from __future__ import annotations

import json
import re
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterable

from ...version import xt_home

SEVERITIES = ("critical", "high", "medium", "low", "info")
_SEVERITY_RANK = {name: index for index, name in enumerate(SEVERITIES)}
_TARGET_OK = re.compile(r"[^A-Za-z0-9._\-]+")
LEDGER_NAME = "findings.jsonl"
NOTES_NAME = "notes.jsonl"


@dataclass
class Finding:
    id: str
    target: str
    severity: str
    title: str
    detail: str = ""
    evidence: str = ""
    tags: list[str] = field(default_factory=list)
    created: int = 0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def sanitize_target(target: str) -> str:
    """A target is a label, never a path."""
    cleaned = _TARGET_OK.sub("_", (target or "").strip()).strip("._")
    if not cleaned:
        raise ValueError("target name is empty after sanitising")
    return cleaned[:80]


def target_dir(target: str) -> Path:
    return xt_home() / "recon" / sanitize_target(target)


def _append(path: Path, obj: dict[str, Any]) -> dict[str, Any]:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(obj, ensure_ascii=False, sort_keys=True) + "\n")
    return obj


def _read(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    out = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out


def init(target: str) -> dict[str, Any]:
    directory = target_dir(target)
    directory.mkdir(parents=True, exist_ok=True)
    (directory / LEDGER_NAME).touch(exist_ok=True)
    (directory / NOTES_NAME).touch(exist_ok=True)
    return {"ok": True, "target": sanitize_target(target), "path": str(directory)}


def add_finding(target: str, *, severity: str, title: str,
                detail: str = "", evidence: str = "",
                tags: Iterable[str] = (), now: int | None = None) -> dict[str, Any]:
    level = (severity or "info").strip().lower()
    if level not in _SEVERITY_RANK:
        raise ValueError(f"severity must be one of {SEVERITIES}")
    heading = " ".join((title or "").split())
    if not heading:
        raise ValueError("a finding needs a title")
    directory = target_dir(target)
    directory.mkdir(parents=True, exist_ok=True)
    ts = int(now if now is not None else time.time())
    seq = len(_read(directory / LEDGER_NAME)) + 1
    finding = Finding(
        id=f"{sanitize_target(target)}-{seq:04d}", target=sanitize_target(target),
        severity=level, title=heading[:160],
        detail=" ".join((detail or "").split())[:2000],
        evidence=(evidence or "").strip()[:500],
        tags=sorted({t.strip() for t in tags if t and t.strip()}),
        created=ts)
    _append(directory / LEDGER_NAME, finding.to_dict())
    return finding.to_dict()


def add_note(target: str, text: str, now: int | None = None) -> dict[str, Any]:
    body = " ".join((text or "").split())
    if not body:
        raise ValueError("a note needs text")
    directory = target_dir(target)
    directory.mkdir(parents=True, exist_ok=True)
    record = {"id": f"{sanitize_target(target)}-n"
                    f"{len(_read(directory / NOTES_NAME)) + 1:04d}",
              "target": sanitize_target(target), "text": body[:2000],
              "created": int(now if now is not None else time.time())}
    _append(directory / NOTES_NAME, record)
    return record


def ledger(target: str) -> dict[str, Any]:
    directory = target_dir(target)
    return {
        "target": sanitize_target(target),
        "findings": _read(directory / LEDGER_NAME),
        "notes": _read(directory / NOTES_NAME),
    }


def stats(target: str) -> dict[str, Any]:
    data = ledger(target)
    by_severity = {name: 0 for name in SEVERITIES}
    for finding in data["findings"]:
        by_severity[finding.get("severity", "info")] = \
            by_severity.get(finding.get("severity", "info"), 0) + 1
    return {"target": data["target"], "findings": len(data["findings"]),
            "notes": len(data["notes"]), "by_severity": by_severity}


def report(target: str) -> str:
    """Render the ledger as markdown. Deterministic: same ledger, same bytes."""
    data = ledger(target)
    name = data["target"]
    findings = sorted(
        data["findings"],
        key=lambda f: (_SEVERITY_RANK.get(f.get("severity", "info"), 9),
                       f.get("created", 0), f.get("id", "")))
    counts = {sev: sum(1 for f in findings if f.get("severity") == sev)
              for sev in SEVERITIES}

    lines = [
        f"# Recon report: {name}", "",
        f"- findings: {len(findings)}",
        f"- notes: {len(data['notes'])}",
        "- severity: " + ", ".join(f"{k} {v}" for k, v in counts.items() if v),
        "",
    ]
    if findings:
        lines.append("## Findings")
        lines.append("")
        for finding in findings:
            lines.append(f"### [{finding.get('severity', 'info')}] "
                         f"{finding.get('title', '')}")
            if finding.get("detail"):
                lines.append("")
                lines.append(finding["detail"])
            if finding.get("evidence"):
                lines.append("")
                lines.append(f"    evidence: {finding['evidence']}")
            if finding.get("tags"):
                lines.append("")
                lines.append("    tags: " + ", ".join(finding["tags"]))
            lines.append("")
    if data["notes"]:
        lines.append("## Notes")
        lines.append("")
        for note in sorted(data["notes"], key=lambda n: (n.get("created", 0),
                                                         n.get("id", ""))):
            lines.append(f"- {note.get('text', '')}")
        lines.append("")
    if not findings and not data["notes"]:
        lines.append("(empty ledger)")
        lines.append("")
    return "\n".join(lines)
