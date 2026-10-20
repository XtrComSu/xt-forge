"""Completion protocol: `<goal-done>` markers with independently replayed proof.

A goal is `achieved` only when the claim survives checks the agent does not
control. Self-reported "done" is never sufficient.

    <goal-done>
      <claim>All 42 tests pass and the migration is complete.</claim>
      <evidence>
        <item cmd="python3 -m unittest discover -s tests" exit="0">148 tests OK</item>
        <item file="xtforge/core/taste/store.py" change="added taste ingest"/>
      </evidence>
    </goal-done>

Five checks, in order:

  1. marker      well-formed claim plus at least one evidence item
  2. replay      claimed commands are re-run and their exit codes compared
  3. files       claimed files exist inside the workspace
  4. criteria    every user criterion has evidence that verifies
  5. integrity   escapes, cwd switches and self-serving test edits

A command is only replayed when it is explicitly approved: the goal's verify
command, or a member of the approved list. An unapproved command is not proof
and is never executed — that is the difference between verification and an
arbitrary shell.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable

MARKER = re.compile(r"<goal-done\b[^>]*>(.*?)</goal-done>", re.DOTALL)
CLAIM = re.compile(r"<claim>(.*?)</claim>", re.DOTALL)
ITEM = re.compile(r"<item\b([^>]*?)(?:/>|>(.*?)</item>)", re.DOTALL)
ATTR = re.compile(r"(\w+)\s*=\s*\"([^\"]*)\"")
CRITERIA = re.compile(r"<criterion>(.*?)</criterion>", re.DOTALL)

DEFAULT_TIMEOUT = 120
MAX_OUTPUT = 8192
MAX_REJECTIONS = 3

VERDICT_PASS = "pass"
VERDICT_REJECT = "reject"
VERDICT_INSUFFICIENT = "insufficient_evidence"


@dataclass
class Evidence:
    cmd: str | None = None
    exit: int | None = None
    file: str | None = None
    change: str | None = None
    body: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"cmd": self.cmd, "exit": self.exit, "file": self.file,
                "change": self.change, "body": self.body}


@dataclass
class Completion:
    claim: str = ""
    evidence: list[Evidence] = field(default_factory=list)
    criteria: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {"claim": self.claim,
                "evidence": [item.to_dict() for item in self.evidence],
                "criteria": list(self.criteria)}


def parse_marker(text: str) -> tuple[Completion | None, list[str]]:
    """Extract a completion claim. Returns (completion, problems)."""
    if not text or not text.strip():
        return None, ["no completion marker found"]
    match = MARKER.search(text)
    if not match:
        return None, ["no <goal-done> block found"]
    block = match.group(1)
    problems: list[str] = []

    claim_match = CLAIM.search(block)
    claim = " ".join(claim_match.group(1).split()) if claim_match else ""
    if not claim:
        problems.append("marker has no <claim>")

    criteria = [" ".join(item.split()) for item in CRITERIA.findall(text)]
    evidence: list[Evidence] = []
    for attrs, body in ITEM.findall(block):
        parsed = dict(ATTR.findall(attrs))
        item = Evidence(
            cmd=parsed.get("cmd"),
            exit=int(parsed["exit"]) if parsed.get("exit", "").lstrip("-").isdigit()
            else None,
            file=parsed.get("file"),
            change=parsed.get("change"),
            body=" ".join((body or "").split())[:400],
        )
        if not item.cmd and not item.file:
            problems.append("evidence item has neither cmd nor file")
            continue
        if item.cmd and item.exit is None:
            problems.append(f"evidence command has no exit code: {item.cmd}")
            continue
        evidence.append(item)

    if not evidence:
        problems.append("marker has no evidence items")
    return Completion(claim=claim, evidence=evidence, criteria=criteria), problems


def _inside_workspace(path: Path, workspace: Path) -> bool:
    try:
        path.resolve().relative_to(workspace.resolve())
        return True
    except (ValueError, OSError):
        return False


def _default_run(cmd: str, cwd: str | None = None,
                 timeout: int = DEFAULT_TIMEOUT) -> dict[str, Any]:
    import subprocess
    try:
        proc = subprocess.run(cmd, shell=True, cwd=cwd, capture_output=True,
                              text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return {"exit": None, "tail": f"timed out after {timeout}s"}
    except OSError as exc:
        return {"exit": None, "tail": str(exc)}
    out = (proc.stdout or "") + (proc.stderr or "")
    return {"exit": proc.returncode, "tail": out[-MAX_OUTPUT:]}


def verify_completion(completion: Completion | str,
                      *, workspace: str | Path = ".",
                      criteria: Iterable[str] = (),
                      approved_cmds: Iterable[str] = (),
                      verify_cmd: str | None = None,
                      baseline: dict[str, str] | None = None,
                      run: Callable[..., dict[str, Any]] | None = None,
                      timeout: int = DEFAULT_TIMEOUT) -> dict[str, Any]:
    """Verify a completion claim. Deterministic given the same inputs."""
    problems: list[str] = []
    if isinstance(completion, str):
        completion, problems = parse_marker(completion)

    root = Path(workspace)
    runner = run or _default_run
    approved = {cmd.strip() for cmd in approved_cmds if cmd and cmd.strip()}
    if verify_cmd:
        approved.add(verify_cmd.strip())
    wanted_criteria = [c.strip() for c in criteria if c and c.strip()]
    if completion is not None and completion.criteria:
        wanted_criteria = list(dict.fromkeys(wanted_criteria + completion.criteria))

    result: dict[str, Any] = {
        "ok": False,
        "verdict": VERDICT_INSUFFICIENT,
        "claim": completion.claim if completion else "",
        "gaps": list(problems),
        "checks": {},
    }
    if completion is None:
        result["checks"]["marker"] = {"ok": False, "problems": problems}
        return result

    # 1. marker ------------------------------------------------------------
    marker_ok = not problems
    result["checks"]["marker"] = {"ok": marker_ok, "problems": problems}
    if not marker_ok:
        result["gaps"].append("completion marker is not well-formed")

    # 2. replay ------------------------------------------------------------
    replay_rows: list[dict[str, Any]] = []
    for item in completion.evidence:
        if not item.cmd:
            continue
        if item.cmd not in approved:
            replay_rows.append({"cmd": item.cmd, "claimed_exit": item.exit,
                                "actual_exit": None, "ran": False,
                                "ok": False,
                                "note": "not approved to replay"})
            result["gaps"].append(
                f"evidence command is not approved and cannot serve as proof: "
                f"{item.cmd}")
            continue
        outcome = runner(item.cmd, cwd=str(root), timeout=timeout)
        actual = outcome.get("exit")
        ok = actual is not None and actual == item.exit
        replay_rows.append({"cmd": item.cmd, "claimed_exit": item.exit,
                            "actual_exit": actual, "ran": True, "ok": ok,
                            "tail": outcome.get("tail", "")[-400:]})
        if not ok:
            result["gaps"].append(
                f"claimed exit {item.exit} but replay returned {actual}: {item.cmd}")
    result["checks"]["replay"] = replay_rows

    # 3. files -------------------------------------------------------------
    file_rows: list[dict[str, Any]] = []
    for item in completion.evidence:
        if not item.file:
            continue
        path = (root / item.file).resolve() if not Path(item.file).is_absolute() \
            else Path(item.file)
        inside = _inside_workspace(path, root)
        exists = path.is_file()
        changed: bool | None = None
        if baseline is not None and item.change is not None:
            changed = baseline.get(item.file) != _hash(path) if exists else None
        row = {"file": item.file, "exists": exists, "inside_workspace": inside,
               "change": item.change, "changed": changed}
        file_rows.append(row)
        if not inside:
            result["gaps"].append(f"evidence file escapes the workspace: {item.file}")
        elif not exists:
            result["gaps"].append(f"evidence file does not exist: {item.file}")
        elif changed is False:
            result["gaps"].append(f"evidence file is unchanged: {item.file}")
    result["checks"]["files"] = file_rows

    # 4. criteria ----------------------------------------------------------
    verified = [row for row in replay_rows if row.get("ok")]
    for row in file_rows:
        if row["exists"] and row["inside_workspace"] and row.get("changed") is not False:
            verified.append({"file": row["file"], "ok": True})
    criterion_rows = []
    for criterion in wanted_criteria:
        needle = criterion.lower()
        support = [item.to_dict() for item in completion.evidence
                   if needle in (f"{item.body} {item.change or ''} "
                                 f"{item.cmd or ''}").lower()]
        met = bool(support) and bool(verified)
        criterion_rows.append({"criterion": criterion, "met": met,
                               "support": support})
        if not met:
            result["gaps"].append(f"criterion has no verifying evidence: {criterion}")
    result["checks"]["criteria"] = criterion_rows

    # 5. integrity ---------------------------------------------------------
    integrity: list[dict[str, str]] = []
    for item in completion.evidence:
        if item.cmd and re.search(r"\bcd\s+|pushd\s+|chdir\(", item.cmd):
            integrity.append({"problem": "evidence command changes directory",
                              "detail": item.cmd})
            result["gaps"].append(
                f"evidence command changes cwd and cannot be replayed safely: "
                f"{item.cmd}")
        if item.file and item.change and _is_test_path(item.file):
            integrity.append({"problem": "test file edited as part of the claim",
                              "detail": item.file})
            result["gaps"].append(
                f"claim depends on editing tests, which needs review: {item.file}")
    result["checks"]["integrity"] = integrity

    # verdict --------------------------------------------------------------
    if not result["gaps"] and marker_ok and (replay_rows or file_rows):
        result["verdict"] = VERDICT_PASS
        result["ok"] = True
    elif any("does not exist" in gap or "claimed exit" in gap or
             "escapes the workspace" in gap for gap in result["gaps"]):
        result["verdict"] = VERDICT_REJECT
    else:
        result["verdict"] = VERDICT_INSUFFICIENT
    return result


def _is_test_path(path: str) -> bool:
    lowered = path.replace("\\", "/").lower()
    return (lowered.startswith("tests/") or "/tests/" in lowered
            or lowered.startswith("test/") or "/test/" in lowered
            or lowered.endswith("_test.py") or lowered.startswith("test_"))


def _hash(path: Path) -> str:
    import hashlib
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return ""


class RejectionTracker:
    """Pause after repeated identical failures: three strikes, not forever."""

    def __init__(self, max_rejections: int = MAX_REJECTIONS):
        self.max_rejections = max_rejections
        self.last_gap: str | None = None
        self.streak = 0

    def record(self, verdict: dict[str, Any]) -> dict[str, Any]:
        if verdict.get("ok"):
            self.last_gap = None
            self.streak = 0
            return {"streak": 0, "pause": False}
        gaps = verdict.get("gaps") or ["(no gap reported)"]
        gap = gaps[0]
        if gap == self.last_gap:
            self.streak += 1
        else:
            self.last_gap = gap
            self.streak = 1
        return {"streak": self.streak, "gap": gap,
                "pause": self.streak >= self.max_rejections}
