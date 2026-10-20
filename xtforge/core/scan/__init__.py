"""Static safety scan: secrets, risky patterns, manifest hygiene.

Three rulesets, one engine, zero writes. The scan only ever reads; a test
asserts the filesystem is untouched.

Output policy: findings **mask** the matched text by default. A scanner that
prints a live AWS key into a transcript has leaked the thing it found, so the
full value requires an explicit `--reveal`. This is the guard rule applied to
the scanner itself.
"""
from __future__ import annotations

import math
import re
from pathlib import Path
from typing import Any, Iterable

from ..route import guard

MAX_FILE_BYTES = 2_000_000
MAX_FINDINGS = 500
BINARY_SNIFF = 8192

# (id, severity, pattern, description)
SECRET_RULES: list[tuple[str, str, re.Pattern[str], str]] = [
    ("aws_access_key", "critical",
     re.compile(r"\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b"),
     "AWS access key id"),
    ("aws_secret_key", "critical",
     re.compile(r"(?i)aws[_\-]?(?:secret)?[_\-]?(?:access)?[_\-]?key\s*[:=]\s*['\"][0-9a-zA-Z/+]{40}['\"]"),
     "AWS secret access key"),
    ("github_token", "critical",
     re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b"),
     "GitHub personal/OAuth/app token"),
    ("github_pat", "critical",
     re.compile(r"\bgithub_pat_[A-Za-z0-9_]{22,}\b"),
     "GitHub fine-grained personal access token"),
    ("slack_token", "critical",
     re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
     "Slack token"),
    ("jwt", "high",
     re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b"),
     "JSON web token"),
    ("private_key_block", "critical",
     re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |PGP |DSA )?PRIVATE KEY-----"),
     "PEM private key block"),
    ("stripe_key", "critical",
     re.compile(r"\b[sr]k_(?:live|test)_[A-Za-z0-9]{20,}\b"),
     "Stripe secret/restricted key"),
    ("google_api_key", "high",
     re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"),
     "Google API key"),
    ("sendgrid_key", "high",
     re.compile(r"\bSG\.[A-Za-z0-9_\-]{22,}\.[A-Za-z0-9_\-]{22,}\b"),
     "SendGrid API key"),
    ("bearer_token", "high",
     re.compile(r"(?i)\bbearer\s+[A-Za-z0-9_\-\.]{20,}"),
     "Authorization bearer token"),
    ("url_credentials", "high",
     re.compile(r"://[^/\s:@'\"<>]+:[^/\s:@'\"<>]+@"),
     "URL with embedded credentials"),
    ("generic_assignment", "medium",
     re.compile(r"(?i)\b(api[_\-]?key|secret|token|pass(?:word|wd)?|credential|"
                r"access[_\-]?key|private[_\-]?key|auth)\s*[:=]\s*"
                r"['\"][^'\"\s]{8,}['\"]"),
     "Credential-shaped assignment"),
]

# High-entropy string with no rule above: catches unlabelled keys.
ENTROPY_MIN_LEN = 20
ENTROPY_MIN_BITS = 3.6
_ENTROPY_CANDIDATE = re.compile(r"['\"]([A-Za-z0-9+/=_\-]{%d,})['\"]" % ENTROPY_MIN_LEN)

# (id, severity, pattern, description)
PATTERN_RULES: list[tuple[str, str, re.Pattern[str], str]] = [
    ("eval", "high", re.compile(r"\beval\s*\("), "dynamic code execution"),
    ("exec", "high", re.compile(r"\bexec\s*\("), "dynamic code execution"),
    ("pickle_load", "high", re.compile(r"\bpickle\.loads?\s*\("),
     "unsafe deserialization"),
    ("yaml_unsafe_load", "high", re.compile(r"\byaml\.load\s*\((?!.*SafeLoader)"),
     "unsafe YAML load"),
    ("shell_true", "high", re.compile(r"shell\s*=\s*True"),
     "shell injection surface"),
    ("os_system", "high", re.compile(r"\bos\.system\s*\("), "shell invocation"),
    ("weak_hash", "medium", re.compile(r"\b(?:md5|sha1)\s*\("),
     "weak hash function"),
    ("insecure_random", "medium", re.compile(r"\brandom\.(?:random|randint|choice)\s*\("),
     "non-cryptographic randomness"),
    ("tls_verify_off", "critical", re.compile(r"verify\s*=\s*False"),
     "TLS verification disabled"),
    ("unverified_context", "critical",
     re.compile(r"_create_unverified_context"), "TLS verification disabled"),
    ("sql_format", "high",
     re.compile(r"execute\s*\(\s*f['\"]|execute\s*\(\s*['\"][^'\"]*%[sd]"),
     "SQL built by string interpolation"),
    ("temp_insecure", "medium", re.compile(r"\btempfile\.mktemp\s*\("),
     "insecure temporary file"),
    ("assert_security", "medium",
     re.compile(r"assert\s+.*\b(?:auth|permission|allowed|admin)\b"),
     "security check via assert (stripped with -O)"),
]

# (id, severity, pattern, description) applied to manifests
MANIFEST_RULES: list[tuple[str, str, re.Pattern[str], str]] = [
    ("unpinned", "low", re.compile(r"^\s*[A-Za-z0-9_.\-\[\]]+\s*(?:#.*)?$"),
     "dependency not pinned to a version"),
    ("unbounded_range", "medium", re.compile(r"[><=~!]=?\s*\*|@latest|@next"),
     "dependency floats to whatever is newest"),
    ("http_index", "high", re.compile(r"(?i)(?:--index-url|registry\s*=)[^\n]*http://"),
     "package index over plain HTTP"),
    ("git_http", "high", re.compile(r"git\+http://"), "dependency fetched over HTTP"),
    ("local_path", "medium", re.compile(r"(?:file://|\.\./|/home/|/tmp/)"),
     "dependency resolved from a local path"),
]

MANIFEST_NAMES = ("requirements.txt", "requirements-dev.txt", "pyproject.toml",
                  "Pipfile", "poetry.lock", "package.json", "Gemfile",
                  "go.mod", "Cargo.toml")


def _logical_chunks(lines: list[str]) -> list[tuple[int, str]]:
    """Runs of adjacent string literals, folded into one logical value.

    `"abc."` + `"def"` on two lines is one value; a secret split that way
    would otherwise escape a line-based scan.
    """
    string_line = re.compile(r"^\s*['\"](.*)['\"]\s*,?\s*$")
    punct = {"", "(", ")", "[", "]", "{", "}", ",", ");", "])"}
    chunks: list[tuple[int, str]] = []
    run: list[str] = []
    run_start = 0
    for index, raw in enumerate(lines, start=1):
        stripped = raw.strip()
        match = string_line.match(stripped)
        if match:
            if not run:
                run_start = index
            run.append(match.group(1))
        elif stripped in punct or stripped.endswith(("(", "[", ",")):
            continue
        else:
            if len(run) >= 2:
                chunks.append((run_start, "".join(run)))
            run = []
    if len(run) >= 2:
        chunks.append((run_start, "".join(run)))
    return chunks


def shannon(text: str) -> float:
    """Bits of entropy per character; high values look like random keys."""
    if not text:
        return 0.0
    counts: dict[str, int] = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    total = len(text)
    return -sum((n / total) * math.log2(n / total) for n in counts.values())


def mask(value: str) -> str:
    """Show enough to identify a secret, never enough to use it."""
    if len(value) <= 8:
        return "*" * len(value)
    return f"{value[:4]}…{'*' * min(8, len(value) - 6)}{value[-2:]}"


def _finding(rule_id: str, severity: str, description: str, path: str,
             line: int, matched: str, reveal: bool) -> dict[str, Any]:
    return {
        "rule": rule_id, "severity": severity, "description": description,
        "path": path, "line": line,
        "value": matched if reveal else mask(matched),
        "masked": not reveal,
        "entropy": round(shannon(matched), 2),
    }


def scan_text(text: str, path: str = "<text>", reveal: bool = False,
              mode: str = "secrets") -> dict[str, Any]:
    """Scan one body of text. Deterministic; never touches the filesystem.

    mode: `secrets` (credentials + entropy), `patterns` (risky code), `all`.
    """
    findings: list[dict[str, Any]] = []
    lines = text.splitlines()
    covered: list[tuple[int, int]] = []   # spans already reported
    seen_values: set[tuple[str, str]] = set()

    def overlaps(start: int, end: int) -> bool:
        return any(start < prev_end and prev_start < end
                   for prev_start, prev_end in covered)

    def record(rule_id: str, severity: str, description: str, line_no: int,
               matched: str) -> None:
        key = (rule_id, matched)
        if key in seen_values:
            return
        seen_values.add(key)
        findings.append(_finding(rule_id, severity, description, path,
                                 line_no, matched.strip(), reveal))

    offset = 0
    for line_no, line in enumerate(lines, start=1):
        for rule_id, severity, pattern, description in SECRET_RULES:
            for match in pattern.finditer(line):
                start = offset + match.start()
                end = offset + match.end()
                if overlaps(start, end):
                    continue
                covered.append((start, end))
                record(rule_id, severity, description, line_no,
                       match.group().strip())
        offset += len(line) + 1

    # Secrets are often hidden as adjacent string literals across lines. Fold
    # those runs and match again, reporting the first line of the run.
    for start_line, folded in _logical_chunks(lines):
        for rule_id, severity, pattern, description in SECRET_RULES:
            for match in pattern.finditer(folded):
                record(rule_id, severity, description, start_line,
                       match.group().strip())

    # Entropy pass over the whole text, skipping anything already reported.
    if mode in ("secrets", "all"):
        for match in _ENTROPY_CANDIDATE.finditer(text):
            value = match.group(1)
            start, end = match.start(1), match.end(1)
            if overlaps(start, end) or shannon(value) < ENTROPY_MIN_BITS:
                continue
            covered.append((start, end))
            line_no = text.count("\n", 0, start) + 1
            findings.append(_finding("high_entropy", "medium",
                                     "high-entropy string with no rule match",
                                     path, line_no, value, reveal))

    if mode in ("patterns", "all"):
        for line_no, line in enumerate(lines, start=1):
            for rule_id, severity, pattern, description in PATTERN_RULES:
                if pattern.search(line):
                    findings.append(_finding(rule_id, severity, description,
                                             path, line_no, line.strip()[:80],
                                             reveal=True))

    return {"path": path, "findings": findings, "count": len(findings)}


def _is_binary(path: Path) -> bool:
    try:
        with path.open("rb") as fh:
            chunk = fh.read(BINARY_SNIFF)
    except OSError:
        return True
    return b"\0" in chunk


def scan_file(path: str | Path, reveal: bool = False,
              mode: str = "secrets") -> dict[str, Any]:
    try:
        canon = guard.read_guard(path)
    except guard.Denied as exc:
        return {"path": str(path), "error": f"{exc.code}: {exc.reason}",
                "findings": [], "count": 0}
    if not canon.is_file():
        return {"path": str(canon), "error": "not_a_file",
                "findings": [], "count": 0}
    if canon.stat().st_size > MAX_FILE_BYTES:
        return {"path": str(canon), "error": "file_too_large",
                "findings": [], "count": 0}
    if _is_binary(canon):
        return {"path": str(canon), "skipped": "binary",
                "findings": [], "count": 0}
    try:
        text = canon.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return {"path": str(canon), "error": f"unreadable: {exc}",
                "findings": [], "count": 0}
    return scan_text(text, path=str(canon), reveal=reveal, mode=mode)


def scan_tree(root: str | Path, glob: str | None = None, reveal: bool = False,
              mode: str = "secrets",
              limit: int = MAX_FINDINGS) -> dict[str, Any]:
    """Scan a tree. Read-only: nothing here opens a file for writing."""
    from ..route import reference as ref

    try:
        base = guard.read_guard(root)
    except guard.Denied as exc:
        return {"ok": False, "err": f"{exc.code}: {exc.reason}", "findings": []}
    if not base.is_dir():
        return {"ok": False, "err": "not_a_directory", "findings": []}
    findings: list[dict[str, Any]] = []
    scanned = 0
    truncated = False
    for entry in ref.walk_py(base, max_depth=12, limit=2000):
        if entry.get("dir"):
            continue
        path = Path(entry["path"])
        if guard.is_denied_name(str(path)):
            continue
        if glob and not path.match(glob):
            continue
        result = scan_file(path, reveal=reveal, mode=mode)
        if result.get("skipped") or result.get("error"):
            continue
        scanned += 1
        for item in result["findings"]:
            if len(findings) >= limit:
                truncated = True
                break
            findings.append(item)
        if truncated:
            break
    findings.sort(key=lambda f: (f["path"], f["line"], f["rule"]))
    return {"ok": True, "root": str(base), "files_scanned": scanned,
            "findings": findings, "count": len(findings),
            "truncated": truncated, "masked": not reveal,
            "summary": summarize(findings)}


def scan_manifest(path: str | Path, reveal: bool = False) -> dict[str, Any]:
    """Manifest hygiene: pinning, transport, and local-path dependencies.

    Secret findings from the same file are kept — a token committed in a
    manifest is exactly the kind of thing this must not miss.
    """
    result = scan_file(path, reveal=reveal, mode="secrets")
    if result.get("error") or result.get("skipped"):
        return result
    try:
        text = Path(result["path"]).read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return {"path": str(path), "error": f"unreadable: {exc}",
                "findings": [], "count": 0}
    findings = list(result["findings"])
    for line_no, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", "//", "[")):
            continue
        for rule_id, severity, pattern, description in MANIFEST_RULES:
            if pattern.search(stripped):
                findings.append(_finding(rule_id, severity, description,
                                         result["path"], line_no, stripped[:80],
                                         reveal=True))
    return {"path": result["path"], "findings": findings, "count": len(findings),
            "kind": "manifest"}


def summarize(findings: Iterable[dict[str, Any]]) -> dict[str, int]:
    out: dict[str, int] = {}
    for item in findings:
        out[item["severity"]] = out.get(item["severity"], 0) + 1
    return dict(sorted(out.items()))
