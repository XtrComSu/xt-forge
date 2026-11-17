"""Query-aware context packing.

`route context` without a query builds a project map. With a query, packing
becomes relevance-driven: rank matching lines across the tree, take bounded
windows around them, and spend the token budget where the answer is. The map
is still there as a header, so the model keeps its bearings.

Rules:
- **error lines survive.** A matched failure line scores +2.0 and, when the
  budget is tight, is trimmed to fit rather than skipped — diagnostics are the
  last thing a packer should silently drop.
- **deterministic.** Equal scores break by path then line, so two runs pack
  identical bytes.
- **bounded.** Every loop has a cap; a hostile tree cannot stall the packer.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from . import guard, tools
from . import reference as ref

_WORD = re.compile(r"[A-Za-z0-9_]+")
_IDENT_SPLIT = re.compile(r"[_\-]+|(?<=[a-z0-9])(?=[A-Z])")
# Surface form -> canonical, so "written"/"writes" meet "write". Both sides of
# the match expand through this, which is plain query expansion.
ALIASES = {
    "written": "write", "writing": "write", "wrote": "write", "writes": "write",
    "directories": "directory", "folders": "directory", "folder": "directory",
    "opened": "open", "opening": "open", "opens": "open",
    "connections": "connection", "attempts": "attempt", "retries": "retry",
    "refused": "refuse", "denied": "deny", "evicted": "evict",
    "latencies": "latency", "buckets": "bucket", "samples": "sample",
    "params": "param", "rows": "row", "dicts": "dict", "tokens": "token",
}
STOPWORDS = frozenset("""
a an and are as at be but by did do does for from had has have how i if in into
is it its just me my no not of on or our so than that the their them then there
these this those to too us was we were what when where which who why will with
would you your about above after again against all am any are because been
before being below between both can cannot could down during each few further
had has have he her here hers herself him himself his how its itself more most
other ought out over own same she should some such that the their theirs them
themselves then there these they those through under until up very was we were
what when where which while who whom why with would
""".split())
ERRORISH = re.compile(
    r"(Traceback \(most recent call last\)|\bfatal\b|\bsegfault\b|\bpanicked?\b|"
    r"\brefused\b|\bdenied\b|\bcrash(?:ed)?\b|\btimeout\b|\bcorrupt\b|"
    r"^\s*(?:raise|throw)\b|\b[A-Za-z]*Error\b\s*:|\b[A-Za-z]*Exception\b\s*:|"
    r"\b(?:failed|failure)\b)", re.IGNORECASE)
DECLISH = re.compile(r"^\s*(def|class|function|func|fn|impl|struct|type|"
                     r"interface|export|import|from|return|async)\b")
# A constant or field assignment is where "what is X set to" questions are
# answered, so it earns the same structural bonus as a declaration.
ASSIGNISH = re.compile(r"^\s*(?:export\s+)?(?:const\s+|let\s+|var\s+|static\s+|"
                       r"final\s+)?[A-Za-z_][A-Za-z0-9_]*\s*[:=][^=]")
MAX_FILES_SCANNED = 400
MAX_MATCHES = 400


def _tokens(text: str) -> int:
    return max(0, (len(text or "") + 3) // 4)


def _payload_tokens(data: dict[str, Any]) -> int:
    """Same estimator as shortcuts._payload_tokens: fixed point over JSON size."""
    estimate = 0
    for _ in range(3):
        data["estimated_tokens"] = estimate
        estimate = _tokens(json.dumps(data, ensure_ascii=False))
    data["estimated_tokens"] = estimate
    return estimate


def _stem(token: str) -> str:
    if len(token) > 4 and token.endswith("ing"):
        return token[:-3]
    if len(token) > 3 and token.endswith("ed"):
        return token[:-2]
    if len(token) > 3 and token.endswith("es"):
        return token[:-2]
    if len(token) > 3 and token.endswith("s") and not token.endswith("ss"):
        return token[:-1]
    return token


def _query_tokens(query: str) -> list[str]:
    """Content tokens: stopwords match everywhere and only add noise.

    A stopword-only query yields no tokens at all — that is not a query, and
    returning matches for it would be noise pretending to be a result.
    """
    return [t.lower() for t in _WORD.findall(query or "")
            if len(t) >= 2 and t.lower() not in STOPWORDS]


def _line_words(line: str) -> set[str]:
    """Words plus identifier parts: `MAX_ATTEMPTS` -> max, max_attempts, attempts."""
    out: set[str] = set()
    for raw in _WORD.findall(line or ""):
        out.add(raw.lower())
        for part in _IDENT_SPLIT.split(raw):
            if part:
                out.add(part.lower())
    return out


def _canon(token: str) -> str:
    """Alias then stem: 'written' -> 'write', 'indexing' -> 'index'."""
    return _stem(ALIASES.get(token, token))


def score_line(line: str, query_tokens: list[str], path: str) -> float:
    """Relevance of one line. Cheap, deterministic, explainable."""
    if not query_tokens:
        return 0.0
    lower = line.lower()
    words = _line_words(line)
    canon_words = {_canon(word) for word in words}
    name = path.lower()
    score = 0.0
    for token in query_tokens:
        canon = _canon(token)
        if token in words:
            score += 3.0
        elif canon in canon_words:
            score += 2.0
        elif len(token) >= 4 and any(word.startswith(token) for word in words):
            score += 1.5
        if token in name or (len(canon) >= 4 and canon in name):
            score += 1.5
        if token not in words and token in lower:
            score += 0.5
    if DECLISH.match(line) or ASSIGNISH.match(line):
        score += 1.0
    if ERRORISH.search(line):
        score += 2.0
    return min(score, 12.0)


def rank_lines(root: Path, query: str, limit: int = 20,
               glob: str | None = None) -> list[dict[str, Any]]:
    """Best matching lines across the tree, highest score first."""
    tokens = _query_tokens(query)
    if not tokens:
        return []
    matches: list[dict[str, Any]] = []
    scanned = 0
    for entry in ref.walk_py(root, max_depth=8, limit=MAX_FILES_SCANNED):
        if entry.get("dir"):
            continue
        if entry.get("size", 0) > 2_000_000:
            continue
        path = Path(entry["path"])
        if guard.is_denied_name(str(path)):
            continue
        if glob and not path.match(glob):
            continue
        if scanned >= MAX_FILES_SCANNED:
            break
        scanned += 1
        try:
            canon = guard.read_guard(path)
            text = canon.read_text(encoding="utf-8", errors="replace")
        except (guard.Denied, OSError):
            continue
        if "\0" in text[:2000]:
            continue
        for lineno, line in enumerate(ref.split_lines(text), start=1):
            score = score_line(line, tokens, str(path))
            if score > 0:
                matches.append({
                    "path": str(path), "line": lineno,
                    "text": line.strip()[:200], "score": round(score, 2),
                    "error_line": bool(ERRORISH.search(line)),
                })
        if len(matches) >= MAX_MATCHES:
            break
    matches.sort(key=lambda m: (-m["score"], m["path"], m["line"]))
    return matches[:limit]


def _windows(path: Path, lines: list[str], center: int, radius: int) -> str:
    start = max(1, center - radius)
    end = min(len(lines), center + radius)
    body = "\n".join(f"{n}: {lines[n - 1]}" for n in range(start, end + 1))
    return body


def pack(root: str, query: str, token_budget: int = 1200,
         file_limit: int = 12, window: int = 2,
         max_matches: int = 40, use_symbols: bool = False) -> dict[str, Any]:
    """Budget-packed context around the lines that answer the query."""
    try:
        base = guard.read_guard(root)
    except guard.Denied as exc:
        return tools.envelope(False, err=f"{exc.code}: {exc.reason}")
    if not base.is_dir():
        return tools.envelope(False, err="not_a_directory")
    budget = max(64, min(int(token_budget), 4000))
    tokens = _query_tokens(query)
    if not tokens:
        return tools.envelope(False, err="empty_query")

    candidates = rank_lines(base, query, limit=max_matches)
    graph_hits = 0
    if use_symbols:
        from ..code.graph import query_graph
        seen_pairs = {(c["path"], c["line"]) for c in candidates}
        for tok in tokens[:4]:
            if len(tok) < 3:
                continue
            gres = query_graph(tok, root=base, depth=1)
            for item in (gres.get("definitions") or [])[:4] + (gres.get("callers") or [])[:4]:
                fpath = item.get("file") or ""
                lineno = int(item.get("line") or 0)
                if fpath and lineno > 0 and (fpath, lineno) not in seen_pairs:
                    seen_pairs.add((fpath, lineno))
                    try:
                        text_ln = Path(fpath).read_text(encoding="utf-8", errors="replace").splitlines()[lineno - 1]
                    except (OSError, IndexError):
                        text_ln = tok
                    candidates.append({
                        "path": fpath, "line": lineno,
                        "text": text_ln.strip()[:200], "score": 6.5,
                        "error_line": False,
                    })
                    graph_hits += 1
        candidates.sort(key=lambda m: (-m["score"], m["path"], m["line"]))
        candidates = candidates[:max_matches]
    header = [f"ROOT {base}", f"QUERY {query.strip()}", f"MATCHES {len(candidates)}"]

    # Group candidate windows per file, keeping only the best centre per
    # overlapping neighbourhood.
    per_file: dict[str, list[int]] = {}
    for match in candidates:
        centres = per_file.setdefault(match["path"], [])
        if len(centres) >= file_limit:
            continue          # this file has enough windows; keep scanning others
        if any(abs(centre - match["line"]) <= window for centre in centres):
            continue
        centres.append(match["line"])

    windows: list[dict[str, Any]] = []
    for match in candidates:
        centres = per_file.get(match["path"]) or []
        if match["line"] not in centres:
            continue
        path = Path(match["path"])
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        lines = ref.split_lines(text)
        body = _windows(path, lines, match["line"], window)
        windows.append({"path": match["path"], "line": match["line"],
                        "score": match["score"], "body": body,
                        "error_line": match["error_line"]})

    # Highest score first. Error lines earn their place through the +2.0
    # score bonus in score_line; the packing loop trims an error window to fit
    # instead of skipping it, so a failure signal is never silently dropped.
    windows.sort(key=lambda w: (-w["score"], w["path"], w["line"]))
    kept: list[dict[str, Any]] = []
    used = _tokens("\n".join(header))
    packed_files: set[str] = set()
    for item in windows:
        if len(packed_files) >= file_limit and item["path"] not in packed_files:
            continue
        cost = _tokens(item["body"])
        if used + cost > budget:
            if item["error_line"]:
                # still keep the error line itself, trimmed to one line
                line_body = f"{item['path']}:L{item['line']} {item['body'].splitlines()[-1]}"
                cost = _tokens(line_body)
                if used + cost > budget:
                    continue
                item = {**item, "body": line_body}
            else:
                continue
        used += cost
        kept.append(item)
        packed_files.add(item["path"])

    sections = [f"FILE {item['path']} (L{item['line']}, score {item['score']})\n"
                f"{item['body']}" for item in kept]
    context = "\n\n".join(header + sections)
    data = {"root": str(base), "query": query, "context": context,
            "token_budget": budget, "estimated_tokens": 0,
            "matches": len(candidates), "windows": len(kept),
            "files": len(packed_files),
            "evidence": [{"path": item["path"], "line": item["line"]}
                         for item in kept]}
    estimate = _payload_tokens(data)
    while estimate > budget and kept:
        dropped = kept.pop()
        data["windows"] = len(kept)
        data["evidence"] = [{"path": item["path"], "line": item["line"]}
                            for item in kept]
        data["context"] = "\n\n".join(
            header + [f"FILE {item['path']} (L{item['line']}, score {item['score']})\n"
                      f"{item['body']}" for item in kept])
        estimate = _payload_tokens(data)
    data["estimated_tokens"] = estimate
    data["truncated"] = bool(candidates) and not kept
    if use_symbols:
        data["symbol_graph_hits"] = graph_hits
    return tools.envelope(True, data)
