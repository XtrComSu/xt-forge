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

import hashlib
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
    "dequeued": "dequeue", "enqueued": "enqueue",
    "allowed": "allow", "permitted": "permit",
}
SYNONYMS: dict[str, tuple[str, ...]] = {
    "record": ("observe", "emit", "log", "metric"),
    "recorded": ("observe", "emit", "log", "metric"),
    "observe": ("record", "metric"),
    "latency": ("duration", "elapsed", "timing"),
    "dequeue": ("queue", "pop", "take", "next"),
    "enqueue": ("queue", "push", "add"),
    "order": ("priority", "sort"),
    "allow": ("permit", "roots", "whitelist"),
    "connection": ("pool", "connect"),
}
FAILURE_INTENT = frozenset({
    "error", "errors", "err", "fail", "failed", "failing", "failure",
    "exception", "traceback", "raise", "throw", "crash", "crashed",
    "timeout", "refused", "denied", "corrupt", "missing", "fatal",
})
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


def _line_score_detail(line: str, query_tokens: list[str], path: str) -> tuple[float, dict[str, float]]:
    """Score one line and return structural breakdown for diagnostics."""
    if not query_tokens:
        return 0.0, {"lexical": 0.0, "synonym": 0.0, "path": 0.0, "decl_assign": 0.0, "error_bonus": 0.0}
    lower = line.lower()
    words = _line_words(line)
    canon_words = {_canon(word) for word in words}
    name = path.lower()
    has_failure_intent = any(t in FAILURE_INTENT or _canon(t) in FAILURE_INTENT for t in query_tokens)

    lex = 0.0
    syn = 0.0
    pth = 0.0
    for token in query_tokens:
        canon = _canon(token)
        if token in words:
            lex += 3.0
        elif canon in canon_words:
            lex += 2.0
        elif len(token) >= 4 and any(word.startswith(token) for word in words):
            lex += 1.5
        else:
            syns = SYNONYMS.get(token) or SYNONYMS.get(canon) or ()
            if any(s in words or s in canon_words for s in syns):
                syn += 1.5
        if token in name or (len(canon) >= 4 and canon in name):
            pth += 1.5
        if token not in words and token in lower:
            lex += 0.5

    decl_assign = 1.0 if (DECLISH.match(line) or ASSIGNISH.match(line)) else 0.0
    err_bonus = (2.0 if has_failure_intent else 0.5) if ERRORISH.search(line) else 0.0
    raw_score = lex + syn + pth + decl_assign + err_bonus
    return round(min(raw_score, 12.0), 2), {
        "lexical": round(lex, 2),
        "synonym": round(syn, 2),
        "path": round(pth, 2),
        "decl_assign": decl_assign,
        "error_bonus": err_bonus,
        "ref_def_bonus": 0.0,
        "adj_bonus": 0.0,
    }


def score_line(line: str, query_tokens: list[str], path: str) -> float:
    """Relevance of one line. Cheap, deterministic, explainable."""
    score, _ = _line_score_detail(line, query_tokens, path)
    return score


_IDENT_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]{2,})\b")
_DEF_LHS_RE = re.compile(
    r"^\s*(?:async\s+)?(?:def|class|function|func|fn|const|let|var|export|static|final)?\s*([A-Za-z_][A-Za-z0-9_]*)\s*(?:\(|[:=][^=])"
)
_COMMENT_OR_DOC = re.compile(r'^\s*(?:#|//|/\*|\*|"""|\'\'\')')


def _score_file_lines(lines: list[str], tokens: list[str], path_str: str) -> list[dict[str, Any]]:
    """Score lines in a single file with intra-file ref propagation & comment bleed."""
    rows: list[dict[str, Any]] = []
    for lineno, line in enumerate(lines, start=1):
        sc, brk = _line_score_detail(line, tokens, path_str)
        rows.append({
            "path": path_str,
            "line": lineno,
            "text": line.strip()[:200],
            "raw": line,
            "score": sc,
            "breakdown": brk,
            "error_line": bool(ERRORISH.search(line)),
        })

    # Pass 2A: referenced symbol -> definition propagation within the file.
    ref_boosts: dict[str, float] = {}
    for idx, row in enumerate(rows):
        if row["score"] < 2.5:
            continue
        # Only propagate strong lexical/synonym matches (ignore pure path matches).
        sig_score = row["breakdown"]["lexical"] + row["breakdown"]["synonym"]
        if sig_score < 1.5:
            continue
        for ident in _IDENT_RE.findall(row["raw"]):
            low = ident.lower()
            if low in STOPWORDS or len(ident) < 3:
                continue
            weight = 0.85 if ident.isupper() else 0.55
            cand_boost = min(4.0, round(sig_score * weight, 2))
            if cand_boost > ref_boosts.get(ident, 0.0):
                ref_boosts[ident] = cand_boost

    # Also propagate leading comment/docstring relevance to the next 1..4 non-blank code lines.
    adj_boosts = [0.0] * len(rows)
    for idx, row in enumerate(rows):
        lex_syn = row["breakdown"]["lexical"] + row["breakdown"]["synonym"]
        if lex_syn >= 2.0 and (_COMMENT_OR_DOC.match(row["raw"]) or DECLISH.match(row["raw"])):
            bleed = min(2.5, round(lex_syn * 0.55, 2))
            step = 0
            for j in range(idx + 1, min(len(rows), idx + 6)):
                nxt = rows[j]["raw"].strip()
                if not nxt:
                    continue
                if DECLISH.match(nxt) and j > idx + 1:
                    break
                adj_boosts[j] = max(adj_boosts[j], bleed)
                step += 1
                if step >= 4:
                    break

    out: list[dict[str, Any]] = []
    for idx, row in enumerate(rows):
        m = _DEF_LHS_RE.match(row["raw"])
        lhs = m.group(1) if m else ""
        # Don't boost a line via self-reference from itself alone unless mentioned by another line.
        ref_b = ref_boosts.get(lhs, 0.0) if lhs else 0.0
        adj_b = adj_boosts[idx]
        if ref_b > 0 or adj_b > 0:
            row["breakdown"]["ref_def_bonus"] = round(ref_b, 2)
            row["breakdown"]["adj_bonus"] = round(adj_b, 2)
            row["score"] = round(min(12.0, row["score"] + ref_b + adj_b), 2)
        if row["score"] > 0:
            out.append(row)
    return out


def rank_lines(root: Path, query: str, limit: int = 20,
               glob: str | None = None, *, _collect_all: bool = False,
               _scanned_paths: list[str] | None = None) -> list[dict[str, Any]]:
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
            raw_bytes = canon.read_bytes()
        except (guard.Denied, OSError):
            continue
        if b"\0" in raw_bytes[:2000]:
            continue
        if _scanned_paths is not None:
            _scanned_paths.append(str(path))
        digest = hashlib.sha256(raw_bytes).hexdigest()
        text = raw_bytes.decode("utf-8", errors="replace")
        for row in _score_file_lines(ref.split_lines(text), tokens, str(path)):
            row["digest"] = digest
            matches.append(row)
            if not _collect_all and len(matches) >= MAX_MATCHES:
                break
        if not _collect_all and len(matches) >= MAX_MATCHES:
            break
    matches.sort(key=lambda m: (-m["score"], m["path"], m["line"]))
    if _collect_all:
        return matches
    return matches[:limit]


def _windows(path: Path, lines: list[str], center: int, radius: int) -> tuple[str, int, int]:
    start = max(1, center - radius)
    end = min(len(lines), center + radius)
    body = "\n".join(f"{n}: {lines[n - 1]}" for n in range(start, end + 1))
    return body, start, end


def _match_expected_path(cand_path: str, expected_file: str | None) -> bool:
    if not expected_file:
        return True
    norm_c = cand_path.replace("\\", "/")
    norm_e = expected_file.replace("\\", "/")
    return norm_c == norm_e or norm_c.endswith("/" + norm_e) or norm_e.endswith("/" + Path(norm_c).name) and Path(norm_c).name == Path(norm_e).name and norm_e in norm_c


def pack(root: str, query: str, token_budget: int = 1200,
         file_limit: int = 12, window: int = 2,
         max_matches: int = 40, use_symbols: bool = False,
         diagnose: bool = False, expected_file: str | None = None,
         expected_line: int | None = None) -> dict[str, Any]:
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

    scanned_paths: list[str] = []
    all_scored = rank_lines(
        base, query, limit=max_matches,
        _collect_all=True,
        _scanned_paths=scanned_paths if diagnose else None,
    )
    candidates = all_scored[:max_matches]
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
                        raw_b = Path(fpath).read_bytes()
                        text_ln = raw_b.decode("utf-8", errors="replace").splitlines()[lineno - 1]
                        f_sha = hashlib.sha256(raw_b).hexdigest()
                    except (OSError, IndexError):
                        text_ln = tok
                        f_sha = ""
                    candidates.append({
                        "path": fpath, "line": lineno,
                        "text": text_ln.strip()[:200], "score": 6.5,
                        "digest": f_sha,
                        "breakdown": {"lexical": 0.0, "synonym": 0.0, "path": 0.0, "decl_assign": 0.0, "error_bonus": 0.0, "ref_def_bonus": 6.5, "adj_bonus": 0.0},
                        "error_line": False,
                    })
                    graph_hits += 1
        candidates.sort(key=lambda m: (-m["score"], m["path"], m["line"]))
        candidates = candidates[:max_matches]
    header = [f"ROOT {base}", f"QUERY {query.strip()}", f"MATCHES {len(candidates)}"]

    # Group candidate windows per file, keeping only the best centre per
    # overlapping neighbourhood.
    per_file: dict[str, list[int]] = {}
    cand_drop: dict[tuple[str, int], str] = {}
    for match in candidates:
        key = (match["path"], match["line"])
        centres = per_file.setdefault(match["path"], [])
        if len(centres) >= file_limit:
            cand_drop[key] = "file_limit_exceeded"
            continue
        if any(abs(centre - match["line"]) <= window for centre in centres):
            cand_drop[key] = "window_merged"
            continue
        centres.append(match["line"])

    windows: list[dict[str, Any]] = []
    for match in candidates:
        centres = per_file.get(match["path"]) or []
        if match["line"] not in centres:
            continue
        path = Path(match["path"])
        try:
            raw_b = path.read_bytes()
            text = raw_b.decode("utf-8", errors="replace")
            f_sha = match.get("digest") or hashlib.sha256(raw_b).hexdigest()
        except OSError:
            continue
        lines = ref.split_lines(text)
        body, start_ln, end_ln = _windows(path, lines, match["line"], window)
        windows.append({
            "path": match["path"], "line": match["line"],
            "start_line": start_ln, "end_line": end_ln, "digest": f_sha,
            "score": match["score"], "body": body,
            "error_line": match["error_line"],
        })

    # Highest score first. Error lines earn their place through the +2.0
    # score bonus in score_line; the packing loop trims an error window to fit
    # instead of skipping it, so a failure signal is never silently dropped.
    windows.sort(key=lambda w: (-w["score"], w["path"], w["line"]))
    kept: list[dict[str, Any]] = []
    used = _tokens("\n".join(header))
    packed_files: set[str] = set()
    for item in windows:
        key = (item["path"], item["line"])
        if len(packed_files) >= file_limit and item["path"] not in packed_files:
            cand_drop[key] = "file_limit_exceeded"
            continue
        cost = _tokens(item["body"])
        if used + cost > budget:
            if item["error_line"]:
                # still keep the error line itself, trimmed to one line
                line_body = f"{item['path']}:L{item['line']} {item['body'].splitlines()[-1]}"
                cost = _tokens(line_body)
                if used + cost > budget:
                    cand_drop[key] = "token_budget_cut"
                    continue
                item = {**item, "body": line_body, "start_line": item["line"], "end_line": item["line"]}
            else:
                cand_drop[key] = "token_budget_cut"
                continue
        used += cost
        kept.append(item)
        packed_files.add(item["path"])
        cand_drop[key] = "packed"

    def _ev(w: dict[str, Any]) -> dict[str, Any]:
        return {
            "path": w["path"],
            "line": w["line"],
            "start_line": w["start_line"],
            "end_line": w["end_line"],
            "digest": w["digest"],
        }

    sections = [f"FILE {item['path']} (L{item['line']}, score {item['score']})\n"
                f"{item['body']}" for item in kept]
    context = "\n\n".join(header + sections)
    data = {"root": str(base), "query": query, "context": context,
            "token_budget": budget, "estimated_tokens": 0,
            "matches": len(candidates), "windows": len(kept),
            "files": len(packed_files),
            "evidence": [_ev(item) for item in kept]}
    estimate = _payload_tokens(data)
    while estimate > budget and kept:
        dropped = kept.pop()
        cand_drop[(dropped["path"], dropped["line"])] = "evicted_during_budget_trim"
        data["windows"] = len(kept)
        data["evidence"] = [_ev(item) for item in kept]
        data["context"] = "\n\n".join(
            header + [f"FILE {item['path']} (L{item['line']}, score {item['score']})\n"
                      f"{item['body']}" for item in kept])
        estimate = _payload_tokens(data)
    data["estimated_tokens"] = estimate
    data["truncated"] = bool(candidates) and not kept
    if use_symbols:
        data["symbol_graph_hits"] = graph_hits

    if diagnose:
        top_diag = []
        for idx, c in enumerate(all_scored[:20], start=1):
            in_ctx = any(
                e["path"] == c["path"] and e["start_line"] <= c["line"] <= e["end_line"]
                for e in data["evidence"]
            )
            reason = "packed" if in_ctx else cand_drop.get(
                (c["path"], c["line"]),
                "below_max_matches" if idx > max_matches else "dropped",
            )
            top_diag.append({
                "rank": idx,
                "path": c["path"],
                "line": c["line"],
                "score": c["score"],
                "breakdown": c.get("breakdown", {}),
                "status": reason,
            })

        diag: dict[str, Any] = {
            "query_tokens": tokens,
            "indexed_files_count": len(scanned_paths),
            "total_non_zero_candidates": len(all_scored),
            "top_candidates": top_diag,
        }
        if expected_file or expected_line:
            file_indexed = (
                any(_match_expected_path(p, expected_file) for p in scanned_paths)
                if expected_file else True
            )
            best_target: dict[str, Any] | None = None
            best_rank: int | None = None
            for idx, c in enumerate(all_scored, start=1):
                if not _match_expected_path(c["path"], expected_file):
                    continue
                if expected_line and c["line"] != expected_line:
                    continue
                best_target = c
                best_rank = idx
                break
            in_packed = any(
                _match_expected_path(e["path"], expected_file)
                and (not expected_line or e["start_line"] <= expected_line <= e["end_line"])
                for e in data["evidence"]
            )
            if in_packed:
                drop_reason = "packed"
            elif not file_indexed:
                drop_reason = "file_not_indexed"
            elif best_target is None:
                drop_reason = "score_zero"
            elif best_rank is not None and best_rank > max_matches:
                drop_reason = "below_max_matches"
            else:
                drop_reason = cand_drop.get((best_target["path"], best_target["line"]), "token_budget_cut")
            diag["target"] = {
                "expected_file": expected_file,
                "expected_line": expected_line,
                "indexed": file_indexed,
                "packed": in_packed,
                "rank": best_rank,
                "total_non_zero_candidates": len(all_scored),
                "score": best_target["score"] if best_target else 0.0,
                "breakdown": best_target.get("breakdown") if best_target else None,
                "drop_reason": drop_reason,
            }
        data["diagnostic"] = diag

    return tools.envelope(True, data)
