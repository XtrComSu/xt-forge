"""Compression passes (F5): L1 lossless-ish and L2 structural.

Hard invariant: lines containing ERROR / FAIL / Traceback / assert are never
dropped at L1 or L2. Each pass is individually idempotent.
"""
from __future__ import annotations

import json
import re
from collections import Counter
from typing import Any

ANSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")
PROGRESS = re.compile(r"^[\s|/\-\\.=+*#▓▒░█▁▂▃▄▅▆▇]*\d{1,4}(?:\.\d+)?%[\s|/\-\\.=+*#▓▒░█▁▂▃▄▅▆▇]*$")
REPEAT = re.compile(r"^(.*?)\s*[x×](\d+)\s*$")
SPINNER = re.compile(r"^[\s|/\-\\.█▁▂▃▄▅▆▇]+$")

HIGH_VALUE = re.compile(
    r"ERROR|FAIL|Traceback|assert|Exception|panic:|FATAL|error:|warning:",
    re.IGNORECASE)

WHITESPACE_RUN = re.compile(r"[ \t]{2,}")


def est_tokens(text: str) -> int:
    return max(0, (len(text or "") + 3) // 4)


def is_high_value(line: str) -> bool:
    return bool(HIGH_VALUE.search(line or ""))


# ---------------- L1 ----------------

def strip_ansi(text: str) -> str:
    return ANSI.sub("", text or "")


def collapse_whitespace(line: str) -> str:
    line = line.rstrip()
    lead = len(line) - len(line.lstrip(" \t"))
    body = WHITESPACE_RUN.sub(" ", line.strip())
    return (" " * lead) + body if body or lead == 0 else body


def collapse_repeats(lines: list[str]) -> list[str]:
    """Collapse identical consecutive lines to 'line ×N'. Keeps error lines intact."""
    out: list[str] = []
    i = 0
    while i < len(lines):
        line = lines[i]
        n = 1
        j = i + 1
        while j < len(lines) and lines[j] == line:
            n += 1
            j += 1
        if n > 1 and not is_high_value(line):
            out.append(f"{line} ×{n}")
        elif n > 1:
            out.append(f"{line} ×{n} (error line preserved)")
        else:
            out.append(line)
        i = j
    return out


def drop_noise(lines: list[str]) -> list[str]:
    """Remove progress bars, spinners, blank runs. Error lines always kept."""
    out: list[str] = []
    blanks = 0
    for line in lines:
        if not line.strip():
            blanks += 1
            if blanks <= 1:
                out.append("")
            continue
        blanks = 0
        if not is_high_value(line) and (PROGRESS.match(line) or SPINNER.match(line)):
            continue
        out.append(line)
    return out


def minify_json(text: str) -> str:
    stripped = text.strip()
    if not stripped or stripped[0] not in "[{":
        return text
    try:
        return json.dumps(json.loads(stripped), separators=(",", ":"), sort_keys=True)
    except json.JSONDecodeError:
        return text


def pass_l1(text: str) -> dict[str, Any]:
    """Lossless-ish: ANSI, whitespace, repeated lines, progress noise, JSON minify."""
    original = text or ""
    lines = strip_ansi(original).split("\n")
    lines = [collapse_whitespace(l) for l in lines]
    lines = drop_noise(lines)
    lines = collapse_repeats(lines)
    lines = [minify_json(l) for l in lines]
    out = "\n".join(lines)
    while "\n\n\n" in out:
        out = out.replace("\n\n\n", "\n\n")
    out = out.strip("\n")
    return {"text": out, "level": "L1",
            "ratio": (len(out) / len(original)) if original else 1.0,
            "tokens_before": est_tokens(original), "tokens_after": est_tokens(out)}


def _l2_input(text: str) -> str:
    """Apply the L1 clean pass before structural compression, for fair accounting."""
    return pass_l1(text)["text"]


# ---------------- L2 ----------------

STACK_FRAME = re.compile(r'^\s*File "(.+?)", line (\d+), in (.+)$')
FRAME_SUMMARY = re.compile(r"^\s*\[\d+ frames\]$")
MORE_FRAMES = re.compile(r"^\s*…\+\d+ more frames$")
_SUMMARIZED_FRAME = re.compile(r"^\s+\S+:\d+ in \S+$")
STAT_LINE = re.compile(r"^(\d+) files? changed")


def _summarized_frame(line: str) -> bool:
    return bool(_SUMMARIZED_FRAME.match(line))


def summarize_stack(text: str) -> tuple[str, list[str]]:
    """Keep the error signature line plus the first frames of the traceback."""
    lines = text.split("\n")
    sig: str | None = None
    frames: list[str] = []
    for line in lines:
        m = STACK_FRAME.match(line)
        if m:
            frames.append(f"  {m.group(1)}:{m.group(2)} in {m.group(3)}")
        elif is_high_value(line) and not line.startswith("  File") and sig is None:
            sig = line.strip()
    out: list[str] = []
    if sig:
        out.append(sig)
    if frames:
        out.append(f"  [{len(frames)} frames]")
        out.extend(frames[:3])
        if len(frames) > 3:
            out.append(f"  …+{len(frames) - 3} more frames")
    return "\n".join(out), frames


def head_tail_stats(text: str, head: int = 10, tail: int = 5) -> str:
    lines = text.split("\n")
    total = len(lines)
    if total <= head + tail + 2:
        return text
    keep = lines[:head] + [f"… [{total - head - tail} lines elided] …"] + lines[-tail:]
    return "\n".join(keep)


def diff_stat(text: str) -> str | None:
    if not text.lstrip().startswith(("diff --git", "--- ", "+++ ")):
        return None
    files = re.findall(r"^\+\+\+ b/(.+)$", text, re.MULTILINE)
    changed = [l for l in text.split("\n") if STAT_LINE.match(l)]
    return "\n".join(changed + [f"files: {len(files)}"] +
                     [f"  {f}" for f in files[:10]])


def pass_l2(text: str) -> dict[str, Any]:
    """Structural: stack traces, diffs, head/tail, stats. Error lines preserved.

    Idempotent: already-summarized stacks (frame summary + …+N more frames) are
    passed through untouched.
    """
    original = text or ""
    pre = _l2_input(original)
    if "Traceback (most recent call last)" in pre and "  File \"" in pre:
        out, _ = summarize_stack(pre)
    elif "Traceback (most recent call last)" in pre:
        kept_tb = []
        for l in pre.split("\n"):
            if "Traceback" in l or is_high_value(l):
                kept_tb.append(l)
            elif FRAME_SUMMARY.match(l) or MORE_FRAMES.match(l) or _summarized_frame(l):
                kept_tb.append(l)
        out = "\n".join(kept_tb) if kept_tb else pre
    else:
        stat = diff_stat(pre)
        out = stat if stat else head_tail_stats(strip_ansi(pre))
    kept = []
    for l in pre.split("\n"):
        if not is_high_value(l):
            continue
        stripped = l.strip()
        if not stripped or stripped in out:
            continue
        if FRAME_SUMMARY.match(l) or MORE_FRAMES.match(l):
            continue
        if STACK_FRAME.match(l):
            continue
        kept.append(stripped)
    if kept:
        out = out + "\n" + "\n".join(dict.fromkeys(kept))
    ratio = (len(out) / len(original)) if original else 1.0
    return {"text": out, "level": "L2", "ratio": ratio,
            "tokens_before": est_tokens(original), "tokens_after": est_tokens(out),
            "error_lines_kept": len(kept) + 1}


def compress(text: str, level: str = "L1") -> dict[str, Any]:
    level = level.upper()
    if level == "L0":
        return {"text": text or "", "level": "L0", "ratio": 1.0,
                "tokens_before": est_tokens(text), "tokens_after": est_tokens(text)}
    if level == "L1":
        return pass_l1(text)
    if level == "L2":
        return pass_l1(pass_l2(text)["text"])
    if level == "L3":
        return pass_l2(text)
    raise ValueError(f"unknown level {level!r}; expected L0..L3")


def line_stats(text: str) -> dict[str, Any]:
    lines = (text or "").split("\n")
    hv = [l for l in lines if is_high_value(l)]
    words = Counter(re.findall(r"\w+", " ".join(lines)))
    return {"lines": len(lines), "chars": len(text or ""),
            "tokens": est_tokens(text), "high_value_lines": len(hv),
            "top_words": words.most_common(5)}