"""Render a 52-week UTC commit chart from this project's local Git history."""
from collections import Counter
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
import subprocess
import sys
from tempfile import NamedTemporaryFile

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "docs/assets/activity.svg"
WEEKS = 52
DAYS = WEEKS * 7
COLORS = ("#242e3b", "#14532d", "#166534", "#22c55e", "#86efac")
EPOCH = date(1970, 1, 1)


def git(*args, check=True):
    return subprocess.run(["git", "-C", str(ROOT), *args], text=True,
                          capture_output=True, check=check)


def daily_counts(first_day):
    top = git("rev-parse", "--show-toplevel", check=False)
    if top.returncode or Path(top.stdout.rstrip("\r\n")).resolve() != ROOT:
        raise ValueError("Initialize Git at the project root before refreshing the chart.")

    head = git("rev-parse", "--verify", "--quiet", "HEAD", check=False)
    if head.returncode == 1:
        return Counter()
    head.check_returncode()

    log = git("log", "--no-show-signature", "--no-notes", "--no-decorate",
              "--no-color", "--format=%at", head.stdout.strip(), "--")
    start = (first_day - EPOCH).days
    days = (int(stamp) // 86400 - start for stamp in log.stdout.splitlines())
    return Counter(day for day in days if 0 <= day < DAYS)


def render(first, today, counts):
    total = counts.total()
    active = len(counts)
    summary = f"{total} commit{'s' if total != 1 else ''} across {active} active day{'s' if active != 1 else ''}"
    lines = [
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 672 144" role="img" aria-labelledby="title">',
        f'<title id="title">{summary}, {first} through {today} UTC</title>',
        '<rect width="672" height="144" rx="6" fill="#0d1117"/>',
        '<g fill="#e6edf3" font-family="sans-serif" font-size="12">',
        f'<text x="16" y="20">{summary}</text>',
        f'<text x="656" y="20" text-anchor="end">{first} to {today} UTC</text>',
        '<text x="16" y="128" fill="#aab7c4">Author dates of commits reachable from HEAD</text>',
        '<text x="544" y="128" fill="#aab7c4">Commits</text>',
        '</g>',
    ]
    for index in range(DAYS):
        week, row = divmod(index, 7)
        day = first + timedelta(days=index)
        count = counts[index]
        label = f"{day}: {count} commit{'s' if count != 1 else ''}"
        lines.append(f'<rect x="{16 + 12 * week}" y="{30 + 11 * row}" width="9" height="9" '
                     f'rx="2" fill="{COLORS[min(count, 4)]}"><title>{label}</title></rect>')
    for index, color in enumerate(COLORS):
        lines.append(f'<rect x="{598 + 12 * index}" y="120" width="9" height="9" rx="2" fill="{color}">'
                     f'<title>{index}{"+" if index == 4 else ""} commits</title></rect>')
    lines.append("</svg>\n")
    return "\n".join(lines)


def main():
    today = datetime.now(timezone.utc).date()
    first = today - timedelta(days=DAYS - 1)
    try:
        svg = render(first, today, daily_counts(first))
        if OUTPUT.is_file() and OUTPUT.read_text(encoding="utf-8") == svg:
            return 0
        with NamedTemporaryFile(dir=OUTPUT.parent, delete=False, mode="w",
                                encoding="utf-8", newline="\n") as tmp:
            temp_path = Path(tmp.name)
            try:
                tmp.write(svg)
                tmp.close()
                temp_path.replace(OUTPUT)
            finally:
                tmp.close()
                temp_path.unlink(missing_ok=True)
    except (OSError, ValueError, subprocess.CalledProcessError) as exc:
        detail = exc.stderr.strip() if isinstance(exc, subprocess.CalledProcessError) else str(exc)
        print(f"Could not refresh activity: {detail}", file=sys.stderr)
        return 1
    print(f"Updated {OUTPUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
