#!/usr/bin/env python3
"""Render captured terminal output as a PNG, so a README can show real output as an image.

The input is a text file containing exactly what the command printed — these images are not
mockups. A `$ command` line is rendered in a different colour from its output so the reader can
tell what was run from what came back, and severity words are coloured the way the CLI colours
them.

Usage:
    python3 scripts/render_terminal_png.py captures/*.txt --out docs/assets
"""
from __future__ import annotations

import argparse
import re
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

# A real monospace face, because a proportional font makes aligned columns meaningless — and the
# columns are most of what these tools have to say.
FONT_CANDIDATES = [
    "/usr/share/fonts/TTF/JetBrainsMonoNLNerdFont-Regular.ttf",
    "/usr/share/fonts/TTF/JetBrainsMonoNerdFontMono-Regular.ttf",
    "/usr/share/fonts/TTF/CaskaydiaCoveNerdFontMono-Regular.ttf",
    "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
    "/usr/share/fonts/Adwaita/AdwaitaMono-Regular.ttf",
]
BOLD_CANDIDATES = [
    "/usr/share/fonts/TTF/JetBrainsMonoNLNerdFont-Bold.ttf",
    "/usr/share/fonts/TTF/JetBrainsMonoNerdFontMono-Bold.ttf",
    "/usr/share/fonts/TTF/CaskaydiaCoveNerdFontMono-Bold.ttf",
    "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf",
    "/usr/share/fonts/Adwaita/AdwaitaMono-Bold.ttf",
]

BACKGROUND = (13, 14, 20)
CHROME = (22, 24, 33)
BORDER = (42, 46, 60)
DEFAULT = (203, 208, 222)
PROMPT = (108, 214, 160)
COMMENT = (108, 116, 136)
SEVERITY = {
    "HIGH": (255, 92, 92),
    "CRITICAL": (255, 60, 60),
    "MODERATE": (240, 178, 70),
    "MEDIUM": (240, 178, 70),
    "LOW": (120, 190, 255),
    "UNKNOWN": (150, 156, 176),
}
ACCENT = (110, 180, 255)
OK = (108, 214, 160)
WARN = (240, 178, 70)
RISK = (255, 92, 92)


def _font(candidates: list[str], size: int) -> ImageFont.FreeTypeFont:
    for path in candidates:
        if Path(path).is_file():
            return ImageFont.truetype(path, size)
    raise SystemExit(f"no monospace font found; looked for {candidates}")


def _colour_for(line: str) -> tuple[int, int, int]:
    """Colour a line by what it is, not by where it is."""
    stripped = line.strip()
    if stripped.startswith("$ "):
        return PROMPT
    if stripped.startswith("#"):
        return COMMENT
    if "[ok" in stripped or "verified" in stripped.lower():
        return OK
    if "[RISK]" in stripped or "not an all-clear" in stripped:
        return RISK
    if "TRUNCATED" in stripped or "WARNING" in stripped:
        return WARN
    for word, colour in SEVERITY.items():
        if re.search(rf"\b{word}\b", stripped):
            return colour
    return DEFAULT


def render(text: str, *, size: int = 15, padding: int = 26, title: str = "") -> Image.Image:
    regular = _font(FONT_CANDIDATES, size)
    # Advance width of a single character, so columns line up exactly as in a terminal.
    advance = regular.getlength("M")
    line_height = int(size * 1.62)
    lines = text.expandtabs(4).rstrip("\n").splitlines() or [""]
    width = int(max(advance * max(len(line) for line in lines), 520) + padding * 2)
    chrome = 34 if title else 12
    height = line_height * len(lines) + padding * 2 + chrome

    image = Image.new("RGB", (width, height), BACKGROUND)
    draw = ImageDraw.Draw(image)
    if title:
        draw.rectangle([0, 0, width, chrome], fill=CHROME)
        for index, colour in enumerate([(255, 95, 86), (255, 189, 46), (39, 201, 63)]):
            draw.ellipse([14 + index * 20, chrome // 2 - 6, 26 + index * 20, chrome // 2 + 6],
                         fill=colour)
        draw.text((padding, chrome // 2 - size // 2 - 1), title, font=regular, fill=COMMENT)
    draw.rectangle([0, 0, width - 1, height - 1], outline=BORDER)

    y = chrome + padding
    for line in lines:
        draw.text((padding, y), line, font=regular, fill=_colour_for(line))
        y += line_height
    return image


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("sources", nargs="+")
    parser.add_argument("--out", required=True)
    parser.add_argument("--size", type=int, default=15)
    args = parser.parse_args()
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    for source in args.sources:
        path = Path(source)
        text = path.read_text()
        image = render(text, size=args.size, title=path.stem.replace("-", " "))
        target = out / f"{path.stem}.png"
        image.save(target, optimize=True)
        print(f"  {target}  {image.width}x{image.height}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
