#!/usr/bin/env python3
"""Render the README workflow and captured CLI output as standalone SVG."""

from html import escape
import json
from pathlib import Path
import subprocess

from PIL import Image, ImageDraw, ImageFont


ASSETS = Path(__file__).resolve().parents[1] / "docs" / "assets" / "release-review"


def svg(title: str, width: int, height: int, body: str) -> str:
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
        f'viewBox="0 0 {width} {height}" role="img" aria-labelledby="title">\n'
        f'<title id="title">{escape(title)}</title>\n{body}\n</svg>\n'
    )


def workflow() -> str:
    cards = [
        ("Input", ("ELF, PE, Mach-O", "Source trees", "Package manifests")),
        ("Inspect", ("Map sections and symbols", "Decode instructions and xrefs", "Resolve package versions")),
        ("Results", ("CLI and JSON", "MCP tool responses", "Saved evidence")),
    ]
    body = [
        '<rect width="100%" height="100%" rx="16" fill="#101116"/>',
        '<path d="M24 20 H98 L91 26 H24Z" fill="#ff5057"/>',
        '<defs><marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" '
        'markerWidth="7" markerHeight="7" orient="auto">'
        '<path d="M 0 0 L 10 5 L 0 10 z" fill="#8293ad"/></marker></defs>',
        '<g fill="none" stroke="#8293ad" stroke-width="2" marker-end="url(#arrow)">'
        '<path d="M 300 138 H 332"/><path d="M 615 138 H 647"/></g>',
        '<g font-family="system-ui, sans-serif">',
    ]
    for index, (label, lines) in enumerate(cards):
        x = 24 + index * 315
        body.append(
            f'<rect x="{x}" y="47" width="270" height="182" rx="12" '
            'fill="#1b1d25" stroke="#3b3e4b"/>'
        )
        body.append(
            f'<text x="{x + 24}" y="87" fill="#ff8589" font-size="22" '
            f'font-weight="700">{escape(label)}</text>'
        )
        for offset, line in enumerate(lines):
            body.append(
                f'<text x="{x + 24}" y="{128 + 30 * offset}" fill="#e4eaf5" '
                f'font-size="16">{escape(line)}</text>'
            )
    body.append("</g>")
    return svg("xt-forge inputs, analysis, and results", 948, 276, "\n".join(body))


def terminal(title: str, lines: list[str]) -> str:
    width = max(680, 48 + 9 * max(map(len, lines)))
    height = 80 + 23 * len(lines)
    body = [
        '<rect width="100%" height="100%" rx="12" fill="#111827"/>',
        f'<text x="24" y="33" fill="#a9b7cf" font-family="system-ui, sans-serif" '
        f'font-size="15">{escape(title)}</text>',
        '<g font-family="monospace" font-size="14" xml:space="preserve">',
    ]
    for index, line in enumerate(lines):
        color = "#9be7cc" if index == 0 else "#e4eaf5"
        body.append(f'<text x="24" y="{63 + 23 * index}" fill="{color}">{escape(line)}</text>')
    body.append("</g>")
    return svg(title, width, height, "\n".join(body))


def capture(name: str) -> tuple[str, dict]:
    command, _, output = (ASSETS / f"{name}.txt").read_text().partition("\n")
    return command, json.loads(output)


def animation(filename: str, title: str, stages: list[tuple[str, str, list[str], list[tuple[str, str]]]]) -> None:
    def font(family: str, size: int):
        try:
            match = subprocess.check_output(["fc-match", "-f", "%{file}", family], text=True)
            return ImageFont.truetype(match, size)
        except (OSError, subprocess.CalledProcessError):
            return ImageFont.load_default(size=size)

    brand = font("sans-serif:style=Bold", 28)
    heading = font("sans-serif:style=Bold", 23)
    label = font("monospace:style=Bold", 14)
    mono = font("monospace", 15)
    small = font("monospace", 12)
    frames, durations = [], []
    for index, (stage, command, lines, details) in enumerate(stages):
        for visible in range(0, len(lines) + 1, 1):
            frame = Image.new("RGB", (960, 433), "#101116")
            draw = ImageDraw.Draw(frame)
            draw.rectangle((0, 0, 959, 4), fill="#ff5057")
            draw.text((26, 14), "XT", fill="#ff5057", font=brand)
            draw.text((76, 17), title, fill="#f1f3f9", font=heading)
            draw.line((26, 58, 934, 58), fill="#393b48")
            draw.rounded_rectangle((25, 75, 666, 365), 12, fill="#181a22", outline="#393b48")
            draw.rounded_rectangle((684, 75, 934, 365), 12, fill="#191b23", outline="#393b48")
            draw.text((44, 92), stage, fill="#ff8589", font=label)
            draw.line((44, 121, 645, 121), fill="#393b48")
            draw.text((44, 134), command, fill="#a2e8ca", font=small)
            for row, line in enumerate(lines[:visible]):
                draw.text((44, 166 + row * 21), line, fill="#e5e9f5", font=mono)
            for row, (key, value) in enumerate(details):
                y = 99 + row * 78
                draw.text((703, y), key, fill="#a8b0c5", font=small)
                draw.text((703, y + 24), value, fill="#f1f3f9", font=mono)
            for step, (leg, *_) in enumerate(stages):
                x = 25 + step * 300
                color = "#ff5057" if step == index else "#555b6c"
                draw.line((x, 389, x + 256, 389), width=2, fill=color)
                draw.text((x, 398), leg, fill=color if step != index else "#f1f3f9", font=small)
            frames.append(frame)
            durations.append(2200 if visible == len(lines) else (480 if visible == 0 else 180))
    frames[0].save(ASSETS / filename, save_all=True, append_images=frames[1:],
                   duration=durations, loop=0, optimize=True)


def main() -> None:
    overview_command, overview = capture("overview")
    command, disasm = capture("disassembly")
    xrefs_command, xrefs = capture("references")
    deps_command, inventory = capture("dependencies")
    image = overview["images"][0]
    call = next(ref for ref in xrefs["references"] if ref["kind"] == "call")
    package = inventory["dependencies"][0]
    instructions = [
        f"0x{item['address']:08x}  {item['bytes']:<18}  {item['text']}"
        for item in disasm["instructions"]
    ]
    deps = [
        f"{package['ecosystem']}   {package['name']}   {package['version']}",
        f"Source: {package['source']}    Scope: {package['scope']}",
        f"Resolved: {inventory['resolved_count']}   Unresolved: {inventory['unresolved_count']}",
    ]
    figures = {
        "workflow": workflow(),
        "disassembly": terminal("Instructions from main", [command, "", *instructions]),
        "dependencies": terminal("Dependency inventory", [deps_command, "", *deps]),
    }
    for name, figure in figures.items():
        (ASSETS / f"{name}.svg").write_text(figure, encoding="utf-8")
    animation("binary-walkthrough.gif", "Binary inspection", [
        ("Identify the image", overview_command,
         [f"Format:              {overview['format']}", f"Architecture:        {image['arch']}",
          f"Entry address:       0x{image['entry_point']:x}",
          f"Entry file offset:   0x{image['entry_file_offset']:x}"],
         [("INPUT", "demo"), ("BACKEND", overview["engine"]), ("ADDRESS SPACE", f"{image['bits']}-bit")]),
        ("Disassemble main", command, instructions,
         [("FUNCTION", disasm["name"]), ("SYMBOL SOURCE", disasm["name_source"]),
          ("INSTRUCTIONS", str(len(instructions)))]),
        ("Follow the call", xrefs_command,
         [f"Caller:     {call['function_name']} @ 0x{call['function']:x}",
          f"Call site:  0x{call['site']:x}",
          f"Target:     {call['target_name']} @ 0x{call['target']:x}"],
         [("REFERENCE", call["kind"]), ("TARGET SOURCE", call["target_source"]),
          ("MATCHING REFERENCES", str(xrefs["total_references"]))]),
    ])
    manifest = (ASSETS / "manifest.txt").read_text().splitlines()
    animation("dependency-walkthrough.gif", "Dependency inventory", [
        ("Read the manifest", "$ cat go.mod", manifest,
         [("INPUT", package["source"]), ("ECOSYSTEM", package["ecosystem"])]),
        ("Resolve package identity", deps_command, deps,
         [("PACKAGE", package["name"]), ("VERSION IN MANIFEST", package["raw_version"]),
          ("RESOLVED VERSION", package["version"])]),
    ])


if __name__ == "__main__":
    main()
