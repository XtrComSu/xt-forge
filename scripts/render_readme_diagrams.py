#!/usr/bin/env python3
"""Render the README diagrams and captured CLI walkthroughs."""

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


def feature_banner() -> str:
    cards = [
        ("ELF · PE · Mach-O", "Native inspection", "Sections, symbols and xrefs", "#ff303d"),
        ("4 MCP tools", "Compact catalog", "Discover, schema, call and batch", "#5fa8fa"),
        ("OSV", "Dependency checks", "Advisories for resolved versions", "#0ac68d"),
        ("JSON", "Analysis output", "Structured results and saved evidence", "#f5b449"),
    ]
    body = [
        '<rect width="100%" height="100%" fill="#0a0c11"/>',
        '<rect x="15" y="15" width="1170" height="169" rx="17" fill="#10121a" stroke="#343949"/>',
        '<path d="M34 16H1166" stroke="#ff303d" stroke-width="3" stroke-linecap="round"/>',
    ]
    for index, (headline, label, description, color) in enumerate(cards):
        x = 31 + index * 289
        body.extend([
            f'<rect x="{x}" y="36" width="270" height="131" rx="12" fill="#151823" stroke="#2d3343"/>',
            f'<circle cx="{x + 23}" cy="67" r="4" fill="{color}"/>',
            f'<text x="{x + 37}" y="76" fill="#f2f4fa" font-family="monospace" '
            f'font-weight="700" font-size="22">{escape(headline)}</text>',
            f'<text x="{x + 20}" y="110" fill="#c2cada" font-family="system-ui,sans-serif" '
            f'font-weight="600" font-size="15">{escape(label)}</text>',
            f'<text x="{x + 20}" y="136" fill="#a3aec4" font-family="system-ui,sans-serif" '
            f'font-size="13">{escape(description)}</text>',
        ])
    return svg("xt-forge capabilities", 1200, 199, "\n".join(body))


def animation(filename: str, title: str, stages: list[tuple[str, str, list[str], list[tuple[str, str]]]]) -> None:
    def font(family: str, size: int):
        try:
            match = subprocess.check_output(["fc-match", "-f", "%{file}", family], text=True)
            return ImageFont.truetype(match, size)
        except (OSError, subprocess.CalledProcessError):
            return ImageFont.load_default(size=size)

    heading = font("monospace:style=Bold", 19)
    label = font("monospace:style=Bold", 15)
    mono = font("monospace", 17)
    small = font("monospace", 14)
    icon_path = ASSETS.parent / "xtforge-icon.png"
    with Image.open(icon_path) as logo:
        icon = logo.convert("RGBA").resize((32, 32), Image.Resampling.LANCZOS)
    frames, durations = [], []
    red, green, blue, white, muted = "#ff303d", "#25ce99", "#6aaefd", "#eef0f6", "#949eb3"
    for index, (stage, command, lines, details) in enumerate(stages):
        chrome = Image.new("RGB", (1200, 645), "#090a0e")
        draw = ImageDraw.Draw(chrome)
        draw.rounded_rectangle((18, 18, 1181, 626), 16, fill="#0f1016", outline="#363a49", width=2)
        draw.rounded_rectangle((19, 19, 1180, 77), 15, fill="#15171e")
        draw.rectangle((19, 51, 1180, 77), fill="#15171e")
        chrome.paste(icon, (37, 32), icon)
        draw.text((79, 30), f"XT-FORGE  //  {title.upper()}", fill=white, font=heading)
        draw.text((79, 55), "Rust + Go + Python  /  CLI and MCP", fill=muted, font=small)
        draw.rounded_rectangle((918, 32, 1157, 64), 8, fill="#13141a", outline=red)
        draw.text((1037, 48), "XT-OSS  •  v0.4.8 DAMASCUS", fill=red, font=label, anchor="mm")
        draw.line((19, 77, 1180, 77), fill=red)
        x = 38
        for step, (name, *_) in enumerate(stages):
            tab = f"{step + 1:02d}  {name}"
            width = int(draw.textlength(tab, font=label)) + 26
            active = step == index
            draw.rounded_rectangle((x, 93, x + width, 126), 7,
                                   fill="#24181f" if active else "#171920",
                                   outline=red if active else "#333747")
            draw.text((x + 13, 109), tab, fill=white if active else muted, font=label, anchor="lm")
            x += width + 10
        draw.rounded_rectangle((38, 139, 1162, 582), 11, fill="#08090d", outline="#303443")
        draw.text((42, 605), "XT-OSS  //  xt-forge  |  Rust + Go + Python", fill=muted, font=small, anchor="lm")
        draw.text((1158, 605), "XT-STYLE  •  xtrcom.xyz", fill=red, font=label, anchor="rm")
        prompt = "xt-forge:~$ "
        command = command.removeprefix("$ ")
        line_y = 161
        text_x = 58 + int(draw.textlength(prompt, font=mono))
        step_size = max(1, len(command) // 12)
        typing = list(range(0, len(command), step_size))
        for count in typing:
            frame = chrome.copy()
            draw = ImageDraw.Draw(frame)
            draw.text((58, line_y), prompt, fill=red, font=mono)
            draw.text((text_x, line_y), command[:count], fill=white, font=mono)
            cursor = text_x + int(draw.textlength(command[:count], font=mono))
            draw.rectangle((cursor, line_y + 1, cursor + 9, line_y + 19), fill=red)
            frames.append(frame)
            durations.append(65 if count else 230)
        for visible in range(len(lines) + 1):
            frame = chrome.copy()
            draw = ImageDraw.Draw(frame)
            draw.text((58, line_y), prompt, fill=red, font=mono)
            draw.text((text_x, line_y), command, fill=white, font=mono)
            for row, line in enumerate(lines[:visible]):
                color = blue if line.lstrip().startswith("0x") else white
                draw.text((58, 205 + row * 27), line, fill=color, font=mono)
            if visible == len(lines):
                summary = "   |   ".join(f"{key.lower()}: {value}" for key, value in details)
                draw.rounded_rectangle((57, 528, 1141, 566), 7, fill="#111b1a", outline="#226f59")
                draw.text((70, 547), summary, fill=green, font=small, anchor="lm")
            frames.append(frame)
            durations.append(2300 if visible == len(lines) else 105)
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
        "features": feature_banner(),
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
