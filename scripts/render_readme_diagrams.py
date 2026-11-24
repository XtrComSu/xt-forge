#!/usr/bin/env python3
"""Render the README workflow and captured CLI output as standalone SVG."""

from html import escape
import json
from pathlib import Path


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
        '<rect width="100%" height="100%" rx="16" fill="#111827"/>',
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
            'fill="#1c273a" stroke="#42516a"/>'
        )
        body.append(
            f'<text x="{x + 24}" y="87" fill="#9be7cc" font-size="22" '
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


def main() -> None:
    command, _, output = (ASSETS / "disassembly.txt").read_text().partition("\n")
    disasm = json.loads(output)
    instructions = [
        f"0x{item['address']:08x}  {item['bytes']:<18}  {item['text']}"
        for item in disasm["instructions"]
    ]
    deps = (ASSETS / "dependencies.txt").read_text().splitlines()
    figures = {
        "workflow": workflow(),
        "disassembly": terminal("Instructions from main", [command, "", *instructions]),
        "dependencies": terminal("Dependency inventory", deps),
    }
    for name, figure in figures.items():
        (ASSETS / f"{name}.svg").write_text(figure, encoding="utf-8")


if __name__ == "__main__":
    main()
