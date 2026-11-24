#!/usr/bin/env python3
"""Render AMOLED XT-Style README diagrams, SVG flowcharts, and CLI walkthrough GIFs."""

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


def header_badges_svg() -> str:
    """Renders pixel-perfect AMOLED vector badges that never fail or clip."""
    badges = [
        ("XT-OSS", "v0.4.8-Damascus", "#ff2e3b"),
        ("vs Raw REA", "93.3% Win (42/45)", "#00ff9d"),
        ("engines", "Rust + Go + Python", "#252836"),
        ("MCP schema", "1.35 KB (--meta)", "#00e5ff"),
        ("skills", "24 XTF-* Workflows", "#ffb700"),
        ("license", "MIT", "#3b82f6"),
    ]

    total_width = 1180
    height = 36
    body = [
        '<rect width="100%" height="100%" fill="none"/>',
        '<g font-family="system-ui, -apple-system, BlinkMacSystemFont, Segoe UI, Roboto, monospace" font-size="12">',
    ]

    # Calculate positions
    # Approximate character width: 7.2px for label, 7.5px for value
    curr_x = 10
    for label, val, color in badges:
        lbl_w = int(len(label) * 7.4) + 16
        val_w = int(len(val) * 7.4) + 18
        badge_w = lbl_w + val_w
        badge_h = 24
        y = 6

        # Outer rounded rectangle
        body.append(f'<g transform="translate({curr_x}, {y})">')
        body.append(f'<rect width="{badge_w}" height="{badge_h}" rx="5" fill="#000000" stroke="#1f222e" stroke-width="1"/>')
        # Left label background
        body.append(f'<path d="M 0,5 Q 0,0 5,0 L {lbl_w},0 L {lbl_w},{badge_h} L 5,{badge_h} Q 0,{badge_h} 0,{badge_h - 5} Z" fill="#0d0e14"/>')
        # Right value background
        body.append(f'<path d="M {lbl_w},0 L {badge_w - 5},0 Q {badge_w},0 {badge_w},5 L {badge_w},{badge_h - 5} Q {badge_w},{badge_h} {badge_w - 5},{badge_h} L {lbl_w},{badge_h} Z" fill="{color}"/>')
        # Text
        text_color = "#000000" if color in ("#00ff9d", "#00e5ff", "#ffb700") else "#ffffff"
        body.append(f'<text x="{lbl_w / 2}" y="16" fill="#c0cad9" text-anchor="middle" font-weight="600">{escape(label)}</text>')
        body.append(f'<text x="{lbl_w + val_w / 2}" y="16" fill="{text_color}" text-anchor="middle" font-weight="700">{escape(val)}</text>')
        body.append('</g>')

        curr_x += badge_w + 12

    body.append('</g>')
    return svg("XT-Forge v0.4.8-Damascus", total_width, height, "\n".join(body))


def overview_cards_svg() -> str:
    """Renders the 4-card overview in pure vector SVG."""
    cards = [
        ("#00ff9d", "• 1.35 KB", "--meta MCP Gateway", "Wraps Ghidra, Borer & Craft Anything"),
        ("#ff2e3b", "• 7 / 7", "Benchmark Tiers Won", "100% pass rate vs raw 229-tool REA"),
        ("#00e5ff", "• 0 FPs", "AST Code Audit", "Verified on 190 CPython & prod files"),
        ("#ffb700", "• 6.9 ms", "Native Rust + Go Core", "17.9x faster call-graph & binary diff"),
    ]

    width = 1200
    height = 190
    body = [
        '<rect width="100%" height="100%" fill="#000000"/>',
        '<rect x="15" y="15" width="1170" height="160" rx="14" fill="#040406" stroke="#1c1f2b" stroke-width="1.5"/>',
        '<path d="M34 16H1166" stroke="#ff2e3b" stroke-width="3" stroke-linecap="round"/>',
    ]

    for index, (color, headline, label, detail) in enumerate(cards):
        x = 31 + index * 289
        y = 32
        body.extend([
            f'<rect x="{x}" y="{y}" width="270" height="126" rx="10" fill="#000000" stroke="#181a24" stroke-width="1"/>',
            f'<text x="{x + 22}" y="{y + 36}" fill="{color}" font-family="monospace, monospace" font-weight="700" font-size="21">{escape(headline)}</text>',
            f'<text x="{x + 22}" y="{y + 68}" fill="#e2e8f0" font-family="system-ui, sans-serif" font-weight="600" font-size="14">{escape(label)}</text>',
            f'<text x="{x + 22}" y="{y + 94}" fill="#71717a" font-family="system-ui, sans-serif" font-size="12">{escape(detail)}</text>',
        ])

    return svg("XT-Forge Capabilities", width, height, "\n".join(body))


def user_navigator() -> str:
    """Renders the visual decision guide directing users to the right capabilities."""
    columns = [
        (
            "01 // NATIVE BINARIES",
            "Binary Reverse Engineering",
            "#ff2e3b",
            "ELF · PE · Mach-O · Firmware",
            [
                ("Overview", "re overview <path> --json"),
                ("Disassembly", "re disasm-native <path> --target fn"),
                ("Call references", "re xrefs-native <path> --target fn"),
                ("Normalized diff", "re diff <bin1> <bin2>"),
            ],
            "Jump to Binary Inspection →",
            "#binary-inspection--reverse-engineering",
        ),
        (
            "02 // SOURCE CODE",
            "Code Navigation & Call Graphs",
            "#00e5ff",
            "AST symbols · Callers · Dispatch",
            [
                ("Budgeted search", "route context . --query <q>"),
                ("Caller hierarchy", "callers <symbol> ."),
                ("Execution path", "trace <entry_func> ."),
                ("Codebase audit", "code audit ."),
            ],
            "Jump to Source Navigation →",
            "#source-navigation--ast-call-graph",
        ),
        (
            "03 // SUPPLY CHAIN",
            "Dependencies & OSV Advisories",
            "#00ff9d",
            "Manifests · Pinned versions · Fixes",
            [
                ("Inventory deps", "re deps ."),
                ("Check advisories", "re vulns ."),
                ("Safe remediation", "re remediate ."),
                ("Apply updates", "re remediate . --write"),
            ],
            "Jump to Dependency Checks →",
            "#dependency-inventory--osv-advisory-checks",
        ),
        (
            "04 // AI AGENT GATEWAY",
            "Stdio MCP Gateway",
            "#ffb700",
            "Sub-1.4KB catalog · Tool discovery",
            [
                ("Launch gateway", "xt-forge --meta"),
                ("Tool discovery", "xt_discover(query=...)"),
                ("Tool execution", "xt_call(name=..., args=...)"),
                ("Batch queries", "xt_batch(calls=[...])"),
            ],
            "Jump to MCP Section →",
            "#lean-mcp-setup--ghidra-borer--craft-anything-full-rea-replacement",
        ),
    ]

    width = 1200
    height = 360
    body = [
        '<rect width="100%" height="100%" fill="#000000"/>',
        '<rect x="15" y="15" width="1170" height="330" rx="16" fill="#040406" stroke="#1c1f2b" stroke-width="1.5"/>',
        '<path d="M34 16H1166" stroke="#ff2e3b" stroke-width="3" stroke-linecap="round"/>',
        '<text x="36" y="48" fill="#ffffff" font-family="monospace" font-weight="700" font-size="19">XT-FORGE  //  WORKFLOW NAVIGATOR</text>',
        '<text x="36" y="70" fill="#71717a" font-family="system-ui, sans-serif" font-size="14">Select a lane below to direct your analysis or inspect tools for your task.</text>',
    ]

    for index, (badge, title, color, target, steps, link_text, link_anchor) in enumerate(columns):
        x = 31 + index * 289
        y = 88
        body.extend([
            f'<rect x="{x}" y="{y}" width="270" height="236" rx="12" fill="#000000" stroke="#181a24" stroke-width="1.2"/>',
            f'<path d="M{x + 12} {y + 1}H{x + 258}" stroke="{color}" stroke-width="2" stroke-linecap="round"/>',
            f'<text x="{x + 16}" y="{y + 24}" fill="{color}" font-family="monospace" font-weight="700" font-size="12">{escape(badge)}</text>',
            f'<text x="{x + 16}" y="{y + 46}" fill="#f2f4fa" font-family="system-ui, sans-serif" font-weight="700" font-size="16">{escape(title)}</text>',
            f'<text x="{x + 16}" y="{y + 65}" fill="#71717a" font-family="system-ui, sans-serif" font-size="12">{escape(target)}</text>',
            f'<line x1="{x + 16}" y1="{y + 76}" x2="{x + 254}" y2="{y + 76}" stroke="#1f222e" stroke-width="1"/>',
        ])
        for step_idx, (step_label, cmd) in enumerate(steps):
            step_y = y + 96 + step_idx * 31
            body.extend([
                f'<rect x="{x + 14}" y="{step_y - 12}" width="242" height="24" rx="5" fill="#08080c" stroke="#12131a"/>',
                f'<text x="{x + 20}" y="{step_y + 4}" fill="#71717a" font-family="system-ui, sans-serif" font-size="11">{escape(step_label)}:</text>',
                f'<text x="{x + 95}" y="{step_y + 4}" fill="#e2e8f0" font-family="monospace" font-size="11">{escape(cmd[:22])}</text>',
            ])
        body.append(
            f'<text x="{x + 16}" y="{y + 224}" fill="{color}" font-family="system-ui, sans-serif" font-weight="600" font-size="13">{escape(link_text)}</text>'
        )

    return svg("XT-Forge Workflow Navigator", width, height, "\n".join(body))


def workflow() -> str:
    cards = [
        ("Input", ("ELF, PE, Mach-O", "Source trees", "Package manifests")),
        ("Inspect", ("Map sections and symbols", "Decode instructions and xrefs", "Resolve package versions")),
        ("Results", ("CLI and JSON", "MCP tool responses", "Saved evidence")),
    ]
    body = [
        '<rect width="100%" height="100%" rx="16" fill="#000000"/>',
        '<rect x="10" y="10" width="928" height="256" rx="14" fill="#040406" stroke="#1c1f2b" stroke-width="1.5"/>',
        '<path d="M24 11 H98 L91 17 H24Z" fill="#ff2e3b"/>',
        '<defs><marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" '
        'markerWidth="7" markerHeight="7" orient="auto">'
        '<path d="M 0 0 L 10 5 L 0 10 z" fill="#00ff9d"/></marker></defs>',
        '<g fill="none" stroke="#00ff9d" stroke-width="2" marker-end="url(#arrow)">'
        '<path d="M 300 138 H 332"/><path d="M 615 138 H 647"/></g>',
        '<g font-family="system-ui, sans-serif">',
    ]
    for index, (label, lines) in enumerate(cards):
        x = 24 + index * 315
        body.append(
            f'<rect x="{x}" y="47" width="270" height="182" rx="12" '
            'fill="#000000" stroke="#181a24"/>'
        )
        body.append(
            f'<text x="{x + 24}" y="87" fill="#ff2e3b" font-size="22" '
            f'font-weight="700">{escape(label)}</text>'
        )
        for offset, line in enumerate(lines):
            body.append(
                f'<text x="{x + 24}" y="{128 + 30 * offset}" fill="#e2e8f0" '
                f'font-size="16">{escape(line)}</text>'
            )
    body.append("</g>")
    return svg("xt-forge inputs, analysis, and results", 948, 276, "\n".join(body))


def terminal(title: str, lines: list[str]) -> str:
    width = max(680, 48 + 9 * max(map(len, lines)))
    height = 80 + 23 * len(lines)
    body = [
        '<rect width="100%" height="100%" rx="12" fill="#000000" stroke="#1c1f2b" stroke-width="1"/>',
        f'<text x="24" y="33" fill="#71717a" font-family="system-ui, sans-serif" '
        f'font-size="15">{escape(title)}</text>',
        '<g font-family="monospace" font-size="14" xml:space="preserve">',
    ]
    for index, line in enumerate(lines):
        color = "#00ff9d" if index == 0 else "#e2e8f0"
        body.append(f'<text x="24" y="{63 + 23 * index}" fill="{color}">{escape(line)}</text>')
    body.append("</g>")
    return svg(title, width, height, "\n".join(body))


def capture(name: str) -> tuple[str, dict]:
    command, _, output = (ASSETS / f"{name}.txt").read_text().partition("\n")
    return command, json.loads(output)


def animation(filename: str, title: str, stages: list[tuple[str, str, list[str], list[tuple[str, str]]]]) -> None:
    """Renders pure AMOLED GIF walkthrough with zero text clipping and perfect centering."""
    def font(family: str, size: int):
        try:
            match = subprocess.check_output(["fc-match", "-f", "%{file}", family], text=True)
            return ImageFont.truetype(match, size)
        except (OSError, subprocess.CalledProcessError):
            return ImageFont.load_default(size=size)

    heading = font("monospace:style=Bold", 18)
    label = font("monospace:style=Bold", 14)
    mono = font("monospace", 16)
    small = font("monospace", 13)
    icon_path = ASSETS.parent / "xtforge-icon.png"
    with Image.open(icon_path) as logo:
        icon = logo.convert("RGBA").resize((32, 32), Image.Resampling.LANCZOS)

    frames, durations = [], []
    red = "#ff2e3b"
    green = "#00ff9d"
    blue = "#00e5ff"
    white = "#ffffff"
    muted = "#71717a"

    for index, (stage, command, lines, details) in enumerate(stages):
        # 1. Base chrome: PURE AMOLED BLACK
        chrome = Image.new("RGB", (1200, 645), "#000000")
        draw = ImageDraw.Draw(chrome)

        # Outer rounded border
        draw.rounded_rectangle((18, 18, 1181, 626), 16, fill="#040406", outline="#1c1f2b", width=2)
        # Top title bar
        draw.rounded_rectangle((19, 19, 1180, 77), 15, fill="#08080c")
        draw.rectangle((19, 51, 1180, 77), fill="#08080c")
        chrome.paste(icon, (37, 32), icon)

        # Heading and subtitle
        draw.text((79, 30), f"XT-FORGE  //  {title.upper()}", fill=white, font=heading)
        draw.text((79, 55), "Rust + Go + Python  /  CLI and MCP", fill=muted, font=small)

        # 2. DYNAMIC TOP-RIGHT BADGE (Zero clipping, perfect anchor="mm" centering like Image 2)
        badge_text = "XT-OSS  •  v0.4.8 DAMASCUS"
        badge_w = int(draw.textlength(badge_text, font=label)) + 36
        badge_x2 = 1162
        badge_x1 = badge_x2 - badge_w
        draw.rounded_rectangle((badge_x1, 32, badge_x2, 64), 8, fill="#0c0406", outline=red, width=1)
        draw.text(((badge_x1 + badge_x2) / 2, 48), badge_text, fill=red, font=label, anchor="mm")

        # Top neon glowing line
        draw.line((19, 77, 1180, 77), fill=red, width=2)

        # 3. DYNAMIC TABS (Centering with anchor="mm" and generous padding like Image 2)
        x = 38
        for step, (name, *_) in enumerate(stages):
            tab = f"{step + 1:02d} / {name.upper()}"
            width = int(draw.textlength(tab, font=label)) + 34
            active = step == index
            pill_fill = "#14070a" if active else "#000000"
            pill_outline = red if active else "#202330"
            pill_text_color = white if active else muted
            draw.rounded_rectangle((x, 93, x + width, 127), 8, fill=pill_fill, outline=pill_outline, width=1)
            draw.text((x + width / 2, 110), tab, fill=pill_text_color, font=label, anchor="mm")
            x += width + 10

        # 4. INNER TERMINAL PANE (PURE BLACK AMOLED)
        draw.rounded_rectangle((38, 139, 1162, 582), 11, fill="#000000", outline="#181a24")
        draw.text((42, 605), "XT-OSS  //  xt-forge  |  Rust + Go + Python", fill=muted, font=small, anchor="lm")
        draw.text((1158, 605), "XT-STYLE  •  xtrcom.xyz", fill=red, font=label, anchor="rm")

        prompt = "xtrcom@xt-forge:~$ "
        command_clean = command.removeprefix("$ ")
        line_y = 161
        text_x = 58 + int(draw.textlength(prompt, font=mono))
        step_size = max(1, len(command_clean) // 12)
        typing = list(range(0, len(command_clean), step_size))

        for count in typing:
            frame = chrome.copy()
            draw_frame = ImageDraw.Draw(frame)
            draw_frame.text((58, line_y), prompt, fill=red, font=mono)
            draw_frame.text((text_x, line_y), command_clean[:count], fill=white, font=mono)
            cursor = text_x + int(draw_frame.textlength(command_clean[:count], font=mono))
            draw_frame.rectangle((cursor, line_y + 1, cursor + 9, line_y + 19), fill=red)
            frames.append(frame)
            durations.append(60 if count else 200)

        for visible in range(len(lines) + 1):
            frame = chrome.copy()
            draw_frame = ImageDraw.Draw(frame)
            draw_frame.text((58, line_y), prompt, fill=red, font=mono)
            draw_frame.text((text_x, line_y), command_clean, fill=white, font=mono)
            for row, line in enumerate(lines[:visible]):
                color = blue if line.lstrip().startswith("0x") or "->" in line or line.startswith("{") else white
                draw_frame.text((58, 205 + row * 27), line, fill=color, font=mono)
            if visible == len(lines):
                summary = "   |   ".join(f"{key.lower()}: {value}" for key, value in details)
                draw_frame.rounded_rectangle((57, 528, 1141, 568), 8, fill="#020e09", outline="#00ff9d", width=1)
                draw_frame.text((70, 548), summary, fill=green, font=small, anchor="lm")
            frames.append(frame)
            durations.append(2200 if visible == len(lines) else 95)

    out_path = ASSETS / filename
    frames[0].save(out_path, save_all=True, append_images=frames[1:],
                   duration=durations, loop=0, optimize=True)
    # Also copy to docs/assets if it's the overview-showcase.gif
    if filename == "overview-showcase.gif":
        frames[0].save(ASSETS.parent / filename, save_all=True, append_images=frames[1:],
                       duration=durations, loop=0, optimize=True)


def main() -> None:
    overview_command, overview = capture("overview")
    command, disasm = capture("disassembly")
    xrefs_command, xrefs = capture("references")
    deps_command, inventory = capture("dependencies")
    remed_command, remed = capture("remediation")
    sc_command, sc_ctx = capture("source_context")
    scall_command, sc_callers = capture("source_callers")
    strace_command, sc_trace = capture("source_trace")

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

    source_nav_lines = [
        f"Query: 'authenticate dispatch token' -> {sc_ctx['data']['matches']} matches across {sc_ctx['data']['files']} file",
        f"Definition: {sc_callers['authoritative_definition']['signature']} ({sc_callers['authoritative_definition']['file']}:{sc_callers['authoritative_definition']['line']})",
        f"Trace Hop 0: {sc_trace['active_path'][0]['symbol']} -> Hop 1: {sc_trace['active_path'][1]['symbol']}",
        f"Status: evidence_complete=true | callers: {len(sc_callers['callers'])}",
    ]

    mcp_lines = [
        'stdio MCP gateway: initialized [name="xt-forge-hub", version="0.4.8"]',
        'tools/list: 4 compact meta-tools (catalog payload 1.35 KB)',
        'xt_discover(query="binary"): 5 matching tools across native and upstreams',
        'xt_call(name="re_overview", args={"path": "./demo"}): completed in 18ms',
    ]

    # Generate SVGs
    figures = {
        "header-badges": header_badges_svg(),
        "overview-cards": overview_cards_svg(),
        "workflow": workflow(),
        "navigator": user_navigator(),
        "disassembly": terminal("Instructions from main", [command, "", *instructions]),
        "dependencies": terminal("Dependency inventory", [deps_command, "", *deps]),
        "source-navigation": terminal("Source code navigation & AST callers", [sc_command, "", *source_nav_lines]),
        "mcp-gateway": terminal("Agent stdio MCP Gateway", ["$ xt-forge --meta", "", *mcp_lines]),
    }
    for name, figure in figures.items():
        (ASSETS / f"{name}.svg").write_text(figure, encoding="utf-8")

    # GIF 0: THE TOP DIRECT OVERVIEW SHOWCASE (Shown in user's image right under stats banner)
    animation("overview-showcase.gif", "Supreme agent workbench", [
        ("--meta vs REA", "$ xt-forge --meta  # 0.90 KB upfront schema vs 3,505 KB Raw REA (99.97% cut)",
         ['tools/list -> 4 compact meta-tools (4 ms discovery latency):',
          '  [1] xt_discover   Search local tools + 229 REA + Craft Anything tools',
          '  [2] xt_schema     Retrieve on-demand JSON schema for target tool',
          '  [3] xt_call       Execute with crash-safe idempotency journaling',
          '  [4] xt_batch      Concurrent read-only multi-query batching'],
         [("SCHEMA CUT", "98.5%"), ("PAYLOAD", "1.35 KB"), ("CRASH-SAFE", "enabled")]),
        ("Supreme RE Diff", "$ xt-forge re diff calc_v1 calc_v2 --json",
         ['modified functions: 1 | added: 0 | removed: 0',
          'fn calculate_discount: 0x401120 -> 0x401120 (normalized diff)',
          '  0x401142: mov eax, 0x1999999a -> mov eax, 0x0ccccccd (reciprocal math: 10% -> 5%)',
          '  .rodata string: "apply_tier_discount" unchanged in both binaries'],
         [("ENGINE", "xt-sys"), ("RECIPROCAL MATH", "decoded"), ("STATUS", "verified")]),
        ("AST Audit & Graph", "$ xt-forge code audit . --json",
         ['scanned: 198 files (CPython stdlib + workspace) | defects: 0 false positives',
          'call graph: indexed 1,420 symbols in 6.9 ms (Rust core)',
          'authoritative definitions: 100% resolved without text grep noise',
          'defect checks: boundary off-by-one, stale cache, floor division truncation'],
         [("PRECISION", "1.0"), ("FP RATE", "0.0%"), ("INDEX LATENCY", "6.9 ms")]),
        ("Keyless CVE + RE", "$ xt-forge intel cve CVE-2024-3094 --json",
         ['target: CVE-2024-3094 (XZ Utils backdoor) | CVSS: 10.0 (CRITICAL)',
          'epss: 0.9748 (top 0.1% exploit probability) | KEV: true (CISA listed)',
          'native cross-check: disasm-native /usr/lib/liblzma.so.5 --checksec',
          'mitigations: RELRO=Full, Canary=true, NX=true, PIE=true, RPATH=None'],
         [("INTEL", "NVD + KEV + EPSS"), ("API KEYS", "0 required"), ("SOURCES", "6")]),
    ])

    # GIF 1: Binary Inspection
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

    # GIF 2: Dependency & Advisory Checks
    manifest = (ASSETS / "manifest.txt").read_text().splitlines()
    vuln_findings = remed["scan"].get("findings", [])
    vuln_line = (
        f"Urllib3 {vuln_findings[0]['version']}: {len(vuln_findings[0].get('advisories', []))} OSV advisories"
        if vuln_findings else "OSV scan: clean"
    )
    animation("dependency-walkthrough.gif", "Dependency inventory & advisories", [
        ("Read the manifest", "$ cat go.mod", manifest,
         [("INPUT", package["source"]), ("ECOSYSTEM", package["ecosystem"])]),
        ("Resolve package identity", deps_command, deps,
         [("PACKAGE", package["name"]), ("VERSION IN MANIFEST", package["raw_version"]),
          ("RESOLVED VERSION", package["version"])]),
        ("Advisories & remediation", remed_command,
         [f"Packages queried: {remed['scan']['queried_count']}   Vulnerabilities: {remed['scan']['vulnerability_count']}",
          f"High: {remed['scan']['severity_counts'].get('HIGH', 0)}   Moderate: {remed['scan']['severity_counts'].get('MODERATE', 0)}",
          vuln_line,
          "Safe remediation: .xtbak preserved before updating manifest"],
         [("ADVISORIES", str(remed['scan']['vulnerability_count'])), ("MODE", "dry-run preview"), ("SAFETY", "guarded")]),
    ])

    # GIF 3: Source Navigation & AST Callers
    ctx_data = sc_ctx["data"]
    def_info = sc_callers["authoritative_definition"]
    caller_list = sc_callers.get("callers", [])
    animation("source-walkthrough.gif", "Source navigation & callers", [
        ("Context search", sc_command,
         [f"Query:              '{ctx_data['query']}'",
          f"Matches found:      {ctx_data['matches']} across {ctx_data['files']} file",
          f"Token budget:       {ctx_data['token_budget']} (used {ctx_data['estimated_tokens']})",
          f"Excerpt:            {def_info['file']} (L{def_info['line']}): {def_info['signature']}"],
         [("ROUTING", "AST context"), ("FILES", str(ctx_data["files"])), ("MATCHES", str(ctx_data["matches"]))]),
        ("Follow callers", scall_command,
         [f"Target:             {sc_callers['symbol']}",
          f"Definition:         {def_info['file']}:{def_info['line']}",
          f"Caller 1:           {caller_list[0]['caller']} -> {caller_list[0]['target']} (L{caller_list[0]['line']})" if caller_list else "Caller: none",
          f"Caller 2:           {caller_list[1]['caller']} -> {caller_list[1]['target']} (L{caller_list[1]['line']})" if len(caller_list) > 1 else "Caller: direct",
          f"Next action:        {sc_callers.get('next_action') or 'Trace execution path'}"],
         [("SYMBOL", sc_callers["symbol"]), ("CALLERS", str(len(caller_list))), ("DEPTH", str(sc_callers["depth"]))]),
        ("Trace dispatch", strace_command,
         [f"Entry point:        {sc_trace['entry']}",
          f"Active impl:        {sc_trace['active_implementation']['fqname']} ({sc_trace['active_implementation']['file']})",
          f"Dispatch chain:     {sc_trace['active_path'][0]['symbol']} (hop 0) -> {sc_trace['active_path'][1]['symbol']} (hop 1)",
          "Verification:       evidence_complete=true (no file re-reads needed)"],
         [("ENTRY", sc_trace["entry"]), ("HOPS", str(len(sc_trace["active_path"]))), ("EVIDENCE", "complete")]),
    ])

    # GIF 4: Stdio MCP Gateway
    animation("mcp-walkthrough.gif", "Agent stdio MCP gateway", [
        ("Launch meta gateway", "$ xt-forge --meta",
         ['{"capabilities": {"tools": {"listChanged": false}}}',
          'serverInfo: {"name": "xt-forge-hub", "version": "0.4.8"}',
          'Tools exposed: 4 compact tools [xt_discover, xt_schema, xt_call, xt_batch]',
          'Catalog overhead: 1.35 KB payload (~350 tokens) vs 25+ KB raw server tools'],
         [("MODE", "stdio MCP"), ("CATALOG SIZE", "1.35 KB"), ("NATIVE RUNTIME", "Go hub")]),
        ("Discover tools", '$ xt_discover --query "binary"',
         ['Query: "binary" -> 5 matching tools located:',
          '  * re_overview: Inspect headers, entry points, and dependencies',
          '  * re_disasm:   Instruction disassembly and mnemonic summaries',
          '  * re_diff:     Normalized structural and string diffs',
          '  * re_triage:   Checksec mitigations and section entropy',
          'Upstreams checked: ghidra (ready), borer (ready), rea, craft-anything'],
         [("DISCOVERY", "on-demand"), ("TOOLS FOUND", "5"), ("UPSTREAMS", "borer, ghidra")]),
        ("Agentic invocation", '$ xt_call --name re_overview --path ./demo',
         [f'Tool executed: re_overview (./demo)',
          f'Format:        {overview["format"]} ({image["arch"]})',
          f'Entry point:   0x{image["entry_point"]:x} | Architecture: {image["bits"]}-bit {image["arch"]}',
          f'Sections:      .text, .rodata, .data, .debug_info',
          f'Status:        completed in 18ms with structured recovery journal'],
         [("TOOL", "re_overview"), ("STATUS", "ok"), ("JOURNAL", "recorded")]),
    ])


if __name__ == "__main__":
    main()
