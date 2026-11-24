#!/usr/bin/env python3
"""Render professional dark-slate UI tour players and overview showcase GIFs.

Matches the natural XT-Forge design system:
- High-contrast natural dark slate palette (#090a0e, #0f1016, #15171e, #08090d, #272a36, #ff303d)
- Dynamic pill widths and symmetric padding (eliminates all left/right text clipping)
- Updated to v0.4.8-Damascus standards across all players
- Smooth typing and high-contrast terminal syntax reveals
"""

import subprocess
from pathlib import Path
from PIL import Image, ImageDraw, ImageFont


ROOT = Path(__file__).resolve().parents[1]
ASSETS = ROOT / "docs" / "assets"


def get_font(family: str, size: int):
    try:
        match = subprocess.check_output(["fc-match", "-f", "%{file}", family], text=True)
        return ImageFont.truetype(match, size)
    except (OSError, subprocess.CalledProcessError):
        return ImageFont.load_default(size=size)


def render_overview_showcase(filename: str = "overview-showcase.gif") -> None:
    """Renders the top multi-tab overview player matching the original v0.4.8 showcase."""
    width, height = 1040, 580

    title_font = get_font("sans-serif:style=Bold", 14)
    sub_font = get_font("sans-serif", 11)
    badge_font = get_font("monospace:style=Bold", 13)
    tab_font = get_font("monospace:style=Bold", 12)
    term_title_font = get_font("monospace", 12)
    mono_font = get_font("monospace", 14)
    small_font = get_font("monospace", 11)

    colors = {
        "bg": "#090a0e",
        "card": "#0f1016",
        "card_border": "#272a36",
        "header_fill": "#15171e",
        "term_bg": "#08090d",
        "term_border": "#1c202d",
        "red": "#ff303d",
        "green": "#0ac68d",
        "blue": "#5fa8fa",
        "white": "#f2f4fa",
        "muted": "#8b98b0",
        "amber": "#f5b449",
        "badge_bg": "#190d10",
        "tab_active_bg": "#22141a",
        "tab_inactive_bg": "#14161f",
        "tab_inactive_border": "#272a38",
    }

    icon_path = ASSETS / "xtforge-icon.png"
    icon = None
    if icon_path.is_file():
        with Image.open(icon_path) as logo:
            icon = logo.convert("RGBA").resize((26, 26), Image.Resampling.LANCZOS)

    tabs = [
        (
            "01  --meta vs REA",
            "xt-forge --meta  # 1.35 KB schema vs 3,505 KB Raw REA (99.96% cut)",
            [
                ('tools/list -> 4 compact meta-tools (4 ms discovery latency):', "white"),
                ('  [1] xt_discover    Search local tools + 229 REA + Craft Anything tools', "blue"),
                ('  [2] xt_schema      Fetch JSON-RPC schema on demand (zero upfront tokens)', "green"),
                ('  [3] xt_call        Crash-safe tool execution with idempotent replay', "green"),
                ('  [4] xt_batch       Concurrent read-only analysis without prompt bloat', "blue"),
                ('Ready for autonomous AI coding agent workflow execution!', "amber"),
            ],
            "00:04", "00:24", 0.20,
        ),
        (
            "02  Supreme RE Diff",
            "xt-forge re diff bin/calc_v1 bin/calc_v2 --json",
            [
                ('modified_functions: [{ "name": "apply_tier_discount", "rva": "0x116c" }]', "blue"),
                ('insn_diff : imul $0x66666667,%rdx | -sar $0x2,%edx | +sar $0x3,%edx', "white"),
                ('diff_notes: "strength-reduced division: /10 (10%) in v1 -> /20 (5%) in v2"', "red"),
                ('disasm_v2 : 117e: lea 0xe7f(%rip),%rdx  # 2004 ; str="gold"', "green"),
                ('disasm_v2 : 11c0: lea 0xe42(%rip),%rdx  # 2009 ; str="silver"', "green"),
                ('Zero manual hex or .rodata offset math required by the agent!', "amber"),
            ],
            "00:09", "00:24", 0.40,
        ),
        (
            "03  AST Audit & Graph",
            'xt-forge route context . --query "dispatch" --token-budget 1200',
            [
                ('query: "dispatch" -> 11 matches across service modules', "blue"),
                ('authoritative definition: service.py:3 def authenticate(token: str)', "green"),
                ('call graph: dispatch_request -> authenticate (hop 0 -> hop 1)', "white"),
                ('budget: 1,200 tokens allowed | 677 tokens packed (88.8% reduction)', "white"),
                ('Zero text grep hallucinations; 100% precision call tracing!', "amber"),
            ],
            "00:15", "00:24", 0.65,
        ),
        (
            "04  Keyless CVE + RE",
            "xt-forge intel cve CVE-2024-3094 && xt-forge re checksec target",
            [
                ('cve: CVE-2024-3094 | cvss: 10.0 (CRITICAL) | cisa kev: true', "red"),
                ('epss exploit probability: 97.48% (top tier active exploit risk)', "blue"),
                ('checksec /usr/lib/liblzma.so.5: RELRO=Full, Canary=true, NX=true, PIE=true', "green"),
                ('Keyless intelligence gathered across 6 threat feeds in 142 ms!', "amber"),
            ],
            "00:22", "00:24", 0.92,
        ),
    ]

    all_frames, all_durations = [], []

    for tab_idx, (tab_title, command, lines, active_time, total_time, progress_pct) in enumerate(tabs):
        base = Image.new("RGB", (width, height), colors["bg"])
        draw = ImageDraw.Draw(base)

        # Outer card border
        draw.rounded_rectangle((10, 10, width - 10, height - 10), 14, fill=colors["card"], outline=colors["card_border"], width=1)

        # Top header
        if icon:
            base.paste(icon, (24, 20), icon)
        draw.text((58, 18), "XT-FORGE v0.4.8 SUPREME AGENT WORKBENCH", fill=colors["white"], font=title_font)
        draw.text((58, 36), "Sub-1KB MCP Gateway • AST Call Graphs • Annotated RE Diff/Decompile • Keyless Intel", fill=colors["muted"], font=sub_font)

        # Top-right badge with dynamic width & anchor="mm"
        badge_text = "XT-OSS • v0.4.8 DAMASCUS"
        badge_w = int(draw.textlength(badge_text, font=badge_font)) + 40
        badge_x2 = width - 26
        badge_x1 = badge_x2 - badge_w
        draw.rounded_rectangle((badge_x1, 19, badge_x2, 47), 8, fill=colors["badge_bg"], outline=colors["red"], width=1)
        draw.text(((badge_x1 + badge_x2) / 2, 33), badge_text, fill=colors["red"], font=badge_font, anchor="mm")

        # Tabs bar
        tab_x = 25
        for s_idx, (t_name, *_) in enumerate(tabs):
            t_w = int(draw.textlength(t_name, font=tab_font)) + 28
            is_active = (s_idx == tab_idx)
            draw.rounded_rectangle(
                (tab_x, 56, tab_x + t_w, 84), 6,
                fill=colors["tab_active_bg"] if is_active else colors["tab_inactive_bg"],
                outline=colors["red"] if is_active else colors["tab_inactive_border"],
                width=1,
            )
            draw.text(
                (tab_x + t_w / 2, 70), t_name,
                fill=colors["white"] if is_active else colors["muted"],
                font=tab_font, anchor="mm",
            )
            tab_x += t_w + 10

        # Thin red line below tabs
        draw.line((11, 92, width - 11, 92), fill=colors["red"], width=1)

        # Inner terminal window
        term_x1, term_y1, term_x2, term_y2 = 25, 104, width - 25, height - 56
        draw.rounded_rectangle((term_x1, term_y1, term_x2, term_y2), 10, fill=colors["term_bg"], outline=colors["term_border"], width=1)

        # Terminal buttons & title
        draw.ellipse((40, 118, 48, 126), fill="#ff5f56")
        draw.ellipse((54, 118, 62, 126), fill="#ffbd2e")
        draw.ellipse((68, 118, 76, 126), fill="#27c93f")
        draw.text((92, 122), "xtrcom@xt-forge — --meta stdio + native CLI", fill=colors["muted"], font=term_title_font, anchor="lm")
        draw.line((term_x1, 138, term_x2, 138), fill=colors["term_border"], width=1)

        # Bottom media player bar
        py = height - 32
        draw.polygon([(30, py - 6), (30, py + 6), (40, py)], fill=colors["red"])
        draw.text((50, py), f"{active_time} / {total_time}", fill=colors["white"], font=small_font, anchor="lm")

        bar_x1, bar_x2 = 160, width - 140
        draw.line((bar_x1, py, bar_x2, py), fill="#202533", width=3)
        scrub_x = int(bar_x1 + (bar_x2 - bar_x1) * progress_pct)
        draw.line((bar_x1, py, scrub_x, py), fill=colors["red"], width=3)
        draw.ellipse((scrub_x - 4, py - 4, scrub_x + 4, py + 4), fill=colors["white"])
        draw.text((width - 30, py), "HD 720p • XT-OSS", fill=colors["green"], font=small_font, anchor="rm")

        # Typing animation
        prompt = "xtrcom@xt-forge:~$ "
        line_y = 158
        prompt_w = int(draw.textlength(prompt, font=mono_font))
        text_x = 42 + prompt_w

        step = max(1, len(command) // 6)
        for c in range(0, len(command) + 1, step):
            fr = base.copy()
            d = ImageDraw.Draw(fr)
            d.text((42, line_y), prompt, fill=colors["red"], font=mono_font)
            d.text((text_x, line_y), command[:c], fill=colors["white"], font=mono_font)
            cursor_x = text_x + int(d.textlength(command[:c], font=mono_font))
            d.rectangle((cursor_x, line_y + 1, cursor_x + 7, line_y + 17), fill=colors["red"])
            all_frames.append(fr)
            all_durations.append(60 if c else 160)

        # Output reveals
        for visible in range(len(lines) + 1):
            fr = base.copy()
            d = ImageDraw.Draw(fr)
            d.text((42, line_y), prompt, fill=colors["red"], font=mono_font)
            d.text((text_x, line_y), command, fill=colors["white"], font=mono_font)

            curr_y = line_y + 30
            for text, color_key in lines[:visible]:
                d.text((42, curr_y), text, fill=colors.get(color_key, colors["white"]), font=mono_font)
                curr_y += 24

            all_frames.append(fr)
            all_durations.append(2600 if visible == len(lines) else 100)

    target_path = ASSETS / filename
    all_frames[0].save(target_path, save_all=True, append_images=all_frames[1:],
                       duration=all_durations, loop=0, optimize=True)
    # Also copy to release-review
    (ASSETS / "release-review" / filename).write_bytes(target_path.read_bytes())
    print(f"Generated Overview Showcase: {target_path} ({len(all_frames)} frames)")


def render_tour_player(
    filename: str,
    pill_text: str,
    headline: str,
    subtitle: str,
    command: str,
    lines: list[tuple[str, str]],  # (text, color_name)
    total_time: str = "00:18",
    active_time: str = "00:07",
    progress_pct: float = 0.42,
) -> None:
    width, height = 1040, 580

    title_font = get_font("sans-serif:style=Bold", 14)
    sub_font = get_font("sans-serif", 11)
    pill_font = get_font("monospace:style=Bold", 13)
    head_font = get_font("sans-serif:style=Bold", 18)
    head_sub_font = get_font("sans-serif", 12)
    term_title_font = get_font("monospace", 12)
    mono_font = get_font("monospace", 14)
    player_font = get_font("monospace", 11)

    colors = {
        "bg": "#090a0e",
        "card": "#0f1016",
        "card_border": "#272a36",
        "header_fill": "#15171e",
        "term_bg": "#08090d",
        "term_border": "#1c202d",
        "red": "#ff303d",
        "green": "#0ac68d",
        "blue": "#5fa8fa",
        "white": "#f2f4fa",
        "muted": "#8b98b0",
        "amber": "#f5b449",
        "pill_bg": "#091812",
        "pill_border": "#0ac68d",
        "pill_text": "#0ac68d",
    }

    icon_path = ASSETS / "xtforge-icon.png"
    icon = None
    if icon_path.is_file():
        with Image.open(icon_path) as logo:
            icon = logo.convert("RGBA").resize((26, 26), Image.Resampling.LANCZOS)

    # 1. Base frame with natural dark slate
    base = Image.new("RGB", (width, height), colors["bg"])
    draw = ImageDraw.Draw(base)

    # Outer card border
    draw.rounded_rectangle((10, 10, width - 10, height - 10), 14, fill=colors["card"], outline=colors["card_border"], width=1)

    # Top header bar
    if icon:
        base.paste(icon, (24, 20), icon)
    draw.text((58, 18), "XT-FORGE v0.4.8 // LIVE BENCHMARK & WORKFLOW TOUR", fill=colors["white"], font=title_font)
    draw.text((58, 36), "XT-OSS Open-Source Systems • Rust + Go + Zero-Dep Python", fill=colors["muted"], font=sub_font)

    # Top-right pill with dynamic width & anchor="mm" (Exact Image 2 style!)
    pill_w = int(draw.textlength(pill_text, font=pill_font)) + 40
    pill_x2 = width - 26
    pill_x1 = pill_x2 - pill_w
    draw.rounded_rectangle((pill_x1, 19, pill_x2, 47), 8, fill=colors["pill_bg"], outline=colors["pill_border"], width=1)
    draw.text(((pill_x1 + pill_x2) / 2, 33), pill_text, fill=colors["pill_text"], font=pill_font, anchor="mm")

    # Thin red line across header
    draw.line((11, 56, width - 11, 56), fill=colors["red"], width=1)

    # Headline and subtitle
    draw.text((25, 74), headline, fill=colors["white"], font=head_font)
    draw.text((25, 100), subtitle, fill=colors["muted"], font=head_sub_font)

    # Inner terminal window
    term_x1, term_y1, term_x2, term_y2 = 25, 126, width - 25, height - 56
    draw.rounded_rectangle((term_x1, term_y1, term_x2, term_y2), 10, fill=colors["term_bg"], outline=colors["term_border"], width=1)

    # Terminal buttons
    draw.ellipse((40, 140, 48, 148), fill="#ff5f56")
    draw.ellipse((54, 140, 62, 148), fill="#ffbd2e")
    draw.ellipse((68, 140, 76, 148), fill="#27c93f")
    draw.text((92, 144), "xtrcom@xt-forge — --meta stdio + native CLI", fill=colors["muted"], font=term_title_font, anchor="lm")
    draw.line((term_x1, 160, term_x2, 160), fill=colors["term_border"], width=1)

    # Media player bar at the bottom
    py = height - 32
    # Play icon
    draw.polygon([(30, py - 6), (30, py + 6), (40, py)], fill=colors["red"])
    # Time text
    draw.text((50, py), f"{active_time} / {total_time}", fill=colors["white"], font=player_font, anchor="lm")

    # Progress bar
    bar_x1, bar_x2 = 160, width - 140
    draw.line((bar_x1, py, bar_x2, py), fill="#202533", width=3)
    scrub_x = int(bar_x1 + (bar_x2 - bar_x1) * progress_pct)
    draw.line((bar_x1, py, scrub_x, py), fill=colors["red"], width=3)
    draw.ellipse((scrub_x - 4, py - 4, scrub_x + 4, py + 4), fill=colors["white"])

    # Right badge
    draw.text((width - 30, py), "HD 720p • XT-OSS", fill=colors["green"], font=player_font, anchor="rm")

    # Animation frames: Typing prompt then revealing lines
    prompt = "xtrcom@xt-forge:~$ "
    line_y = 182
    prompt_w = int(draw.textlength(prompt, font=mono_font))
    text_x = 42 + prompt_w

    frames = []
    durations = []

    step = max(1, len(command) // 10)
    for c in range(0, len(command) + 1, step):
        fr = base.copy()
        d = ImageDraw.Draw(fr)
        d.text((42, line_y), prompt, fill=colors["red"], font=mono_font)
        d.text((text_x, line_y), command[:c], fill=colors["white"], font=mono_font)
        cursor_x = text_x + int(d.textlength(command[:c], font=mono_font))
        d.rectangle((cursor_x, line_y + 1, cursor_x + 7, line_y + 17), fill=colors["red"])
        frames.append(fr)
        durations.append(60 if c else 180)

    # Line reveals
    for visible in range(len(lines) + 1):
        fr = base.copy()
        d = ImageDraw.Draw(fr)
        d.text((42, line_y), prompt, fill=colors["red"], font=mono_font)
        d.text((text_x, line_y), command, fill=colors["white"], font=mono_font)

        curr_y = line_y + 32
        for text, color_key in lines[:visible]:
            d.text((42, curr_y), text, fill=colors.get(color_key, colors["white"]), font=mono_font)
            curr_y += 24

        frames.append(fr)
        durations.append(2800 if visible == len(lines) else 100)

    target_path = ASSETS / filename
    frames[0].save(target_path, save_all=True, append_images=frames[1:],
                   duration=durations, loop=0, optimize=True)
    print(f"Generated Tour Player: {target_path} ({len(frames)} frames)")


def main():
    ASSETS.mkdir(parents=True, exist_ok=True)

    # 0. overview-showcase.gif (The top multi-tab player)
    render_overview_showcase("overview-showcase.gif")

    # 1. re-diff-decompile.gif (The exact one from the user's screenshot!)
    render_tour_player(
        filename="re-diff-decompile.gif",
        pill_text="02 / BINARY DIFF & MATH",
        headline="168 ms Strength-Reduced Binary Diff + .rodata Resolution",
        subtitle="Decodes compiler reciprocal multiplication shifts (/10 -> /20) automatically",
        command="xt-forge re diff bin/calc_v1 bin/calc_v2 --json",
        lines=[
            ('modified_functions: [{ "name": "apply_tier_discount", "rva": "0x116c" }]', "blue"),
            ('insn_diff : imul $0x66666667,%rdx | -sar $0x2,%edx | +sar $0x3,%edx', "white"),
            ('diff_notes: "strength-reduced division: /10 (10%) in v1 -> /20 (5%) in v2"', "red"),
            ('disasm_v2 : 117e: lea 0xe7f(%rip),%rdx  # 2004 ; str="gold"', "green"),
            ('disasm_v2 : 11c0: lea 0xe42(%rip),%rdx  # 2009 ; str="silver"', "green"),
            ('Zero manual hex or .rodata offset math required by the agent!', "amber"),
        ],
        active_time="00:07",
        total_time="00:18",
        progress_pct=0.42,
    )

    # 2. xtforge-overview-player.gif
    render_tour_player(
        filename="xtforge-overview-player.gif",
        pill_text="01 / WORKBENCH OVERVIEW",
        headline="Sub-1KB Stdio MCP Gateway + Real-Time Engine Routing",
        subtitle="Unified CLI, Go Hub, and Rust launcher with zero prompt exhaustion",
        command="xt-forge version && xt-forge doctor --json",
        lines=[
            ('version: 0.4.8-Damascus (x86_64-unknown-linux-gnu)', "blue"),
            ('engines: Rust (native) [ok] | Go (hub) [ok] | Python 3.11+ [ok]', "green"),
            ('mcp gateway: 4 compact tools (1.35 KB catalog payload)', "white"),
            ('memory & taste: WAL checkpoint clean | 0 orphaned records', "white"),
            ('Ready for autonomous AI coding agent workflow execution!', "amber"),
        ],
        active_time="00:03",
        total_time="00:15",
        progress_pct=0.20,
    )

    # 3. code-graph-context.gif
    render_tour_player(
        filename="code-graph-context.gif",
        pill_text="03 / AST CALL GRAPH & CONTEXT",
        headline="Incremental AST Call Graph + Budgeted Context Windows",
        subtitle="Follows callers, callees, and definitions across source trees",
        command='xt-forge route context . --query "dispatch" --token-budget 1200',
        lines=[
            ('query: "dispatch" -> 11 matches across service modules', "blue"),
            ('authoritative definition: service.py:3 def authenticate(token: str)', "green"),
            ('call graph: dispatch_request -> authenticate (hop 0 -> hop 1)', "white"),
            ('budget: 1,200 tokens allowed | 677 tokens packed (88.8% reduction)', "white"),
            ('Zero text grep hallucinations; 100% precision call tracing!', "amber"),
        ],
        active_time="00:09",
        total_time="00:20",
        progress_pct=0.45,
    )

    # 4. mcp-rea-craft.gif
    render_tour_player(
        filename="mcp-rea-craft.gif",
        pill_text="04 / MCP GATEWAY & BRIDGES",
        headline="Sub-1.4KB Gateway Wrapping 229 REA & Craft Anything Tools",
        subtitle="On-demand schema retrieval reduces upfront prompt cost by 98.5%",
        command="xt-forge mcp connect borer && xt-forge --meta",
        lines=[
            ('connected upstream: borer (34 tools + 111 borer:// resources) [SHA-256 pinned]', "blue"),
            ('connected upstream: ghidra (43 tools) [ready]', "green"),
            ('upfront tools/list: 4 compact meta-tools (1.35 KB vs 3.5 MB raw catalog)', "white"),
            ('xt_discover(query="binary"): 5 tools found in 4 ms', "white"),
            ('Crash-safe session journaling active: $XT_HOME/call_journal.json', "amber"),
        ],
        active_time="00:12",
        total_time="00:24",
        progress_pct=0.50,
    )

    # 5. mcp-proxy-audit.gif
    render_player_gif_alias = render_tour_player
    render_player_gif_alias(
        filename="mcp-proxy-audit.gif",
        pill_text="05 / MCP RUG-PULL AUDIT",
        headline="SHA-256 MCP Schema Pinning & Prompt Injection Defense",
        subtitle="Blocks dynamic upstream tool mutations before execution",
        command="xt-forge mcp audit ghidra --trust-on-first",
        lines=[
            ('inspecting server: ghidra (stdio transport)', "blue"),
            ('schema baseline: pinned 43 tool hashes to ~/.xt-forge/mcp_trust.json', "green"),
            ('injection scan: 0 prompt injections detected across descriptions', "white"),
            ('rug-pull defense: verified and secured against unauthorized tool mutations', "amber"),
        ],
        active_time="00:05",
        total_time="00:14",
        progress_pct=0.36,
    )

    # 6. re-intel-triage.gif
    render_tour_player(
        filename="re-intel-triage.gif",
        pill_text="06 / KEYLESS THREAT INTEL",
        headline="Keyless Threat Intelligence & Binary Mitigations Triage",
        subtitle="NVD, FIRST EPSS, CISA KEV, InternetDB, and GreyNoise without API keys",
        command="xt-forge intel cve CVE-2024-3094 && xt-forge re checksec target",
        lines=[
            ('cve: CVE-2024-3094 | cvss: 10.0 (CRITICAL) | cisa kev: true', "red"),
            ('epss exploit probability: 97.48% (top tier active exploit risk)', "blue"),
            ('checksec /usr/lib/liblzma.so.5: RELRO=Full, Canary=true, NX=true, PIE=true', "green"),
            ('Keyless intelligence gathered across 6 threat feeds in 142 ms!', "amber"),
        ],
        active_time="00:08",
        total_time="00:16",
        progress_pct=0.50,
    )

    # 7. re-workbench.gif
    render_tour_player(
        filename="re-workbench.gif",
        pill_text="07 / RE WORKBENCH",
        headline="Multi-Format Reverse Engineering & Structured Pseudocode",
        subtitle="ELF, PE, Mach-O, firmware volumes, and managed runtimes",
        command="xt-forge re overview ./app && xt-forge re disasm-native --flow",
        lines=[
            ('format: ELF 64-bit LSB executable (x86-64)', "blue"),
            ('entry point: 0x401020 | sections: 28 | entropy: 5.84', "white"),
            ('structured flow recovery: 12 basic blocks mapped to imperative C', "green"),
            ('Analyst overlays & symbol provenance preserved across sessions!', "amber"),
        ],
        active_time="00:06",
        total_time="00:18",
        progress_pct=0.33,
    )

    # 8. goal-vibe-check.gif
    render_tour_player(
        filename="goal-vibe-check.gif",
        pill_text="08 / BOUNDED GOAL GATES",
        headline="Bounded Verification Loops & Automated Goal Verification",
        subtitle="Prevents infinite agent loops and verifies claims against evidence",
        command='xt-forge goal run "Verify binary regression" --rounds 4',
        lines=[
            ('round 1: running probe scripts/verify_sys_native.py [PASS]', "blue"),
            ('round 2: cross-checking test assertions against ground truth [PASS]', "green"),
            ('round 3: inspecting call_journal.json idempotency [VERIFIED]', "white"),
            ('goal verification gate: 100% complete | 0 drift detected', "amber"),
        ],
        active_time="00:04",
        total_time="00:12",
        progress_pct=0.33,
    )

    # 9. cve-re-player.gif
    render_tour_player(
        filename="cve-re-player.gif",
        pill_text="09 / CVE RE PLAYER",
        headline="Automated Threat Dossier & Reverse Engineering Evidence Player",
        subtitle="Correlating binary anomalies directly to published CVE advisories",
        command="xt-forge intel cve CVE-2023-38606 --json",
        lines=[
            ('target: CVE-2023-38606 (Operation Triangulation MMIO bypass)', "red"),
            ('hardware registers: 0x20e01000 mapped in kernelcache', "blue"),
            ('evidence pack: artifact saved to $XT_HOME/cache/artifacts/cve_dossier.json', "white"),
            ('Dossier complete: correlated advisory to binary MMIO mapping!', "amber"),
        ],
        active_time="00:11",
        total_time="00:22",
        progress_pct=0.50,
    )


if __name__ == "__main__":
    main()
