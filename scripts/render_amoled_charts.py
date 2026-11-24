#!/usr/bin/env python3
"""Render pure AMOLED charts and architecture figures for XT-Forge documentation."""

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
from pathlib import Path
from PIL import Image, ImageDraw, ImageFont
import subprocess

ROOT = Path(__file__).resolve().parents[1]
ASSETS = ROOT / "docs" / "assets"
DOCS = ROOT / "docs"


def get_font(family: str, size: int):
    try:
        match = subprocess.check_output(["fc-match", "-f", "%{file}", family], text=True)
        return ImageFont.truetype(match, size)
    except (OSError, subprocess.CalledProcessError):
        return ImageFont.load_default(size=size)


def render_bench_charts():
    """Renders 9-tier benchmark charts with pure AMOLED black theme."""
    fig, (ax1, ax2, ax3) = plt.subplots(1, 3, figsize=(18, 5.5), facecolor="#000000")

    tiers = [f"T{i}" for i in range(1, 10)]
    x = np.arange(len(tiers))
    width = 0.26

    # Arm A (Raw REA), Arm B (XT-Forge + REA), Arm C (Standalone XT-Forge)
    pass_a = [0, 3, 1, 0, 4, 1, 1, 0, 0] # 10/45 (22.2%)
    pass_b = [2, 3, 5, 5, 5, 4, 5, 3, 2] # 34/45 (75.6%)
    pass_c = [3, 5, 4, 5, 5, 5, 5, 5, 5] # 42/45 (93.3%)

    time_a = [60.03, 87.85, 90.03, 90.03, 71.50, 120.03, 120.03, 120.03, 120.03]
    time_b = [27.59, 66.23, 39.42, 54.93, 21.19, 75.90, 69.20, 116.91, 120.03]
    time_c = [15.69, 54.56, 28.98, 36.06, 21.19, 69.73, 51.05, 80.02, 62.96]

    tokens_a = [7.7, 16.4, 12.5, 9.0, 10.0, 23.9, 25.0, 21.9, 27.8]
    tokens_b = [6.6, 13.4, 5.8, 11.5, 5.9, 20.8, 14.4, 21.0, 19.8]
    tokens_c = [6.4, 13.9, 7.0, 10.4, 10.6, 16.6, 15.7, 21.4, 27.8]

    red = "#ff2e3b"
    blue = "#00e5ff"
    green = "#00ff9d"

    for ax in (ax1, ax2, ax3):
        ax.set_facecolor("#040406")
        ax.tick_params(colors="#8b98b0", labelsize=11)
        for spine in ax.spines.values():
            spine.set_color("#1c1f2b")
        ax.grid(axis="y", color="#141724", linestyle="--", alpha=0.7)

    # Panel 1: Pass Count
    ax1.bar(x - width, pass_a, width, label="Arm A: Raw REA (22.2%)", color=red)
    ax1.bar(x, pass_b, width, label="Arm B: XT-Forge + REA (75.6%)", color=blue)
    ax1.bar(x + width, pass_c, width, label="Arm C: Standalone (93.3%)", color=green)
    ax1.set_title("Pass Count / 5 Reps (Higher is Better)", color="#ffffff", fontsize=13, fontweight="bold", pad=12)
    ax1.set_xticks(x)
    ax1.set_xticklabels(tiers)
    ax1.set_ylim(0, 5.5)
    ax1.legend(facecolor="#000000", edgecolor="#1c1f2b", labelcolor="#e2e8f0", loc="upper left", fontsize=10)

    # Panel 2: Median Duration
    ax2.bar(x - width, time_a, width, color=red)
    ax2.bar(x, time_b, width, color=blue)
    ax2.bar(x + width, time_c, width, color=green)
    ax2.set_title("Median Duration (s, Lower is Faster)", color="#ffffff", fontsize=13, fontweight="bold", pad=12)
    ax2.set_xticks(x)
    ax2.set_xticklabels(tiers)

    # Panel 3: Token Usage
    ax3.bar(x - width, tokens_a, width, color=red)
    ax3.bar(x, tokens_b, width, color=blue)
    ax3.bar(x + width, tokens_c, width, color=green)
    ax3.set_title("Token Usage (k Tokens, Lower is Better)", color="#ffffff", fontsize=13, fontweight="bold", pad=12)
    ax3.set_xticks(x)
    ax3.set_xticklabels(tiers)

    plt.tight_layout()
    out = DOCS / "bench_9tier_charts.png"
    plt.savefig(out, facecolor="#000000", dpi=160)
    plt.close()
    print(f"Generated AMOLED Benchmark Chart: {out}")


def render_mcp_savings():
    """Renders MCP catalog token savings comparison in pure AMOLED."""
    fig, ax = plt.subplots(figsize=(10, 4.5), facecolor="#000000")
    ax.set_facecolor("#040406")

    servers = [
        "Raw REA Full (229 Tools)",
        "Borer Direct (34 Tools)",
        "XT-Forge --meta (Go Hub)",
        "XT-Forge --meta (Python)",
    ]
    sizes_kb = [3505.0, 24.8, 1.35, 1.01]
    colors = ["#ff2e3b", "#ffb700", "#00ff9d", "#00e5ff"]

    y = np.arange(len(servers))
    bars = ax.barh(y, sizes_kb, color=colors, height=0.55)

    ax.set_xscale("log")
    ax.set_facecolor("#040406")
    ax.tick_params(colors="#8b98b0", labelsize=11)
    for spine in ax.spines.values():
        spine.set_color("#1c1f2b")
    ax.grid(axis="x", color="#141724", linestyle="--", alpha=0.7)

    ax.set_yticks(y)
    ax.set_yticklabels(servers, color="#ffffff", fontweight="600", fontsize=12)
    ax.set_xlabel("MCP Initial Schema Payload (KB, Log Scale - Lower is Better)", color="#8b98b0", fontsize=11, labelpad=10)
    ax.set_title("Upfront Prompt Schema Overhead: 99.96% Reduction", color="#ffffff", fontsize=14, fontweight="bold", pad=14)

    # Annotate bars
    for bar, val in zip(bars, sizes_kb):
        label = f"{val:.2f} KB" if val < 100 else f"{val:,.0f} KB (100% bloat)"
        if val <= 1.35:
            label += " [98.5%–99.9% savings]"
        ax.text(bar.get_width() * 1.25, bar.get_y() + bar.get_height() / 2, label,
                va="center", ha="left", color="#e2e8f0", fontsize=10, fontweight="bold")

    ax.set_xlim(0.5, 30000)
    plt.tight_layout()
    out = ASSETS / "mcp-token-savings.png"
    plt.savefig(out, facecolor="#000000", dpi=160)
    plt.close()
    print(f"Generated AMOLED MCP Savings Chart: {out}")


def render_architecture_diagram():
    """Renders pure AMOLED hybrid architecture diagram."""
    width, height = 1100, 440
    img = Image.new("RGB", (width, height), "#000000")
    draw = ImageDraw.Draw(img)

    title_font = get_font("sans-serif:style=Bold", 17)
    sub_font = get_font("sans-serif", 12)
    box_font = get_font("monospace:style=Bold", 14)
    mono_small = get_font("monospace", 11)

    # Frame
    draw.rounded_rectangle((10, 10, width - 10, height - 10), 14, fill="#040406", outline="#1c1f2b", width=1)
    draw.line((11, 56, width - 11, 56), fill="#ff2e3b", width=2)
    draw.text((25, 20), "XT-FORGE // HYBRID ARCHITECTURE (RUST + GO + PYTHON)", fill="#ffffff", font=title_font)
    draw.text((width - 30, 24), "v0.4.8 DAMASCUS", fill="#ff2e3b", font=sub_font, anchor="rm")

    boxes = [
        (40, 90, 250, 150, "01 / CLI & HARNESS", ["Shell & scripts", "Agent stdio MCP", "IDE slash commands"], "#ff2e3b"),
        (330, 90, 250, 150, "02 / RUST CORE", ["Fast secret scan", "Context packer", "AST code indexer"], "#00ff9d"),
        (620, 90, 250, 150, "03 / GO HUB", ["Image overview & xrefs", "Native disassembly", "Demangler & checksec"], "#00e5ff"),
        (910, 90, 160, 150, "04 / PYTHON", ["OSV advisory check", "Guarded fixes", "Borer/Ghidra bridges"], "#ffb700"),
        (40, 270, 480, 130, "SYSTEM STORAGE & MEMORY", ["Universal Memory: mem.db (WAL checkpointed)", "Session Recovery: $XT_HOME/call_journal.json", "Taste Engine: Learned deterministic preferences"], "#8b98b0"),
        (560, 270, 510, 130, "ENGINES & ADVISORY SERVICES", ["Native SYS image parser: ELF, PE, Mach-O, firmware", "Live OSV advisory vulnerability lookup", "External upstreams: Ghidra (43 tools), Borer (34 tools)"], "#8b98b0"),
    ]

    for x1, y1, w, h, title, lines, color in boxes:
        draw.rounded_rectangle((x1, y1, x1 + w, y1 + h), 10, fill="#000000", outline="#1c1f2b", width=1)
        draw.line((x1 + 8, y1 + 1, x1 + w - 8, y1 + 1), fill=color, width=2)
        draw.text((x1 + 14, y1 + 14), title, fill=color, font=box_font)
        for idx, line in enumerate(lines):
            draw.text((x1 + 14, y1 + 42 + idx * 24), f"• {line}", fill="#c0cad9", font=mono_small)

    out = ASSETS / "architecture-rust-go.png"
    img.save(out, optimize=True)
    print(f"Generated AMOLED Architecture Diagram: {out}")


if __name__ == "__main__":
    render_bench_charts()
    render_mcp_savings()
    render_architecture_diagram()
