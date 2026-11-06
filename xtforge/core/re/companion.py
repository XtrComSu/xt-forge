"""Standalone airgapped visual companion generator for binary analysis.

Produces self-contained HTML/SVG artifacts with interactive pan-and-zoom CFG flowcharts,
IDA Pro dark theme, and section entropy visualizations with zero external dependencies.
"""
from __future__ import annotations

import html
import json
from pathlib import Path
from typing import Any


def _compute_layout(blocks: list[dict[str, Any]], edges: list[dict[str, str]]) -> tuple[dict[str, tuple[int, int, int, int]], list[dict[str, Any]]]:
    """Calculate layered positions (x, y, width, height) for basic blocks and routed edges."""
    if not blocks:
        return {}, []

    block_map = {b["id"]: b for b in blocks}
    in_edges: dict[str, list[str]] = {b["id"]: [] for b in blocks}
    out_edges: dict[str, list[dict[str, str]]] = {b["id"]: [] for b in blocks}

    for e in edges:
        src = e["from"]
        dst = e["to"]
        if src in block_map and dst in block_map:
            out_edges[src].append(e)
            in_edges[dst].append(src)

    # Assign layers using topological ordering / longest path from roots
    roots = [bid for bid, preds in in_edges.items() if not preds]
    if not roots:
        roots = [blocks[0]["id"]]

    layer_map: dict[str, int] = {}
    visited = set()
    queue = [(r, 0) for r in roots]

    while queue:
        cur, layer = queue.pop(0)
        layer_map[cur] = max(layer_map.get(cur, 0), layer)
        for e in out_edges.get(cur, []):
            nxt = e["to"]
            if nxt not in visited or layer + 1 > layer_map.get(nxt, 0):
                visited.add(nxt)
                queue.append((nxt, layer + 1))

    # Catch any unvisited blocks
    for b in blocks:
        if b["id"] not in layer_map:
            layer_map[b["id"]] = 0

    layers: dict[int, list[str]] = {}
    for bid, layer in layer_map.items():
        layers.setdefault(layer, []).append(bid)

    layout: dict[str, tuple[int, int, int, int]] = {}
    block_width = 240

    for layer_num, bids in sorted(layers.items()):
        total_width = len(bids) * (block_width + 60) - 60
        start_x = max(60, 400 - total_width // 2)
        y = 60 + layer_num * 180

        for col, bid in enumerate(bids):
            b = block_map[bid]
            insns = b.get("instructions") or []
            h = 45 + max(1, len(insns)) * 16
            x = start_x + col * (block_width + 60)
            layout[bid] = (x, y, block_width, h)

    # Edge routing points
    routed_edges = []
    for e in edges:
        src = e["from"]
        dst = e["to"]
        if src in layout and dst in layout:
            sx, sy, sw, sh = layout[src]
            dx, dy, dw, dh = layout[dst]
            start_pt = (sx + sw // 2, sy + sh)
            end_pt = (dx + dw // 2, dy)
            routed_edges.append({
                "from": src,
                "to": dst,
                "type": e.get("type", "unconditional"),
                "start": start_pt,
                "end": end_pt,
            })

    return layout, routed_edges


def render_html_companion(
    binary_name: str,
    info: dict[str, Any],
    cfg: dict[str, Any] | None = None,
    out_path: str | Path | None = None,
) -> str:
    """Generate a 100% self-contained airgapped HTML/SVG reverse engineering workbench."""
    sections = info.get("sections") or []
    blocks = (cfg.get("blocks") if cfg else []) or []
    edges = (cfg.get("edges") if cfg else []) or []
    symbol_name = (cfg.get("symbol") if cfg else "") or "Function Graph"

    layout, routed_edges = _compute_layout(blocks, edges)

    # SVG Canvas bounds
    max_x = max([x + w for x, y, w, h in layout.values()] + [900]) + 150
    max_y = max([y + h for x, y, w, h in layout.values()] + [600]) + 150

    # Section Entropy Bars HTML
    sec_bars_html = []
    for sec in sections:
        ent = sec.get("entropy", 0.0)
        pct = min(100.0, (ent / 8.0) * 100.0)
        color = "#22c55e" if ent < 5.5 else ("#f59e0b" if ent < 7.0 else "#ef4444")
        verdict = "Normal" if ent < 5.5 else ("Mixed" if ent < 7.0 else "Packed/Encrypted")
        sec_bars_html.append(f"""
        <div class="sec-row">
            <div class="sec-meta">
                <span class="sec-name">{html.escape(sec.get('name', 'unnamed'))}</span>
                <span class="sec-val">{ent:.2f} ({verdict})</span>
            </div>
            <div class="bar-bg">
                <div class="bar-fill" style="width: {pct:.1f}%; background-color: {color};"></div>
            </div>
        </div>
        """)

    # SVG Blocks Elements
    svg_blocks_html = []
    for bid, (bx, by, bw, bh) in layout.items():
        b = next((x for x in blocks if x["id"] == bid), None)
        if not b:
            continue
        insns = b.get("instructions") or []
        insns_svg = []
        for idx, ins in enumerate(insns[:16]):
            iy = 40 + idx * 16
            m = html.escape(ins.get("mnemonic", ""))
            ops = html.escape(ins.get("operands", ""))
            addr = html.escape(ins.get("hex_address", ""))
            insns_svg.append(
                f'<text x="12" y="{iy}" class="insn"><tspan class="addr">{addr}  </tspan><tspan class="mnem">{m:<6} </tspan><tspan class="ops">{ops}</tspan></text>'
            )

        if len(insns) > 16:
            insns_svg.append(f'<text x="12" y="{40 + 16*16}" class="insn-more">... +{len(insns)-16} more instructions</text>')
        elif not insns and b.get("instruction_count", 0) > 0:
            insns_svg.append(f'<text x="12" y="40" class="insn-more">{b["instruction_count"]} instructions (bounded)</text>')

        svg_blocks_html.append(f"""
        <g id="{bid}" class="cfg-block" transform="translate({bx}, {by})">
            <rect width="{bw}" height="{bh}" rx="6" class="block-rect" />
            <rect width="{bw}" height="24" rx="6" class="block-header" />
            <text x="10" y="16" class="block-title">{html.escape(bid)} ({html.escape(str(b.get('start_rva', '')))})</text>
            {''.join(insns_svg)}
        </g>
        """)

    # SVG Edges Paths
    svg_edges_html = []
    for edge in routed_edges:
        (sx, sy) = edge["start"]
        (dx, dy) = edge["end"]
        etype = edge["type"]
        color_class = "edge-unconditional"
        marker_id = "arrow-blue"
        if etype == "conditional_true":
            color_class = "edge-true"
            marker_id = "arrow-green"
        elif etype == "conditional_false":
            color_class = "edge-false"
            marker_id = "arrow-red"
        elif etype == "fallthrough":
            color_class = "edge-fallthrough"
            marker_id = "arrow-gray"

        # Smooth Bezier curve routing
        ctrl1_y = sy + (dy - sy) // 2
        ctrl2_y = dy - (dy - sy) // 2
        path_d = f"M {sx} {sy} C {sx} {ctrl1_y}, {dx} {ctrl2_y}, {dx} {dy}"

        svg_edges_html.append(f"""
        <path d="{path_d}" class="cfg-edge {color_class} {etype}" data-type="{etype}" marker-end="url(#{marker_id})" />
        """)

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>XT-Forge RE: {html.escape(binary_name)}</title>
<style>
  :root {{
    --bg-main: #18181b;
    --bg-card: #27272a;
    --border: #3f3f46;
    --text-primary: #f4f4f5;
    --text-muted: #a1a1aa;
    --color-true: #22c55e;
    --color-false: #ef4444;
    --color-jump: #3b82f6;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, monospace;
    background: var(--bg-main);
    color: var(--text-primary);
    display: flex;
    flex-direction: column;
    height: 100vh;
    overflow: hidden;
  }}
  header {{
    background: var(--bg-card);
    padding: 12px 20px;
    border-bottom: 1px solid var(--border);
    display: flex;
    justify-content: space-between;
    align-items: center;
  }}
  .brand {{ font-size: 16px; font-weight: bold; color: #38bdf8; }}
  .meta-tag {{ font-size: 13px; color: var(--text-muted); margin-left: 12px; }}
  .layout-container {{
    display: flex;
    flex: 1;
    overflow: hidden;
  }}
  .sidebar {{
    width: 320px;
    background: #1f1f23;
    border-right: 1px solid var(--border);
    padding: 16px;
    overflow-y: auto;
  }}
  .sidebar h3 {{ font-size: 14px; text-transform: uppercase; color: var(--text-muted); margin-bottom: 12px; }}
  .sec-row {{ margin-bottom: 12px; }}
  .sec-meta {{ display: flex; justify-content: space-between; font-size: 12px; margin-bottom: 4px; }}
  .bar-bg {{ background: #3f3f46; height: 8px; border-radius: 4px; overflow: hidden; }}
  .bar-fill {{ height: 100%; }}
  .canvas-container {{
    flex: 1;
    position: relative;
    background: #09090b;
    overflow: hidden;
  }}
  .toolbar {{
    position: absolute;
    top: 16px;
    left: 16px;
    z-index: 10;
    display: flex;
    gap: 8px;
    background: var(--bg-card);
    padding: 6px 10px;
    border-radius: 6px;
    border: 1px solid var(--border);
  }}
  button {{
    background: #3f3f46;
    color: var(--text-primary);
    border: none;
    padding: 4px 10px;
    border-radius: 4px;
    cursor: pointer;
    font-size: 12px;
  }}
  button:hover {{ background: #52525b; }}
  input[type="text"] {{
    background: #18181b;
    border: 1px solid var(--border);
    color: var(--text-primary);
    padding: 4px 8px;
    border-radius: 4px;
    font-size: 12px;
  }}
  svg {{ width: 100%; height: 100%; cursor: grab; }}
  svg:active {{ cursor: grabbing; }}
  .block-rect {{ fill: #27272a; stroke: #52525b; stroke-width: 1.5; }}
  .block-header {{ fill: #3f3f46; }}
  .block-title {{ font-size: 11px; font-weight: bold; fill: #38bdf8; font-family: monospace; }}
  .insn {{ font-size: 10px; font-family: monospace; }}
  .addr {{ fill: #71717a; }}
  .mnem {{ fill: #facc15; font-weight: bold; }}
  .ops {{ fill: #e4e4e7; }}
  .insn-more {{ font-size: 10px; fill: #a1a1aa; font-style: italic; font-family: monospace; }}
  .cfg-edge {{ fill: none; stroke-width: 2; }}
  .edge-true {{ stroke: var(--color-true); }}
  .edge-false {{ stroke: var(--color-false); }}
  .edge-unconditional {{ stroke: var(--color-jump); }}
  .edge-fallthrough {{ stroke: #71717a; stroke-dasharray: 4; }}
</style>
</head>
<body>
<header>
  <div>
    <span class="brand">XT-Forge Reverse Engineering Workbench</span>
    <span class="meta-tag">Target: <b>{html.escape(binary_name)}</b></span>
    <span class="meta-tag">Format: <b>{html.escape(info.get('format', 'Unknown'))}</b> ({html.escape(info.get('machine', 'Unknown'))})</span>
    <span class="meta-tag">Entry: <b>{html.escape(str(info.get('entry_point', '')))}</b></span>
  </div>
  <div>
    <span class="meta-tag">Symbol: <b>{html.escape(symbol_name)}</b></span>
  </div>
</header>
<div class="layout-container">
  <div class="sidebar">
    <h3>Section Entropy</h3>
    {''.join(sec_bars_html) if sec_bars_html else '<p style="font-size:12px; color:var(--text-muted);">No section entropy data available</p>'}
    <div style="margin-top: 24px;">
      <h3>Execution Gates</h3>
      <p style="font-size:12px; margin-bottom:6px;">TLS Callbacks: <b>{len(info.get('tls_callbacks', []))}</b></p>
      <p style="font-size:12px; margin-bottom:6px;">Has .pdata: <b>{'Yes' if info.get('has_pdata') else 'No'}</b></p>
    </div>
  </div>
  <div class="canvas-container">
    <div class="toolbar">
      <button id="zoom-in">+</button>
      <button id="zoom-out">-</button>
      <button id="zoom-reset">Reset</button>
      <input type="text" id="block-search" placeholder="Search block (e.g. b_1000)...">
    </div>
    <svg id="cfg-svg">
      <defs>
        <marker id="arrow-green" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
          <path d="M 0 1 L 9 5 L 0 9 z" fill="#22c55e" />
        </marker>
        <marker id="arrow-red" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
          <path d="M 0 1 L 9 5 L 0 9 z" fill="#ef4444" />
        </marker>
        <marker id="arrow-blue" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
          <path d="M 0 1 L 9 5 L 0 9 z" fill="#3b82f6" />
        </marker>
        <marker id="arrow-gray" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
          <path d="M 0 1 L 9 5 L 0 9 z" fill="#71717a" />
        </marker>
      </defs>
      <g id="viewport" transform="matrix(1 0 0 1 50 50)">
        {''.join(svg_edges_html)}
        {''.join(svg_blocks_html)}
      </g>
    </svg>
  </div>
</div>
<script>
  (function() {{
    const svg = document.getElementById('cfg-svg');
    const viewport = document.getElementById('viewport');
    let scale = 1.0;
    let pointX = 50, pointY = 50;
    let isPanning = false, startX = 0, startY = 0;

    function updateTransform() {{
      viewport.setAttribute('transform', `matrix(${{scale}} 0 0 ${{scale}} ${{pointX}} ${{pointY}})`);
    }}

    svg.addEventListener('mousedown', function(e) {{
      if (e.target.closest('button') || e.target.closest('input')) return;
      isPanning = true;
      startX = e.clientX - pointX;
      startY = e.clientY - pointY;
    }});

    window.addEventListener('mousemove', function(e) {{
      if (!isPanning) return;
      pointX = e.clientX - startX;
      pointY = e.clientY - startY;
      updateTransform();
    }});

    window.addEventListener('mouseup', function() {{ isPanning = false; }});

    svg.addEventListener('wheel', function(e) {{
      e.preventDefault();
      const xs = (e.clientX - pointX) / scale;
      const ys = (e.clientY - pointY) / scale;
      const delta = -e.deltaY;
      (delta > 0) ? (scale *= 1.1) : (scale /= 1.1);
      scale = Math.max(0.2, Math.min(3.0, scale));
      pointX = e.clientX - xs * scale;
      pointY = e.clientY - ys * scale;
      updateTransform();
    }});

    document.getElementById('zoom-in').onclick = () => {{ scale = Math.min(3.0, scale * 1.2); updateTransform(); }};
    document.getElementById('zoom-out').onclick = () => {{ scale = Math.max(0.2, scale / 1.2); updateTransform(); }};
    document.getElementById('zoom-reset').onclick = () => {{ scale = 1.0; pointX = 50; pointY = 50; updateTransform(); }};

    document.getElementById('block-search').addEventListener('input', function(e) {{
      const query = e.target.value.toLowerCase().trim();
      document.querySelectorAll('.cfg-block').forEach(el => {{
        const id = el.id.toLowerCase();
        if (query && id.includes(query)) {{
          el.querySelector('.block-rect').style.stroke = '#38bdf8';
          el.querySelector('.block-rect').style.strokeWidth = '3';
        }} else {{
          el.querySelector('.block-rect').style.stroke = '#52525b';
          el.querySelector('.block-rect').style.strokeWidth = '1.5';
        }}
      }});
    }});
  }})();
</script>
</body>
</html>
"""

    if out_path:
        p = Path(out_path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(html_content, encoding="utf-8")

    return html_content
