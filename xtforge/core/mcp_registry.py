"""MCP Tool Registry & On-Demand Dispatcher.

Enables on-demand discovery and execution of specialized MCP tools (OpenSCAD/cad3d,
photoeditor, glmocr, etc.) through xt-forge WITHOUT dumping all their schemas into the
model's initial prompt catalog on every turn, saving thousands of tokens per request.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

_SHARE_ROOT = Path.home() / ".local" / "share"

EXTERNAL_SERVERS: dict[str, dict[str, Any]] = {
    "cad3d": {
        "title": "3D CAD & OpenSCAD Modeling",
        "description": "3D CAD modeling, OpenSCAD script compilation, CSG booleans, extrusion, mesh inspection, and STL/OBJ/GLB/3MF conversions.",
        "command": str(_SHARE_ROOT / "mcp-cad-env" / "bin" / "python"),
        "args": [str(_SHARE_ROOT / "cad3d" / "cad3d_mcp.py")],
        "aliases": ["opencad", "cad", "3d", "openscad", "stl", "obj", "mesh", "trimesh", "csg", "modeling", "cad3d"],
        "tools": [
            {"name": "cad_generate_scad", "description": "Generate and compile parametric OpenSCAD scripts into STL/OBJ/3MF 3D meshes."},
            {"name": "cad_create_primitive", "description": "Create 3D solid primitive (cube, cylinder, sphere, cone, torus)."},
            {"name": "cad_csg_boolean", "description": "Perform manifold CSG boolean operations (union, difference, intersection)."},
            {"name": "cad_extrude_2d", "description": "Extrude 2D polyline or SVG profile into a 3D solid."},
            {"name": "cad_inspect_mesh", "description": "Inspect mesh watertightness, volume, surface area, and bounding box."},
            {"name": "cad_convert_format", "description": "Convert between 3D formats (STL, OBJ, GLB, PLY, 3MF)."},
            {"name": "cad_render_preview", "description": "Render 2D isometric/orthographic preview PNG/SVG of a 3D mesh."},
        ],
    },
    "photoeditor": {
        "title": "Photo & Image Manipulation",
        "description": "Photo editing, color grading, adjustments, filters, cropping, resizing, annotations, watermark compositing, and background removal.",
        "command": str(_SHARE_ROOT / "mcp-cad-env" / "bin" / "python"),
        "args": [str(_SHARE_ROOT / "photoeditor" / "photoeditor_mcp.py")],
        "aliases": ["photo", "image", "picture", "filter", "crop", "resize", "watermark", "background_removal", "photoeditor", "png", "jpeg"],
        "tools": [
            {"name": "photo_adjust", "description": "Color, brightness, contrast, saturation, and sharpness adjustments."},
            {"name": "photo_filter", "description": "Filters: blur, sharpen, edge enhance, emboss, sepia, grayscale, invert."},
            {"name": "photo_transform", "description": "Transformations: crop, resize, rotate, flip, transpose."},
            {"name": "photo_composite", "description": "Layer compositing: alpha blending, watermarking, positioning."},
            {"name": "photo_annotate", "description": "Text overlays and geometric annotations on images."},
            {"name": "photo_convert", "description": "Convert image formats (PNG, JPEG, WebP, GIF, BMP, TIFF)."},
            {"name": "photo_analyze", "description": "Image dimensions, color palette, EXIF metadata, histogram."},
            {"name": "photo_remove_background", "description": "Color-key / chroma-key transparency background extraction."},
        ],
    },
    "glmocr": {
        "title": "Local Document & Image OCR",
        "description": "Local high-precision OCR on images and PDFs for small text, tables, and formulas.",
        "command": sys.executable,
        "args": [str(_SHARE_ROOT / "glmocr" / "glmocr_mcp.py")],
        "aliases": ["ocr", "text_recognition", "scan_image", "glmocr", "read_image", "pdf_ocr"],
        "tools": [
            {"name": "ocr", "description": "Extract text, markdown, and tables from image or PDF file."},
        ],
    },
    "searchd": {
        "title": "Local Web & Google Search",
        "description": "Google organic web search endpoint via local searchd daemon.",
        "command": sys.executable,
        "args": [str(_SHARE_ROOT / "searchd" / "searchd_mcp.py")],
        "aliases": ["web", "google", "searchd", "web_search"],
        "tools": [
            {"name": "search", "description": "Search the web with real Google organic results."},
        ],
    },
}


def search_tools(query: str, limit: int = 5) -> list[dict[str, Any]]:
    """Search external tools matching query keywords or aliases."""
    q = query.lower().strip()
    words = [w for w in q.split() if len(w) > 1]
    matches: list[dict[str, Any]] = []

    for s_name, s_info in EXTERNAL_SERVERS.items():
        score = 0
        matching_tools = []
        # Check aliases
        for alias in s_info.get("aliases", []):
            if alias in q or any(w == alias for w in words):
                score += 3
        # Check title / description
        if any(w in s_info.get("description", "").lower() for w in words):
            score += 1

        for t in s_info.get("tools", []):
            t_name = t["name"].lower()
            t_desc = t["description"].lower()
            if any(w in t_name or w in t_desc for w in words) or score > 0:
                matching_tools.append(t)

        if score > 0 or matching_tools:
            matches.append({
                "server": s_name,
                "title": s_info["title"],
                "description": s_info["description"],
                "tools": matching_tools or s_info.get("tools", []),
                "invocation": f"xtforge tool run {s_name} <tool_name> '{{\"arg\": \"val\"}}'",
            })

    return matches[:limit]


def execute_tool(server_name: str, tool_name: str, arguments: dict[str, Any] | None = None,
                 timeout: int = 60) -> dict[str, Any]:
    """Execute an external MCP tool via stdio JSON-RPC."""
    server = EXTERNAL_SERVERS.get(server_name.lower())
    if not server:
        # Check alias
        for s_name, s_info in EXTERNAL_SERVERS.items():
            if server_name.lower() in s_info.get("aliases", []):
                server = s_info
                server_name = s_name
                break

    if not server:
        return {"ok": False, "error": f"unknown server '{server_name}'. Available: {list(EXTERNAL_SERVERS.keys())}"}

    cmd = [server["command"], *server["args"]]
    if not os.path.exists(cmd[0]):
        return {"ok": False, "error": f"server executable not found: {cmd[0]}"}

    try:
        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        req = json.dumps({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": tool_name, "arguments": arguments or {}},
        }) + "\n"
        stdout, stderr = proc.communicate(req, timeout=timeout)
        if not stdout.strip():
            return {"ok": False, "error": f"empty response from {server_name}: {stderr}"}

        resp = json.loads(stdout.strip().split("\n")[0])
        if "error" in resp:
            return {"ok": False, "error": resp["error"]}
        return {"ok": True, "result": resp.get("result", {})}
    except subprocess.TimeoutExpired:
        proc.kill()
        return {"ok": False, "error": f"tool '{tool_name}' timed out after {timeout}s"}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}
