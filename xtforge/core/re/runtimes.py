"""Pure-Python fallbacks for multi-runtime RE inspection (ASAR, netcap, APK, decompile, trace)."""
from __future__ import annotations

import json
import re
import shutil
import struct
import subprocess
import zipfile
from pathlib import Path
from typing import Any

from ..route import guard


def inspect_asar(path: str | Path, *, grep: str = "", limit: int = 200) -> dict[str, Any]:
    canon = guard.read_guard(path)
    raw = canon.read_bytes()
    if len(raw) < 16:
        return {"ok": False, "err": "asar file too small"}
    header_json_len = struct.unpack_from("<I", raw, 12)[0]
    start = 16
    end = start + header_json_len
    if end > len(raw):
        return {"ok": False, "err": "corrupt asar header length"}
    header = json.loads(raw[start:end].decode("utf-8", errors="replace"))
    files: list[dict[str, Any]] = []

    def walk(node: dict[str, Any], prefix: str) -> None:
        if len(files) >= limit:
            return
        children = node.get("files")
        if isinstance(children, dict):
            for name, child in children.items():
                rel = f"{prefix}/{name}" if prefix else name
                if isinstance(child, dict):
                    if "files" in child:
                        walk(child, rel)
                    else:
                        if not grep or grep.lower() in rel.lower():
                            files.append({
                                "path": rel,
                                "size": int(child.get("size", 0)),
                                "offset": child.get("offset", "0"),
                            })
                        if len(files) >= limit:
                            return

    walk(header, "")
    return {"ok": True, "path": str(canon), "count": len(files), "files": files, "engine": "python"}


def _redact_query(url: str) -> str:
    """Replace query-string values with a length hint, keeping parameter names."""
    if "?" not in url:
        return url
    base, _, query = url.partition("?")
    redacted = []
    for pair in query.split("&"):
        name, sep, value = pair.partition("=")
        if sep and value:
            redacted.append(f"{name}=<{len(value)} chars>")
        else:
            redacted.append(pair)
    return base + "?" + "&".join(redacted)


def _mask_secret(val: str, reveal: bool) -> str:
    if reveal or len(val) <= 8:
        return val
    return f"{val[:4]}...{val[-4:]}"


def inspect_netcap(path: str | Path, *, reveal: bool = False, limit: int = 100) -> dict[str, Any]:
    canon = guard.read_guard(path)
    # A raw capture is a different animal from HAR/SAZ: HAR and SAZ are browser
    # exports (already-decoded transactions), pcap/pcapng are link-layer frames that
    # have to be parsed. Dispatch on the magic before attempting JSON, because
    # json.loads on a binary capture raises rather than returning nothing useful.
    try:
        head = canon.read_bytes()[:4]
    except OSError as exc:
        return {"ok": False, "path": str(canon), "error": str(exc)}
    from . import capture as _capture
    if head in _capture._PCAP_MAGICS or head == _capture._PCAPNG_SHB:
        result = _capture.inspect_capture(canon, limit=limit)
        result["engine"] = "pcap"
        if not reveal and result.get("http_requests"):
            # Captured request lines routinely carry tokens in the query string.
            # Mask the *values*, not the URL: redacting a whole URL to "http...html"
            # hides which endpoint was called, which is the one thing worth keeping.
            for request in result["http_requests"]:
                request["url"] = _redact_query(request.get("url") or "")
        return result
    endpoints: list[dict[str, Any]] = []
    if zipfile.is_zipfile(canon):
        with zipfile.ZipFile(canon, "r") as zf:
            for name in zf.namelist():
                if name.endswith("_c.txt") and name.startswith("raw/"):
                    text = zf.read(name).decode("utf-8", errors="replace")
                    first = text.splitlines()[0] if text.splitlines() else ""
                    parts = first.split(" ")
                    if len(parts) >= 2:
                        endpoints.append({"method": parts[0], "url": parts[1], "member": name})
                if len(endpoints) >= limit:
                    break
        return {"ok": True, "format": "saz", "count": len(endpoints),
                "endpoints": endpoints, "engine": "python"}

    # Anything that is not HAR or SAZ lands here, and `json.loads` on an arbitrary binary
    # raises rather than returning something the caller can inspect. A capture reader must
    # answer "this is not a capture I understand", not throw at the caller — the whole point of
    # inspecting an unknown file is to find out what it is.
    try:
        data = json.loads(canon.read_text(encoding="utf-8", errors="replace"))
    except (json.JSONDecodeError, UnicodeDecodeError, OSError) as exc:
        return {"ok": False, "path": str(canon), "format": "unknown",
                "error": f"not a recognised capture format (pcap, pcapng, HAR or SAZ): {exc}",
                "engine": "python"}
    if not isinstance(data, dict):
        return {"ok": False, "path": str(canon), "format": "unknown",
                "error": "JSON capture is not an object", "engine": "python"}
    entries = ((data.get("log") or {}).get("entries") or [])[:limit]
    secret_headers = {"authorization", "cookie", "set-cookie", "x-api-key", "x-auth-token"}
    for ent in entries:
        req = ent.get("request") or {}
        resp = ent.get("response") or {}
        hdrs = {}
        for h in req.get("headers") or []:
            k = str(h.get("name", ""))
            v = str(h.get("value", ""))
            hdrs[k] = _mask_secret(v, reveal) if k.lower() in secret_headers else v
        endpoints.append({
            "method": req.get("method", "GET"),
            "url": req.get("url", ""),
            "status": resp.get("status", 0),
            "headers": hdrs,
        })
    return {"ok": True, "format": "har", "count": len(endpoints),
            "endpoints": endpoints, "engine": "python"}


def inspect_apk(path: str | Path) -> dict[str, Any]:
    canon = guard.read_guard(path)
    if not zipfile.is_zipfile(canon):
        return {"ok": False, "err": "not a valid zip/apk archive"}
    with zipfile.ZipFile(canon, "r") as zf:
        names = zf.namelist()
        dex = [n for n in names if n.endswith(".dex")]
        libs = [n for n in names if n.startswith("lib/") and n.endswith(".so")]
        has_manifest = "AndroidManifest.xml" in names
        perms: list[str] = []
        if has_manifest:
            raw_m = zf.read("AndroidManifest.xml")
            for m in re.findall(rb"android\.permission\.[A-Z0-9_]+", raw_m):
                p = m.decode("ascii", errors="ignore")
                if p not in perms:
                    perms.append(p)
        return {
            "ok": True, "path": str(canon), "has_manifest": has_manifest,
            "dex_files": dex, "native_libs": libs[:40],
            "permissions": perms[:50], "total_entries": len(names), "engine": "python",
        }


def decompile(path: str | Path, *, target: str = "main") -> dict[str, Any]:
    canon = guard.read_guard(path)
    targets = [t.strip() for t in str(target).split(",") if t.strip()]
    if len(targets) > 1:
        results: dict[str, Any] = {}
        for t in targets[:8]:
            results[t] = decompile(canon, target=t)
        return {
            "ok": any(v.get("ok") for v in results.values()),
            "batch": True,
            "count": len(results),
            "results": results,
        }
    target = targets[0] if targets else "main"
    try:
        from ...adapters.ghidra_mcp import _handle_tool
        out = _handle_tool("decompile_function", {"path": str(canon), "name": target})
        if out.get("ok") and out.get("pseudocode"):
            return {
                "ok": True,
                "engine": out.get("engine", "ghidra+borer"),
                "target": target,
                "code": out["pseudocode"],
                "rodata_strings": out.get("rodata_strings", {}),
                "math_notes": out.get("math_notes", []),
            }
    except Exception:
        pass
    rz = shutil.which("rizin") or shutil.which("r2")
    if rz:
        res = subprocess.run(
            [rz, "-q0", "-c", f"aaa; pdg @ {target}", str(canon)],
            capture_output=True, text=True, timeout=30,
        )
        if res.returncode == 0 and res.stdout.strip():
            return {"ok": True, "engine": Path(rz).name, "target": target, "code": res.stdout}
    obj = shutil.which("objdump")
    if obj:
        res = subprocess.run([obj, "-d", f"--disassemble={target}", str(canon)],
                             capture_output=True, text=True, timeout=20)
        if res.returncode == 0 and res.stdout.strip():
            return {"ok": True, "engine": "objdump", "target": target, "code": res.stdout}
    return {"ok": False, "err": "no supported decompiler/disassembler found (ghidra/borer/rizin/r2/objdump)"}


def triage_binary(path: str | Path) -> dict[str, Any]:
    """One-shot RE triage: format info, checksec, sections, RTTI, top borer functions, and key strings."""
    canon = guard.read_guard(path)
    from . import native, rtti
    from ...adapters.ghidra_mcp import STATE as _GSTATE

    info = native.get_info(canon)
    checksec = native.checksec(canon)
    sections = native.get_sections(canon)
    rtti_res = rtti.extract_rtti(canon)
    strings_res = native.extract_strings(canon, min_len=6, limit=40)
    borer_funcs = (_GSTATE.run_borer_cli("functions", str(canon), "", "0", "40") or "").splitlines()[:25] if _GSTATE.borer_bin else []
    return {
        "ok": True,
        "evidence_complete": True,
        "path": str(canon),
        "info": info,
        "checksec": checksec,
        "sections": sections.get("sections", [])[:15],
        "rtti": {"class_count": rtti_res.get("class_count", 0), "classes": (rtti_res.get("classes") or [])[:10]},
        "borer_functions": borer_funcs,
        "strings_sample": (strings_res.get("strings") or [])[:30],
    }


def trace_binary(path: str | Path, *, confirm: str | None = None) -> dict[str, Any]:
    canon = guard.read_guard(path)
    guard.check_write_mode(confirm_token=confirm)
    if not confirm:
        tok = guard.issue_token("trace", str(canon), scope="re")
        return {"ok": False, "err": "confirm_required", "confirm_hint": tok}
    return {"ok": False, "err": "dynamic tracing requires native xtforge-hub + frida-trace or gdb"}
