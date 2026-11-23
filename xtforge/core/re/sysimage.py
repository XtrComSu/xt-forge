"""Access the native XT-Forge-SYS image model from the Python CLI and MCP."""

import json
import os
import shutil
import subprocess
from pathlib import Path

from ...version import project_root


def callgraph(path: str, *, member: str | None = None, arch: str | None = None,
              limit: int = 0) -> dict:
    options = ["--limit", str(limit)]
    if arch:
        options.extend(["--arch", arch])
    return _run("callgraph", path, member, options)


def overview(path: str, *, member: str | None = None, arch: str | None = None,
             base: int | None = None) -> dict:
    options: list[str] = []
    if arch:
        # A raw image needs an explicit architecture and load address: it has no
        # header to read either from.
        options.extend(["--arch", arch])
        if base is not None:
            options.extend(["--base", hex(base)])
    return _run("overview", path, member, options)


def pdb_types(path: str, *, limit: int = 0) -> dict:
    options = ["--limit", str(limit)]
    return _run("pdb-types", path, None, options)


def functions(path: str, *, member: str | None = None, arch: str | None = None,
              limit: int = 200) -> dict:
    options = ["--limit", str(limit)]
    if arch:
        options.extend(["--arch", arch])
    return _run("functions", path, member, options)


def disassemble(path: str, *, member: str | None = None, arch: str | None = None,
                target: str | None = None, byte_count: int = 0, count: int = 200,
                flow: bool = False, lift: bool = False) -> dict:
    options = ["--bytes", str(byte_count), "--max-instructions", str(count)]
    if arch:
        options.extend(["--arch", arch])
    if target:
        options.extend(["--target", target])
    if flow:
        options.append("--flow")
    return _run("decompile-native" if lift else "disasm-native", path, member, options)


def references(path: str, *, member: str | None = None, arch: str | None = None,
               target: str | None = None, max_functions: int = 0, limit: int = 200) -> dict:
    options = ["--limit", str(limit), "--max-functions", str(max_functions)]
    if arch:
        options.extend(["--arch", arch])
    if target:
        options.extend(["--target", target])
    return _run("xrefs-native", path, member, options)


def dispatch(path: str, *, member: str | None = None, arch: str | None = None,
             target: str | None = None) -> dict:
    """Recover indirect dispatch tables (jump tables) for one function."""
    options: list[str] = []
    if arch:
        options.extend(["--arch", arch])
    options.extend(["--target", target or ""])
    return _run("dispatch-native", path, member, options)


def _annotation_target(path: str, options: list[str]) -> list[str]:
    """Rewrite an annotated function name to its address for the native engine.

    The overlay database is the only place analyst renames exist, so a request
    that names a renamed function has to be translated before it reaches
    XT-Forge-SYS, which resolves targets against the image's own symbols.
    """
    if "--target" not in options:
        return options
    index = options.index("--target")
    if index + 1 >= len(options):
        return options
    wanted = options[index + 1]
    try:
        from .annotate import overlay_map_for_binary
        notes = overlay_map_for_binary(path)
    except Exception:
        return options
    for address, name in notes["renames_by_rva"].items():
        if name == wanted:
            rewritten = list(options)
            rewritten[index + 1] = address
            return rewritten
    return options


def overlay(path: str, result: dict) -> dict:
    """Merge analyst annotations into an XT-Forge-SYS result.

    Renames apply to function names and comments attach as notes, so a
    disassembly pass keeps the labels the analyst already assigned in the
    overlay database instead of reverting to raw symbol names.
    """
    if not result.get("ok"):
        return result
    try:
        from .annotate import overlay_map_for_binary
        notes = overlay_map_for_binary(path)
    except Exception:
        return result
    if not notes["count"]:
        return result
    renames, comments = notes["renames_by_rva"], notes["comments_by_rva"]

    def apply(item: dict) -> None:
        address = item.get("address")
        if address is None:
            return
        key = hex(address).lower()
        if key in renames:
            # Keep the image's own symbol as symbol_name; only overwrite the
            # display name so a caller can still map back to the raw image.
            if "symbol_name" not in item:
                if original := (item.get("name") or item.get("function_name")):
                    item["symbol_name"] = original
            item["name"] = renames[key]
            item["name_source"] = "annotation"
        if key in comments:
            item["comment"] = comments[key]

    for image in result.get("images") or []:
        for function in image.get("functions") or []:
            apply(function)
    for key in ("blocks", "instructions"):
        for item in result.get(key) or []:
            apply(item)
    # Cross-reference rows name the enclosing function instead of carrying its
    # address, so map the recorded symbol names back through the overlay.
    by_symbol = notes["renames_by_orig"]
    if by_symbol:
        for reference in result.get("references") or []:
            if current := reference.get("function_name"):
                if renamed := by_symbol.get(current):
                    reference["symbol_name"] = current
                    reference["function_name"] = renamed
    identity = result.get("function")
    if identity is None:
        identity = result.get("address")
    if identity is not None:
        key = hex(identity).lower()
        if key in renames:
            if original := (result.get("function_name") or result.get("name")):
                result["symbol_name"] = original
            result["name"] = renames[key]
            if "function_name" in result:
                result["function_name"] = renames[key]
            result["name_source"] = "annotation"
        if key in comments:
            result["comment"] = comments[key]
    result["annotations"] = notes["count"]
    return result


def _run(verb: str, path: str, member: str | None, options: list[str]) -> dict:
    binary = "xtforge-hub.exe" if os.name == "nt" else "xtforge-hub"
    root = Path(os.environ["XT_ROOT"]) if os.environ.get("XT_ROOT") else project_root()
    bundled = root / "native" / "xtforge-go" / binary
    paths = (bundled, Path(shutil.which(binary) or ""))
    hub = next((p.resolve() for p in paths if p.is_file() and os.access(p, os.X_OK)), None)
    if hub is None or os.environ.get("XT_NATIVE_HUB") == "0":
        return {"ok": False, "error": f"XT-Forge-SYS {verb} requires the enabled xtforge-hub native runtime"}
    options = _annotation_target(path, options)
    argv = [str(hub), "re", verb, path, *options]
    if member:
        argv.extend(["--member", member])
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=30)
        return overlay(path, json.loads(proc.stdout))
    except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
        return {"ok": False, "error": str(exc)}


def demangle(symbols: list[str]) -> dict:
    """Demangle Swift symbols through the Go hub.

    Separate from _run because _run always appends a path, and demangle takes only
    symbols.
    """
    binary = "xtforge-hub.exe" if os.name == "nt" else "xtforge-hub"
    root = Path(os.environ["XT_ROOT"]) if os.environ.get("XT_ROOT") else project_root()
    bundled = root / "native" / "xtforge-go" / binary
    paths = (bundled, Path(shutil.which(binary) or ""))
    hub = next((p.resolve() for p in paths if p.is_file() and os.access(p, os.X_OK)), None)
    if hub is None or os.environ.get("XT_NATIVE_HUB") == "0":
        return {"ok": False, "error": "demangle requires the enabled xtforge-hub native runtime"}
    try:
        proc = subprocess.run([str(hub), "re", "demangle", *symbols],
                              capture_output=True, text=True, timeout=30)
        return json.loads(proc.stdout)
    except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
        return {"ok": False, "error": str(exc)}
