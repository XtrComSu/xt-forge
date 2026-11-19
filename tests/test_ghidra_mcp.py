"""Tests for the 38-tool Ghidra & REA-replacement MCP server (`xtforge.adapters.ghidra_mcp`)."""
from __future__ import annotations

from pathlib import Path

from xtforge.adapters import ghidra_mcp
from xtforge.core import mcp_registry


def test_ghidra_mcp_preset_and_catalog(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("XT_HOME", str(tmp_path))
    assert mcp_registry.canonical_upstream_name("ghidra-mcp") == "ghidra"
    assert mcp_registry.canonical_upstream_name("pyghidra-mcp") == "ghidra"
    canon, argv, err = mcp_registry.resolve_upstream_cmd("ghidra")
    assert err is None
    assert canon == "ghidra"
    assert argv and argv[-1] == "xtforge.adapters.ghidra_mcp"
    assert len(ghidra_mcp.TOOLS) == 38


def test_ghidra_mcp_overlay_renames_prototype_and_comments(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("XT_HOME", str(tmp_path))
    bin_path = "/usr/bin/ls"
    if not Path(bin_path).is_file():
        return

    r1 = ghidra_mcp._handle_tool(
        "rename_function",
        {"path": bin_path, "old_name": "0x5620", "new_name": "ls_main_entry"},
    )
    assert r1["ok"] is True

    r2 = ghidra_mcp._handle_tool(
        "set_function_prototype",
        {"path": bin_path, "function_address": "0x5620", "prototype": "int ls_main_entry(int argc, char **argv)"},
    )
    assert r2["ok"] is True

    r3 = ghidra_mcp._handle_tool(
        "set_decompiler_comment",
        {"path": bin_path, "address": "0x5620", "comment": "Verified entry point"},
    )
    assert r3["ok"] is True

    r4 = ghidra_mcp._handle_tool(
        "rename_variable",
        {"path": bin_path, "function_name": "ls_main_entry", "old_name": "retaddr", "new_name": "saved_ret"},
    )
    assert r4["ok"] is True

    dec = ghidra_mcp._handle_tool(
        "decompile_function",
        {"path": bin_path, "name": "ls_main_entry"},
    )
    assert dec["ok"] is True
    code = dec["pseudocode"]
    assert "Verified entry point" in code
    assert "int ls_main_entry(int argc, char **argv)" in code or "ls_main_entry" in code
    assert dec["overlay"]["prototype"] == "int ls_main_entry(int argc, char **argv)"
