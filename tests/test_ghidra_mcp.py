"""Tests for the 43-tool Ghidra & REA-replacement MCP server (`xtforge.adapters.ghidra_mcp`)."""
from __future__ import annotations

import os
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
    assert len(ghidra_mcp.TOOLS) == 43


def test_ghidra_mcp_sober_re_hardened_tools(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("XT_HOME", str(tmp_path))
    bin_path = "/usr/bin/ls"
    if not Path(bin_path).is_file():
        return

    deep = ghidra_mcp._handle_tool("inspect_elf_deep", {"path": bin_path})
    assert deep["ok"] is True
    assert "pt_load_segments" in deep
    assert "safe_post_bss_vaddr" in deep

    anchors = ghidra_mcp._handle_tool(
        "resolve_string_anchors",
        {"path": bin_path, "queries": ["POSIX", "version"]},
    )
    assert anchors["ok"] is True
    assert anchors["anchors_resolved"] >= 1

    win = ghidra_mcp._handle_tool(
        "slice_disasm_window",
        {"path": bin_path, "address": deep.get("entry_point") or "0x6000", "before_bytes": 16, "after_bytes": 64},
    )
    assert win["ok"] is True
    assert win["line_count"] >= 1

    probe = ghidra_mcp._handle_tool("probe_live_process", {"pid": os.getpid()})
    assert probe["ok"] is True
    assert "yama_ptrace_scope" in probe


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
