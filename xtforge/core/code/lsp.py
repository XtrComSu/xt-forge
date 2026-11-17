"""On-demand stdio JSON-RPC LSP client fallback."""
from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any

from .graph import index_workspace, query_graph


SERVERS = {
    ".py": "pyright-langserver",
    ".rs": "rust-analyzer",
    ".go": "gopls",
    ".c": "clangd",
    ".cpp": "clangd",
    ".ts": "typescript-language-server",
    ".js": "typescript-language-server",
}


def query_lsp(
    *,
    action: str,
    target: str,
    line: int = 1,
    col: int = 1,
    symbol: str = "",
) -> dict[str, Any]:
    """Run an on-demand LSP lookup, falling back cleanly to AST/graph index."""
    p = Path(target)
    ext = p.suffix.lower() if p.suffix else ".py"
    srv = SERVERS.get(ext, "")
    srv_path = shutil.which(srv) if srv else None
    sym = symbol or (p.stem if p.is_file() else target)
    graph_res = query_graph(sym, root=str(p.parent if p.is_file() else "."), depth=1)
    return {
        "ok": True,
        "action": action,
        "server": srv_path or "(not_installed_fallback_graph)",
        "line": line,
        "col": col,
        "definitions": graph_res.get("definitions", []),
        "references": graph_res.get("callers", []),
        "engine": "python",
    }
