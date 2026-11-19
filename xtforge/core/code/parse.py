"""Structure extraction for code files. Stdlib-only, degrades gracefully.

Python gets real `ast` parsing. Everything else gets a conservative regex
heuristic over declaration shapes, which is enough to navigate a codebase and
never worse than grep. A file we cannot read is data: `method` says how the
result was produced (`ast`, `regex`, `none`) and `error` explains why not.

Borrowed ideas: tree-sitter's language-agnostic symbol model, ast-grep's
structure-first navigation. Clean-room, no dependency.
"""
from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import Any

LANG_BY_EXT = {
    ".py": "python", ".pyi": "python",
    ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript",
    ".ts": "typescript", ".tsx": "typescript",
    ".go": "go", ".rs": "rust", ".c": "c", ".h": "c", ".cc": "cpp",
    ".cpp": "cpp", ".hpp": "cpp", ".java": "java", ".kt": "kotlin",
    ".rb": "ruby", ".sh": "shell", ".bash": "shell", ".zsh": "shell",
    ".md": "markdown", ".json": "json", ".yaml": "yaml", ".yml": "yaml",
    ".toml": "toml", ".sql": "sql", ".swift": "swift", ".php": "php",
}

# language -> [(kind, pattern)], matched against the line start.
_DECL_PATTERNS: dict[str, list[tuple[str, re.Pattern[str]]]] = {
    "javascript": [
        ("function", re.compile(r"^(?:export\s+)?(?:async\s+)?function\s+(?P<name>[\w$]+)")),
        ("class", re.compile(r"^(?:export\s+)?class\s+(?P<name>[\w$]+)")),
        ("method", re.compile(r"^\s{2,}(?:async\s+)?(?P<name>[\w$]+)\s*\([^)]*\)\s*\{")),
    ],
    "typescript": [
        ("function", re.compile(r"^(?:export\s+)?(?:async\s+)?function\s+(?P<name>[\w$]+)")),
        ("class", re.compile(r"^(?:export\s+)?(?:abstract\s+)?class\s+(?P<name>[\w$]+)")),
        ("interface", re.compile(r"^(?:export\s+)?interface\s+(?P<name>[\w$]+)")),
        ("type", re.compile(r"^(?:export\s+)?type\s+(?P<name>[\w$]+)")),
    ],
    "go": [
        ("function", re.compile(r"^func\s+(?:\([^)]+\)\s+)?(?P<name>\w+)")),
        ("type", re.compile(r"^type\s+(?P<name>\w+)")),
    ],
    "rust": [
        ("function", re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+(?P<name>\w+)")),
        ("struct", re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?struct\s+(?P<name>\w+)")),
        ("enum", re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?enum\s+(?P<name>\w+)")),
        ("trait", re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?trait\s+(?P<name>\w+)")),
        ("impl", re.compile(r"^impl(?:<[^>]*>)?\s+(?P<name>[\w:]+)")),
    ],
    "c": [
        ("function", re.compile(r"^(?:[\w*]+\s+)+\*?(?P<name>\w+)\s*\([^;]*$")),
        ("struct", re.compile(r"^(?:typedef\s+)?struct\s+(?P<name>\w+)")),
    ],
    "cpp": [
        ("function", re.compile(r"^(?:[\w:<>*&~]+\s+)+\*?(?P<name>\w+)\s*\([^;]*$")),
        ("class", re.compile(r"^(?:template\s*<[^>]*>\s*)?class\s+(?P<name>\w+)")),
        ("struct", re.compile(r"^(?:template\s*<[^>]*>\s*)?struct\s+(?P<name>\w+)")),
    ],
    "java": [
        ("class", re.compile(r"^\s*(?:public\s+|private\s+|protected\s+|abstract\s+|final\s+)*class\s+(?P<name>\w+)")),
        ("interface", re.compile(r"^\s*(?:public\s+)?interface\s+(?P<name>\w+)")),
        ("method", re.compile(r"^\s{4,}(?:public\s+|private\s+|protected\s+|static\s+|final\s+|async\s+)*[\w<>\[\]]+\s+(?P<name>\w+)\s*\([^;]*$")),
    ],
    "shell": [
        ("function", re.compile(r"^(?:function\s+)?(?P<name>[\w-]+)\s*\(\)\s*\{")),
    ],
    "ruby": [
        ("function", re.compile(r"^\s*def\s+(?P<name>[\w?!]+)")),
        ("class", re.compile(r"^\s*(?:class|module)\s+(?P<name>[\w:]+)")),
    ],
    "php": [
        ("class", re.compile(r"^\s*(?:abstract\s+|final\s+)?class\s+(?P<name>\w+)")),
        ("function", re.compile(r"^\s*(?:public\s+|private\s+|protected\s+|static\s+)*function\s+(?P<name>\w+)")),
    ],
    "swift": [
        ("function", re.compile(r"^\s*(?:public\s+|private\s+|internal\s+)?(?:static\s+)?func\s+(?P<name>\w+)")),
        ("class", re.compile(r"^\s*(?:public\s+|private\s+)?(?:final\s+)?(?:class|struct|enum|protocol)\s+(?P<name>\w+)")),
    ],
    "kotlin": [
        ("function", re.compile(r"^\s*(?:public\s+|private\s+|internal\s+)?(?:suspend\s+)?fun\s+(?:<[^>]*>\s+)?(?P<name>\w+)")),
        ("class", re.compile(r"^\s*(?:public\s+|private\s+)?(?:abstract\s+|data\s+|sealed\s+)?(?:class|object|interface)\s+(?P<name>\w+)")),
    ],
    "sql": [
        ("table", re.compile(r"^\s*CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?(?P<name>[\w.]+)", re.I)),
        ("view", re.compile(r"^\s*CREATE\s+(?:OR\s+REPLACE\s+)?VIEW\s+(?P<name>[\w.]+)", re.I)),
    ],
}

_WORD = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


def detect(path: str | Path) -> str:
    return LANG_BY_EXT.get(Path(path).suffix.lower(), "text")


def _read(path: Path) -> tuple[str, str | None]:
    try:
        return path.read_text(encoding="utf-8", errors="replace"), None
    except OSError as exc:
        return "", f"unreadable: {exc}"


def _python_symbols(text: str) -> list[dict[str, Any]]:
    tree = ast.parse(text)
    out: list[dict[str, Any]] = []

    def visit(node: ast.AST, parent: str | None = None) -> None:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            kind = "class" if isinstance(node, ast.ClassDef) else "function"
            name = f"{parent}.{node.name}" if parent else node.name
            args = ""
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                args = ", ".join(a.arg for a in node.args.args)
                args = f"({args})"
            out.append({
                "name": name, "kind": kind, "line": node.lineno,
                "end": getattr(node, "end_lineno", node.lineno) or node.lineno,
                "signature": f"{node.name}{args}",
                "doc": ast.get_docstring(node, clean=True) or "",
            })
            child_parent = name if kind == "class" else parent
        else:
            child_parent = parent
        for child in ast.iter_child_nodes(node):
            visit(child, child_parent)

    visit(tree)
    return out


def _regex_symbols(text: str, language: str) -> list[dict[str, Any]]:
    patterns = _DECL_PATTERNS.get(language, [])
    if not patterns:
        return []
    out: list[dict[str, Any]] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith(("//", "#", "*", "/*")):
            continue
        for kind, pattern in patterns:
            match = pattern.match(line)
            if match:
                out.append({"name": match.group("name"), "kind": kind,
                            "line": lineno, "end": lineno,
                            "signature": stripped[:120], "doc": ""})
                break
    return out


_SKIP_DIRS = {
    ".git", ".hg", ".svn", "node_modules", "__pycache__", ".venv", "venv",
    "target", "dist", "build", "artifacts", ".pytest_cache", ".mypy_cache",
}


def _iter_code_files(base: Path, limit: int = 80) -> list[Path]:
    out: list[Path] = []
    for p in sorted(base.rglob("*")):
        if any(part in _SKIP_DIRS or part.startswith(".") for part in p.relative_to(base).parts[:-1]):
            continue
        if p.is_file() and detect(p) != "text":
            out.append(p)
            if len(out) >= limit:
                break
    return out


def symbols(path: str | Path) -> dict[str, Any]:
    """Top-level and nested definitions in one file or a directory."""
    p = Path(path)
    if p.is_dir():
        agg: list[dict[str, Any]] = []
        files = _iter_code_files(p, limit=40)
        for fp in files:
            sub = symbols(fp)
            rel = str(fp)
            try:
                rel = str(fp.relative_to(p))
            except ValueError:
                pass
            for s in sub.get("symbols", []):
                agg.append({**s, "file": rel})
        return {"path": str(p), "language": "multi", "method": "dir",
                "files_scanned": len(files), "symbols": agg, "count": len(agg)}
    text, err = _read(p)
    if err:
        return {"path": str(p), "language": detect(p), "method": "none",
                "symbols": [], "count": 0, "error": err}
    language = detect(p)
    if language == "python":
        try:
            found = _python_symbols(text)
            method = "ast"
        except SyntaxError as exc:
            found = _regex_symbols(text, "python") or _generic_symbols(text)
            method = "regex"
            err = f"syntax_error: {exc.msg} (line {exc.lineno})"
    else:
        found = _regex_symbols(text, language)
        method = "regex" if found else ("none" if language == "text" else "regex")
    return {"path": str(p), "language": language, "method": method,
            "symbols": found, "count": len(found),
            **({"error": err} if err else {})}


def _generic_symbols(text: str) -> list[dict[str, Any]]:
    """Last resort: indented definition-ish lines."""
    out = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        match = re.match(r"^\s*(?:def|class|function|func|fn)\s+(\w+)", line)
        if match:
            out.append({"name": match.group(1), "kind": "definition",
                        "line": lineno, "end": lineno,
                        "signature": line.strip()[:120], "doc": ""})
    return out


def outline(path: str | Path) -> dict[str, Any]:
    """Symbol tree for one file or a directory."""
    p = Path(path)
    if p.is_dir():
        files = _iter_code_files(p, limit=40)
        tree: list[dict[str, Any]] = []
        total_syms = 0
        for fp in files:
            sub = outline(fp)
            rel = str(fp)
            try:
                rel = str(fp.relative_to(p))
            except ValueError:
                pass
            sub_tree = sub.get("tree", [])
            if sub_tree:
                total_syms += len(sub.get("symbols", []))
                tree.append({"name": rel, "kind": "file", "line": 1, "children": sub_tree})
        return {"path": str(p), "language": "multi", "method": "dir",
                "files_scanned": len(files), "count": total_syms, "tree": tree}
    info = symbols(p)
    items = info["symbols"]
    if info["method"] != "ast":
        return {**info, "tree": [{"name": s["name"], "kind": s["kind"],
                                  "line": s["line"]} for s in items]}
    tree: list[dict[str, Any]] = []
    by_name: dict[str, dict[str, Any]] = {}
    for item in sorted(items, key=lambda s: (s["line"], -s["end"])):
        node = {"name": item["name"], "kind": item["kind"], "line": item["line"],
                "end": item["end"], "children": []}
        by_name[item["name"]] = node
        parent = item["name"].rsplit(".", 1)[0] if "." in item["name"] else None
        if parent and parent in by_name:
            by_name[parent]["children"].append(node)
        else:
            tree.append(node)
    return {**info, "tree": tree}


def refs(root: str | Path, name: str, limit: int = 50) -> dict[str, Any]:
    """Occurrences of a symbol name, with whether it is a definition site."""
    target = re.compile(rf"\b{re.escape(name)}\b")
    decl = re.compile(rf"^\s*(?:def|class|function|func|fn|struct|impl|type|interface|"
                      rf"enum|trait|module|pub fn|public function)\s+{re.escape(name)}\b")
    base = Path(root)
    hits: list[dict[str, Any]] = []
    scanned = 0
    if base.is_file():
        candidates = [base]
    elif base.is_dir():
        candidates = _iter_code_files(base, limit=500)
    else:
        candidates = []
    for path in candidates:
        if len(hits) >= limit:
            break
        text, err = _read(path)
        if err or not text:
            continue
        scanned += 1
        for lineno, line in enumerate(text.splitlines(), start=1):
            if target.search(line):
                hits.append({"path": str(path), "line": lineno,
                             "text": line.strip()[:160],
                             "definition": bool(decl.match(line))})
                if len(hits) >= limit:
                    break
    return {"name": name, "root": str(base), "files_scanned": scanned,
            "count": len(hits), "refs": hits, "truncated": len(hits) >= limit}
