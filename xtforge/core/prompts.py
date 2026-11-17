"""Prompt loading (R11): one function, every prompt hashed into the run log.

No runtime prompt may be constructed anywhere else.
"""


from __future__ import annotations

import hashlib
import os
import re
from functools import lru_cache
from pathlib import Path
from typing import Any

from ..version import project_root

def _xt_cmd() -> str:
    """How this installation should be invoked, discovered not assumed.

    A release must not ship one machine's absolute path in the prompt every
    agent reads. Prefer the launcher that exists, then the console script, then
    a bare module invocation - all of which work wherever it is installed.
    """
    import os
    import shutil
    env = os.environ.get("XT_BIN")
    if env:
        return env
    for p in Path.home().parents:
        if p.name == ".dsh":
            cand = p.parent / "bin" / "xtforge"
            if cand.exists():
                return str(cand)
    home_bin = os.path.expanduser("~/bin/xtforge")
    if os.path.exists(home_bin):
        return home_bin
    found = shutil.which("xtforge")
    if found:
        return found
    return "python3 -m xtforge.cli"


def _mounted_mcp_summary() -> dict[str, Any]:
    """What MCP the active profile really mounts, for the injected prompt.

    Everything about this is best-effort: a prompt is rendered on machines with
    no harness at all, and an unreadable config must degrade to "unknown"
    rather than break the render. The point is that the prompt names servers
    and tools that exist — the previous version hardcoded `memos`, which the
    live profile does not mount, so it described a harness nobody was running.
    """
    summary: dict[str, Any] = {
        "profile": None,
        "names": "",
        "tools": "",
        "memory_tools": [],
    }
    try:
        from . import mcp as _mcp

        profile = _mcp.active_profile()
        summary["profile"] = profile
        report = _mcp.inventory(profile=profile)
        servers = report.get("servers") or []
        if not servers:
            return summary
        summary["names"] = ",".join(sorted({s.name for s in servers}))
        # Tool names are only known after a probe; naming them before that
        # would be a guess presented as fact.
        summary["tools"] = ""
        # Which server carries memory is a property of the PROFILE, not of this
        # module: `xt-forge` here, `memos` on another installation. Looking for
        # one hardcoded name would just relocate the bug this replaced, so pick
        # the first server that plausibly owns durable memory.
        memory = _memory_server(servers)
        if memory is None:
            return summary
        if memory.proxied:
            # Behind the lite proxy the memory tools are NOT individual MCP
            # tools — the model sees meta-tools and reaches mem_* through
            # `*_call`. Claiming `mcp__<server>__mem_put` here would be a tool
            # name that cannot be called, which is the same class of lie as the
            # hardcoded `memos` this replaced.
            call_tool = f"{memory.proxy_prefix}_call"
            summary["memory_tools"] = [(
                call_tool,
                f"run any {memory.name} tool, including `mem_put` and `mem_search`",
            )]
            summary["tools"] = call_tool
            return summary
        if not memory.tool_names:
            return summary
        purposes = {
            "mem_put": "store a durable finding",
            "mem_search": "recall prior findings",
            "mem_get": "read one record by id",
            "knowledge_put": "contribute a lifecycle-tracked knowledge record",
            "knowledge_search": "search contributed knowledge",
        }
        for name in memory.tool_names:
            if name in purposes:
                summary["memory_tools"].append(
                    (f"mcp__{memory.name}__{name}", purposes[name]))
        if summary["memory_tools"]:
            summary["tools"] = ",".join(t for t, _ in summary["memory_tools"])
    except Exception:  # noqa: BLE001 - a prompt must render without a harness
        return summary
    return summary


#: Server names that plausibly carry durable memory, in preference order. The
#: prompt only ever NAMES a server it found in the profile; this list decides
#: which of the mounted servers to describe, not what to claim is mounted.
_MEMORY_SERVER_HINTS = ("xt-forge", "memos", "mem", "memory", "knowledge")


def _memory_server(servers: list[Any]) -> Any:
    """The mounted server that owns durable memory, or None."""
    for hint in _MEMORY_SERVER_HINTS:
        for server in servers:
            if server.name.lower() == hint:
                return server
    for server in servers:
        lowered = server.name.lower()
        if any(hint in lowered for hint in ("mem", "knowledge")):
            return server
    return None


PROMPT_DIR = project_root() / "prompts"
_VAR = re.compile(r"\{\{\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*\}\}")
UNKNOWN = object()


class PromptError(RuntimeError):
    pass


def prompt_path(name: str) -> Path:
    """Resolve a prompt reference.

    Accepts a bare name ("verifier"), a path relative to prompts/
    ("phases/design"), a project-relative path ("prompts/phases/design"),
    or an absolute path.
    """
    rel = name[:-3] if name.endswith(".md") else name
    candidates = [
        PROMPT_DIR / f"{rel}.md",
        project_root() / f"{rel}.md",
        Path(rel) if Path(rel).is_absolute() else None,
    ]
    for c in candidates:
        if c is not None and c.exists():
            return c
    raise PromptError(f"prompt not found: {name} (tried {[str(c) for c in candidates if c]})")


@lru_cache(maxsize=64)
def _load(name: str) -> str:
    return prompt_path(name).read_text(encoding="utf-8")


def prompt_hash(name: str) -> str:
    return hashlib.sha256(_load(name).encode("utf-8")).hexdigest()[:12]


def variables(name: str) -> list[str]:
    return sorted(set(_VAR.findall(_load(name))))


def render(name: str, **values: Any) -> str:
    """Substitute {{vars}}. Missing vars raise; extra vars are ignored."""
    text = _load(name)
    needed = set(variables(name))
    missing = needed - set(values)
    if missing:
        raise PromptError(f"prompt {name} missing vars: {sorted(missing)}")
    return _VAR.sub(lambda m: str(values.get(m.group(1), "")), text)


def render_with_hashes(name: str, **values: Any) -> tuple[str, dict[str, str]]:
    """Returns (rendered_text, {prompt_name: hash}) for the run log."""
    return render(name, **values), {name: prompt_hash(name)}


def hash_all() -> dict[str, str]:
    """Hash every shipped prompt, for the run header."""
    out: dict[str, str] = {}
    for p in sorted(PROMPT_DIR.rglob("*.md")):
        rel = p.relative_to(PROMPT_DIR).with_suffix("").as_posix()
        out[rel] = hashlib.sha256(p.read_bytes()).hexdigest()[:12]
    return out


def build_agent_context(include_taste: bool = True,
                        include_rules: bool = True,
                        include_flash: bool = True,
                        flash_scope: str = "global",
                        flash_base: Path | str | None = None,
                        query: str | None = None,
                        mem_k: int = 3,
                        harness: str = "auto",
                        compact: bool = False,
                        token_budget: int | None = None,
                        prompt_name: str | None = None,
                        **values: Any) -> str:
    """Build a consolidated, optimized system context block for LLM agents.
    
    Injects:
    1. Base prompt if specified (e.g. prompt_name="phases/design")
    2. Relevant durable memories from Store if query is given
    3. Active pinned session context from FlashStore
    4. Active enforced taste policies from TasteStore
    5. Harness-specific tool context (e.g. DSH MCP tools and plugins)
    6. Native xt-forge launcher directives with safety and token optimization.
    """
    sections: list[str] = []
    
    # 1. Base prompt if specified
    if prompt_name:
        sections.append(render(prompt_name, **values))

    # 2. Durable memory recall if query is provided
    if query:
        try:
            from .mem.store import Store
            from .mem import search as memsearch
            from ..version import db_path
            st = Store(db_path())
            search_res = memsearch.search(st, query, k=mem_k)
            results = search_res.get("results", [])
            st.close()
            if results:
                if compact:
                    items = []
                    for r in results:
                        rec = r.get("record", {})
                        title = rec.get("title", "")[:40]
                        body = rec.get("body", "").strip()[:160]
                        items.append(f'<mem id="{rec.get("id")}" t="{title}">{body}</mem>')
                    sections.append(f'<recalled_memory q="{query}">' + "".join(items) + '</recalled_memory>')
                else:
                    lines = [f'<recalled_memory query="{query}">']
                    for r in results:
                        rec = r.get("record", {})
                        lines.append(f'  <item id="{rec.get("id")}" title="{rec.get("title","")}">{rec.get("body","").strip()}</item>')
                    lines.append('</recalled_memory>')
                    sections.append("\n".join(lines))
        except Exception:
            pass

    # 3. Pinned hot flash memory
    if include_flash:
        try:
            from .mem.flash import Flash
            from ..version import flash_dir
            fb = flash_base or flash_dir()
            fl = Flash(fb)
            pinned = fl.list(scope=flash_scope, pin_only=True)
            if pinned:
                if compact:
                    items = [f'<p k="{p.get("k")}">{p.get("v","").strip()}</p>' for p in pinned]
                    sections.append('<session_flash>' + "".join(items) + '</session_flash>')
                else:
                    lines = ['<session_flash source="flash" type="pinned">']
                    for p in pinned:
                        lines.append(f'  <item key="{p.get("k")}">{p.get("v","").strip()}</item>')
                    lines.append('</session_flash>')
                    sections.append("\n".join(lines))
        except Exception:
            pass

    # 4. Enforced taste rules
    if include_taste:
        try:
            from .taste.store import TasteStore
            from .taste import block as tasteblock
            from ..version import taste_db_path
            st = TasteStore(taste_db_path())
            rows = st.search(status="enforced", limit=100)
            if rows:
                if compact:
                    items = [f'<r cat="{r.get("category")}" cf="{r.get("confidence", 0.0):.2f}">{r.get("statement","")}</r>' for r in rows]
                    sections.append('<taste>' + "".join(items) + '</taste>')
                else:
                    taste_block = tasteblock.render_block(rows)
                    if taste_block:
                        sections.append(taste_block)
            st.close()
        except Exception:
            pass

    # 5. Harness-specific context
    eff_harness = harness.lower() if harness else "auto"
    if eff_harness == "auto":
        if os.environ.get("XT_HARNESS"):
            eff_harness = os.environ.get("XT_HARNESS", "").lower()
        elif (
            os.environ.get("DSH_HOME")
            or any(k.startswith("DSH_") for k in os.environ)
            or (Path.home() / ".dsh").is_dir()
            or any(p.name == ".dsh" or (p / ".dsh").is_dir() for p in Path.home().parents)
        ):
            eff_harness = "dsh"
        else:
            eff_harness = "generic"

    if eff_harness == "dsh":
        # This block used to be a literal naming the `memos` server. The live
        # `dsh-tui` profile mounts no such server — memory is reached through
        # `xt-forge` (proxied as `xt`) — so the injected prompt was telling the
        # model to call tools that do not exist while remaining silent about the
        # ones that do. Read the profile that is actually configured instead,
        # and stay honest when it cannot be read.
        mounted = _mounted_mcp_summary()
        if compact:
            sections.append(
                '<harness type="dsh">'
                f'<mcp servers="{mounted["names"] or "unknown"}" '
                f'tools="{mounted["tools"] or "unknown"}"/>'
                '<plugins list="dsh-context,dshmarket,dsh-rea,dsh-purge,dsh-project-memory"/>'
                '<skills list="media-tools,remotion-*,browser-skill"/>'
                '</harness>'
            )
        else:
            if mounted["memory_tools"]:
                memory_lines = "".join(
                    f'    `{name}` — {purpose}\n'
                    for name, purpose in mounted["memory_tools"])
                memory_block = (
                    '  <mcp_tools server="xt-forge">\n'
                    '    Prefer these for durable memory and recall:\n'
                    f'{memory_lines}'
                    '  </mcp_tools>\n'
                )
            else:
                memory_block = (
                    '  <mcp_tools>\n'
                    '    No memory MCP server is mounted in the active profile; '
                    f'use the CLI instead (`{_xt_cmd()} mem search`).\n'
                    '  </mcp_tools>\n'
                )
            sections.append(
                '<harness_context type="dsh">\n'
                f'  <profile name="{mounted["profile"] or "unknown"}">\n'
                f'    MCP servers: {mounted["names"] or "none detected"}.\n'
                '  </profile>\n'
                f'{memory_block}'
                '  <plugins>\n'
                '    Active in web profile: dsh-context, dsh-purge (audit only; never run --apply), dshmarket, dsh-rea, dsh-project-memory.\n'
                '    Mounted local skills: media-tools, remotion-*, browser-skill.\n'
                '  </plugins>\n'
                '</harness_context>'
            )

    # 6. Tool invocation directives
    if compact:
        sections.append(
            '<system_instructions source="xt-forge">'
            f'<directive priority="critical">Use {_xt_cmd()} route/code/mem/scan; always --json; no destructive cmds.</directive>'
            '</system_instructions>'
        )
    else:
        sections.append(
            '<system_instructions source="xt-forge">\n'
            '  <directive priority="critical">\n'
            f'    Always prioritize reaching for native xt-forge tools via `{_xt_cmd()}`\n'
            '    for repository mapping (`route context`, `code symbols/syntax`), memory recall (`mem search`), \n'
            '    and safety checks (`scan secrets`, `code syntax`) before re-deriving or guessing.\n'
            '  </directive>\n'
            '</system_instructions>'
        )

    delimiter = "" if compact else "\n\n"
    rendered = delimiter.join(sections)

    # 7. Token budget enforcement (~4 chars / token)
    if token_budget and token_budget > 0:
        char_limit = token_budget * 4
        if len(rendered) > char_limit:
            # If standard directive is too large for budget, switch to compact directive
            if not compact and len(sections[-1]) > char_limit:
                compact_dir = (
                    '<system_instructions source="xt-forge">'
                    f'<directive priority="critical">Use {_xt_cmd()} route/code/mem/scan; always --json.</directive>'
                    '</system_instructions>'
                )
                sections[-1] = compact_dir
                rendered = delimiter.join(sections)

            last_sec = sections[-1]
            avail = max(0, char_limit - len(last_sec) - len(delimiter))
            if avail > 0:
                truncated_head = rendered[:avail]
                if not compact and "\n\n" in truncated_head:
                    truncated_head = truncated_head.rsplit("\n\n", 1)[0]
                rendered = f"{truncated_head}{delimiter}{last_sec}"
            else:
                rendered = last_sec[:char_limit]

    return rendered


def clear_cache() -> None:
    _load.cache_clear()
