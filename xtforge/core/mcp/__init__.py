"""MCP server inventory: what the harness mounts, and what it costs.

The harness config is the only source of truth for which MCP servers run.
Nothing here guesses: every server, transport and command comes from the
cordis config that dsh actually reads on startup.

Two costs matter for context, and they are not the same thing:

  * wire cost    - the `tools/list` payload a client receives
  * seen cost    - what the model reads in its tool catalog each request

For a directly-mounted server those are equal. For a server behind the lite
proxy they diverge sharply: the proxy holds a large catalog and shows the
model four small meta-tools, so the wire cost measured from the proxy is the
seen cost, not the cost of the catalog it hides.

Config format: dsh reads `$DSH_HOME/cordis.patch.yml` plus
`$DSH_HOME/profiles/<name>/cordis.patch.yml`. The files are YAML patch lists,
but the only structure needed here is `serverName:` and its sibling keys,
so a small reader handles it without a YAML dependency. The core is
stdlib-only by policy (see pyproject: dependencies = []).
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# The proxy shows four meta-tools whatever size the catalog behind it is.
# Measured across gh/rea/xt/glm at 1822-1850 bytes, so this is the observed
# midpoint rather than a guess.
PROXY_META_TOOLS = 4
PROXY_META_BYTES = 1836

# A server whose schema costs less than this cannot benefit from the proxy:
# the proxy's fixed four-tool preamble would cost more than the catalog.
PROXY_BREAK_EVEN_BYTES = PROXY_META_BYTES

_SERVER_RE = re.compile(r"^\s*-?\s*serverName:\s*(\S+)\s*$")
_KEY_RE = re.compile(r"^(\s+)([A-Za-z_][\w-]*):\s*(.*)$")
_LIST_ITEM_RE = re.compile(r"^(\s*)-\s+(.*)$")


@dataclass
class McpServer:
    """One MCP server as the harness will start it."""

    name: str
    profile: str
    config_path: str
    line: int
    transport: str = "stdio"
    command: str | None = None
    args: list[str] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)
    url: str | None = None

    # Populated by a live probe.
    tools: int | None = None
    bytes: int | None = None
    tool_names: list[str] = field(default_factory=list)
    probe_error: str | None = None

    @property
    def proxied(self) -> bool:
        """Whether this server is fronted by the lite proxy.

        Two spellings exist in practice and both mean the same thing:

          * an explicit `LITE_PREFIX` in env (gh, xt)
          * the proxy SCRIPT itself as the command with no prefix at all (rea,
            whose proxy defaults `LITE_PREFIX` to "rea")

        Testing only for `LITE_PREFIX` reported `rea` — the single largest
        catalog in the profile, 229 tools — as a direct mount, which inverted
        its cost: its real seen cost is the proxy's three meta-tools, not the
        273 KB it hides.
        """
        if self.env.get("LITE_PREFIX"):
            return True
        return any("rea_lite" in str(arg) for arg in self.args) or \
            any("lite" in str(arg).lower() and str(arg).endswith(".py") for arg in self.args)

    @property
    def proxy_prefix(self) -> str | None:
        if self.env.get("LITE_PREFIX"):
            return self.env["LITE_PREFIX"]
        # The lite proxy defaults to "rea" when no prefix is declared.
        return "rea" if (self.proxied and "rea_lite" in " ".join(map(str, self.args))) else None

    @property
    def child_command(self) -> str | None:
        """The real server the proxy would spawn (REA_CMD), when proxied."""
        return self.env.get("REA_CMD")

    @property
    def tokens(self) -> int | None:
        """Rough token cost at ~4 bytes per token, matching the repo's convention."""
        return None if self.bytes is None else self.bytes // 4

    def effective_bytes(self) -> int | None:
        """What the model pays for this server in its tool catalog.

        A probed server reports its own wire size. A server not probed falls
        back to the proxy constant when proxied, and is otherwise unknown.
        """
        if self.bytes is not None:
            return self.bytes
        if self.proxied:
            return PROXY_META_BYTES
        return None

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "profile": self.profile,
            "transport": self.transport,
            "command": self.command,
            "args": self.args,
            "url": self.url,
            "proxied": self.proxied,
            "proxyPrefix": self.proxy_prefix,
            "childCommand": self.child_command,
            "tools": self.tools,
            "bytes": self.bytes,
            "tokens": self.tokens,
            "effectiveBytes": self.effective_bytes(),
            "toolNames": self.tool_names,
            "probeError": self.probe_error,
            "configPath": self.config_path,
            "line": self.line,
        }


def dsh_home() -> Path:
    """Resolve the harness home without hardcoding a user path."""
    env = os.environ.get("DSH_HOME")
    if env:
        return Path(env)
    cand = Path.home() / ".dsh"
    if cand.is_dir():
        return cand
    for p in Path.home().parents:
        if p.name == ".dsh" and p.is_dir():
            return p
        if (p / ".dsh").is_dir():
            return p / ".dsh"
    return cand


def active_profile() -> str | None:
    """The profile this process runs under, when the harness declares one."""
    return os.environ.get("DSH_PROFILE") or os.environ.get("DSH_TUI_PROFILE") or None


def config_paths(home: Path | None = None, profile: str | None = None
                 ) -> list[tuple[str, Path]]:
    """Every cordis patch file, as (profile-label, path).

    The root patch applies to every profile and is read first. When `profile`
    is given, only that profile's file is added.
    """
    base = home or dsh_home()
    out: list[tuple[str, Path]] = []
    root = base / "cordis.patch.yml"
    if root.is_file():
        out.append(("*", root))
    profiles_dir = base / "profiles"
    if not profiles_dir.is_dir():
        return out
    wanted = [profile] if profile else sorted(
        p.name for p in profiles_dir.iterdir() if p.is_dir())
    for name in wanted:
        p = profiles_dir / name / "cordis.patch.yml"
        if p.is_file():
            out.append((name, p))
    return out


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip())


def parse_servers(text: str, profile: str, path: str) -> list[McpServer]:
    """Extract MCP servers from one cordis patch file.

    Each `serverName:` starts a record. Keys indented beneath it belong to
    that record until a line at the same or lower indent that is not a list
    continuation ends it.

    Env values are read only from the `env:` block, which keeps an unrelated
    `command:` elsewhere in the file from being attributed to a server.
    """
    lines = text.splitlines()
    servers: list[McpServer] = []
    i = 0
    while i < len(lines):
        m = _SERVER_RE.match(lines[i])
        if not m:
            i += 1
            continue
        server = McpServer(name=m.group(1).strip("'\""), profile=profile,
                           config_path=path, line=i + 1)
        # `serverName` and the keys that describe the server are SIBLINGS in
        # the patch document, indented to the same level:
        #
        #     config:
        #       serverName: github
        #       transport: stdio
        #       command: /usr/bin/python3
        #       env:
        #         LITE_PREFIX: gh
        #
        # So the record's indent level IS the serverName indent; a previous
        # version treated anything at that indent as the end of the record and
        # therefore parsed every server with no command, no args and no env —
        # which silently reported every proxied server as direct and costless.
        base_indent = _indent(lines[i])
        j = i + 1
        while j < len(lines):
            line = lines[j]
            if not line.strip():
                j += 1
                continue
            ind = _indent(line)
            if ind < base_indent:
                break
            if _SERVER_RE.match(line):
                break
            # A list item at or left of the record indent starts the next
            # entry of the enclosing patch list, not another key of this one.
            if ind <= base_indent and _LIST_ITEM_RE.match(line):
                break
            km = _KEY_RE.match(line)
            if km and not _LIST_ITEM_RE.match(line) and len(km.group(1)) == base_indent:
                key, value = km.group(2), km.group(3).strip().strip("'\"")
                if key == "transport":
                    server.transport = value or server.transport
                elif key == "command":
                    server.command = value or None
                elif key == "url":
                    server.url = value or None
                elif key == "args":
                    # args: [] inline, or a block list on following lines.
                    if value.startswith("["):
                        server.args = _split_inline_list(value)
                    else:
                        k = j + 1
                        while k < len(lines):
                            lm = _LIST_ITEM_RE.match(lines[k])
                            if not lm or len(lm.group(1)) <= base_indent:
                                break
                            server.args.append(lm.group(2).strip().strip("'\""))
                            k += 1
                        j = k - 1
                elif key == "env":
                    k = j + 1
                    while k < len(lines):
                        em = _KEY_RE.match(lines[k])
                        if not em or len(em.group(1)) <= base_indent:
                            break
                        server.env[em.group(2)] = em.group(3).strip().strip("'\"")
                        k += 1
                    j = k - 1
            j += 1
        servers.append(server)
        i = j
    return servers


def _split_inline_list(value: str) -> list[str]:
    inner = value.strip()[1:-1].strip()
    if not inner:
        return []
    # Args may themselves be JSON (REA_ARGS), so split on commas outside quotes.
    out: list[str] = []
    buf = ""
    quote: str | None = None
    for ch in inner:
        if quote:
            buf += ch
            if ch == quote:
                quote = None
        elif ch in "\"'":
            quote = ch
            buf += ch
        elif ch == ",":
            out.append(buf.strip().strip("'\""))
            buf = ""
        else:
            buf += ch
    if buf.strip():
        out.append(buf.strip().strip("'\""))
    return out


def inventory(home: Path | None = None, profile: str | None = None
              ) -> dict[str, Any]:
    """All servers across the selected config files, with a cost summary."""
    paths = config_paths(home, profile)
    servers: list[McpServer] = []
    for label, path in paths:
        try:
            text = path.read_text(encoding="utf-8")
        except OSError as exc:
            servers.append(McpServer(name=f"<unreadable: {path}>", profile=label,
                                     config_path=str(path), line=0,
                                     probe_error=f"{type(exc).__name__}: {exc}"))
            continue
        servers.extend(parse_servers(text, label, str(path)))

    # The same name can be declared in several profiles. Keep them all; the
    # caller filters by profile when it cares.
    return {
        "configs": [{"profile": label, "path": str(p)} for label, p in paths],
        "servers": servers,
        "activeProfile": active_profile(),
        "summary": summarise(servers),
    }


def summarise(servers: list[McpServer]) -> dict[str, Any]:
    """Cost totals, separating servers whose size is known from those unprobed."""
    known = [s for s in servers if s.effective_bytes() is not None]
    unknown = [s for s in servers if s.effective_bytes() is None]
    total_bytes = sum(s.effective_bytes() or 0 for s in known)
    proxied = [s for s in servers if s.proxied]
    direct = [s for s in servers if not s.proxied]
    return {
        "servers": len(servers),
        "proxied": len(proxied),
        "direct": len(direct),
        "knownBytes": total_bytes,
        "knownTokens": total_bytes // 4,
        "unmeasured": [s.name for s in unknown],
        "tools": sum(s.tools or 0 for s in servers),
    }


def proxy_advice(server: McpServer) -> dict[str, Any]:
    """Whether putting this server behind the lite proxy would save anything.

    The proxy costs a fixed four meta-tools. A catalog smaller than that is
    made more expensive, not less, which is why the small servers here should
    stay direct and only the large ones are worth fronting.
    """
    size = server.effective_bytes()
    if size is None:
        return {"name": server.name, "verdict": "unknown",
                "reason": "not probed; run `xtforge mcp status --probe` first"}
    if server.proxied:
        return {"name": server.name, "verdict": "already-proxied",
                "savesBytes": 0,
                "reason": f"behind proxy '{server.proxy_prefix}'; "
                          f"{server.tools or PROXY_META_TOOLS} meta-tools visible"}
    delta = size - PROXY_META_BYTES
    if delta <= 0:
        return {"name": server.name, "verdict": "keep-direct",
                "savesBytes": 0,
                "reason": f"{size} B is below the proxy's {PROXY_META_BYTES} B "
                          f"preamble; proxying would cost {-delta} B more"}
    return {"name": server.name, "verdict": "proxy-worthwhile",
            "savesBytes": delta,
            "savesTokens": delta // 4,
            "reason": f"{size} B catalog would become ~{PROXY_META_BYTES} B "
                      f"of meta-tools"}
