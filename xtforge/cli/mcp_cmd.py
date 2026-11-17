"""`xtforge mcp` — what the harness actually mounts, and what it costs.

The inventory module (`xtforge.core.mcp`) answers "which MCP servers are
declared, in which profile, and how expensive is each one". This command is the
only thing a person types, so it stays small and honest:

    status            every declared server, its transport, and its cost
    advice            whether proxying each one would save anything
    configs           just the cordis files that were read

Two deliberate abstentions:

  * There is no `probe` verb. Measuring a server's real `tools/list` payload
    means starting it (a process, an API key, sometimes a network call), so it
    is not something a status command may do silently. `--probe` on `status`
    is the opt-in, and it starts only the servers selected.
  * Unknown cost is reported as unknown, never as zero. A server nobody
    measured has no number, which is why the summary counts it separately
    instead of quietly folding it into the total.
"""

from __future__ import annotations

from typing import Any

from ..core.mcp import inventory, proxy_advice, summarise
from .common import _out


def _fmt_bytes(value: int | None) -> str:
    if value is None:
        return "—"
    if value >= 1024 * 1024:
        return f"{value / (1024 * 1024):.1f} MB"
    if value >= 1024:
        return f"{value / 1024:.1f} KB"
    return f"{value} B"


def _table(rows: list[dict[str, Any]]) -> str:
    """Fixed-width table; every column is left-aligned and never truncated."""
    headers = ("SERVER", "PROFILE", "TRANSPORT", "PROXY", "TOOLS", "COST")
    body = [
        (
            str(row["name"]),
            str(row["profile"]),
            str(row["transport"]),
            str(row.get("proxyPrefix") or "direct"),
            "—" if row.get("tools") is None else str(row["tools"]),
            _fmt_bytes(row.get("effectiveBytes")),
        )
        for row in rows
    ]
    widths = [
        max(len(headers[i]), max((len(r[i]) for r in body), default=0))
        for i in range(len(headers))
    ]
    lines = ["  ".join(h.ljust(widths[i]) for i, h in enumerate(headers)).rstrip()]
    lines.append("  ".join("-" * w for w in widths))
    for r in body:
        lines.append("  ".join(c.ljust(widths[i]) for i, c in enumerate(r)).rstrip())
    return "\n".join(lines)


def _maybe_probe(args, servers) -> None:
    """Run the opt-in probe, if asked for.

    Starting MCP servers is a side effect — processes, sometimes network, and
    on a metered server a bill — so it only ever happens behind an explicit
    flag, and both verbs that can use a measurement go through here rather than
    each growing its own copy.
    """
    if not getattr(args, "probe", False):
        return
    from ..core.mcp_probe import probe_servers

    probe_servers(servers, timeout=getattr(args, "timeout", 20.0))


def cmd_mcp(args) -> int:
    verb = getattr(args, "mcp_verb", "status")
    if verb == "serve":
        import subprocess, sys
        argv = [sys.executable, "-m", "adapters.mcp.server"]
        if getattr(args, "meta", False):
            argv.append("--meta")
        return subprocess.run(argv).returncode
    if verb == "audit":
        from ..core import mcp_proxy as proxymod
        cmd = getattr(args, "cmd", None)
        if not cmd:
            return _out(args, {"ok": False, "err": "mcp audit requires --cmd"}, "error: mcp audit requires --cmd", code=2)
        rep = proxymod.audit_child_server(
            getattr(args, "server", None) or "child",
            cmd,
            trust_on_first=bool(getattr(args, "trust_on_first", False)),
        )
        return _out(args, rep, f"audit ok={rep['ok']} rug_pull={rep.get('rug_pull')} findings={len(rep.get('findings', []))}",
                    code=0 if rep.get("ok") else 1)
    if verb == "proxy":
        from ..core import mcp_proxy as proxymod
        cmd = getattr(args, "cmd", None)
        if not cmd:
            return _out(args, {"ok": False, "err": "mcp proxy requires --cmd"}, "error: mcp proxy requires --cmd", code=2)
        return proxymod.serve_proxy_lite(
            getattr(args, "server", None) or "child",
            cmd,
            trust_on_first=bool(getattr(args, "trust_on_first", False)),
        )
    if verb == "trust":
        from ..core import mcp_audit as auditmod
        from ..core import mcp_proxy as proxymod
        srv = getattr(args, "server", None)
        cmd = getattr(args, "cmd", None)
        if srv and cmd:
            tools, err = proxymod.probe_child_tools(cmd)
            if err:
                return _out(args, {"ok": False, "err": err}, err, code=1)
            res = auditmod.pin_trust(srv, tools, note="pinned via cli")
            return _out(args, res, f"pinned {srv} ({res['tool_count']} tools) sha256={res['sha256'][:16]}")
        db = auditmod.load_trust()
        return _out(args, {"ok": True, **db}, f"trusted servers: {len(db.get('servers', {}))}")

    try:
        report = inventory(profile=getattr(args, "profile", None))
    except Exception as exc:  # noqa: BLE001 - a config read must not traceback
        return _out(args, {"ok": False, "error": f"{type(exc).__name__}: {exc}"})

    servers = report["servers"]

    if verb == "configs":
        return _out(args, {
            "ok": True,
            "activeProfile": report["activeProfile"],
            "configs": report["configs"],
        })

    if verb == "advice":
        # Advice about a size that was never measured is only a guess, so the
        # same opt-in probe is available here: without it the verdict is
        # "unknown", and with it the numbers are the server's own.
        _maybe_probe(args, servers)
        rows = [proxy_advice(server) for server in servers]
        payload = {
            "ok": True,
            "advice": rows,
            "worthwhile": [r["name"] for r in rows
                           if r["verdict"] == "proxy-worthwhile"],
            "totalSavesBytes": sum(r.get("savesBytes") or 0 for r in rows),
        }
        if getattr(args, "json", False):
            return _out(args, payload)
        lines = []
        for row in rows:
            lines.append(f"{row['name']:<24} {row['verdict']:<18} {row['reason']}")
        worthwhile = payload["worthwhile"]
        lines.append("")
        lines.append(
            "no server would benefit from the proxy"
            if not worthwhile
            else "proxy worthwhile for: " + ", ".join(worthwhile)
        )
        print("\n".join(lines))
        return 0

    # status
    _maybe_probe(args, servers)

    summary = summarise(servers)
    payload = {
        "ok": True,
        "activeProfile": report["activeProfile"],
        "servers": [s.as_dict() for s in servers],
        "summary": summary,
    }
    if getattr(args, "json", False):
        return _out(args, payload)

    if not servers:
        print("no MCP servers declared in any cordis patch file")
        return 0

    print(_table(payload["servers"]))
    print()
    print(f"{summary['servers']} servers "
          f"({summary['proxied']} proxied, {summary['direct']} direct); "
          f"{summary['tools']} tools visible; "
          f"known catalog cost {_fmt_bytes(summary['knownBytes'])} "
          f"(~{summary['knownTokens']} tokens)")
    if summary["unmeasured"]:
        print(f"unmeasured (run `xtforge mcp status --probe`): "
              f"{', '.join(summary['unmeasured'])}")
    return 0
