#!/usr/bin/env python3
"""Capture the README examples using a compiled fixture, sample manifests, and MCP."""
import json
import os
from pathlib import Path
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[1]
ASSETS = ROOT / "docs" / "assets" / "release-review"


def main() -> None:
    ASSETS.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="xtforge-demo-") as temp:
        project = Path(temp)

        # 1. Binary Fixture
        (project / "demo.c").write_text(
            "int increment(int n) { return n + 1; }\n"
            "int main(void) { return increment(4); }\n",
            encoding="utf-8",
        )
        subprocess.run(["cc", "-g", "-O0", "demo.c", "-o", "demo"], cwd=project, check=True)

        # 2. Dependency & Vulnerability Fixture
        manifest = "module example.com/demo\n\ngo 1.21\n\nrequire example.com/library v1.2.3\n"
        (project / "go.mod").write_text(manifest, encoding="utf-8")
        (ASSETS / "manifest.txt").write_text(manifest, encoding="utf-8")

        reqs = "requests==2.25.0\nurllib3==1.26.4\n"
        (project / "requirements.txt").write_text(reqs, encoding="utf-8")

        # 3. Source Navigation Fixture
        (project / "service.py").write_text(
            '"""API dispatch and security verification service."""\n\n'
            'def authenticate(token: str) -> bool:\n'
            '    """Verify API bearer credentials."""\n'
            '    return bool(token and token.startswith("Bearer xt-"))\n\n'
            'def dispatch_request(route: str, token: str):\n'
            '    """Route authorized API requests to handlers."""\n'
            '    if not authenticate(token):\n'
            '        raise PermissionError("Invalid API token")\n'
            '    return {"status": "ok", "route": route}\n\n'
            'def handle_client_call():\n'
            '    return dispatch_request("/v1/scan", "Bearer xt-live")\n',
            encoding="utf-8",
        )

        env = {
            **os.environ,
            "XT_HOME": str(project / "state"),
            "XT_FORCE_PYTHON": "1",
            "XT_ROOT": str(ROOT),
        }

        # Native and Dependency captures
        re_captures = {
            "overview": ["re", "overview", "./demo", "--json"],
            "disassembly": ["re", "disasm-native", "./demo", "--target", "main", "--flow"],
            "references": ["re", "xrefs-native", "./demo", "--target", "increment", "--json"],
            "dependencies": ["re", "deps", ".", "--json"],
            "remediation": ["re", "remediate", ".", "--json"],
        }
        for name, args in re_captures.items():
            output = subprocess.check_output(
                [str(ROOT / "bin" / "xtforge"), *args],
                cwd=project,
                env=env,
                text=True,
            )
            output = output.replace(f"{project}/", "./").replace(str(project), ".")
            (ASSETS / f"{name}.txt").write_text(
                "$ xt-forge " + " ".join(args) + "\n" + output, encoding="utf-8",
            )

        # Source Navigation captures
        source_captures = {
            "source_context": ["route", "context", ".", "--query", "authenticate dispatch token", "--json"],
            "source_callers": ["code", "callers", "authenticate", ".", "--json"],
            "source_trace": ["code", "trace", "dispatch_request", ".", "--json"],
        }
        for name, args in source_captures.items():
            output = subprocess.check_output(
                [str(ROOT / "bin" / "xtforge"), *args],
                cwd=project,
                env=env,
                text=True,
            )
            output = output.replace(f"{project}/", "./").replace(str(project), ".")
            (ASSETS / f"{name}.txt").write_text(
                "$ xt-forge " + " ".join(args) + "\n" + output, encoding="utf-8",
            )

        # 4. MCP Gateway captures
        proc = subprocess.Popen(
            [str(ROOT / "bin" / "xtforge"), "--meta"],
            cwd=project,
            env=env,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        reqs_mcp = [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"capabilities": {}}},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "xt_discover", "arguments": {"query": "binary"}}},
            {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "xt_call", "arguments": {"name": "re_overview", "arguments": {"path": "./demo"}}}},
        ]
        mcp_stdout, _ = proc.communicate(input="\n".join(json.dumps(r) for r in reqs_mcp) + "\n", timeout=15)
        mcp_lines = [line.strip() for line in mcp_stdout.strip().splitlines() if line.strip()]

        if len(mcp_lines) >= 3:
            init_res = json.loads(mcp_lines[0])
            disc_res = json.loads(mcp_lines[1])
            call_res = json.loads(mcp_lines[2])

            (ASSETS / "mcp_init.txt").write_text(
                "$ xt-forge --meta\n" + json.dumps(init_res, indent=2), encoding="utf-8"
            )
            (ASSETS / "mcp_discover.txt").write_text(
                "$ xt_discover --query binary\n" + disc_res["result"]["content"][0]["text"], encoding="utf-8"
            )
            (ASSETS / "mcp_call.txt").write_text(
                '$ xt_call --name re_overview --path ./demo\n' + call_res["result"]["content"][0]["text"].replace(f"{project}/", "./").replace(str(project), "."), encoding="utf-8"
            )


if __name__ == "__main__":
    main()
