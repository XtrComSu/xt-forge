"""Parity contracts for native Rust (`xtforge-native`) and Go (`xtforge-hub`) engines."""
from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "bin" / "xtforge"
NATIVE_RS = ROOT / "native" / "xtforge-rs" / "target" / "release" / "xtforge-native"
NATIVE_GO = ROOT / "native" / "xtforge-go" / "xtforge-hub"


def _run(*args: str, env_extra: dict[str, str] | None = None, input_data: str | None = None) -> subprocess.CompletedProcess[str]:
    env = dict(os.environ)
    env.pop("XT_FORCE_PYTHON", None)
    if env_extra:
        env.update(env_extra)
    return subprocess.run(
        [str(BIN), *args],
        cwd=str(ROOT),
        env=env,
        input=input_data,
        capture_output=True,
        text=True,
        timeout=30,
    )


@unittest.skipUnless(NATIVE_RS.is_file() and NATIVE_GO.is_file(), "native Rust/Go binaries not built")
class TestNativeRustGoParity(unittest.TestCase):
    def test_intel_sources_runs_in_go(self):
        r = _run("intel", "sources", "--json")
        self.assertEqual(r.returncode, 0, r.stderr)
        data = json.loads(r.stdout)
        self.assertTrue(data["ok"])
        self.assertEqual(data.get("engine"), "go")
        self.assertEqual(data.get("count"), 9)
        self.assertIn("nvd", data.get("active", []))

    def test_re_checksec_and_capa_run_in_go(self):
        target = "/bin/ls" if Path("/bin/ls").exists() else str(NATIVE_RS)
        rc = _run("re", "checksec", target, "--json")
        self.assertEqual(rc.returncode, 0, rc.stderr)
        dc = json.loads(rc.stdout)
        self.assertTrue(dc["ok"])
        self.assertEqual(dc.get("engine"), "go")
        for key in ("nx", "pie", "canary", "relro"):
            self.assertIn(key, dc.get("mitigations", {}))

        rp = _run("re", "capa", target, "--json")
        self.assertEqual(rp.returncode, 0, rp.stderr)
        dp = json.loads(rp.stdout)
        self.assertTrue(dp["ok"])
        self.assertEqual(dp.get("engine"), "go")
        self.assertIsInstance(dp.get("capabilities"), list)

    def test_scan_secrets_and_patterns_run_in_rust(self):
        leak = str(ROOT / "tests" / "fixtures" / "secret_hunt" / "leak.py")
        r = _run("scan", "secrets", leak, "--json")
        self.assertEqual(r.returncode, 0, r.stderr)
        d = json.loads(r.stdout)
        self.assertTrue(d["ok"])
        self.assertEqual(d.get("engine"), "rust")
        self.assertTrue(d.get("masked"))
        rules = {item["rule"] for item in d["findings"]}
        self.assertIn("aws_access_key", rules)
        self.assertIn("github_token", rules)

        risky = str(ROOT / "tests" / "fixtures" / "secret_hunt" / "risky.py")
        rp = _run("scan", "patterns", risky, "--json")
        self.assertEqual(rp.returncode, 0, rp.stderr)
        dp = json.loads(rp.stdout)
        self.assertEqual(dp.get("engine"), "rust")
        prules = {item["rule"] for item in dp["findings"]}
        self.assertIn("yaml_unsafe_load", prules)
        self.assertIn("shell_true", prules)

    def test_route_context_symbols_runs_in_rust(self):
        with tempfile.TemporaryDirectory() as td:
            r = _run(
                "route", "context", "xtforge/core/route",
                "--query", "route_context", "--symbols", "--json",
                env_extra={"XT_HOME": td},
            )
            self.assertEqual(r.returncode, 0, r.stderr)
            d = json.loads(r.stdout)
            self.assertTrue(d["ok"], d)
            self.assertIn("symbol_graph_hits", d["data"])
            self.assertGreater(d["data"]["matches"], 0)

    def test_codec_runs_in_rust(self):
        r1 = _run("codec", "hash", "--algo", "sha256", "hello", "--json")
        self.assertEqual(r1.returncode, 0, r1.stderr)
        d1 = json.loads(r1.stdout)
        self.assertEqual(
            d1["digest"],
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
        )
        r2 = _run("codec", "encode", "--scheme", "base64", "xt-forge", "--json")
        self.assertEqual(r2.returncode, 0, r2.stderr)
        self.assertEqual(json.loads(r2.stdout)["output"], "eHQtZm9yZ2U")

        r3 = _run("codec", "entropy", "--block", "8", "0123456789abcdef0123456789abcdef", "--json")
        self.assertEqual(r3.returncode, 0, r3.stderr)
        d3 = json.loads(r3.stdout)
        self.assertIn("blocks", d3)
        self.assertGreater(d3["entropy"], 3.0)

    def test_meta_gateway_shortcut(self):
        req = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}) + "\n"
        r = _run("--meta", input_data=req)
        self.assertEqual(r.returncode, 0, r.stderr)
        resp = json.loads(r.stdout.strip().splitlines()[0])
        names = [t["name"] for t in resp["result"]["tools"]]
        self.assertEqual(names, ["xt_discover", "xt_schema", "xt_call", "xt_batch"])


if __name__ == "__main__":
    unittest.main()
