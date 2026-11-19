"""Priority 5: End-to-end verification of shipped packages and public entrypoints."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import tomllib
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _copy_mini_project(dst_home: Path) -> Path:
    proj = dst_home / "mini_project"
    shutil.copytree(ROOT / "tests" / "fixtures" / "mini_project", proj)
    return proj


def _mcp_handshake(cmd: list[str], env: dict[str, str]) -> tuple[dict, dict]:
    reqs = "\n".join([
        json.dumps({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"protocolVersion": "2025-03-26", "capabilities": {}, "clientInfo": {"name": "pkg-test", "version": "1"}},
        }),
        json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}),
    ]) + "\n"
    proc = subprocess.run(cmd, input=reqs, env=env, text=True, capture_output=True, timeout=20)
    if proc.returncode != 0:
        raise AssertionError(f"MCP command failed ({proc.returncode}): {cmd}\nstderr={proc.stderr}\nstdout={proc.stdout}")
    lines = [json.loads(line) for line in proc.stdout.splitlines() if line.strip()]
    if len(lines) < 2:
        raise AssertionError(f"expected 2 JSON-RPC replies, got {len(lines)}: {proc.stdout}")
    return lines[0], lines[1]


class TestShippedPackages(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="xt_shipped_"))
        self.fake_home = self.tmp / "home"
        self.fake_home.mkdir(parents=True, exist_ok=True)
        self.proj = _copy_mini_project(self.fake_home)
        self.env = os.environ.copy()
        real_home = Path.home()
        if (real_home / ".cargo").is_dir():
            self.env.setdefault("CARGO_HOME", str(real_home / ".cargo"))
        if (real_home / ".rustup").is_dir():
            self.env.setdefault("RUSTUP_HOME", str(real_home / ".rustup"))
        if (real_home / "go").is_dir():
            self.env.setdefault("GOPATH", str(real_home / "go"))
        self.env["HOME"] = str(self.fake_home)
        self.env["XT_HOME"] = str(self.fake_home / ".xt-forge")
        self.env.pop("PYTHONPATH", None)

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_packaging_manifests_entrypoint_contract(self) -> None:
        pyproj = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
        npm_pkg = json.loads((ROOT / "package.json").read_text(encoding="utf-8"))

        py_scripts = set(pyproj["project"]["scripts"].keys())
        npm_bins = set(npm_pkg["bin"].keys())
        self.assertEqual(py_scripts, {"xtforge"})
        self.assertEqual(npm_bins, {"xt-forge", "xtf"})
        self.assertEqual(pyproj["project"]["version"], npm_pkg["version"])

        # Windows PowerShell installer parity checks (syntax & required shims).
        ps1 = (ROOT / "install.ps1").read_text(encoding="utf-8")
        for needle in ("xt-forge.cmd", "xtforge.cmd", "xtf.cmd", "xtforge-hub.exe", "npx-xtforge.mjs"):
            self.assertIn(needle, ps1)
        self.assertEqual(ps1.count("{"), ps1.count("}"))

    @unittest.skipUnless(shutil.which("uv"), "uv required to test Python wheel install cleanly")
    def test_python_package_install_upgrade_and_commands(self) -> None:
        venv = self.tmp / "py_venv"
        subprocess.run(["uv", "venv", str(venv)], check=True, capture_output=True, text=True)
        py_bin = venv / "bin" / "python"
        subprocess.run(["uv", "pip", "install", "--python", str(py_bin), str(ROOT)], check=True, capture_output=True, text=True)

        xtforge_bin = venv / "bin" / "xtforge"
        self.assertTrue(xtforge_bin.is_file())
        self.assertFalse((venv / "bin" / "xt-forge").exists())
        self.assertFalse((venv / "bin" / "xtf").exists())

        ver = subprocess.run([str(xtforge_bin), "--version"], env=self.env, text=True, capture_output=True, timeout=10)
        self.assertEqual(ver.returncode, 0, ver.stderr)
        self.assertIn("xt-forge", ver.stdout)

        doc = subprocess.run([str(xtforge_bin), "doctor", "--json"], env=self.env, text=True, capture_output=True, timeout=15)
        self.assertEqual(doc.returncode, 0, doc.stderr)
        doc_json = json.loads(doc.stdout)
        self.assertIsNone(doc_json["native"]["native_dir"])

        init_r, list_r = _mcp_handshake([str(xtforge_bin), "mcp", "serve", "--meta"], self.env)
        self.assertNotEqual(init_r["result"]["serverInfo"]["version"], "0.0.0")
        self.assertEqual(len(list_r["result"]["tools"]), 4)

        q = subprocess.run(
            [str(xtforge_bin), "route", "context", str(self.proj), "--query", "how is the retry delay calculated", "--json"],
            env=self.env, text=True, capture_output=True, timeout=15,
        )
        self.assertEqual(q.returncode, 0, q.stderr)
        self.assertIn("BASE_DELAY", json.loads(q.stdout)["data"]["context"])

        # Upgrade/reinstall idempotency check.
        subprocess.run(
            ["uv", "pip", "install", "--reinstall", "--python", str(py_bin), str(ROOT)],
            check=True, capture_output=True, text=True,
        )
        ver2 = subprocess.run([str(xtforge_bin), "--version"], env=self.env, text=True, capture_output=True, timeout=10)
        self.assertEqual(ver2.returncode, 0, ver2.stderr)

    @unittest.skipUnless(shutil.which("npm") and shutil.which("node"), "npm/node required to test npm tarball install")
    def test_npm_package_install_upgrade_and_commands(self) -> None:
        pack_dir = self.tmp / "pack"
        pack_dir.mkdir(parents=True, exist_ok=True)
        pack = subprocess.run(["npm", "pack", str(ROOT)], cwd=str(pack_dir), check=True, text=True, capture_output=True)
        tgz = pack_dir / pack.stdout.strip().splitlines()[-1]
        self.assertTrue(tgz.is_file())

        prefix = self.tmp / "npm_prefix"
        prefix.mkdir(parents=True, exist_ok=True)
        subprocess.run(
            ["npm", "install", "--no-audit", "--no-fund", "--prefix", str(prefix), str(tgz)],
            check=True, capture_output=True, text=True,
        )
        bin_dir = prefix / "node_modules" / ".bin"
        self.assertTrue((bin_dir / "xt-forge").exists())
        self.assertTrue((bin_dir / "xtf").exists())
        self.assertFalse((bin_dir / "xtforge").exists())

        for bname in ("xt-forge", "xtf"):
            bpath = str(bin_dir / bname)
            doc = subprocess.run([bpath, "doctor", "--json"], env=self.env, text=True, capture_output=True, timeout=15)
            self.assertEqual(doc.returncode, 0, doc.stderr)
            sk = subprocess.run([bpath, "skills", "list", "--json"], env=self.env, text=True, capture_output=True, timeout=15)
            self.assertEqual(sk.returncode, 0, sk.stderr)
            self.assertEqual(json.loads(sk.stdout)["count"], 24)

            init_r, list_r = _mcp_handshake([bpath, "mcp", "serve", "--meta"], self.env)
            self.assertIn("xt-forge", init_r["result"]["serverInfo"]["name"])
            self.assertEqual(len(list_r["result"]["tools"]), 4)

            q = subprocess.run(
                [bpath, "route", "context", str(self.proj), "--query", "how many database connections are opened", "--json"],
                env=self.env, text=True, capture_output=True, timeout=15,
            )
            self.assertEqual(q.returncode, 0, q.stderr)
            self.assertIn("POOL_SIZE = 4", json.loads(q.stdout)["data"]["context"])

        # Upgrade/reinstall idempotency check.
        subprocess.run(
            ["npm", "install", "--no-audit", "--no-fund", "--force", "--prefix", str(prefix), str(tgz)],
            check=True, capture_output=True, text=True,
        )

    @unittest.skipUnless(shutil.which("bash"), "bash required to verify install.sh")
    def test_unix_installer_links_and_queries(self) -> None:
        syntax = subprocess.run(["bash", "-n", str(ROOT / "install.sh")], text=True, capture_output=True)
        self.assertEqual(syntax.returncode, 0, syntax.stderr)

        inst = subprocess.run(
            ["bash", str(ROOT / "install.sh")],
            cwd=str(ROOT),
            env=self.env,
            text=True,
            capture_output=True,
            timeout=120,
        )
        self.assertEqual(inst.returncode, 0, inst.stderr + inst.stdout)
        local_bin = self.fake_home / ".local" / "bin"
        for alias in ("xt-forge", "xtforge", "xtf"):
            self.assertTrue((local_bin / alias).exists(), f"missing {alias} in {local_bin}")

        # Verify installed skills & command query via installed symlink.
        self.assertGreaterEqual(len(list((self.fake_home / ".agents" / "skills").glob("XTF-*"))), 18)
        init_r, list_r = _mcp_handshake([str(local_bin / "xt-forge"), "mcp", "serve", "--meta"], self.env)
        self.assertEqual(len(list_r["result"]["tools"]), 4)
        q = subprocess.run(
            [str(local_bin / "xtf"), "route", "context", str(self.proj), "--query", "what order are jobs dequeued in", "--json"],
            env=self.env, text=True, capture_output=True, timeout=15,
        )
        self.assertEqual(q.returncode, 0, q.stderr)
        self.assertIn("ORDER BY priority DESC, id LIMIT 1", json.loads(q.stdout)["data"]["context"])


if __name__ == "__main__":
    unittest.main()
