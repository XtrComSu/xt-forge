"""Priority 5: End-to-end verification of shipped packages and public entrypoints."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import tomllib
import unittest
import zipfile
import tarfile
import re
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
        # Force the real toolchain homes. Inheriting an isolated CARGO_HOME (for example a
        # scratch directory used by an outer harness) turns the installer's dependency build
        # into a from-scratch rebuild, which cannot meet the subprocess budget below.
        if (real_home / ".cargo").is_dir():
            self.env["CARGO_HOME"] = str(real_home / ".cargo")
        if (real_home / ".rustup").is_dir():
            self.env["RUSTUP_HOME"] = str(real_home / ".rustup")
        if (real_home / "go").is_dir():
            self.env["GOPATH"] = str(real_home / "go")
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

        dependency_project = self.fake_home / "dependency-demo"
        dependency_project.mkdir()
        inventory = dependency_project / "go.mod"
        inventory.write_text("module example.com/demo\n\ngo 1.21\n\n"
                             "require example.com/library v1.2.3\n", encoding="utf-8")
        deps = subprocess.run(
            [str(xtforge_bin), "re", "deps", str(dependency_project), "--json"],
            env=self.env, text=True, capture_output=True, timeout=15,
        )
        self.assertEqual(deps.returncode, 0, deps.stderr)
        self.assertEqual(json.loads(deps.stdout)["dependencies"][0]["version"], "1.2.3")

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
            self.assertEqual(json.loads(sk.stdout)["count"], 26)

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
            # A cold Rust build of the release target takes ~110s on a modest machine, so the
            # budget must cover that path; the installer skips the build once artifacts are fresh.
            timeout=600,
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


class TestReleaseArchiveContents(unittest.TestCase):
    """Release integrity: archive contents must match what the filename advertises."""

    DIST_DIR = ROOT / "dist"
    PLATFORM_RE = re.compile(
        r"(?:linux|darwin|macos|osx|windows|win32|win64)"
        r"-(?:x86_64|amd64|arm64|aarch64|x86|i386|i686)",
        re.IGNORECASE,
    )
    SOURCE_STEM_RE = re.compile(r"^xt[_-]forge-\d[\w.]*$", re.IGNORECASE)
    LAUNCHERS = ("bin/xtforge", "bin/xtforge.cmd")
    NATIVE_SUFFIXES = (
        "xtforge-native", "xtforge-native.exe",
        "xtforge-hub", "xtforge-hub.exe",
    )

    def setUp(self) -> None:
        if not self.DIST_DIR.is_dir():
            self.skipTest(f"no dist/ directory at {self.DIST_DIR}")
        self.archives = sorted(
            p for p in self.DIST_DIR.iterdir()
            if p.is_file()
            and (p.name.endswith(".tar.gz") or p.name.endswith(".zip"))
            and (p.name.startswith("xt-forge-") or p.name.startswith("xt_forge-"))
        )

    @staticmethod
    def _stem(archive: Path) -> str:
        for suffix in (".tar.gz", ".zip"):
            if archive.name.endswith(suffix):
                return archive.name[:-len(suffix)]
        return archive.name

    @classmethod
    def _classify(cls, archive: Path) -> str | None:
        stem = cls._stem(archive)
        if cls.PLATFORM_RE.search(stem):
            return "native"
        if cls.SOURCE_STEM_RE.fullmatch(stem):
            return "source"
        return None

    def _of_kind(self, kind: str) -> list[Path]:
        return [a for a in self.archives if self._classify(a) == kind]

    @staticmethod
    def _entry_names(archive: Path) -> list[str]:
        # List names only; never extract the archive to disk.
        if archive.name.endswith(".zip"):
            with zipfile.ZipFile(archive) as zf:
                return zf.namelist()
        with tarfile.open(archive, "r:gz") as tf:
            return tf.getnames()

    def test_every_release_archive_is_accounted_for(self) -> None:
        unclassified = [a.name for a in self.archives if self._classify(a) is None]
        self.assertEqual(
            [], unclassified,
            f"unclassified release archive(s) in {self.DIST_DIR}: "
            + ", ".join(unclassified)
            + " (expected a platform triple for a native archive or a version-only source archive)",
        )

    def test_native_archives_declare_their_natives(self) -> None:
        # DEFECT FIXED, 2026-11-23. It was recorded here as an expected failure against the
        # 0.4.6 artifacts:
        #   xt-forge-0.4.6-darwin-arm64.tar.gz  541 entries, no native executable
        #   xt-forge-0.4.6-windows-x86_64.zip   222 entries, no .exe at all
        #   xt-forge-0.4.6-linux-x86_64.tar.gz  had BOTH xtforge-native and xtforge-hub
        # macOS and Windows users got a Python-only payload while the launchers advertised
        # native executables. `scripts/build_release.py` now produces the archives and every
        # platform bundle carries one; running the suite after rebuilding reported
        # "unexpected success", which was the signal to delete the decorator — exactly as
        # the note here said it would be. The 0.4.6 artifacts are kept under
        # dist/superseded-0.4.6/ as the evidence of what was wrong.
        problems: list[str] = []
        for archive in self._of_kind("native"):
            names = self._entry_names(archive)
            has_launcher = any(
                name == launcher or name.endswith("/" + launcher)
                for name in names for launcher in self.LAUNCHERS
            )
            has_native = any(
                name.endswith(suffix)
                for name in names for suffix in self.NATIVE_SUFFIXES
            )
            if not has_launcher:
                problems.append(
                    f"{archive.name}: missing launcher entry (bin/xtforge or bin/xtforge.cmd)"
                )
            if not has_native:
                problems.append(
                    f"{archive.name}: missing native executable (one of "
                    + ", ".join(self.NATIVE_SUFFIXES) + ")"
                )
        self.assertEqual(
            [], problems,
            "platform-named archives are missing their advertised executables:\n"
            + "\n".join(problems),
        )

    def test_source_archives_are_marked_source_only(self) -> None:
        problems: list[str] = []
        for archive in self._of_kind("source"):
            names = self._entry_names(archive)
            if not any(
                name == "pyproject.toml" or name.endswith("/pyproject.toml")
                for name in names
            ):
                problems.append(f"{archive.name}: missing pyproject.toml")
        self.assertEqual(
            [], problems,
            "source archives must contain pyproject.toml:\n" + "\n".join(problems),
        )


if __name__ == "__main__":
    unittest.main()
