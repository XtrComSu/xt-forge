"""Contract tests for native RE analysis and the docs client."""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from xtforge.core import docs as docsmod  # noqa: E402
from xtforge.core.re import native as renative  # noqa: E402

SAMPLE = b"""
PACKET to http://evil.example.org:8080/gate.php
callback 185.199.108.153 and 10.0.0.5
contact admin@malware-test.invalid
sha256 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
see CVE-2024-12345 for details
C:\\Users\\Public\\payload.exe
/etc/cron.d/implant
HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run
endpoint postgres://admin:hunter2@db.internal:5432/app
"""


class TestIoc(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="ioc-")) / "sample.bin"
        self.tmp.write_bytes(SAMPLE)

    def test_extracts_indicator_types(self):
        res = renative.ioc(self.tmp)
        self.assertTrue(res["ok"], res)
        counts = res["counts"]
        self.assertGreaterEqual(counts["ips"], 2)
        self.assertGreaterEqual(counts["urls"], 1)
        self.assertGreaterEqual(counts["emails"], 1)
        self.assertGreaterEqual(counts["hashes"], 1)
        self.assertGreaterEqual(counts["cves"], 1)
        self.assertGreaterEqual(counts["windows_paths"], 1)
        self.assertGreaterEqual(counts["linux_paths"], 1)
        self.assertGreaterEqual(counts["registry_keys"], 1)

    def test_flags_credentials_in_urls(self):
        res = renative.ioc(self.tmp)
        self.assertTrue(res["findings"]["credential_urls"])

    def test_never_prints_the_secret(self):
        """An IOC report must not become a secret store."""
        res = renative.ioc(self.tmp)
        dumped = json.dumps(res)
        self.assertNotIn("hunter2", dumped)
        self.assertIn("***", res["findings"]["credential_urls"][0])

    def test_missing_file_is_an_error(self):
        res = renative.ioc(self.tmp.parent / "nope.bin")
        self.assertFalse(res["ok"])


class TestDisasm(unittest.TestCase):
    def test_parses_instructions(self):
        with tempfile.NamedTemporaryFile(suffix=".py", delete=False) as fh:
            fh.write(b"print('hi')\n")
            path = fh.name
        try:
            res = renative.disasm(path, count=5)
            # A text file is not an ELF: either a parse with zero
            # instructions or an honest error — never a crash.
            self.assertIn("ok", res)
        finally:
            Path(path).unlink()

    def test_real_binary_when_available(self):
        import shutil
        if not shutil.which("objdump"):
            self.skipTest("objdump not installed")
        target = Path("/bin/ls")
        if not target.is_file():
            self.skipTest("no /bin/ls")
        res = renative.disasm(target, count=25)
        self.assertTrue(res["ok"], res)
        self.assertGreater(res["count"], 0)
        self.assertIn("mnemonic_histogram", res)
        first = res["instructions"][0]
        self.assertIn("address", first)
        self.assertIn("mnemonic", first)


class TestGraph(unittest.TestCase):
    def test_graph_reports_structure(self):
        import shutil
        if not shutil.which("nm"):
            self.skipTest("binutils not installed")
        target = Path("/bin/ls")
        if not target.is_file():
            self.skipTest("no /bin/ls")
        res = renative.graph(target)
        self.assertTrue(res["ok"], res)
        self.assertGreater(res["import_count"], 0)
        self.assertGreater(res["call_count"], 0)
        self.assertTrue(res["imports"][0]["symbol"])
        self.assertTrue(res["hot_targets"])

    def test_missing_file_is_an_error(self):
        res = renative.graph("/nonexistent/binary")
        self.assertFalse(res["ok"])


class TestDocsClient(unittest.TestCase):
    def test_search_parses_results(self):
        fake = {"results": [{"settings": {
            "title": "FastAPI", "project": "/websites/fastapi_tiangolo",
            "description": "web framework"}}]}
        with mock.patch.object(docsmod, "_get", return_value=(200, fake)):
            payload = docsmod.search("FastAPI")
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["results"][0]["project"],
                         "/websites/fastapi_tiangolo")

    def test_search_without_query_is_an_error(self):
        self.assertFalse(docsmod.search("  ")["ok"])

    def test_resolve_picks_the_best(self):
        fake = {"results": [
            {"settings": {"title": "A", "project": "/a/b"}},
            {"settings": {"title": "B", "project": "/c/d"}}]}
        with mock.patch.object(docsmod, "_get", return_value=(200, fake)):
            payload = docsmod.resolve("A")
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["project"], "/a/b")
        self.assertEqual(len(payload["alternatives"]), 1)

    def test_show_returns_docs(self):
        with mock.patch.object(docsmod, "_get",
                               return_value=(200, "### Docs\nbody")):
            payload = docsmod.show("websites/fastapi_tiangolo", topic="Depends")
        self.assertTrue(payload["ok"])
        self.assertIn("Docs", payload["docs"])

    def test_show_handles_http_errors(self):
        with mock.patch.object(docsmod, "_get", return_value=(404, "nope")):
            payload = docsmod.show("websites/nothing")
        self.assertFalse(payload["ok"])

    def test_never_sends_without_a_project(self):
        self.assertFalse(docsmod.show("")["ok"])


class TestCliWiring(unittest.TestCase):
    def test_new_verbs_are_registered(self):
        from xtforge.cli import build_parser
        parser = build_parser()
        for argv, attr in ((["docs", "search", "x"], "docs_verb"),
                           (["re", "ioc", "/bin/ls"], "re_verb"),
                           (["re", "disasm", "/bin/ls"], "re_verb"),
                           (["re", "graph", "/bin/ls"], "re_verb")):
            args = parser.parse_args(argv)
            self.assertTrue(getattr(args, attr, None))

    def test_mcp_surface_unchanged(self):
        """Docs and native RE are CLI-first: no schema cost on every step."""
        server = (ROOT / "adapters" / "mcp" / "server.py").read_text()
        self.assertNotIn('"docs_search"', server)
        self.assertNotIn('"re_ioc"', server)


if __name__ == "__main__":
    unittest.main()
