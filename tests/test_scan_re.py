"""Contract tests for round 6: static safety scan, ELF inspection, guard roots.

Run: python3 -m unittest discover -s tests -v
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from xtforge.core import scan as scanmod  # noqa: E402
from xtforge.core.re import elf  # noqa: E402
from xtforge.core.route import guard  # noqa: E402

FIXTURE = ROOT / "tests" / "fixtures" / "secret_hunt"
EXPECTED = json.loads((FIXTURE / "expected.json").read_text(encoding="utf-8"))


def find_elf() -> Path | None:
    for candidate in ("/bin/ls", "/usr/bin/ls", "/usr/bin/python3",
                      "/bin/busybox", sys.executable):
        path = Path(candidate)
        if path.is_file():
            try:
                if path.read_bytes()[:4] == b"\x7fELF":
                    return path
            except OSError:
                continue
    return None


class TestSecretScan(unittest.TestCase):
    def test_every_planted_secret_is_found(self):
        result = scanmod.scan_file(FIXTURE / EXPECTED["leak_file"], mode="secrets")
        found = {item["rule"] for item in result["findings"]}
        missing = sorted(set(EXPECTED["must_find_rules"]) - found)
        self.assertEqual(missing, [], f"false negatives: {missing}")

    def test_decoy_file_is_clean(self):
        result = scanmod.scan_file(FIXTURE / EXPECTED["decoy_file"], mode="secrets")
        self.assertEqual(result["count"], 0, result["findings"])

    def test_values_are_masked_by_default(self):
        result = scanmod.scan_file(FIXTURE / EXPECTED["leak_file"])
        for item in result["findings"]:
            self.assertTrue(item["masked"], item["rule"])
            self.assertNotIn("AKIAIOSFODNN7EXAMPLE", item["value"])
            self.assertLess(len(item["value"]), 24)

    def test_reveal_prints_the_value(self):
        result = scanmod.scan_file(FIXTURE / EXPECTED["leak_file"], reveal=True)
        values = [item["value"] for item in result["findings"]]
        self.assertTrue(any(v.startswith("AKIA") and len(v) >= 20 for v in values))
        self.assertTrue(all(not item["masked"] for item in result["findings"]))

    def test_secret_split_across_string_literals_is_found(self):
        text = ('TOKEN = (\n'
                '    "ghp_1234567890abc"\n'
                '    "defghijklmnopqrstuvwxyz012345"\n'
                ')\n')
        result = scanmod.scan_text(text, path="mem.py")
        rules = {item["rule"] for item in result["findings"]}
        self.assertIn("github_token", rules)

    def test_high_entropy_catch_all(self):
        text = 'KEY = "9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e"\n'
        result = scanmod.scan_text(text)
        self.assertIn("high_entropy",
                      {item["rule"] for item in result["findings"]})

    def test_low_entropy_is_not_reported(self):
        text = 'NAME = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"\n'
        result = scanmod.scan_text(text)
        self.assertEqual(result["count"], 0)

    def test_scan_is_deterministic(self):
        text = (FIXTURE / EXPECTED["leak_file"]).read_text(encoding="utf-8")
        a = scanmod.scan_text(text, path="leak.py")
        b = scanmod.scan_text(text, path="leak.py")
        self.assertEqual(a, b)

    def test_scan_writes_nothing(self):
        before = {str(p): (p.stat().st_size, p.stat().st_mtime_ns)
                  for p in FIXTURE.rglob("*") if p.is_file()}
        scanmod.scan_tree(FIXTURE, mode="secrets")
        scanmod.scan_tree(FIXTURE, mode="patterns")
        after = {str(p): (p.stat().st_size, p.stat().st_mtime_ns)
                 for p in FIXTURE.rglob("*") if p.is_file()}
        self.assertEqual(before, after)

    def test_binary_files_are_skipped_not_crashed(self):
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as fh:
            fh.write(b"\x00\x01\x02secret\x00")
            path = fh.name
        try:
            result = scanmod.scan_file(path)
            self.assertEqual(result.get("skipped"), "binary")
        finally:
            os.unlink(path)


class TestPatternScan(unittest.TestCase):
    def test_every_pattern_rule_fires(self):
        result = scanmod.scan_file(FIXTURE / EXPECTED["pattern_file"],
                                   mode="patterns")
        found = {item["rule"] for item in result["findings"]}
        missing = sorted(set(EXPECTED["pattern_must_find_rules"]) - found)
        self.assertEqual(missing, [], f"rules that never fired: {missing}")

    def test_secrets_mode_does_not_report_code_patterns(self):
        result = scanmod.scan_file(FIXTURE / EXPECTED["pattern_file"],
                                   mode="secrets")
        self.assertEqual(result["count"], 0)


class TestManifestScan(unittest.TestCase):
    def test_every_manifest_rule_fires(self):
        result = scanmod.scan_manifest(FIXTURE / EXPECTED["manifest_file"])
        found = {item["rule"] for item in result["findings"]}
        missing = sorted(set(EXPECTED["manifest_must_find_rules"]) - found)
        self.assertEqual(missing, [], f"rules that never fired: {missing}")


class TestElf(unittest.TestCase):
    def test_entropy_on_text_is_low(self):
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as fh:
            fh.write("hello world " * 200)
            path = fh.name
        try:
            result = elf.entropy(path)
            self.assertTrue(result["ok"])
            self.assertLess(result["entropy"], 4.0)
            self.assertEqual(result["verdict"], "low")
        finally:
            os.unlink(path)

    def test_entropy_on_random_bytes_is_high(self):
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as fh:
            fh.write(os.urandom(4096))
            path = fh.name
        try:
            result = elf.entropy(path)
            self.assertGreater(result["entropy"], 7.0)
            self.assertEqual(result["verdict"], "packed_or_encrypted")
        finally:
            os.unlink(path)

    def test_entropy_blocks(self):
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as fh:
            fh.write(b"a" * 128 + os.urandom(128))
            path = fh.name
        try:
            result = elf.entropy(path, block=128, limit=4)
            self.assertEqual(len(result["blocks"]), 2)
            self.assertLess(result["blocks"][0]["entropy"],
                            result["blocks"][1]["entropy"])
        finally:
            os.unlink(path)

    def test_non_elf_raises(self):
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as fh:
            fh.write("not an elf")
            path = fh.name
        try:
            with self.assertRaises(elf.ElfError):
                elf.info(path)
        finally:
            os.unlink(path)

    def test_pack_flags_packed_content(self):
        import random
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as fh:
            # Seeded, so the fixture is the same bytes every run.
            fh.write(random.Random(42).randbytes(4096))
            path = fh.name
        try:
            result = elf.pack(path)
            self.assertTrue(result["ok"])
            self.assertEqual(result["verdict"], "likely_packed_or_encrypted")
            self.assertGreater(result["entropy"], 7.0)
            self.assertLess(result["long_string_density_per_kb"], 0.5)
        finally:
            os.unlink(path)

    def test_pack_passes_plain_content(self):
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as fh:
            fh.write("hello world this is ordinary text " * 100)
            path = fh.name
        try:
            result = elf.pack(path)
            self.assertEqual(result["verdict"], "normal")
        finally:
            os.unlink(path)

    def test_real_binary_when_available(self):
        binary = find_elf()
        if binary is None:
            self.skipTest("no ELF binary on this host")
        info = elf.info(binary)
        self.assertTrue(info["ok"])
        self.assertIn("ELF", info.get("class", ""))
        sections = elf.sections(binary)
        self.assertTrue(sections["sections"])
        names = {s["name"] for s in sections["sections"]}
        self.assertIn(".text", names)
        strings = elf.strings(binary, min_len=6, limit=10)
        self.assertTrue(strings["strings"])


class TestGuardRoots(unittest.TestCase):
    def test_no_placeholder_roots(self):
        for root in guard.roots():
            self.assertNotIn("$", str(root))

    def test_system_binary_roots_present(self):
        roots = {str(r) for r in guard.roots()}
        self.assertTrue(any(r.startswith("/usr") or r.startswith("/bin")
                            for r in roots))

    def test_deny_list_still_blocks_secrets(self):
        with self.assertRaises(guard.Denied) as ctx:
            guard.read_guard(Path.home() / ".ssh" / "id_rsa")
        self.assertEqual(ctx.exception.code, "deny_listed")

    def test_outside_roots_is_denied(self):
        with self.assertRaises(guard.Denied):
            guard.read_guard("/proc/self/mem")


class TestCliRound6(unittest.TestCase):
    def run_cli(self, *args, expect_ok: bool = True):
        proc = subprocess.run(
            [sys.executable, "-m", "xtforge.cli", *args],
            capture_output=True, text=True, cwd=str(ROOT), timeout=60)
        if expect_ok:
            self.assertEqual(proc.returncode, 0, proc.stderr or proc.stdout)
        return proc

    def test_scan_masks_by_default(self):
        out = self.run_cli("scan", "secrets", str(FIXTURE / "leak.py"),
                           "--json").stdout
        payload = json.loads(out)
        self.assertTrue(payload["masked"])
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", out)

    def test_scan_reveal_shows_value(self):
        out = self.run_cli("scan", "secrets", str(FIXTURE / "leak.py"),
                           "--reveal", "--json").stdout
        self.assertIn("AKIAIOSFODNN7EXAMPLE", out)

    def test_scan_patterns_over_cli(self):
        payload = json.loads(self.run_cli(
            "scan", "patterns", str(FIXTURE / "risky.py"), "--json").stdout)
        self.assertGreaterEqual(payload["count"], 8)

    def test_scan_deps_over_cli(self):
        payload = json.loads(self.run_cli(
            "scan", "deps", str(FIXTURE / "requirements.txt"), "--json").stdout)
        self.assertEqual(payload["manifests"], 1)
        self.assertGreaterEqual(payload["count"], 5)

    def test_re_verbosity_over_cli(self):
        binary = find_elf()
        if binary is None:
            self.skipTest("no ELF binary on this host")
        payload = json.loads(self.run_cli("re", "entropy", str(binary),
                                          "--json").stdout)
        self.assertIn("entropy", payload)
        self.assertIn("verdict", payload)


if __name__ == "__main__":
    unittest.main()
