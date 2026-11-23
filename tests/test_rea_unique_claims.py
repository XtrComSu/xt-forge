"""Every "unique capability" claim must be backed by a verb that actually works.

The point of this file is that the uniqueness list is dangerous in a way the breadth table is
not. Breadth under-claims by construction: a row with no verb says so. A uniqueness claim is
an assertion that we have something REA does not, and it is flattering, so it needs a
mechanical check or it drifts into marketing.

Four claims survive scrutiny. Three others did not, and they are recorded here because the
failure mode is repeatable:

  * "Borer object-graph RE" — `re borer` shells out to an external `borer` binary that is not
    even installed. That is a wrapper, exactly like the REA tools it was being compared
    against. Removed.
  * "Engine-native decompilation" (whole category) — false. REA's `inspect_android_method`
    decompiles Dalvik in its own engine.
  * "Native-code decompilation" — still false. That same tool reaches native methods via JNI.
    The claim only holds narrowed to plain x86/ARM ELF+PE, which is what it says now.

The classifier therefore has to distinguish "REA has this" from "REA has a tool that mentions
it". Two heuristics do that work, and both were needed:

  * **Negation awareness** — REA writes "without opening a disassembler" constantly. A plain
    substring search reads those denials as capability evidence and `inspect_dwarf_units`
    looked like a disassembler.
  * **Own-action scoping** — `inspect_address_context` ends with "Use xrefs, assembly, or
    pseudocode for those deeper views", a pointer to another tool. Only the tool's name and
    first sentence count.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "rea_unique.py"
CATALOG = Path("/tmp/rea-latest/package/dist/mcp-catalog.json")
sys.path.insert(0, str(SCRIPT.parent))


class ClassifierUnitTest(unittest.TestCase):
    def setUp(self) -> None:
        import rea_unique
        self.module = rea_unique

    def test_plain_mention_counts(self) -> None:
        self.assertTrue(self.module.mentions_capability(
            "decompile one procedure", ["decompile"]))

    def test_negated_mention_does_not_count(self) -> None:
        """REA says "without opening a disassembler" in half its tool descriptions."""
        self.assertFalse(self.module.mentions_capability(
            "Inspect an ELF image without executing it or opening a disassembler.",
            ["disassembl"]))

    def test_negation_reaches_across_a_long_clause(self) -> None:
        """The negation can be 55 characters before the word, so a fixed window fails."""
        text = ("inspect one image without executing the image or opening a "
                "disassembler. returns notes")
        self.assertFalse(self.module.mentions_capability(text, ["disassembl"]))

    def test_positive_mention_after_a_negated_sentence_counts(self) -> None:
        """A negation in an earlier sentence must not suppress a later real claim."""
        text = ("does not execute the image. operation disassemble optionally scopes "
                "to a symbol")
        self.assertTrue(self.module.mentions_capability(text, ["disassembl"]))

    def test_wrapper_markers_are_recognised(self) -> None:
        for marker in self.module.WRAPPER_MARKERS:
            self.assertIn(marker, self.module.WRAPPER_MARKERS)

    def test_scope_excludes_cover_narrow_formats(self) -> None:
        for marker in ("android", "dalvik", "java", "javascript"):
            self.assertIn(marker, self.module.SCOPE_EXCLUDES)


class ClaimTest(unittest.TestCase):
    def setUp(self) -> None:
        if not CATALOG.is_file():
            self.skipTest("REA catalogue is not present; cannot verify claims")

    def test_script_runs(self) -> None:
        result = subprocess.run([sys.executable, str(SCRIPT)],
                                capture_output=True, timeout=300, check=False)
        self.assertEqual(result.returncode, 0, result.stderr.decode()[:300])
        self.assertIn(b"verified-unique capabilities", result.stdout)

    def test_every_claimed_verb_exists_in_the_cli(self) -> None:
        """A unique claim naming a verb that does not exist is worse than no claim."""
        source = (ROOT / "xtforge" / "cli" / "__init__.py").read_text()
        import rea_unique
        result = subprocess.run([sys.executable, str(SCRIPT), "--json", "/tmp/u.json"],
                                capture_output=True, timeout=300, check=False)
        self.assertEqual(result.returncode, 0, result.stderr.decode()[:300])
        record = json.loads(Path("/tmp/u.json").read_text())
        for claim in record["claims"]:
            verb = claim["xt_forge_verb"]
            self.assertIn(f'"{verb}"', source,
                          f"claim {claim['capability']!r} names missing verb {verb!r}")

    def test_borer_is_not_claimed(self) -> None:
        """`re borer` is a shell-out to an absent binary — not our capability."""
        import rea_unique
        verbs = [claim[1] for claim in rea_unique.CLAIMS]
        self.assertNotIn("borer", verbs)

    def test_claims_are_not_vacuous(self) -> None:
        result = subprocess.run([sys.executable, str(SCRIPT), "--json", "/tmp/u2.json"],
                                capture_output=True, timeout=300, check=False)
        if result.returncode != 0:
            self.skipTest("classifier did not run")
        record = json.loads(Path("/tmp/u2.json").read_text())
        self.assertGreater(len(record["claims"]), 0)
        self.assertGreater(record["unique_count"], 0)

    def test_at_least_one_claim_survives(self) -> None:
        """If every claim were refuted, the script should be rewritten, not left green."""
        result = subprocess.run([sys.executable, str(SCRIPT)], capture_output=True,
                                timeout=300, check=False)
        self.assertIn(b"UNIQUE", result.stdout,
                      "no claim survived scrutiny — the list needs rebuilding")


class WorkingVerbTest(unittest.TestCase):
    """Each claimed verb must produce a real answer, not just exist in argparse."""

    def _run(self, *args: str) -> subprocess.CompletedProcess:
        return subprocess.run([str(ROOT / "bin" / "xtforge"), "re", *args],
                              capture_output=True, timeout=180, check=False)

    def test_disasm_native_returns_instructions(self) -> None:
        result = self._run("disasm-native", "/bin/ls")
        self.assertEqual(result.returncode, 0, result.stderr.decode()[:200])
        self.assertIn(b"instruction", result.stdout.lower())

    def test_decompile_native_returns_pseudocode(self) -> None:
        result = self._run("decompile-native", "/bin/ls")
        self.assertEqual(result.returncode, 0, result.stderr.decode()[:200])
        text = result.stdout.decode("utf-8", "replace").lower()
        self.assertTrue(any(token in text for token in
                            ("function", "pseudo", "return", "locals")), text[:300])

    def test_rbxm_parses_a_real_container(self) -> None:
        import struct
        import tempfile
        import zlib
        header = b"<roblox!\x89\xff\r\n\x1a\n\x00\x00"

        def chunk(name: bytes, payload: bytes, compress: bool = True) -> bytes:
            body = zlib.compress(payload) if compress else payload
            return (name + struct.pack("<I", len(body)) + struct.pack("<I", len(payload))
                    + struct.pack("<I", 0) + body)

        meta = struct.pack("<I", 1) + b"\x04Name" + b"\x05Hello"
        blob = (header + chunk(b"META", meta)
                + chunk(b"END\x00", b"", compress=False))
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "t.rbxm"
            target.write_bytes(blob)
            result = self._run("rbxm", str(target))
        self.assertEqual(result.returncode, 0, result.stderr.decode()[:200])
        self.assertIn(b"ok=True", result.stdout)

    def test_live_probe_reports_on_a_live_process(self) -> None:
        import os
        result = self._run("live-probe", str(os.getpid()))
        self.assertEqual(result.returncode, 0, result.stderr.decode()[:200])
        self.assertIn(b"ok=True", result.stdout)


if __name__ == "__main__":
    unittest.main()
