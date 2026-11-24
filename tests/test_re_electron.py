"""Electron fuses: the security switches compiled into an Electron binary.

An Electron app ships a full Chromium and Node runtime, and the fuses decide whether that runtime
can be repurposed: `RunAsNode` lets anyone launch the binary as a plain Node interpreter with the
app's privileges, `EnableNodeOptionsEnvironmentVariable` lets the environment inject code, and
`OnlyLoadAppFromAsar` decides whether a loose `app/` directory beside the binary is honoured — which
is the whole basis of the repack attack.

The wire format is from `@electron/fuses`, the reference implementation:

    sentinel "dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX", then version, then length, then one byte per fuse
    0x30 'disabled'  0x31 'enabled'  0x72 'removed'  0x90 'inherit'

**These tests build the wire to that structure; they do not read a real Electron binary.** No
Electron binary exists on this host — a search of the filesystem for the sentinel found none, and
neither `electron` nor any `app.asar` is installed. What is verified against reality is the negative
case: the shipped Chromium (463 MB) is correctly reported as *not* Electron, which proves the
sentinel search does not match arbitrary large binaries.

The positive path rests on the documented format. That is weaker than a byte-for-byte comparison
with a known-good binary, and the row's note says so rather than implying otherwise.
"""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from xtforge.core.re import electron

# FuseState values from @electron/fuses src/constants.ts.
ENABLE = 0x31
DISABLE = 0x30
REMOVED = 0x72
INHERIT = 0x90


class FuseWireTest(unittest.TestCase):
    def _blob(self, wire: list[int], *, version: int = 1, padding: int = 64) -> bytes:
        return (b"\x00" * padding + electron.SENTINEL
                + bytes([version, len(wire)]) + bytes(wire) + b"\x00" * padding)

    def test_a_hardened_wire_is_read(self) -> None:
        wire = [DISABLE, ENABLE, DISABLE, DISABLE, ENABLE, ENABLE, ENABLE, DISABLE, ENABLE]
        report = electron.inspect_electron_fuses(self._blob(wire))
        self.assertTrue(report["ok"])
        self.assertEqual(report["fuse_count"], 9)
        self.assertEqual(report["version"], 1)

    def test_the_fuse_names_come_from_the_index(self) -> None:
        """The index is the contract: position 0 is RunAsNode, 5 is OnlyLoadAppFromAsar."""
        report = electron.inspect_electron_fuses(self._blob([DISABLE] * 9))
        names = [entry["name"] for entry in report["fuses"]]
        self.assertEqual(names[0], "RunAsNode")
        self.assertEqual(names[2], "EnableNodeOptionsEnvironmentVariable")
        self.assertEqual(names[3], "EnableNodeCliInspectArguments")
        self.assertEqual(names[5], "OnlyLoadAppFromAsar")

    def test_enabling_run_as_node_is_reported_as_exposure(self) -> None:
        """`RunAsNode` is a capability switch: enabled means the binary runs arbitrary script."""
        report = electron.inspect_electron_fuses(
            self._blob([ENABLE, DISABLE, DISABLE, DISABLE, DISABLE, DISABLE, DISABLE, DISABLE,
                        DISABLE]))
        self.assertIn("RunAsNode", report["exposed"])
        self.assertNotIn("RunAsNode", report["hardened"])

    def test_disabling_only_load_app_from_asar_is_reported_as_exposure(self) -> None:
        """This one is protective when enabled, so disabled is the finding — the opposite
        direction from RunAsNode. A reader that treated every fuse the same way would report
        this app as maximally hardened."""
        wire = [DISABLE] * 9
        wire[5] = DISABLE
        report = electron.inspect_electron_fuses(self._blob(wire))
        self.assertIn("OnlyLoadAppFromAsar", report["exposed"])

    def test_enabling_only_load_app_from_asar_is_not_a_finding(self) -> None:
        wire = [DISABLE] * 9
        wire[5] = ENABLE
        report = electron.inspect_electron_fuses(self._blob(wire))
        self.assertNotIn("OnlyLoadAppFromAsar", report["exposed"])
        self.assertIn("OnlyLoadAppFromAsar", report["hardened"])

    def test_removed_is_neither_a_protection_nor_a_risk(self) -> None:
        """A removed fuse guards a code path that no longer exists.

        Scoring it as exposure put four phantom findings in the list; scoring it as hardening
        claimed a protection that is not there. It is reported on its own.
        """
        report = electron.inspect_electron_fuses(self._blob([REMOVED] * 9))
        self.assertEqual(len(report["removed"]), 9)
        self.assertEqual(report["exposed"], [])
        self.assertEqual(report["hardened"], [])
        for entry in report["fuses"]:
            self.assertIsNone(entry["hardening"])
            self.assertIn("no longer exists", entry["note"])

    def test_inherit_is_undetermined_not_exposed(self) -> None:
        """`inherit` means the wire does not set the fuse, so the build default applies and this
        reader cannot see it.

        Scoring inherit as "not enabled" reported four protective fuses as exposed on an
        all-inherit wire — four findings where the honest answer is four unknowns.
        """
        report = electron.inspect_electron_fuses(self._blob([INHERIT] * 9))
        self.assertEqual(report["exposed"], [])
        self.assertEqual(report["hardened"], [])
        self.assertEqual(len(report["undetermined"]), 9)
        for entry in report["fuses"]:
            self.assertIsNone(entry["hardening"])
            self.assertIn("default applies", entry["note"])

    def test_every_state_symbol_matches_the_reference(self) -> None:
        report = electron.inspect_electron_fuses(
            self._blob([DISABLE, ENABLE, REMOVED, INHERIT]))
        symbols = {entry["state"]: entry["symbol"] for entry in report["fuses"]}
        self.assertEqual(symbols["disabled"], "0")
        self.assertEqual(symbols["enabled"], "1")
        self.assertEqual(symbols["removed"], "r")

    def test_a_short_wire_is_read_as_far_as_it_goes(self) -> None:
        """A build with fewer fuses than this reader knows about is normal, not an error."""
        report = electron.inspect_electron_fuses(self._blob([DISABLE, DISABLE]))
        self.assertTrue(report["ok"])
        self.assertEqual(report["fuse_count"], 2)

    def test_a_longer_wire_than_known_names_still_decodes(self) -> None:
        """A future Electron may add fuses; the known ones must still be named correctly."""
        report = electron.inspect_electron_fuses(self._blob([DISABLE] * 12))
        self.assertEqual(report["fuse_count"], 12)
        self.assertEqual(report["fuses"][0]["name"], "RunAsNode")
        self.assertEqual(report["fuses"][11]["name"], "unknown_11")

    def test_an_unknown_state_byte_is_reported_not_guessed(self) -> None:
        report = electron.inspect_electron_fuses(self._blob([0x42]))
        self.assertEqual(report["fuses"][0]["state"], "unknown_code_0x42")
        self.assertIsNone(report["fuses"][0]["hardening"])

    def test_a_missing_sentinel_is_reported_as_not_electron(self) -> None:
        report = electron.inspect_electron_fuses(b"an ordinary executable with no fuses in it")
        self.assertFalse(report["ok"])
        self.assertIn("not an Electron binary", report["error"])

    def test_a_sentinel_at_the_end_of_the_file_does_not_crash(self) -> None:
        report = electron.inspect_electron_fuses(b"\x00" * 32 + electron.SENTINEL)
        self.assertFalse(report["ok"])
        self.assertIn("no fuse header follows", str(report.get("error")))

    def test_a_truncated_wire_reports_what_it_read(self) -> None:
        """Declared length runs past the end: report the bytes present rather than failing."""
        blob = b"\x00" * 16 + electron.SENTINEL + bytes([1, 9, DISABLE, ENABLE])
        report = electron.inspect_electron_fuses(blob)
        self.assertTrue(report["ok"])
        self.assertEqual(report["declared_length"], 9)
        self.assertEqual(report["wire_bytes_read"], 2)

    def test_two_sentinels_are_both_reported(self) -> None:
        """A universal macOS binary carries one wire per architecture, and they can differ."""
        first = self._blob([DISABLE] * 9, padding=16)
        second = self._blob([ENABLE] * 9, padding=16)
        report = electron.inspect_electron_fuses(first + second)
        self.assertEqual(report["sentinel_count"], 2)
        self.assertEqual(len(report["wires"]), 2)
        self.assertFalse(report["slices_agree"],
                         "wires that differ must not be reported as agreeing")
        # `first` is the all-disabled wire and it comes first in the file, so it is the primary.
        # All-disabled means every protective fuse is off — that is the exposure — while every
        # capability switch is also off, which is correct hardening. The point of the test is that
        # both wires are reported at all; which one is primary is file order, which is documented.
        self.assertIn("WasmTrapHandlers", report["exposed"],
                      "the primary wire is the all-disabled one, whose protective fuses are off")
        self.assertIn("OnlyLoadAppFromAsar", report["exposed"])
        self.assertIn("RunAsNode", report["hardened"],
                      "RunAsNode disabled is hardening, not a finding")

    def test_matching_slices_are_reported_as_agreeing(self) -> None:
        report = electron.inspect_electron_fuses(
            self._blob([DISABLE] * 9, padding=16) + self._blob([DISABLE] * 9, padding=16))
        self.assertTrue(report["slices_agree"])

    def test_more_than_two_sentinels_is_flagged(self) -> None:
        """The reference treats >2 as corruption; the count is surfaced rather than swallowed."""
        blob = b"".join(self._blob([DISABLE] * 9, padding=8) for _ in range(3))
        report = electron.inspect_electron_fuses(blob)
        self.assertEqual(report["sentinel_count"], 3)
        self.assertIn("corrupted", report["warning"])

    def test_a_sentinel_straddling_a_chunk_boundary_is_found(self) -> None:
        """The reference overlaps its read window by `len(sentinel) - 1` for exactly this."""
        filler = b"\x01" * (electron.CHUNK - 10)
        blob = filler + electron.SENTINEL + bytes([1, 1, DISABLE])
        report = electron.inspect_electron_fuses(blob)
        self.assertEqual(report["sentinel_count"], 1)

    def test_it_accepts_a_path(self) -> None:
        directory = Path(tempfile.mkdtemp(prefix="xtfuse-"))
        try:
            target = directory / "fake-electron"
            target.write_bytes(self._blob([DISABLE] * 9))
            report = electron.inspect_electron_fuses(str(target))
            self.assertTrue(report["ok"])
            self.assertEqual(report["fuse_count"], 9)
        finally:
            import shutil
            shutil.rmtree(directory, ignore_errors=True)

    def test_a_missing_file_fails_cleanly(self) -> None:
        report = electron.inspect_electron_fuses("/nonexistent/electron-binary")
        self.assertFalse(report["ok"])
        self.assertIn("error", report)


class RealBinaryTest(unittest.TestCase):
    """The one check that touches reality: the shipped Chromium is not Electron.

    A sentinel search that matches arbitrary large binaries would report fuses for every
    executable on the machine, which would be worse than not having the feature. This binary is a
    real 463 MB Chromium build and it must come back as not-Electron.
    """

    def _chromium(self) -> Path | None:
        import glob
        import os
        candidates = glob.glob(os.path.expanduser(
            "~/.cache/ms-playwright/*/chrome-linux/chrome"))
        return Path(candidates[0]) if candidates else None

    def test_chromium_is_not_reported_as_electron(self) -> None:
        target = self._chromium()
        if target is None:
            self.skipTest("no Chromium build on this host")
        report = electron.inspect_electron_fuses(str(target))
        self.assertFalse(report["ok"])
        self.assertEqual(report["sentinel_count"], 0)
        self.assertGreater(report["file_size"], 100 * 1024 * 1024)


if __name__ == "__main__":
    unittest.main()


class EveryFuseLandsInOneBucketTest(unittest.TestCase):
    """A fuse must never be reported and then dropped from the summary.

    Found by stress-testing all-`0xff` state bytes. All nine fuses came back carrying
    `hardening: None` and a note reading "this is not one of the four documented fuse states", and
    then appeared in none of `exposed`, `hardened` or `undetermined` — nine unknowns rendering as
    nine clean fuses. The filter asked for `state == "inherit"`, so any state outside the four
    documented codes fell through the summary entirely.

    The invariant that makes the output trustworthy: for every fuse the reader reports, exactly one
    of exposed / hardened / removed / undetermined names it. Without this a caller counting
    `len(hardened)` to decide whether a build is hardened is counting a number that silently omits
    what the reader did not understand.
    """

    def _summary(self, code: int, count: int = 9) -> dict:
        return electron.inspect_electron_fuses(
            electron.SENTINEL + bytes([1, count]) + bytes([code]) * count)

    def test_unknown_state_codes_are_undetermined(self) -> None:
        report = self._summary(0xFF)
        self.assertTrue(report["ok"], report.get("error"))
        self.assertEqual(len(report["undetermined"]), 9)
        self.assertEqual(report["exposed"], [])
        self.assertEqual(report["hardened"], [])

    def test_an_unrecognised_code_is_never_scored_as_safe(self) -> None:
        """The dangerous reading: an unknown byte quietly counting as protection present."""
        report = self._summary(0xFF)
        self.assertNotIn(True, [fuse.get("hardening") for fuse in report["fuses"]])
        self.assertNotIn(False, [fuse.get("hardening") for fuse in report["fuses"]])

    def test_every_state_lands_in_exactly_one_bucket(self) -> None:
        for code in (0x30, 0x31, 0x72, 0x90, 0xFF, 0x00, 0x01):
            report = self._summary(code)
            if not report["ok"]:
                continue
            named = (report["exposed"] + report["hardened"] + report["removed"]
                     + report["undetermined"])
            with self.subTest(code=hex(code)):
                self.assertEqual(len(named), len(report["fuses"]),
                                 f"{len(report['fuses'])} fuses reported, "
                                 f"{len(named)} accounted for")
                self.assertEqual(len(set(named)), len(named), "a fuse is in two buckets")

    def test_removed_is_not_double_counted_as_undetermined(self) -> None:
        """`removed` is undetermined in direction but is reported in its own bucket."""
        report = self._summary(0x72)
        self.assertEqual(len(report["removed"]), 9)
        self.assertEqual(report["undetermined"], [])


class WireVersionTest(unittest.TestCase):
    """Only version 1 is documented; another version's slots are not this code's to name.

    Before this check, a wire whose version byte read 2 was decoded as though it were version 1 and
    the nine v1 fuse names were printed against it. A wrong name on a real slot reads as knowledge;
    the honest report is that the layout is unknown.
    """

    def test_version_2_is_refused_rather_than_guessed(self) -> None:
        report = electron.inspect_electron_fuses(
            electron.SENTINEL + bytes([2, 9]) + b"\x31" * 9)
        self.assertFalse(report["ok"])
        self.assertIn("version 2", report["error"])
        self.assertEqual(report["fuses"], [], "no names may be invented for an unknown layout")

    def test_the_refusal_still_reports_what_it_saw(self) -> None:
        report = electron.inspect_electron_fuses(
            electron.SENTINEL + bytes([7, 4]) + b"\x31" * 4)
        self.assertEqual(report["version"], 7)
        self.assertEqual(report["declared_length"], 4)

    def test_version_1_is_unaffected(self) -> None:
        report = electron.inspect_electron_fuses(
            electron.SENTINEL + bytes([1, 9]) + b"\x31" * 9)
        self.assertTrue(report["ok"], report.get("error"))
        self.assertEqual(report["version"], 1)
        self.assertEqual(len(report["fuses"]), 9)


class AllClearSentenceTest(unittest.TestCase):
    """The renderer must not print an all-clear when it did not understand the wire.

    Having fixed the data (nine `0xff` fuses now land in `undetermined`), the rendering still ended
    with "no exposure found on this wire" — the same error in prose. A reader skimming the last line
    gets a clean bill of health from nine unknowns.
    """

    def _render(self, wire: bytes) -> str:
        import tempfile
        from pathlib import Path
        from xtforge.cli.scan_cmd import _render_fuses
        directory = tempfile.mkdtemp(prefix="xtfuse-")
        self.addCleanup(lambda: __import__("shutil").rmtree(directory, ignore_errors=True))
        path = Path(directory) / "wire"
        path.write_bytes(electron.SENTINEL + bytes([1, len(wire)]) + wire)
        return _render_fuses(electron.inspect_electron_fuses(path))

    def test_unknown_states_do_not_produce_an_all_clear(self) -> None:
        text = self._render(b"\xff" * 9)
        self.assertNotIn("no exposure found on this wire", text)
        self.assertIn("not an all-clear", text)
        self.assertIn("9 undetermined", text)

    def test_a_genuinely_clean_wire_does_produce_an_all_clear(self) -> None:
        codes = bytes(0x31 if name in electron._PROTECTIVE_WHEN_ENABLED else 0x30
                      for name, _ in electron.FUSE_V1_OPTIONS)
        text = self._render(codes)
        self.assertIn("no exposure found on this wire", text)
        self.assertNotIn("not an all-clear", text)

    def test_inherit_also_suppresses_the_all_clear(self) -> None:
        """`inherit` is a real state, and it also means the direction is unknown."""
        text = self._render(b"\x90" * 9)
        self.assertNotIn("no exposure found on this wire", text)


class RendererNeverReturnsNothingTest(unittest.TestCase):
    """Every outcome must render something.

    Extracting the renderer into `_render_fuses` dropped the `return` from the not-found branch, so
    `re fuses <non-Electron binary>` printed nothing at all and exited 0. An empty result with a
    success code is the worst failure mode available: a script piping this output sees no error, and
    a person sees no output and assumes the tool did nothing. The 463 MB Chromium in the Playwright
    cache is the real case — correctly identified as not-Electron, and silently so.
    """

    def test_a_non_electron_binary_renders_its_reason(self) -> None:
        from xtforge.cli.scan_cmd import _render_fuses
        report = {"ok": False, "file_size": 4096, "sentinel_count": 0,
                  "error": "the Electron fuse sentinel was not found"}
        text = _render_fuses(report)
        self.assertTrue(text.strip(), "the not-found path rendered nothing")
        self.assertIn("sentinel was not found", text)

    def test_a_truncated_wire_renders_its_reason(self) -> None:
        from xtforge.cli.scan_cmd import _render_fuses
        report = {"ok": False, "sentinel_count": 1,
                  "error": "the sentinel is at the very end of the file"}
        text = _render_fuses(report)
        self.assertTrue(text.strip())
        self.assertIn("very end of the file", text)

    def test_a_successful_wire_renders_a_header(self) -> None:
        from xtforge.cli.scan_cmd import _render_fuses
        report = electron.inspect_electron_fuses(
            electron.SENTINEL + bytes([1, 9]) + b"\x31" * 9)
        text = _render_fuses(report)
        self.assertIn("Electron fuses", text)
        self.assertIn("9 fuses", text)

    def test_every_verdict_produces_non_empty_output(self) -> None:
        """Enumerated over the real state space rather than one example per branch."""
        from xtforge.cli.scan_cmd import _render_fuses
        cases = {
            "empty": b"",
            "sentinel only": electron.SENTINEL,
            "header truncated": electron.SENTINEL + b"\x01",
            "unknown states": electron.SENTINEL + bytes([1, 9]) + b"\xff" * 9,
            "inherit": electron.SENTINEL + bytes([1, 9]) + b"\x90" * 9,
            "removed": electron.SENTINEL + bytes([1, 9]) + b"\x72" * 9,
            "bad version": electron.SENTINEL + bytes([9, 9]) + b"\x31" * 9,
            "clean": electron.SENTINEL + bytes([1, 9]) + b"\x30" * 9,
        }
        for label, payload in cases.items():
            with self.subTest(case=label):
                text = _render_fuses(electron.inspect_electron_fuses(payload))
                self.assertTrue(text.strip(), f"{label} rendered nothing")
