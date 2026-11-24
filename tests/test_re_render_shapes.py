"""Renderers that read keys their result does not have.

Both defects here are the same mistake in different places: a human renderer written against one
engine's result shape, then reached by a different engine's result. The output is not an error —
it is a full table of `None`, which reads like a successful parse of an empty file. That is worse
than a refusal, because nothing signals that anything went wrong.

  * `re wasm compare` failing produced `format None version None size None`: the compare branch
    was gated on `interface_identical`, a key absent when the comparison fails, so a failure fell
    through to the single-module renderer.
  * `re firmware <ovmf>` produced `UEFI firmware image (None volume(s), None bytes)` while the
    JSON carried 19 files: `firmware.inspect` and `firmwarevolume.inspect_firmware_volume` return
    different shapes and two renderer branches existed, the correct one unreachable behind the
    wrong one.
"""
from __future__ import annotations

import unittest
from pathlib import Path

OVMF = Path("/tmp/ovmf_dec.bin")

def _wasm(exports: list[str]) -> bytes:
    """A minimal valid wasm module exporting the given zero-arg functions.

    Section bodies are measured, not hand-counted: an earlier fixture hardcoded the export
    section length and the reader rejected it with "truncated u32 LEB128", which is the parser
    being right.
    """
    def leb(value: int) -> bytes:
        out = bytearray()
        while True:
            byte = value & 0x7F
            value >>= 7
            out.append(byte | (0x80 if value else 0))
            if not value:
                return bytes(out)

    def section(section_id: int, body: bytes) -> bytes:
        return bytes([section_id]) + leb(len(body)) + body

    types = section(1, b"\x01\x60\x00\x00")          # one func type () -> ()
    funcs = section(3, bytes([len(exports)]) + bytes(len(exports)))  # all of type 0
    body = leb(len(exports))
    for index, name in enumerate(exports):
        encoded = name.encode()
        body += leb(len(encoded)) + encoded + b"\x00" + leb(index)
    code = section(10, leb(len(exports)) + b"".join(
        b"\x02\x00\x0b" for _ in exports))            # each body: no locals, end
    return (bytes.fromhex("0061736d01000000") + types + funcs
            + section(7, body) + code)


WASM_A = _wasm(["alpha", "beta"])


def render(argv: list[str]) -> str:
    """Run the CLI the way a person would, and return the human output.

    There is no standalone render function to call — the rendering is one long `elif` chain
    inside `cmd_re` — so a renderer can only be exercised end to end. That is also the level the
    bugs were at: the JSON was correct in both cases and only the human output lied.
    """
    import contextlib
    import io
    import os
    import subprocess
    import sys
    completed = subprocess.run([sys.executable, "-m", "xtforge.cli", "re", *argv],
                               capture_output=True, text=True,
                               cwd=str(Path(__file__).resolve().parent.parent), timeout=180)
    return completed.stdout + completed.stderr


class WasmCompareTest(unittest.TestCase):
    def test_a_failed_compare_names_the_reason(self) -> None:
        """The bug: a table of Nones where the reason belonged."""
        bad = Path(self.directory) / "bad.wasm"
        bad.write_bytes(WASM_A + b"\x00")
        good = Path(self.directory) / "good.wasm"
        good.write_bytes(WASM_A)
        text = render(["wasm", "compare", str(good), str(bad)])
        self.assertIn("cannot compare", text)
        self.assertNotIn("None", text)
        self.assertIn("right", text, "the failing side was not named")

    def test_a_successful_compare_still_diffs(self) -> None:
        text = render(["wasm", "compare", self.good, self.differing])
        self.assertIn("wasm interface:", text)
        self.assertIn("+ gamma", text)
        self.assertIn("- alpha", text)

    def setUp(self) -> None:
        import tempfile
        self.directory = tempfile.mkdtemp(prefix="xtws-")
        self.addCleanup(__import__("shutil").rmtree, self.directory, ignore_errors=True)
        self.good = str(Path(self.directory) / "a.wasm")
        Path(self.good).write_bytes(WASM_A)
        self.differing = str(Path(self.directory) / "b.wasm")
        # `alpha` renamed to `gamma`, so exactly one export is added and one removed.
        Path(self.differing).write_bytes(_wasm(["gamma", "beta"]))


@unittest.skipUnless(OVMF.is_file(), "needs the OVMF volume at /tmp/ovmf_dec.bin")
class FirmwareShapeTest(unittest.TestCase):
    def test_the_engine_reports_real_files(self) -> None:
        """Independent of rendering: the parse itself found content."""
        from xtforge.core.re import firmware
        report = firmware.inspect(str(OVMF))
        self.assertTrue(report["ok"])
        self.assertEqual(report["size"], OVMF.stat().st_size)
        self.assertTrue(report["files"], "no files parsed out of a 16 MB firmware volume")

    def test_the_renderer_shows_that_content(self) -> None:
        """The bug: the parse found files and the renderer printed Nones over them."""
        from xtforge.core.re import firmware
        text = render(["firmware", str(OVMF)])
        self.assertIn("uefi_fv", text)
        self.assertIn(str(OVMF.stat().st_size), text)
        self.assertNotIn("None volume(s)", text)
        self.assertNotIn("None bytes", text)
        self.assertNotIn("(None, None", text)

    def test_no_field_renders_as_the_word_none(self) -> None:
        """A literal "None" in a rendered report means a key the result does not carry."""
        from xtforge.core.re import firmware
        text = render(["firmware", str(OVMF)])
        offenders = [line.strip() for line in text.splitlines()
                     if "None" in line and "UNKNOWN" not in line]
        self.assertEqual(offenders, [], f"fields rendered as None: {offenders}")

    def test_the_sibling_verb_still_reports_its_own_error(self) -> None:
        """`fv` uses the other engine; fixing the firmware branch must not silence it."""
        from xtforge.core.re import firmwarevolume
        text = render(["fv", str(OVMF)])
        self.assertIn("firmware volume:", text)
        self.assertIn("_FVH", text)

    def test_a_non_volume_says_so(self) -> None:
        from xtforge.core.re import firmware
        text = render(["firmware", "/bin/ls"])
        self.assertIn("no _FVH signature", text)
        self.assertNotIn("None volume(s)", text)


if __name__ == "__main__":
    unittest.main()
