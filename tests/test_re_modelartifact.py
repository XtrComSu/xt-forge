"""GGUF and safetensors header parsing, checked against the formats and against real files.

The breadth matrix excluded this as "different product surface (ML artifacts)". Reading what the
REA tool does — parse a GGUF v2/v3 header and a safetensors JSON declaration without a runtime —
shows it is container parsing of documented binary formats, which is this engine's job.

Two oracles are used, deliberately different:

  * **synthetic headers built byte by byte** from the published layout, so every field's offset
    and width is exercised independently of the parser;
  * **the real 787 MB GGUF and 90 MB safetensors on this host**, cross-checked against a direct
    `struct.unpack` of the fixed 24-byte prefix.

That pair matters because the two failure modes here are opposite: a parser written only from
the spec can be right and never run, and a parser tested only on one real file can hardcode that
file's shape. Also asserted, and load-bearing: nothing reads tensor weights, so a 2 GB artifact
is inspected in milliseconds.
"""
from __future__ import annotations

import json
import os
import struct
import tempfile
import unittest
from pathlib import Path

from xtforge.core.re import modelartifact

# Discovered rather than hardcoded: a source file naming a home directory is exactly what the
# repository's own guard test forbids, and it is right to — the fixtures belong to whoever has
# them. The globs are tried in order and the real-artifact tests skip when none match.
def _first(pattern: str) -> Path:
    import glob
    matches = sorted(glob.glob(os.path.expanduser(pattern)))
    return Path(matches[0]) if matches else Path("/nonexistent")


REAL_GGUF = _first("~/work/lunaris/xt-lunaris-v4-Q5_K_M.gguf")
REAL_SAFETENSORS = _first("~/work/lunaris/*/adapters/*/adapter_model.safetensors")


def _gguf_string(text: str) -> bytes:
    encoded = text.encode()
    return struct.pack("<Q", len(encoded)) + encoded


def build_gguf(*, version: int = 3, metadata: list | None = None,
               tensors: list | None = None, magic: bytes = b"GGUF") -> bytes:
    """Build a GGUF header from the published layout.

    metadata entries are (key, type_id, value_bytes); tensors are (name, shape, type_id, offset).
    """
    metadata = metadata if metadata is not None else []
    tensors = tensors if tensors is not None else []
    out = struct.pack("<4sIQQ", magic, version, len(tensors), len(metadata))
    for key, type_id, payload in metadata:
        out += _gguf_string(key) + struct.pack("<I", type_id) + payload
    for name, shape, type_id, offset in tensors:
        out += _gguf_string(name) + struct.pack("<I", len(shape))
        out += b"".join(struct.pack("<Q", dim) for dim in shape)
        out += struct.pack("<IQ", type_id, offset)
    return out


def _u32(value: int) -> bytes:
    return struct.pack("<I", value)


class SyntheticGgufTest(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.mkdtemp(prefix="xtmodel-")

    def tearDown(self) -> None:
        import shutil
        shutil.rmtree(self.directory, ignore_errors=True)

    def write(self, data: bytes) -> Path:
        path = Path(self.directory) / "m.gguf"
        path.write_bytes(data)
        return path

    def test_a_minimal_header_is_parsed(self) -> None:
        data = build_gguf(
            metadata=[("general.architecture", 8, _gguf_string("llama")),
                      ("general.name", 8, _gguf_string("Tiny"))],
            tensors=[("blk.0.weight", [4, 8], 0, 0)])
        report = modelartifact.inspect_gguf(self.write(data))
        self.assertTrue(report["ok"], report.get("error"))
        self.assertEqual(report["version"], 3)
        self.assertEqual(report["tensor_count"], 1)
        self.assertEqual(report["metadata_count"], 2)
        self.assertEqual(report["architecture"], "llama")
        self.assertEqual(report["name"], "Tiny")

    def test_parameter_count_is_the_product_of_the_shape(self) -> None:
        """4x8 = 32, and F32 is 4 bytes each, so 128 bytes."""
        data = build_gguf(tensors=[("w", [4, 8], 0, 0)])
        report = modelartifact.inspect_gguf(self.write(data))
        tensor = report["tensors"][0]
        self.assertEqual(tensor["parameters"], 32)
        self.assertEqual(tensor["bytes"], 128)
        self.assertEqual(report["parameter_count"], 32)

    def test_quantisation_ids_map_to_names(self) -> None:
        data = build_gguf(tensors=[("a", [2], 0, 0), ("b", [2], 1, 8),
                                   ("c", [2], 12, 12), ("d", [2], 14, 16)])
        report = modelartifact.inspect_gguf(self.write(data))
        self.assertEqual([tensor["type"] for tensor in report["tensors"]],
                         ["F32", "F16", "Q4_K", "Q6_K"])

    def test_an_unknown_quantisation_is_named_not_guessed(self) -> None:
        """Reporting a plausible element size would fabricate the parameter and byte totals."""
        data = build_gguf(tensors=[("w", [4], 200, 0)])
        report = modelartifact.inspect_gguf(self.write(data))
        tensor = report["tensors"][0]
        self.assertEqual(tensor["type"], "type-200")
        self.assertIsNone(tensor["bytes"])
        self.assertFalse(report["byte_totals_complete"])
        self.assertIn("partial", report["note"])

    def test_version_one_is_refused_rather_than_misparsed(self) -> None:
        """v1 has uint32 counts and no alignment field; the v2/v3 layout would read garbage."""
        report = modelartifact.inspect_gguf(self.write(build_gguf(version=1)))
        self.assertFalse(report["ok"])
        self.assertIn("v1", report["error"])
        self.assertIn("v2 and v3", report["error"])

    def test_a_bad_magic_is_refused(self) -> None:
        report = modelartifact.inspect_gguf(self.write(build_gguf(magic=b"NOPE")))
        self.assertFalse(report["ok"])
        self.assertIn("not a GGUF", report["error"])

    def test_a_truncated_header_is_an_error_not_a_partial_parse(self) -> None:
        data = build_gguf(metadata=[("k", 8, _gguf_string("value"))])
        report = modelartifact.inspect_gguf(self.write(data[:30]))
        self.assertFalse(report["ok"])
        self.assertIn("truncated", report["error"])

    def test_an_implausible_string_length_is_refused(self) -> None:
        """A declared length near 2**64 must not become an allocation attempt.

        The first version of this test appended bytes to a *valid* header, which parses fine
        because the trailing bytes are never reached — the assertion was inverted relative to
        what the fixture actually built. The declared length has to be inside the metadata
        entry, where the parser will read it.
        """
        huge = struct.pack("<Q", 2 ** 62) + b"ab"
        data = build_gguf(metadata=[("k", 8, huge)])
        report = modelartifact.inspect_gguf(self.write(data))
        self.assertFalse(report["ok"])
        self.assertIn("exceeds the header budget", report["error"])

    def test_a_short_file_is_refused(self) -> None:
        report = modelartifact.inspect_gguf(self.write(b"GGUF"))
        self.assertFalse(report["ok"])
        self.assertIn("too short", report["error"])

    def test_metadata_array_is_previewed_with_its_true_count(self) -> None:
        payload = _u32(5) + struct.pack("<Q", 100) + b"".join(struct.pack("<I", n) for n in range(100))
        data = build_gguf(metadata=[("arr", 9, payload)])
        report = modelartifact.inspect_gguf(self.write(data))
        entry = report["metadata"]["arr"]
        self.assertEqual(entry["count"], 100)
        self.assertEqual(len(entry["preview"]), 8)
        self.assertTrue(entry["truncated"])

    def test_no_weights_are_read(self) -> None:
        """A sparse 512 MB file whose header claims one tensor must return immediately."""
        path = Path(self.directory) / "sparse.gguf"
        data = build_gguf(tensors=[("w", [1024, 1024], 0, 0)])
        with path.open("wb") as handle:
            handle.write(data)
            handle.seek(512 * 1024 * 1024)
            handle.write(b"\x00")
        import time
        started = time.monotonic()
        report = modelartifact.inspect_gguf(path)
        elapsed = time.monotonic() - started
        self.assertTrue(report["ok"], report.get("error"))
        self.assertGreater(report["parameter_count"], 1_000_000)
        self.assertLess(elapsed, 5.0, "header inspection must not stream a 512 MB file")


class SyntheticSafetensorsTest(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.mkdtemp(prefix="xtst-")

    def tearDown(self) -> None:
        import shutil
        shutil.rmtree(self.directory, ignore_errors=True)

    def build(self, header: dict, payload: bytes = b"\x00" * 64) -> Path:
        raw = json.dumps(header).encode()
        path = Path(self.directory) / "m.safetensors"
        path.write_bytes(struct.pack("<Q", len(raw)) + raw + payload)
        return path

    def test_tensors_are_listed_with_offsets(self) -> None:
        path = self.build({"a": {"dtype": "F16", "shape": [2, 2], "data_offsets": [0, 8]},
                           "b": {"dtype": "F32", "shape": [2], "data_offsets": [8, 16]}})
        report = modelartifact.inspect_safetensors(path)
        self.assertTrue(report["ok"], report.get("error"))
        self.assertEqual(report["tensor_count"], 2)
        self.assertEqual(report["dtypes"], ["F16", "F32"])
        first = report["tensors"][0]
        self.assertEqual(first["bytes"], 8)
        self.assertEqual(report["data_offset"], 8 + report["header_bytes"])

    def test_metadata_key_is_not_counted_as_a_tensor(self) -> None:
        path = self.build({"__metadata__": {"format": "pt"},
                           "w": {"dtype": "F32", "shape": [1], "data_offsets": [0, 4]}})
        report = modelartifact.inspect_safetensors(path)
        self.assertEqual(report["tensor_count"], 1)
        self.assertEqual(report["metadata"], {"format": "pt"})

    def test_a_tensor_pointing_past_eof_is_flagged(self) -> None:
        report = modelartifact.inspect_safetensors(
            self.build({"w": {"dtype": "F32", "shape": [100], "data_offsets": [0, 400]}},
                       payload=b"\x00" * 8))
        self.assertTrue(report["ok"])
        self.assertEqual(report["truncated_count"], 1)
        self.assertIn("w", report["truncated_tensors"])

    def test_a_malformed_entry_is_reported_individually(self) -> None:
        path = self.build({"good": {"dtype": "F32", "shape": [1], "data_offsets": [0, 4]},
                           "bad": {"dtype": "F32"}})
        report = modelartifact.inspect_safetensors(path)
        self.assertEqual(report["tensor_count"], 1)
        self.assertEqual(report["problem_count"], 1)
        self.assertIn("bad", report["problems"][0])

    def test_a_zero_length_header_is_refused(self) -> None:
        path = Path(self.directory) / "z.safetensors"
        path.write_bytes(struct.pack("<Q", 0) + b"{}")
        report = modelartifact.inspect_safetensors(path)
        self.assertFalse(report["ok"])
        self.assertIn("zero", report["error"])

    def test_a_header_running_past_eof_is_refused(self) -> None:
        path = Path(self.directory) / "t.safetensors"
        path.write_bytes(struct.pack("<Q", 1000) + b"{}")
        report = modelartifact.inspect_safetensors(path)
        self.assertFalse(report["ok"])
        self.assertIn("past the end", report["error"])

    def test_non_json_header_is_refused(self) -> None:
        raw = b"not json at all"
        path = Path(self.directory) / "j.safetensors"
        path.write_bytes(struct.pack("<Q", len(raw)) + raw)
        report = modelartifact.inspect_safetensors(path)
        self.assertFalse(report["ok"])
        self.assertIn("not valid JSON", report["error"])


@unittest.skipUnless(REAL_GGUF.is_file(), "no real GGUF on this host")
class RealGgufTest(unittest.TestCase):
    def test_the_fixed_header_matches_an_independent_read(self) -> None:
        """Ground truth: unpack the 24-byte prefix with nothing from the module."""
        with REAL_GGUF.open("rb") as handle:
            magic, version, tensors, kvs = struct.unpack("<4sIQQ", handle.read(24))
        self.assertEqual(magic, b"GGUF")
        report = modelartifact.inspect_gguf(REAL_GGUF)
        self.assertTrue(report["ok"], report.get("error"))
        self.assertEqual(report["version"], version)
        self.assertEqual(report["tensor_count"], tensors)
        self.assertEqual(report["metadata_count"], kvs)

    def test_the_architecture_and_quantisation_are_named(self) -> None:
        report = modelartifact.inspect_gguf(REAL_GGUF)
        self.assertEqual(report["architecture"], "llama")
        self.assertIn("Q5_K", report["quantisations"])
        self.assertGreater(report["parameter_count"], 100_000_000)


@unittest.skipUnless(REAL_SAFETENSORS.is_file(), "no real safetensors on this host")
class RealSafetensorsTest(unittest.TestCase):
    def test_the_declared_header_length_is_honoured(self) -> None:
        with REAL_SAFETENSORS.open("rb") as handle:
            declared = struct.unpack("<Q", handle.read(8))[0]
            raw = handle.read(declared)
        independent = json.loads(raw)
        report = modelartifact.inspect_safetensors(REAL_SAFETENSORS)
        self.assertTrue(report["ok"], report.get("error"))
        self.assertEqual(report["header_bytes"], declared)
        self.assertEqual(report["tensor_count"], len(independent) - ("__metadata__" in independent))


class DetectionTest(unittest.TestCase):
    def test_a_non_model_file_is_refused(self) -> None:
        report = modelartifact.inspect("/etc/passwd")
        self.assertFalse(report["ok"])
        self.assertIn("not a GGUF or safetensors", report["error"])

    def test_a_missing_file_is_refused(self) -> None:
        self.assertFalse(modelartifact.inspect("/nonexistent/m.gguf")["ok"])

    def test_detection_routes_gguf_correctly(self) -> None:
        if not REAL_GGUF.is_file():
            self.skipTest("no real GGUF")
        self.assertEqual(modelartifact.inspect(REAL_GGUF)["format"], "gguf")

    def test_detection_routes_safetensors_correctly(self) -> None:
        if not REAL_SAFETENSORS.is_file():
            self.skipTest("no real safetensors")
        self.assertEqual(modelartifact.inspect(REAL_SAFETENSORS)["format"], "safetensors")

    def test_gpu_inspection_states_what_it_did_not_do(self) -> None:
        report = modelartifact.inspect_gpu_code("/bin/ls")
        self.assertTrue(report["ok"])
        self.assertIn("not decoded", report["note"])


if __name__ == "__main__":
    unittest.main()
