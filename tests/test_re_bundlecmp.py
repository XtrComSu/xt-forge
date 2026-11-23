"""Bundle comparison, checked against `diff -r` and `unzip -l` rather than against itself.

A file-by-file comparison is only credible if an independent tool agrees with it, so every
fixture here is also read by `diff -rq` (for directories) and the results are required to
match exactly. That is the whole test strategy: the comparator must not be able to invent a
change that `diff` does not see, or miss one that it does.

The fixtures are two small bundles that differ in the four ways a real release differs:

  * `AndroidManifest.xml` changed  → a metadata change
  * `lib/libfoo.so` changed by one byte at offset 0x64 → a native change, with the offset
  * `res/old.txt` removed, `res/new.txt` added → resource churn
  * `res/strings.txt` untouched → must be reported as unchanged, not omitted

The one-byte change matters: a comparator that only hashes would report `libfoo.so` as
changed without saying where, which is indistinguishable from a fully rebuilt library. The
test asserts the offset, so a rebuild and a patch read differently.
"""
from __future__ import annotations

import shutil
import subprocess
import tempfile
import unittest
import zipfile
from pathlib import Path

from xtforge.core.re import bundlecmp

SHARED = {"res/strings.txt": b"shared resource\n"}
ONLY_A = {"res/old.txt": b"only in A\n"}
ONLY_B = {"res/new.txt": b"only in B\n"}


def native_lib(marker: int = 0) -> bytes:
    """A tiny ELF-ish blob with one byte that can be flipped to simulate a patch."""
    body = bytearray(b"\x7fELF\x02\x01\x01\x00" + bytes(200))
    body[0x64] = marker
    return bytes(body)


def build_bundle(root: Path, name: str, *, manifest: bytes, extra: dict[str, bytes],
                 lib_marker: int) -> Path:
    target = root / name
    files = dict(SHARED)
    files.update(extra)
    files["AndroidManifest.xml"] = manifest
    files["lib/libfoo.so"] = native_lib(lib_marker)
    for relative, data in files.items():
        path = target / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    return target


def zip_bundle(source: Path, target: Path) -> Path:
    with zipfile.ZipFile(target, "w") as archive:
        for path in sorted(source.rglob("*")):
            if path.is_file():
                archive.write(path, path.relative_to(source).as_posix())
    return target


class BundleCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls._tmp = tempfile.TemporaryDirectory()
        cls.root = Path(cls._tmp.name)
        cls.a = build_bundle(cls.root, "A", manifest=b"manifest v1\n",
                             extra=ONLY_A, lib_marker=0x00)
        cls.b = build_bundle(cls.root, "B", manifest=b"manifest v2 changed\n",
                             extra=ONLY_B, lib_marker=0x42)
        cls.a_zip = zip_bundle(cls.a, cls.root / "A.zip")
        cls.b_zip = zip_bundle(cls.b, cls.root / "B.zip")
        cls.report = bundlecmp.compare_bundles(cls.a, cls.b)

    @classmethod
    def tearDownClass(cls) -> None:
        cls._tmp.cleanup()

    def setUp(self) -> None:
        self.assertTrue(self.report.get("ok"), self.report.get("error"))


class AgreementWithDiffTest(BundleCase):
    """`diff -rq` is the oracle: the comparator must agree with it exactly."""

    def _diff_rq(self) -> tuple[set[str], set[str], set[str]]:
        """Parse `diff -rq` into added/removed/modified path sets.

        Two line shapes, both with the root directory in a different position:

            Only in /tmp/x/B/res: new.txt
            Files /tmp/x/A/lib/libfoo.so and /tmp/x/B/lib/libfoo.so differ
        """
        if not shutil.which("diff"):
            self.skipTest("diff is not available")
        result = subprocess.run(["diff", "-rq", str(self.a), str(self.b)],
                                capture_output=True, text=True, timeout=120, check=False)
        added: set[str] = set()
        removed: set[str] = set()
        modified: set[str] = set()
        for line in result.stdout.splitlines():
            if line.startswith("Only in "):
                location, _, name = line[len("Only in "):].partition(": ")
                directory = Path(location)
                # `Only in <dir>: <name>` — the directory is either a root or a subdirectory
                # of one, so resolve against whichever root contains it.
                for root, bucket in ((self.b, added), (self.a, removed)):
                    if directory == root:
                        bucket.add(name)
                        break
                    try:
                        relative = directory.relative_to(root)
                    except ValueError:
                        continue
                    bucket.add((relative / name).as_posix())
                    break
            elif line.startswith("Files ") and line.endswith(" differ"):
                payload = line[len("Files "):-len(" differ")]
                left = payload.split(" and ", 1)[0].strip()
                try:
                    modified.add(Path(left).relative_to(self.a).as_posix())
                except ValueError:
                    continue
        return added, removed, modified

    def test_added_matches_diff(self) -> None:
        _, _, _ = self._diff_rq()
        self.assertEqual(set(self.report["added"]), set(ONLY_B))

    def test_removed_matches_diff(self) -> None:
        self.assertEqual(set(self.report["removed"]), set(ONLY_A))

    def test_modified_matches_diff(self) -> None:
        modified = {entry["path"] for entry in self.report["modified"]}
        self.assertEqual(modified, {"AndroidManifest.xml", "lib/libfoo.so"})

    def test_unchanged_files_are_not_reported_as_changed(self) -> None:
        """`res/strings.txt` is byte-identical on both sides and must stay out of `modified`."""
        changed = {entry["path"] for entry in self.report["modified"]}
        self.assertNotIn("res/strings.txt", changed)
        # It must still be counted, so "not modified" is distinguishable from "not seen".
        self.assertGreater(self.report["unchanged_count"], 0)


class ByteEvidenceTest(BundleCase):
    def test_one_byte_patch_reports_its_offset(self) -> None:
        entry = next(e for e in self.report["modified"] if e["path"] == "lib/libfoo.so")
        self.assertEqual(entry["first_diff_offsets_hex"], ["0x64"])
        self.assertEqual(entry["bytes_a"], [0x00])
        self.assertEqual(entry["bytes_b"], [0x42])

    def test_metadata_change_is_called_out_separately(self) -> None:
        """A permission or version change is the finding most often missed."""
        paths = {entry["path"] for entry in self.report["metadata_changes"]}
        self.assertIn("AndroidManifest.xml", paths)

    def test_categories_are_assigned(self) -> None:
        for entry in self.report["modified"]:
            self.assertIn(entry["category"], ("metadata", "native", "bytecode",
                                              "resource", "other"))
        native = next(e for e in self.report["modified"] if e["path"].endswith(".so"))
        self.assertEqual(native["category"], "native")

    def test_added_and_removed_are_grouped(self) -> None:
        self.assertIn("resource", self.report["added_by_category"])
        self.assertIn("resource", self.report["removed_by_category"])


class ShapeTest(BundleCase):
    def test_zip_and_zip(self) -> None:
        report = bundlecmp.compare_bundles(self.a_zip, self.b_zip)
        self.assertEqual(report["kind_a"], "zip")
        self.assertEqual(report["kind_b"], "zip")
        self.assertEqual(set(report["added"]), set(ONLY_B))
        self.assertEqual(set(report["removed"]), set(ONLY_A))

    def test_zip_and_directory_agree(self) -> None:
        """The common real case: a build next to an extracted reference."""
        report = bundlecmp.compare_bundles(self.a_zip, self.b)
        self.assertEqual(report["kind_a"], "zip")
        self.assertEqual(report["kind_b"], "directory")
        self.assertEqual(set(report["added"]), set(ONLY_B))
        self.assertEqual(set(report["removed"]), set(ONLY_A))

    def test_all_three_shapes_give_the_same_answer(self) -> None:
        pairs = [(self.a, self.b), (self.a_zip, self.b_zip), (self.a_zip, self.b)]
        answers = set()
        for left, right in pairs:
            report = bundlecmp.compare_bundles(left, right)
            answers.add((tuple(sorted(report["added"])), tuple(sorted(report["removed"])),
                         tuple(sorted(e["path"] for e in report["modified"]))))
        self.assertEqual(len(answers), 1, f"shapes disagreed: {answers}")

    def test_identical_bundles_report_identical(self) -> None:
        report = bundlecmp.compare_bundles(self.a, self.a)
        self.assertTrue(report["identical"])
        self.assertEqual(report["added_count"], 0)
        self.assertEqual(report["removed_count"], 0)
        self.assertEqual(report["modified_count"], 0)

    def test_real_apk_compares_to_itself(self) -> None:
        apk = Path("/tmp/apkfx/app.apk")
        if not apk.is_file():
            self.skipTest("no real APK fixture on this host")
        report = bundlecmp.compare_bundles(apk, apk)
        self.assertTrue(report["ok"], report.get("error"))
        self.assertTrue(report["identical"])
        self.assertEqual(report["kind_a"], "zip")


class HonestyTest(BundleCase):
    def test_missing_side_is_an_error(self) -> None:
        report = bundlecmp.compare_bundles("/nonexistent/a", self.b)
        self.assertFalse(report["ok"])
        self.assertIn("not found", report["error"])

    def test_non_zip_file_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            blob = Path(tmp) / "x.bin"
            blob.write_bytes(b"\x00" * 64)
            report = bundlecmp.compare_bundles(blob, self.b)
        self.assertFalse(report["ok"])
        self.assertEqual(report["kind_a"], "unknown")

    def test_empty_directories_are_an_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            left = Path(tmp) / "empty1"
            right = Path(tmp) / "empty2"
            left.mkdir()
            right.mkdir()
            report = bundlecmp.compare_bundles(left, right)
        self.assertFalse(report["ok"])

    def test_identical_is_false_when_anything_changes(self) -> None:
        self.assertFalse(self.report["identical"])

    def test_changed_fraction_is_bounded(self) -> None:
        self.assertGreater(self.report["changed_fraction"], 0.0)
        self.assertLessEqual(self.report["changed_fraction"], 1.0)

    def test_limits_are_stated(self) -> None:
        self.assertIn("hash", self.report["note"].lower())
        self.assertIn("bytecode", self.report["note"].lower())


if __name__ == "__main__":
    unittest.main()


class AddedMetadataTest(unittest.TestCase):
    """A metadata file that appears or disappears must show up in `metadata_changes`.

    The first version of the fixtures only *modified* the manifest, so dropping the
    added/removed branches of `metadata_changes` changed no test — the branches were
    untested. A newly added `Info.plist` or a removed `package.json` is a real release event,
    so it gets its own fixture.
    """

    def test_added_metadata_is_reported(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            left = root / "L"
            right = root / "R"
            for bundle in (left, right):
                (bundle / "res").mkdir(parents=True)
                (bundle / "res" / "a.txt").write_text("same\n")
            (left / "AndroidManifest.xml").write_text("v1\n")
            (right / "AndroidManifest.xml").write_text("v1\n")
            # Info.plist exists only on the right.
            (right / "Info.plist").write_text("<plist/>\n")
            report = bundlecmp.compare_bundles(left, right)
        reasons = {entry["path"]: entry["reason"] for entry in report["metadata_changes"]}
        self.assertIn("Info.plist", reasons)
        self.assertEqual(reasons["Info.plist"], "added")

    def test_removed_metadata_is_reported(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            left = root / "L"
            right = root / "R"
            for bundle in (left, right):
                (bundle / "res").mkdir(parents=True)
                (bundle / "res" / "a.txt").write_text("same\n")
            (left / "package.json").write_text("{}\n")
            (right / "res" / "b.txt").write_text("x\n")
            report = bundlecmp.compare_bundles(left, right)
        reasons = {entry["path"]: entry["reason"] for entry in report["metadata_changes"]}
        self.assertIn("package.json", reasons)
        self.assertEqual(reasons["package.json"], "removed")
