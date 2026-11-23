"""Tests for keyed archives, JVM/NuGet build metadata, and desktop bundles.

Every fixture is built here, so every expected value is chosen. Real files are used
where they exist (this host has genuine Maven poms), because a reader that only works
on its own fixtures has not been tested.

The three bugs these tests exist to catch:

  * An NSKeyedArchiver plist is a *graph* of UIDs into a flat object array. Printing
    the plist as-is shows `{'root': UID(1)}` — the reference is opaque, and the whole
    point of the reader is to resolve it. A resolver that forgets to pop the
    "currently resolving" set on exit treats every repeated reference as a cycle, and
    one that never pops it recurses until the stack dies.
  * Maven declares xmlns="http://maven.apache.org/POM/4.0.0", so every element tag
    carries that namespace. `root.find("groupId")` returns None on a *valid* pom, and
    all coordinates read as missing. The test asserts real coordinates from a real pom.
  * A `.app` bundle's executable lives at `Contents/MacOS/<CFBundleExecutable>`, never
    at the bundle root. Looking in the wrong place reports "no executable" for every
    real application.
"""
from __future__ import annotations

import json
import plistlib
import tempfile
import unittest
from pathlib import Path

from xtforge.core.re import packaging


def find_real_pom() -> Path | None:
    """A pom.xml with at least one <dependencies> block, searched without hardcoding."""
    for root in (Path.home() / "src", Path.home() / "projects", Path("/usr/share")):
        if not root.is_dir():
            continue
        try:
            for candidate in root.rglob("pom.xml"):
                try:
                    text = candidate.read_text("utf-8", "replace")
                except OSError:
                    continue
                # A parent/aggregator pom can contain <dependencies> only under
                # <dependencyManagement>; require a real top-level block so the
                # assertion is about a module that actually declares dependencies.
                if text.count("<dependencies>") > text.count("<dependencyManagement>"):
                    return candidate
        except OSError:
            continue
    return None


class KeyedArchiveTest(unittest.TestCase):
    def _write(self, directory: Path, archive: dict, fmt=plistlib.FMT_BINARY) -> Path:
        target = directory / "archive.plist"
        target.write_bytes(plistlib.dumps(archive, fmt=fmt))
        return target

    def _simple(self) -> dict:
        """NSDictionary{name: 'Widget', count: NSMutableString}."""
        return {
            "$archiver": "NSKeyedArchiver",
            "$version": 100000,
            "$top": {"root": plistlib.UID(1)},
            "$objects": [
                "$null",
                {"NS.keys": [plistlib.UID(2), plistlib.UID(3)],
                 "NS.objects": [plistlib.UID(4), plistlib.UID(5)],
                 "$class": plistlib.UID(6)},
                "name",
                "count",
                "Widget",
                {"$classname": "NSMutableString",
                 "$classes": ["NSMutableString", "NSString", "NSObject"]},
                {"$classname": "NSDictionary",
                 "$classes": ["NSDictionary", "NSObject"]},
            ],
        }

    def test_uids_are_resolved_into_values(self) -> None:
        """The root must come back as a dictionary with real keys and values.

        A reader that returns the raw plist reports `{'root': UID(1)}`, which answers
        nothing — the file's whole structure is behind that reference.
        """
        with tempfile.TemporaryDirectory() as tmp:
            report = packaging.inspect_keyed_archive(self._write(Path(tmp), self._simple()))
        self.assertTrue(report["ok"], report.get("error"))
        root = report["roots"]["root"]
        self.assertEqual(root["_class"], "NSDictionary")
        self.assertEqual(root["dict"]["name"], "Widget")

    def test_class_chains_are_reported(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            report = packaging.inspect_keyed_archive(self._write(Path(tmp), self._simple()))
        self.assertIn("NSDictionary", report["classes"])
        self.assertIn("NSMutableString", report["classes"])

    def test_object_and_class_counts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            report = packaging.inspect_keyed_archive(self._write(Path(tmp), self._simple()))
        self.assertEqual(report["object_count"], 7)
        self.assertEqual(report["class_count"], 2)

    def test_shared_reference_is_not_reported_as_a_cycle(self) -> None:
        """The same UID legitimately appears many times in a flat archive.

        A resolver that never removes entries from its "in progress" set reports the
        second use of a value as a cycle. Here one string object is referenced twice.
        """
        archive = {
            "$archiver": "NSKeyedArchiver", "$version": 100000,
            "$top": {"root": plistlib.UID(1)},
            "$objects": [
                "$null",
                {"NS.keys": [plistlib.UID(2), plistlib.UID(3)],
                 "NS.objects": [plistlib.UID(4), plistlib.UID(4)],
                 "$class": plistlib.UID(5)},
                "a", "b", "shared",
                {"$classname": "NSDictionary"},
            ],
        }
        with tempfile.TemporaryDirectory() as tmp:
            report = packaging.inspect_keyed_archive(self._write(Path(tmp), archive))
        mapping = report["roots"]["root"]["dict"]
        self.assertEqual(mapping["a"], "shared")
        self.assertEqual(mapping["b"], "shared")
        self.assertNotIn("_cycle", json.dumps(mapping))

    def test_true_cycle_is_reported_not_recursed(self) -> None:
        """An object that references itself must terminate, with a marker."""
        archive = {
            "$archiver": "NSKeyedArchiver", "$version": 100000,
            "$top": {"root": plistlib.UID(1)},
            "$objects": [
                "$null",
                {"NS.keys": [plistlib.UID(2)],
                 "NS.objects": [plistlib.UID(1)],
                 "$class": plistlib.UID(3)},
                "self", {"$classname": "NSDictionary"},
            ],
        }
        with tempfile.TemporaryDirectory() as tmp:
            report = packaging.inspect_keyed_archive(self._write(Path(tmp), archive))
        self.assertTrue(report["ok"], report.get("error"))
        self.assertIn("_cycle", json.dumps(report["roots"]))

    def test_plain_plist_is_rejected_with_a_pointer_to_the_right_verb(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "plain.plist"
            target.write_bytes(plistlib.dumps({"name": "not an archive"},
                                              fmt=plistlib.FMT_BINARY))
            report = packaging.inspect_keyed_archive(target)
        self.assertFalse(report["ok"])
        self.assertIn("$archiver", report["error"])

    def test_xml_archive_header_is_identified(self) -> None:
        """NSKeyedArchiver writes binary plists in practice.

        The XML property-list format cannot represent plistlib.UID at all — the writer
        raises TypeError — so a genuine keyed archive of a non-trivial graph is always
        binary. What matters is that a file which *looks* like an XML plist is
        identified as one and answered with a reason rather than a traceback.
        """
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "plain-xml.plist"
            target.write_bytes(plistlib.dumps({"$archiver": "NSKeyedArchiver",
                                               "$objects": ["$null"],
                                               "$top": {}},
                                              fmt=plistlib.FMT_XML))
            report = packaging.inspect_keyed_archive(target)
        self.assertTrue(report["ok"], report.get("error"))
        self.assertEqual(report["format"], "xml")


class JvmMetadataTest(unittest.TestCase):
    POM = """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <parent>
    <groupId>org.example</groupId>
    <artifactId>parent</artifactId>
    <version>9.9.9</version>
  </parent>
  <artifactId>child</artifactId>
  <dependencies>
    <dependency>
      <groupId>org.example</groupId>
      <artifactId>dep-one</artifactId>
      <version>1.2.3</version>
    </dependency>
    <dependency>
      <groupId>org.junit</groupId>
      <artifactId>junit-jupiter</artifactId>
      <version>5.10.0</version>
      <scope>test</scope>
    </dependency>
  </dependencies>
  <repositories>
    <repository><id>sketchy</id><url>https://evil.example/repo</url></repository>
  </repositories>
  <build><plugins><plugin>
    <groupId>org.apache.maven.plugins</groupId>
    <artifactId>maven-compiler-plugin</artifactId>
    <version>3.11.0</version>
  </plugin></plugins></build>
</project>
"""

    NUSPEC = """<?xml version="1.0"?>
<package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd">
  <metadata>
    <id>Example.Package</id>
    <version>4.5.6</version>
    <authors>Example Author</authors>
    <dependencies>
      <group targetFramework="net8.0">
        <dependency id="Newtonsoft.Json" version="13.0.3" />
      </group>
    </dependencies>
  </metadata>
</package>
"""

    def _write(self, directory: Path, text: str, name: str) -> Path:
        target = directory / name
        target.write_text(text)
        return target

    def test_namespaced_maven_coordinates_are_read(self) -> None:
        """The real xmlns makes `root.find('groupId')` return None.

        Every Maven pom declares a namespace, so a reader that ignores it finds no
        coordinates at all on valid input.
        """
        with tempfile.TemporaryDirectory() as tmp:
            report = packaging.inspect_jvm_metadata(
                self._write(Path(tmp), self.POM, "pom.xml"))
        self.assertTrue(report["ok"], report.get("error"))
        self.assertEqual(report["kind"], "maven")
        coords = report["coordinates"]
        self.assertEqual(coords["artifact"], "child")
        # groupId and version come from <parent> when the child omits them.
        self.assertEqual(coords["group"], "org.example")
        self.assertEqual(coords["version"], "9.9.9")

    def test_dependencies_and_scopes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            report = packaging.inspect_jvm_metadata(
                self._write(Path(tmp), self.POM, "pom.xml"))
        self.assertEqual(report["dependency_count"], 2)
        by_artifact = {d["artifact"]: d for d in report["dependencies"]}
        self.assertEqual(by_artifact["dep-one"]["scope"], "compile")
        self.assertEqual(by_artifact["junit-jupiter"]["scope"], "test")
        self.assertEqual(by_artifact["dep-one"]["version"], "1.2.3")

    def test_non_central_repository_is_surfaced(self) -> None:
        """A dependency resolved from an unfamiliar repository is the supply-chain
        signal this reader exists for, so it gets its own field."""
        with tempfile.TemporaryDirectory() as tmp:
            report = packaging.inspect_jvm_metadata(
                self._write(Path(tmp), self.POM, "pom.xml"))
        urls = [r["url"] for r in report.get("custom_repositories") or []]
        self.assertIn("https://evil.example/repo", urls)

    def test_plugins_are_listed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            report = packaging.inspect_jvm_metadata(
                self._write(Path(tmp), self.POM, "pom.xml"))
        artifacts = [p["artifact"] for p in report["plugins"]]
        self.assertIn("maven-compiler-plugin", artifacts)

    def test_nuspec_is_recognised_and_read(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            report = packaging.inspect_jvm_metadata(
                self._write(Path(tmp), self.NUSPEC, "Example.nuspec"))
        self.assertTrue(report["ok"], report.get("error"))
        self.assertEqual(report["kind"], "nuget")
        self.assertEqual(report["coordinates"]["id"], "Example.Package")
        self.assertEqual(report["coordinates"]["version"], "4.5.6")
        self.assertEqual(report["dependencies"][0]["id"], "Newtonsoft.Json")

    def test_gradle_module_metadata_is_json(self) -> None:
        document = {
            "formatVersion": "1.1",
            "component": {"group": "org.example", "module": "thing", "version": "1.0"},
            "variants": [{"name": "runtimeElements",
                          "dependencies": [{"group": "org.other", "module": "dep",
                                            "version": {"requires": "2.0"}}]}],
        }
        with tempfile.TemporaryDirectory() as tmp:
            report = packaging.inspect_jvm_metadata(
                self._write(Path(tmp), json.dumps(document), "module.json"))
        self.assertTrue(report["ok"], report.get("error"))
        self.assertEqual(report["kind"], "gradle-module")
        self.assertEqual(report["coordinates"]["module"], "thing")
        self.assertEqual(report["dependencies"][0]["version"], "2.0")

    def test_non_build_xml_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            report = packaging.inspect_jvm_metadata(
                self._write(Path(tmp), "<html><body/></html>", "page.xml"))
        self.assertFalse(report["ok"])

    def test_real_pom_on_this_host(self) -> None:
        """A genuine pom, so the reader is measured against reality, not just itself."""
        pom = find_real_pom()
        if pom is None:
            self.skipTest("no Maven pom.xml on this host")
        report = packaging.inspect_jvm_metadata(pom)
        self.assertTrue(report["ok"], report.get("error"))
        self.assertEqual(report["kind"], "maven")
        self.assertGreater(report["dependency_count"], 0)


class DesktopBundleTest(unittest.TestCase):
    def _build(self, directory: Path) -> Path:
        bundle = directory / "Test.app"
        (bundle / "Contents" / "MacOS").mkdir(parents=True)
        info = {
            "CFBundleIdentifier": "com.example.testapp",
            "CFBundleName": "TestApp",
            "CFBundleExecutable": "TestApp",
            "CFBundleShortVersionString": "2.1.0",
            "CFBundleVersion": "210",
            "CFBundlePackageType": "APPL",
            "LSMinimumSystemVersion": "13.0",
            "CFBundleURLTypes": [{"CFBundleURLName": "com.example.testapp.url",
                                  "CFBundleURLSchemes": ["testapp", "tx"]}],
            "CFBundleDocumentTypes": [{"CFBundleTypeName": "Test Doc",
                                       "CFBundleTypeRole": "Editor",
                                       "CFBundleTypeExtensions": ["txd"]}],
            "NSHighResolutionCapable": True,
        }
        (bundle / "Contents" / "Info.plist").write_bytes(
            plistlib.dumps(info, fmt=plistlib.FMT_BINARY))
        # A Mach-O magic plus padding: the bundle only needs a regular file here.
        (bundle / "Contents" / "MacOS" / "TestApp").write_bytes(b"\xcf\xfa\xed\xfe" + bytes(96))
        return bundle

    def test_identity_and_version(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            report = packaging.inspect_desktop_bundle(self._build(Path(tmp)))
        self.assertTrue(report["ok"], report.get("error"))
        self.assertEqual(report["identifier"], "com.example.testapp")
        self.assertEqual(report["version"], "2.1.0")
        self.assertEqual(report["build"], "210")
        self.assertEqual(report["plist_format"], "binary")

    def test_executable_is_found_inside_contents_macos(self) -> None:
        """CFBundleExecutable names a file in Contents/MacOS.

        The bundle directory itself is never executable, so looking for an executable
        at the bundle root reports "missing" for every real app.
        """
        with tempfile.TemporaryDirectory() as tmp:
            report = packaging.inspect_desktop_bundle(self._build(Path(tmp)))
        self.assertIn("executable", report)
        self.assertEqual(Path(report["executable"]).name, "TestApp")
        self.assertIn("MacOS", report["executable"])
        self.assertEqual(report["executable_size"], 100)

    def test_url_schemes_and_document_types(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            report = packaging.inspect_desktop_bundle(self._build(Path(tmp)))
        schemes = [s["scheme"] for s in report["url_schemes"]]
        self.assertEqual(schemes, ["testapp", "tx"])
        self.assertEqual(report["document_types"][0]["extensions"], ["txd"])

    def test_accepts_the_info_plist_directly(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            bundle = self._build(Path(tmp))
            report = packaging.inspect_desktop_bundle(
                bundle / "Contents" / "Info.plist")
        self.assertTrue(report["ok"], report.get("error"))
        self.assertEqual(report["identifier"], "com.example.testapp")
        self.assertEqual(Path(report["bundle"]).name, "Test.app")

    def test_missing_executable_is_a_warning_not_a_failure(self) -> None:
        """A bundle whose executable was deleted is still worth describing."""
        with tempfile.TemporaryDirectory() as tmp:
            bundle = self._build(Path(tmp))
            (bundle / "Contents" / "MacOS" / "TestApp").unlink()
            report = packaging.inspect_desktop_bundle(bundle)
        self.assertTrue(report["ok"], report.get("error"))
        self.assertIn("warning", report)
        self.assertNotIn("executable", report)

    def test_directory_without_contents_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            report = packaging.inspect_desktop_bundle(Path(tmp))
        self.assertFalse(report["ok"])


class DetectorTest(unittest.TestCase):
    def test_detects_each_kind(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive = root / "a.plist"
            archive.write_bytes(plistlib.dumps({
                "$archiver": "NSKeyedArchiver", "$version": 100000,
                "$top": {"root": plistlib.UID(1)},
                "$objects": ["$null", "hello"],
            }, fmt=plistlib.FMT_BINARY))
            self.assertTrue(packaging.inspect(archive)["ok"])

            pom = root / "pom.xml"
            pom.write_text('<project xmlns="http://maven.apache.org/POM/4.0.0">'
                           '<artifactId>x</artifactId></project>')
            self.assertEqual(packaging.inspect(pom).get("kind"), "maven")

    def test_unknown_content_is_rejected(self) -> None:
        report = packaging.inspect("/bin/ls")
        self.assertFalse(report["ok"])

    def test_random_bytes_never_raise(self) -> None:
        import random
        random.seed(5150)
        with tempfile.TemporaryDirectory() as tmp:
            for index in range(15):
                blob = Path(tmp) / f"r{index}.bin"
                blob.write_bytes(bytes(random.randrange(256)
                                       for _ in range(random.randint(0, 1500))))
                for reader in (packaging.inspect, packaging.inspect_keyed_archive,
                               packaging.inspect_jvm_metadata):
                    try:
                        reader(blob)
                    except Exception as exc:  # noqa: BLE001
                        self.fail(f"{reader.__name__} raised {type(exc).__name__}: {exc}")

    def test_missing_file_reports_not_raises(self) -> None:
        for reader in (packaging.inspect, packaging.inspect_keyed_archive,
                       packaging.inspect_jvm_metadata,
                       packaging.inspect_desktop_bundle):
            report = reader("/nonexistent/nothing")
            self.assertFalse(report["ok"])
            self.assertIn("error", report)


if __name__ == "__main__":
    unittest.main()
