"""Dependency discovery, vulnerability matching, and remediation.

The scenario these exist for: an engineer has a Go project on a specific version and wants to know
what is wrong with it. That means four things have to be right, and each is tested separately
because each fails differently:

  * the manifest is parsed for *versions*, not ranges — a range has no answer
  * version ordering follows SemVer, because a fix lands next to the versions it matters for
  * the advisory's own range decides the finding, not the server's package-level answer
  * an edit is verified by re-parsing, not by trusting the write

The version-ordering tests are checked against an independent implementation (Node's SemVer-spec
comparator and PEP 440's `packaging`) rather than against expectations I wrote from the same mental
model as the code — which is exactly how I got the pre-release rule wrong the first time.
"""
from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from xtforge.core import deps
from xtforge.core.deps import remediate, vulns


class GoModTest(unittest.TestCase):
    MOD = """module example.com/x

go 1.21

require (
\tgithub.com/gin-gonic/gin v1.6.0
\tgolang.org/x/text v0.3.0 // indirect
)

require github.com/pkg/errors v0.9.1

replace github.com/pkg/errors => github.com/pkg/errors v0.9.0
"""

    def test_both_require_forms_are_read(self) -> None:
        parsed = deps.parse_go_mod(self.MOD)
        names = {entry["name"] for entry in parsed}
        self.assertIn("github.com/gin-gonic/gin", names)
        self.assertIn("github.com/pkg/errors", names)

    def test_an_indirect_module_is_kept_and_marked(self) -> None:
        """Indirect modules are compiled into the binary, so they are still attack surface."""
        parsed = {entry["name"]: entry for entry in deps.parse_go_mod(self.MOD)}
        self.assertTrue(parsed["golang.org/x/text"]["indirect"])
        self.assertFalse(parsed["github.com/gin-gonic/gin"]["indirect"])

    def test_the_version_has_its_v_prefix_removed(self) -> None:
        parsed = {entry["name"]: entry for entry in deps.parse_go_mod(self.MOD)}
        self.assertEqual(parsed["github.com/gin-gonic/gin"]["version"], "1.6.0")

    def test_a_replace_directive_is_reported(self) -> None:
        """Reporting the required version when a replace overrides it names the wrong build."""
        parsed = {entry["name"]: entry for entry in deps.parse_go_mod(self.MOD)}
        replaced = parsed["github.com/pkg/errors"].get("replaced_by")
        self.assertIsNotNone(replaced)
        self.assertEqual(replaced["version"], "0.9.0")


class NpmTest(unittest.TestCase):
    def test_a_caret_range_is_not_a_version(self) -> None:
        """`^1.3.0` could be any of hundreds of versions; only an exact spec resolves."""
        parsed = {entry["name"]: entry
                  for entry in deps.parse_package_json(json.dumps({
                      "dependencies": {"left-pad": "^1.3.0", "pinned": "1.2.3",
                                       "tilded": "~2.0.0", "gte": ">=1.0.0 <2.0.0"}}))}
        self.assertFalse(parsed["left-pad"]["resolved"])
        self.assertTrue(parsed["pinned"]["resolved"])
        self.assertFalse(parsed["tilded"]["resolved"])
        self.assertFalse(parsed["gte"]["resolved"])

    def test_dev_dependencies_are_scoped(self) -> None:
        parsed = deps.parse_package_json(json.dumps({
            "dependencies": {"a": "1.0.0"}, "devDependencies": {"b": "2.0.0"}}))
        scopes = {entry["name"]: entry["scope"] for entry in parsed}
        self.assertEqual(scopes["a"], "runtime")
        self.assertEqual(scopes["b"], "dev")

    def test_a_lockfile_v2_packages_map_resolves(self) -> None:
        parsed = deps.parse_package_lock(json.dumps({
            "lockfileVersion": 3,
            "packages": {"": {"name": "root"},
                         "node_modules/lodash": {"version": "4.17.15"},
                         "node_modules/a/node_modules/lodash": {"version": "4.17.21"}}}))
        versions = sorted(entry["version"] for entry in parsed)
        self.assertEqual(versions, ["4.17.15", "4.17.21"],
                         "two copies of one package at two versions are two findings")

    def test_a_lockfile_v1_tree_resolves(self) -> None:
        parsed = deps.parse_package_lock(json.dumps({
            "dependencies": {"lodash": {"version": "4.17.15"}}}))
        self.assertEqual(parsed[0]["version"], "4.17.15")
        self.assertTrue(parsed[0]["resolved"])

    def test_broken_json_is_reported_not_swallowed(self) -> None:
        with self.assertRaises(deps.DependencyError):
            deps.parse_package_json("{not json")


class PythonManifestTest(unittest.TestCase):
    def test_exact_pin_resolves_and_range_does_not(self) -> None:
        parsed = {entry["name"]: entry for entry in deps.parse_requirements(
            "requests==2.31.0\nflask>=2.0.0\nurllib3==1.26.*\n")}
        self.assertTrue(parsed["requests"]["resolved"])
        self.assertFalse(parsed["flask"]["resolved"])
        self.assertFalse(parsed["urllib3"]["resolved"], "a wildcard pin is not a version")

    def test_extras_and_markers_are_stripped(self) -> None:
        parsed = deps.parse_requirements('requests[security]==2.31.0 ; python_version >= "3.8"\n')
        self.assertEqual(parsed[0]["name"], "requests")
        self.assertEqual(parsed[0]["version"], "2.31.0")

    def test_an_include_is_reported_rather_than_followed(self) -> None:
        """Following `-r` can leave the tree entirely, so it is surfaced, not chased."""
        parsed = deps.parse_requirements("-r other.txt\nrequests==2.31.0\n")
        self.assertTrue(any(entry.get("include") for entry in parsed))

    def test_pyproject_pep621_dependencies(self) -> None:
        parsed = deps.parse_pyproject(
            '[project]\nname="x"\ndependencies=["requests==2.31.0","flask>=2.0"]\n')
        names = {entry["name"] for entry in parsed}
        self.assertEqual(names, {"requests", "flask"})


class CargoTest(unittest.TestCase):
    def test_table_forms_and_renames(self) -> None:
        parsed = deps.parse_cargo_toml(
            '[dependencies]\nserde = "1.0.0"\n'
            '[dependencies.tokio]\nversion = "1.20.0"\nfeatures = ["full"]\n')
        by_name = {entry["name"]: entry for entry in parsed}
        self.assertEqual(by_name["serde"]["version"], "1.0.0")
        self.assertEqual(by_name["tokio"]["version"], "1.20.0")
        self.assertEqual(by_name["tokio"]["features"], ["full"])

    def test_cargo_lock_pairs_name_with_version(self) -> None:
        parsed = deps.parse_cargo_lock(
            '[[package]]\nname = "serde"\nversion = "1.0.100"\n'
            '[[package]]\nname = "tokio"\nversion = "1.20.0"\n')
        pairs = {(entry["name"], entry["version"]) for entry in parsed}
        self.assertIn(("serde", "1.0.100"), pairs)
        self.assertIn(("tokio", "1.20.0"), pairs)


class MavenTest(unittest.TestCase):
    def test_a_dependency_without_groupid_inherits_the_pom_group(self) -> None:
        parsed = reparse_pom = deps.parse_pom(
            '<project xmlns="http://maven.apache.org/POM/4.0.0">'
            "<groupId>com.example</groupId><artifactId>app</artifactId>"
            "<dependencies><dependency><artifactId>lib</artifactId>"
            "<version>1.2.3</version></dependency></dependencies></project>")
        self.assertEqual(parsed[0]["name"], "com.example:lib")

    def test_a_property_is_resolved_when_defined(self) -> None:
        parsed = deps.parse_pom(
            '<project><groupId>g</groupId><properties><v>1.2.3</v></properties>'
            "<dependencies><dependency><artifactId>a</artifactId>"
            "<version>${v}</version></dependency></dependencies></project>")
        self.assertEqual(parsed[0]["version"], "1.2.3")
        self.assertTrue(parsed[0]["resolved"])

    def test_an_undefined_property_stays_unresolved(self) -> None:
        """Printing `${nope}` as a version would produce a lookup that silently finds nothing."""
        parsed = deps.parse_pom(
            '<project><groupId>g</groupId><dependencies><dependency>'
            "<artifactId>a</artifactId><version>${nope}</version></dependency>"
            "</dependencies></project>")
        self.assertFalse(parsed[0]["resolved"])


class VersionOrderTest(unittest.TestCase):
    def test_numeric_segments_compare_numerically(self) -> None:
        self.assertEqual(vulns.compare("1.10.0", "1.9.0"), 1)

    def test_a_prerelease_precedes_its_release(self) -> None:
        self.assertEqual(vulns.compare("2.0.0-rc1", "2.0.0"), -1)
        self.assertEqual(vulns.compare("2.0.0", "2.0.0-rc1"), 1)

    def test_alphanumeric_prerelease_identifiers_compare_lexically(self) -> None:
        """SemVer §11: identifiers with letters compare in ASCII order, so rc2 > rc10.

        I first asserted the opposite and treated the failure as a bug, then checked Node's
        spec-compliant comparator, which returns 1 for `rc2` vs `rc10` and -1 for `rc.2` vs
        `rc.10`. The distinction is whether the identifier is numeric, and this test pins both
        halves so the rule cannot drift.
        """
        self.assertEqual(vulns.compare("1.0.0-rc2", "1.0.0-rc10"), 1)
        self.assertEqual(vulns.compare("1.0.0-rc.2", "1.0.0-rc.10"), -1)

    def test_an_equals_and_a_v_prefix_are_ignored(self) -> None:
        self.assertEqual(vulns.compare("v1.2.3", "1.2.3"), 0)
        self.assertEqual(vulns.compare("=1.2.3", "1.2.3"), 0)

    def test_build_metadata_does_not_affect_order(self) -> None:
        self.assertEqual(vulns.compare("1.2.3+build", "1.2.3"), 0)


class RangeTest(unittest.TestCase):
    def test_a_version_below_the_fix_is_inside(self) -> None:
        verdict = vulns.range_contains(
            [{"introduced": "0"}, {"fixed": "1.9.0"}], "1.6.0")
        self.assertTrue(verdict["match"])

    def test_a_version_at_the_fix_is_outside(self) -> None:
        """`fixed` closes the range exclusively; the fix version is not vulnerable."""
        verdict = vulns.range_contains(
            [{"introduced": "0"}, {"fixed": "1.9.0"}], "1.9.0")
        self.assertFalse(verdict["match"])

    def test_a_version_above_the_fix_is_outside(self) -> None:
        verdict = vulns.range_contains(
            [{"introduced": "0"}, {"fixed": "1.9.0"}], "1.10.0")
        self.assertFalse(verdict["match"])

    def test_a_zero_fix_means_never_fixed(self) -> None:
        """`fixed: 0` must not close the range, or every unfixed advisory reads as clean."""
        verdict = vulns.range_contains(
            [{"introduced": "0"}, {"fixed": "0"}], "5.0.0")
        self.assertTrue(verdict["match"])

    def test_last_affected_is_inclusive(self) -> None:
        self.assertTrue(vulns.range_contains(
            [{"introduced": "1.0.0"}, {"last_affected": "1.5.0"}], "1.5.0")["match"])
        self.assertFalse(vulns.range_contains(
            [{"introduced": "1.0.0"}, {"last_affected": "1.5.0"}], "1.5.1")["match"])

    def test_two_ranges_on_two_branches(self) -> None:
        """An advisory listing a fix per branch is where a naive and/or test fails."""
        events = [{"introduced": "0"}, {"fixed": "1.9.0"},
                  {"introduced": "2.0.0"}, {"fixed": "2.1.0"}]
        self.assertTrue(vulns.range_contains(events, "1.6.0")["match"])
        self.assertFalse(vulns.range_contains(events, "1.9.5")["match"])
        self.assertTrue(vulns.range_contains(events, "2.0.5")["match"])
        self.assertFalse(vulns.range_contains(events, "2.1.0")["match"])

    def test_an_unorderable_version_does_not_raise(self) -> None:
        verdict = vulns.range_contains([{"introduced": "0"}, {"fixed": "1.0"}], "")
        self.assertFalse(verdict["match"])


class DedupeTest(unittest.TestCase):
    """One bug published under three identifiers is one finding.

    Measured against the real API: `golang.org/x/text 0.3.0` returns 8 advisories that are 5
    vulnerabilities, because `GHSA-5rcv-m4m3-hfh7`, `CVE-2020-14040` and `GO-2020-0015` are the
    same bug. Reporting all three triples the headline number and adds nothing.
    """

    def test_alias_linked_advisories_collapse(self) -> None:
        merged = vulns.dedupe([
            {"id": "GHSA-1", "aliases": ["CVE-2020-1", "GO-1"], "severity": "HIGH",
             "fixed_in": ["1.0.1"]},
            {"id": "CVE-2020-1", "aliases": ["GHSA-1", "GO-1"], "severity": "MODERATE",
             "fixed_in": ["1.0.1"]},
            {"id": "GO-1", "aliases": ["CVE-2020-1"], "severity": "HIGH", "fixed_in": ["1.0.1"]},
        ])
        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0]["id"], "CVE-2020-1", "the CVE should be the display id")
        self.assertEqual(len(merged[0]["merged_advisories"]), 3)

    def test_the_worst_severity_survives_the_merge(self) -> None:
        """A bug assessed HIGH by one database and MODERATE by another is a HIGH finding."""
        merged = vulns.dedupe([
            {"id": "GHSA-1", "aliases": ["CVE-1"], "severity": "MODERATE", "fixed_in": []},
            {"id": "CVE-1", "aliases": [], "severity": "HIGH", "fixed_in": []},
        ])
        self.assertEqual(merged[0]["severity"], "HIGH")

    def test_one_way_aliases_still_group(self) -> None:
        """Aliases are not symmetric in general, so grouping cannot rely on both listing each
        other."""
        merged = vulns.dedupe([
            {"id": "A", "aliases": ["B"], "severity": "LOW", "fixed_in": []},
            {"id": "B", "aliases": [], "severity": "LOW", "fixed_in": []},
        ])
        self.assertEqual(len(merged), 1)

    def test_distinct_vulnerabilities_are_not_merged(self) -> None:
        merged = vulns.dedupe([
            {"id": "GHSA-1", "aliases": [], "severity": "HIGH", "fixed_in": []},
            {"id": "GHSA-2", "aliases": [], "severity": "LOW", "fixed_in": []},
        ])
        self.assertEqual(len(merged), 2)


class DiscoveryTreeTest(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = Path(tempfile.mkdtemp(prefix="xtdeps-"))

    def tearDown(self) -> None:
        shutil.rmtree(self.directory, ignore_errors=True)

    def test_node_modules_is_not_walked(self) -> None:
        """Walking it turns a five-second inventory into a five-minute one and adds noise."""
        nested = self.directory / "node_modules" / "x"
        nested.mkdir(parents=True)
        (nested / "package.json").write_text('{"dependencies":{"a":"1.0.0"}}')
        (self.directory / "package.json").write_text('{"dependencies":{"b":"2.0.0"}}')
        report = deps.discover(self.directory)
        self.assertEqual(report["manifest_count"], 1)

    def test_a_broken_manifest_makes_the_report_incomplete(self) -> None:
        (self.directory / "package.json").write_text("{ broken")
        report = deps.discover(self.directory)
        self.assertFalse(report["complete"], "a parse failure must not read as a clean tree")
        self.assertTrue(report["errors"])

    def test_a_missing_path_is_refused(self) -> None:
        report = deps.discover("/nonexistent/path/xyz")
        self.assertFalse(report["ok"])

    def test_the_same_package_at_two_versions_is_two_findings(self) -> None:
        (self.directory / "go.mod").write_text(
            "module x\n\nrequire (\n\ta.example.com/m v1.0.0\n)\n")
        nested = self.directory / "sub"
        nested.mkdir()
        (nested / "go.mod").write_text(
            "module y\n\nrequire (\n\ta.example.com/m v1.2.0\n)\n")
        report = deps.discover(self.directory)
        versions = sorted(entry["version"] for entry in report["dependencies"])
        self.assertEqual(versions, ["1.0.0", "1.2.0"])

    def test_provenance_is_recorded_per_dependency(self) -> None:
        (self.directory / "requirements.txt").write_text("requests==2.31.0\n")
        report = deps.discover(self.directory)
        self.assertTrue(report["dependencies"][0]["sources"])


class BinaryToolchainTest(unittest.TestCase):
    def test_a_go_buildinfo_blob_is_recognised(self) -> None:
        """The deployed truth: what is compiled in, not what a manifest in the tree says."""
        # The real format, copied from `go version -m` on a binary built on this host:
        #   dep	github.com/google/uuid	v1.3.0	h1:t6Ji...
        # My first fixture invented a concatenated form and then a regex to split it, which
        # reported one fictional module instead of two real ones.
        blob = (b"\x00\x00go1.21.5\x00"
                b"dep\tgithub.com/gin-gonic/gin\tv1.6.0\th1:abc=\n"
                b"dep\tgithub.com/stretchr/testify\tv1.8.0\th1:def=\n")
        found = deps.detect_binary_toolchains(blob)
        self.assertEqual(found["toolchains"][0]["version"], "1.21.5")
        names = {module["name"] for module in found["embedded_modules"]}
        self.assertIn("github.com/gin-gonic/gin", names)
        self.assertIn("github.com/stretchr/testify", names,
                      "both modules must be found, not one merged fiction")
        versions = {module["name"]: module["version"]
                    for module in found["embedded_modules"]}
        self.assertEqual(versions["github.com/stretchr/testify"], "1.8.0")

    def test_ordinary_prose_does_not_match(self) -> None:
        found = deps.detect_binary_toolchains(b"this is just a text file with no versions")
        self.assertEqual(found["embedded_modules"], [])


class RemediationTest(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = Path(tempfile.mkdtemp(prefix="xtrem-"))
        self.mod = self.directory / "go.mod"
        self.mod.write_text("module example.com/x\n\nrequire (\n"
                            "\tgithub.com/gin-gonic/gin v1.6.0\n"
                            "\tgolang.org/x/text v0.3.0\n)\n")

    def tearDown(self) -> None:
        shutil.rmtree(self.directory, ignore_errors=True)

    def _plan(self, ecosystem="Go", name="github.com/gin-gonic/gin", current="1.6.0",
              fixed=None, **kwargs) -> dict:
        dependencies = [{"ecosystem": ecosystem, "name": name, "version": current,
                         "resolved": True, "sources": [{"path": str(self.mod),
                                                        "kind": "go"}]}]
        findings = [{"ecosystem": ecosystem, "name": name, "version": current,
                     "worst_severity": "HIGH",
                     "vulnerabilities": [{"id": "GHSA-x", "fixed_in": fixed or ["1.7.7"]}]}]
        return remediate.plan(dependencies, findings, **kwargs)

    def test_the_lowest_qualifying_fix_is_chosen(self) -> None:
        """Raising further than necessary widens the change for no security benefit."""
        plan = self._plan(fixed=["1.9.0", "1.7.7", "1.8.0"])
        self.assertEqual(plan["edits"][0]["to"], "1.7.7")

    def test_a_fix_below_the_installed_version_is_not_proposed(self) -> None:
        plan = self._plan(fixed=["1.0.0"])
        self.assertEqual(plan["edit_count"], 0)
        self.assertTrue(plan["skipped"])

    def test_a_major_bump_is_refused_without_the_flag(self) -> None:
        """A major bump usually needs source changes; proposing it unasked breaks builds."""
        plan = self._plan(current="1.6.0", fixed=["2.0.0"])
        self.assertEqual(plan["edit_count"], 0)
        self.assertIn("major", " ".join(entry["reason"] for entry in plan["skipped"]))

    def test_a_major_bump_is_proposed_with_the_flag(self) -> None:
        plan = self._plan(current="1.6.0", fixed=["2.0.0"], allow_major=True)
        self.assertEqual(plan["edits"][0]["to"], "2.0.0")

    def test_planning_writes_nothing(self) -> None:
        before = self.mod.read_text()
        self._plan()
        self.assertEqual(self.mod.read_text(), before)

    def test_a_dry_run_assembles_the_edit_without_writing(self) -> None:
        before = self.mod.read_text()
        plan = self._plan()
        report = remediate.apply(plan["edits"], write=False)
        self.assertTrue(report["ok"], report.get("failures"))
        self.assertEqual(self.mod.read_text(), before, "a dry run wrote to the file")

    def test_a_write_lands_and_is_verified_by_reparsing(self) -> None:
        plan = self._plan()
        report = remediate.apply(plan["edits"], write=True)
        self.assertTrue(report["ok"], report.get("failures"))
        self.assertIn("v1.7.7", self.mod.read_text())
        self.assertEqual(report["verified"][0]["verified_by"], "reparse")

    def test_the_original_is_backed_up(self) -> None:
        plan = self._plan()
        remediate.apply(plan["edits"], write=True, backup=True)
        self.assertIn("v1.6.0", (self.directory / "go.mod.xtbak").read_text())

    def test_a_name_that_is_a_prefix_of_another_is_not_edited(self) -> None:
        """`gin` inside `gin-gonic` must not be touched by a fix for `gin`."""
        self.mod.write_text("module x\n\nrequire (\n\tgithub.com/gin v1.6.0\n"
                            "\tgithub.com/gin-gonic/gin v1.6.0\n)\n")
        dependencies = [{"ecosystem": "Go", "name": "github.com/gin", "version": "1.6.0",
                         "resolved": True, "sources": [{"path": str(self.mod)}]}]
        findings = [{"ecosystem": "Go", "name": "github.com/gin", "version": "1.6.0",
                     "worst_severity": "HIGH",
                     "vulnerabilities": [{"id": "x", "fixed_in": ["1.7.0"]}]}]
        plan = remediate.plan(dependencies, findings, allow_major=True)
        remediate.apply(plan["edits"], write=True)
        text = self.mod.read_text()
        self.assertIn("github.com/gin v1.7.0", text)
        self.assertIn("gin-gonic/gin v1.6.0", text, "the longer name was edited too")

    def test_an_unfindable_version_fails_loudly(self) -> None:
        plan = self._plan()
        plan["edits"][0]["from"] = "9.9.9"
        report = remediate.apply(plan["edits"], write=True)
        self.assertFalse(report["ok"])
        self.assertIn("v1.6.0", self.mod.read_text())

    def test_a_missing_file_fails_cleanly(self) -> None:
        report = remediate.apply([{"ecosystem": "Go", "name": "x", "from": "1", "to": "2",
                                   "path": "/nonexistent/go.mod"}])
        self.assertFalse(report["ok"])

    def test_requirements_rewriter_touches_only_the_pin(self) -> None:
        target = self.directory / "requirements.txt"
        target.write_text("requests==2.0.0\nflask==2.0.0\n")
        edit = {"ecosystem": "PyPI", "name": "requests", "from": "2.0.0", "to": "2.31.0",
                "path": str(target)}
        report = remediate.apply([edit], write=True)
        self.assertTrue(report["ok"], report.get("failures"))
        text = target.read_text()
        self.assertIn("requests==2.31.0", text)
        self.assertIn("flask==2.0.0", text)

    def test_package_json_stays_valid_after_an_edit(self) -> None:
        target = self.directory / "package.json"
        target.write_text(json.dumps({"dependencies": {"lodash": "4.17.15"}}, indent=2))
        edit = {"ecosystem": "npm", "name": "lodash", "from": "4.17.15", "to": "4.17.21",
                "path": str(target)}
        report = remediate.apply([edit], write=True)
        self.assertTrue(report["ok"], report.get("failures"))
        payload = json.loads(target.read_text())
        self.assertEqual(payload["dependencies"]["lodash"], "4.17.21")


if __name__ == "__main__":
    unittest.main()
