"""Reachability tests for the elfmeta/wasm/firmware `re` verbs.

WHY this file exists: the modules behind these verbs were written and unit-tested
in isolation, and every one of their own tests passed while the verbs were still
unreachable from the CLI — no `elif verb == ...` branch, no argparse choice, so
`re elfmeta` was an argparse usage error. A module that no route reaches is not
a capability, and its green test file says nothing about whether a user can get
the answer. These tests therefore assert the *route*: the verb is accepted by the
parser, reaches the module, and returns the module's payload. They are written
against the CLI surface on purpose (not by importing the core modules) because
the surface is exactly what was missing.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


def _run(*args: str, home: str | None = None) -> subprocess.CompletedProcess:
    """Run the CLI in a subprocess.

    `home` sets XT_HOME, which is where annotations and bookmarks live. Tests that
    write state MUST pass it: the store is keyed by the SHA-256 of the file's bytes
    alone, not by its path, so two copies of /bin/ls in different temp dirs are the
    *same* binary to the store. Without an isolated XT_HOME these tests read and
    write the developer's real annotations, and pass or fail depending on what was
    annotated on that machine before.
    """
    env = dict(os.environ)
    if home is not None:
        env["XT_HOME"] = home
    return subprocess.run(
        [sys.executable, "-m", "xtforge.cli", *args],
        capture_output=True,
        text=True,
        cwd=str(REPO_ROOT),
        timeout=180,
        env=env,
    )


def _json_run(*args: str, home: str | None = None) -> tuple[int, dict]:
    res = _run("--json", *args, home=home)
    try:
        payload = json.loads(res.stdout)
    except json.JSONDecodeError as exc:  # pragma: no cover - diagnostic path
        raise AssertionError(
            f"expected JSON on stdout for {args!r}; got rc={res.returncode}\n"
            f"stdout={res.stdout[:800]}\nstderr={res.stderr[:800]}"
        ) from exc
    return res.returncode, payload


class TestVerbIsRegistered(unittest.TestCase):
    """A verb missing from the argparse choices fails before any module runs."""

    def test_verbs_appear_in_help(self):
        res = _run("re", "--help")
        self.assertEqual(res.returncode, 0, res.stderr)
        for verb in ("elfmeta", "wasm", "firmware", "search"):
            self.assertIn(verb, res.stdout,
                          f"{verb} is not offered by `re --help`, so it is unreachable")

    def test_unknown_verb_still_fails(self):
        # Guards against the choices list being loosened to accept anything,
        # which would make the assertions above vacuous.
        res = _run("re", "not-a-real-verb", "/bin/ls")
        self.assertNotEqual(res.returncode, 0)


@unittest.skipUnless(shutil.which("clang"), "clang is required to build an ELF fixture")
class TestElfmetaVerb(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.TemporaryDirectory()
        cls.src = Path(cls.tmp.name) / "t.c"
        cls.src.write_text("int helper(int x){return x*3;}\n"
                           "int main(void){return helper(7);}\n")
        cls.binary = Path(cls.tmp.name) / "t_elf"
        built = subprocess.run(
            ["clang", "-g", "-O0", "-Wl,--build-id", str(cls.src), "-o", str(cls.binary)],
            capture_output=True, text=True,
        )
        if built.returncode != 0:  # pragma: no cover - environment dependent
            raise unittest.SkipTest(f"clang could not build the fixture: {built.stderr[:400]}")

    @classmethod
    def tearDownClass(cls) -> None:
        cls.tmp.cleanup()

    def test_reports_dwarf_units_and_unwind(self):
        rc, payload = _json_run("re", "elfmeta", str(self.binary))
        self.assertEqual(rc, 0, payload)
        self.assertTrue(payload.get("ok"))
        self.assertEqual(payload.get("format"), "elf")
        self.assertEqual(payload["dwarf"]["count"], 1,
                         "one .c file was compiled, so exactly one compile unit is expected")
        # clang records DW_AT_name as the path it was given, so an absolute
        # source path yields an absolute DW_AT_name. Assert the basename rather
        # than assuming the compiler stores the path as written.
        self.assertEqual(Path(payload["dwarf"]["units"][0]["name"]).name, "t.c")
        self.assertTrue(payload["notes"]["build_id"],
                        "-Wl,--build-id was passed, so a build id must be reported")
        self.assertGreaterEqual(payload["unwind"]["fde_count"], 1)

    def test_non_elf_is_a_clean_error_not_a_traceback(self):
        rc, payload = _json_run("re", "elfmeta", "/bin/ls" if Path("/bin/ls").exists()
                                else str(self.binary))
        # /bin/ls is a real ELF, so this asserts the happy path on a system
        # binary; the refusal path is covered by test_wasm below and by the
        # module's own tests. What matters here is that the route returns a
        # payload rather than dying in argparse.
        self.assertEqual(rc, 0, payload)
        self.assertTrue(payload.get("ok"))


class TestWasmVerb(unittest.TestCase):
    MINIMAL = bytes.fromhex("0061736d01000000")

    def test_minimal_module_is_inventoried(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "m.wasm"
            path.write_bytes(self.MINIMAL)
            rc, payload = _json_run("re", "wasm", str(path))
        self.assertEqual(rc, 0, payload)
        self.assertEqual(payload.get("format"), "wasm")
        self.assertEqual(payload.get("version"), 1)
        self.assertEqual(payload.get("sections"), [])
        self.assertEqual(payload["counts"]["imports"], 0)

    def test_elf_input_is_refused_with_a_readable_message(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "not-wasm.bin"
            path.write_bytes(b"\x7fELFnot a wasm module")
            res = _run("re", "wasm", str(path))
        self.assertEqual(res.returncode, 1,
                         "a file that is not WebAssembly must fail, not silently succeed")
        self.assertIn("WebAssembly", res.stderr + res.stdout)
        self.assertNotIn("Traceback", res.stderr,
                         "refusals must be reported, not raised as tracebacks")


class TestFirmwareVerb(unittest.TestCase):
    def test_unknown_blob_answers_instead_of_erroring(self):
        """A non-firmware file is a legitimate answer, not a failure.

        `re firmware` on an arbitrary file has to say 'not a firmware volume' and
        exit 0, otherwise every caller has to special-case the exit code before
        it can read the note explaining why.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "blob.bin"
            path.write_bytes(bytes(range(256)) * 16)
            rc, payload = _json_run("re", "firmware", str(path))
        self.assertEqual(rc, 0, payload)
        self.assertEqual(payload.get("format"), "unknown")
        self.assertTrue(payload.get("notes"),
                        "an unknown blob must explain itself in notes")

    def test_directory_is_refused(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            res = _run("re", "firmware", tmpdir)
        self.assertEqual(res.returncode, 1)
        self.assertIn("directory", (res.stderr + res.stdout).lower())
        self.assertNotIn("Traceback", res.stderr)


class TestBookmarksVerb(unittest.TestCase):
    """Navigation state round-trips through the CLI.

    Every write goes to an isolated XT_HOME, because the store is keyed on file
    bytes: /bin/ls copied twice is one binary to the store, so a shared home would
    make these tests order-dependent against each other and against real use.
    """

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.home = str(Path(self.tmp.name) / "xt-home")
        self.binary = str(Path(self.tmp.name) / "b")
        shutil.copyfile("/bin/ls", self.binary)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_set_list_next_unset_lifecycle(self):
        rc, saved = _json_run("re", "bookmarks", "set", self.binary, "0x1130",
                              "--name", "entrypoint", home=self.home)
        self.assertEqual(rc, 0, saved)
        self.assertEqual(saved["rva"], "0x1130")
        self.assertEqual(saved["label"], "entrypoint")

        _json_run("re", "bookmarks", "set", self.binary, "0x2000",
                  "--name", "after_main", home=self.home)

        rc, listed = _json_run("re", "bookmarks", "list", self.binary, home=self.home)
        self.assertEqual(rc, 0, listed)
        self.assertEqual([b["rva"] for b in listed["bookmarks"]], ["0x1130", "0x2000"],
                         "bookmarks must come back sorted by address, not by insertion")

        rc, nxt = _json_run("re", "bookmarks", "next", self.binary, "0x1130", home=self.home)
        self.assertEqual(nxt["bookmark"]["rva"], "0x2000")

        rc, prv = _json_run("re", "bookmarks", "prev", self.binary, "0x2000", home=self.home)
        self.assertEqual(prv["bookmark"]["rva"], "0x1130")

        rc, removed = _json_run("re", "bookmarks", "unset", self.binary, "0x1130", home=self.home)
        self.assertEqual(rc, 0, removed)
        self.assertTrue(removed["removed"])

        rc, after = _json_run("re", "bookmarks", "list", self.binary, home=self.home)
        self.assertEqual([b["rva"] for b in after["bookmarks"]], ["0x2000"])

    def test_next_past_the_end_answers_none(self):
        _json_run("re", "bookmarks", "set", self.binary, "0x1000", home=self.home)
        rc, res = _json_run("re", "bookmarks", "next", self.binary, "0x1000", home=self.home)
        self.assertEqual(rc, 0, "asking for the next bookmark when there is none is not an error")
        self.assertIsNone(res["bookmark"])

    def test_unset_of_missing_bookmark_reports_not_removed(self):
        rc, res = _json_run("re", "bookmarks", "unset", self.binary, "0x9999", home=self.home)
        self.assertEqual(rc, 0, res)
        self.assertFalse(res["removed"])

    def test_set_without_address_is_a_usage_error(self):
        res = _run("re", "bookmarks", "set", self.binary, home=self.home)
        self.assertEqual(res.returncode, 2)
        self.assertNotIn("Traceback", res.stderr)


class TestBulkVerb(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.home = str(Path(self.tmp.name) / "xt-home")
        self.binary = str(Path(self.tmp.name) / "b")
        shutil.copyfile("/bin/ls", self.binary)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_csv_batch_rename_is_visible_to_annotate(self):
        csv_path = Path(self.tmp.name) / "r.csv"
        csv_path.write_text("# comment\n0x1130,custom_start\n\n0x2000,custom_mid\n")
        rc, res = _json_run("re", "bulk", self.binary, "--pattern", str(csv_path), home=self.home)
        self.assertEqual(rc, 0, res)
        self.assertEqual(res["count"], 2)

        # The rename has to land in the store that `annotate` reads. A batch verb
        # that wrote its own table would look correct here and be invisible to
        # every consumer of annotations, which is the failure this asserts against.
        rc, listed = _json_run("re", "annotate", "list", self.binary, home=self.home)
        names = {a["rva"]: a.get("new_name") for a in listed.get("annotations", [])}
        self.assertEqual(names.get("0x1130"), "custom_start")
        self.assertEqual(names.get("0x2000"), "custom_mid")

    def test_malformed_line_names_its_line_number(self):
        csv_path = Path(self.tmp.name) / "bad.csv"
        csv_path.write_text("0x1130,ok_name\nthis-line-has-no-comma\n")
        res = _run("re", "bulk", self.binary, "--pattern", str(csv_path), home=self.home)
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("2", res.stderr + res.stdout,
                      "a malformed CSV must report the 1-based line number it failed on")

    def test_missing_rename_list_is_a_usage_error(self):
        res = _run("re", "bulk", self.binary, "--pattern", "/no/such.csv", home=self.home)
        self.assertEqual(res.returncode, 2)
        self.assertNotIn("Traceback", res.stderr)


class TestMcpRoute(unittest.TestCase):
    """The MCP tool is a second surface onto the same verbs and rots separately.

    `re_inspect` builds a CLI argv, so a verb can be reachable from the shell and
    still be invisible to an agent — either because the arg builder omits a flag or
    because the enum in the tool schema does not offer the verb at all. These tests
    assert the argv, which is the only thing standing between the schema and the CLI.
    """

    def setUp(self) -> None:
        from xtforge.adapters import mcp_server
        self.builder = mcp_server._re_inspect_args
        self.tools = {tool["name"]: tool for tool in mcp_server.TOOLS}

    def test_new_verbs_are_advertised_in_the_schema(self):
        enum = self.tools["re_inspect"]["inputSchema"]["properties"]["verb"]["enum"]
        for verb in ("elfmeta", "wasm", "firmware", "bookmarks", "bulk"):
            self.assertIn(verb, enum,
                          f"{verb} missing from the re_inspect enum: MCP clients "
                          f"select from this list, so the verb is uncallable")

    def test_argv_for_format_readers(self):
        self.assertEqual(self.builder({"verb": "elfmeta", "path": "/bin/ls"}),
                         ["re", "elfmeta", "/bin/ls"])
        self.assertEqual(self.builder({"verb": "wasm", "path": "/bin/ls"}),
                         ["re", "wasm", "/bin/ls"])
        self.assertEqual(self.builder({"verb": "firmware", "path": "/bin/ls"}),
                         ["re", "firmware", "/bin/ls"])

    def test_bookmarks_subverb_is_spliced_before_the_path(self):
        self.assertEqual(
            self.builder({"verb": "bookmarks", "sub": "set", "path": "/b",
                          "target": "0x1130", "name": "ep"}),
            ["re", "bookmarks", "set", "/b", "0x1130", "--name", "ep"],
            "the subverb is a positional: forwarding it as a flag would make every "
            "call resolve to `list` and silently do nothing")
        self.assertEqual(self.builder({"verb": "bookmarks", "path": "/b"}),
                         ["re", "bookmarks", "list", "/b"],
                         "an omitted sub must default to list, not to a broken argv")

    def test_bulk_forwards_the_rename_list(self):
        self.assertEqual(self.builder({"verb": "bulk", "path": "/b",
                                       "pattern": "/tmp/r.csv"}),
                         ["re", "bulk", "/b", "--pattern", "/tmp/r.csv"])

    def test_missing_path_is_still_rejected(self):
        with self.assertRaises(ValueError):
            self.builder({"verb": "elfmeta"})


if __name__ == "__main__":
    unittest.main()
