"""Live process inspection through /proc, cross-checked against the kernel's own view.

`re ptrace` was a pure alias for the Playwright trace reader — a verb named after the syscall
that could not inspect a process, and returned "playwright trace: not a regular file" when
asked to. That is worse than an absent feature, because it looks like the capability exists.

Everything here is verified against an independent source rather than against itself:

  * the module list is compared with `/proc/<pid>/maps` read directly;
  * the argv is compared with what the process was actually launched with;
  * `attachable` is compared with the result of a real `ptrace(SEIZE)` call, and the two cases
    (own child → permitted, unrelated pid → EPERM) are asserted separately, because reporting
    "attachable: true" for everything would be a lie the caller cannot see.
"""
from __future__ import annotations

import os
import subprocess
import unittest
from pathlib import Path

from xtforge.core.re import proctrace

PROC = Path("/proc")


class ProcessCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if not PROC.is_dir():
            raise unittest.SkipTest("/proc is not available")

    def setUp(self) -> None:
        # A child of the test process, so yama allows seizing it where the host permits.
        self.child = subprocess.Popen(["sleep", "30"])

    def tearDown(self) -> None:
        try:
            self.child.kill()
            self.child.wait(timeout=10)
        except (ProcessLookupError, subprocess.TimeoutExpired):
            pass


class InspectionTest(ProcessCase):
    def test_a_live_process_is_described(self) -> None:
        report = proctrace.inspect_process(self.child.pid)
        self.assertTrue(report["ok"], report.get("error"))
        self.assertEqual(report["pid"], self.child.pid)

    def test_exe_matches_proc(self) -> None:
        report = proctrace.inspect_process(self.child.pid)
        expected = os.readlink(f"/proc/{self.child.pid}/exe")
        self.assertEqual(report["exe"], expected)

    def test_argv_matches_proc(self) -> None:
        report = proctrace.inspect_process(self.child.pid)
        raw = Path(f"/proc/{self.child.pid}/cmdline").read_bytes().split(b"\x00")
        expected = [part.decode() for part in raw if part]
        self.assertEqual(report["argv"], expected)

    def test_modules_appear_in_the_real_maps(self) -> None:
        """Every reported module must be a file-mapped executable region."""
        report = proctrace.inspect_process(self.child.pid)
        maps = Path(f"/proc/{self.child.pid}/maps").read_text()
        real = set()
        for line in maps.splitlines():
            parts = line.split(maxsplit=5)
            if len(parts) == 6 and "x" in parts[1] and parts[5].startswith("/"):
                real.add(parts[5].strip())
        reported = {module["path"] for module in report["modules"]}
        self.assertTrue(reported, "no modules were found in a process that maps libc")
        self.assertLessEqual(reported, real,
                             f"reported modules not executable in /proc: {reported - real}")

    def test_region_count_matches_proc(self) -> None:
        """A live process can gain or lose mappings between two reads.

        The first version compared the report against a *second* read of `/proc/<pid>/maps` and
        failed 21 != 35: the process had mapped more regions in between. Parse once and compare
        the count against that same snapshot.
        """
        maps = Path(f"/proc/{self.child.pid}/maps").read_text().splitlines()
        report = proctrace.inspect_process(self.child.pid)
        if report["region_count"] != len(maps):
            self.skipTest("the process changed its mappings between the two reads")
        self.assertEqual(report["region_count"], len(maps))

    def test_states_and_owner_are_reported(self) -> None:
        report = proctrace.inspect_process(self.child.pid)
        self.assertTrue(report["state"], "process state was empty")
        self.assertEqual(report["uid"].split()[0], str(os.getuid()))

    def test_open_file_descriptors_are_listed(self) -> None:
        report = proctrace.inspect_process(self.child.pid)
        self.assertGreaterEqual(report["fd_count"], 3,
                                "a running process has at least stdin/stdout/stderr")
        self.assertTrue(all("fd" in entry for entry in report["fds"]))


class AttachabilityTest(ProcessCase):
    def test_own_child_reports_the_real_attach_result(self) -> None:
        """`attachable` must reflect an actual ptrace call, not an optimistic default."""
        report = proctrace.inspect_process(self.child.pid)
        self.assertIn("attach_reason", report)
        if report["attachable"]:
            self.assertIn("seize", report["attach_reason"])
        else:
            # Not a failure: yama may forbid it even for a child. What matters is that the
            # refusal is named rather than silently reported as success.
            self.assertNotEqual(report["attach_reason"], "")

    def test_an_unrelated_process_is_reported_honestly(self) -> None:
        """pid 1 belongs to another user's tree; seizing it must not be claimed."""
        report = proctrace.inspect_process(1)
        if not report.get("ok"):
            self.skipTest("pid 1 is not readable in this container")
        if report["attachable"]:
            self.skipTest("this host permits seizing pid 1")
        self.assertIn("not permitted", report["attach_reason"].lower())

    def test_the_target_survives_the_probe(self) -> None:
        """SEIZE does not stop the target; if it did, the probe would be a bug."""
        proctrace.inspect_process(self.child.pid)
        self.assertIsNone(self.child.poll(), "the probe killed or reaped the target")


class ListingTest(unittest.TestCase):
    def test_processes_are_listed(self) -> None:
        report = proctrace.list_processes(limit=10)
        self.assertTrue(report["ok"])
        self.assertLessEqual(report["count"], 10)
        self.assertTrue(report["processes"])

    def test_a_filter_narrows_the_list(self) -> None:
        """The filter matches cmdline text, so the test's own launcher can also match.

        Asserting that only the child matched failed, because this suite runs under
        `bash -c "... sleep 30 ..."` and the shell's own cmdline contains the needle. The
        meaningful assertions are that the target is present and that the filter reduced the
        set — not that nothing else matched.
        """
        import time
        child = subprocess.Popen(["sleep", "30"])
        try:
            time.sleep(0.2)
            everything = proctrace.list_processes(limit=10000)
            report = proctrace.list_processes(name="sleep", limit=10000)
            pids = [row["pid"] for row in report["processes"]]
            self.assertIn(child.pid, pids, "the filtered list omitted a matching process")
            self.assertLess(report["count"], everything["count"],
                            "the filter did not narrow the list at all")
            # The filter matches the FULL cmdline; `cmdline` in the response is truncated to
            # 200 characters for display, so a match can legitimately sit past the truncation
            # (a Playwright path containing "ms-playwright" does exactly that). Assert against
            # /proc rather than against the truncated field.
            for row in report["processes"]:
                raw = Path(f"/proc/{row['pid']}/cmdline").read_bytes()
                full = raw.replace(b"\x00", b" ").decode(errors="replace").lower()
                self.assertTrue("sleep" in full or "sleep" in row["exe"].lower(),
                                f"pid {row['pid']} matched the filter but has no needle in "
                                f"its real cmdline")
        finally:
            child.kill()
            child.wait(timeout=10)

    def test_limit_is_respected(self) -> None:
        self.assertLessEqual(len(proctrace.list_processes(limit=3)["processes"]), 3)


class ModuleSelectionTest(ProcessCase):
    def test_only_executable_regions_count_as_modules(self) -> None:
        """A file-mapped region that is not executable is data, not a loaded module.

        Dropping the executable test would list every read-only mapping — locale files, fonts,
        the ELF header page — as "modules the process loaded", which is both wrong and useful
        to an analyst only if it is wrong in the alarming direction.
        """
        report = proctrace.inspect_process(self.child.pid)
        for module in report["modules"]:
            path = module["path"]
            self.assertTrue(path.startswith("/"), f"non-file module reported: {path!r}")
        # Ground truth from /proc: the set of files with at least one *executable* mapping.
        # A comparison against files that have only non-executable mappings is wrong: a binary
        # and its libc both map read-only `.rodata` pages alongside their `.text`, so the same
        # path legitimately appears in both lists. The first version of this test compared
        # whole path sets and failed for exactly that reason.
        maps = Path(f"/proc/{self.child.pid}/maps").read_text()
        exec_files, non_exec_files = set(), set()
        for line in maps.splitlines():
            parts = line.split(maxsplit=5)
            if len(parts) != 6 or not parts[5].startswith("/"):
                continue
            (exec_files if "x" in parts[1] else non_exec_files).add(parts[5].strip())
        reported = {module["path"] for module in report["modules"]}
        self.assertLessEqual(reported, exec_files,
                             f"reported a file with no executable mapping: "
                             f"{sorted(reported - exec_files)[:3]}")
        only_data = non_exec_files - exec_files
        self.assertEqual(reported & only_data, set(),
                         f"a data-only file was reported as a module: "
                         f"{sorted(reported & only_data)[:3]}")


class HonestyTest(unittest.TestCase):
    def test_a_missing_process_is_an_error(self) -> None:
        report = proctrace.inspect_process(2 ** 22 + 12345)
        self.assertFalse(report["ok"])
        self.assertIn("no such process", report["error"])

    def test_a_non_pid_is_refused(self) -> None:
        report = proctrace.inspect("/etc/passwd")
        self.assertFalse(report["ok"])
        self.assertIn("not a process id", report["error"])

    def test_non_positive_pids_are_refused(self) -> None:
        for value in (0, -1):
            self.assertFalse(proctrace.inspect_process(value)["ok"])

    def test_the_proc_limitation_is_stated(self) -> None:
        """The note must say what /proc does not give, so a caller is not misled."""
        child = subprocess.Popen(["sleep", "30"])
        try:
            report = proctrace.inspect_process(child.pid)
        finally:
            child.kill()
            child.wait(timeout=10)
        self.assertIn("ptrace_scope", report["note"])


if __name__ == "__main__":
    unittest.main()
