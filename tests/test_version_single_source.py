"""Every surface must report the same version.

xt-forge shipped three answers at once — the `VERSION` file said 0.3.2,
`pyproject.toml` said 0.3.3, and `xtforge.version()` said 0.1.0 — because the
package kept its own literal. A user asking "what am I running?" got whichever
answer the surface they happened to touch was built with, and no test noticed.

The fix is structural: `VERSION` is the single source and
`xtforge/__init__.py` re-exports it. These tests pin the structure, not just
today's number, so adding a second literal fails here first.

Run: python3 -m unittest tests.test_version_single_source -v
"""
from __future__ import annotations

import re
import unittest
from pathlib import Path

import importlib

import xtforge

# `import xtforge.version as x` binds the package's `version` FUNCTION, not the
# submodule, because the package exports that name. import_module is the only
# way to reach the module itself.
version_module = importlib.import_module("xtforge.version")

ROOT = Path(__file__).resolve().parents[1]
VERSION_FILE = ROOT / "VERSION"
PYPROJECT = ROOT / "pyproject.toml"
INIT = ROOT / "xtforge" / "__init__.py"


def version_file_facts() -> dict[str, str]:
    facts: dict[str, str] = {}
    for line in VERSION_FILE.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        facts[key.strip()] = value.strip()
    return facts


class SingleSourceTest(unittest.TestCase):
    def test_version_file_exists_and_declares_a_version(self):
        self.assertTrue(VERSION_FILE.is_file())
        self.assertRegex(version_file_facts()["version"], r"^\d+\.\d+\.\d+$")

    def test_package_reports_the_version_file_value(self):
        self.assertEqual(xtforge.version(), version_file_facts()["version"])
        self.assertEqual(version_module.version(), version_file_facts()["version"])

    def test_version_is_a_string_not_a_module(self):
        """The package exports a function named `version`.

        A `from . import version` in `__init__` shadows that function with the
        submodule, and `xtforge.version()` then fails at the call site. Cheap to
        check, and it already happened once.
        """
        self.assertIsInstance(xtforge.version(), str)

    def test_pyproject_agrees_with_the_version_file(self):
        match = re.search(r'^version\s*=\s*"([^"]+)"', PYPROJECT.read_text(),
                          re.MULTILINE)
        self.assertIsNotNone(match, "pyproject.toml has no version")
        self.assertEqual(match.group(1), version_file_facts()["version"],
                         "pyproject.toml and VERSION disagree")

    def test_package_keeps_no_second_version_literal(self):
        """No `_VERSION = (0, 1, 0)`-style tuple may come back into the package."""
        source = INIT.read_text()
        self.assertIsNone(
            re.search(r"^\s*_?VERSION\s*=\s*\(", source, re.MULTILINE),
            "xtforge/__init__.py declares its own version tuple; read VERSION instead",
        )

    def test_version_str_composes_version_and_codename(self):
        facts = version_file_facts()
        self.assertEqual(xtforge.version_str(),
                         f"{facts['version']}-{facts['codename']}")


if __name__ == "__main__":
    unittest.main()
