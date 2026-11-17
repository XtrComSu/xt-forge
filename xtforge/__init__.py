"""xt-forge core: harness-free library. All runtime state lives under XT_HOME.

Version identity lives in exactly one place — the `VERSION` file at the project
root — and this module only re-exports it. A second literal here (it used to be
`_VERSION = (0, 1, 0)`) is how the package ended up claiming three different
versions at once: the file said 0.3.2, pyproject said 0.3.3, and
`xtforge.version()` said 0.1.0. Whichever surface a user happened to ask, they
got a different answer, and no test noticed.
"""

from __future__ import annotations

# The submodule is imported under a private name because this package exports a
# FUNCTION called `version`; binding the module as `version` would shadow it and
# `xtforge.version()` would then hand callers a module instead of a string.
import importlib as _importlib

__all__ = ["version", "codename", "version_str"]

_version_mod = _importlib.import_module(".version", __name__)


def version() -> str:
    """The package version, read from the VERSION file (or install metadata)."""
    return _version_mod.version()


def codename() -> str:
    """The release codename, read from the VERSION file."""
    return _version_mod.codename()


def version_str() -> str:
    """`<version>-<codename>`, e.g. `0.3.3-Damascus`."""
    return _version_mod.version_str()
