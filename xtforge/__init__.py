"""xt-forge core: harness-free library. All runtime state lives under XT_HOME."""

__all__ = ["version", "codename", "version_str"]

_CODENAME = "Damascus"
_VERSION = (0, 1, 0)


def version() -> str:
    return ".".join(str(p) for p in _VERSION)


def codename() -> str:
    return _CODENAME


def version_str() -> str:
    return f"{version()}-{_CODENAME}"