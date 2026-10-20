"""Plugin management: the OpenCode plugin that ships with xt-forge."""
from .manager import (PLUGIN_ID, install, manifest, register, repo_root,
                      source_dir, status, target_dir, unregister, uninstall)

__all__ = [
    "PLUGIN_ID",
    "install",
    "manifest",
    "register",
    "repo_root",
    "source_dir",
    "status",
    "target_dir",
    "unregister",
    "uninstall",
]
