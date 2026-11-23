#!/usr/bin/env python3
"""Assemble per-platform release bundles, with the natives each platform can carry.

The shipped 0.4.6 artifacts were built by hand and two of them were wrong: the darwin
tarball (541 entries) and the windows zip (222 entries) contained **no native executable at
all**, so those users got a Python-only payload while the launchers advertised natives. The
Linux tarball had both. `tests/test_shipped_packages.py` records that as an expected failure
precisely so it becomes visible when packaging is fixed.

This script is that fix. It builds what it can and is explicit about what it cannot:

* the Go hub cross-compiles for every target from a single machine, so every bundle gets one;
* the Rust core needs a per-target toolchain and is included only when the build succeeds —
  a bundle that silently claims a native it does not contain is the original defect.

Usage:
    python scripts/build_release.py --version 0.4.7 --out dist/
    python scripts/build_release.py --version 0.4.7 --out /tmp/release --platform linux-x86_64
"""
from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

GO_TARGETS = {
    "linux-x86_64": ("linux", "amd64", "xtforge-hub"),
    "linux-aarch64": ("linux", "arm64", "xtforge-hub"),
    "darwin-arm64": ("darwin", "arm64", "xtforge-hub"),
    "darwin-x86_64": ("darwin", "amd64", "xtforge-hub"),
    "windows-x86_64": ("windows", "amd64", "xtforge-hub.exe"),
}

# Directories and files every bundle carries.
PAYLOAD = ("xtforge", "adapters", "bin", "docs", "README.md", "LICENSE", "VERSION",
           "pyproject.toml", "uv.lock")
WINDOWS_LAUNCHER = "bin/xtforge.cmd"
POSIX_LAUNCHER = "bin/xtforge"


def _run(argv: list[str], cwd: Path | None = None) -> tuple[int, str]:
    completed = subprocess.run(argv, cwd=str(cwd or ROOT), capture_output=True, text=True)
    return completed.returncode, (completed.stdout + completed.stderr).strip()


def build_hub(platform: str, staging: Path) -> tuple[bool, str]:
    """Cross-compile the Go hub for one platform. Returns (kept, note)."""
    if platform not in GO_TARGETS:
        return False, f"no Go target for {platform}"
    goos, goarch, name = GO_TARGETS[platform]
    if shutil.which("go") is None:
        return False, "go toolchain not available"
    destination = staging / "bin" / name
    destination.parent.mkdir(parents=True, exist_ok=True)
    env = {**os.environ, "GOOS": goos, "GOARCH": goarch, "CGO_ENABLED": "0"}
    completed = subprocess.run(
        ["go", "build", "-ldflags", "-s -w", "-o", str(destination), "./cmd/xtforge-hub"],
        cwd=str(ROOT / "native" / "xtforge-go"), env=env, capture_output=True, text=True)
    if completed.returncode != 0 or not destination.is_file():
        return False, f"go build failed: {completed.stderr.strip()[:200]}"
    destination.chmod(0o755)
    return True, f"xtforge-hub ({goos}/{goarch})"


def host_platform() -> str:
    """The platform this machine builds for, in the same vocabulary as GO_TARGETS."""
    machine = {"x86_64": "x86_64", "amd64": "x86_64",
               "arm64": "arm64", "aarch64": "aarch64"}.get(
                   os.uname().machine if hasattr(os, "uname") else "", "unknown")
    if sys.platform.startswith("darwin"):
        return f"darwin-{machine}"
    if sys.platform.startswith("win"):
        return f"windows-{machine}"
    return f"linux-{machine}"


def build_native(platform: str, staging: Path) -> tuple[bool, str]:
    """Build the Rust core, but only for the platform this machine can actually target.

    `cargo build` without `--target` produces a **host** binary. Copying that into a
    darwin or windows bundle would put a Linux executable named xtforge-native in an
    archive that claims to carry one — the same defect this script exists to fix, only
    harder to notice because the file is present.
    """
    if shutil.which("cargo") is None:
        return False, "cargo not available"
    if platform != host_platform():
        return False, (f"xtforge-native is host-only ({host_platform()}); "
                       f"cross-building for {platform} needs its Rust target installed")
    destination = staging / "bin" / "xtforge-native"
    destination.parent.mkdir(parents=True, exist_ok=True)
    code, output = _run(["cargo", "build", "--release", "--quiet"], ROOT / "native" / "xtforge-rs")
    if code != 0:
        return False, f"cargo build failed: {output[:200]}"
    built = ROOT / "native" / "xtforge-rs" / "target" / "release" / "xtforge-native"
    if not built.is_file():
        return False, "cargo produced no xtforge-native binary"
    shutil.copy2(built, destination)
    destination.chmod(0o755)
    return True, "xtforge-native (host toolchain; verify it matches the target)"


def stage(platform: str, version: str, work: Path) -> tuple[Path, list[str]]:
    """Copy the payload into a staging tree and add the platform's natives."""
    staging = work / f"xt-forge-{version}-{platform}"
    if staging.exists():
        shutil.rmtree(staging)
    staging.mkdir(parents=True)
    for entry in PAYLOAD:
        source = ROOT / entry
        if not source.exists():
            continue
        target = staging / entry
        if source.is_dir():
            shutil.copytree(source, target,
                            ignore=shutil.ignore_patterns("__pycache__", "*.pyc", ".pytest_cache"))
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)
    notes = []
    for builder in (build_hub, build_native):
        kept, note = builder(platform, staging)
        notes.append(("built " if kept else "skipped ") + note)
    if platform.startswith("windows"):
        # The POSIX launcher is meaningless in a zip built for cmd.exe, and its presence
        # would hide the fact that the .cmd is what users run.
        posix = staging / POSIX_LAUNCHER
        if posix.exists():
            posix.unlink()
    return staging, notes


def archive(staging: Path, out: Path, platform: str) -> Path:
    out.mkdir(parents=True, exist_ok=True)
    if platform.startswith("windows"):
        destination = out / f"{staging.name}.zip"
        with zipfile.ZipFile(destination, "w", zipfile.ZIP_DEFLATED) as bundle:
            for path in sorted(staging.rglob("*")):
                if path.is_file():
                    bundle.write(path, path.relative_to(staging.parent))
    else:
        destination = out / f"{staging.name}.tar.gz"
        with tarfile.open(destination, "w:gz") as bundle:
            bundle.add(staging, arcname=staging.name)
    return destination


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", default=(ROOT / "VERSION").read_text().strip())
    parser.add_argument("--out", default=str(ROOT / "dist"))
    parser.add_argument("--platform", action="append", choices=sorted(GO_TARGETS))
    parser.add_argument("--work", default=None, help="staging directory (default: temp)")
    args = parser.parse_args()

    platforms = args.platform or sorted(GO_TARGETS)
    work = Path(args.work) if args.work else Path(
        subprocess.run(["mktemp", "-d"], capture_output=True, text=True).stdout.strip())
    out = Path(args.out)
    missing_native = 0
    for platform in platforms:
        staging, notes = stage(platform, args.version, work)
        destination = archive(staging, out, platform)
        names = [p.relative_to(staging).as_posix() for p in staging.rglob("*") if p.is_file()]
        natives = [n for n in names if Path(n).name in
                   ("xtforge-hub", "xtforge-hub.exe", "xtforge-native")]
        launcher = WINDOWS_LAUNCHER if platform.startswith("windows") else POSIX_LAUNCHER
        print(f"{destination.name}: {len(names)} entries, natives: {natives or 'NONE'}")
        for note in notes:
            print(f"    {note}")
        if not natives:
            missing_native += 1
            print("    WARNING: no native executable in this archive")
        if launcher not in names:
            print(f"    WARNING: launcher {launcher} missing")
    if not args.work:
        shutil.rmtree(work, ignore_errors=True)
    return 1 if missing_native else 0


if __name__ == "__main__":
    raise SystemExit(main())
