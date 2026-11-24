#!/usr/bin/env python3
"""Capture the README examples using a compiled fixture and a sample manifest."""
import os
from pathlib import Path
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[1]
ASSETS = ROOT / "docs" / "assets" / "release-review"


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="xtforge-demo-") as temp:
        project = Path(temp)
        (project / "demo.c").write_text(
            "int increment(int n) { return n + 1; }\n"
            "int main(void) { return increment(4); }\n",
            encoding="utf-8",
        )
        manifest = "module example.com/demo\n\ngo 1.21\n\nrequire example.com/library v1.2.3\n"
        (project / "go.mod").write_text(manifest, encoding="utf-8")
        (ASSETS / "manifest.txt").write_text(manifest, encoding="utf-8")
        subprocess.run(["cc", "-g", "-O0", "demo.c", "-o", "demo"], cwd=project, check=True)
        env = {**os.environ, "XT_HOME": str(project / "state"), "XT_FORCE_PYTHON": "1"}
        captures = {
            "overview": ["overview", "./demo", "--json"],
            "disassembly": ["disasm-native", "./demo", "--target", "main", "--flow"],
            "references": ["xrefs-native", "./demo", "--target", "increment", "--json"],
            "dependencies": ["deps", ".", "--json"],
        }
        for name, args in captures.items():
            output = subprocess.check_output(
                [str(ROOT / "bin" / "xtforge"), "re", *args],
                cwd=project,
                env=env,
                text=True,
            )
            # Keep the example paths readable across different checkout locations.
            output = output.replace(f"{project}/", "./").replace(str(project), ".")
            (ASSETS / f"{name}.txt").write_text(
                "$ xt-forge re " + " ".join(args) + "\n" + output, encoding="utf-8",
            )


if __name__ == "__main__":
    main()
