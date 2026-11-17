"""Tests for code index, code graph, code lsp, and `route context --symbols`."""
from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from xtforge.core.code import graph as cg
from xtforge.core.route import pack as packmod

ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "bin" / "xtforge"


class TestCodeGraph(unittest.TestCase):
    def test_python_graph_and_symbol_pack(self):
        with tempfile.TemporaryDirectory() as td:
            old = os.environ.get("XT_HOME")
            os.environ["XT_HOME"] = td
            try:
                src = Path(td) / "auth.py"
                src.write_text(
                    "def verify_sig(tok):\n"
                    "    return len(tok) > 10\n\n"
                    "def authenticate(user, tok):\n"
                    "    return verify_sig(tok)\n"
                )
                db = Path(td) / "code_graph.db"
                idx = cg.index_workspace(td, db_path=db)
                self.assertTrue(idx["ok"])
                self.assertGreaterEqual(idx["total_symbols"], 2)

                gres = cg.query_graph("verify_sig", root=td, depth=2, db_path=db)
                self.assertTrue(gres["ok"])
                self.assertTrue(any(c["caller"] == "authenticate" for c in gres["callers"]))

                pres = packmod.pack(td, "verify_sig", token_budget=600, use_symbols=True)
                self.assertTrue(pres["ok"])
                self.assertIn("symbol_graph_hits", pres["data"])
            finally:
                if old is None:
                    os.environ.pop("XT_HOME", None)
                else:
                    os.environ["XT_HOME"] = old

    def test_native_rust_index_graph_and_route_symbols(self):
        with tempfile.TemporaryDirectory() as td:
            env = {**os.environ, "XT_HOME": td}
            src = Path(td) / "worker.py"
            src.write_text("def dispatch_job(x):\n    return run_job(x)\n\ndef run_job(x):\n    return x\n")
            ri = subprocess.run(
                [str(BIN), "code", "index", td, "--json"],
                capture_output=True, text=True, env=env, cwd=str(ROOT),
            )
            self.assertEqual(ri.returncode, 0, ri.stderr)
            di = json.loads(ri.stdout)
            self.assertTrue(di["ok"])
            self.assertEqual(di["engine"], "rust")

            rg = subprocess.run(
                [str(BIN), "code", "graph", "run_job", td, "--json"],
                capture_output=True, text=True, env=env, cwd=str(ROOT),
            )
            self.assertEqual(rg.returncode, 0, rg.stderr)
            dg = json.loads(rg.stdout)
            self.assertTrue(any(c["caller"] == "dispatch_job" for c in dg["callers"]))

            rc = subprocess.run(
                [str(BIN), "route", "context", td, "--query", "run_job", "--symbols", "--json"],
                capture_output=True, text=True, env=env, cwd=str(ROOT),
            )
            self.assertEqual(rc.returncode, 0, rc.stderr)
            dc = json.loads(rc.stdout)
            self.assertTrue(dc["ok"])


if __name__ == "__main__":
    unittest.main()
