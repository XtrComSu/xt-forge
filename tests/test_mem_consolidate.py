"""Tests for mem record-failure, consolidate, and negative-memory warnings (Rust + Python)."""
from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from xtforge.core.mem import search as memsearch
from xtforge.core.mem.store import Store

ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "bin" / "xtforge"


class TestMemConsolidateAndFailure(unittest.TestCase):
    def test_python_record_failure_search_warning_and_consolidate(self):
        with tempfile.TemporaryDirectory() as td:
            db = Path(td) / "mem.db"
            st = Store(db)
            try:
                f = st.record_failure(
                    scope="global",
                    title="Broken proxy TLS bypass",
                    body="Passing insecure curl flag fails corporate MITM pinning checks",
                    error_sig="ERR_TLS_PIN",
                    tags=["tls", "proxy"],
                )
                self.assertEqual(f["kind"], "failed_attempt")
                self.assertEqual(f["error_sig"], "ERR_TLS_PIN")
                self.assertEqual(f["outcome"], "failed")

                sres = memsearch.search(st, query="corporate MITM pinning", scopes=["global"], k=5)
                self.assertTrue(sres["warnings"], "search should surface failed_attempt warning")
                self.assertEqual(sres["warnings"][0]["error_sig"], "ERR_TLS_PIN")

                st.put(
                    scope="global", kind="fact", title="OAuth token flow",
                    body="OAuth token refresh endpoint retry flow enforces circuit breaker",
                    source="test",
                )
                st.put(
                    scope="global", kind="fact", title="OAuth token flow",
                    body="OAuth token refresh endpoint retry flow uses jitter timeout",
                    source="test",
                )
                dry = st.consolidate(scope="global", threshold=0.5, dry_run=True)
                self.assertEqual(dry["clusters"], 1)
                self.assertEqual(dry["created"], 1)

                applied = st.consolidate(scope="global", threshold=0.5, dry_run=False)
                self.assertEqual(applied["clusters"], 1)
                self.assertEqual(applied["merged"], 2)
                sum_id = applied["summaries"][0]["id"]
                links = st.links(sum_id)
                self.assertEqual(len(links["out"]), 2)
                self.assertTrue(all(x["rel"] == "derived_from" for x in links["out"]))
            finally:
                st.close()

    def test_native_and_python_cli_parity(self):
        for force_py in ("0", "1"):
            with tempfile.TemporaryDirectory() as td:
                env = {**os.environ, "XT_HOME": td, "XT_FORCE_PYTHON": force_py}
                db = str(Path(td) / "mem.db")
                r1 = subprocess.run(
                    [str(BIN), "mem", "record-failure", "--db", db,
                     "--title", "Bad bind flag", "--body", "Binding 0.0.0.0 exposes admin port",
                     "--error-sig", "ERR_BIND_ALL", "--json"],
                    capture_output=True, text=True, env=env, cwd=str(ROOT),
                )
                self.assertEqual(r1.returncode, 0, r1.stderr)
                p1 = json.loads(r1.stdout)
                self.assertEqual(p1["kind"], "failed_attempt")
                self.assertEqual(p1["error_sig"], "ERR_BIND_ALL")

                r2 = subprocess.run(
                    [str(BIN), "mem", "consolidate", "--db", db, "--dry-run", "--json"],
                    capture_output=True, text=True, env=env, cwd=str(ROOT),
                )
                self.assertEqual(r2.returncode, 0, r2.stderr)
                p2 = json.loads(r2.stdout)
                self.assertIn("clusters", p2)


if __name__ == "__main__":
    unittest.main()
