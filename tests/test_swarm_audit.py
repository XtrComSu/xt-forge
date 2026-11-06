"""Tests for the high-concurrency swarm auditor."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from xtforge.core.swarm.audit import audit_binary
from tests.test_re_pe import create_minimal_pe


class TestSwarmAudit(unittest.TestCase):
    def test_swarm_audit_pe(self):
        # PE with TLS callback and security mitigations
        pe_bytes = create_minimal_pe(
            bits=64,
            sections=[(".text", 0x1000, 0x1000, b"\x90" * 0x1000, 0x60000020)],
            tls_callbacks=[0x140001050],
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            fpath = Path(tmpdir) / "target.dll"
            fpath.write_bytes(pe_bytes)

            res = audit_binary(fpath, workers=4)
            self.assertTrue(res["ok"])
            findings = res.get("findings", [])
            self.assertTrue(any("TLS" in f["title"] for f in findings))
            self.assertIn("summary", res)
            self.assertIn("categories", res)
