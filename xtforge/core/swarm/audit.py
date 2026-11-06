"""Autonomous high-concurrency capability and vulnerability audit swarm."""
from __future__ import annotations

import re
import shutil
from pathlib import Path
from typing import Any

from ..re import native as renative
from .worker import SwarmPool

CRYPTO_SIGNATURES = [
    ("AES_SBOX", bytes([0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5])),
    ("MD5_CONSTANTS", bytes([0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef])),
    ("SHA256_K", bytes([0x98, 0x2f, 0x8a, 0x42, 0x91, 0x44, 0x37, 0x71])),
]


def _audit_checksec(canon: Path) -> list[dict[str, Any]]:
    findings = []
    res = renative.checksec(canon)
    if res.get("ok"):
        mits = res.get("mitigations", {})
        if mits.get("aslr") is False:
            findings.append({
                "severity": "HIGH",
                "category": "mitigations",
                "title": "ASLR Disabled",
                "description": "Binary lacks dynamic base / ASLR, making ROP and fixed-offset exploits trivial.",
            })
        if mits.get("dep_nx") is False or mits.get("nx") is False:
            findings.append({
                "severity": "HIGH",
                "category": "mitigations",
                "title": "DEP/NX Disabled",
                "description": "Data execution prevention is absent; stack or heap buffers may be executable.",
            })
        if mits.get("cfg") is False and res.get("format") == "pe":
            findings.append({
                "severity": "LOW",
                "category": "mitigations",
                "title": "Control Flow Guard Absent",
                "description": "No Control Flow Guard (CFG) indirect call verification.",
            })
    return findings


def _audit_tls_integrity(canon: Path) -> list[dict[str, Any]]:
    findings = []
    info = renative.get_info(canon)
    cbs = info.get("tls_callbacks", [])
    if cbs:
        findings.append({
            "severity": "MEDIUM",
            "category": "integrity",
            "title": f"Active TLS Callbacks ({len(cbs)})",
            "description": f"Binary registers {len(cbs)} TLS callbacks executing before the entry point.",
            "callbacks": cbs,
        })
    return findings


def _audit_crypto(canon: Path) -> list[dict[str, Any]]:
    findings = []
    data = canon.read_bytes()
    for name, sig in CRYPTO_SIGNATURES:
        idx = data.find(sig)
        if idx >= 0:
            findings.append({
                "severity": "INFO",
                "category": "crypto",
                "title": f"Cryptographic Constant Detected ({name})",
                "description": f"Found signature match for {name} at offset 0x{idx:x}.",
                "offset": hex(idx),
            })
    return findings


def _audit_hooks(canon: Path) -> list[dict[str, Any]]:
    findings = []
    tool = shutil.which("objdump")
    if tool:
        out_txt, ok = renative._run([tool, "-d", str(canon)], timeout=30)
        if ok and out_txt:
            res = renative.scan_hooks_and_syscalls(out_txt)
            for sc in res.get("syscalls", []):
                findings.append({
                    "severity": "INFO",
                    "category": "syscalls",
                    "title": f"Direct Syscall Stub ({sc['function']})",
                    "description": f"Executes raw syscall with SSN {sc.get('hex_ssn')} ({sc.get('ssn')}) at {sc['address']}.",
                })
            for h in res.get("hooks", []):
                findings.append({
                    "severity": "MEDIUM",
                    "category": "hooks",
                    "title": f"Inline Detour/Hook in {h['function']}",
                    "description": f"{h['type']} at {h['address']} targeting {h['target']}.",
                })
    return findings


def _audit_strings(canon: Path) -> list[dict[str, Any]]:
    findings = []
    data = canon.read_bytes()
    xors = renative.extract_xor_strings(data, min_len=6)
    for x in xors[:5]:
        findings.append({
            "severity": "LOW",
            "category": "obfuscation",
            "title": f"XOR-Encoded String (key {x['hex_key']})",
            "description": f"Decrypted: '{x['string']}' at offset {hex(x['offset'])}.",
        })
    return findings


def audit_binary(
    target: str | Path,
    categories: list[str] | None = None,
    workers: int = 4,
) -> dict[str, Any]:
    """Execute autonomous concurrent capability and security audit swarm."""
    canon = renative.guard.read_guard(target)
    if not canon.is_file():
        return {"ok": False, "err": "target is not a file"}

    pool = SwarmPool(workers=workers)
    tasks = [
        lambda c=canon: _audit_checksec(c),
        lambda c=canon: _audit_tls_integrity(c),
        lambda c=canon: _audit_crypto(c),
        lambda c=canon: _audit_hooks(c),
        lambda c=canon: _audit_strings(c),
    ]

    results = pool.run_all(tasks)
    all_findings = []
    for r in results:
        if r["ok"]:
            all_findings.extend(r.get("result", []))

    severity_counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    cat_counts: dict[str, int] = {}
    for f in all_findings:
        sev = f.get("severity", "INFO")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
        cat = f.get("category", "general")
        cat_counts[cat] = cat_counts.get(cat, 0) + 1

    return {
        "ok": True,
        "path": str(canon),
        "total_findings": len(all_findings),
        "summary": severity_counts,
        "categories": cat_counts,
        "findings": all_findings,
    }
