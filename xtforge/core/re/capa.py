"""Behavioral capability detection engine (inspired by Mandiant capa).

Detects executable capabilities (anti-debugging, process injection, privilege
manipulation, memory evasion, network communications) using rule-based import,
symbol, and pattern heuristics without external dependencies.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from ..route import guard
from . import native as renative
from .pe import PEFile, PeError

RULES: list[dict[str, Any]] = [
    {
        "name": "anti_debugging",
        "category": "evasion",
        "severity": "HIGH",
        "description": "Checks for debugger presence or interacts with debug subsystems",
        "imports": [
            "IsDebuggerPresent",
            "CheckRemoteDebuggerPresent",
            "NtQueryInformationProcess",
            "ZwQueryInformationProcess",
            "OutputDebugStringA",
            "OutputDebugStringW",
            "DbgBreakPoint",
            "DbgUserBreakPoint",
            "ptrace",
        ],
        "strings": [
            r"BeingDebugged",
            r"DebuggerDetected",
        ],
    },
    {
        "name": "process_injection",
        "category": "execution",
        "severity": "CRITICAL",
        "description": "Allocates memory or creates execution threads in remote processes",
        "imports": [
            "VirtualAllocEx",
            "WriteProcessMemory",
            "CreateRemoteThread",
            "CreateRemoteThreadEx",
            "NtMapViewOfSection",
            "ZwMapViewOfSection",
            "QueueUserAPC",
            "SetThreadContext",
            "process_vm_writev",
        ],
        "strings": [],
    },
    {
        "name": "privilege_manipulation",
        "category": "privilege_escalation",
        "severity": "HIGH",
        "description": "Inspects or adjusts process token privileges or user IDs",
        "imports": [
            "OpenProcessToken",
            "AdjustTokenPrivileges",
            "LookupPrivilegeValueA",
            "LookupPrivilegeValueW",
            "DuplicateTokenEx",
            "setuid",
            "setgid",
            "cap_set_proc",
        ],
        "strings": [
            r"SeDebugPrivilege",
            r"SeTcbPrivilege",
        ],
    },
    {
        "name": "memory_evasion",
        "category": "defense_evasion",
        "severity": "MEDIUM",
        "description": "Alters page memory protection flags at runtime",
        "imports": [
            "VirtualProtect",
            "VirtualProtectEx",
            "NtProtectVirtualMemory",
            "ZwProtectVirtualMemory",
            "mprotect",
        ],
        "strings": [],
    },
    {
        "name": "persistence",
        "category": "persistence",
        "severity": "MEDIUM",
        "description": "Writes to autostart registry keys or installs system services",
        "imports": [
            "RegCreateKeyExA",
            "RegCreateKeyExW",
            "RegSetValueExA",
            "RegSetValueExW",
            "CreateServiceA",
            "CreateServiceW",
        ],
        "strings": [
            r"CurrentVersion\\Run",
            r"CurrentVersion\\RunOnce",
        ],
    },
    {
        "name": "network_communication",
        "category": "command_and_control",
        "severity": "LOW",
        "description": "Establishes socket connections or performs HTTP requests",
        "imports": [
            "WSAStartup",
            "connect",
            "InternetOpenA",
            "InternetOpenW",
            "HttpSendRequestA",
            "HttpSendRequestW",
            "curl_easy_init",
        ],
        "strings": [],
    },
    {
        "name": "process_execution",
        "category": "execution",
        "severity": "LOW",
        "description": "Spawns child processes or executes commands",
        "imports": [
            "WinExec",
            "ShellExecuteA",
            "ShellExecuteW",
            "CreateProcessA",
            "CreateProcessW",
            "system",
            "execve",
            "popen",
        ],
        "strings": [],
    },
]


def detect_capabilities(path: str | Path) -> dict[str, Any]:
    """Analyze executable capabilities against behavioral rule definitions."""
    try:
        canon = guard.read_guard(path)
    except guard.Denied as exc:
        return {"ok": False, "err": f"{exc.code}: {exc.reason}"}

    if not canon.is_file():
        return {"ok": False, "err": "not_a_file", "path": str(canon)}

    fmt = renative.sniff_format(canon)
    all_imports: set[str] = set()

    if fmt == "pe":
        try:
            pe = PEFile(canon)
            for imp_dll in pe.imports():
                for fn in imp_dll.get("functions", []):
                    all_imports.add(fn)
        except PeError:
            pass
    elif fmt == "elf":
        syms_res = renative.get_symbols(canon, limit=1000)
        if syms_res.get("ok"):
            for s in syms_res.get("symbols", []):
                all_imports.add(s.get("name", ""))

    file_bytes = canon.read_bytes()

    detected: list[dict[str, Any]] = []

    for rule in RULES:
        matches: list[dict[str, str]] = []

        # Check imports
        for imp_name in rule.get("imports", []):
            if imp_name in all_imports:
                matches.append({"type": "import", "indicator": imp_name})

        # Check strings/regexes
        for str_pat in rule.get("strings", []):
            try:
                regex = re.compile(str_pat.encode("utf-8"), re.IGNORECASE)
                if regex.search(file_bytes):
                    matches.append({"type": "string", "indicator": str_pat})
            except Exception:
                continue

        if matches:
            detected.append({
                "name": rule["name"],
                "category": rule["category"],
                "severity": rule["severity"],
                "description": rule["description"],
                "matches": matches,
                "count": len(matches),
            })

    return {
        "ok": True,
        "path": str(canon),
        "format": fmt,
        "capabilities": detected,
        "count": len(detected),
    }
