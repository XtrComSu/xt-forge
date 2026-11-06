"""Tests for syscall trampolines and inline hook detection."""
from __future__ import annotations

import unittest
from xtforge.core.re.native import scan_hooks_and_syscalls

SAMPLE_DISASM_HOOKS = """
0000000000001000 <NtDelayExecution>:
    1000:	4c 8b d1             	mov    %rcx,%r10
    1003:	b8 34 00 00 00       	mov    $0x34,%eax
    1008:	0f 05                	syscall 
    100a:	c3                   	ret

0000000000001020 <NtQuerySystemTime>:
    1020:	4c 8b d1             	mov    %rcx,%r10
    1023:	b8 5a 00 00 00       	mov    $0x5a,%eax
    1028:	0f 05                	syscall 
    102a:	c3                   	ret

0000000000001040 <HookedTarget>:
    1040:	48 b8 00 20 00 40 01 	movabs $0x140002000,%rax
    1047:	00 00 00 
    104a:	ff e0                	jmp    *%rax
"""


class TestHooksAndSyscalls(unittest.TestCase):
    def test_scan_syscall_stubs(self):
        res = scan_hooks_and_syscalls(SAMPLE_DISASM_HOOKS)
        syscalls = res.get("syscalls", [])
        self.assertEqual(len(syscalls), 2)
        self.assertEqual(syscalls[0]["function"], "NtDelayExecution")
        self.assertEqual(syscalls[0]["ssn"], 0x34)
        self.assertEqual(syscalls[1]["function"], "NtQuerySystemTime")
        self.assertEqual(syscalls[1]["ssn"], 0x5A)

    def test_scan_inline_hooks(self):
        res = scan_hooks_and_syscalls(SAMPLE_DISASM_HOOKS)
        hooks = res.get("hooks", [])
        self.assertEqual(len(hooks), 1)
        self.assertEqual(hooks[0]["function"], "HookedTarget")
        self.assertEqual(hooks[0]["type"], "indirect_jmp_rax")
