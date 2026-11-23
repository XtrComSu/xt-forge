"""`re rtti` class counts must describe the binary, not its ABI plumbing.

On a two-class fixture the verb reported **7** classes: four were the C++ ABI's own vtables
(`_ZTVN10__cxxabiv117__class_type_infoE` and friends), some were versioned aliases of the
same symbol, and one was an undefined import with value 0. A further duplicate appeared
because the structure scan says "Derived" while the symbol supplement says "_ZTV7Derived".
"""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

SOURCE = """
#include <typeinfo>
struct Base { virtual ~Base(){} virtual int f(){return 1;} };
struct Derived : Base { int f() override { return 2; } };
const char* name_of(Base* b){ return typeid(*b).name(); }
int main(){ Base* b = new Derived(); const char* n = name_of(b);
            int r = (dynamic_cast<Derived*>(b) != nullptr); delete b;
            return r + (n[0] == '7'); }
"""

# Mach-O cross-builds have no Apple SDK here. Polymorphic classes still emit
# Itanium RTTI without <typeinfo>, so keep the fixture SDK-independent.
MACHO_SOURCE = """
struct Base { virtual ~Base(){} virtual int f(){return 1;} };
struct Derived : Base { int f() override { return 2; } };
int main(){ Derived d; Base* b = &d; return b->f() - 2; }
"""


def _run(*argv: str) -> dict:
    proc = subprocess.run([sys.executable, "-m", "xtforge.cli", "re", *argv, "--json"],
                          capture_output=True, text=True, cwd=str(ROOT))
    return json.loads(proc.stdout)


@unittest.skipUnless(shutil.which("clang++"), "clang++ required")
class TestRttiClasses(unittest.TestCase):
    def _binary(self, tmp: str) -> Path:
        source = Path(tmp) / "r.cpp"
        source.write_text(SOURCE)
        binary = Path(tmp) / "r.bin"
        subprocess.run(["clang++", "-O1", str(source), "-o", str(binary)],
                       check=True, capture_output=True)
        return binary

    def test_only_user_classes_are_counted(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            binary = self._binary(tmp)
            result = _run("rtti", str(binary))
            oracle = subprocess.run(["llvm-nm", "-C", str(binary)],
                                    capture_output=True, text=True).stdout
        self.assertTrue(result.get("ok"), result)
        names = {c.get("name") for c in result["classes"]}
        self.assertEqual(result["class_count"], 2, f"classes: {names}")
        self.assertEqual(names, {"Base", "Derived"})
        # Cross-check: the binary really has exactly two user typeinfo symbols.
        user_typeinfo = [line for line in oracle.splitlines()
                         if "typeinfo for" in line and "__cxxabiv1" not in line]
        self.assertEqual(len(user_typeinfo), 2)
        for name in names:
            self.assertNotIn("cxxabiv1", name)
            self.assertNotIn("@", name)

    def test_vtable_methods_are_attached(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            binary = self._binary(tmp)
            result = _run("rtti", str(binary))
        derived = next(c for c in result["classes"] if c["name"] == "Derived")
        self.assertTrue(derived["vtables"], "Derived should have a vtable")
        self.assertGreater(derived["method_count"], 0)
        previews = derived.get("method_previews") or {}
        self.assertTrue(any("return 2" in text for text in previews.values()),
                        f"no method preview shows the overridden body: {previews}")


@unittest.skipUnless(shutil.which("clang++") and shutil.which("ld64.lld") and
                     shutil.which("llvm-nm"), "Mach-O toolchain required")
class TestRttiClassesMachO(unittest.TestCase):
    def _binary(self, tmp: str) -> Path:
        source = Path(tmp) / "m.cpp"
        source.write_text(MACHO_SOURCE)
        obj = Path(tmp) / "m.o"
        binary = Path(tmp) / "m.bin"
        subprocess.run(["clang++", "-target", "arm64-apple-ios13.0", "-c",
                        str(source), "-o", str(obj)], check=True, capture_output=True)
        # The C++ runtime and unwind helper are supplied by the target OS, not
        # by this linker invocation; dynamic_lookup keeps the fixture SDK-free.
        subprocess.run(["ld64.lld", "-arch", "arm64", "-platform_version", "ios",
                        "13.0", "13.0", "-e", "_main", "-undefined",
                        "dynamic_lookup", str(obj), "-o", str(binary)],
                       check=True, capture_output=True)
        return binary

    def test_only_user_classes_are_counted(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            binary = self._binary(tmp)
            result = _run("rtti", str(binary))
            oracle = subprocess.run(["llvm-nm", "-C", str(binary)],
                                    capture_output=True, text=True).stdout
        self.assertTrue(result.get("ok"), result)
        self.assertEqual(result.get("format"), "macho")
        names = {c.get("name") for c in result["classes"]}
        self.assertEqual(names, {"Base", "Derived"}, f"classes: {names}")
        user_typeinfo = [line for line in oracle.splitlines()
                         if "typeinfo for" in line and "__cxxabiv1" not in line]
        self.assertEqual(len(user_typeinfo), 2, oracle)
        self.assertEqual(result["class_count"], len(user_typeinfo),
                         f"classes: {names}")
        for name in names:
            self.assertNotIn("cxxabiv1", name)
            self.assertNotIn("@", name)
