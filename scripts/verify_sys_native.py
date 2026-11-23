#!/usr/bin/env python3
"""Build synthetic SYS fixtures and verify decoding and lifting through the launcher and MCP."""

import argparse
import hashlib
import json
import os
import random
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
FIXTURE = """\
const char fixture_marker[] = "XT-Forge SYS verification";
__attribute__((noinline)) const char *data_ref(void) { return fixture_marker; }
__attribute__((noinline)) unsigned increment(unsigned value) { return value + 1; }
__attribute__((noinline)) unsigned pure(unsigned value) {
    if (value == 0) return 7;
    return value + 1;
}
__attribute__((noinline)) unsigned choose(unsigned value) {
    if (value) return increment(value);
    return 4;
}
static unsigned dispatch_leaf(unsigned value) { return value + 11; }
__attribute__((noinline)) unsigned dispatch_table(unsigned op, unsigned value) {
    switch (op) {
    case 0: return value + 11;
    case 1: return value * 3;
    case 2: return value - 7;
    case 3: return value ^ 21;
    case 4: return value << 2;
    case 5: return value + 3;
    case 6: return value | 8;
    case 7: return dispatch_leaf(value);
    case 8: return value + 17;
    case 9: return value - 13;
    case 10: return value & 0xf0;
    case 11: return value >> 1;
    default: return value;
    }
}
__attribute__((noinline)) unsigned count_down(unsigned value) {
    unsigned total = 0;
    while (value > 0) { total += value; value--; }
    return total;
}
int main(void) { return choose(3) + (int)dispatch_table(3, 5) + (int)count_down(4); }
"""


def run(argv, *, cwd=ROOT, env=None, input=None):
    proc = subprocess.run(argv, cwd=cwd, env=env, input=input, text=True, capture_output=True)
    if proc.returncode:
        raise RuntimeError(f"{argv}: exit {proc.returncode}\n{proc.stdout}{proc.stderr}")
    return proc.stdout


def build(root: Path, native_binary: Path | None = None) -> Path:
    go = root / "native/xtforge-go"
    go.mkdir(parents=True)
    run(["go", "build", "-buildvcs=false", "-o", str(go / "xtforge-hub"), "./cmd/xtforge-hub"],
        cwd=ROOT / "native/xtforge-go")
    if native_binary is None:
        run(["cargo", "build", "--offline"], cwd=ROOT / "native/xtforge-rs")
        native_binary = ROOT / "native/xtforge-rs/target/debug/xtforge-native"
    rust = root / "native/xtforge-rs/target/release"
    rust.mkdir(parents=True)
    shutil.copy2(native_binary, rust / "xtforge-native")
    (root / "bin").mkdir()
    shutil.copy2(ROOT / "bin/xtforge", root / "bin/xtforge")
    shutil.copy2(ROOT / "VERSION", root / "VERSION")
    return root / "bin/xtforge"


def fixtures(root: Path) -> None:
    (root / "fixture.c").write_text(FIXTURE, encoding="utf-8")
    for optimization, suffix in [("-O0", ""), ("-O2", "-opt")]:
        run(["cc", optimization, "fixture.c", "-o", "linux" + suffix], cwd=root)
        run(["x86_64-w64-mingw32-gcc", optimization, "fixture.c", "-o", f"windows{suffix}.exe"], cwd=root)
        for name, arch, platform, version in [
            ("mac" + suffix, "x86_64", "macos", "10.15"),
            ("ios" + suffix, "arm64", "ios", "13.0"),
        ]:
            run(["clang", optimization, "-target", f"{arch}-apple-{platform}{version}",
                 "-c", "fixture.c", "-o", f"{name}.o"], cwd=root)
            run(["ld64.lld", "-arch", arch, "-platform_version", platform, version, version,
                 "-e", "_main", f"{name}.o", "-o", name], cwd=root)
        with zipfile.ZipFile(root / f"Fixture{suffix}.ipa", "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.write(root / ("ios" + suffix), "Payload/Fixture.app/Fixture")


def verify_cli(launcher: Path, root: Path, env: dict) -> None:
    recovered = []
    for name, arch, prefix in [
        ("linux", "x86_64", ""), ("windows.exe", "x86_64", ""),
        ("mac", "x86_64", "_"), ("Fixture.ipa", "arm64", "_"),
    ]:
        path = str(root / name)
        index = json.loads(run([str(launcher), "re", "functions", path, "--limit", "2000", "--json"], env=env))
        expected = next(fn["address"] for fn in index["images"][0]["functions"] if fn.get("name") == prefix + "increment")
        result = json.loads(run([str(launcher), "re", "disasm-native", path,
                                 "--target", prefix + "choose", "--flow", "--json"], env=env))
        assert result["arch"] == arch and result["mode"] == "flow" and len(result["blocks"]) >= 3, result
        calls = [ins.get("target") for ins in result["instructions"] if ins.get("kind") == "call"]
        assert expected in calls, result
        raw_path = str(root / "ios") if name == "Fixture.ipa" else path
        reference = run(["llvm-objdump", "-d", "--no-show-raw-insn",
                         f"--disassemble-symbols={prefix}choose", raw_path])
        reference_calls = {
            (int(pc, 16), int(target, 16)) for pc, target in
            re.findall(r"^\s*([0-9a-f]+):\s+(?:callq?|bl)\s+0x([0-9a-f]+)", reference, re.M)
        }
        actual_calls = {(ins["address"], ins["target"]) for ins in result["instructions"]
                        if ins.get("kind") == "call" and "target" in ins}
        assert reference_calls and actual_calls == reference_calls, (result, reference)
        xrefs = json.loads(run([str(launcher), "re", "xrefs-native", path,
                                "--target", prefix + "increment", "--json"], env=env))
        indexed = {(ref["site"], ref["target"]) for ref in xrefs["references"]
                   if ref["kind"] == "call" and ref.get("function_name") == prefix + "choose"}
        assert indexed == reference_calls and xrefs["pending"] == 0, (xrefs, reference)
        assert any(ins.get("kind") == "return" for ins in result["instructions"]), result
        print(f"{name}: {len(result['instructions'])} instructions, {len(result['blocks'])} blocks, expected call {expected:#x}")
        lifted = json.loads(run([str(launcher), "re", "decompile-native", path,
                                 "--target", prefix + "choose", "--json"], env=env))
        operations = [op for block in lifted["ir"] for op in block["operations"]]
        assert any(op["opcode"] == "call" and op.get("target") == expected for op in operations), lifted
        assert {"branch", "return"} <= {op["opcode"] for op in operations}, lifted
        coverage = lifted["coverage"]
        assert coverage["decoded"] == len(result["instructions"]) == coverage["lifted"] + coverage["opaque"], lifted
        increment = json.loads(run([str(launcher), "re", "decompile-native", path,
                                    "--target", prefix + "increment", "--json"], env=env))
        assert any(op["opcode"] == "add" and op["destination"]["width"] == 32
                   for block in increment["ir"] for op in block["operations"]), increment
        print(f"{name}: lifted {coverage['lifted']}/{coverage['decoded']} instructions in choose")
        reg = "x0" if arch == "arm64" else "rcx" if name == "windows.exe" else "rdi"
        add_recovered(lifted, "choose", prefix, reg, recovered)
        recover_source(launcher, path, "pure", prefix, reg, env, recovered)
    verify_dispatch(launcher, root, env)
    symbols = run(["llvm-objdump", "--syms", str(root / "ios")])
    marker = re.search(r"^([0-9a-f]+)\b[^\n]*\b_fixture_marker$", symbols, re.M)
    assert marker, symbols
    target = int(marker[1], 16)
    xrefs = json.loads(run([str(launcher), "re", "xrefs-native", str(root / "Fixture.ipa"),
                            "--target", hex(target), "--json"], env=env))
    assert any(ref["kind"] == "pc_relative_address" and ref.get("function_name") == "_data_ref" and
               ref["target"] == target for ref in xrefs["references"]), (target, xrefs)
    print(f"Fixture.ipa: resolved arm64 page-relative data reference to {target:#x}")
    for name, prefix, register in [
        ("linux-opt", "", "rdi"), ("windows-opt.exe", "", "rcx"),
        ("mac-opt", "_", "rdi"), ("Fixture-opt.ipa", "_", "x0"),
    ]:
        recover_source(launcher, str(root / name), "pure", prefix, register, env, recovered)
        recover_source(launcher, str(root / name), "choose", prefix, register, env, recovered)
    # count_down is the loop case. Its summary is a statement list rather than an
    # expression, so it is checked by running it, not by comparing pseudocode.
    verify_structured(root, recovered)
    verify_loops(launcher, root, env)
    verify_call_before_loop(launcher, root, env)
    verify_call_in_loop(launcher, root, env)
    verify_arm64_widening(launcher, root, env)
    verify_arm64_optimized_loop(launcher, root, env)
    verify_compiled_branch_loop(launcher, root, env)
    verify_compiled_multiply(launcher, root, env)


def verify_compiled_multiply(launcher: Path, root: Path, env: dict) -> None:
    source = root / "multiply.c"
    source.write_text("""\
__attribute__((noinline)) unsigned multiply_const(unsigned n) { return n * 37u; }
__attribute__((noinline)) unsigned long long multiply_pair(unsigned long long a, unsigned long long b) { return a * b; }
int main(void) { return multiply_const(1) != 37 || multiply_pair(4, 5) != 20; }
""", encoding="utf-8")
    linux, windows = root / "multiply_linux", root / "multiply_windows.exe"
    run(["cc", "-O2", str(source), "-o", str(linux)])
    run(["x86_64-w64-mingw32-gcc", "-O2", str(source), "-o", str(windows)])
    for arch, platform, version in (("x86_64", "macos", "10.15"), ("arm64", "ios", "13.0")):
        obj, image = root / f"multiply_{platform}.o", root / f"multiply_{platform}"
        run(["clang", "-O2", "-target", f"{arch}-apple-{platform}{version}", "-c", str(source), "-o", str(obj)])
        run(["ld64.lld", "-arch", arch, "-platform_version", platform, version, version,
             "-e", "_main", str(obj), "-o", str(image)])
    for label, image, prefix in (("ELF", linux, ""), ("PE", windows, ""),
                                  ("Mach-O", root / "multiply_macos", "_"),
                                  ("arm64", root / "multiply_ios", "_")):
        definitions = []
        for name in ("multiply_const", "multiply_pair"):
            result = json.loads(run([str(launcher), "re", "decompile-native", str(image),
                                     "--target", prefix + name, "--json"], env=env))
            assert "structured" in result, result
            definitions.append(result["structured"]["pseudocode"].replace(
                " " + prefix + name + "(", " recovered_" + name + "(", 1))
        harness = '#include <stdint.h>\n#define main fixture_main\n#include "multiply.c"\n#undef main\n'
        harness += "\n".join(definitions) + """\
int main(void) {
    uint32_t small[] = {0, 1, 0x80000000u, UINT32_MAX};
    uint64_t wide[] = {0, 1, UINT64_C(0x8000000000000000), UINT64_MAX};
    for (unsigned i = 0; i < 4; i++) {
        if (recovered_multiply_const(small[i]) != multiply_const(small[i])) return 1;
        for (unsigned j = 0; j < 4; j++)
            if (recovered_multiply_pair(wide[i], wide[j]) != multiply_pair(wide[i], wide[j])) return 2;
    }
    return 0;
}
"""
        driver = root / "verify_multiply.c"
        driver.write_text(harness, encoding="utf-8")
        run(["cc", "-O2", "-std=c11", "-Wall", "-Werror", str(driver), "-o", str(root / "verify_multiply")])
        subprocess.run([str(root / "verify_multiply")], check=True, timeout=10)
        print(f"optimized {label} multiplication: recovered C matched boundary inputs")


def verify_compiled_branch_loop(launcher: Path, root: Path, env: dict) -> None:
    source = root / "branch_loop.c"
    source.write_text("""\
unsigned branch_loop(unsigned n) {
    unsigned result = 0;
    while (n) {
        if (n & 1u) result += n;
        else result ^= n;
        n--;
    }
    return result;
}
unsigned optional_loop(unsigned n) {
    unsigned result = 0;
    while (n) {
        if (n & 1u) result += n;
        n--;
    }
    return result;
}
int main(void) { return branch_loop(4) != 7; }
""", encoding="utf-8")
    binary = root / "branch_loop"
    run(["cc", "-O0", str(source), "-o", str(binary)])
    result = json.loads(run([str(launcher), "re", "decompile-native", str(binary),
                             "--target", "branch_loop", "--json"], env=env))
    assert "structured" in result, result
    code = result["structured"]["pseudocode"].replace(" branch_loop(", " recovered_branch_loop(", 1)
    optional = json.loads(run([str(launcher), "re", "decompile-native", str(binary),
                               "--target", "optional_loop", "--json"], env=env))
    assert "structured" in optional, optional
    code += optional["structured"]["pseudocode"].replace(" optional_loop(", " recovered_optional_loop(", 1)
    harness = '#include <stdint.h>\n#define main fixture_main\n#include "branch_loop.c"\n#undef main\n'
    harness += code + """\
int main(void) {
    for (uint32_t n = 0; n < 4096; n++)
        if (recovered_branch_loop(n) != branch_loop(n)) return 1;
    for (uint32_t n = 0; n < 4096; n++)
        if (recovered_optional_loop(n) != optional_loop(n)) return 2;
    return 0;
}
"""
    driver = root / "verify_branch_loop.c"
    driver.write_text(harness, encoding="utf-8")
    run(["cc", "-O2", "-std=c11", "-Wall", "-Werror", str(driver), "-o", str(root / "verify_branch_loop")])
    subprocess.run([str(root / "verify_branch_loop")], check=True, timeout=10)
    print("unoptimized x86-64 conditional loop: recovered C matched 4096 inputs")

    optimized = root / "branch_loop_optimized"
    run(["cc", "-O1", "-fno-if-conversion", str(source), "-o", str(optimized)])
    result = json.loads(run([str(launcher), "re", "decompile-native", str(optimized),
                             "--target", "branch_loop", "--json"], env=env))
    assert "structured" in result, result
    code = result["structured"]["pseudocode"].replace(" branch_loop(", " recovered_opt_branch_loop(", 1)
    harness = '#include <stdint.h>\n#define main fixture_main\n#include "branch_loop.c"\n#undef main\n'
    harness += code + """\
int main(void) {
    for (uint32_t n = 0; n < 4096; n++)
        if (recovered_opt_branch_loop(n) != branch_loop(n)) return 1;
    return 0;
}
"""
    driver = root / "verify_opt_branch_loop.c"
    driver.write_text(harness, encoding="utf-8")
    run(["cc", "-O2", "-std=c11", "-Wall", "-Werror", str(driver), "-o", str(root / "verify_opt_branch_loop")])
    subprocess.run([str(root / "verify_opt_branch_loop")], check=True, timeout=10)
    print("optimized x86-64 conditional loop: recovered C matched 4096 inputs")

    opt_windows = root / "branch_loop_opt.exe"
    run(["x86_64-w64-mingw32-gcc", "-O1", "-fno-if-conversion", str(source), "-o", str(opt_windows)])
    for arch, platform, version in (("x86_64", "macos", "10.15"), ("arm64", "ios", "13.0")):
        obj, image = root / f"branch_opt_{platform}.o", root / f"branch_opt_{platform}"
        run(["clang", "-O1", "-target", f"{arch}-apple-{platform}{version}",
             "-c", str(source), "-o", str(obj)])
        run(["ld64.lld", "-arch", arch, "-platform_version", platform, version, version,
             "-e", "_main", str(obj), "-o", str(image)])
    for label, image, prefix in (("Windows PE", opt_windows, ""),
                                  ("macOS Mach-O", root / "branch_opt_macos", "_"),
                                  ("arm64 Mach-O", root / "branch_opt_ios", "_")):
        result = json.loads(run([str(launcher), "re", "decompile-native", str(image),
                                 "--target", prefix + "branch_loop", "--json"], env=env))
        assert "structured" in result, result
        code = result["structured"]["pseudocode"].replace(
            " " + prefix + "branch_loop(", " recovered_cross_opt(", 1)
        harness = '#include <stdint.h>\n#define main fixture_main\n#include "branch_loop.c"\n#undef main\n'
        harness += code + """\
int main(void) {
    for (uint32_t n = 0; n < 4096; n++)
        if (recovered_cross_opt(n) != branch_loop(n)) return 1;
    return 0;
}
"""
        driver = root / "verify_cross_opt.c"
        driver.write_text(harness, encoding="utf-8")
        run(["cc", "-O2", "-std=c11", "-Wall", "-Werror", str(driver), "-o", str(root / "verify_cross_opt")])
        subprocess.run([str(root / "verify_cross_opt")], check=True, timeout=10)
        print(f"optimized {label} conditional loop: recovered C matched 4096 inputs")

    obj = root / "branch_loop_ios.o"
    ios = root / "branch_loop_ios"
    run(["clang", "-O0", "-target", "arm64-apple-ios13.0", "-c", str(source), "-o", str(obj)])
    run(["ld64.lld", "-arch", "arm64", "-platform_version", "ios", "13.0", "13.0",
         "-e", "_main", str(obj), "-o", str(ios)])
    definitions = []
    for name in ("branch_loop", "optional_loop"):
        result = json.loads(run([str(launcher), "re", "decompile-native", str(ios),
                                 "--target", "_" + name, "--json"], env=env))
        assert "structured" in result, result
        definitions.append(result["structured"]["pseudocode"].replace(
            " _" + name + "(", " recovered_ios_" + name + "(", 1))
    harness = '#include <stdint.h>\n#define main fixture_main\n#include "branch_loop.c"\n#undef main\n'
    harness += "\n".join(definitions) + """\
int main(void) {
    for (uint32_t n = 0; n < 4096; n++) {
        if (recovered_ios_branch_loop(n) != branch_loop(n)) return 1;
        if (recovered_ios_optional_loop(n) != optional_loop(n)) return 2;
    }
    return 0;
}
"""
    driver = root / "verify_ios_branch_loop.c"
    driver.write_text(harness, encoding="utf-8")
    run(["cc", "-O2", "-std=c11", "-Wall", "-Werror", str(driver), "-o", str(root / "verify_ios_branch_loop")])
    subprocess.run([str(root / "verify_ios_branch_loop")], check=True, timeout=10)
    print("unoptimized arm64 conditional loops: recovered C matched 4096 inputs")

    windows = root / "branch_loop.exe"
    run(["x86_64-w64-mingw32-gcc", "-O0", str(source), "-o", str(windows)])
    mac_obj, mac = root / "branch_loop_mac.o", root / "branch_loop_mac"
    run(["clang", "-O0", "-target", "x86_64-apple-macos10.15", "-c", str(source), "-o", str(mac_obj)])
    run(["ld64.lld", "-arch", "x86_64", "-platform_version", "macos", "10.15", "10.15",
         "-e", "_main", str(mac_obj), "-o", str(mac)])
    for label, image_path, prefix in (("PE", windows, ""), ("Mach-O", mac, "_")):
        definitions = []
        for name in ("branch_loop", "optional_loop"):
            result = json.loads(run([str(launcher), "re", "decompile-native", str(image_path),
                                     "--target", prefix + name, "--json"], env=env))
            assert "structured" in result, result
            definitions.append(result["structured"]["pseudocode"].replace(
                " " + prefix + name + "(", " recovered_cross_" + name + "(", 1))
        harness = '#include <stdint.h>\n#define main fixture_main\n#include "branch_loop.c"\n#undef main\n'
        harness += "\n".join(definitions) + """\
int main(void) {
    for (uint32_t n = 0; n < 4096; n++) {
        if (recovered_cross_branch_loop(n) != branch_loop(n)) return 1;
        if (recovered_cross_optional_loop(n) != optional_loop(n)) return 2;
    }
    return 0;
}
"""
        driver = root / "verify_cross_branch_loop.c"
        driver.write_text(harness, encoding="utf-8")
        run(["cc", "-O2", "-std=c11", "-Wall", "-Werror", str(driver),
             "-o", str(root / "verify_cross_branch_loop")])
        subprocess.run([str(root / "verify_cross_branch_loop")], check=True, timeout=10)
        print(f"unoptimized {label} conditional loops: recovered C matched 4096 inputs")


def verify_call_before_loop(launcher: Path, root: Path, env: dict) -> None:
    source = root / "call_loop.c"
    source.write_text("""\
__attribute__((noinline)) unsigned adjust(unsigned n) { return n + 1; }
__attribute__((noinline)) unsigned call_loop(unsigned n) {
    n = adjust(n);
    unsigned result = 0;
    while (n) { result += n; n--; }
    return result;
}
int main(void) { return call_loop(3) != 10; }
""", encoding="utf-8")
    binary = root / "call_loop"
    run(["cc", "-O1", "-fno-inline", str(source), "-o", str(binary)])
    result = json.loads(run([str(launcher), "re", "decompile-native", str(binary),
                             "--target", "call_loop", "--json"], env=env))
    assert "structured" in result, result
    code = result["structured"]["pseudocode"].replace(" call_loop(", " recovered_call_loop(", 1)
    program = '#include <stdint.h>\n#define main fixture_main\n#include "call_loop.c"\n#undef main\n'
    program += code + """\
int main(void) {
    for (uint32_t n = 0; n < 4096; n++)
        if (recovered_call_loop(n) != call_loop(n)) return 1;
    return 0;
}
"""
    driver = root / "verify_call_loop.c"
    driver.write_text(program, encoding="utf-8")
    run(["cc", "-O2", "-std=c11", "-Wall", "-Werror", str(driver), "-o", str(root / "verify_call_loop")])
    run([str(root / "verify_call_loop")])
    print("call before loop: recovered C matched the original for 4096 inputs")


def verify_call_in_loop(launcher: Path, root: Path, env: dict) -> None:
    source = root / "inside_loop.c"
    source.write_text("""\
__attribute__((noinline)) unsigned inc(unsigned n) { return n + 1; }
__attribute__((noinline)) unsigned inside_loop(unsigned n) {
    unsigned result = 0;
    while (n) { result += inc(n); n--; }
    return result;
}
int main(void) { return inside_loop(3) != 9; }
""", encoding="utf-8")
    binary = root / "inside_loop"
    run(["cc", "-O1", "-fno-inline", str(source), "-o", str(binary)])
    result = json.loads(run([str(launcher), "re", "decompile-native", str(binary),
                             "--target", "inside_loop", "--json"], env=env))
    assert "structured" in result, result
    code = result["structured"]["pseudocode"].replace(" inside_loop(", " recovered_inside_loop(", 1)
    program = '#include <stdint.h>\n#define main fixture_main\n#include "inside_loop.c"\n#undef main\n'
    program += code + """\
int main(void) {
    for (uint32_t n = 0; n < 4096; n++)
        if (recovered_inside_loop(n) != inside_loop(n)) return 1;
    return 0;
}
"""
    driver = root / "verify_inside_loop.c"
    driver.write_text(program, encoding="utf-8")
    run(["cc", "-O2", "-std=c11", "-Wall", "-Werror", str(driver), "-o", str(root / "verify_inside_loop")])
    run([str(root / "verify_inside_loop")])
    print("call inside loop: recovered C matched the original for 4096 inputs")

    windows = root / "inside_loop.exe"
    run(["x86_64-w64-mingw32-gcc", "-O1", "-fno-inline", str(source), "-o", str(windows)])
    result = json.loads(run([str(launcher), "re", "decompile-native", str(windows),
                             "--target", "inside_loop", "--json"], env=env))
    assert "structured" in result, result
    code = result["structured"]["pseudocode"].replace(" inside_loop(", " recovered_windows_loop(", 1)
    program = '#include <stdint.h>\n#define main fixture_main\n#include "inside_loop.c"\n#undef main\n'
    program += code + """\
int main(void) {
    for (uint32_t n = 0; n < 4096; n++)
        if (recovered_windows_loop(n) != inside_loop(n)) return 1;
    return 0;
}
"""
    driver = root / "verify_windows_loop.c"
    driver.write_text(program, encoding="utf-8")
    run(["cc", "-O2", "-std=c11", "-Wall", "-Werror", str(driver), "-o", str(root / "verify_windows_loop")])
    run([str(root / "verify_windows_loop")])
    print("Windows PE call inside loop: recovered C matched the original for 4096 inputs")

    mac_obj = root / "inside_loop_mac.o"
    mac = root / "inside_loop_mac"
    run(["clang", "-O1", "-fno-inline", "-target", "x86_64-apple-macos10.15",
         "-c", str(source), "-o", str(mac_obj)])
    run(["ld64.lld", "-arch", "x86_64", "-platform_version", "macos", "10.15", "10.15",
         "-e", "_main", str(mac_obj), "-o", str(mac)])
    result = json.loads(run([str(launcher), "re", "decompile-native", str(mac),
                             "--target", "_inside_loop", "--json"], env=env))
    assert "structured" in result, result
    code = result["structured"]["pseudocode"].replace(" _inside_loop(", " recovered_mac_loop(", 1)
    program = '#include <stdint.h>\n#define main fixture_main\n#include "inside_loop.c"\n#undef main\n'
    program += code + """\
int main(void) {
    for (uint32_t n = 0; n < 4096; n++)
        if (recovered_mac_loop(n) != inside_loop(n)) return 1;
    return 0;
}
"""
    driver = root / "verify_mac_loop.c"
    driver.write_text(program, encoding="utf-8")
    run(["cc", "-O2", "-std=c11", "-Wall", "-Werror", str(driver), "-o", str(root / "verify_mac_loop")])
    run([str(root / "verify_mac_loop")])
    print("macOS Mach-O call inside loop: recovered C matched the original for 4096 inputs")

    ios_obj = root / "inside_loop_ios.o"
    ios = root / "inside_loop_ios"
    run(["clang", "-O1", "-fno-inline", "-target", "arm64-apple-ios13.0",
         "-c", str(source), "-o", str(ios_obj)])
    run(["ld64.lld", "-arch", "arm64", "-platform_version", "ios", "13.0", "13.0",
         "-e", "_main", str(ios_obj), "-o", str(ios)])
    result = json.loads(run([str(launcher), "re", "decompile-native", str(ios),
                             "--target", "_inside_loop", "--json"], env=env))
    assert "structured" in result, result
    code = result["structured"]["pseudocode"].replace(" _inside_loop(", " recovered_ios_loop(", 1)
    program = '#include <stdint.h>\n#define main fixture_main\n#include "inside_loop.c"\n#undef main\n'
    program += code + """\
int main(void) {
    for (uint32_t n = 0; n < 4096; n++)
        if (recovered_ios_loop(n) != inside_loop(n)) return 1;
    return 0;
}
"""
    driver = root / "verify_ios_loop.c"
    driver.write_text(program, encoding="utf-8")
    run(["cc", "-O2", "-std=c11", "-Wall", "-Werror", str(driver), "-o", str(root / "verify_ios_loop")])
    run([str(root / "verify_ios_loop")])
    print("arm64 Mach-O call inside loop: recovered C matched the original for 4096 inputs")

    assembly = root / "last_call.s"
    assembly.write_text("""\
.text
.globl last_call
.type last_call, @function
last_call:
    push %rbx
    mov %edi, %ebx
    test %ebx, %ebx
    je .Lzero
.Lloop:
    mov %ebx, %edi
    call inc
    sub $1, %ebx
    jne .Lloop
    pop %rbx
    ret
.Lzero:
    xor %eax, %eax
    pop %rbx
    ret
.size last_call, .-last_call
.globl top_call
.type top_call, @function
top_call:
    push %rbx
    push %rbp
    mov %edi, %ebx
    xor %ebp, %ebp
.Ltop:
    test %ebx, %ebx
    je .Ldone
    mov %ebx, %edi
    call inc
    add %eax, %ebp
    sub $1, %ebx
    jmp .Ltop
.Ldone:
    mov %ebp, %eax
    pop %rbp
    pop %rbx
    ret
.size top_call, .-top_call
.globl high_byte_test
.type high_byte_test, @function
high_byte_test:
    mov %edi, %eax
    testb $0x80, %ah
    jne .Lhigh
    mov $3, %eax
    ret
.Lhigh:
    mov $9, %eax
    ret
.size high_byte_test, .-high_byte_test
.globl scaled_index
.type scaled_index, @function
scaled_index:
    lea 17(,%rdi,4), %eax
    ret
.size scaled_index, .-scaled_index
.globl scaled_base
.type scaled_base, @function
scaled_base:
    lea -7(%rdi,%rsi,8), %rax
    ret
.size scaled_base, .-scaled_base
.globl multiply_immediate
.type multiply_immediate, @function
multiply_immediate:
    imul $-7, %edi, %eax
    ret
.size multiply_immediate, .-multiply_immediate
.globl multiply_register
.type multiply_register, @function
multiply_register:
    mov %rdi, %rax
    imul %rsi, %rax
    ret
.size multiply_register, .-multiply_register
.globl shift_left32
.type shift_left32, @function
shift_left32:
    mov %edi, %eax
    shl $37, %eax
    ret
.size shift_left32, .-shift_left32
.globl shift_right64
.type shift_right64, @function
shift_right64:
    mov %rdi, %rax
    shr $63, %rax
    ret
.size shift_right64, .-shift_right64
.globl shift_signed32
.type shift_signed32, @function
shift_signed32:
    mov %edi, %eax
    sar $7, %eax
    ret
.size shift_signed32, .-shift_signed32
.globl variable_sar
.type variable_sar, @function
variable_sar:
    mov %edi, %eax
    mov %esi, %ecx
    sar %cl, %eax
    ret
.size variable_sar, .-variable_sar
.globl variable_shr64
.type variable_shr64, @function
variable_shr64:
    mov %rdi, %rax
    mov %esi, %ecx
    shr %cl, %rax
    ret
.size variable_shr64, .-variable_shr64
.section .note.GNU-stack,"",@progbits
""", encoding="utf-8")
    fixture = root / "last_call.c"
    fixture.write_text("unsigned inc(unsigned n) { return n + 1; }\n"
                       "unsigned last_call(unsigned);\n"
                       "unsigned top_call(unsigned);\n"
                       "int main(void) { return last_call(3) != 2; }\n", encoding="utf-8")
    executable = root / "last_call"
    run(["cc", "-O1", str(assembly), str(fixture), "-o", str(executable)])
    result = json.loads(run([str(launcher), "re", "decompile-native", str(executable),
                             "--target", "last_call", "--json"], env=env))
    assert "structured" in result, result
    code = result["structured"]["pseudocode"].replace(" last_call(", " recovered_last_call(", 1)
    program = '#include <stdint.h>\n#define main fixture_main\n#include "last_call.c"\n#undef main\n'
    program += code + """\
int main(void) {
    for (uint32_t n = 0; n < 100; n++)
        if (recovered_last_call(n) != last_call(n)) return 1;
    return 0;
}
"""
    driver = root / "verify_last_call.c"
    driver.write_text(program, encoding="utf-8")
    run(["cc", "-O2", "-std=c11", "-Wall", "-Werror", str(driver), str(assembly),
         "-o", str(root / "verify_last_call")])
    run([str(root / "verify_last_call")])
    print("loop call result: preserved across subsequent register updates")

    result = json.loads(run([str(launcher), "re", "decompile-native", str(executable),
                             "--target", "top_call", "--json"], env=env))
    assert "structured" in result, result
    code = result["structured"]["pseudocode"].replace(" top_call(", " recovered_top_call(", 1)
    program = '#include <stdint.h>\n#define main fixture_main\n#include "last_call.c"\n#undef main\n'
    program += code + """\
int main(void) {
    for (uint32_t n = 0; n < 4096; n++)
        if (recovered_top_call(n) != top_call(n)) return 1;
    return 0;
}
"""
    driver = root / "verify_top_call.c"
    driver.write_text(program, encoding="utf-8")
    run(["cc", "-O2", "-std=c11", "-Wall", "-Werror", str(driver), str(assembly),
         "-o", str(root / "verify_top_call")])
    subprocess.run([str(root / "verify_top_call")], check=True, timeout=10)
    print("top-tested loop call: recovered C matched the original for 4096 inputs")

    result = json.loads(run([str(launcher), "re", "decompile-native", str(executable),
                             "--target", "high_byte_test", "--json"], env=env))
    assert "structured" in result, result
    code = result["structured"]["pseudocode"].replace(" high_byte_test(", " recovered_high_byte_test(", 1)
    program = '#include <stdint.h>\nunsigned inc(unsigned n) { return n + 1; }\n' + code + """\
unsigned high_byte_test(unsigned);
int main(void) {
    for (uint32_t n = 0; n < 65536; n++)
        if (recovered_high_byte_test(n) != high_byte_test(n)) return 1;
    return 0;
}
"""
    driver = root / "verify_high_byte.c"
    driver.write_text(program, encoding="utf-8")
    run(["cc", "-O2", "-std=c11", "-Wall", "-Werror", str(driver), str(assembly),
         "-o", str(root / "verify_high_byte")])
    subprocess.run([str(root / "verify_high_byte")], check=True, timeout=10)
    print("x86 high-byte test: recovered C matched 65536 inputs")

    definitions = []
    for name in ("scaled_index", "scaled_base", "multiply_immediate", "multiply_register",
                 "shift_left32", "shift_right64", "shift_signed32", "variable_sar", "variable_shr64"):
        result = json.loads(run([str(launcher), "re", "decompile-native", str(executable),
                                 "--target", name, "--json"], env=env))
        assert "structured" in result, result
        definitions.append(result["structured"]["pseudocode"].replace(
            " " + name + "(", " recovered_" + name + "(", 1))
    program = '#include <stdint.h>\nunsigned inc(unsigned n) { return n + 1; }\n' + "\n".join(definitions) + """\
unsigned scaled_index(unsigned);
uint64_t scaled_base(uint64_t, uint64_t);
unsigned multiply_immediate(unsigned);
uint64_t multiply_register(uint64_t, uint64_t);
unsigned shift_left32(unsigned);
uint64_t shift_right64(uint64_t);
unsigned shift_signed32(unsigned);
unsigned variable_sar(unsigned, unsigned);
uint64_t variable_shr64(uint64_t, unsigned);
int main(void) {
    uint32_t values[] = {0, 1, UINT32_MAX, UINT32_C(0x80000000)};
    uint64_t wide[] = {0, 1, UINT64_MAX, UINT64_C(0x8000000000000000)};
    for (unsigned i = 0; i < 4; i++) {
        if (recovered_scaled_index(values[i]) != scaled_index(values[i])) return 1;
        if (recovered_multiply_immediate(values[i]) != multiply_immediate(values[i])) return 3;
        if (recovered_shift_left32(values[i]) != shift_left32(values[i])) return 4;
        if (recovered_shift_signed32(values[i]) != shift_signed32(values[i])) return 5;
        if (recovered_shift_right64(wide[i]) != shift_right64(wide[i])) return 6;
        for (unsigned count = 0; count < 256; count++) {
            if (recovered_variable_sar(values[i], count) != variable_sar(values[i], count)) return 7;
            if (recovered_variable_shr64(wide[i], count) != variable_shr64(wide[i], count)) return 8;
        }
        for (unsigned j = 0; j < 4; j++)
            if (recovered_scaled_base(wide[i], wide[j]) != scaled_base(wide[i], wide[j]) ||
                recovered_multiply_register(wide[i], wide[j]) != multiply_register(wide[i], wide[j])) return 2;
    }
    return 0;
}
"""
    driver = root / "verify_scaled_lea.c"
    driver.write_text(program, encoding="utf-8")
    run(["cc", "-O2", "-std=c11", "-Wall", "-Werror", str(driver), str(assembly),
         "-o", str(root / "verify_scaled_lea")])
    subprocess.run([str(root / "verify_scaled_lea")], check=True, timeout=10)
    print("x86 scaled LEA: recovered C matched boundary inputs")


def verify_arm64_optimized_loop(launcher: Path, root: Path, env: dict) -> None:
    source = root / "arm_loop.c"
    source.write_text(LOOP_SOURCE + LOOP_DRIVER, encoding="utf-8")
    obj = root / "arm_loop.o"
    binary = root / "arm_loop"
    run(["clang", "-O1", "-target", "arm64-apple-ios13.0", "-c", str(source), "-o", str(obj)])
    run(["ld64.lld", "-arch", "arm64", "-platform_version", "ios", "13.0", "13.0",
         "-e", "_main", str(obj), "-o", str(binary)])
    result = json.loads(run([str(launcher), "re", "decompile-native", str(binary),
                             "--target", "_loop_sum", "--json"], env=env))
    assert "structured" in result, result
    program = '#include <stdint.h>\n' + LOOP_SOURCE + result["structured"]["pseudocode"] + """\
int main(void) {
    for (uint32_t n = 0; n < 4096; n++) {
        if (loop_sum(n) != _loop_sum(n)) return 1;
    }
    return 0;
}
"""
    driver = root / "verify_arm_loop.c"
    driver.write_text(program, encoding="utf-8")
    run(["cc", "-O2", "-std=c11", "-Wall", "-Werror", str(driver), "-o", str(root / "verify_arm_loop")])
    run([str(root / "verify_arm_loop")])
    print("arm64 optimized loop: recovered C matched the original for 4096 inputs")

    run(["clang", "-O0", "-target", "arm64-apple-ios13.0", "-c", str(source), "-o", str(obj)])
    run(["ld64.lld", "-arch", "arm64", "-platform_version", "ios", "13.0", "13.0",
         "-e", "_main", str(obj), "-o", str(binary)])
    result = json.loads(run([str(launcher), "re", "decompile-native", str(binary),
                             "--target", "_loop_sum", "--json"], env=env))
    assert "structured" in result, result
    program = '#include <stdint.h>\n' + LOOP_SOURCE + result["structured"]["pseudocode"] + """\
int main(void) {
    for (uint32_t n = 0; n < 4096; n++)
        if (loop_sum(n) != _loop_sum(n)) return 1;
    return 0;
}
"""
    driver.write_text(program, encoding="utf-8")
    run(["cc", "-O2", "-std=c11", "-Wall", "-Werror", str(driver), "-o", str(root / "verify_arm_loop")])
    subprocess.run([str(root / "verify_arm_loop")], check=True, timeout=10)
    print("arm64 unoptimized loop: recovered C matched the original for 4096 inputs")


def verify_arm64_widening(launcher: Path, root: Path, env: dict) -> None:
    """Compile arm64 instructions and execute the recovered C with boundary inputs."""
    asm = root / "widening.s"
    asm.write_text("""\
.text
.globl _wide_mul, _wide_add, _wide_sub, _shift32, _shift64, _same_xor, _same_sub, _mixed_arg, _reverse_arg, _mixed_loop, _two_block_loop, _top_loop, _branch_loop, _main
_wide_mul:
    umull x0, w0, w1
    ret
_wide_add:
    umaddl x0, w0, w1, x2
    ret
_wide_sub:
    umsubl x0, w0, w1, x2
    ret
_shift32:
    add w0, w0, w1, asr #7
    ret
_shift64:
    add x0, x0, x1, asr #17
    ret
_same_xor:
    eor w0, w0, w0, lsl #1
    ret
_same_sub:
    sub w0, w0, w0, lsr #1
    ret
_mixed_arg:
    mov x1, x0
    add w0, w0, #1
    add x0, x1, x0
    ret
_reverse_arg:
    cmp w0, #0
    mov x1, x0
    add x0, x1, x0
    ret
_mixed_loop:
    mov x2, x0
    cbz w1, 2f
1:
    add x2, x2, x0
    add w2, w2, #1
    subs w1, w1, #1
    b.ne 1b
2:
    mov x0, x2
    ret
_two_block_loop:
    mov w1, #0
    cbz w0, 4f
3:
    add w1, w1, w0
    b 5f
5:
    subs w0, w0, #1
    b.ne 3b
4:
    mov w0, w1
    ret
_top_loop:
    mov w1, #0
6:
    cbz w0, 7f
    add w1, w1, w0
    sub w0, w0, #1
    b 6b
7:
    mov w0, w1
    ret
_branch_loop:
    mov w1, #0
8:
    cbz w0, 12f
    tst w0, #1
    b.eq 9f
    add w1, w1, w0
    b 10f
9:
    eor w1, w1, w0
10:
    sub w0, w0, #1
    b 8b
12:
    mov w0, w1
    ret
_main:
    mov w0, #0
    ret
""", encoding="utf-8")
    obj = root / "widening.o"
    binary = root / "widening"
    run(["clang", "-target", "arm64-apple-ios13.0", "-c", str(asm), "-o", str(obj)])
    run(["ld64.lld", "-arch", "arm64", "-platform_version", "ios", "13.0", "13.0",
         "-e", "_main", str(obj), "-o", str(binary)])
    definitions = []
    for name, opcode in (("wide_mul", "umull"), ("wide_add", "umaddl"), ("wide_sub", "umsubl")):
        result = json.loads(run([str(launcher), "re", "decompile-native", str(binary),
                                 "--target", "_" + name, "--json"], env=env))
        ops = [op["opcode"] for block in result["ir"] for op in block["operations"]]
        assert opcode in ops and "structured" in result, result
        assert result["structured"]["return_width"] == 64, result
        definitions.append(result["structured"]["pseudocode"])
    for name, width in (("shift32", 32), ("shift64", 64)):
        result = json.loads(run([str(launcher), "re", "decompile-native", str(binary),
                                 "--target", "_" + name, "--json"], env=env))
        assert result.get("structured", {}).get("return_width") == width, result
        definitions.append(result["structured"]["pseudocode"])
    for name in ("same_xor", "same_sub"):
        result = json.loads(run([str(launcher), "re", "decompile-native", str(binary),
                                 "--target", "_" + name, "--json"], env=env))
        assert result.get("structured", {}).get("return_width") == 32, result
        definitions.append(result["structured"]["pseudocode"])
    result = json.loads(run([str(launcher), "re", "decompile-native", str(binary),
                             "--target", "_mixed_arg", "--json"], env=env))
    assert result.get("structured", {}).get("parameters", [])[0]["width"] == 64, result
    definitions.append(result["structured"]["pseudocode"])
    result = json.loads(run([str(launcher), "re", "decompile-native", str(binary),
                             "--target", "_mixed_loop", "--json"], env=env))
    assert "structured" in result, result
    definitions.append(result["structured"]["pseudocode"])
    result = json.loads(run([str(launcher), "re", "decompile-native", str(binary),
                             "--target", "_branch_loop", "--json"], env=env))
    assert "structured" in result, result
    definitions.append(result["structured"]["pseudocode"])
    result = json.loads(run([str(launcher), "re", "decompile-native", str(binary),
                             "--target", "_top_loop", "--json"], env=env))
    assert "structured" in result, result
    definitions.append(result["structured"]["pseudocode"])
    result = json.loads(run([str(launcher), "re", "decompile-native", str(binary),
                             "--target", "_two_block_loop", "--json"], env=env))
    assert "structured" in result, result
    definitions.append(result["structured"]["pseudocode"])
    result = json.loads(run([str(launcher), "re", "decompile-native", str(binary),
                             "--target", "_reverse_arg", "--json"], env=env))
    assert result.get("structured", {}).get("parameters", [])[0]["width"] == 64, result
    definitions.append(result["structured"]["pseudocode"])
    program = '#include <stdint.h>\n' + "\n".join(definitions) + """\
int main(void) {
    uint32_t values[] = {0, 1, 0x7fffffff, 0x80000000, 0xffffffff};
    uint64_t addends[] = {0, 1, UINT64_MAX, UINT64_C(0x8000000000000000)};
    for (unsigned i = 0; i < 5; i++) {
        for (unsigned j = 0; j < 5; j++) {
            uint64_t product = (uint64_t)values[i] * values[j];
            if (_wide_mul(values[i], values[j]) != product) return 1;
            for (unsigned k = 0; k < 4; k++) {
                if (_wide_add(values[i], values[j], addends[k]) != product + addends[k]) return 2;
                if (_wide_sub(values[i], values[j], addends[k]) != addends[k] - product) return 3;
            }
        }
    }
    if (_mixed_arg(UINT64_C(0xabcdef01ffffffff)) != UINT64_C(0xabcdef01ffffffff)) return 12;
    if (_mixed_arg(UINT64_C(0x1234567800000001)) != UINT64_C(0x1234567800000003)) return 13;
    if (_reverse_arg(UINT64_C(0x1234567800000000)) != UINT64_C(0x2468acf000000000)) return 14;
    if (_reverse_arg(UINT64_MAX) != UINT64_MAX - 1) return 15;
    for (unsigned n = 0; n < 16; n++) {
        uint64_t value = UINT64_C(0x12345678ffffffff);
        uint64_t expected = value;
        for (unsigned i = 0; i < n; i++) expected = (uint32_t)(expected + value + 1);
        if (_mixed_loop(value, n) != expected) return 16;
    }
    for (uint32_t n = 0; n < 1000; n++)
        if (_two_block_loop(n) != n * (n + 1) / 2) return 17;
    for (uint32_t n = 0; n < 1000; n++)
        if (_top_loop(n) != n * (n + 1) / 2) return 18;
    for (uint32_t n = 0; n < 1024; n++) {
        uint32_t expected = 0;
        for (uint32_t i = n; i; i--)
            expected = (i & 1) ? expected + i : expected ^ i;
        if (_branch_loop(n) != expected) return 19;
    }
    if (_shift32(5, UINT32_C(0x80000000)) != UINT32_C(0xff000005)) return 4;
    if (_shift32(7, UINT32_C(0xffffffff)) != 6) return 5;
    if (_shift32(7, UINT32_C(0x7fffffff)) != UINT32_C(0x01000006)) return 6;
    if (_shift64(5, UINT64_C(0x8000000000000000)) != UINT64_C(0xffffc00000000005)) return 7;
    if (_shift64(7, UINT64_MAX) != 6) return 8;
    if (_shift64(7, UINT64_C(0x7fffffffffffffff)) != UINT64_C(0x0000400000000006)) return 9;
    for (unsigned i = 0; i < 5; i++) {
        uint32_t n = values[i];
        if (_same_xor(n) != (n ^ (n << 1))) return 10;
        if (_same_sub(n) != (n - (n >> 1))) return 11;
    }
    return 0;
}
"""
    source = root / "verify_widening.c"
    source.write_text(program, encoding="utf-8")
    run(["cc", "-std=c11", "-O2", "-Wall", "-Werror", str(source), "-o", str(root / "verify_widening")])
    run([str(root / "verify_widening")])
    print("arm64 widening multiply and arithmetic shifts: recovered C matched boundary cases")


def verify_dispatch(launcher: Path, root: Path, env: dict) -> None:
    """Recovered jump-table targets must be real case bodies, one per case value."""
    for name, arch, prefix, kinds in [
        ("linux-opt", "x86_64", "", ("x86_offset_table",)),
        ("windows-opt.exe", "x86_64", "", ("x86_offset_table",)),
        ("mac-opt", "x86_64", "_", ("x86_offset_table",)),
        # arm64 uses a byte table scaled by the stride or a signed-word table
        # depending on the case count and optimisation level.
        ("ios-opt", "arm64", "_", ("arm64_byte_table", "arm64_offset_table")),
        ("ios", "arm64", "_", ("arm64_byte_table", "arm64_offset_table")),
    ]:
        path = str(root / name)
        symbol = prefix + "dispatch_table"
        result = json.loads(run([str(launcher), "re", "dispatch-native", path,
                                 "--target", symbol, "--json"], env=env))
        assert result["ok"] and result["arch"] == arch, result
        assert result["tables"], f"{name}: no jump table recovered: {result}"
        table = result["tables"][0]
        assert table["kind"] in kinds, (name, table["kind"], kinds)
        # The switch has twelve cases (0..11) with a separate default path.
        # Fewer cases let the compiler emit a compare/csel chain with no table.
        assert table["bound"] == 11, (name, table)
        assert table["entries"] == 12, (name, table)
        targets = table["targets"]
        assert len(targets) == 12, (name, targets)
        # Targets must land on instruction boundaries of the reference
        # disassembly; a mis-decoded table would point into the middle of one.
        reference = run(["llvm-objdump", "-d", "--no-show-raw-insn",
                         f"--disassemble-symbols={symbol}", path])
        boundaries = {int(pc, 16) for pc in re.findall(r"^\s*([0-9a-f]+):", reference, re.M)}
        assert boundaries, (name, reference)
        stray = [t for t in targets if t not in boundaries]
        assert not stray, f"{name}: targets {[hex(t) for t in stray]} are not instruction starts"
        print(f"{name}: {len(targets)} {table['kind']} targets, all on instruction boundaries")


def recover_source(launcher: Path, path: str, name: str, prefix: str, register: str, env: dict,
                   recovered: list[tuple[str, str]]) -> None:
    source = json.loads(run([str(launcher), "re", "decompile-native", path,
                             "--target", prefix + name, "--json"], env=env))
    add_recovered(source, name, prefix, register, recovered)


def add_recovered(source: dict, name: str, prefix: str, register: str, recovered: list[tuple[str, str]]) -> None:
    assert "structured" in source, source
    summary = source["structured"]
    assert summary["parameters"] == [{"index": 0, "register": register, "width": 32}], summary
    assert summary["return_width"] == 32, summary
    function = f"recovered_{len(recovered)}"
    pseudocode = summary["pseudocode"].replace(f" {prefix}{name}(", f" {function}(", 1)
    assert f" {function}(" in pseudocode, pseudocode
    if name == "choose":
        assert len(summary["dependencies"]) == 1, summary
        dependency = summary["dependencies"][0]["name"]
        pseudocode = pseudocode.replace(dependency, f"{function}_{dependency}")
    recovered.append((pseudocode, name))


LOOP_SOURCE = """\
unsigned loop_sum(unsigned value) {
    unsigned total = 0;
    while (value) { total += value; value -= 1; }
    return total;
}
"""

LOOP_DRIVER = """\
int main(void) { return (int)loop_sum(3); }
"""


def verify_loops(launcher: Path, root: Path, env: dict) -> None:
    """A recovered loop must be a statement list whose behaviour matches the original.

    The -O2 fixtures peel their loops into a guarded fast path, so this compiles a
    dedicated body at -O1, where the loop stays a single block.
    """
    source = root / "loop.c"
    source.write_text(LOOP_SOURCE, encoding="utf-8")
    driver = root / "loop_driver.c"
    driver.write_text("unsigned loop_sum(unsigned value);\n" + LOOP_DRIVER, encoding="utf-8")
    unoptimized_source = root / "countdown_o0.c"
    unoptimized_source.write_text("unsigned countdown_o0(unsigned n) { while (n) n--; return n; }\n"
                                  "int main(void) { return countdown_o0(3); }\n", encoding="utf-8")
    unoptimized = root / "loop_unoptimized"
    run(["cc", "-O0", "-fno-inline", str(unoptimized_source), "-o", str(unoptimized)])
    unoptimized_result = json.loads(run([str(launcher), "re", "decompile-native", str(unoptimized),
                                         "--target", "countdown_o0", "--json"], env=env))
    assert "structured" in unoptimized_result, unoptimized_result
    unoptimized_code = unoptimized_result["structured"]["pseudocode"].replace(" countdown_o0(", " recovered_o0(", 1)
    harness = '#include <stdint.h>\n' + unoptimized_code + """\
int main(void) {
    for (uint32_t n = 0; n < 4096; n++)
        if (recovered_o0(n) != 0) return 1;
    return 0;
}
"""
    (root / "verify_loop_o0.c").write_text(harness, encoding="utf-8")
    run(["cc", "-O2", "-std=c11", "-Wall", "-Werror", str(root / "verify_loop_o0.c"),
         "-o", str(root / "verify_loop_o0")])
    run([str(root / "verify_loop_o0")])
    print("unoptimized stack loop: recovered C matched the original for 4096 inputs")
    unoptimized_sum = root / "loop_sum_o0"
    run(["cc", "-O0", "-fno-inline", str(source), str(driver), "-o", str(unoptimized_sum)])
    result = json.loads(run([str(launcher), "re", "decompile-native", str(unoptimized_sum),
                             "--target", "loop_sum", "--json"], env=env))
    assert "structured" in result, result
    code = result["structured"]["pseudocode"].replace(" loop_sum(", " recovered_sum_o0(", 1)
    harness = '#include <stdint.h>\n' + LOOP_SOURCE + code + """\
int main(void) {
    for (uint32_t n = 0; n < 4096; n++)
        if (recovered_sum_o0(n) != loop_sum(n)) return 1;
    return 0;
}
"""
    (root / "verify_sum_o0.c").write_text(harness, encoding="utf-8")
    run(["cc", "-O2", "-std=c11", "-Wall", "-Werror", str(root / "verify_sum_o0.c"),
         "-o", str(root / "verify_sum_o0")])
    run([str(root / "verify_sum_o0")])
    print("unoptimized accumulator loop: recovered C matched the original for 4096 inputs")
    binary = root / "loop"
    run(["cc", "-O1", "-fno-inline", str(source), str(driver), "-o", str(binary)])
    result = json.loads(run([str(launcher), "re", "decompile-native", str(binary),
                             "--target", "loop_sum", "--json"], env=env))
    assert "structured" in result, result.get("structured_declined", result)
    summary = result["structured"]
    pseudocode = summary["pseudocode"]
    assert "for (;;)" in pseudocode and "break" in pseudocode, pseudocode
    program = (
        '#include <stdint.h>\n#include <stdio.h>\n'
        '_Noreturn void __assert_fail(void) { for (;;) {} }\n'
        + LOOP_SOURCE
        + pseudocode.replace(" loop_sum(", " recovered(")
        + """\
int main(void) {
    uint32_t sample = 0x45298a31u;
    for (unsigned i = 0; i < 4096; i++) {
        uint32_t input = i < 3 ? i : sample % 2048u;
        sample = sample * 1664525u + 1013904223u;
        if (recovered(input) != loop_sum(input)) return 1;
    }
    puts("recovered loop matched the original for 4096 inputs");
    return 0;
}
"""
    )
    (root / "loopcheck.c").write_text(program, encoding="utf-8")
    run(["cc", "-O2", "-std=c11", str(root / "loopcheck.c"), "-o", str(root / "loopcheck")])
    run([str(root / "loopcheck")])
    print("Loop recovery: statement-list summary matched the original for 4096 inputs")


def verify_structured(root: Path, recovered: list[tuple[str, str]]) -> None:
    functions = ", ".join(f"{{recovered_{i}, {name}}}" for i, (_, name) in enumerate(recovered))
    program = (
        '#include <stdint.h>\n#define main fixture_main\n#include "fixture.c"\n#undef main\n'
        + "\n".join(code for code, _ in recovered)
        + "\ntypedef uint32_t (*case_fn)(uint32_t);\n"
        + f"static struct {{ case_fn actual; case_fn expected; }} cases[] = {{{functions}}};\n"
        + """\
int main(void) {
    uint32_t sample = 0x45298a31u;
    for (unsigned i = 0; i < 4096; i++) {
        uint32_t input = i == 0 ? 0u : i == 1 ? UINT32_MAX : sample;
        sample = sample * 1664525u + 1013904223u;
        for (unsigned j = 0; j < sizeof(cases) / sizeof(cases[0]); j++) {
            if (cases[j].actual(input) != cases[j].expected(input)) return 1;
        }
    }
    return 0;
}
"""
    )
    (root / "structured.c").write_text(program, encoding="utf-8")
    run(["cc", "-O2", "-std=c11", "-Werror", "structured.c", "-o", "structured"], cwd=root)
    run([str(root / "structured")], cwd=root)
    print(f"Structured C matched the fixture for 4096 inputs across {len(recovered)} recovered functions")


PE_ARM64_MARKER = "XT-Forge ARM64 PE marker 2026"
PE_ARM64_SOURCE = f"""\
const char arm64_pe_marker[] = "{PE_ARM64_MARKER}";
__attribute__((noinline)) const char *arm64_pe_marker_ref(void) {{ return arm64_pe_marker; }}
__attribute__((noinline)) unsigned arm64_pe_helper(unsigned value) {{
    if (value == 0) return 7;
    return value + 1;
}}
__declspec(dllexport) unsigned arm64_pe_exported(unsigned value) {{
    return arm64_pe_helper(value) + 1;
}}
int main(void) {{
    volatile unsigned input = 3;
    return (int)arm64_pe_helper(input) + (arm64_pe_marker_ref()[0] != 0);
}}
"""


def verify_pe_arm64(launcher: Path, root: Path, env: dict) -> None:
    """Build a tiny arm64 PE and check entry mapping, decoding, and strings."""
    if shutil.which("clang") is None or shutil.which("lld-link") is None:
        print("Windows PE arm64: skipped (clang or lld-link is not available)")
        return
    source = root / "prog.c"
    obj = root / "prog.obj"
    image = root / "prog.exe"
    source.write_text(PE_ARM64_SOURCE, encoding="utf-8")
    run(["clang", "-target", "arm64-pc-windows-msvc", "-O1", "-funwind-tables",
         "-fno-inline", "-c", str(source), "-o", str(obj)])
    run(["lld-link", "/entry:main", "/subsystem:console", "/nodefaultlib",
         "/export:arm64_pe_exported", f"/out:{image}", str(obj)])
    overview = json.loads(run([str(launcher), "re", "overview", str(image), "--json"], env=env))
    assert overview["ok"] and overview["format"] == "pe", overview
    assert overview["images"], overview
    info = overview["images"][0]
    assert info["arch"] == "arm64", overview
    entry = info["entry_point"]
    offset = info["entry_file_offset"]
    assert isinstance(entry, int) and isinstance(offset, int), overview
    assert 0 <= offset < image.stat().st_size, (overview, image.stat().st_size)
    decoded = json.loads(run([str(launcher), "re", "disasm-native", str(image),
                              "--target", hex(entry), "--max-instructions", "32",
                              "--json"], env=env))
    assert decoded["ok"] and decoded["format"] == "pe" and decoded["arch"] == "arm64", decoded
    assert decoded["address"] == entry and decoded["file_offset"] == offset, decoded
    assert decoded["instructions"], decoded
    strings = json.loads(run([str(launcher), "re", "strings", str(image), "--json"], env=env))
    assert strings["ok"] and PE_ARM64_MARKER in strings["strings"], strings
    # Export-table naming: the binary declares this entry point, so the index must
    # carry the name. Without it an arm64 PE with no unwind table yields one
    # unnamed entry point and nothing else.
    functions = json.loads(run([str(launcher), "re", "functions", str(image), "--json"], env=env))
    assert functions["ok"], functions
    named = {item.get("name") for item in functions["images"][0]["functions"]}
    assert "arm64_pe_exported" in named, functions["images"][0]
    print(f"Windows PE arm64: format pe, arch arm64, entry {entry:#x} -> file offset {offset}, "
          f"{len(decoded['instructions'])} instructions, marker string found, "
          f"export named arm64_pe_exported")


PE_X86_MARKER = "XT-Forge X86 PE marker 2026"
PE_X86_SOURCE = f"""\
const char x86_pe_marker[] = "{PE_X86_MARKER}";
__attribute__((noinline)) const char *x86_pe_marker_ref(void) {{ return x86_pe_marker; }}
__attribute__((noinline)) unsigned x86_pe_helper(unsigned value) {{
    if (value == 0) return 7;
    return value + 1;
}}
__declspec(dllexport) unsigned x86_pe_exported(unsigned value) {{
    return x86_pe_helper(value) + 1;
}}
int main(void) {{
    volatile unsigned input = 3;
    return (int)x86_pe_helper(input) + (x86_pe_marker_ref()[0] != 0);
}}
"""


def verify_pe_x86(launcher: Path, root: Path, env: dict) -> None:
    """Build a 32-bit x86 PE and check entry mapping, decoding, and exports."""
    if shutil.which("clang") is None or shutil.which("lld-link") is None:
        print("Windows PE x86: skipped (clang or lld-link is not available)")
        return
    source = root / "prog32.c"
    obj = root / "prog32.obj"
    image = root / "prog32.exe"
    source.write_text(PE_X86_SOURCE, encoding="utf-8")
    try:
        run(["clang", "-target", "i686-pc-windows-msvc", "-O1", "-funwind-tables",
             "-fno-inline", "-c", str(source), "-o", str(obj)])
        run(["lld-link", "/entry:main", "/subsystem:console", "/nodefaultlib",
             "/export:x86_pe_exported", f"/out:{image}", str(obj)])
    except RuntimeError as error:
        print(f"Windows PE x86: skipped (i686 target unsupported or build failed: {error})")
        return
    overview = json.loads(run([str(launcher), "re", "overview", str(image), "--json"], env=env))
    assert overview["ok"] and overview["format"] == "pe", overview
    assert overview["images"], overview
    info = overview["images"][0]
    # The tool reports the 32-bit PE architecture as "x86" (not "i386").
    assert info["arch"] == "x86", overview
    entry = info["entry_point"]
    offset = info["entry_file_offset"]
    assert isinstance(entry, int) and isinstance(offset, int), overview
    assert 0 <= offset < image.stat().st_size, (overview, image.stat().st_size)
    decoded = json.loads(run([str(launcher), "re", "disasm-native", str(image),
                              "--target", hex(entry), "--max-instructions", "32",
                              "--json"], env=env))
    assert decoded["ok"] and decoded["format"] == "pe" and decoded["arch"] == "x86", decoded
    assert decoded["address"] == entry and decoded["file_offset"] == offset, decoded
    assert decoded["instructions"], decoded
    strings = json.loads(run([str(launcher), "re", "strings", str(image), "--json"], env=env))
    assert strings["ok"] and PE_X86_MARKER in strings["strings"], strings
    functions = json.loads(run([str(launcher), "re", "functions", str(image), "--json"], env=env))
    assert functions["ok"], functions
    named = {item.get("name") for item in functions["images"][0]["functions"]}
    assert "x86_pe_exported" in named, functions["images"][0]
    print(f"Windows PE x86: format pe, arch x86, entry {entry:#x} -> file offset {offset}, "
          f"{len(decoded['instructions'])} instructions, marker string found, "
          f"export named x86_pe_exported")


ELF32_SOURCE = """\
__attribute__((noinline)) unsigned elf32_helper(unsigned value) {
    if (value == 0) return 7;
    return value + 1;
}
int main(void) {
    volatile unsigned input = 3;
    return (int)elf32_helper(input);
}
"""


def verify_elf32_lane(launcher: Path, root: Path, env: dict) -> None:
    """Build a 32-bit x86 ELF and check its header mapping and entry decoding."""
    if shutil.which("clang") is None:
        print("ELF x86: skipped (clang is not available)")
        return
    source = root / "prog32.c"
    image = root / "prog32"
    source.write_text(ELF32_SOURCE, encoding="utf-8")
    try:
        run(["clang", "-m32", "-O1", "-fno-inline", "-o", str(image), str(source)])
    except RuntimeError as error:
        print(f"ELF x86: skipped (32-bit libc/crt objects unavailable for the -m32 link: {error})")
        return
    overview = json.loads(run([str(launcher), "re", "overview", str(image), "--json"], env=env))
    assert overview["ok"] and overview["format"] == "elf", overview
    assert overview["images"], overview
    info = overview["images"][0]
    assert info["bits"] == 32 and info["arch"] == "x86", overview
    assert info["sections"], overview
    entry = info["entry_point"]
    offset = info["entry_file_offset"]
    assert isinstance(entry, int) and isinstance(offset, int), overview
    assert 0 <= offset < image.stat().st_size, (overview, image.stat().st_size)
    decoded = json.loads(run([str(launcher), "re", "disasm-native", str(image),
                              "--target", hex(entry), "--max-instructions", "32",
                              "--json"], env=env))
    assert decoded["ok"] and decoded["format"] == "elf" and decoded["arch"] == "x86", decoded
    assert decoded["address"] == entry and decoded["file_offset"] == offset, decoded
    assert decoded["instructions"], decoded
    print(f"ELF x86: format elf, arch x86, bits 32, {len(info['sections'])} sections, "
          f"entry {entry:#x} -> file offset {offset}, {len(decoded['instructions'])} instructions")


COFF_SOURCE = """\
__attribute__((noinline)) unsigned coff_first(unsigned value) {
    return value + 1;
}
__attribute__((noinline)) unsigned coff_second(unsigned value) {
    return value * 3;
}
"""


def verify_coff_lane(launcher: Path, root: Path, env: dict) -> None:
    """Build a bare x86-64 COFF object and verify what the hub reports for it."""
    if shutil.which("clang") is None:
        print("COFF: skipped (clang is not available)")
        return
    # The hub is the component that reads the object header; the launcher's own
    # fallback does not parse bare COFF objects.
    hub = root / "native" / "xtforge-go" / ("xtforge-hub.exe" if os.name == "nt" else "xtforge-hub")
    drive = str(hub) if hub.is_file() else str(launcher)
    source = root / "prog.c"
    obj = root / "prog.obj"
    source.write_text(COFF_SOURCE, encoding="utf-8")
    try:
        run(["clang", "-target", "x86_64-pc-windows-msvc", "-O1", "-c", str(source), "-o", str(obj)])
    except RuntimeError as error:
        print(f"COFF: skipped (clang cannot produce the x86_64-pc-windows-msvc object: {error})")
        return
    overview = json.loads(run([drive, "re", "overview", str(obj), "--json"], env=env))
    assert overview["ok"] and overview["images"], overview
    info = overview["images"][0]
    # An object is not runnable; the linker has not produced an entry point.
    assert info["entry_point"] is None, overview
    if overview["format"] == "coff" and info.get("coff"):
        coff = info["coff"]
        machine = coff["machine"]
        # 0x8664 is 34404 in decimal; also accept the literal value some tools
        # report for this machine so the check follows the hub rather than a
        # hard-coded convention.
        assert machine == 0x8664, overview
        # COFF sections live on the coff record, not on image.sections: an object
        # has no loadable regions, only section headers.
        sections = [region["name"] for region in coff["sections"] if region.get("name")]
        assert len(sections) >= 2, overview
        print(f"COFF: format coff, machine {machine} ({machine:#x}), "
              f"{len(sections)} sections ({', '.join(sections)}), no entry point")
        return
    # The hub no longer lacks a COFF loader, so this branch must not exist as a
    # permissive fallback: a lane that also accepts "unknown" would pass happily
    # while COFF support silently regressed. Fail loudly instead.
    raise AssertionError(f"COFF object was not recognised: {overview}")


ARM_ELF_SOURCE = """\
__attribute__((noinline)) unsigned arm_first(unsigned value) {
    return value + 1;
}
__attribute__((noinline)) unsigned arm_second(unsigned value) {
    return value * 3;
}
int main(void) {
    return (int)(arm_first(3) + arm_second(4));
}
"""


def verify_arm_elf_lane(launcher: Path, root: Path, env: dict) -> None:
    """Build a freestanding 32-bit ARM ELF object and check mapping and disassembly."""
    if shutil.which("clang") is None:
        print("ELF arm: skipped (clang is not available)")
        return
    hub = root / "native" / "xtforge-go" / ("xtforge-hub.exe" if os.name == "nt" else "xtforge-hub")
    drive = str(hub) if hub.is_file() else str(launcher)
    source = root / "prog.c"
    obj = root / "prog.o"
    source.write_text(ARM_ELF_SOURCE, encoding="utf-8")
    try:
        run(["clang", "-target", "armv7-none-eabi", "-O1", "-c", str(source), "-o", str(obj)])
    except RuntimeError as error:
        print(f"ELF arm: skipped (clang cannot produce the armv7-none-eabi object: {error})")
        return
    overview = json.loads(run([drive, "re", "overview", str(obj), "--json"], env=env))
    assert overview["ok"] and overview["format"] == "elf", overview
    assert overview["images"], overview
    info = overview["images"][0]
    assert info["arch"] == "arm" and info["bits"] == 32, overview
    assert info["sections"], overview
    # A relocatable object puts every section at address 0, so "address 0x0" is
    # genuinely ambiguous and the hub refuses it — correctly. Disassembly is therefore
    # proven on a LINKED freestanding ARM executable, which has real addresses. Linking
    # needs lld and no libc, hence -nostdlib.
    linked = root / "prog_arm_linked"
    try:
        run(["clang", "-target", "armv7-none-eabi", "-O1", "-fno-inline", "-nostdlib",
             "-fuse-ld=lld", "-Wl,-e,main", str(source), "-o", str(linked)])
    except RuntimeError as error:
        print(f"ELF arm: format elf, arch {info['arch']}, bits {info['bits']}, "
              f"{len(info['sections'])} sections, no entry point")
        print(f"ELF arm: disassembly skipped (cannot link an ARM executable: {error})")
        return
    linked_overview = json.loads(run([drive, "re", "overview", str(linked), "--json"], env=env))
    assert linked_overview["ok"] and linked_overview["format"] == "elf", linked_overview
    entry = linked_overview["images"][0].get("entry_point")
    assert isinstance(entry, int), linked_overview
    decoded = json.loads(run([drive, "re", "disasm-native", str(linked),
                              "--target", hex(entry), "--json"], env=env))
    assert decoded["ok"] and decoded["arch"] == "arm", decoded
    instructions = decoded["instructions"]
    assert len(instructions) >= 4, decoded
    assert all(ins.get("mnemonic") for ins in instructions), decoded
    opaque = sum(ins["mnemonic"] == "opaque" for ins in instructions)
    assert opaque < len(instructions), decoded
    print(f"ELF arm: format elf, arch {info['arch']}, bits {info['bits']}, "
          f"{len(info['sections'])} sections; linked entry {entry:#x} decoded "
          f"{len(instructions)} instructions ({opaque} opaque)")


def note_macho32_skip() -> None:
    """Report why this tree has no 32-bit Mach-O verifier lane."""
    print("Mach-O x86: skipped (32-bit Mach-O cannot be linked: ld64.lld does not support -arch i386)")


PE_DLL_MARKER = "XT-Forge ARM64 PE DLL marker 2026"
PE_DLL_SOURCE = f"""\
const char arm64_dll_marker[] = "{PE_DLL_MARKER}";
__attribute__((noinline)) const char *arm64_dll_marker_ref(void) {{ return arm64_dll_marker; }}
__declspec(dllexport) unsigned arm64_dll_exported(unsigned value) {{
    return value + (arm64_dll_marker_ref()[0] != 0);
}}
"""


def verify_pe_dll(launcher: Path, root: Path, env: dict) -> None:
    """Build an arm64 PE DLL and check loader information and its export."""
    if shutil.which("clang") is None or shutil.which("lld-link") is None:
        print("Windows PE dll: skipped (clang or lld-link is not available)")
        return
    source = root / "prog_dll.c"
    obj = root / "prog_dll.obj"
    image = root / "prog_dll.dll"
    source.write_text(PE_DLL_SOURCE, encoding="utf-8")
    try:
        run(["clang", "-target", "arm64-pc-windows-msvc", "-O1", "-funwind-tables",
             "-fno-inline", "-c", str(source), "-o", str(obj)])
        run(["lld-link", "/dll", "/noentry", "/nodefaultlib",
             "/export:arm64_dll_exported", f"/out:{image}", str(obj)])
    except RuntimeError as error:
        print(f"Windows PE dll: skipped (DLL link unsupported or build failed: {error})")
        return
    overview = json.loads(run([str(launcher), "re", "overview", str(image), "--json"], env=env))
    assert overview["ok"] and overview["format"] == "pe", overview
    assert overview["images"], overview
    assert overview["images"][0]["arch"] == "arm64", overview
    # The PE header reader reports the no-entry image as PE32+/ARM64 at RVA 0.
    loader = json.loads(run([str(launcher), "re", "info", str(image), "--json"], env=env))
    assert loader["ok"] and loader["format"] == "PE32+", loader
    assert loader["machine"] == "ARM64" and loader["entry_point"] == "0x0", loader
    functions = json.loads(run([str(launcher), "re", "functions", str(image), "--json"], env=env))
    assert functions["ok"], functions
    exported = [item for item in functions["images"][0]["functions"]
                if item.get("name") == "arm64_dll_exported"]
    assert len(exported) == 1, functions["images"][0]
    assert exported[0]["source"] == "pe_export", functions["images"][0]
    decoded = json.loads(run([str(launcher), "re", "disasm-native", str(image),
                              "--target", "arm64_dll_exported", "--max-instructions", "32",
                              "--json"], env=env))
    assert decoded["ok"] and decoded["format"] == "pe" and decoded["arch"] == "arm64", decoded
    assert decoded["name"] == "arm64_dll_exported" and decoded["instructions"], decoded
    print(f"Windows PE dll: format pe, arch arm64, loader {loader['format']} "
          f"{loader['machine']} entry {loader['entry_point']}, "
          f"{len(decoded['instructions'])} instructions, export named arm64_dll_exported")


def verify_pdb_lane(launcher: Path, root: Path, env: dict) -> None:
    """A matched PDB names functions; a mismatched PDB is rejected wholesale."""
    if shutil.which("clang") is None or shutil.which("lld-link") is None:
        print("PDB naming: skipped (clang or lld-link is not available)")
        return
    helper = "xt_pdb_helper_bravo"
    source = root / "prog.c"
    obj = root / "prog.obj"
    image = root / "prog.exe"
    pdb = root / "prog.pdb"
    source.write_text(f"""\
__attribute__((noinline)) unsigned {helper}(unsigned value) {{ return value + 1; }}
int main(void) {{ volatile unsigned input = 3; return (int){helper}(input); }}
""", encoding="utf-8")
    run(["clang", "-target", "x86_64-pc-windows-msvc", "-O1", "-g", "-gcodeview",
         "-c", str(source), "-o", str(obj)])
    run(["lld-link", "/entry:main", "/subsystem:console", "/nodefaultlib", "/debug",
         f"/pdb:{pdb}", f"/out:{image}", str(obj)])
    matched = json.loads(run([str(launcher), "re", "functions", str(image), "--json"], env=env))
    assert matched["ok"] and matched["images"], matched
    info = matched["images"][0]
    record = info.get("pdb")
    assert record and record.get("matched") is True, info
    guid = record.get("guid")
    assert guid and isinstance(guid, str), info
    named = [fn for fn in info["functions"] if fn.get("name") == helper]
    assert named, info["functions"]
    # S_GPROC32 records are the primary naming source: they carry the code size
    # and a rendered signature, while pdb_public only covers code the module
    # streams do not describe.
    procedures = [fn for fn in info["functions"] if fn.get("name_source") == "pdb_procedure"]
    assert procedures, info["functions"]
    procedure = procedures[0]
    assert procedure.get("size", 0) > 0, procedure
    signature = procedure.get("signature")
    assert isinstance(signature, str) and signature.strip() and "(" in signature and ")" in signature, procedure
    helper_function = named[0]
    assert helper_function.get("name") == helper, helper_function
    helper_signature = helper_function.get("signature")
    assert isinstance(helper_signature, str) and helper_signature.strip(), helper_function

    # A PDB from a different build has a different GUID/age; the hub must refuse
    # it rather than attach wrong names to wrong addresses.
    other_source = root / "other.c"
    other_source.write_text("""\
__attribute__((noinline)) unsigned xt_pdb_other_helper(unsigned value) { return value * 9; }
int main(void) { volatile unsigned input = 7; return (int)xt_pdb_other_helper(input); }
""", encoding="utf-8")
    other_obj, other_image, other_pdb = root / "other.obj", root / "other.exe", root / "other.pdb"
    run(["clang", "-target", "x86_64-pc-windows-msvc", "-O1", "-g", "-gcodeview",
         "-c", str(other_source), "-o", str(other_obj)])
    run(["lld-link", "/entry:main", "/subsystem:console", "/nodefaultlib", "/debug",
         f"/pdb:{other_pdb}", f"/out:{other_image}", str(other_obj)])
    shutil.copy2(other_pdb, pdb)
    rejected = json.loads(run([str(launcher), "re", "functions", str(image), "--json"], env=env))
    assert rejected["ok"] and rejected["images"], rejected
    bad_info = rejected["images"][0]
    bad_record = bad_info.get("pdb")
    assert bad_record is None or bad_record.get("matched") is False, bad_info
    assert not any(fn.get("name_source") == "pdb_public" for fn in bad_info["functions"]), bad_info["functions"]
    warnings = [str(item) for item in (bad_info.get("warnings") or []) + (rejected.get("warnings") or [])]
    assert any("pdb" in warning.lower() and "match" in warning.lower()
               for warning in warnings), (warnings, bad_info)
    print(f"PDB naming: guid {guid} matched, {len(procedures)} procedures, helper {helper} "
          f"named via {helper_function.get('name_source')} with signature {helper_signature}; "
          f"mismatched PDB rejected (no pdb_public names, mismatch warning)")


def verify_archive_lane(launcher: Path, root: Path, env: dict) -> None:
    """A static archive is reported as an archive with its member names."""
    if shutil.which("ar") is None:
        print("Archive: skipped (ar is not available)")
        return
    # Names must fit ar's 16-byte header field; longer ones move to the
    # long-name table, which is not what this lane is checking.
    first, second = root / "archive_a.o", root / "archive_b.o"
    run(["cc", "-c", "fixture.c", "-o", first.name], cwd=root)
    run(["cc", "-c", "fixture.c", "-o", second.name], cwd=root)
    run(["ar", "rcs", "lib.a", first.name, second.name], cwd=root)
    overview = json.loads(run([str(launcher), "re", "overview", str(root / "lib.a"), "--json"], env=env))
    assert overview["ok"] and overview["format"] == "archive", overview
    members = overview["archive"]
    assert len(members) >= 2, overview
    names = [member["name"] for member in members]
    assert {first.name, second.name} <= set(names), overview
    print(f"Archive: format archive, {len(members)} members ({', '.join(names)})")


def _der_tlv(tag: int, value: bytes) -> bytes:
    """Encode one Image4 DER tag-length-value record (short, 0x81 or 0x82 length)."""
    length = len(value)
    if length < 128:
        header = bytes([length])
    elif length < 256:
        header = bytes([0x81, length])
    elif length < 65536:
        header = b"\x82" + length.to_bytes(2, "big")
    else:
        raise ValueError(f"Image4 field of {length} bytes is too large for this fixture")
    return bytes([tag]) + header + value


def verify_kernelcache_lane(launcher: Path, root: Path, env: dict) -> None:
    """Wrap an existing Mach-O in IMG4 and check the kernelcache container gate."""
    macho = root / "ios"
    bare = json.loads(run([str(launcher), "re", "overview", str(macho), "--json"], env=env))
    assert bare["ok"] and bare["images"], bare
    arch = bare["images"][0]["arch"]
    payload = macho.read_bytes()
    im4p = _der_tlv(0x16, b"IM4P") + _der_tlv(0x16, b"krnl") + _der_tlv(0x16, b"kernel")
    im4p += _der_tlv(0x04, payload)
    # An IMG4 file is the magic followed by a SEQUENCE whose children include
    # the IM4P record sequence carrying the payload.
    image4 = _der_tlv(0x16, b"IMG4") + _der_tlv(0x30, im4p)
    container = root / "kernelcache.img4"
    container.write_bytes(b"IMG4" + _der_tlv(0x30, image4))
    overview = json.loads(run([str(launcher), "re", "overview", str(container), "--json"], env=env))
    assert overview["ok"] and overview["format"] == "kernelcache", overview
    assert overview["member"] == "img4-kernel", overview
    assert overview["images"] and overview["images"][0]["arch"] == arch, overview
    # A malformed container must be rejected rather than accepted as a Mach-O.
    broken = root / "kernelcache-bad.img4"
    broken.write_bytes(b"IMG4" + bytes(128))
    rejected = subprocess.run([str(launcher), "re", "overview", str(broken), "--json"],
                              cwd=ROOT, env=env, text=True, capture_output=True)
    # The hub exits non-zero and prints a pretty-printed JSON error, so run()
    # cannot be used here; decode every JSON object across both streams.
    payloads = []
    decoder = json.JSONDecoder()
    for stream in (rejected.stdout, rejected.stderr):
        pos = 0
        while (start := stream.find("{", pos)) >= 0:
            try:
                item, end = decoder.raw_decode(stream[start:])
            except json.JSONDecodeError:
                pos = start + 1
                continue
            if isinstance(item, dict):
                payloads.append(item)
            pos = start + end
    assert any(item.get("ok") is False for item in payloads), (rejected.returncode, rejected.stdout, rejected.stderr)
    print(f"Kernelcache: format kernelcache, member {overview['member']}, arch {arch}, malformed IMG4 rejected")


def verify_elf_versions_lane(launcher: Path, root: Path, env: dict) -> None:
    """Dynamically linked ELFs carry symbol versions; names vary by distro."""
    elf = next((path for path in (Path("/bin/ls"), Path("/usr/bin/ls"), root / "linux")
                if path.is_file()), None)
    if elf is None:
        print("ELF symbol versions: skipped (no dynamic ELF available)")
        return
    overview = json.loads(run([str(launcher), "re", "overview", str(elf), "--json"], env=env))
    assert overview["ok"] and overview["format"] == "elf" and overview["images"], overview
    image = overview["images"][0]
    if not any("libc.so" in dependency for dependency in image.get("dependencies", [])):
        print(f"ELF symbol versions: skipped ({elf} does not link libc dynamically)")
        return
    versions = image.get("versions") or []
    assert versions, overview
    assert all(isinstance(entry, dict) and entry.get("name") and entry.get("version")
               for entry in versions), overview
    assert any(entry.get("library") for entry in versions), overview
    library = next(entry["library"] for entry in versions if entry.get("library"))
    print(f"ELF symbol versions: {len(versions)} versioned symbols from {library} in {elf.name}")


def verify_primitives_lane(launcher: Path, root: Path, env: dict) -> None:
    """Swift demangling, call graph and section entropy are reachable from the hub.

    demangle and callgraph are spoken by the Go hub. They are driven through the hub
    binary directly rather than through `bin/xtforge`: the launcher reached through
    this lane lives in a temporary tree that carries the native binary and the hub but
    not the Python package, so its Python fallback has nothing to import. Driving the
    hub is what actually exercises the new code.
    """
    hub = root / "native" / "xtforge-go" / ("xtforge-hub.exe" if os.name == "nt" else "xtforge-hub")
    drive = str(hub) if hub.is_file() else str(launcher)
    demangled = json.loads(run([drive, "re", "demangle",
                                '_$s10Foundation10CocoaErrorV4CodeV16fileReadTooLargeAEvgZ',
                                "main"], env=env))
    assert demangled["ok"] and len(demangled["results"]) == 2, demangled
    swift, plain = demangled["results"]
    assert swift["demangled"] and "Foundation" in swift["demangled"], demangled
    assert plain["demangled"] == "", demangled
    elf = next((path for path in (root / "linux", Path("/bin/ls"), Path("/usr/bin/ls"))
                if path.is_file()), None)
    if elf is None:
        print("Primitives: skipped (no ELF available)")
        return
    graph = json.loads(run([drive, "re", "callgraph", str(elf), "--json"], env=env))
    assert graph["ok"] and graph["nodes"] >= 2, graph
    assert isinstance(graph["edges"], int) and graph["edges"] >= 0, graph
    overview = json.loads(run([str(launcher), "re", "overview", str(elf), "--json"], env=env))
    assert overview["ok"] and overview["images"], overview
    image = overview["images"][0]
    assert "section_entropy" in image and image["section_entropy"], overview
    entropy = image["section_entropy"]
    assert all({"name", "entropy", "class", "bytes"} <= set(entry) for entry in entropy), overview
    assert any(entry["class"] in ("low", "structured", "high", "very-high") for entry in entropy), overview
    print(f"Primitives: demangled Foundation symbol, callgraph {graph['nodes']} nodes / "
          f"{graph['edges']} edges, {len(entropy)} entropy regions in {elf.name}")


def verify_unknown_lane(launcher: Path, root: Path, env: dict) -> None:
    """A file no loader claims gets a bounded report with a whole-file hash."""
    hub = root / "native" / "xtforge-go" / ("xtforge-hub.exe" if os.name == "nt" else "xtforge-hub")
    drive = str(hub) if hub.is_file() else str(launcher)
    markers = (b"XT-UNKNOWN-BLOB-MARKER", b"no loader claims this blob")
    blob = root / "unknown.bin"
    data = bytearray(random.Random(1234).randbytes(4096))
    for offset, marker in zip((32, 160), markers):
        # NUL boundaries keep each overlay run separate from the random bytes.
        data[offset:offset + len(marker) + 2] = b"\x00" + marker + b"\x00"
    blob.write_bytes(data)
    overview = json.loads(run([drive, "re", "overview", str(blob), "--json"], env=env))
    assert overview["ok"] and overview["format"] == "unknown", overview
    assert len(overview["images"]) == 1, overview
    unknown = overview["images"][0]["unknown"]
    assert unknown, overview
    assert unknown["size"] == len(data), unknown
    # Independent hash implementation: the implementation must hash every byte,
    # not just the bounded preview it reports.
    assert unknown["sha256"] == hashlib.sha256(data).hexdigest(), unknown
    assert unknown["entropy_class"] in ("low", "structured", "high", "very-high"), unknown
    assert re.fullmatch(r"[0-9a-f]{16}", unknown["magic"]), unknown
    assert unknown["hex_preview"].startswith(unknown["magic"]), unknown
    assert isinstance(unknown["strings"], list), unknown
    assert all(marker.decode("ascii") in unknown["strings"] for marker in markers), unknown
    note = unknown["note"].lower()
    assert "no disassembly" in note and "was attempted" in note, unknown

    # A truncated preview must not shrink the hash to the bytes it happens to show.
    oversized = bytearray(random.Random(4321).randbytes((1 << 20) + 4096))
    for offset, marker in zip((32, 160), markers):
        oversized[offset:offset + len(marker) + 2] = b"\x00" + marker + b"\x00"
    large_blob = root / "unknown-large.bin"
    large_blob.write_bytes(oversized)
    large = json.loads(run([drive, "re", "overview", str(large_blob), "--json"], env=env))
    assert large["ok"] and large["format"] == "unknown", large
    large_unknown = large["images"][0]["unknown"]
    assert large_unknown["truncated"] is True, large
    assert large_unknown["sha256"] == hashlib.sha256(oversized).hexdigest(), large

    # The fallback is a last resort: loaders must still claim real binaries.
    elf = next((path for path in (root / "linux", Path("/bin/ls"), Path("/usr/bin/ls"))
                if path.is_file()), None)
    assert elf is not None, "no ELF available for the unknown-format guard"
    real = json.loads(run([drive, "re", "overview", str(elf), "--json"], env=env))
    assert real["ok"] and real["format"] != "unknown" and real["images"], real
    assert all(image.get("unknown") is None for image in real["images"]), real
    print(f"Unknown: format unknown, {unknown['size']} bytes, sha256 {unknown['sha256'][:16]}..., "
          f"entropy {unknown['entropy']:.2f} ({unknown['entropy_class']}), "
          f"{len(unknown['strings'])} strings; whole-file hash kept for {large_unknown['size']} "
          f"truncated bytes; {elf.name} still {real['format']}")


def verify_mcp(launcher: Path, root: Path, env: dict) -> None:
    args = {"path": str(root / "Fixture.ipa"), "arch": "arm64", "target": "_choose", "flow": True}
    for label, cmd, tool, arguments in [
        ("Go", [str(launcher), "--meta"], "xt_call", {"name": "re_disasm_native", "arguments": args}),
        ("Python", [sys.executable, "-m", "xtforge.cli", "mcp", "serve"], "re_inspect", {**args, "verb": "disasm-native"}),
    ]:
        request = {"jsonrpc": "2.0", "id": 7, "method": "tools/call",
                   "params": {"name": tool, "arguments": arguments}}
        result = json.loads(run(cmd, env=env, input=json.dumps(request) + "\n").splitlines()[-1])["result"]
        assert not result.get("isError"), (label, result)
        body = json.loads(result["content"][0]["text"])
        value = body.get("data", body)
        assert value["arch"] == "arm64" and value["mode"] == "flow" and len(value["blocks"]) >= 3, (label, value)
        print(f"{label} MCP verified on arm64 IPA")
        if label == "Go":
            arguments["name"] = "re_decompile_native"
        else:
            arguments["verb"] = "decompile-native"
        result = json.loads(run(cmd, env=env, input=json.dumps(request) + "\n").splitlines()[-1])["result"]
        assert not result.get("isError"), (label, result)
        body = json.loads(result["content"][0]["text"])
        value = body.get("data", body)
        assert value["arch"] == "arm64" and value["coverage"]["lifted"] > 0 and "return_to_caller(" in value["pseudocode"], (label, value)
        assert len(value["structured"]["dependencies"]) == 1, (label, value)
        print(f"{label} MCP native lift and direct-call composition verified on arm64 IPA")
        args["target"] = "_pure"
        if label == "Python":
            arguments["target"] = "_pure"
        result = json.loads(run(cmd, env=env, input=json.dumps(request) + "\n").splitlines()[-1])["result"]
        assert not result.get("isError"), (label, result)
        body = json.loads(result["content"][0]["text"])
        value = body.get("data", body)
        assert value["structured"]["return_width"] == 32, (label, value)
        args["target"] = "_choose"
        print(f"{label} MCP structured recovery verified on arm64 IPA")
        cross = {"path": args["path"], "arch": "arm64", "target": "_increment", "max_functions": 20}
        if label == "Go":
            request["params"]["arguments"] = {"name": "re_xrefs_native", "arguments": cross}
        else:
            request["params"]["arguments"] = {**cross, "verb": "xrefs-native"}
        result = json.loads(run(cmd, env=env, input=json.dumps(request) + "\n").splitlines()[-1])["result"]
        assert not result.get("isError"), (label, result)
        body = json.loads(result["content"][0]["text"])
        value = body.get("data", body)
        assert any(ref.get("function_name") == "_choose" and ref["kind"] == "call"
                   for ref in value["references"]), (label, value)
        print(f"{label} MCP native cross-references verified on arm64 IPA")
        dispatch = {"path": args["path"], "arch": "arm64", "target": "_dispatch_table"}
        if label == "Go":
            request["params"]["arguments"] = {"name": "re_dispatch_native", "arguments": dispatch}
        else:
            request["params"]["arguments"] = {**dispatch, "verb": "dispatch-native"}
        result = json.loads(run(cmd, env=env, input=json.dumps(request) + "\n").splitlines()[-1])["result"]
        assert not result.get("isError"), (label, result)
        body = json.loads(result["content"][0]["text"])
        value = body.get("data", body)
        tables = value.get("tables") or []
        assert len(tables) == 1 and tables[0]["kind"] in ("arm64_byte_table", "arm64_offset_table"), (label, value)
        assert len(tables[0]["targets"]) == 12 and tables[0]["bound"] == 11, (label, value)
        print(f"{label} MCP dispatch recovery verified on arm64 IPA")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--native-binary", type=Path, help="reuse an existing Rust launcher build")
    options = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="xtforge-native-flow-") as temp:
        root = Path(temp)
        launch = build(root, options.native_binary)
        fixtures(root)
        env = {**os.environ, "XT_ROOT": str(root), "XT_HOME": str(root / "state"),
               "XT_FORCE_PYTHON": "0", "XT_NATIVE_HUB": "1"}
        verify_cli(launch, root, env)
        verify_pe_arm64(launch, root, env)
        verify_pe_x86(launch, root, env)
        verify_elf32_lane(launch, root, env)
        verify_coff_lane(launch, root, env)
        verify_arm_elf_lane(launch, root, env)
        # No 32-bit Mach-O lane: clang compiles -target i386-apple-macos10.7 objects,
        # but ld64.lld rejects -arch i386, so no i386 Mach-O image can be linked here.
        note_macho32_skip()
        verify_pe_dll(launch, root, env)
        verify_pdb_lane(launch, root, env)
        verify_archive_lane(launch, root, env)
        verify_kernelcache_lane(launch, root, env)
        verify_elf_versions_lane(launch, root, env)
        verify_primitives_lane(launch, root, env)
        verify_unknown_lane(launch, root, env)
        verify_mcp(launch, root, env)
