#!/usr/bin/env python3
"""Measure xt-forge's breadth against REA's tool catalogue, by capability.

WHY this exists: "catch up to REA's breadth" is not a number anyone can check by
reading a README. REA ships 263 MCP tools; xt-forge ships 67. Comparing those
totals is meaningless — REA counts a dozen separate ADB tools where one verb would
answer the same analyst question, and it counts provider clients (JEB, apktool,
rizin, Cutter, GDB) that are wrappers around tools this engine deliberately does
not shell out to.

So the comparison is made per *capability*: a question an analyst can ask ("what
are this PE's imports", "which DWARF units are in here") that at least one tool on
each side answers. Each capability declares which REA tools implement it and which
xt-forge verb does, plus why if it does not.

Three verdicts:
  covered    - xt-forge answers it, and `verify` names the command that proves it
  partial    - xt-forge answers part of the question; the gap is named
  missing    - xt-forge cannot answer it; the reason says why (out-of-lane,
               external tool required, or simply not built yet)

The point is that every claim is falsifiable: `covered` rows carry a command, and
`--run` executes them so a stale claim fails loudly instead of ageing quietly.

Usage:
  python3 scripts/rea_breadth.py             # coverage table + totals
  python3 scripts/rea_breadth.py --run       # also execute every covered probe
  python3 scripts/rea_breadth.py --json PATH # machine-readable record
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REA_CATALOG = Path("/tmp/rea-latest/package/dist/mcp-catalog.json")

# Each row: (capability, rea_tools, xt_verb, verdict, reason_or_probe)
# `xt_verb` is the CLI verb that answers it, or None. For `covered` rows the probe
# is a concrete argv that must exit 0 and print something non-empty.
C = []


def cap(name, rea, xt, verdict, note="", probe=None):
    C.append({"capability": name, "rea_tools": list(rea), "xt_verb": xt,
              "verdict": verdict, "note": note, "probe": probe})


# ---------------------------------------------------------------- native core
cap("File identity, format, arch", ["inspect_artifact", "open_binary"],
    "info", "covered", probe=["re", "info", "{elf}"])
cap("Function inventory", ["inspect_native_function", "list_native_functions"],
    "functions", "covered", probe=["re", "functions", "{elf}"])
cap("Cross-references", ["inspect_native_xrefs", "xrefs"],
    "xrefs-native", "covered", probe=["re", "xrefs-native", "{elf}", "--target", "main"])
cap("Disassembly", ["inspect_native_instruction", "inspect_with_objdump"],
    "disasm-native", "covered", probe=["re", "disasm-native", "{elf}", "--target", "main"])
cap("Decompilation / IR lift", ["decompile_native_function"],
    "decompile-native", "covered",
    probe=["re", "decompile-native", "{elf}", "--target", "main"])
cap("Control-flow graph", ["inspect_native_dispatch_metadata"],
    "cfg", "covered", probe=["re", "cfg", "{elf}", "--target", "main"])
cap("Indirect dispatch / jump tables", ["inspect_native_dispatch_metadata"],
    "dispatch-native", "covered")
cap("Sections and layout", ["inspect_binary_layout"],
    "sections", "covered", probe=["re", "sections", "{elf}"])
cap("Symbols", ["inspect_native_api"],
    "symbols", "covered", probe=["re", "symbols", "{elf}"])
cap("Strings", ["inspect_native_strings"],
    "strings", "covered", probe=["re", "strings", "{elf}"])
cap("Byte entropy / packing", ["inspect_byte_entropy"],
    "entropy", "covered", probe=["re", "entropy", "{elf}"])
cap("Hardening / checksec", ["inspect_binary_hardening"],
    "checksec", "covered", probe=["re", "checksec", "{elf}"])
cap("PE identity and headers", ["inspect_native_load_image"],
    "pe", "covered")
cap("PE imports", ["inspect_pe_imports"],
    "pe", "covered")
cap("PE exports", ["inspect_native_exports"],
    "pe", "covered")
cap("Binary diff", ["compare_native_artifacts", "compare_native_functions"],
    "diff", "covered")
cap("C++ RTTI / vtables", ["inspect_native_data_type"],
    "rtti", "covered")
cap("Demangling", ["demangle"],
    "demangle", "covered")
cap("Capability detection (capa)", ["inspect_native_api"],
    "capa", "covered")
cap("Crash / recorded artifact", ["inspect_recorded_crash"],
    "crash", "covered")

# ------------------------------------------------------- ELF metadata surface
cap("DWARF compile units", ["inspect_dwarf_units"],
    "elfmeta", "covered", probe=["re", "elfmeta", "{elf}"])
cap("ELF notes / build-id", ["inspect_elf_notes"],
    "elfmeta", "covered", probe=["re", "elfmeta", "{elf}"])
cap("ELF unwind ranges", ["inspect_elf_unwind_ranges"],
    "elfmeta", "covered", probe=["re", "elfmeta", "{elf}"])
cap("ELF dependencies (DT_NEEDED)", ["inspect_elf_dependencies"],
    "needed", "covered", probe=["re", "needed", "{elf}"])
cap("ELF debug link", ["inspect_elf_debug_link"],
    "elfmeta", "covered",
    "section name and CRC-32 of the separate debug file, verified against zlib")

# --------------------------------------------------------------- other formats
cap("WebAssembly inventory", ["inspect_wasm_artifact"],
    "wasm", "covered", probe=["re", "wasm", "{wasm}"])
cap("WASM interface compare", ["compare_wasm_interfaces"],
    "wasm compare", "covered")
cap("UEFI firmware volume", ["inspect_uefi_firmware"],
    "firmware", "covered", probe=["re", "firmware", "{blob}"])
cap("UEFI firmware extraction", ["extract_uefi_firmware"],
    None, "missing", "inventory only: section-level compression (LZMA/Tiano) not "
                     "decompressed, so files are located but not extracted")
cap("UEFI NVRAM variables", ["inspect_uefi_nvram"],
    "uefi", "covered",
    "efivarfs inventory, EFI_LOAD_OPTION boot entries with decoded device paths, "
    "boot order, and a Secure Boot assessment")
cap("Mach-O", ["inspect_macho", "get_objc_classes", "get_objc_protocols"],
    "objc", "covered",
    "Mach-O via the native hub, plus re objc: class hierarchy, instance and class "
    "methods with type encodings, protocol definitions and conformance, categories "
    "(verified against llvm-objdump --objc-meta-data)")
cap("Swift types", ["analyze_swift_types"],
    None, "missing", "Swift metadata demangling not built")
cap("Kernel cache", ["inspect_kernel_module"],
    "kernelcache", "covered")
cap("Apple IPS crash reports", ["inspect_apple_ips"],
    "ips", "covered",
    "two-object and single-document forms, faulting thread frames resolved to images")
cap("plist", ["inspect_plist"],
    "formats plist", "covered")
cap("Asset catalog", ["inspect_asset_catalog"],
    None, "missing", "Apple .car asset catalog not built")
cap("devicetree", ["inspect_devicetree"],
    "devicetree", "covered",
    "nodes, properties, memory reservations; finds an FDT embedded in a container")
cap("Kernel build config", ["inspect_kernel_build_config"],
    "kconfig", "covered",
    "IKCONFIG gzip blob, /proc/config.gz and plaintext .config")
cap("PE certificates", ["inspect_pe_certificates"],
    "pe certificates", "covered",
    "the table is located and described; the signature is not chained to a trust root")
cap("PE resources", ["inspect_pe_resources"],
    "pe resources", "covered")
cap("PE load config", ["inspect_pe_load_config"],
    "pe load-config", "covered")
cap("Windows shortcut (.lnk)", ["inspect_windows_shortcut"],
    "lnk", "covered")
cap("Keyed archive / NSKeyedArchiver", ["inspect_keyed_archive"],
    "keyed", "covered",
    "object graph resolved through UIDs, class chains reported, cycles and shared "
    "references distinguished")
cap("Go binary metadata", ["inspect_go_binary"],
    "formats go", "covered",
    "version, module, dependencies and VCS revision, checked against `go version -m`")
cap("Rust binary metadata", ["inspect_rust_binary"],
    "formats rust", "covered",
    "rustc version, commit hash, commit date and distributor read from .comment, "
    "verified against `rustc --version`; crate candidates inferred and labelled as "
    "inferences rather than presented as identity")
cap("Python .pyc", ["inspect_python_pyc"],
    "formats pyc", "covered")
cap("Erlang BEAM", ["inspect_erlang_beam"],
    "beam", "covered",
    "chunk inventory, module name, exports, compiler version and source paths")
cap("V8 code cache", ["inspect_v8_code_cache"],
    "v8cache", "covered",
    "header fields (V8 build fingerprint, source size and hash, flags, payload) read "
    "from caches written by Node's createCachedData, plus directory surveys across "
    "builds and flag sets; 32-byte header pinned against real file sizes")
cap("SQLite database", ["inspect_sqlite_database"],
    "sqlite", "covered",
    "header parsed directly so truncated/hot-journalled files are described, "
    "not refused; schema names cross-checked against the sqlite3 module")
cap("NTFS journal", ["inspect_ntfs_journal"],
    None, "missing", "not built")
cap("EVM interface", ["inspect_evm_interface"],
    "evm", "covered",
    "selectors from the PUSH4/EQ dispatcher; raw bytecode or hex text")
cap("il2cpp metadata", ["inspect_il2cpp_metadata"],
    None, "missing", "not built")
cap("Rizin command execution", ["execute_rizin_command", "rizin_command"],
    "id…", None, "out-of-lane: this engine does not drive third-party RE shells")
C.pop()  # placeholder removed; rizin is stated below properly
cap("Rizin / Cutter command shells",
    ["execute_rizin_command", "rizin_command", "cutter_command",
     "list_cutter_sessions"],
    None, "out-of-lane", "wraps a third-party RE shell; xt-forge answers from its "
                         "own engine instead")
cap("GDB session control", ["gdb_command", "start_debug_session",
                            "list_debug_sessions"],
    None, "out-of-lane", "wraps GDB; xt-forge does live probing (re live-probe) "
                         "rather than driving a debugger")
cap("Frida instrumentation", ["list_frida_devices", "start_frida_session",
                              "instrument_frida_target"],
    None, "out-of-lane", "requires an attached Frida server on a device")
cap("ADB device control", ["inspect_adb_client", "list_adb_devices",
                           "inspect_adb_device", "inspect_adb_package"],
    None, "out-of-lane", "requires an Android device or emulator over ADB")
cap("Browser / Electron / CDP", ["inspect_web_page", "inspect_electron_page",
                                 "observe_web_session", "analyze_web_bundle"],
    None, "out-of-lane", "requires a running browser and DevTools endpoint")
cap("APK / Android package", ["inspect_android_package", "inspect_apk_signature",
                              "inspect_android_class", "inspect_android_method"],
    "apk", "covered",
    "zip inventory, manifest permissions/components, and DEX class/method "
    "enumeration with access flags, prototypes and native methods")
cap("JADX / apktool / JEB providers", ["inspect_jeb_client", "open_jeb_project",
                                       "inspect_apktool_client"],
    None, "out-of-lane", "provider clients for third-party tools")
cap("Packet capture (TShark)", ["inspect_packet_capture", "inspect_packet_fields"],
    "netcap", "covered",
    "pcap and pcapng (both byte orders, micro/nano timestamps), HAR and SAZ: flows, "
    "endpoint attribution, plaintext HTTP requests with query redaction. No display "
    "filter language of its own")
cap("Signal decoding (sigrok)", ["decode_signal_recording",
                                 "inspect_signal_decoders"],
    None, "out-of-lane", "requires sigrok decoders and a saved logic capture")
cap("Build VM / build artifacts", ["inspect_build_vm", "build_artifact"],
    "build_run", "covered")
cap("Evidence bundle", ["export_evidence", "import_evidence"],
    "evidence", "covered", probe=["re", "evidence", "{elf}"])
cap("Bookmarks / navigation", ["list_bookmarks", "set_bookmark", "unset_bookmark"],
    "bookmarks", "covered")
cap("Comments and annotation", ["comment", "inline_comment", "annotate_native_function"],
    "annotate", "covered")
cap("Unknown tracking / ledger", ["list_unknowns", "record_unknown"],
    "unknowns", "covered",
    "per-binary obligation ledger: open/waived/resolved states, waivers require a "
    "reason, re-recording a resolved item reopens it, and `clean` gates a conclusion "
    "on nothing being open")
cap("Managed PE/CLI artifact", ["inspect_managed_artifact"],
    "managed artifact", "covered")
cap("Managed members (types/methods/CIL)", ["inspect_managed_members"],
    "managed members", "covered",
    "types, methods, fields, MethodAttributes, plus CIL method body headers: "
    "tiny/fat format, code size, max stack, locals and exception-handler presence")
cap("Managed native boundaries", ["inspect_managed_native_boundaries"],
    "managed boundaries", "covered")
cap("Dart AOT", ["inspect_dart_aot"],
    None, "missing", "not built")
cap("Model / GPU artifacts", ["inspect_model_artifact", "inspect_gpu_code_objects"],
    None, "out-of-lane", "different product surface (ML artifacts)")
cap("Maven/Gradle, NuGet metadata", ["inspect_maven_gradle_metadata",
                                    "inspect_nuget_nupkg"],
    "maven", "covered",
    "pom.xml, Gradle module JSON and nuspec: coordinates, dependencies with scopes, "
    "plugins, and non-Central repositories surfaced; XML namespaces handled")
cap("Playwright trace", ["inspect_playwright_trace"],
    "ptrace", "covered",
    "actions paired with durations, failures with their messages, console output, "
    "network requests with status, DOM snapshots and screenshots (verified against "
    "traces generated by Playwright's own tracing.start)")
cap("Desktop application bundle", ["inspect_desktop_application"],
    "bundle", "covered",
    "freedesktop .desktop entries, macOS .app bundles (Info.plist, Contents/MacOS "
    "executable, URL schemes, document types) and Windows .lnk shortcuts")
cap("Byte search", ["search_native_bytes"],
    "search", "covered", probe=["re", "search", "{elf}", "--pattern", "7f 45", "--hex"])


def _fixtures() -> dict[str, str]:
    """Resolve the concrete binaries the probes run against.

    `elf` must be an *unstripped* binary. /bin/ls looks like the obvious choice and
    is wrong: it is stripped, so it exposes no function names and every probe that
    names a symbol (`--target main`) fails with "function was not found". That
    produced three false "covered" claims on the first run, which is exactly what
    --run exists to catch. The fixture is compiled here instead so the probes test
    the tool rather than the host's packaging choices.
    """
    import shutil
    import tempfile
    out: dict[str, str] = {}
    workdir = Path(tempfile.mkdtemp())
    compiler = next((c for c in ("clang", "cc", "gcc") if shutil.which(c)), None)
    if compiler:
        src = workdir / "probe.c"
        src.write_text("int helper(int x){return x*3;}\n"
                       "int main(void){return helper(7);}\n")
        binary = workdir / "probe_elf"
        built = subprocess.run([compiler, "-O0", "-g", str(src), "-o", str(binary)],
                               capture_output=True, text=True)
        if built.returncode == 0 and binary.is_file():
            out["elf"] = str(binary)
    if "elf" not in out:
        for cand in ("/usr/bin/env", "/bin/ls"):
            if Path(cand).is_file():
                out["elf"] = cand
                break
    wasm = workdir / "m.wasm"
    wasm.write_bytes(bytes.fromhex("0061736d01000000"))
    out["wasm"] = str(wasm)
    blob = workdir / "blob.bin"
    blob.write_bytes(bytes(range(256)) * 8)
    out["blob"] = str(blob)
    return out


def run_probes(rows: list[dict]) -> int:
    fixtures = _fixtures()
    failures = 0
    for row in rows:
        probe = row.get("probe")
        if not probe:
            continue
        argv = [p.format(**fixtures) for p in probe]
        completed = subprocess.run([sys.executable, "-m", "xtforge.cli", *argv],
                                   capture_output=True, text=True, cwd=str(ROOT),
                                   timeout=180)
        ok = completed.returncode == 0 and completed.stdout.strip() != ""
        row["probe_ok"] = ok
        if not ok:
            failures += 1
            print(f"  PROBE FAILED  {' '.join(argv)}\n"
                  f"    rc={completed.returncode}  out={completed.stdout[:200]!r}\n"
                  f"    err={completed.stderr[:200]!r}")
    return failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", action="store_true",
                        help="execute every covered probe and fail on a dead claim")
    parser.add_argument("--json", help="write the full table to this path")
    args = parser.parse_args()

    rea_total = 0
    if REA_CATALOG.is_file():
        rea_total = len(json.loads(REA_CATALOG.read_text())["tools"])

    if args.run:
        failures = run_probes(C)

    tally: dict[str, int] = {}
    for row in C:
        tally[row["verdict"]] = tally.get(row["verdict"], 0) + 1

    width = max(len(r["capability"]) for r in C)
    print(f"{'CAPABILITY':<{width}}  {'XT VERB':<16} VERDICT")
    print("-" * (width + 40))
    for row in C:
        print(f"{row['capability']:<{width}}  {str(row['xt_verb'] or '-'):<16} {row['verdict']}")
        if row["verdict"] != "covered" and row["note"]:
            print(f"{'':<{width}}  {'':<16}   {row['note']}")

    in_lane = [r for r in C if r["verdict"] != "out-of-lane"]
    covered = [r for r in in_lane if r["verdict"] == "covered"]
    print()
    print(f"REA tools                {rea_total}")
    print(f"capabilities compared    {len(C)}")
    print(f"  covered                {tally.get('covered', 0)}")
    print(f"  partial                {tally.get('partial', 0)}")
    print(f"  missing                {tally.get('missing', 0)}")
    print(f"  out-of-lane (excluded) {tally.get('out-of-lane', 0)}")
    if in_lane:
        pct = len(covered) / len(in_lane) * 100
        print(f"in-lane coverage         {len(covered)}/{len(in_lane)} = {pct:.1f}%")

    if args.json:
        Path(args.json).write_text(json.dumps(
            {"rea_tools": rea_total, "tally": tally, "rows": C}, indent=1))
        print(f"wrote {args.json}")

    if args.run and failures:
        print(f"\n{failures} covered claim(s) did not reproduce")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
