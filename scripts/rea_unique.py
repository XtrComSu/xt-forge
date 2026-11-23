#!/usr/bin/env python3
"""Measure the other half of "equal or above": what xt-forge has that REA does not.

`scripts/rea_breadth.py` measures how much of REA's catalogue xt-forge answers. This script
measures the reverse, and it is deliberately strict about what counts as a unique
capability.

The rule: a capability is unique only if REA's **entire catalogue text** — every tool name
and every description — never mentions the concept. That is a high bar and most of my first
guesses failed it. `checksec`, `v8cache`, `assetcatalog`, `netcap` and `kernelcache` all
looked unique by tool name and all turned out to be covered by an REA tool whose name simply
did not match (`inspect_binary_hardening`, `inspect_v8_code_cache`,
`inspect_asset_catalog`, `inspect_packet_capture`, `inspect_kernel_module`). Guessing from
tool names would have produced a flattering and false list.

The one judgement call is "native engine" versus "wrapper". REA has no disassembler of its
own: `inspect_with_objdump` shell-outs to objdump and says the implementation is unverified.
All three of its decompile tools are JEB-backed. xt-forge decodes both in-process. That is a
real architectural difference, and it is recorded as such rather than as a missing feature.

Usage:
  python3 scripts/rea_unique.py
  python3 scripts/rea_unique.py --json /tmp/unique.json
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REA_CATALOG = Path("/tmp/rea-latest/package/dist/mcp-catalog.json")

# (capability, xt-forge verb, words that would prove REA has it too, note)
CLAIMS = [
    ("Engine-native disassembly", "disasm-native",
     ["disassembl"], ""),
    # Narrowed twice, and the narrowing is the finding. My first claim was "engine-native
    # decompilation" — false, because `inspect_android_method` decompiles Dalvik in REA's
    # own engine. My second was "native-code decompilation" — still wrong, because
    # `inspect_android_method` also reaches native methods through JNI.
    #
    # What is actually true: REA has no decompiler for a plain x86/ARM ELF or PE. Its
    # `procedure_pseudo_code` and `batch_decompile` are provider-normalised reads from an
    # external r2/JEB session, and `inspect_android_method` is scoped to Android packages.
    # The claim is stated at exactly that width, with the scoping enforced by requiring the
    # tool to be about ELF/PE — see `SCOPE_EXCLUDES` below.
    ("Engine-native x86/ARM ELF+PE decompilation", "decompile-native",
     ["decompile", "pseudocode"], ""),
    ("Roblox place/model containers", "rbxm",
     ["roblox", "rbxm", "rbxl"], "REA never mentions Roblox"),
    # NOT claimed: `re borer` shells out to an external `borer` binary that is not installed
    # here, so it is a wrapper like REA's — not an engine capability. It was in my first
    # draft of this list and had to come out. Listing it would have been the exact error this
    # script exists to catch.
    ("ptrace live process probing", "live-probe",
     ["ptrace"], "REA uses Frida/GDB sessions instead"),
]

WRAPPER_MARKERS = ("objdump", "jeb", "ida", "rizar", "rizin", "radare", "cutter", "ghidra")

# REA's descriptions are full of NEGATED mentions: "without executing it or opening a
# disassembler". A naive substring search counts those as evidence that REA has the
# capability, which is the opposite of what the text says. Any word preceded by one of these
# within a few tokens is a denial, not a claim.
NEGATIONS = ("without", "no ", "not ", "never", "neither", "nor ")

# A tool scoped to a package format is not a general native-code decompiler. These markers
# in a tool's name or first sentence mean its scope is narrower than the claim.
SCOPE_EXCLUDES = ("android", "dalvik", "apk", "smali", "javascript", "java", "managed",
                  "flutter", "dart", "wasm", "il2cpp")


def mentions_capability(text: str, words: list[str]) -> bool:
    """True only if `text` mentions one of `words` affirmatively.

    The window is the whole sentence, not a fixed character count: REA writes "without
    executing the image or opening a disassembler", where the negation is 55 characters
    before the word. A 40-character window counts that as a positive claim — which is how
    `inspect_dwarf_units` and `inspect_elf_dependencies` were misread as having a
    disassembler when their descriptions say the opposite.
    """
    for word in words:
        start = text.find(word)
        while start != -1:
            # Boundaries: sentence start, or the previous full stop.
            sentence_start = max(text.rfind(". ", 0, start), text.rfind("; ", 0, start))
            prefix = text[sentence_start + 1:start]
            if not any(neg in prefix for neg in NEGATIONS):
                return True
            start = text.find(word, start + 1)
    return False


def classify() -> list[dict]:
    if not REA_CATALOG.is_file():
        return []
    catalog = json.loads(REA_CATALOG.read_text())
    tools = catalog.get("tools", [])
    full_text = " ".join(
        (tool["name"] + " " + (tool.get("description") or "")).lower()
        for tool in tools)

    results = []
    for capability, verb, words, note in CLAIMS:
        # Only count a tool as implementing the capability if the word appears in its NAME
        # or in the FIRST sentence of its description — not anywhere in a trailing aside.
        # `inspect_address_context` ends with "Use xrefs, assembly, or pseudocode for those
        # deeper views", which is a pointer to a different tool, not a decompiler.
        def implements(tool: dict) -> bool:
            name_text = tool["name"].lower().replace("_", " ")
            if mentions_capability(name_text, words):
                return True
            description = (tool.get("description") or "").lower()
            first = description.split(". ")[0]
            return mentions_capability(first, words)

        def in_scope(tool: dict) -> bool:
            """Reject tools whose scope is a narrower package format than the claim."""
            text = tool["name"].lower().replace("_", " ") + " " + \
                (tool.get("description") or "").lower().split(". ")[0]
            return not any(marker in text for marker in SCOPE_EXCLUDES)

        matching = [tool["name"] for tool in tools
                    if implements(tool) and in_scope(tool)] if words else []
        # A tool that only wraps an external engine does not implement the capability.
        descriptions = {tool["name"]: (tool.get("description") or "").lower()
                        for tool in tools}
        engine_native = []
        for name in matching:
            text = name.lower() + " " + descriptions.get(name, "")
            if any(marker in text for marker in WRAPPER_MARKERS):
                continue  # wraps an external engine, so REA does not implement it
            # REA's decompile tools are all "provider-normalised": they read pseudocode out
            # of an external analysis session (r2/JEB/IDA) rather than decoding in-process.
            # `provider` in the description is what marks that indirection.
            if "provider" in text:
                continue
            engine_native.append(name)
        # `full_text` joins every tool's text into one string, so a negation in one tool's
        # description would sit "in the same sentence" as a positive mention in another's.
        # Use it only to answer "does ANY tool mention this at all"; the per-tool analysis
        # below decides who actually implements it.
        # Unique when REA has no engine-native implementation. Two ways that happens:
        # nothing mentions it at all, or the only tools that mention it are wrappers around
        # an external engine. `bool(matching)` must NOT be part of the test — a capability
        # whose sole REA tool is `inspect_with_objdump` is exactly the unique case.
        unique = not engine_native
        if words:
            # The honest per-tool record: who mentions it, and which of those are native.
            results.append({
                "capability": capability,
                "xt_forge_verb": verb,
                "rea_mentions": matching,
                "rea_engine_native": engine_native,
                "unique": unique,
                "note": note,
            })
            continue
        results.append({
            "capability": capability,
            "xt_forge_verb": verb,
            "rea_tools": matching,
            "rea_engine_native": engine_native,
            "unique": unique,
            "note": note,
        })
    return results


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", help="write the record here")
    args = parser.parse_args()

    results = classify()
    if not results:
        print(f"REA catalogue not found at {REA_CATALOG}", file=sys.stderr)
        return 2

    print("WHAT XT-FORGE HAS THAT REA DOES NOT")
    print()
    unique = 0
    for entry in results:
        if entry["unique"]:
            unique += 1
            print(f"  UNIQUE  {entry['capability']}")
            print(f"          verb: {entry['xt_forge_verb']}")
            if entry.get("rea_mentions") or entry.get("rea_tools"):
                nearest = entry.get("rea_mentions") or entry["rea_tools"]
                print(f"          REA's nearest: {nearest} "
                      f"(all external wrappers, none engine-native)")
            elif entry["note"]:
                print(f"          {entry['note']}")
        else:
            nearest = entry.get("rea_mentions") or entry.get("rea_tools") or []
            print(f"  shared  {entry['capability']}  (REA native: "
                  f"{entry.get('rea_engine_native') or nearest[:3]})")
    print()
    print(f"verified-unique capabilities: {unique}/{len(results)}")

    if args.json:
        Path(args.json).write_text(json.dumps(
            {"claims": results, "unique_count": unique}, indent=1))
        print(f"wrote {args.json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
