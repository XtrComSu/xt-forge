"""Searchable analysis guidance, with every workflow bound to verbs that actually exist.

`re overview` and `re triage` answer "what next" for one file. What was missing is the
knowledge base behind the answer: the ordered procedure for a task, why each step is in that
order, and what a given result means. Without it an analyst has 128 verbs and no sequence.

Two things make this guidance rather than documentation:

  * **Every step names a real verb, and the module refuses to load a workflow that does not.**
    Guidance that says "use the decompiler" and leaves the analyst to find the flag is
    folklore. Guidance whose step references a verb that was renamed or never existed is
    worse — it is folklore with a citation. `_validate()` runs at import and raises.
  * **Every step says what its result would tell you.** A step with no interpretation is a
    command, not guidance.

The workflows here are the ones the rest of the tool is actually built around, written from
the order the analyses depend on each other: you cannot grade an API surface before you know
which exports are even dynamic, and you cannot correlate a capture before you have endpoints.
"""
from __future__ import annotations

from typing import Any

# Verbs that exist in `re`. Kept as data so `_validate` can check every workflow step against
# it at import time; the parity test asserts this set matches the CLI's argparse choices, so a
# renamed verb breaks the build rather than silently producing guidance that cannot run.
#
# This is a snapshot, not the source of truth — the test is what keeps it honest.
KNOWN_VERBS = frozenset({
    "info", "overview", "functions", "xrefs-native", "dispatch-native", "disasm-native",
    "decompile-native", "needed", "sections", "symbols", "strings", "entropy", "pack",
    "ioc", "disasm", "graph", "pe", "cfg", "block", "view", "xrefs", "checksec", "hooks",
    "patch", "rtti", "diff", "capa", "crash", "annotate", "asar", "netcap", "apk",
    "decompile", "trace", "deep-elf", "anchors", "slice", "live-probe", "rbxm", "ida",
    "borer", "triage", "init-project", "llvm", "archives", "kernelcache", "pdb",
    "pdb-types", "demangle", "callgraph", "evidence", "search", "elfmeta", "wasm",
    "firmware", "managed", "formats", "devicetree", "kconfig", "lnk", "sqlite", "beam",
    "evm", "ips", "uefi", "nvram", "dex", "goto", "nav", "resume", "bookmark", "step",
    "capture-diff", "capture-compare", "correlate", "coverage", "recon-coverage",
    "evaluate-coverage", "api", "api-contract", "abi", "bundle-diff", "compare-bundles",
    "bundle-compare", "fn-match", "fnmatch", "match-functions", "firmware-carve", "carve",
    "extract-firmware", "evidence-export", "evidence-import", "app", "appgraph",
    "application-graph", "il2cpp", "il2cpp-metadata", "global-metadata", "dart", "dart-aot",
    "snapshot", "swift", "swift-types", "ntfs", "ntfs-journal", "fuses", "electron-fuses", "nib", "interface-builder", "fv", "uefi-firmware",
    "assetcatalog", "car", "unknowns", "obligations", "v8cache", "codecache", "ptrace",
    "playwright", "objc", "objc-classes", "objc-protocols", "keyed", "keyed-archive", "jvm",
    "maven", "nuget", "appbundle", "bundle", "bookmarks", "bulk",
    # The guidance verbs themselves, so a workflow may reference them.
    "guidance", "workflows", "guide", "cdp", "dex-search", "dex-refs", "hap", "model", "gdb",
    "deps", "vulns", "cve-scan", "remediate", "cve-info",
})

# A step is (verb, purpose, what-the-result-tells-you). Every field is required: a purpose with
# no interpretation is a command, not guidance.
_WORKFLOWS: list[dict[str, Any]] = [
    {
        "id": "triage-unknown-binary",
        "title": "Triage an unknown binary",
        "when": "You have a file of unknown purpose and need to decide whether it matters.",
        "steps": [
            ("info", "Identify the container: format, architecture, bitness, packing.",
             "A high entropy section or few imports suggests packing; stop and unpack first, "
             "because every later step on a packed sample describes the unpacker."),
            ("checksec", "Record the mitigation posture.",
             "Full RELRO and PIE mean address work must be offset-relative; absent NX means "
             "shellcode on the stack is a plausible finding."),
            ("strings", "Survey human-readable content, URLs and paths.",
             "Endpoints and file paths here seed the later `correlate` step, so collect them "
             "now even if they look uninteresting."),
            ("symbols", "List what survives.",
             "If this is empty the file is stripped; go to `fn-match` rather than expecting "
             "named functions in `functions`."),
            ("capa", "Match known capability rules.",
             "This names behaviours without reading assembly, so it decides where the rest of "
             "the session should spend its time."),
            ("functions", "Enumerate the function surface.",
             "A very large count on a small file is recursion or obfuscation; on a large file "
             "it tells you whether full decompilation is even feasible."),
            ("triage", "Get the ranked next steps for this specific file.",
             "This is the synthesis step: it reconciles everything above into an order."),
        ],
    },
    {
        "id": "attack-runtime-behaviour",
        "title": "Establish what a binary actually does at runtime",
        "when": "A binary references interesting endpoints or hosts and you need to know "
                "which of them fire.",
        "steps": [
            ("strings", "Collect the endpoints and hosts the binary references.",
             "This is the static side of the comparison and the only source of dormant "
             "capabilities, which no capture can show you."),
            ("live-probe", "Attach and observe the process while it runs.",
             "Confirms the binary reaches the network at all, and gives you the process tree "
             "and child processes that a capture alone will not attribute."),
            ("netcap", "Inspect the capture you recorded.",
             "Establishes the runtime endpoint set, including hosts resolved at runtime that "
             "left no string."),
            ("correlate", "Compare referenced endpoints against observed ones.",
             "`static_only` entries are dormant or dead references; `runtime_only` entries "
             "were constructed at runtime, which is the signature of obfuscation or encrypted "
             "config. Both are findings."),
            ("capture-diff", "If you have two captures, diff them at endpoint level.",
             "A new endpoint between two runs is the highest-signal release finding, and HTTP "
             "path changes are caught even when host and port never moved."),
        ],
    },
    {
        "id": "reconstruct-stripped-native",
        "title": "Recover meaning from a stripped native binary",
        "when": "The binary has no symbols and you need named functions and a coverage number.",
        "steps": [
            ("deep-elf", "Recover the structural ground truth: sections, segments, dynsym.",
             "Establishes which addresses are real code, so later recovery is checked against "
             "something rather than trusted."),
            ("functions", "Recover the function set by analysis rather than by symbol table.",
             "This is the denominator for every coverage claim you will make."),
            ("decompile", "Decompile the functions that matter.",
             "Read the highest-fan-in functions first; the decompiler's output quality drops "
             "on the obfuscated tail, and spending time there first is wasted."),
            ("fn-match", "Match recovered functions against a reference build.",
             "Structural matching survives a strip and a compiler change, so this is how you "
             "transfer names from a build you do have to one you do not."),
            ("annotate", "Record each conclusion against its address.",
             "Annotations are keyed by content hash, so this survives across sessions and is "
             "what makes the next step meaningful."),
            ("goto", "Mark your position as you work.",
             "`re goto` and `re bookmark` let you stop and resume; without them a long "
             "reconstruction restarts from the entry point every session."),
            ("coverage", "Score the reconstruction against the original source.",
             "`present_pct` minus `coverage_pct` is the work that is finished but undocumented, "
             "which is the number a reviewer needs and no ledger can produce."),
            ("unknowns", "Record what you still cannot explain.",
             "An open question with provenance is a result; an unexplained function is a gap "
             "that will be rediscovered."),
        ],
    },
    {
        "id": "grade-an-api-surface",
        "title": "Grade and gate an exported API surface",
        "when": "A library changed and you need to know whether the contract broke.",
        "steps": [
            ("api", "Enumerate the dynamic export surface and grade it.",
             "Exporting an internal symbol is an ABI commitment nobody intended to make; "
             "underscore-prefixed exports and forbidden names are the usual tells."),
            ("symbols", "Cross-check what is defined versus what is exported.",
             "A symbol present in `.symtab` but absent from `.dynsym` was never externally "
             "callable, so it cannot be part of the public contract."),
            ("diff", "Diff two builds to see what actually changed.",
             "Distinguishes a rebuild from a real change; a version-bump-only diff means the "
             "surface shift is cosmetic."),
            ("api", "Re-run against the previous build as a baseline.",
             "Regressions are only regressions relative to a recorded baseline; without one "
             "you are grading in a vacuum."),
            ("unknowns", "Record any deliberate break you cannot explain.",
             "An intentional break is fine, but only if it is written down with a reason."),
        ],
    },
    {
        "id": "compare-two-app-builds",
        "title": "Compare two app builds layer by layer",
        "when": "You have two bundles — an old and a new release — and need the difference.",
        "steps": [
            ("bundle-diff", "Compare the bundles as trees: entries added, removed, changed.",
             "Metadata files changing while code does not is a rebuild; code changing while "
             "metadata does not is a hotfix."),
            ("app", "Build the application graph for each side.",
             "Ties manifests, native libraries and assets together, so a changed `.so` is "
             "attributed to a component instead of floating."),
            ("asar", "If Electron, inspect the packed archive.",
             "JavaScript in an asar is usually where the behavioural change actually lives, "
             "even when the native side is untouched."),
            ("dex", "If Android, compare the Dalvik side.",
             "Native-only comparison misses Java-layer changes that drive the native calls."),
            ("fn-match", "Match native functions structurally across the two builds.",
             "Gives you the subset of changes worth reading rather than a list of every "
             "function whose address moved."),
        ],
    },
    {
        "id": "carve-firmware",
        "title": "Carve and classify firmware",
        "when": "You have a vendor image and need the components inside it.",
        "steps": [
            ("formats", "Identify the container before carving.",
             "An image may be a raw flash dump, a vendor header wrapped around a filesystem, "
             "or a UEFI volume; carving the wrong layer yields fragments."),
            ("firmware-carve", "Carve the embedded filesystems and archives.",
             "Reports what it found and what it skipped, so a partial carve is visible as "
             "partial rather than looking complete."),
            ("entropy", "Locate compressed or encrypted regions.",
             "A high-entropy region that yielded no filesystem is compression you have not "
             "unpacked yet, not absence of content."),
            ("uefi", "If a firmware volume, enumerate the volumes and files.",
             "UEFI modules carry their own metadata, so this recovers structure a raw carve "
             "cannot see."),
            ("nvram", "Extract the NVRAM variables.",
             "Configuration and credentials frequently survive here after the filesystem has "
             "been wiped."),
            ("checksec", "Run the posture check across extracted binaries.",
             "Firmware commonly ships without NX or with fixed load addresses, which changes "
             "what is exploitable."),
        ],
    },
]


def _validate(workflows: list[dict[str, Any]]) -> None:
    """Refuse to load a workflow that names a verb the CLI does not have.

    Guidance citing a verb that does not exist is worse than no guidance: it reads
    authoritative and sends the analyst looking for a flag that was renamed three releases
    ago. Catching it at import makes the failure loud and immediate.
    """
    for workflow in workflows:
        if not workflow.get("steps"):
            raise ValueError(f"workflow {workflow.get('id')!r} has no steps")
        if len(workflow["steps"]) < 3:
            raise ValueError(
                f"workflow {workflow.get('id')!r} has {len(workflow['steps'])} steps; "
                "a sequence that short is a command, not a workflow")
        for verb, purpose, meaning in workflow["steps"]:
            if verb not in KNOWN_VERBS:
                raise ValueError(
                    f"workflow {workflow.get('id')!r} references unknown verb {verb!r}")
            if not purpose or not meaning:
                raise ValueError(
                    f"workflow {workflow.get('id')!r} step {verb!r} is missing its purpose "
                    "or its interpretation")


_validate(_WORKFLOWS)


def list_workflows() -> dict[str, Any]:
    """Every workflow, with just enough to choose between them."""
    return {
        "ok": True,
        "count": len(_WORKFLOWS),
        "workflows": [{"id": workflow["id"], "title": workflow["title"],
                       "when": workflow["when"], "steps": len(workflow["steps"])}
                      for workflow in _WORKFLOWS],
    }


def show_workflow(workflow_id: str) -> dict[str, Any]:
    """One workflow in full, with runnable commands."""
    for workflow in _WORKFLOWS:
        if workflow["id"] == workflow_id:
            return {
                "ok": True,
                "id": workflow["id"],
                "title": workflow["title"],
                "when": workflow["when"],
                "steps": [
                    {"n": index + 1, "verb": verb,
                     "command": f"xtforge re {verb} <target>",
                     "purpose": purpose, "tells_you": meaning}
                    for index, (verb, purpose, meaning) in enumerate(workflow["steps"])
                ],
            }
    return {"ok": False, "error": f"no workflow with id {workflow_id!r}",
            "available": [workflow["id"] for workflow in _WORKFLOWS]}


def search_guidance(query: str) -> dict[str, Any]:
    """Find workflows and steps matching a free-text query.

    Searches steps as well as titles, because an analyst looking for "entropy" wants the
    firmware workflow's entropy step, not a workflow with "entropy" in its name.
    """
    needle = (query or "").strip().lower()
    if not needle:
        return {"ok": False, "error": "search query must not be empty"}
    hits: list[dict[str, Any]] = []
    for workflow in _WORKFLOWS:
        title_match = needle in workflow["title"].lower() or needle in workflow["when"].lower()
        step_hits = [
            {"n": index + 1, "verb": verb, "purpose": purpose}
            for index, (verb, purpose, meaning) in enumerate(workflow["steps"])
            if needle in verb.lower() or needle in purpose.lower() or needle in meaning.lower()
        ]
        if title_match or step_hits:
            hits.append({"id": workflow["id"], "title": workflow["title"],
                         "matched_title": title_match, "steps": step_hits})
    return {"ok": True, "query": query, "count": len(hits), "hits": hits,
            "note": ("Steps are matched on their purpose and on what the result tells you, "
                     "so searching for a conclusion finds the step that produces it.")}


def guidance_for_verb(verb: str) -> dict[str, Any]:
    """Which workflows use a verb, and at what position.

    Answers "I have this output, now what" — the reverse lookup that makes the guidance
    reachable from where an analyst already is.
    """
    clean = (verb or "").strip().lower()
    if not clean:
        return {"ok": False, "error": "verb must not be empty"}
    uses = []
    for workflow in _WORKFLOWS:
        for index, (step_verb, purpose, _meaning) in enumerate(workflow["steps"]):
            if step_verb == clean:
                uses.append({"workflow": workflow["id"], "title": workflow["title"],
                             "position": f"{index + 1}/{len(workflow['steps'])}",
                             "after": (workflow["steps"][index - 1][0]
                                       if index else None),
                             "then": (workflow["steps"][index + 1][0]
                                      if index + 1 < len(workflow["steps"]) else None),
                             "purpose": purpose})
    if not uses:
        return {"ok": True, "verb": clean, "count": 0, "uses": [],
                "note": f"{clean} is not part of any guided workflow; it is a direct "
                        f"inspection verb rather than a step in a sequence"}
    return {"ok": True, "verb": clean, "count": len(uses), "uses": uses}


def inspect(path: str | None = None, **kwargs: Any) -> dict[str, Any]:
    return list_workflows()
