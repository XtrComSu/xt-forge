"""`xtforge re` and `xtforge scan`: binary inspection and static safety scan.

`scan` is read-only and masks matched values by default.
"""
from __future__ import annotations

import json
import shutil
from pathlib import Path

from .common import _out


_UNKNOWN_NOTE = "unrecognised format; no disassembly or symbol recovery attempted"


def _human_evidence(record: dict) -> str:
    """Short human form of an evidence record: identity, not the full report."""
    return "\n".join((
        f"evidence (schema {record.get('schema', '?')})",
        f"{'path':<9} {record.get('path', '')}",
        f"{'size':<9} {record.get('size', 0)} bytes",
        f"{'sha256':<9} {str(record.get('sha256', ''))[:16]}",
        f"{'backend':<9} {record.get('backend', '')}",
    ))


def _human_overview(payload: dict) -> str:
    """Render an unclaimed file's bounded description instead of the whole report.

    Every other format keeps the full overview dump. For "unknown", only the
    description is meaningful: the image's arch and bits are empty placeholders
    (no loader claimed the file), so neither is included here.
    """
    if payload.get("format") != "unknown":
        return json.dumps(payload, indent=2)

    images = payload.get("images") or []
    unknown = {}
    if images and isinstance(images[0], dict):
        candidate = images[0].get("unknown")
        if isinstance(candidate, dict):
            unknown = candidate
    runs = unknown.get("strings") or []
    if not isinstance(runs, list):
        runs = []
    fields = (
        ("format", "unknown"),
        ("size", f"{unknown.get('size', 0)} bytes"),
        ("sha256", str(unknown.get("sha256", ""))),
        ("entropy", f"{float(unknown.get('entropy', 0.0)):.2f} "
                    f"({unknown.get('entropy_class', '')})"),
        ("magic", str(unknown.get("magic", ""))),
        ("strings", ", ".join(str(run) for run in runs[:5])),
        ("note", _UNKNOWN_NOTE),
    )
    return "\n".join(f"{name:<16} {value}" for name, value in fields)


def _human_pdb_types(payload: dict) -> str:
    """Summarise a PDB type census and show at most twenty procedure signatures."""
    census = payload.get("census") or {}
    kinds = census.get("kinds") or {}
    summary = ", ".join(f"{name}:{count}" for name, count in kinds.items())
    lines = [f"{census.get('record_count', 0)} type records ({summary})"]
    signatures = payload.get("signatures") or []
    lines.extend(str(sig.get("rendered", "")) for sig in signatures[:20])
    hidden = len(signatures) - 20
    if hidden > 0:
        lines.append(f"... ({hidden} more signatures not shown)")
    aggregates = payload.get("aggregates") or []
    if aggregates:
        lines.append("")
        lines.append(f"{len(aggregates)} aggregate layouts")
        lines.extend(str(item.get("rendered", "")) for item in aggregates[:10])
        if len(aggregates) > 10:
            lines.append(f"... ({len(aggregates) - 10} more aggregates not shown)")
    return "\n".join(lines)


def _human_functions(payload: dict) -> str:
    """Render the function index as address/name columns, with PDB signatures.

    The signature is a trailing column, so long names simply push it further
    right instead of being truncated. Functions without a signature keep the
    plain two-column form.
    """
    if not payload.get("ok", True):
        return f"error: {payload.get('error') or 'cannot list functions'}"

    lines = []
    for image in payload.get("images") or []:
        if not isinstance(image, dict):
            continue
        for fn in image.get("functions") or []:
            if not isinstance(fn, dict):
                continue
            address = fn.get("address")
            if isinstance(address, int):
                address_text = hex(address)
            elif address is None:
                address_text = ""
            else:
                address_text = str(address)
            name = str(fn.get("name") or fn.get("symbol_name") or "")
            # An unnamed function still needs to read as a row, not as a bare
            # address: a stripped binary would otherwise print a column of hex.
            label = name if name else "(unnamed)"
            line = f"{address_text:<12}  {label:<26}"
            size = fn.get("size")
            if isinstance(size, int) and size > 0:
                line += f" {size:>5}B"
            source = fn.get("name_source") or fn.get("source")
            if source:
                line += f"  {source}"
            signature = fn.get("signature")
            if signature:
                line += f"  {signature}"
            lines.append(line.rstrip())
    return "\n".join(lines) or "(no functions)"


def _human_findings(payload: dict) -> str:
    lines = []
    for item in payload.get("findings", []):
        lines.append(f"{item['severity']:<8} {item['rule']:<20} "
                     f"{item['path']}:{item['line']}  {item['value']}")
    summary = ", ".join(f"{k} {v}" for k, v in
                        (payload.get("summary") or {}).items())
    tail = [f"files scanned: {payload.get('files_scanned', '?')}  findings: "
            f"{payload.get('count', 0)}"]
    if summary:
        tail.append(f"by severity: {summary}")
    if payload.get("masked", True):
        tail.append("values masked (use --reveal to print them)")
    return "\n".join(lines + tail) if lines else "\n".join(tail + ["(no findings)"])


def _flatten_graph(value, depth: int, limit: int = 40) -> list[str]:
    """Render a resolved keyed-archive graph compactly, depth-first.

    The graph is already resolved by the reader; this only decides how to print it.
    Cycles and invalid UIDs are values in the graph, not exceptions, because a real
    NSKeyedArchiver archive legitimately contains both.
    """
    lines: list[str] = []
    indent = "  " * depth
    if isinstance(value, dict):
        if "_cycle" in value:
            return [f"{indent}(cycle to uid {value['_cycle']})"]
        if "_invalid_uid" in value:
            return [f"{indent}(invalid uid {value['_invalid_uid']})"]
        if "_truncated" in value:
            return [f"{indent}({value['_truncated']})"]
        class_name = value.get("_class")
        if "dict" in value and isinstance(value["dict"], dict):
            lines.append(f"{indent}dict" + (f" <{class_name}>" if class_name else ""))
            for key, item in list(value["dict"].items())[:limit]:
                joined = _flatten_graph(item, depth + 1, limit)
                if joined:
                    lines.append(f"{indent}  {key}: {joined[0].lstrip()}")
                    lines.extend(joined[1:])
            return lines
        if "array" in value and isinstance(value["array"], list):
            lines.append(f"{indent}array[{len(value['array'])}]"
                         + (f" <{class_name}>" if class_name else ""))
            for item in value["array"][:limit]:
                lines.extend(_flatten_graph(item, depth + 1, limit))
            return lines
        for key, item in list(value.items())[:limit]:
            if key == "_class":
                continue
            joined = _flatten_graph(item, depth + 1, limit)
            if joined:
                lines.append(f"{indent}{key}: {joined[0].lstrip()}")
                lines.extend(joined[1:])
        return lines
    if isinstance(value, list):
        lines.append(f"{indent}array[{len(value)}]")
        for item in value[:limit]:
            lines.extend(_flatten_graph(item, depth + 1, limit))
        return lines
    return [f"{indent}{value!r}"]


# borer's own subcommands. Used to decide whether the first positional argument is a
# subcommand or a target path, so `re borer ./a.out` and `re borer info ./a.out` both work.
BORER_SUBCOMMANDS = frozenset({
    "info", "functions", "function", "summary", "symbols", "hexdump", "strings",
    "xrefs", "callgraph", "sections", "imports", "exports", "search", "disasm",
})


def _render_guidance(res):
    if not res.get("ok"):
        callable_hint = ""
        if res.get("available"):
            callable_hint = chr(10) + "  try: " + ", ".join(res["available"][:6])
        human = "guidance: " + str(res.get("error", "unknown")) + callable_hint
    elif "hits" in res:
        lines = [f"Guidance search {res.get('query')!r}: {res.get('count')} match(es)"]
        for hit in res["hits"][:6]:
            lines.append(f"  {hit['id']}")
            for step in hit["steps"][:3]:
                lines.append(f"    {step['n']}. {step['verb']:<16} {step['purpose'][:56]}")
        human = chr(10).join(lines)
    elif "uses" in res:
        lines = [f"Step {res.get('verb')} appears in {res.get('count')} workflow(s)"]
        for use in res["uses"][:6]:
            before = use.get("after") or "(start)"
            after = use.get("then") or "(end)"
            lines.append(f"  {use['workflow']:<28} {use['position']}"
                         f"  {before} -> {after}")
        if res.get("note"):
            lines.append("  " + res["note"])
        human = chr(10).join(lines)
    elif "steps" in res and isinstance(res["steps"], list) and res["steps"]                 and isinstance(res["steps"][0], dict):
        lines = [f"{res['title']}  ({res['id']})", f"  when: {res['when']}"]
        for step in res["steps"]:
            lines.append(f"  {step['n']}. {step['verb']:<16} {step['purpose']}")
            lines.append(f"     -> {step['tells_you'][:100]}")
        human = chr(10).join(lines)
    else:
        lines = [f"Guided workflows ({res.get('count')})"]
        for workflow in res.get("workflows") or []:
            lines.append(f"  {workflow['id']:<30} {workflow['steps']} steps  "
                         f"{workflow['title']}")
        human = chr(10).join(lines)
    return human


def _render_hap(res):
    if not res.get("ok"):
        lines = ["hap: " + str(res.get("error", "unknown"))]
        if res.get("hint"):
            lines.append("  hint: " + str(res["hint"]))
        return chr(10).join(lines)
    version = res.get("version") or {}
    # A .hap built without pack.info carries no bundle name; printing the literal string "None"
    # would read as a parsed field whose value is the text None.
    identity = res.get("bundle_name") or f"(module {(res.get('module_name') or 'unnamed')})"
    stamp = " ".join(part for part in (version.get("name"), f"({version.get('code')})"
                                       if version.get("code") is not None else "") if part)
    lines = [f"{identity}  {stamp}".rstrip(),
             f"  module      {res.get('module_name')}  type {res.get('module_type')}",
             f"  targets     {', '.join(res.get('device_types') or []) or 'unspecified'}",
             f"  entries     {res.get('entry_count')}  "
             f"bytecode {len(res.get('bytecode_files') or [])}  "
             f"native {len(res.get('native_files') or [])}"]
    if res.get("unrecognised_device_types"):
        lines.append(f"  UNKNOWN     device types {res['unrecognised_device_types']}")
    if res.get("permission_count"):
        lines.append(f"  permissions {res['permission_count']}")
        for item in (res["permissions"] or [])[:12]:
            lines.append(f"    {item.get('name')}")
    if res.get("ability_count"):
        lines.append(f"  abilities   {res['ability_count']}")
        for item in (res["abilities"] or [])[:10]:
            exported = " exported" if item.get("exported") else ""
            lines.append(f"    {item.get('kind'):<9} {item.get('name')}{exported}")
    for item in (res.get("native_files") or [])[:6]:
        lines.append(f"    native {item['path']} ({item['size']} bytes)")
    if res.get("note"):
        lines.append("  " + str(res["note"]))
    return chr(10).join(lines)


def _render_model(res):
    if not res.get("ok"):
        return "model: " + str(res.get("error", "unknown"))
    if "candidates" in res:
        lines = [f"{res.get('path')}  ({res.get('size_bytes')} bytes)"]
        for item in res["candidates"]:
            lines.append(f"  {item['kind']:<10} at offset {item['offset']}")
        lines.append("  " + str(res.get("note")))
        return chr(10).join(lines)
    lines = [f"{res.get('format')} v{res.get('version')}  {res.get('path')}"
             if res.get("version") else f"{res.get('format')}  {res.get('path')}",
             f"  size        {res.get('size_bytes')} bytes"
             + (f"  header {res.get('header_bytes')}" if res.get("header_bytes") else ""),
             f"  tensors     {res.get('tensor_count')}"
             + (f"  metadata {res.get('metadata_count')}"
                if res.get("metadata_count") is not None else "")]
    if res.get("architecture"):
        lines.append(f"  arch        {res['architecture']}"
                     + (f"  name {res['name']}" if res.get("name") else ""))
    if res.get("parameter_count"):
        lines.append(f"  parameters  {res['parameter_count']:,}")
    if res.get("quantisations"):
        lines.append(f"  quantised   {', '.join(res['quantisations'])}")
    if res.get("dtypes"):
        lines.append(f"  dtypes      {', '.join(res['dtypes'])}")
    for tensor in (res.get("tensors") or [])[:12]:
        shape = "x".join(str(dim) for dim in (tensor.get("shape") or []))
        lines.append(f"    {str(tensor['name'])[:44]:<44} {tensor.get('dtype') or tensor.get('type')}"
                     f"  {shape}")
    if res.get("tensors_truncated"):
        lines.append(f"    ... {res['tensor_count'] - 12} more")
    if res.get("truncated_count"):
        lines.append(f"  WARNING     {res['truncated_count']} tensor(s) point past EOF")
    if res.get("problem_count"):
        lines.append(f"  WARNING     {res['problem_count']} header problem(s)")
    if res.get("note"):
        lines.append("  " + str(res["note"]))
    return chr(10).join(lines)


def _render_gdb(res):
    if not res.get("ok"):
        return "gdb: " + str(res.get("error", "unknown"))
    lines = [f"gdb  {res.get('gdb') or ''}  {res.get('path')}".rstrip()]
    if "instructions" in res:
        lines.append(f"  {res.get('target')}: {res.get('count')} instruction(s)")
        for item in (res["instructions"] or [])[:24]:
            lines.append(f"    {item['address']}  {str(item['instruction'])[:60]}")
    elif "breakpoints" in res:
        lines.append(f"  {res.get('resolved')} of {res.get('count')} symbol(s) resolved")
        for item in res["breakpoints"]:
            if item.get("ok"):
                lines.append(f"    {item['symbol']:<28} {item['address']}  "
                             f"{item.get('function') or ''}  line {item.get('line')}")
            else:
                lines.append(f"    {item['symbol']:<28} ! {item.get('error')}")
    elif "registers" in res:
        lines.append(f"  {res.get('count')} register(s)")
        for item in (res["registers"] or [])[:20]:
            lines.append(f"    {item['name']:<8} {item['value']}")
    elif "mappings" in res:
        lines.append(f"  {res.get('mapping_count')} mapping(s), "
                     f"{res.get('shared_library_count')} shared library(ies)")
        for item in (res["mappings"] or [])[:16]:
            lines.append(f"    {item['start']}  {item['perms']}  {item['path'][:44]}")
    else:
        lines.append(f"  {res.get('function_symbol_count')} function symbol(s), "
                     f"{res.get('source_file_count')} source file(s)")
    return chr(10).join(lines)


def _render_deps(res):
    if not res.get("ok"):
        lines = ["deps: " + str(res.get("error", "unknown"))]
        if res.get("hint"):
            lines.append("  hint " + str(res["hint"]))
        return chr(10).join(lines)
    ecosystems = res.get("ecosystems") or {}
    lines = [f"Dependencies in {res.get('root')}",
             f"  {res.get('dependency_count')} dependenc(ies) from "
             f"{res.get('manifest_count')} manifest(s)"
             f"  resolved {res.get('resolved_count')}"
             f"  unresolved {res.get('unresolved_count')}"]
    if ecosystems:
        lines.append("  ecosystems  " + "  ".join(f"{name}={count}"
                                                  for name, count in ecosystems.items()))
    for entry in (res.get("toolchains") or [])[:4]:
        lines.append(f"  toolchain   {entry.get('kind')} {entry.get('version')}")
    for manifest in (res.get("manifests") or [])[:10]:
        lines.append(f"  {manifest.get('kind'):<12} {manifest.get('path')}"
                     f"  ({manifest.get('dependency_count')} deps, "
                     f"{manifest.get('resolved_count')} resolved)")
    for item in (res.get("dependencies") or [])[:25]:
        pin = "" if item.get("resolved") else "  (range, not a pinned version)"
        lines.append(f"    {str(item.get('ecosystem')):<9} {str(item.get('name'))[:44]:<44} "
                     f"{str(item.get('version') or '-')[:16]:<16}{pin}")
    if len(res.get("dependencies") or []) > 25:
        lines.append(f"    ... {len(res['dependencies']) - 25} more")
    if res.get("errors"):
        lines.append(f"  {len(res['errors'])} manifest(s) could not be read:")
        for error in res["errors"][:5]:
            lines.append(f"    {error.get('path')}: {error.get('error')}")
    return chr(10).join(lines)


def _render_vulns(res):
    if not res.get("ok"):
        return "vulns: " + str(res.get("error", "unknown"))
    counts = res.get("severity_counts") or {}
    badge = "  ".join(f"{name}={count}" for name, count in counts.items()) or "none"
    inventory = res.get("inventory") or {}
    lines = [f"Vulnerability scan of {inventory.get('root') or '?'}",
             f"  queried {res.get('queried_count')} dependenc(ies)"
             f"  clean {res.get('clean_count')}"
             f"  affected packages {res.get('affected_package_count')}",
             f"  {res.get('vulnerability_count')} distinct vulnerabilit(ies)  {badge}"]
    for finding in (res.get("findings") or [])[:12]:
        lines.append(f"  {str(finding.get('worst_severity')):<8} "
                     f"{str(finding.get('name'))[:40]} {finding.get('version')}"
                     f"  ({finding.get('vulnerability_count')} vuln(s))")
        for vuln in (finding.get("vulnerabilities") or [])[:4]:
            fixed = ", ".join(vuln.get("fixed_in") or []) or "no fix published"
            identifiers = vuln.get("alias_group") or [vuln.get("id")]
            shown = identifiers[0] if identifiers else vuln.get("id")
            lines.append(f"      {str(shown):<18} {str(vuln.get('severity')):<8} "
                         f"fixed in {fixed}")
            if vuln.get("summary"):
                lines.append(f"          {str(vuln['summary'])[:88]}")
    if res.get("unresolved_count"):
        lines.append(f"  {res['unresolved_count']} dependenc(ies) had no pinned version and were "
                     f"not queried:")
        for item in (res.get("unresolved") or [])[:5]:
            lines.append(f"    {item.get('ecosystem')} {item.get('name')} {item.get('version') or ''}")
    if res.get("errors"):
        lines.append(f"  {len(res['errors'])} lookup(s) failed; the scan is not complete")
    if not res.get("findings"):
        lines.append("  no vulnerabilities found"
                     + ("" if res.get("complete") else " (but the scan is incomplete)"))
    return chr(10).join(lines)


def _render_remediate(res):
    apply_report = res.get("apply") or {}
    plan = res.get("plan") or {}
    lines = [_render_vulns(res.get("scan") or {})]
    lines.append("")
    lines.append(f"Remediation plan: {plan.get('edit_count')} edit(s), "
                 f"{plan.get('skipped_count')} skipped")
    for edit in (plan.get("edits") or [])[:15]:
        lines.append(f"  {str(edit.get('name'))[:40]:<40} {edit.get('from')} -> {edit.get('to')}"
                     f"  ({len(edit.get('fixes') or [])} advisory(ies))")
    for skip in (plan.get("skipped") or [])[:6]:
        lines.append(f"  skip {str(skip.get('name'))[:36]:<36} {skip.get('reason')}")
    lines.append(f"  {apply_report.get('note', '')}")
    if apply_report.get("files_changed"):
        lines.append("  files written:")
        for path in apply_report["files_changed"]:
            lines.append(f"    {path}")
    for verified in (apply_report.get("verified") or [])[:10]:
        mark = "ok" if verified.get("ok") else "FAILED"
        lines.append(f"    [{mark}] {str(verified.get('name'))[:34]:<34} {verified.get('from')} "
                     f"-> {verified.get('to')}  verified_by={verified.get('verified_by')}")
    return chr(10).join(lines)


def _render_cve_info(res):
    if not res.get("ok"):
        return "cve: " + str(res.get("error", "unknown"))
    lines = [f"{res.get('id')}  {res.get('severity')}"
             + (f"  CVSS {res.get('cvss')}" if res.get("cvss") is not None else ""),
             f"  {str(res.get('summary') or '')[:100]}"]
    if res.get("aliases"):
        lines.append("  aliases     " + ", ".join(str(a) for a in res["aliases"][:6]))
    for package in (res.get("affected_packages") or [])[:6]:
        lines.append(f"  affects     {package.get('ecosystem')} {package.get('name')}")
        for declared in (package.get("ranges") or [])[:3]:
            events = " ".join(f"{key}:{value}" for event in declared.get("events") or []
                              for key, value in event.items())
            lines.append(f"    {declared.get('type')} {events[:88]}")
    if res.get("details"):
        lines.append("  details     " + str(res["details"])[:400].replace(chr(10), " "))
    return chr(10).join(lines)


def _render_cdp(res):
    if not res.get("ok"):
        lines = ["cdp: " + str(res.get("error", "unknown"))]
        if res.get("hint"):
            lines.append("  hint: " + str(res["hint"]))
        return chr(10).join(lines)
    # The new aspects are not the `inspect` shape at all: a screenshot has no pages and no
    # protocol version, and a network record has requests. Rendering them through the inspect
    # layout printed "None protocol None" over an otherwise correct result.
    aspect = res.get("aspect")
    if aspect == "screenshot":
        target = res.get("target") or {}
        lines = [f"screenshot  {res.get('format')}  {res.get('bytes')} bytes",
                 f"  sha256      {res.get('sha256')}",
                 f"  page        {str(target.get('title'))[:40]!r}  "
                 f"{str(target.get('url'))[:50]}"]
        if res.get("format_mismatch"):
            lines.append(f"  NOTE        asked for {res.get('declared_format')}, "
                         f"browser returned {res.get('format')}")
        if res.get("launched"):
            lines.append(f"  launched    port {res['launched']['port']}")
        return chr(10).join(lines)
    if aspect == "network":
        lines = [f"network  {res.get('request_count')} request(s)"
                 f"  statuses {', '.join(res.get('statuses') or []) or 'none'}",
                 f"  hosts       {', '.join((res.get('hosts') or [])[:6]) or 'none'}"]
        if res.get("navigated_to"):
            lines.append(f"  navigated   {str(res['navigated_to'])[:70]}")
        for request in (res.get("requests") or [])[:15]:
            status = request.get("status")
            size = request.get("encoded_bytes")
            lines.append(f"    {str(request.get('method'))[:6]:<6} "
                         f"{str(request.get('url'))[:52]:<52} "
                         f"{status if status is not None else '-'}"
                         f"{f'  {size}B' if size is not None else ''}"
                         f"{'  FAILED' if request.get('failed') else ''}")
        if res.get("unattributed_events"):
            lines.append(f"  other       {', '.join(res['unattributed_events'][:5])}")
        return chr(10).join(lines)
    if aspect == "targets":
        types = res.get("types") or {}
        lines = [f"targets  {res.get('target_count')}  "
                 + "  ".join(f"{name}={count}" for name, count in sorted(types.items())),
                 f"  electron-shaped  {res.get('electron_shaped')}"]
        for target in (res.get("targets") or [])[:12]:
            lines.append(f"    {str(target.get('type')):<16} "
                         f"{str(target.get('title'))[:30]!r} "
                         f"{str(target.get('url'))[:40]}")
        return chr(10).join(lines)

    lines = [f"{res.get('browser')}  protocol {res.get('protocol_version')}"
             f"  V8 {res.get('v8_version')}",
             f"  endpoint    {res.get('endpoint')}"
             f"  ({res.get('page_count')} page(s) of {res.get('target_count')} targets)"]
    if res.get("launched"):
        lines.append(f"  launched    port {res['launched']['port']}")
    for page in (res.get("pages") or [])[:2]:
        lines.append(f"  page        {str(page.get('title'))[:40]!r}  {str(page.get('url'))[:50]}")
        for expression, value in (page.get("values") or {}).items():
            if value.get("ok"):
                rendered = repr(value.get("value"))
                lines.append(f"    {expression[:34]:<34} {rendered[:48]}")
            else:
                lines.append(f"    {expression[:34]:<34} ! {str(value.get('error'))[:44]}")
    return chr(10).join(lines)


def _render_ptrace(res):
    if not res.get("ok"):
        human = "ptrace: " + str(res.get("error", "unknown"))
    elif "processes" in res:
        lines = [f"Processes ({res.get('count')}"
                 + (f", filter {res['filter']!r}" if res.get("filter") else "") + ")"]
        for row in (res["processes"] or [])[:20]:
            lines.append(f"  {row['pid']:>8}  {row['cmdline'][:70]}")
        human = chr(10).join(lines)
    else:
        lines = [f"Process {res.get('pid')}  {res.get('exe')}",
                 f"  state       {res.get('state')}  ppid {res.get('ppid')}"
                 f"  threads {res.get('threads')}  rss {res.get('rss_kb')}",
                 f"  modules     {res.get('module_count')} across "
                 f"{res.get('region_count')} regions",
                 f"  attach      {'yes' if res.get('attachable') else 'no'}"
                 f"  ({res.get('attach_reason')})"]
        for module in (res.get("modules") or [])[:8]:
            lines.append(f"    {module['exec_bytes']:>9}  {module['path']}")
        if res.get("suspicious_modules"):
            lines.append("  from /tmp, /home or /dev/shm:")
            for item in res["suspicious_modules"][:6]:
                lines.append(f"    {item}")
        if res.get("writable_executable"):
            lines.append(f"  W+X regions {len(res['writable_executable'])}:")
            for item in res["writable_executable"][:5]:
                lines.append(f"    {item['start']}  {item['size']}  {item['path']}")
        if res.get("anonymous_exec_bytes"):
            lines.append(f"  anonymous executable bytes {res['anonymous_exec_bytes']}"
                         "  (a common sign of injected code)")
        human = chr(10).join(lines)
    return human


def cmd_re(args):
    from pathlib import Path
    from ..core.re import elf
    from ..core.re import native as renative
    verb = args.re_verb
    path = args.path or args.value

    # Handle 'pe' and 'annotate' subverb routing: e.g. xtforge re annotate rename <path>
    pe_subverb = "info"
    ann_subverb = "list"
    bm_subverb = "list"
    if verb == "bookmarks":
        # `re bookmarks <sub> <path> [address]` follows the same shape as `annotate`
        # so that an address is a positional, not a flag: at the prompt, the address
        # is the thing you are looking at, and typing --rva for it is friction.
        # Positional binding is subtle here: argparse fills `value` with the subverb,
        # `path` with the next token, and everything after that lands in `extra`. So
        # the address is extra[0] when a path was supplied, and extra[1] only when
        # the caller omitted the path and passed it as extra[0].
        if args.value in ("set", "list", "next", "prev", "unset"):
            bm_subverb = args.value
            extra = getattr(args, "extra", []) or []
            if args.path:
                bm_address = extra[0] if extra else getattr(args, "target", None)
            else:
                path = extra[0] if extra else None
                bm_address = extra[1] if len(extra) > 1 else getattr(args, "target", None)
        else:
            bm_subverb = "list"
            bm_address = getattr(args, "target", None)
    if verb == "pe":
        if args.value in ("info", "sections", "imports", "exports", "tls",
                          "resources", "load-config", "certificates"):
            pe_subverb = args.value
            extra = getattr(args, "extra", [])
            path = args.path or (extra[0] if extra else None)
        else:
            pe_subverb = "info"
            path = args.path or args.value
    elif verb == "annotate":
        if args.value in ("rename", "comment", "type", "list", "export"):
            ann_subverb = args.value
            extra = getattr(args, "extra", [])
            path = args.path or (extra[0] if extra else None)
        else:
            ann_subverb = "list"
            path = args.path or args.value
    elif verb in ("diff", "fn-match", "fnmatch", "match-functions",
                  "bundle-diff", "compare-bundles", "bundle-compare",
                  "api", "api-contract", "abi",
                  "coverage", "recon-coverage", "evaluate-coverage",
                  "capture-diff", "capture-compare", "correlate",
                  "goto", "nav", "resume", "bookmark", "step",
                  "guidance", "workflows", "guide"):
        # These take two positionals: bin1 in `value`, bin2 in `path`. Resolve bin2 BEFORE
        # `path` is rewritten to bin1, otherwise both sides point at the same file and the
        # matcher reports a perfect self-match.
        second_binary = args.path or (getattr(args, "extra", None) or [None])[0]
        path = args.value or args.path

    # 'llvm' routes like 'pe': the subverb is the second positional argument.
    # available/tools need no path, so handle this before the path check.
    if verb == "xrefs":
        # `re xrefs <binary> <symbol>` — the symbol arrives in `path`. Capturing it is only half
        # the job: `path` is still the symbol afterwards, so without the swap below the binary
        # would be `helper` and the guard would refuse a target that was supplied correctly.
        xref_target = args.path or (getattr(args, "extra", None) or [None])[0] or ""
        path = args.value or args.path

    if verb == "llvm":
        from ..core.re import llvm
        subverb = args.value or "available"
        llvm_path = args.path or (getattr(args, "extra", None) or [None])[0]
        tools = llvm.available()
        if subverb in ("available", "tools"):
            res = {"ok": True, "tools": tools}
            human = "\n".join(f"{name:<12} {'yes' if tools[name] else 'no'}"
                              for name in llvm.LLVM_TOOLS)
            return _out(args, res, human)
        if subverb in ("sections", "symbols"):
            needed = ("objdump", "readobj") if subverb == "sections" else ("nm",)
            missing = [llvm.LLVM_TOOLS.get(n, n) for n in needed if not tools.get(n)]
            if missing:
                res = {"ok": False, "error": f"tool not found: {', '.join(missing)}",
                       "tools": tools}
                return _out(args, res, f"error: {res['error']}", code=1)
            if not llvm_path:
                res = {"ok": False, "error": "re llvm needs a path"}
                return _out(args, res, f"error: {res['error']}", code=2)
            try:
                rows = (llvm.sections(str(llvm_path)) if subverb == "sections"
                        else llvm.symbols(str(llvm_path)))
            except (OSError, ValueError, TypeError) as exc:
                res = {"ok": False, "error": str(exc)}
                return _out(args, res, f"error: {exc}", code=1)
            res = {"ok": True, "path": str(llvm_path), subverb: rows}
            return _out(args, res, json.dumps(res, indent=2))
        res = {"ok": False, "error": f"unknown llvm subverb: {subverb}"}
        return _out(args, res, f"error: {res['error']}", code=2)

    # 'demangle' takes symbols, not a path, so it also precedes the path guard.
    if verb == "demangle":
        from ..core.re import sysimage as _sysimage
        symbols = [args.value] if args.value else []
        if args.path:
            symbols.append(args.path)
        symbols.extend(getattr(args, "extra", None) or [])
        symbols = [item for item in symbols if item]
        if not symbols:
            res = {"ok": False, "error": "re demangle needs at least one symbol"}
            return _out(args, res, f"error: {res['error']}", code=2)
        res = _sysimage.demangle(symbols)
        human = "\n".join(f"{row['symbol']} -> {row['demangled'] or '(not swift)'}"
                          for row in res.get("results", []))
        return _out(args, res, human, code=0 if res.get("ok") else 1)

    if verb in ("guidance", "workflows", "guide"):
        # No binary needed: listing workflows, searching them and the reverse verb lookup are
        # all self-contained. Handled before the path requirement rather than demanding a
        # target that is never read.
        from ..core.re import guidance as _guidance
        sub = (getattr(args, "value", None) or "").strip()
        if sub.startswith("search="):
            res = _guidance.search_guidance(sub.split("=", 1)[1])
        elif sub.startswith("for="):
            res = _guidance.guidance_for_verb(sub.split("=", 1)[1])
        elif sub.startswith("verb="):
            res = _guidance.guidance_for_verb(sub.split("=", 1)[1])
        elif sub:
            res = _guidance.show_workflow(sub)
        else:
            res = _guidance.list_workflows()
        return _out(args, res, _render_guidance(res), code=0 if res.get("ok") else 2)

    if verb in ("deps", "vulns", "cve-scan", "remediate", "cve-info"):
        from ..core import deps as _deps
        from ..core.deps import remediate as _remediate
        from ..core.deps import vulns as _vulns

        value = (getattr(args, "value", None) or "").strip()
        symbol = getattr(args, "symbol", None)
        limit = getattr(args, "limit", None) or 400

        if verb == "cve-info":
            res = _vulns.advisory(symbol or value)
            return _out(args, res, _render_cve_info(res), code=0 if res.get("ok") else 2)

        target = path or (value or ".")
        # A compiled artifact carries its own module graph in buildinfo, which is what is actually
        # deployed — stronger evidence than any manifest sitting in a tree.
        if Path(target).is_file():
            try:
                raw = Path(target).read_bytes()[:4 * 1024 * 1024]
            except OSError as exc:
                res = {"ok": False, "error": str(exc), "path": str(target)}
                return _out(args, res, _render_deps(res), code=2)
            toolchains = _deps.detect_binary_toolchains(raw)
            inventory = {
                "ok": True, "root": str(target), "manifests": [], "manifest_count": 0,
                "dependency_count": len(toolchains["embedded_modules"]),
                "resolved_count": len(toolchains["embedded_modules"]),
                "unresolved_count": 0,
                "ecosystems": {"Go": len(toolchains["embedded_modules"])} if
                               toolchains["embedded_modules"] else {},
                "scopes": {"runtime": len(toolchains["embedded_modules"])},
                "dependencies": toolchains["embedded_modules"],
                "toolchains": toolchains["toolchains"], "errors": [], "complete": True,
            }
        else:
            inventory = _deps.discover(target, include_dev=not getattr(args, "no_dev", False))
            if not inventory.get("ok"):
                return _out(args, inventory, _render_deps(inventory), code=2)
            inventory["toolchains"] = []

        if verb == "deps":
            return _out(args, inventory, _render_deps(inventory),
                        code=0 if inventory.get("ok") else 2)

        scan = _vulns.scan(inventory.get("dependencies") or [], limit=limit,
                           include_dev=not getattr(args, "no_dev", False))
        scan["inventory"] = {key: inventory.get(key) for key in
                             ("root", "manifest_count", "dependency_count", "resolved_count",
                              "unresolved_count", "ecosystems", "toolchains")}

        if verb in ("vulns", "cve-scan"):
            return _out(args, scan, _render_vulns(scan), code=0 if scan.get("ok") else 2)

        # remediate: plan, then apply only when explicitly asked.
        plan = _remediate.plan(inventory.get("dependencies") or [], scan.get("findings") or [],
                              allow_major=bool(getattr(args, "allow_major", False)),
                              include_dev=not getattr(args, "no_dev", False))
        write = bool(getattr(args, "write", False))
        applied = _remediate.apply(plan.get("edits") or [], write=write) if plan.get("edits") else {
            "ok": True, "applied_count": 0, "failure_count": 0, "files_changed": [],
            "verified": [], "failures": [], "note": "nothing to remediate"}
        result = {"ok": applied.get("ok", False), "scan": scan, "plan": plan, "apply": applied}
        return _out(args, result, _render_remediate(result),
                    code=0 if applied.get("ok") else 2)

    if verb == "cdp":
        from ..core.re import cdp as _cdp
        target = (getattr(args, "value", None) or "").strip()
        aspect = getattr(args, "symbol", None)
        # Three capabilities that are not expression lists, so they cannot live in
        # `_OBSERVATIONS`: each issues its own protocol commands and returns structured data.
        wait = float(getattr(args, "timeout", None) or 5)
        if aspect == "screenshot":
            # A port attaches to a browser already running; anything else is treated as a URL to
            # launch against, so the capability works with no prior setup.
            res = (_cdp.capture_screenshot(int(target)) if target.isdigit()
                   else _cdp.capture_screenshot_of(target or "about:blank"))
            res["aspect"] = "screenshot"
            return _out(args, res, _render_cdp(res), code=0 if res.get("ok") else 2)
        if aspect == "network":
            res = (_cdp.capture_network(int(target), wait=wait) if target.isdigit()
                   else _cdp.capture_network_of(target or "about:blank", wait=wait))
            res["aspect"] = "network"
            return _out(args, res, _render_cdp(res), code=0 if res.get("ok") else 2)
        if aspect in ("targets", "electrontargets"):
            if not target.isdigit():
                res = {"ok": False,
                       "error": "targets needs the port of a running DevTools endpoint",
                       "hint": "start a browser with --remote-debugging-port=<port>, then pass it"}
            else:
                res = _cdp.enumerate_targets(int(target))
            res["aspect"] = "targets"
            return _out(args, res, _render_cdp(res), code=0 if res.get("ok") else 2)
        if aspect and aspect in _cdp._OBSERVATIONS:
            # `re cdp <port> --symbol=runtime` narrows to one observation aspect.
            if target.isdigit():
                res = _cdp.observe(int(target), aspect=aspect)
            else:
                launched = _cdp.launch_and_inspect(
                    target or "about:blank", expressions=_cdp._OBSERVATIONS[aspect])
                launched["aspect"] = aspect
                res = launched
        else:
            res = _cdp.inspect(target or None)
        return _out(args, res, _render_cdp(res), code=0 if res.get("ok") else 2)

    if verb == "ptrace" and not path:
        # Listing processes needs no target. Everything else about `ptrace` does.
        from ..core.re import proctrace as _proctrace
        res = _proctrace.list_processes(limit=args.limit or 60,
                                        name=getattr(args, "symbol", None))
        return _out(args, res, _render_ptrace(res), code=0 if res.get("ok") else 2)

    if not path:
        return _out(args, {"ok": False, "error": "re needs a path"},
                    "error: re needs a path", code=2)

    if verb in ("evidence-export", "evidence-import"):
        from ..core.re import evidence as _evidence

        if verb == "evidence-export":
            records = []
            try:
                records.append(_evidence.build(path))
            except (FileNotFoundError, ValueError) as exc:
                return _out(args, {"ok": False, "error": str(exc)},
                            f"error: {exc}", code=2)
            destination = getattr(args, "out", None) or (str(path) + ".bundle.json")
            manifest = _evidence.export_bundle(
                destination, records=records,
                note=getattr(args, "note", "") or "")
            human = (f"evidence bundle {manifest['path']}\n"
                     f"  digest      {manifest['digest']}\n"
                     f"  records     {manifest['record_count']}\n"
                     f"  size        {manifest['size']} bytes")
            return _out(args, manifest, human)

        report = _evidence.import_bundle(
            path, verify_files=bool(getattr(args, "verify", False)))
        if not report.get("ok"):
            return _out(args, report, "evidence import: " + str(report.get("error")),
                        code=2)
        lines = [f"evidence bundle {report['path']}",
                 f"  integrity   {report['integrity']}",
                 f"  records     {report['record_count']}",
                 f"  findings    {report['finding_count']}",
                 f"  unknowns    {report['unknown_count']}"]
        if report.get("warning"):
            lines.append(f"  WARNING     {report['warning']}")
        if "file_checks" in report:
            changed = report.get("changed_files") or []
            lines.append(f"  inputs      {len(report['file_checks'])} checked, "
                         f"{len(changed)} changed")
            for name in changed[:10]:
                lines.append(f"    CHANGED   {name}")
        return _out(args, report, "\n".join(lines))

    if verb == "evidence":
        # The record describes the whole file, so it is useful even when the
        # native image model cannot claim the format (a text file, for one).
        # Probe the hub only to enrich slice/address-space/limits; a missing or
        # failing hub degrades to None/{}, it never fails the evidence verb.
        from ..core.re import evidence as _evidence
        from ..core.re import sysimage as _sysimage

        requested_arch = getattr(args, "arch", None)
        slice_name = requested_arch
        address_space = None
        limits: dict = {}
        try:
            ov = _sysimage.overview(path, member=getattr(args, "member", None),
                                    arch=requested_arch)
        except Exception:
            ov = {}
        if isinstance(ov, dict) and ov.get("ok"):
            images = ov.get("images") or []
            first = images[0] if images and isinstance(images[0], dict) else {}
            if not slice_name:
                # A fat Mach-O image carries the selected architecture and a
                # non-zero slice offset; that is the slice, not the whole file.
                slice_name = first.get("slice") or (
                    first.get("arch") if first.get("slice_offset") else None
                )
            base = first.get("base", first.get("image_base"))
            if base is None:
                # A raw-image request states its own load address; the hub
                # echoes it through section addresses but has no `base` key.
                base = getattr(args, "base", None)
            bits = first.get("bits")
            if base is not None and not isinstance(base, bool) and bits:
                try:
                    address_space = {"base": int(base), "bits": int(bits)}
                except (TypeError, ValueError):
                    address_space = None
            unknown = first.get("unknown")
            if isinstance(unknown, dict) and "truncated" in unknown:
                limits["truncated"] = bool(unknown["truncated"])
        try:
            record = _evidence.build(
                path,
                member=getattr(args, "member", None),
                arch=slice_name,
                verb="evidence",
                address_space=address_space,
                limits=limits,
            )
        except (OSError, ValueError) as exc:
            return _out(args, {"ok": False, "error": str(exc)},
                        f"error: {exc}", code=1)
        return _out(args, record, _human_evidence(record))

    if verb == "init-project":
        from ..core.re.project import init_project
        if args.path or args.extra:
            raise ValueError("init-project accepts one destination directory")
        res = init_project(path, name=args.name)
        return _out(args, res, f"Created RE project at {res['path']}. Start with README.md.")
    try:
        if verb == "callgraph":
            from ..core.re import sysimage as _sysimage
            res = _sysimage.callgraph(path, member=args.member, arch=args.arch,
                                      limit=getattr(args, "limit", 0) or 0)
            human = (f"{res.get('nodes', 0)} nodes, {res.get('edges', 0)} edges, "
                     f"{len(res.get('roots') or [])} roots")
            return _out(args, res, human, code=0 if res.get("ok") else 1)

        if verb == "pdb-types":
            from ..core.re import sysimage as _sysimage
            res = _sysimage.pdb_types(path, limit=getattr(args, "limit", 0) or 0)
            human = (_human_pdb_types(res) if res.get("ok")
                     else f"error: {res.get('error') or path}")
            return _out(args, res, human, code=0 if res.get("ok") else 1)

        if verb in ("archives", "kernelcache"):
            # Both container views come from the same Go hub overview the other
            # re verbs use; narrow its result to the container caller asked for.
            from ..core.re import sysimage
            try:
                ov = sysimage.overview(path)
                if not ov.get("ok"):
                    res = {"ok": False, "error": ov.get("error") or f"not a {verb} container"}
                elif verb == "archives":
                    if ov.get("format") != "archive":
                        res = {"ok": False, "error": f"not an archive: {path}"}
                    else:
                        members = ov.get("archive") or []
                        res = {"ok": True, "archive": members, "count": len(members)}
                else:
                    images = ov.get("images") or []
                    first = images[0] if isinstance(images, list) and images else {}
                    if ov.get("format") != "kernelcache" or not isinstance(first, dict):
                        res = {"ok": False, "error": f"not a kernelcache: {path}"}
                    else:
                        res = {"ok": True, "format": "kernelcache",
                               "member": ov.get("member", ""),
                               "arch": first.get("arch"),
                               "entry_point": first.get("entry_point")}
            except Exception as exc:
                res = {"ok": False, "error": str(exc)}
            return _out(args, res, json.dumps(res, indent=2),
                        code=0 if res.get("ok") else 1)
        if verb == "pdb":
            # A PDB only ever applies to a PE. A file whose format is unknown has no
            # binary to match a symbol file against, so asking for its PDB is a usage
            # error; a known non-PE binary (ELF, Mach-O) legitimately has none.
            from ..core.re import sysimage
            try:
                probe = sysimage.overview(path)
                if isinstance(probe, dict) and probe.get("format") == "unknown":
                    # A PDB handed to `re pdb` is the likely mistake: this verb takes the
                    # PE binary and finds its symbol file. `pdb-types` reads a .pdb
                    # directly, so say which is which instead of "not a binary format".
                    try:
                        with open(path, "rb") as handle:
                            magic = handle.read(32)
                    except OSError:
                        magic = b""
                    if magic.startswith(b"Microsoft C/C++ MSF 7.00"):
                        res = {"ok": False,
                               "error": ("this is a PDB symbol file, not a binary. "
                                         "`re pdb-types " + str(path) + "` reads its types; "
                                         "`re pdb <pe-binary>` finds the PDB for a PE"),
                               "suggestion": "pdb-types"}
                    else:
                        res = {"ok": False,
                               "error": f"not a binary format: {path}"}
                    return _out(args, res, f"error: {res['error']}", code=1)
                scanned = sysimage.functions(path, limit=1)
                pdb = None
                warnings = []
                if scanned.get("ok"):
                    for image in scanned.get("images") or []:
                        if not isinstance(image, dict):
                            continue
                        warnings.extend(w for w in (image.get("warnings") or []) if w)
                        if pdb is None and isinstance(image.get("pdb"), dict):
                            pdb = image["pdb"]
                    res = {"ok": True, "pdb": pdb,
                           "matched": bool(pdb and pdb.get("matched")),
                           "warnings": warnings}
                else:
                    res = {"ok": False,
                           "error": scanned.get("error") or f"cannot analyse: {path}"}
            except Exception as exc:
                res = {"ok": False, "error": str(exc)}
            return _out(args, res, json.dumps(res, indent=2),
                        code=0 if res.get("ok") else 1)
        if verb == "info":
            res = renative.get_info(path)
        elif verb in {"overview", "functions", "xrefs-native", "dispatch-native",
                      "disasm-native", "decompile-native"}:
            from ..core.re import sysimage
            if verb == "overview":
                res = sysimage.overview(path, member=args.member, arch=args.arch,
                                        base=getattr(args, "base", None))
            elif verb == "functions":
                res = sysimage.functions(path, member=args.member, arch=args.arch, limit=args.limit)
            elif verb == "dispatch-native":
                res = sysimage.dispatch(path, member=args.member, arch=args.arch,
                                        target=args.target)
            elif verb == "xrefs-native":
                res = sysimage.references(path, member=args.member, arch=args.arch, target=args.target,
                                          max_functions=args.max_functions, limit=args.limit)
            else:
                res = sysimage.disassemble(path, member=args.member, arch=args.arch,
                                          target=args.target, byte_count=args.bytes,
                                          count=args.max_instructions, flow=args.flow,
                                          lift=verb == "decompile-native")
            human = (_human_overview(res) if verb == "overview"
                     else _human_functions(res) if verb == "functions"
                     else json.dumps(res, indent=2))
            return _out(args, res, human, code=0 if res.get("ok") else 1)
        elif verb == "needed":
            try:
                res = elf.needed(path)
            except Exception as exc:
                # `needed` was ELF-only, so a Mach-O reported "not an ELF file" while
                # `re overview` listed 13 dylibs from the same file. The engine answers
                # for every format it reads; an empty list is a real answer (a
                # freestanding binary needs nothing), not a failure.
                from ..core.re import sources as _sources
                overview = _sources.hub_overview(path)
                deps = _sources.needed_from_hub(path, overview)
                if deps is not None:
                    res = {"ok": True, "path": str(path), "needed": deps,
                           "engine": "xtforge-hub",
                           "format": (overview or {}).get("format")}
                else:
                    res = _sources.unsupported("needed", path)
        elif verb == "sections":
            res = renative.get_sections(path)
        elif verb == "symbols":
            res = renative.get_symbols(path, limit=args.limit)
            if not res.get("ok"):
                # The Python symbol readers cover ELF and PE. For anything else, report
                # the names the engine did recover instead of a generic format error —
                # and say plainly what this list is, so it is not mistaken for a symbol
                # table dump.
                from ..core.re import sources as _sources
                named = _sources.named_functions_from_hub(path, limit=args.limit)
                if named:
                    res = {"ok": True, "path": str(path), "symbols": named,
                           "count": len(named), "engine": "xtforge-hub",
                           "note": "named functions recovered by the engine, not a "
                                   "symbol-table listing"}
                else:
                    res = _sources.unsupported("symbols", path)
        elif verb == "search":
            from ..core.re import search as research
            from ..core.re import sources as _sources
            if not (getattr(args, "pattern", None) or "").strip():
                return _out(
                    args,
                    {"ok": False, "error": "search needs --pattern"},
                    "error: search needs --pattern <text> "
                    "(--hex for bytes such as '48 8b ?? c3', --regex for a bytes pattern)",
                    code=2)
            mode = ("hex" if getattr(args, "hex_pattern", False)
                    else "regex" if getattr(args, "regex", False) else "text")
            # A section table is an optimisation, not a requirement: a raw image
            # or an unknown container still gets searched, with file offsets and
            # `va: null`. Losing the mapping must never lose the match.
            try:
                sections = _sources.sections_from_hub(path)
            except (OSError, ValueError, KeyError, TypeError, RuntimeError):
                sections = None
            res = research.search_file(
                path,
                getattr(args, "pattern", None) or "",
                mode=mode,
                limit=args.limit,
                context=getattr(args, "context", 16),
                ignore_case=bool(getattr(args, "ignore_case", False)),
                sections=sections,
            )
        elif verb == "elfmeta":
            from ..core.re import elfmeta
            res = elfmeta.report(path)
        elif verb == "wasm":
            from ..core.re import wasm
            if args.value == "compare":
                _w_extra = [str(x) for x in (getattr(args, "extra", []) or [])]
                other = _w_extra[0] if _w_extra else None
                if not other:
                    return _out(args, {"ok": False,
                                       "error": "wasm compare needs two paths"},
                                "error: wasm compare needs two paths", code=2)
                res = wasm.compare(path, other)
            else:
                res = wasm.inspect(path)
        elif verb == "firmware":
            from ..core.re import firmware
            res = firmware.inspect(path)
        elif verb in ("goto", "nav", "resume", "bookmark", "step"):
            from ..core.re import navsession as _nav
            # Two positionals are `binary arg`: the binary arrives in `value` (already
            # rewritten into `path`) and the argument — address, bookmark name, direction —
            # in `second_binary`. Reading `args.value` here is reading the binary path again,
            # which is how the first version fed a file path into int().
            argument = second_binary
            extra_args = getattr(args, "extra", None) or []
            if verb == "goto":
                res = _nav.goto(path, argument or 0)
            elif verb == "bookmark":
                # Three positionals: binary, name, address. `extra` carries the address.
                address = extra_args[0] if extra_args else None
                res = _nav.bookmark(path, argument or "", address)
            elif verb == "step":
                res = _nav.step(path, argument or "prev")
            elif verb == "resume":
                res = _nav.where_to(path)
            else:
                res = _nav.current(path)
        elif verb in ("capture-diff", "capture-compare", "correlate"):
            from ..core.re import capcmp as _capcmp
            if not second_binary:
                return _out(args,
                            {"ok": False, "error": "capture-diff needs two paths: "
                                                   "xtforge re capture-diff <A> <B>"},
                            "error: capture-diff needs two paths", code=2)
            if verb == "correlate":
                # `re correlate <binary> <capture>` — static against observed.
                res = _capcmp.correlate_static_runtime(path, second_binary)
            else:
                res = _capcmp.compare_captures(path, second_binary)
        elif verb in ("coverage", "recon-coverage", "evaluate-coverage"):
            from ..core.re import reccoverage as _reccoverage
            source_root = second_binary or getattr(args, "target", None)
            if not source_root:
                return _out(args,
                            {"ok": False, "error": "coverage needs a source root: "
                                                   "xtforge re coverage <binary> <src-dir>"},
                            "error: coverage needs a source root", code=2)
            res = _reccoverage.evaluate_coverage(path, source_root)
        elif verb in ("api", "api-contract", "abi"):
            from ..core.re import apicontract as _apicontract
            res = _apicontract.audit_contract(path, baseline=second_binary)
        elif verb in ("bundle-diff", "compare-bundles", "bundle-compare"):
            from ..core.re import bundlecmp as _bundlecmp
            second = second_binary
            if not second:
                return _out(args,
                            {"ok": False, "error": "bundle-diff needs two paths: "
                                                   "xtforge re bundle-diff <A> <B>"},
                            "error: bundle-diff needs two paths", code=2)
            res = _bundlecmp.compare_bundles(path, second)
        elif verb in ("fn-match", "fnmatch", "match-functions"):
            from ..core.re import fnmatch as _fnmatch
            # Like `diff`, the second binary arrives as args.path: `re fn-match A B` puts A
            # in args.value and B in args.path.
            second = second_binary
            if not second:
                return _out(args,
                            {"ok": False, "error": "fn-match needs two binaries: "
                                                   "xtforge re fn-match <A> <B>"},
                            "error: fn-match needs two binaries: xtforge re fn-match <A> <B>",
                            code=2)
            # --confidence defaults to 1.0 for other verbs, so `or 0.55` never fires.
            # Only an explicitly-lowered value should be treated as a threshold.
            confidence = getattr(args, "confidence", 1.0)
            threshold = confidence if confidence < 1.0 else 0.55
            res = _fnmatch.compare_functions(path, second, threshold=threshold)
        elif verb in ("firmware-carve", "carve", "extract-firmware"):
            from ..core.re import firmwarecarve
            res = firmwarecarve.carve_firmware(path)
        elif verb in ("app", "appgraph", "application-graph"):
            from ..core.re import appgraph
            res = appgraph.inspect_application(path, limit=args.limit or 200)
        elif verb in ("il2cpp", "il2cpp-metadata", "global-metadata"):
            from ..core.re import il2cpp
            res = il2cpp.inspect_il2cpp_metadata(path)
        elif verb in ("dart", "dart-aot", "snapshot"):
            from ..core.re import dartsnapshot
            res = dartsnapshot.inspect_dart_snapshot(path)
        elif verb in ("swift", "swift-types"):
            from ..core.re import swiftmeta
            res = swiftmeta.inspect_swift_metadata(path, limit=args.limit or 500)
        elif verb in ("ntfs", "ntfs-journal"):
            from ..core.re import ntfs
            res = ntfs.inspect_ntfs_journal(path, limit=args.limit or 500)
        elif verb in ("firmware", "fv", "uefi-firmware"):
            from ..core.re import firmwarevolume
            res = firmwarevolume.inspect_firmware_volume(path, limit=args.limit or 500)
        elif verb in ("assetcatalog", "car"):
            from ..core.re import assetcatalog
            res = assetcatalog.inspect_asset_catalog(path, limit=args.limit or 200)
        elif verb in ("unknowns", "obligations"):
            from ..core.re import obligations
            action = args.value if args.value in ("list", "record", "resolve",
                                                 "waive") else "list"
            target = path
            if action == "list":
                res = obligations.list_unknowns(target, limit=args.limit or 200)
            elif action == "record":
                res = obligations.record_unknown(
                    target, getattr(args, "name", None) or "",
                    getattr(args, "comment", None) or "")
            elif action == "resolve":
                res = obligations.resolve_unknown(
                    target, getattr(args, "name", None) or "",
                    getattr(args, "comment", None) or "")
            else:
                res = obligations.waive_unknown(
                    target, getattr(args, "name", None) or "",
                    getattr(args, "comment", None) or "")
        elif verb in ("v8cache", "codecache"):
            from ..core.re import v8cache
            res = v8cache.inspect_v8_code_cache(path)
        elif verb in ("dex-classes", "dex-search"):
            from ..core.re import dex as _dex
            res = _dex.search_classes(path, getattr(args, "symbol", None) or "",
                                      limit=args.limit or 60)
        elif verb in ("dex-refs", "dex-trace"):
            from ..core.re import dex as _dex
            res = _dex.trace_references(path, getattr(args, "symbol", None) or "",
                                        limit=args.limit or 60)
        elif verb in ("hap", "harmony"):
            from ..core.re import harmony as _harmony
            res = _harmony.inspect_hap(path)
        elif verb in ("model", "model-artifact", "gguf", "safetensors"):
            from ..core.re import modelartifact as _model
            if verb == "gguf":
                from pathlib import Path as _P
                res = _model.inspect_gguf(_P(path), full_hash=bool(getattr(args, "deep", False)))
            elif verb == "safetensors":
                from pathlib import Path as _P
                res = _model.inspect_safetensors(_P(path),
                                                 full_hash=bool(getattr(args, "deep", False)))
            elif str(getattr(args, "symbol", "") or "").lower() in ("gpu", "gpu-code"):
                res = _model.inspect_gpu_code(path)
            else:
                res = _model.inspect(path, full_hash=bool(getattr(args, "deep", False)))
        elif verb in ("gdb", "gdbmi"):
            from ..core.re import gdbmi as _gdbmi
            sub = (args.value or "inspect").lower()
            target_path = args.path or (args.extra[0] if args.extra else "")
            if sub == "inspect":
                res = _gdbmi.inspect(target_path)
            elif sub in ("disasm", "disassemble"):
                res = _gdbmi.disassemble(
                    target_path,
                    function=(args.extra[0] if args.extra else None),
                    count=int(args.count or 40))
            elif sub in ("break", "breakpoints"):
                res = _gdbmi.breakpoints(target_path, list(args.extra or []))
            elif sub in ("registers", "regs"):
                res = _gdbmi.registers(target_path)
            elif sub in ("segments", "maps"):
                res = _gdbmi.segments(target_path)
            else:
                res = {"ok": False, "error": f"unknown gdb subcommand: {sub!r}",
                       "subcommands": ["inspect", "disasm", "break", "registers",
                                       "segments"]}
        elif verb == "ptrace":
            from ..core.re import proctrace as _proctrace
            res = _proctrace.inspect(path)
        elif verb in ("playwright", "trace"):
            from ..core.re import playwright
            res = playwright.inspect_playwright_trace(path, limit=args.limit or 200)
        elif verb in ("objc", "objc-classes", "objc-protocols"):
            from ..core.re import objc
            res = objc.inspect_objc(path, limit=args.limit or 500)
        elif verb in ("keyed", "keyed-archive"):
            from ..core.re import packaging
            res = packaging.inspect_keyed_archive(path)
        elif verb in ("jvm", "maven", "nuget"):
            from ..core.re import packaging
            res = packaging.inspect_jvm_metadata(path)
        elif verb in ("appbundle", "bundle"):
            from ..core.re import packaging
            res = packaging.inspect_desktop_bundle(path)
        elif verb in ("uefi", "nvram"):
            from ..core.re import uefi
            res = uefi.inspect_uefi_variables(path)
        elif verb == "sqlite":
            from ..core.re import artifacts
            res = artifacts.inspect_sqlite(path)
        elif verb == "beam":
            from ..core.re import artifacts
            res = artifacts.inspect_beam(path)
        elif verb == "evm":
            from ..core.re import artifacts
            res = artifacts.inspect_evm(path)
        elif verb == "ips":
            from ..core.re import artifacts
            res = artifacts.inspect_apple_ips(path)
        elif verb == "devicetree":
            from ..core.re import devices
            res = devices.inspect_devicetree(path)
        elif verb == "kconfig":
            from ..core.re import devices
            res = devices.inspect_kernel_config(path)
        elif verb == "lnk":
            from ..core.re import devices
            res = devices.inspect_shortcut(path)
        elif verb == "formats":
            from ..core.re import formats as formats_mod
            fmt_action = args.value if args.value in (
                "plist", "pyc", "desktop", "go", "rust") else "inspect"
            fmt_extra = [str(x) for x in (getattr(args, "extra", []) or [])]
            fmt_target = path or (fmt_extra[0] if fmt_extra else None)
            if not fmt_target:
                return _out(args, {"ok": False, "error": "formats needs a path"},
                            "error: formats needs a path", code=2)
            fmt_readers = {
                "inspect": formats_mod.inspect,
                "plist": formats_mod.inspect_plist,
                "pyc": formats_mod.inspect_pyc,
                "desktop": formats_mod.inspect_desktop,
                "go": formats_mod.inspect_go_binary,
                "rust": formats_mod.inspect_rust_binary,
            }
            res = fmt_readers[fmt_action](fmt_target)
        elif verb == "managed":
            from ..core.re import managed as managed_mod
            # `re managed <action> <path>`: the action lands in `value`, so the
            # path has to be read from args.path or, when the caller omits a path,
            # from the first extra positional.
            managed_actions = ("artifact", "members", "boundaries")
            managed_extra = [str(x) for x in (getattr(args, "extra", []) or [])]
            if args.value in managed_actions:
                action = args.value
            else:
                action = "artifact"
                if args.value and managed_extra and managed_extra[0] != args.value:
                    managed_extra.insert(0, args.value)
            path = path or (managed_extra[0] if managed_extra else None)
            if not path:
                return _out(args, {"ok": False, "error": "managed needs a path"},
                            "error: managed needs a path", code=2)
            if action == "artifact":
                res = managed_mod.inspect_artifact(path)
            elif action == "members":
                res = managed_mod.inspect_members(path, limit=args.limit or 500)
            elif action == "boundaries":
                res = managed_mod.inspect_boundaries(path)
            else:
                return _out(args, {"ok": False,
                                   "error": f"unknown managed action: {action}"},
                            f"error: unknown managed action {action}", code=2)
        elif verb == "bookmarks":
            from ..core.re import bookmarks as _bm
            label = getattr(args, "name", None) or ""
            note = getattr(args, "comment", None) or ""
            if bm_subverb == "set":
                if not bm_address:
                    return _out(args, {"ok": False, "error": "bookmarks set needs an address"},
                                "error: bookmarks set <path> <address> [--name label]",
                                code=2)
                res = _bm.set_bookmark(path, bm_address, label=label, note=note)
            elif bm_subverb == "unset":
                if not bm_address:
                    return _out(args, {"ok": False, "error": "bookmarks unset needs an address"},
                                "error: bookmarks unset <path> <address>", code=2)
                res = _bm.unset_bookmark(path, bm_address)
            elif bm_subverb == "next":
                res = _bm.next_bookmark(path, bm_address or "0x0")
            elif bm_subverb == "prev":
                res = _bm.prev_bookmark(path, bm_address or "0xffffffffffffffff")
            else:
                res = _bm.list_bookmarks(path, after=bm_address or None,
                                         limit=getattr(args, "limit", 200))
        elif verb == "bulk":
            from pathlib import Path as _Path
            from ..core.re import bulk as _bulk
            # The input is a CSV of `0x1130,name` lines. `-` reads stdin so a
            # rename list can be piped in from another tool without touching disk.
            csv_source = getattr(args, "pattern", None) or ""
            if not csv_source:
                return _out(args, {"ok": False, "error": "bulk needs --pattern <csv>"},
                            "error: bulk <path> --pattern renames.csv   "
                            "(0x1130,name per line, - for stdin)", code=2)
            if csv_source == "-":
                import sys as _sys
                csv_text = _sys.stdin.read()
            else:
                csv_file = _Path(csv_source)
                if not csv_file.is_file():
                    return _out(args, {"ok": False,
                                       "error": f"no such rename list: {csv_source}"},
                                f"error: no such rename list: {csv_source} "
                                f"(expected 0x1130,name per line, or - for stdin)", code=2)
                csv_text = csv_file.read_text(encoding="utf-8", errors="replace")
            res = _bulk.rename_from_csv(path, csv_text)
        elif verb == "strings":
            if getattr(args, "stack", False):
                dis_res = renative.disasm(path, count=10000)
                # Reconstruct raw disasm text from instructions
                tool = shutil.which("objdump")
                out_txt, _ = renative._run([tool, "-d", str(path)]) if tool else ("", False)
                res = {"ok": True, "path": str(path), "stack_strings": renative.extract_stack_strings(out_txt, min_len=getattr(args, "min_len", 4))}
            elif getattr(args, "xor", False):
                canon = renative.guard.read_guard(path)
                data = canon.read_bytes()
                res = {"ok": True, "path": str(path), "xor_strings": renative.extract_xor_strings(data, min_len=getattr(args, "min_len", 4))}
            else:
                res = elf.strings(path, min_len=getattr(args, "min_len", 4),
                                  limit=args.limit)
            # --grep was accepted by the parser and ignored by every strings branch, so a
            # filtered request returned the whole list. Apply it here, once, for all three
            # modes (plain, --stack, --xor).
            # The extractor returns distinct strings: a file with 83 printable runs and 79
            # distinct ones reports 79. Without a stated count, a user comparing against
            # `strings(1)` — which lists every occurrence — sees a disagreeing number and
            # no explanation. Say which it is.
            for key in ("strings", "stack_strings", "xor_strings"):
                items = res.get(key)
                if isinstance(items, list):
                    res["count"] = len(items)
            res["unique"] = True
            grep = (getattr(args, "grep", None) or "").strip().lower()
            if grep:
                for key in ("strings", "stack_strings", "xor_strings"):
                    items = res.get(key)
                    if not isinstance(items, list):
                        continue
                    kept = []
                    for item in items:
                        text = item.get("string", "") if isinstance(item, dict) else str(item)
                        if grep in str(text).lower():
                            kept.append(item)
                    res[key] = kept
                if isinstance(res.get("strings"), list):
                    res["count"] = len(res["strings"])
                res["grep"] = grep
        elif verb == "entropy":
            res = elf.entropy(path, block=getattr(args, "block", 0),
                              limit=getattr(args, "count", 32))
        elif verb == "pack":
            res = elf.pack(path)
        elif verb in ("ioc", "disasm", "graph"):
            if verb == "ioc":
                res = renative.ioc(path)
            elif verb == "disasm":
                res = renative.disasm(path, symbol=getattr(args, "symbol", None),
                                      start=getattr(args, "start", None),
                                      count=getattr(args, "count", 60),
                                      section=getattr(args, "section", None))
            else:
                res = renative.graph(path)
        elif verb == "pe":
            from ..core.re.pe import PEFile
            pe = PEFile(path)
            if pe_subverb == "info":
                res = {"ok": True, "path": str(path), **pe.info()}
            elif pe_subverb == "sections":
                res = {"ok": True, "path": str(path), "sections": pe.sections()}
            elif pe_subverb == "imports":
                res = {"ok": True, "path": str(path), "imports": pe.imports()}
            elif pe_subverb == "exports":
                res = {"ok": True, "path": str(path), "exports": pe.exports()}
            elif pe_subverb == "tls":
                res = {"ok": True, "path": str(path), **pe.tls()}
            elif pe_subverb == "resources":
                res = {"ok": True, "path": str(path), **pe.resources()}
            elif pe_subverb == "load-config":
                res = {"ok": True, "path": str(path), **pe.load_config()}
            elif pe_subverb == "certificates":
                res = {"ok": True, "path": str(path), **pe.certificates()}
            else:
                return _out(args, {"ok": False, "error": f"unknown PE subverb: {pe_subverb}"},
                            f"error: unknown PE subverb {pe_subverb}", code=2)
        elif verb == "cfg":
            from ..core.re import analysis
            rva_int = int(getattr(args, "rva", 0), 16) if getattr(args, "rva", None) else None
            res = analysis.build_cfg(
                path,
                symbol=getattr(args, "symbol", None),
                rva=rva_int,
                engine=getattr(args, "engine", "auto"),
                max_instructions=getattr(args, "max_instructions", 250),
            )
        elif verb == "block":
            from ..core.re import analysis
            rva_int = int(getattr(args, "rva", 0), 16) if getattr(args, "rva", None) else None
            block_id = getattr(args, "block_id", None) or getattr(args, "value", "") or "b_0"
            res = analysis.get_block(
                path,
                block_id=block_id,
                symbol=getattr(args, "symbol", None),
                rva=rva_int,
                engine=getattr(args, "engine", "auto"),
            )
        elif verb == "view":
            from ..core.re import analysis, companion
            rva_int = int(getattr(args, "rva", 0), 16) if getattr(args, "rva", None) else None
            info_res = renative.get_info(path)
            cfg_res = analysis.build_cfg(
                path,
                symbol=getattr(args, "symbol", None),
                rva=rva_int,
                engine=getattr(args, "engine", "auto"),
                max_instructions=getattr(args, "max_instructions", 250),
            )
            out_file = getattr(args, "out", None) or "re_companion.html"
            companion.render_html_companion(
                Path(path).name, info_res, cfg_res, out_path=out_file
            )
            res = {
                "ok": True,
                "path": str(path),
                "view_file": str(out_file),
                "symbol": cfg_res.get("symbol"),
                "blocks": len(cfg_res.get("blocks", [])),
            }
        elif verb == "xrefs":
            from ..core.re import analysis
            target_ref = (xref_target or getattr(args, "target", None)
                          or getattr(args, "symbol", None) or "")
            if not target_ref:
                # With no target the engine still returned 98 rows under the heading
                # "cross-references to :" — a list with no question behind it, which reads as
                # a successful search. Refuse and say what is missing.
                res = {"ok": False,
                       "error": "xrefs needs a target symbol or address",
                       "usage": "re xrefs <binary> <symbol-or-address>",
                       "hint": ("use `re symbols` to list candidates, or `re xrefs <binary> "
                                "0x<sender>` for an address")}
            else:
                res = analysis.find_xrefs(path, target_ref)
        elif verb == "checksec":
            res = renative.checksec(path)
            if not res.get("ok"):
                # `checksec` answered for ELF and PE only, so an iOS or macOS binary —
                # where these questions matter most — got a format complaint. Mach-O
                # hardening is answered from the header and the undefined symbols.
                from ..core.re import macho as _macho
                try:
                    res = _macho.checksec(path, arch=getattr(args, "arch", None) or "")
                except Exception:
                    from ..core.re import sources as _sources
                    res = _sources.unsupported("checksec", path, ("elf", "pe", "macho"))
        elif verb == "hooks":
            tool = shutil.which("objdump")
            out_txt, _ = renative._run([tool, "-d", str(path)], timeout=45) if tool else ("", False)
            res = {"ok": True, "path": str(path), **renative.scan_hooks_and_syscalls(out_txt)}
            # Constructors do not appear as calls in disassembly, so the scan above cannot see
            # them however thorough it is. They are read from the section table instead: an ELF
            # runs everything in `.init_array` before `main`, which is exactly where code that
            # wants to execute first hides.
            try:
                from ..core.re import elf as _elf
                ctors = _elf.constructors(path)
                if ctors.get("ok"):
                    res["constructors"] = ctors.get("constructors") or []
                    res["constructor_count"] = ctors.get("constructor_count", 0)
                    res["destructor_count"] = ctors.get("destructor_count", 0)
            except (OSError, ValueError, ImportError) as exc:
                res["constructors_error"] = str(exc)
        elif verb == "patch":
            from ..core.re.patch import apply_patch
            off_str = getattr(args, "offset", None)
            if not off_str:
                return _out(args, {"ok": False, "error": "patch requires --offset"}, "error: patch requires --offset", code=2)
            off = int(off_str, 16) if ("0x" in off_str or "0X" in off_str) else int(off_str)
            p_hex = getattr(args, "patch_bytes", None)
            if not p_hex:
                return _out(args, {"ok": False, "error": "patch requires --patch-bytes (hex string)"}, "error: patch requires --patch-bytes", code=2)
            pbytes = bytes.fromhex(p_hex.replace(" ", ""))
            obytes = bytes.fromhex(args.orig_bytes.replace(" ", "")) if getattr(args, "orig_bytes", None) else None
            # --confirm is accepted by the shared parser but patch is copy-only by
            # design: it never writes in place, so the flag could never mean anything.
            # Silently ignoring it invites "I confirmed and nothing changed", so say so.
            if getattr(args, "confirm", None):
                res = {"ok": False,
                       "error": "patch never modifies the input; it writes a copy. "
                                "Use --out to choose the destination instead of --confirm"}
                return _out(args, res, f"error: {res['error']}", code=2)
            res = apply_patch(path, offset=off, patch_bytes=pbytes, original_bytes=obytes, out_path=getattr(args, "out", None))
        elif verb == "rtti":
            from ..core.re.rtti import extract_rtti
            res = extract_rtti(path)
        elif verb == "diff":
            from ..core.re.diff import diff_binaries
            extra = getattr(args, "extra", [])
            bin2 = args.path or (extra[0] if extra else None)
            if not bin2:
                return _out(args, {"ok": False, "error": "diff requires two binary paths: xtforge re diff <bin1> <bin2>"}, "error: diff requires two binary paths", code=2)
            res = diff_binaries(path, bin2)
        elif verb == "capa":
            from ..core.re.capa import detect_capabilities
            res = detect_capabilities(path)
        elif verb == "crash":
            from ..core.re.crash import parse_crash
            res = parse_crash(path)
        elif verb == "annotate":
            from ..core.re.annotate import annotate
            # --target is the flag every other re verb uses for an address, while
            # annotate historically read --rva. Ignoring --target silently stored the
            # annotation at 0x0, so accept either and prefer an explicit --rva.
            target_rva = getattr(args, "rva", None)
            if not target_rva:
                target_rva = getattr(args, "target", None) or 0
            # Supplying --name/--comment/--type-decl without a subverb used to fall
            # through to "list" and write nothing at all. Infer the intent instead.
            inferred = ann_subverb
            if inferred == "list":
                if getattr(args, "name", None):
                    inferred = "rename"
                elif getattr(args, "comment", None):
                    inferred = "comment"
                elif getattr(args, "type_decl", None):
                    inferred = "type"
            res = annotate(
                action=inferred,
                binary=path,
                rva=target_rva or 0,
                name=getattr(args, "name", None) or "",
                orig=getattr(args, "orig", None) or "",
                comment=getattr(args, "comment", None) or "",
                type_decl=getattr(args, "type_decl", None) or "",
                confidence=float(getattr(args, "confidence", 1.0) or 1.0),
                fmt=getattr(args, "format", None) or "json",
            )
        elif verb in ("asar", "netcap", "apk", "dex", "decompile", "trace", "triage"):
            from ..core.re import runtimes as rt
            if verb == "asar":
                res = rt.inspect_asar(path, grep=getattr(args, "grep", None) or "", limit=args.limit)
            elif verb == "netcap":
                res = rt.inspect_netcap(path, reveal=bool(getattr(args, "reveal", False)), limit=args.limit)
            elif verb == "dex":
                # The hub does the reading; the Python module is the fallback for
                # builds without the native runtime, and both answer the same shape.
                from ..core.re import sysimage as _sys
                res = _sys._run("dex", str(path), None,
                                ["--limit", str(getattr(args, "limit", 40) or 40)])
                if not res.get("ok"):
                    from ..core.re import dex as _dexmod
                    res = _dexmod.inspect(str(path),
                                          class_filter=getattr(args, "symbol", "") or "")
            elif verb == "apk":
                res = rt.inspect_apk(path)
                # NOTE: the native hub answers `re apk` first, and it does the DEX
                # work (internal/rehub/dex.go). This branch is the Python fallback
                # for builds without the hub, so it enriches the same way rather than
                # drifting into a second, weaker answer.
                from ..core.re import dex as _dex
                _dex_names = [n for n in (res.get("dex_files") or [])
                              if isinstance(n, str) and n.endswith(".dex")] \
                    if res.get("ok") else []
                _dex_summary = []
                for _name in _dex_names[:8]:
                    _info = _dex.inspect_entry(path, _name)
                    if _info.get("ok"):
                        _dex_summary.append(_info)
                if _dex_summary:
                    res["dex_summary"] = _dex_summary
                    res["dex_totals"] = {
                        "classes": sum(d["counts"]["classes"] for d in _dex_summary),
                        "methods": sum(d["counts"]["methods"] for d in _dex_summary),
                    }
            elif verb == "decompile":
                res = rt.decompile(path, target=getattr(args, "symbol", None) or getattr(args, "target", None) or "main")
            elif verb == "triage":
                res = rt.triage_binary(path)
            else:
                res = rt.trace_binary(path, confirm=getattr(args, "confirm", None))
        elif verb in ("deep-elf", "anchors", "slice", "live-probe", "rbxm"):
            from ..core.re import sober_re
            if verb == "deep-elf":
                res = sober_re.inspect_elf_deep(path)
            elif verb == "anchors":
                queries = [q for q in ([getattr(args, "target", None), getattr(args, "symbol", None)] + list(getattr(args, "extra", []))) if q]
                res = sober_re.resolve_string_anchors(path, queries or ["bytecode"])
            elif verb == "slice":
                addr = getattr(args, "start", None) or getattr(args, "rva", None) or getattr(args, "target", None) or "0x0"
                res = sober_re.slice_disasm_window(path, addr)
            elif verb == "live-probe":
                res = sober_re.probe_live_process(int(path))
            else:
                res = sober_re.inspect_rbxm_container(path)
        elif verb == "ida":
            from ..core.re import ida as _ida
            sub = args.value or "status"
            target_path = args.path or (args.extra[0] if args.extra else "")
            sym = getattr(args, "symbol", None) or getattr(args, "target", None) or "main"
            flt = getattr(args, "filter", None) or getattr(args, "grep", None) or ""
            if sub == "status":
                res = _ida.ida_status()
            elif sub == "info":
                res = _ida.inspect_idb(target_path)
            elif sub == "functions":
                res = _ida.ida_functions(target_path, filter_str=flt, limit=args.limit)
            elif sub == "decompile":
                res = _ida.ida_decompile(target_path, sym)
            elif sub == "disasm":
                res = _ida.ida_disasm(target_path, sym)
            elif sub == "xrefs":
                res = _ida.ida_xrefs(target_path, sym)
            elif sub == "strings":
                res = _ida.ida_strings(target_path, filter_str=flt, limit=args.limit)
            elif sub == "structs":
                res = _ida.ida_structs(target_path)
            else:
                res = {"ok": False, "err": f"unknown ida subcommand: {sub}"}
        elif verb == "borer":
            from ..adapters.ghidra_mcp import STATE as _GSTATE
            # `re borer <binary> [sub]` — the binary is the argument people actually pass, and
            # the subcommand is optional. The original read `args.value` as the subcommand
            # unconditionally, so `re borer ./a.out` invoked `borer ./a.out ""` and failed with
            # an empty result while looking like the tool was broken. Decide by shape: a first
            # argument that is one of borer's own subcommands is a subcommand, anything else is
            # the target.
            extra = [str(x) for x in (getattr(args, "extra", []) or [])]
            first = (args.value or "").strip()
            second = (args.path or "").strip()
            if first in BORER_SUBCOMMANDS:
                sub, target_path = first, second
            else:
                sub, target_path = (second or "info"), first
                if second and second not in BORER_SUBCOMMANDS:
                    # `re borer <sub> <binary>` is still honoured when the second positional
                    # is clearly a path rather than a subcommand.
                    sub, target_path = first, second
            if not _GSTATE.borer_bin:
                res = {"ok": False, "err": "borer binary not found",
                       "hint": "install borer or set XT_BORER_BIN"}
            elif not target_path:
                res = {"ok": False, "err": "borer needs a binary path",
                       "usage": "xtforge re borer <binary> [subcommand]",
                       "subcommands": sorted(BORER_SUBCOMMANDS)}
            else:
                out = _GSTATE.run_borer_cli(sub, target_path, *extra)
                res = {"ok": bool(out), "subcommand": sub, "path": target_path,
                       "output": out or "", "engine": "borer"}
        else:
            return _out(args, {"ok": False, "error": f"unknown verb: {verb}"},
                        f"error: unknown verb {verb}", code=2)
    except (elf.ElfError, OSError, ValueError) as exc:
        return _out(args, {"ok": False, "error": str(exc)}, f"error: {exc}", code=1)

    if verb == "info":
        human = "\n".join(f"{k:<14} {v}" for k, v in res.items()
                          if not isinstance(v, (list, dict)))
    elif verb == "needed":
        human = "\n".join(res.get("needed", [])) or "(no shared libraries)"
    elif verb == "sections":
        secs = res.get("sections", [])
        if secs and "entropy" in secs[0]:
            human = "\n".join(
                f"{s.get('rva', ''):>10} {s['name']:<12} {s.get('raw_size', s.get('size', 0)):>8} bytes  entropy:{s['entropy']}"
                for s in secs
            )
        else:
            human = "\n".join(
                f"{s.get('index', 0):>3} {s.get('type', ''):<12} {s.get('size', 0):>10} "
                f"{s.get('flags', ''):<8} {s.get('name', '')}"
                for s in secs
            )
    elif verb == "symbols":
        syms = res.get("symbols", [])
        human = "\n".join(
            f"{s.get('value', s.get('rva', '')):>12} {s.get('type', s.get('kind', '')):<8} {s.get('bind', ''):<6} {s['name']}"
            for s in syms
        )
    elif verb == "strings":
        human = "\n".join(res.get("strings", []))
    elif verb == "search":
        rows = res.get("matches", [])
        human = "\n".join(
            f"{m['offset_hex']:>10}  {('va ' + m['va']) if m.get('va') else 'va -':<20} "
            f"{(m.get('section') or '-'):<14} {m['ascii']}"
            for m in rows
        ) or "(no matches)"
        if res.get("truncated"):
            human += f"\n(truncated: showing the first {res.get('count')})"
    elif verb == "elfmeta":
        notes = res.get("notes") or {}
        dwarf = res.get("dwarf") or {}
        unwind = res.get("unwind") or {}
        lines = [
            f"format          {res.get('format')} {res.get('bits')}-bit {res.get('endian')}",
            f"build-id        {notes.get('build_id') or '(none)'}",
            f"abi-tag         {notes.get('abi_tag') or '(none)'}",
            f"gnu-property    {bool(notes.get('gnu_property'))}",
            f"sections        {res.get('sections_reported', 0)}",
            f"compile units   {dwarf.get('count', 0)}",
        ]
        for unit in (dwarf.get("units") or [])[:20]:
            lines.append(f"  {unit.get('name') or '(unnamed)'}"
                         f"  low={unit.get('low_pc')}  high={unit.get('high_pc')}"
                         f"  producer={unit.get('producer') or '-'}")
        lines.append(f"unwind          {unwind.get('fde_count', 0)} FDE / "
                     f"{unwind.get('cie_count', 0)} CIE")
        debuglink = res.get("debuglink") or {}
        if debuglink.get("present"):
            lines.append(f"debuglink       {debuglink.get('file')} "
                         f"crc32 {debuglink.get('crc32')}")
        else:
            lines.append("debuglink       (none)")
        for warning in (dwarf.get("warnings") or [])[:10]:
            lines.append(f"warning         {warning}")
        human = "\n".join(lines)
    elif verb in ("goto", "nav", "resume", "bookmark", "step"):
        if not res.get("ok"):
            human = "nav: " + str(res.get("error", "unknown"))
        elif verb == "bookmark" and "bookmarks" in res:
            marks = res.get("bookmarks") or []
            human = (f"Bookmarks ({res.get('count')}):\n" if marks
                     else "Bookmarks: none recorded\n") + chr(10).join(
                f"    {m['name']:<24} {m['address']}" for m in marks)
        elif verb == "resume":
            lines = [f"Session resume  cursor {res.get('address') or '(none)'}"
                     f"  ({res.get('annotation_count')} annotations)"]
            if res.get("bookmarks"):
                lines.append("  bookmarks   " + ", ".join(
                    f"{m['name']}@{m['address']}" for m in res["bookmarks"][:8]))
            if res.get("trail"):
                lines.append("  trail       " + " <- ".join(res["trail"][:8]))
            lines.append(f"  resumable   {res.get('resumable')}")
            human = chr(10).join(lines)
        else:
            lines = [f"Cursor {res.get('address') or '(none)'}"]
            if res.get("previous"):
                lines.append(f"  previous    {res['previous']}")
            if res.get("direction"):
                lines.append(f"  direction   {res['direction']}")
            if res.get("note"):
                lines.append(f"  note        {res['note']}")
            human = chr(10).join(lines)
    elif verb in ("capture-diff", "capture-compare"):
        if not res.get("ok"):
            human = "capture diff: " + str(res.get("error", "unknown"))
        else:
            lines = [f"Capture diff ({res.get('endpoints_a')} -> "
                     f"{res.get('endpoints_b')} endpoints)",
                     f"  packets     {res.get('packets_a')} -> {res.get('packets_b')}"]
            if res.get("added_endpoints"):
                lines.append(f"  added       {len(res['added_endpoints'])}: "
                             + ", ".join(res["added_endpoints"][:8]))
            if res.get("removed_endpoints"):
                lines.append(f"  removed     {len(res['removed_endpoints'])}: "
                             + ", ".join(res["removed_endpoints"][:8]))
            if res.get("added_paths"):
                lines.append(f"  new paths   " + ", ".join(res["added_paths"][:6]))
            if res.get("removed_paths"):
                lines.append(f"  gone paths  " + ", ".join(res["removed_paths"][:6]))
            if not res.get("changed"):
                lines.append("  verdict     no change")
            human = chr(10).join(lines)
    elif verb == "correlate":
        if not res.get("ok"):
            human = "correlate: " + str(res.get("error", "unknown"))
        else:
            lines = [f"Static vs runtime ({res.get('static_hosts')} static hosts, "
                     f"{res.get('runtime_hosts')} observed)",
                     f"  correlated  {res.get('correlation_pct')}%"
                     f"  ({len(res.get('in_both') or [])} in both)"]
            if res.get("in_both"):
                lines.append("    both      " + ", ".join(res["in_both"][:8]))
            if res.get("static_only"):
                lines.append(f"  dormant     {res.get('static_only_count')}: "
                             + ", ".join(res["static_only"][:8]))
            if res.get("runtime_only"):
                lines.append(f"  runtime     {res.get('runtime_only_count')} unseen in "
                             f"strings: " + ", ".join(res["runtime_only"][:8]))
            for entry in (res.get("port_mismatches") or [])[:4]:
                lines.append(f"    port      {entry['host']} static {entry['static_port']}"
                             f" vs observed {entry['observed_port']}")
            human = chr(10).join(lines)
    elif verb in ("coverage", "recon-coverage", "evaluate-coverage"):
        if not res.get("ok"):
            human = "coverage: " + str(res.get("error", "unknown"))
        else:
            counts = res.get("counts") or {}
            lines = [f"Reconstruction coverage ({res.get('source_functions')} source "
                     f"functions, {res.get('binary_functions')} in the binary)",
                     f"  covered     {counts.get('covered', 0)}/{res.get('required')}"
                     f"  = {res.get('coverage_pct')}%",
                     f"  present     {res.get('present_pct')}%"
                     f"  (gap = work done but undocumented)"]
            if res.get("present_unrecorded"):
                lines.append(f"  unrecorded  {len(res['present_unrecorded'])}: "
                             + ", ".join(res["present_unrecorded"][:8]))
            if res.get("absent"):
                lines.append(f"  absent      {len(res['absent'])}: "
                             + ", ".join(res["absent"][:8]))
            if res.get("absent_expected"):
                lines.append(f"  inlined     {len(res['absent_expected'])} static "
                             f"(excluded from the denominator)")
            human = chr(10).join(lines)
    elif verb in ("api", "api-contract", "abi"):
        if not res.get("ok"):
            human = "api audit: " + str(res.get("error", "unknown"))
        else:
            tiers = res.get("tiers") or {}
            lines = [f"API contract ({res.get('export_count')} exports)",
                     f"  tiers       public {tiers.get('public', 0)}, "
                     f"risky {tiers.get('risky', 0)}, forbidden {tiers.get('forbidden', 0)}"]
            for entry in (res.get("findings") or [])[:12]:
                lines.append(f"    {entry['tier']:<10} {entry['name']}  ({entry['why']})")
            if res.get("baseline"):
                lines.append(f"  baseline    {res.get('baseline_export_count')} exports "
                             f"-> verdict {res.get('verdict')}")
                if res.get("added"):
                    lines.append(f"  added       {res['added_count']}: "
                                 + ", ".join(res["added"][:8]))
                if res.get("removed"):
                    lines.append(f"  removed     {res['removed_count']} "
                                 f"({res.get('breaking_removal_count', 0)} breaking): "
                                 + ", ".join(res["removed"][:8]))
                if res.get("changed"):
                    lines.append(f"  changed     {res['changed_count']}: "
                                 + ", ".join(c["name"] for c in res["changed"][:8]))
                if res.get("compatible"):
                    lines.append("  compatible  yes")
            human = chr(10).join(lines)
    elif verb in ("bundle-diff", "compare-bundles", "bundle-compare"):
        if not res.get("ok"):
            human = "bundle diff: " + str(res.get("error", "unknown"))
        else:
            lines = [f"Bundle diff ({res.get('kind_a')} vs {res.get('kind_b')})",
                     f"  entries     {res.get('entries_a')} vs {res.get('entries_b')}"
                     f"   unchanged {res.get('unchanged_count')}"]
            for label in ("added", "removed"):
                items = res.get(label) or []
                if items:
                    lines.append(f"  {label:<11} {len(items)}: " + ", ".join(items[:6]))
            if res.get("modified"):
                lines.append(f"  modified    {res['modified_count']}:")
                for entry in res["modified"][:10]:
                    extra_note = ""
                    if entry.get("first_diff_offsets_hex"):
                        extra_note = " at " + ", ".join(entry["first_diff_offsets_hex"][:4])
                    lines.append(f"    {entry['path']} ({entry['category']})"
                                 f"{extra_note}")
            if res.get("metadata_changes"):
                lines.append("  metadata    " + ", ".join(
                    f"{e['path']} {e['reason']}" for e in res["metadata_changes"][:5]))
            if res.get("identical"):
                lines.append("  verdict     identical")
            human = chr(10).join(lines)
    elif verb in ("fn-match", "fnmatch", "match-functions"):
        if not res.get("ok"):
            human = "fn-match: " + str(res.get("error", "unknown"))
        else:
            lines = [f"Function match ({res.get('mode_a')} vs {res.get('mode_b')}, "
                     f"threshold {res.get('threshold')})",
                     f"  matched     {res.get('match_count')} of "
                     f"{res.get('fingerprinted_a')}/{res.get('fingerprinted_b')} "
                     f"({res.get('renamed_count')} renamed)"]
            for match in (res.get("matches") or [])[:20]:
                flag = "renamed" if match["renamed"] else "same   "
                ev = match["evidence"]
                lines.append(f"    {match['score']:.2f} {flag} {match['function_a']}"
                             f" -> {match['function_b']}  "
                             f"blocks={ev['blocks']} insns={ev['instructions']}")
            if res.get("unmatched_a"):
                lines.append(f"  unmatched A {len(res['unmatched_a'])}: "
                             + ", ".join(res["unmatched_a"][:8]))
            if res.get("rejected_count"):
                lines.append(f"  rejected    {res['rejected_count']} pair(s) failed "
                             f"structural guards")
            human = chr(10).join(lines)
    elif verb in ("firmware-carve", "carve", "extract-firmware"):
        if not res.get("ok"):
            human = "firmware carve: " + str(res.get("error", "unknown"))
        else:
            lines = [f"Firmware carve ({res.get('file_size')} bytes, "
                     f"head entropy {res.get('entropy_head')})"]
            if res.get("formats_found"):
                lines.append("  formats     " + ", ".join(
                    f"{k} x{v}" for k, v in res["formats_found"].items()))
            for region in (res.get("regions") or [])[:25]:
                detail = []
                for key in ("version", "length", "size", "compression", "contains",
                            "decompressed_size", "inodes", "block_size", "machine"):
                    value = region.get(key)
                    if value not in (None, "", 0, False):
                        detail.append(f"{key}={value}")
                if region.get("crc_verified"):
                    detail.append("crc=ok")
                lines.append(f"    {region['format']:<10} at {region['offset_hex']:<12} "
                             + " ".join(detail))
            if res.get("rejected"):
                lines.append(f"  rejected    {res['rejected_count']} signature(s) "
                             f"failed validation")
                for entry in res["rejected"][:6]:
                    lines.append(f"    {entry['format']:<10} at 0x{entry['offset']:x} "
                                 f"{entry['reason']}")
            if res.get("note"):
                lines.append(f"  note        {res['note']}")
            if res.get("hint"):
                lines.append(f"  hint        {res['hint']}")
            human = "\n".join(lines)
    elif verb in ("app", "appgraph", "application-graph"):
        if not res.get("ok"):
            human = "application graph: " + str(res.get("error", "unknown"))
        else:
            lines = [f"Application graph ({', '.join(res.get('platforms') or [])}, "
                     f"{res.get('container')}, {res.get('entry_count', '?')} entries)"]
            manifest = res.get("manifest") or {}
            if manifest:
                lines.append(f"  package     {manifest.get('package')} "
                             f"v{manifest.get('version_name')} "
                             f"({manifest.get('version_code')})")
                lines.append(f"  sdk         min {manifest.get('min_sdk')} -> "
                             f"target {manifest.get('target_sdk')}")
                counts = manifest.get("component_counts") or {}
                lines.append("  components  " + ", ".join(
                    f"{k} {v}" for k, v in counts.items() if v) or "  components  -")
                for component in (manifest.get("components") or [])[:20]:
                    guard_flag = ""
                    if component.get("exported"):
                        guard_flag = (" EXPORTED"
                                      + (f" perm={component['permission']}"
                                         if component.get("permission") else " NO-PERMISSION"))
                    lines.append(f"    {component['kind']:<10} {component['name']}"
                                 f"{guard_flag}")
                for permission in (manifest.get("permissions") or [])[:15]:
                    lines.append(f"  permission  {permission}")
            if res.get("bundle_id"):
                lines.append(f"  bundle      {res.get('bundle_id')} "
                             f"({res.get('version')})")
            if res.get("dex_count") is not None:
                lines.append(f"  code        {res.get('dex_count')} dex, "
                             f"{res.get('native_library_count')} native libs "
                             f"[{', '.join(res.get('abis') or [])}]")
            if res.get("primary_runtime"):
                lines.append(f"  runtime     {res.get('primary_runtime')}")
            for flag in (res.get("risk_flags") or [])[:10]:
                lines.append(f"  RISK        {flag}")
            human = "\n".join(lines)
    elif verb in ("il2cpp", "il2cpp-metadata", "global-metadata"):
        if not res.get("ok"):
            human = "il2cpp metadata: " + str(res.get("error", "unknown"))
            if res.get("hint"):
                human += "\n  hint        " + res["hint"]
        else:
            lines = [f"il2cpp global-metadata (version {res.get('version')}, "
                     f"{res.get('file_size')} bytes)",
                     f"  header      {res.get('field_count')} fields, "
                     f"{res.get('header_size')} bytes",
                     f"  regions     {res.get('populated_region_count')} populated "
                     f"of {res.get('region_count')}"]
            for entry in res.get("regions") or []:
                if entry.get("empty"):
                    continue
                note = entry.get("content_note") or entry.get("size_field") or ""
                flag = ""
                if entry.get("inconsistent"):
                    flag = "  INCONSISTENT: " + entry["inconsistent"]
                elif entry.get("truncated"):
                    flag = f"  TRUNCATED by {entry['truncated']} bytes"
                lines.append(f"    {entry['region']:<28} @{entry['offset']:<9} "
                             f"{entry['size']:<9} {note}{flag}")
            if res.get("warning"):
                lines.append(f"  WARNING     {res['warning']}")
            human = "\n".join(lines)
    elif verb in ("dart", "dart-aot", "snapshot"):
        if not res.get("ok"):
            human = "dart snapshot: " + str(res.get("error", "unknown"))
            if res.get("hint"):
                human += "\n  hint        " + res["hint"]
        else:
            lines = [f"Dart AOT image ({res.get('container')}, "
                     f"{res.get('file_size')} bytes)"]
            snap = res.get("snapshot") or {}
            if snap:
                lines.append(f"  snapshot    {snap.get('kind')} at offset "
                             f"{snap.get('offset')}")
                lines.append(f"  length      {snap.get('declared_length')} bytes "
                             f"(total {snap.get('snapshot_size')})")
                if snap.get("truncated"):
                    lines.append(f"  WARNING     truncated: {snap.get('shortfall')} "
                                 f"bytes short")
                if snap.get("data_image_offset") is not None:
                    lines.append(f"  data image  offset {snap.get('data_image_offset')}"
                                 f", {snap.get('data_image_size')} bytes")
            if res.get("elf"):
                lines.append(f"  ELF         recovered from "
                             f"{res['elf'].get('recovered_from')}, "
                             f"{res['elf'].get('elf_size')} bytes")
            if res.get("png_chunks"):
                lines.append("  PNG chunks  " + ", ".join(
                    f"{c['type']}({c['size']})" for c in res["png_chunks"][:6]))
            if res.get("note"):
                lines.append(f"  note        {res['note']}")
            human = "\n".join(lines)
    elif verb in ("swift", "swift-types"):
        if not res.get("ok"):
            human = "swift metadata: " + str(res.get("error", "unknown"))
        else:
            lines = [f"Swift metadata ({res.get('format')}, "
                     f"{res.get('swift_section_count')} swift5 sections)",
                     f"  symbols     {res.get('symbol_count')} "
                     f"({res.get('demangled_count')} demangled, "
                     f"{res.get('undemangled_count')} unresolved)",
                     f"  modules     " + ", ".join(
                         f"{k} ({v})" for k, v in (res.get("modules") or {}).items()),
                     f"  types       {res.get('type_count')}"]
            for entry in (res.get("types") or [])[:30]:
                members = ", ".join(entry.get("members") or []) or "-"
                lines.append(f"    {entry['decl_kind'] or '?':<9} "
                             f"{entry['type']:<24} {members}")
            if res.get("reflection_strings"):
                lines.append("  reflect     " + ", ".join(
                    res["reflection_strings"][:14]))
            if res.get("symbol_roles"):
                lines.append("  roles       " + ", ".join(
                    f"{k} x{v}" for k, v in list(res["symbol_roles"].items())[:8]))
            human = "\n".join(lines)
    elif verb in ("ntfs", "ntfs-journal"):
        if not res.get("ok"):
            human = "ntfs volume: " + str(res.get("error", "unknown"))
        else:
            vol = res.get("volume") or {}
            lines = [f"NTFS volume (serial {vol.get('serial')}, "
                     f"{vol.get('volume_size')} bytes)",
                     f"  cluster     {vol.get('cluster_size')} bytes "
                     f"({vol.get('bytes_per_sector')} x "
                     f"{vol.get('sectors_per_cluster')})",
                     f"  MFT         cluster {vol.get('mft_cluster')} "
                     f"(offset {vol.get('mft_offset')})",
                     f"  records     {res.get('mft_record_count')} "
                     f"({res.get('in_use_count')} in use, "
                     f"{res.get('deleted_count')} deleted, "
                     f"{res.get('named_count')} named)"]
            log = res.get("logfile") or {}
            if log.get("present"):
                lines.append(f"  $LogFile    {log.get('log_size')} bytes at "
                             f"offset {log.get('log_offset')} "
                             f"({log.get('log_clusters')} clusters)")
                if log.get("restart_signature"):
                    lines.append(f"    restart   {log['restart_signature']} "
                                 f"({log.get('shutdown')}), "
                                 f"page {log.get('log_page_size')}")
                elif log.get("formatted_only"):
                    lines.append("    restart   none — the log holds no transactions "
                                 "(formatted, never written)")
                else:
                    lines.append("    restart   not decoded")
            for entry in (res.get("entries") or [])[:30]:
                kind = "dir " if entry.get("directory") else "file"
                lines.append(f"    rec {entry['record']:>3} {kind} "
                             f"{entry.get('name', '')}")
            human = "\n".join(lines)
    elif verb in ("firmware", "fv", "uefi-firmware") and not (
            res.get("volume") or res.get("files") or res.get("format")):
        # Two engines answer for firmware and they return different shapes: `firmware.inspect`
        # reports `format`/`volume`/`files`/`size`, `firmwarevolume.inspect_firmware_volume`
        # reports `volume_count`/`file_size`/`file_count`. This branch only knows the second, so
        # when it claimed the first its real data — 19 files in a 16 MB OVMF image — rendered as
        # "UEFI firmware image (None volume(s), None bytes)". Deferring on the presence of the
        # first shape's keys lets the later `firmware` branch, which was unreachable, render it.
        if not res.get("ok"):
            human = "firmware volume: " + str(res.get("error", "unknown"))
            if res.get("hint"):
                human += "\n  hint        " + res["hint"]
        else:
            vol = res.get("volume") or {}
            lines = [f"UEFI firmware image ({res.get('volume_count')} volume(s), "
                     f"{res.get('file_size')} bytes)",
                     f"  filesystem  {vol.get('file_system')}",
                     f"  revision    {vol.get('revision')}"]
            lines.append(f"  files       {res.get('file_count')} "
                         f"({res.get('top_level_count')} top-level, "
                         f"{res.get('named_count')} named)")
            if res.get("machines"):
                lines.append("  machines    " + ", ".join(
                    f"{k} x{v}" for k, v in res["machines"].items()))
            if res.get("type_counts"):
                counts = list(res["type_counts"].items())[:8]
                lines.append("  types       " + ", ".join(
                    f"{k} x{v}" for k, v in counts))
            for entry in (res.get("named_files") or [])[:25]:
                lines.append(f"    {entry['name']:<40} {entry['type']:<12} "
                             f"{entry['size']}")
            if len(res.get("named_files") or []) > 25:
                lines.append(f"    ... {len(res['named_files']) - 25} more")
            if res.get("warning"):
                lines.append(f"  WARNING     {res['warning']}")
            human = "\n".join(lines)
    elif verb in ("assetcatalog", "car"):
        if not res.get("ok"):
            human = "asset catalog: " + str(res.get("error", "unknown"))
        else:
            header = res.get("car_header") or {}
            lines = [f"Apple asset catalog ({res.get('container')} v{res.get('version')})",
                     f"  blocks      {res.get('occupied_blocks')} occupied, "
                     f"{res.get('empty_blocks')} empty "
                     f"(of {res.get('block_count')})"]
            if header.get("renderer"):
                lines.append(f"  renderer    {header['renderer']}")
            if header:
                lines.append(f"  coreui      {header.get('coreui_version')} "
                             f"(catalog format {header.get('version')}, "
                             f"{header.get('key_count')} keys)")
            for name, block in (res.get("named_blocks") or {}).items():
                tag = f" [{block.get('tag')}]" if block.get("tag") else ""
                size = block.get("size", 0)
                lines.append(f"    {name:<20} {size:>7} bytes"
                             + (" (empty)" if block.get("empty") else "") + tag)
            if res.get("rendition_count"):
                lines.append(f"  renditions  {res['rendition_count']}")
                for name in (res.get("renditions") or [])[:20]:
                    lines.append(f"    {name}")
            if res.get("rendition_note"):
                lines.append(f"  note        {res['rendition_note']}")
            human = "\n".join(lines)
    elif verb in ("unknowns", "obligations"):
        if not res.get("ok"):
            human = "obligation ledger: " + str(res.get("error", "unknown"))
        elif "topic" in res:
            human = f"{res.get('state')}: {res.get('topic')}"
            if res.get("resolution"):
                human += f"\n  resolved by  {res['resolution']}"
            elif res.get("reason"):
                human += f"\n  reason       {res['reason']}"
        else:
            counts = res.get("counts") or {}
            lines = [f"{res.get('count', 0)} obligation(s): "
                     f"{counts.get('open', 0)} open, "
                     f"{counts.get('waived', 0)} waived, "
                     f"{counts.get('resolved', 0)} resolved"]
            if res.get("clean"):
                lines.append("  no open obligations — nothing outstanding")
            for entry in res.get("entries") or []:
                detail = entry.get("resolution") or entry.get("reason") or ""
                lines.append(f"  [{entry.get('state'):<8}] {entry.get('topic')}"
                             + (f"  — {detail}" if detail else ""))
            human = "\n".join(lines)
    elif verb in ("v8cache", "codecache"):
        if not res.get("ok"):
            human = "v8 code cache: " + str(res.get("error", "unknown"))
        elif res.get("kind") == "v8-code-cache-directory":
            lines = [f"{res.get('cache_count', 0)} code cache(s) across "
                     f"{res.get('distinct_builds', 0)} V8 build(s)"]
            for build, count in (res.get("builds") or {}).items():
                lines.append(f"  build {build}   {count} cache(s)")
            if res.get("flag_sets"):
                for flags, count in res["flag_sets"].items():
                    lines.append(f"  flags {flags}   {count} cache(s)")
            lines.append(f"  sources matched  {res.get('sources_matched', 0)}")
            human = "\n".join(lines)
        else:
            lines = [f"V8 code cache ({res.get('file_size')} bytes)",
                     f"  build       {res.get('v8_build_fingerprint')}",
                     f"  source size {res.get('source_size')}",
                     f"  source hash {res.get('source_hash')}"
                     + (" (not recomputed)" if not res.get("source_hash_verified")
                        else ""),
                     f"  flags       {res.get('flags')}"
                     + (f" ({', '.join(res['flag_names'])})"
                        if res.get("flag_names") else ""),
                     f"  payload     {res.get('payload_length')} byte(s)"]
            if res.get("source"):
                lines.append(f"  source      {res['source']}")
            if res.get("truncated"):
                lines.append(f"  WARNING     {res.get('warning')}")
            human = "\n".join(lines)
    elif verb in ("dex-classes", "dex-search"):
        if not res.get("ok"):
            human = "dex-search: " + str(res.get("error", "unknown"))
        else:
            lines = [f"{res.get('path')}  pattern {res.get('pattern')!r}",
                     f"  {res.get('match_count')} match(es) across {res.get('dex_entries')} "
                     f".dex entr(ies), {res.get('classes_scanned')} classes scanned"]
            for item in (res.get("matches") or [])[:24]:
                if item.get("error"):
                    lines.append(f"    ! {item.get('entry')}: {item['error']}")
                else:
                    lines.append(f"    {str(item.get('name'))[:56]:<56} "
                                 f"{item.get('superclass') or ''}")
            human = chr(10).join(lines)
    elif verb in ("dex-refs", "dex-trace"):
        if not res.get("ok"):
            human = "dex-refs: " + str(res.get("error", "unknown"))
        else:
            lines = [f"{res.get('path')}  symbol {res.get('symbol')!r}",
                     f"  {res.get('reference_count')} reference(s) in "
                     f"{res.get('dex_entries')} .dex entr(ies)"]
            for item in (res.get("references") or [])[:24]:
                lines.append(f"    {item.get('kind'):<7} {str(item.get('class'))[:40]:<40}"
                             f" {item.get('name')}")
            human = chr(10).join(lines)
    elif verb in ("hap", "harmony"):
        human = _render_hap(res)
    elif verb in ("model", "model-artifact", "gguf", "safetensors"):
        human = _render_model(res)
    elif verb in ("gdb", "gdbmi"):
        human = _render_gdb(res)
    elif verb == "ptrace":
        human = _render_ptrace(res)
    elif verb in ("playwright", "trace"):
        if not res.get("ok"):
            human = "playwright trace: " + str(res.get("error", "unknown"))
        else:
            browser = res.get("browser") or "?"
            lines = [f"playwright trace v{res.get('version')} ({browser})"
                     + (f" — {res['title']}" if res.get("title") else "")]
            lines.append(f"  events      {res.get('event_count')} "
                         f"({res.get('unparsed_lines')} unparsed line(s))")
            if res.get("duration_ms"):
                lines.append(f"  duration    {res['duration_ms']} ms")
            lines.append(f"  actions     {res.get('action_count')}")
            for action in (res.get("actions") or [])[:25]:
                target = (action.get("url") or action.get("selector")
                          or action.get("expression") or "")
                duration = action.get("duration_ms")
                lines.append(f"    {action.get('api')}"
                             + (f"  {str(target)[:60]}" if target else "")
                             + (f"  {duration} ms" if duration is not None else ""))
            if res.get("failure_count"):
                lines.append(f"  FAILURES    {res['failure_count']}")
                for failure in res["failures"][:10]:
                    lines.append(f"    {failure.get('api')}: "
                                 f"{str(failure.get('message'))[:100]}")
            if res.get("console_count"):
                lines.append(f"  console     {res['console_count']} message(s)")
                for entry in res["console"][:10]:
                    lines.append(f"    [{entry.get('level')}] "
                                 f"{str(entry.get('message'))[:100]}")
            if res.get("network_count"):
                lines.append(f"  network     {res['network_count']} request(s)")
                for request in res["network"][:10]:
                    lines.append(f"    {request.get('status') or '?'} "
                                 f"{request.get('url')}")
            if res.get("snapshot_count"):
                lines.append(f"  snapshots   {res['snapshot_count']} frame(s), "
                             f"{res.get('screenshot_count')} image(s)")
            human = "\n".join(lines)
    elif verb in ("objc", "objc-classes", "objc-protocols"):
        if not res.get("ok"):
            human = "objective-c: " + str(res.get("error", "unknown"))
        elif not res.get("has_objc"):
            human = res.get("hint") or "no Objective-C metadata"
        else:
            lines = [f"{res.get('class_count', 0)} class(es), "
                     f"{res.get('protocol_count', 0)} protocol(s)"]
            for image in res.get("images") or []:
                for cls in (image.get("classes") or [])[:40]:
                    parent = f" : {cls['superclass']}" if cls.get("superclass") else ""
                    lines.append(f"  {cls.get('name')}{parent}")
                    if cls.get("protocols"):
                        lines.append(f"     conforms   {', '.join(cls['protocols'])}")
                    for method in (cls.get("methods") or [])[:15]:
                        types = method.get("types") or ""
                        lines.append(f"     -{method.get('name')}"
                                     + (f"  {types}" if types else ""))
                    for method in (cls.get("class_methods") or [])[:10]:
                        types = method.get("types") or ""
                        lines.append(f"     +{method.get('name')}"
                                     + (f"  {types}" if types else ""))
                for proto in (image.get("protocols") or [])[:20]:
                    lines.append(f"  @protocol {proto.get('name')}")
                    for method in (proto.get("instance_methods") or [])[:10]:
                        types = method.get("types") or ""
                        lines.append(f"     -{method.get('name')}"
                                     + (f"  {types}" if types else ""))
                for cat in image.get("categories") or []:
                    lines.append(f"  @category {cat.get('class')}"
                                 f"({cat.get('name')})")
            human = "\n".join(lines)
    elif verb in ("keyed", "keyed-archive"):
        if not res.get("ok"):
            human = "keyed archive: " + str(res.get("error", "unknown"))
        else:
            lines = [f"NSKeyedArchiver {res.get('archiver')} "
                     f"({res.get('format')}, {res.get('object_count')} objects, "
                     f"{res.get('class_count')} classes)",
                     f"  classes     {', '.join(res.get('classes') or []) or '-'}",
                     f"  roots       {', '.join(res.get('root_names') or []) or '-'}"]
            for name, value in (res.get("roots") or {}).items():
                lines.append(f"  {name}:")
                lines.extend(_flatten_graph(value, 1))
            human = "\n".join(lines)
    elif verb in ("jvm", "maven", "nuget"):
        if not res.get("ok"):
            human = "build metadata: " + str(res.get("error", "unknown"))
        else:
            coords = res.get("coordinates") or {}
            label = coords.get("id") or ":".join(
                str(x) for x in (coords.get("group"), coords.get("module")
                                 or coords.get("artifact"), coords.get("version")) if x)
            lines = [f"{res.get('kind')} metadata: {label or '(no coordinates)'}"]
            if res.get("parent"):
                parent = res["parent"]
                lines.append(f"  parent      {parent.get('group')}:"
                             f"{parent.get('artifact')}:{parent.get('version')}")
            if coords.get("packaging"):
                lines.append(f"  packaging   {coords['packaging']}")
            lines.append(f"  deps        {res.get('dependency_count', 0)}")
            for dep in (res.get("dependencies") or [])[:20]:
                ident = dep.get("id") or ":".join(
                    str(x) for x in (dep.get("group"), dep.get("module")
                                     or dep.get("artifact")) if x)
                version = dep.get("version") or "(managed)"
                scope = dep.get("scope") or ""
                lines.append(f"    {ident} {version} {scope}".rstrip())
            if res.get("plugins"):
                lines.append(f"  plugins     {len(res['plugins'])}")
                for plugin in res["plugins"][:10]:
                    lines.append(f"    {plugin.get('group')}:{plugin.get('artifact')} "
                                 f"{plugin.get('version') or ''}".rstrip())
            for repo in (res.get("custom_repositories") or []):
                lines.append(f"  REPO        {repo.get('id')} {repo.get('url')}")
            human = "\n".join(lines)
    elif verb in ("appbundle", "bundle"):
        if not res.get("ok"):
            human = "app bundle: " + str(res.get("error", "unknown"))
        else:
            lines = [f"{res.get('display_name') or res.get('name') or '?'} "
                     f"{res.get('version') or ''} ({res.get('build') or '?'})".rstrip(),
                     f"  id          {res.get('identifier')}",
                     f"  plist       {res.get('plist_format')}",
                     f"  executable  {res.get('executable') or '(missing)'}"
                     + (f"  {res.get('executable_size')} bytes"
                        if res.get("executable_size") else "")]
            if res.get("minimum_system"):
                lines.append(f"  min os      {res['minimum_system']}")
            for scheme in (res.get("url_schemes") or [])[:10]:
                lines.append(f"  url scheme  {scheme['scheme']}")
            for doc in (res.get("document_types") or [])[:6]:
                lines.append(f"  doc type    {doc.get('name')} "
                             f"({', '.join(doc.get('extensions') or []) or '-'})")
            if res.get("nested_components"):
                lines.append(f"  nested      {', '.join(res['nested_components'][:6])}")
            human = "\n".join(lines)
    elif verb in ("uefi", "nvram"):
        if not res.get("ok"):
            human = "uefi variables: " + str(res.get("error", "unknown"))
        elif "variable_count" in res:
            lines = [f"uefi variables ({res.get('readable_count')} readable, "
                     f"{res.get('unreadable_count')} unreadable)",
                     f"  assessment  {res.get('assessment')}"]
            if res.get("boot_order"):
                lines.append(f"  boot order  {', '.join(res['boot_order'])}")
            for entry in (res.get("boot_entries") or [])[:12]:
                detail = entry.get("boot_entry") or {}
                text = detail.get("description") or "?"
                suffix = ""
                if detail.get("device_path_nodes"):
                    suffix = "  [" + " -> ".join(
                        node["name"] for node in detail["device_path_nodes"]
                        if node["name"] != "End") + "]"
                lines.append(f"    {entry['name']}  {text}{suffix}")
            security = res.get("security") or {}
            if security:
                lines.append(f"  security    {', '.join(sorted(security))}")
            human = "\n".join(lines)
        else:
            lines = [f"uefi variable {res.get('name')}",
                     f"  guid        {res.get('guid')}",
                     f"  attributes  {res.get('attributes')} "
                     f"{', '.join(res.get('attribute_names') or [])}"]
            if res.get("significance"):
                lines.append(f"  meaning     {res['significance']}")
            if "secure_boot_enabled" in res:
                lines.append(f"  enabled     {res['secure_boot_enabled']}")
            if res.get("boot_entry"):
                detail = res["boot_entry"]
                lines.append(f"  entry       {detail.get('description')} "
                             f"({detail.get('device_path_length')} byte path)")
            human = "\n".join(lines)
    elif verb == "sqlite":
        if not res.get("ok"):
            human = "sqlite: " + str(res.get("error", "unknown"))
        else:
            lines = [f"sqlite database ({res.get('page_size')} byte pages, "
                     f"{res.get('text_encoding')})",
                     f"  pages       {res.get('declared_pages')} declared, "
                     f"{res.get('actual_size')} bytes on disk"]
            if res.get("truncated"):
                lines.append(f"  TRUNCATED   {res.get('truncated_by')} bytes short")
            lines.append(f"  schema      format {res.get('schema_format')}, "
                         f"cookie {res.get('schema_cookie')}")
            if res.get("journals"):
                for journal in res["journals"]:
                    lines.append(f"  journal     {journal['name']} "
                                 f"({journal['size']} bytes) — write was in flight")
            lines.append(f"  objects     {res.get('object_count')}")
            for obj in (res.get("objects") or [])[:25]:
                lines.append(f"    {obj['type']:<7} {obj['name']}")
            human = "\n".join(lines)
    elif verb == "beam":
        if not res.get("ok"):
            human = "beam: " + str(res.get("error", "unknown"))
        else:
            lines = [f"beam module {res.get('module') or '(unnamed)'}",
                     f"  compiler    {res.get('compiler_version') or '-'}",
                     f"  chunks      {res.get('chunk_count')}"]
            for source in (res.get("source_paths") or [])[:5]:
                lines.append(f"  source      {source}")
            lines.append(f"  exports     {res.get('export_count', 0)}")
            for export in (res.get("exports") or [])[:25]:
                lines.append(f"    {export['function']}/{export['arity']}")
            human = "\n".join(lines)
    elif verb == "evm":
        if not res.get("ok"):
            human = "evm: " + str(res.get("error", "unknown"))
        else:
            lines = [f"evm bytecode ({res.get('input_form')}, "
                     f"{res.get('bytecode_size')} bytes, "
                     f"{res.get('instruction_count')} instructions)",
                     f"  selectors   {res.get('selector_count')}"]
            for selector in (res.get("selectors") or [])[:25]:
                lines.append(f"    {selector}")
            top = list((res.get("opcodes") or {}).items())[:8]
            if top:
                lines.append("  opcodes     "
                             + ", ".join(f"{name}x{count}" for name, count in top))
            human = "\n".join(lines)
    elif verb == "ips":
        if not res.get("ok"):
            human = "apple ips: " + str(res.get("error", "unknown"))
        else:
            lines = [f"apple {res.get('report_kind')} report (bug_type "
                     f"{res.get('bug_type')})",
                     f"  app         {res.get('app_name')} {res.get('app_version') or ''}".rstrip(),
                     f"  os          {res.get('os_version')}",
                     f"  captured    {res.get('timestamp')}"]
            exception = res.get("exception") or {}
            if exception:
                lines.append(f"  exception   {exception.get('type')} "
                             f"{exception.get('signal') or ''} "
                             f"{exception.get('subtype') or ''}".rstrip())
            if res.get("faulting_thread") is not None:
                lines.append(f"  faulting    thread {res['faulting_thread']}, "
                             f"{res.get('faulting_frames')} frames")
            for frame in (res.get("top_frames") or [])[:12]:
                lines.append(f"    {frame.get('image') or '-'}  "
                             f"{frame.get('symbol') or '?'} + {frame.get('offset')}")
            human = "\n".join(lines)
    elif verb == "devicetree":
        if not res.get("ok"):
            human = "devicetree: " + str(res.get("error", "unknown"))
        else:
            lines = [f"devicetree v{res.get('version')} "
                     f"({res.get('node_count')} nodes, {res.get('property_count')} properties, "
                     f"depth {res.get('max_depth')})"]
            if res.get("embedded"):
                lines.append(f"  embedded at offset 0x{res['header_offset']:x}")
            if res.get("model"):
                model = res["model"]
                lines.append(f"  model       {model if isinstance(model, str) else model[0]}")
            compat = res.get("compatible")
            if compat:
                text = compat if isinstance(compat, str) else ", ".join(compat)
                lines.append(f"  compatible  {text}")
            lines.append(f"  size        {res.get('total_size')} bytes")
            for node in (res.get("nodes") or [])[:25]:
                indent = "  " * (node["depth"] + 1)
                lines.append(f"{indent}{node['name']}"
                             + (f"@{node['unit_address']}" if node.get("unit_address") else ""))
            human = "\n".join(lines)
    elif verb == "kconfig":
        if not res.get("ok"):
            human = "kernel config: " + str(res.get("error", "unknown"))
        else:
            lines = [f"kernel config ({res.get('source')})"]
            if res.get("version"):
                lines.append(f"  localversion  {res['version']}")
            lines.append(f"  enabled       {res.get('enabled_count')}")
            lines.append(f"  modules       {res.get('module_count')}")
            lines.append(f"  disabled      {res.get('disabled_count')}")
            for key, value in (res.get("settings") or {}).items():
                lines.append(f"  {key:<36} {value}")
            human = "\n".join(lines)
    elif verb == "lnk":
        if not res.get("ok"):
            human = "shortcut: " + str(res.get("error", "unknown"))
        else:
            lines = ["windows shortcut",
                     f"  command     {res.get('command')}"]
            if res.get("working_directory"):
                lines.append(f"  workdir     {res['working_directory']}")
            if res.get("relative_path"):
                lines.append(f"  relative    {res['relative_path']}")
            vol = res.get("volume") or {}
            if vol:
                lines.append(f"  volume      {vol.get('drive_type')} "
                             f"serial {vol.get('serial')}")
            lines.append(f"  show        {res.get('show_command')}")
            lines.append(f"  flags       {', '.join(res.get('flag_names') or [])}")
            human = "\n".join(lines)
    elif verb == "formats":
        _fmt_a = args.value if args.value in (
            "plist", "pyc", "desktop", "go", "rust") else "inspect"
        if not res.get("ok"):
            human = (f"{_fmt_a}: " + str(res.get("error", "unknown"))
                     + (f" (detected: {res.get('format_detected')})"
                        if res.get("format_detected") else ""))
        elif "shape" in res:
            lines = [f"plist ({res.get('format_detected')}, {res.get('shape')}, "
                     f"{res.get('key_count', 0)} key(s))"]
            lines.extend(f"  {k}" for k in (res.get("keys") or [])[:40])
            human = "\n".join(lines)
        elif "magic" in res:
            lines = [f"pyc {res.get('magic')} -> Python {res.get('python_version_guess')}"
                     f" ({'hash-based' if res.get('hash_based') else 'timestamp'})"]
            if res.get("source_hash"):
                lines.append(f"  source hash   {res['source_hash']}")
            if res.get("source_timestamp"):
                lines.append(f"  source mtime  {res['source_timestamp']}")
            lines.append(f"  code payload  {res.get('code_payload_bytes')} bytes")
            human = "\n".join(lines)
        elif "exec" in res:
            lines = [f"desktop entry: {res.get('name')} ({res.get('type')})",
                     f"  command     {res.get('command')}"]
            if res.get("arguments"):
                lines.append(f"  arguments   {' '.join(res['arguments'])}")
            if res.get("field_codes"):
                lines.append(f"  field codes {', '.join(res['field_codes'])}")
            if res.get("categories"):
                lines.append(f"  categories  {', '.join(res['categories'])}")
            human = "\n".join(lines)
        elif "build_settings" in res:
            lines = [f"go binary: {res.get('version')}",
                     f"  module      {res.get('module')}"]
            if res.get("goos"):
                lines.append(f"  target      {res.get('goos')}/{res.get('goarch')}")
            if res.get("vcs_revision"):
                lines.append(f"  vcs         {res['vcs_revision'][:12]}")
            lines.append(f"  deps        {res.get('dependency_count', 0)}")
            human = "\n".join(lines)
        else:
            lines = [f"rust markers ({len(res.get('markers') or [])})"]
            if res.get("rustc_commit"):
                lines.append(f"  rustc       {res['rustc_commit'][:12]}")
            lines.append(f"  crates      {res.get('crate_candidate_count', 0)} candidate(s)")
            human = "\n".join(lines)
    elif verb == "managed":
        # Same positional rules as the dispatcher: the action is in args.value.
        _managed_actions = ("artifact", "members", "boundaries")
        action = args.value if args.value in _managed_actions else "artifact"
        if not res.get("ok"):
            human = "not a managed assembly: " + str(res.get("error", "unknown"))
        elif action == "artifact":
            asm = res.get("assembly") or {}
            lines = [f"managed assembly ({res.get('pe_magic')}, "
                     f"runtime {res.get('runtime_version')})"]
            if asm:
                lines.append(f"  name      {asm.get('name')}")
                lines.append(f"  version   {asm.get('version')}")
                lines.append(f"  culture   {asm.get('culture') or '(none)'}")
            else:
                lines.append(f"  {res.get('warning', 'no assembly table')}")
            lines.append(f"  module    {res.get('module')}")
            lines.append(f"  flags     {', '.join(res.get('flags_decoded') or []) or 'none'}")
            entry = res.get("entry_point") or {}
            if entry:
                lines.append(f"  entry     {entry.get('token')} "
                             f"({entry.get('table')} rid {entry.get('rid')})")
            counts = res.get("table_counts") or {}
            lines.append(f"  types     {counts.get('TypeDef', 0)}")
            lines.append(f"  methods   {counts.get('MethodDef', 0)}")
            lines.append(f"  refs      {len(res.get('references') or [])}")
            human = "\n".join(lines)
        elif action == "members":
            lines = [f"{res.get('type_count', 0)} types, "
                     f"{res.get('method_count', 0)} methods"]
            for type_row in (res.get("types") or [])[:40]:
                lines.append(f"  {type_row.get('full_name')}")
                for m in (type_row.get("methods") or [])[:20]:
                    lines.append(f"     {str(m.get('name')):<28} {m.get('access')}")
                    body = m.get("body") or {}
                    if body:
                        extra = [f"{body.get('format')} body",
                                 f"{body.get('code_size')} bytes",
                                 f"stack {body.get('max_stack')}"]
                        if body.get("locals"):
                            extra.append("locals")
                        if body.get("exception_handlers"):
                            extra.append("try/catch")
                        lines.append(f"        {' · '.join(extra)}")
            human = "\n".join(lines)
        else:
            lines = [f"{res.get('pinvoke_count', 0)} P/Invoke(s) across "
                     f"{len(res.get('dlls') or [])} DLL(s)"]
            for p_row in (res.get("pinvokes") or [])[:30]:
                lines.append(f"  {p_row.get('dll')}!{p_row.get('import_name')}"
                             f"  -> {p_row.get('managed_method')}")
            human = "\n".join(lines)
    elif verb == "wasm" and ("interface_identical" in res or "left_error" in res
                             or "right_error" in res):
        if not res.get("ok"):
            # A failed comparison has no `interface_identical`, and gating on that key sent it to
            # the single-module renderer, which printed "format None version None size None" —
            # a table of nulls where the reason belonged. The error names which side failed.
            lines = ["wasm compare: " + str(res.get("error", "unknown"))]
            for side in ("left_error", "right_error"):
                if res.get(side):
                    lines.append(f"  {side.split('_')[0]:<6} {res[side]}")
            human = "\n".join(lines)
        else:
            left, right = res["left"], res["right"]
            lines = [f"wasm interface: {res['summary']}",
                     f"  left   {left['path']} ({left['exports']} exports, "
                     f"{left['imports']} imports)",
                     f"  right  {right['path']} ({right['exports']} exports, "
                     f"{right['imports']} imports)"]
            for name in res.get("exports_added") or []:
                lines.append(f"  + {name}")
            for name in res.get("exports_removed") or []:
                lines.append(f"  - {name}")
            for change in res.get("exports_kind_changed") or []:
                lines.append(f"  ~ {change['name']}: {change['left_kind']} -> "
                             f"{change['right_kind']}")
            human = "\n".join(lines)
    elif verb == "wasm":
        counts = res.get("counts") or {}
        lines = [f"format          {res.get('format')} version {res.get('version')}"
                 f"  size {res.get('size')}",
                 "counts          " + "  ".join(f"{k}={v}" for k, v in counts.items())]
        for sec in (res.get("sections") or [])[:20]:
            lines.append(f"  section {sec.get('id'):>2} {sec.get('name'):<12}"
                         f" off={sec.get('offset')} size={sec.get('size')}")
        for imp in (res.get("imports") or [])[:20]:
            lines.append(f"  import  {imp.get('module')}.{imp.get('name')} ({imp.get('kind')})")
        for exp in (res.get("exports") or [])[:20]:
            lines.append(f"  export  {exp.get('name')} ({exp.get('kind')}, index {exp.get('index')})")
        if res.get("truncated"):
            lines.append("(truncated)")
        human = "\n".join(lines)
    elif verb == "firmware":
        volume = res.get("volume") or {}
        lines = [f"format          {res.get('format')}  size {res.get('size')}"]
        if volume:
            lines += [
                f"fs-guid         {volume.get('fs_guid')}",
                f"length          {volume.get('length')}"
                f" (matches file: {volume.get('reported_length_matches_file')})",
                f"header-length   {volume.get('header_length')}",
                f"revision        {volume.get('revision')}",
                f"checksum        {'ok' if volume.get('checksum_ok') else 'MISMATCH'}",
            ]
        for entry in (res.get("files") or [])[:40]:
            lines.append(f"  [{entry.get('index'):>3}] {entry.get('guid')}  "
                         f"{entry.get('type_name'):<18} {entry.get('size'):>8} bytes")
        for note in (res.get("notes") or [])[:10]:
            lines.append(f"note            {note}")
        if res.get("truncated"):
            lines.append("(truncated)")
        human = "\n".join(lines)
    elif verb == "bookmarks":
        rows = res.get("bookmarks") or []
        if bm_subverb in ("next", "prev"):
            one = res.get("bookmark")
            human = (f"{one['rva']}  {one.get('label') or '(no label)'}  {one.get('note') or ''}"
                     if one else "(no bookmark in that direction)")
        elif bm_subverb in ("set", "unset"):
            if bm_subverb == "unset":
                human = f"{res.get('rva')}  removed={bool(res.get('removed'))}"
            else:
                human = f"{res.get('rva')}  saved  {res.get('label') or '(no label)'}"
        else:
            human = "\n".join(
                f"{b['rva']:>12}  {(b.get('label') or '(no label)'):<28} {b.get('note') or ''}"
                for b in rows) or "(no bookmarks)"
            if res.get("truncated"):
                human += f"\n(truncated: showing the first {res.get('count')}; use --target to page)"
    elif verb == "bulk":
        applied = res.get("applied") or []
        human = (f"{res.get('count', 0)} renames applied\n"
                 + "\n".join(f"  {a['rva']:>12}  {a['name']}" for a in applied[:50])) \
            if applied else "0 renames applied"
    elif verb == "pe":
        if pe_subverb == "info":
            human = "\n".join(f"{k:<16} {v}" for k, v in res.items() if not isinstance(v, (list, dict)))
        elif pe_subverb == "sections":
            human = "\n".join(
                f"{s['rva']:>10}  {s['name']:<12}  {s['raw_size']:>8} bytes  entropy:{s['entropy']}"
                for s in res.get("sections", [])
            )
        elif pe_subverb == "imports":
            lines = []
            for imp in res.get("imports", []):
                lines.append(f"{imp['dll']}:")
                lines.extend(f"  {fn}" for fn in imp.get("functions", [])[:8])
            human = "\n".join(lines)
        elif pe_subverb == "exports":
            human = "\n".join(
                f"{exp['rva']:>10}  ord:{exp.get('ordinal', 0):<4}  {exp['name']}"
                for exp in res.get("exports", [])
            )
        elif pe_subverb == "load-config":
            fields = res.get("fields") or {}
            mit = res.get("mitigations") or {}
            if not res.get("present"):
                human = "no load config: " + "; ".join(res.get("warnings") or [])
            else:
                lines = [f"load config ({res.get('size', 0)} bytes, "
                         f"guard_flags {res.get('guard_flags', 'n/a')})"]
                for name, label in (("security_cookie", "GS cookie"),
                                    ("se_handler_table", "SEH table"),
                                    ("guard_cf_check_function", "CFG check"),
                                    ("guard_cf_function_table", "CFG table"),
                                    ("guard_cf_function_count", "CFG entries")):
                    if name in fields:
                        lines.append(f"  {label:<14} 0x{fields[name]:x}")
                for name, value in mit.items():
                    state = "not applicable" if value is None else ("yes" if value else "no")
                    lines.append(f"  {name:<22} {state}")
                lines.extend(f"  warning: {w}" for w in (res.get("warnings") or []))
                human = "\n".join(lines)
        elif pe_subverb == "certificates":
            if not res.get("signed"):
                human = "unsigned: " + "; ".join(res.get("warnings") or [])
            else:
                lines = [f"{len(res['certificates'])} certificate entr(y/ies)"]
                for c in res["certificates"]:
                    lines.append(f"  {c['type_name']:<18} rev {c['revision_name']:<5} "
                                 f"{c['payload_size']:>6} bytes  {c['encoding']} "
                                 f"@0x{c['offset']:x}")
                human = "\n".join(lines)
        elif pe_subverb == "resources":
            rows = res.get("entries", [])
            lines = [f"{res.get('count', 0)} resource(s): "
                     + (", ".join(res.get("types") or []) or "none")]
            for e in rows:
                size = e.get("size") or 0
                offset = e.get("offset")
                where = f"0x{offset:x}" if isinstance(offset, int) else "not in file"
                lines.append(f"  {e.get('path',''):<32} {size:>7} bytes  @{where}")
            for warning in res.get("warnings") or []:
                lines.append(f"  warning: {warning}")
            human = "\n".join(lines)
        else:
            cbs = [hex(cb) if isinstance(cb, int) else str(cb) for cb in res.get("callbacks", [])]
            human = f"TLS Callbacks ({len(cbs)}): " + (", ".join(cbs) if cbs else "none")
    elif verb == "cfg":
        blocks_count = len(res.get("blocks", []))
        edges_count = len(res.get("edges", []))
        human = f"CFG for {res.get('symbol')}: {blocks_count} blocks, {edges_count} edges ({res.get('engine')})"
        if res.get("truncated_instructions"):
            human += f"\n  (instructions truncated: {res.get('total_instructions')} total; use --max-instructions or 're block <id>')"
    elif verb == "block":
        insns = res.get("instructions") or []
        human = f"Block {res.get('block_id')} ({res.get('start_rva')} - {res.get('end_rva')}):\n" + "\n".join(
            f"  {ins.get('hex_address','')}  {ins.get('mnemonic',''):<8} {ins.get('operands','')}"
            for ins in insns
        )
    elif verb == "view":
        human = f"Visual companion generated at {res.get('view_file')} ({res.get('blocks')} blocks)"
    elif verb == "xrefs":
        if not res.get("ok"):
            # Dropping the error made a refusal render as "0 cross-references to None", which
            # reads like a completed search that found nothing.
            lines = ["xrefs: " + str(res.get("error", "unknown"))]
            if res.get("usage"):
                lines.append("  usage: " + str(res["usage"]))
            if res.get("hint"):
                lines.append("  hint:  " + str(res["hint"]))
            human = "\n".join(lines)
        else:
            xrefs = res.get("xrefs") or []
            human = f"{len(xrefs)} cross-references to {res.get('target')}:\n" + "\n".join(
                f"  {x.get('caller')} ({x.get('address')}): "
                f"{x.get('mnemonic')} {x.get('operands')}"
                for x in xrefs
            )
    elif verb == "checksec":
        mits = res.get("mitigations", {})
        human = f"Checksec for {res.get('path')} ({res.get('format')}):\n" + "\n".join(
            f"  {k:<18} {'YES' if v is True else ('NO' if v is False else v)}"
            for k, v in mits.items()
        )
    elif verb == "hooks":
        syscalls = res.get("syscalls", [])
        hooks = res.get("hooks", [])
        constructors = res.get("constructors") or []
        lines = [f"Hooks & Syscalls for {res.get('path')}: {len(hooks)} hooks, "
                 f"{len(syscalls)} syscall stubs, {len(constructors)} initializer(s)"]
        for h in hooks[:10]:
            lines.append(f"  [HOOK]    {h['function']} @ {h['address']}: {h['type']} -> {h['target']}")
        for sc in syscalls[:10]:
            lines.append(f"  [SYSCALL] {sc['function']} @ {sc['address']}: SSN {sc.get('hex_ssn')} ({sc.get('ssn')})")
        # Listed in the order the loader runs them, which is what makes this actionable: the
        # first entry is the first code to run, and it runs before any breakpoint set on main().
        for entry in constructors[:12]:
            label = entry.get("function") or "(unnamed)"
            kind = entry.get('kind', 'constructor').upper().ljust(11)
            lines.append(f"  [{kind}] {label:<24} {entry.get('address')}  {entry.get('section')}")
        if res.get("constructors_error"):
            lines.append(f"  constructors unavailable: {res['constructors_error']}")
        human = "\n".join(lines)
    elif verb == "patch":
        human = f"Patched {res.get('bytes_patched')} bytes at {res.get('offset')} -> {res.get('out_path')}"
    elif verb == "rtti":
        classes = res.get("classes", [])
        lines = [f"RTTI Classes for {res.get('path')} ({res.get('format')}): {len(classes)} classes"]
        for c in classes[:15]:
            lines.append(f"  {c.get('demangled_name', c.get('name'))} (vtable: {c.get('vtable_rva') or c.get('address')}) - {c.get('method_count', len(c.get('methods', [])))} methods")
        human = "\n".join(lines)
    elif verb == "diff":
        human = (
            f"Binary Diff: {res.get('bin1')} vs {res.get('bin2')}\n"
            f"  Similarity: {res.get('similarity_pct')}%\n"
            f"  Added:    {res.get('added_count')} functions {res.get('added_functions', [])[:6]}\n"
            f"  Removed:  {res.get('removed_count')} functions {res.get('removed_functions', [])[:6]}\n"
            f"  Modified: {res.get('modified_count')} functions"
        )
    elif verb == "capa":
        caps = res.get("capabilities", [])
        lines = [f"Capabilities for {res.get('path')} ({res.get('format')}): {len(caps)} detected"]
        for cap in caps:
            lines.append(f"  [{cap.get('severity')}] {cap.get('name')}: {cap.get('description')}")
            for m in cap.get("matches", []):
                lines.append(f"      - {m.get('type')}: {m.get('indicator')}")
        human = "\n".join(lines)
    elif verb == "crash":
        exc = res.get("exception") or {}
        crashing_mod = res.get("crashing_module") or {}
        lines = [
            f"Crash Dump: {res.get('path')} ({res.get('format')})",
            f"  Exception: {exc.get('code_name')} ({exc.get('code')}) at {exc.get('address')} (thread {exc.get('thread_id')})",
        ]
        if crashing_mod:
            lines.append(f"  Faulting Module: {crashing_mod.get('name')} + {crashing_mod.get('offset')} (base {crashing_mod.get('base')})")
        lines.append(f"  Loaded Modules: {len(res.get('modules', []))}, Threads: {res.get('thread_count', 0)}")
        human = "\n".join(lines)
    elif verb == "strings":
        if "stack_strings" in res:
            human = "\n".join(f"{s['function']}: {s['string']}" for s in res["stack_strings"]) or "(no stack strings found)"
        elif "xor_strings" in res:
            human = "\n".join(f"key {s['hex_key']} @ {s['offset']}: {s['string']}" for s in res["xor_strings"]) or "(no XOR strings found)"
        else:
            human = "\n".join(res.get("strings", []))
    elif verb == "pack":
        human = (f"verdict  {res.get('verdict')}\n"
                 f"entropy  {res.get('entropy')} bits/byte\n"
                 f"strings  {res.get('strings')} "
                 f"({res.get('string_density_per_kb')}/kb)\n"
                 f"hot sections: {res.get('hot_sections')}")
        if res.get("sections"):
            human += "\n" + "\n".join(
                f"  {s['name']:<12} {s['entropy']:>6} {s['size']:>8}"
                for s in res["sections"][:5])
    elif verb == "ioc":
        counts = res.get("counts", {}) or {}
        lines = [f"indicators: {res.get('total', 0)}"]
        for kind, count in counts.items():
            if count:
                lines.append(f"  {kind:<18} {count}")
        findings = res.get("findings", {}) or {}
        for kind in ("urls", "ips", "domains", "emails", "hashes", "cves",
                     "credential_urls"):
            for value in (findings.get(kind) or [])[:5]:
                lines.append(f"    {value}")
        if not res.get("total"):
            lines.append("  (none found)")
        human = "\n".join(lines)
    elif verb == "disasm":
        lines = [f"{res.get('count', 0)} instructions"
                 + (f" in {res['symbol']}" if res.get("symbol") else "")]
        for item in res.get("instructions", [])[:20]:
            lines.append(f"  {item['address']}  {item['mnemonic']:<8} "
                         f"{item['operands']}")
        hist = ", ".join(f"{k}:{v}" for k, v in
                         list((res.get("mnemonic_histogram") or {}).items())[:6])
        if hist:
            lines.append(f"  mnemonics: {hist}")
        human = "\n".join(lines)
    elif verb == "graph":
        lines = [f"imports {res.get('import_count', 0)}  "
                 f"exports {res.get('export_count', 0)}  "
                 f"call sites {res.get('call_count', 0)}"]
        for item in res.get("hot_targets", [])[:8]:
            lines.append(f"  {item['calls']:>4}x  {item['target']}")
        for item in res.get("imports", [])[:6]:
            lines.append(f"  import  {item['symbol']}")
        human = "\n".join(lines)
    elif verb == "dex":
        if not res.get("ok"):
            human = "dex: " + str(res.get("error", "unknown"))
        else:
            counts = res.get("counts") or {}
            verify = res.get("verification") or {}
            lines = [f"dex {res.get('version')} "
                     f"({counts.get('classes')} classes, {counts.get('methods')} methods, "
                     f"{counts.get('strings')} strings)"]
            if verify.get("checksum_ok") is False:
                lines.append("  WARNING checksum does not match — file was modified "
                             "after it was built")
            if verify.get("signature_ok") is False:
                lines.append("  WARNING signature does not match")
            if res.get("entry"):
                lines.append(f"  entry       {res['entry']} "
                             f"({res.get('size')} bytes)")
            for cls in (res.get("classes") or [])[:30]:
                access = ", ".join(cls.get("access") or [])
                lines.append(f"  {cls.get('name')}  [{access}]")
                for method in (cls.get("methods") or [])[:6]:
                    proto = method.get("proto") or {}
                    params = ", ".join(proto.get("parameters") or [])
                    native = " native" if method.get("native") else ""
                    lines.append(f"    {method.get('name')}({params}) -> "
                                 f"{proto.get('return_type')}{native}")
            if res.get("native_methods"):
                lines.append(f"  native      {len(res['native_methods'])} methods")
            human = "\n".join(lines)
    elif verb == "netcap" and res.get("engine") == "pcap":
        if not res.get("ok"):
            human = "capture: " + str(res.get("error", "unknown"))
        else:
            lines = [f"{res.get('format')} capture ({res.get('endianness')}-endian, "
                     f"{res.get('resolution') or 'default'} timestamps)",
                     f"  linktype    {res.get('linktype_name')}",
                     f"  packets     {res.get('packet_count')} "
                     f"(parsed {res.get('parsed_packets')}, "
                     f"unparsed {res.get('unparsed_packets')})",
                     f"  flows       {res.get('flow_count')}"]
            if res.get("first_packet"):
                lines.append(f"  window      {res.get('first_packet')} .. "
                             f"{res.get('last_packet')}")
            if res.get("protocols"):
                summary = ", ".join(f"{name} {count}"
                                    for name, count in res["protocols"].items())
                lines.append(f"  protocols   {summary}")
            for flow in (res.get("flows") or [])[:20]:
                pair = f"{flow.get('src')}"
                if flow.get("src_port") is not None:
                    pair += f":{flow['src_port']}"
                pair += " -> " + str(flow.get("dst"))
                if flow.get("dst_port") is not None:
                    pair += f":{flow['dst_port']}"
                lines.append(f"    {flow.get('protocol'):<5} {pair}  "
                             f"{flow.get('packets')} pkts")
            if res.get("http_requests"):
                lines.append(f"  http        {res.get('http_request_count')} request(s)")
                for request in res["http_requests"][:15]:
                    lines.append(f"    {request.get('method')} {request.get('url')}")
            if res.get("truncated"):
                lines.append("  WARNING     capture is truncated")
            human = "\n".join(lines)
    elif verb in ("annotate", "asar", "netcap", "apk", "dex", "decompile", "trace", "triage", "deep-elf", "anchors", "slice", "live-probe", "rbxm", "ida", "borer"):
        human = res.get("output") or res.get("script") or res.get("code") or res.get("pseudocode") or (
            f"{verb} ok={res.get('ok')} count={res.get('count', res.get('chunk_count', len(res.get('files', res.get('annotations', res.get('warnings', []))))))}"
        )
    else:
        human = (f"entropy {res['entropy']}  {res['verdict']}  "
                 f"({res['bytes']} bytes)")
        if res.get("blocks"):
            human += "\n" + "\n".join(
                f"  @{b['offset']:>8} {b['entropy']:>6} {b['verdict']}"
                for b in res["blocks"])
    return _out(args, res, human or "(no output)")


def cmd_test(args):
    from ..core.build.test_runner import run_tests
    res = run_tests(getattr(args, "path", ".") or ".", pattern=getattr(args, "pattern", "") or "")
    human = f"{res.get('runner')}: rc={res.get('returncode')}\n{res.get('output', '')}"
    return _out(args, res, human, code=0 if res.get("ok") else 1)


def cmd_scan(args):
    from ..core import scan as scanmod
    verb = args.scan_verb
    raw = args.path or args.value or "."
    reveal = bool(getattr(args, "reveal", False))
    glob = getattr(args, "glob", None)
    target = Path(raw)

    if verb == "mcp":
        import json as _json
        from ..core import mcp_audit as auditmod
        from ..core.route import guard
        try:
            canon = guard.read_guard(target)
        except guard.Denied as exc:
            return _out(args, {"ok": False, "err": f"{exc.code}: {exc.reason}"}, f"{exc.code}: {exc.reason}", code=1)
        text = canon.read_text(encoding="utf-8", errors="replace")
        try:
            doc = _json.loads(text)
            tools = doc.get("tools", doc) if isinstance(doc, dict) else doc
            if isinstance(tools, dict):
                tools = [tools]
        except Exception:
            tools = [{"name": canon.name, "description": text}]
        rep = auditmod.evaluate_tools(canon.name, list(tools))
        rep["path"] = str(canon)
        return _out(args, rep, f"mcp scan: ok={rep['ok']} findings={len(rep['findings'])}",
                    code=0 if rep["ok"] else 1)

    if verb == "deps":
        if target.is_file():
            manifests = [target]
        else:
            manifests = [p for p in sorted(target.rglob("*"))
                         if p.is_file() and p.name in scanmod.MANIFEST_NAMES][:50]
        findings = []
        results = []
        for manifest in manifests:
            res = scanmod.scan_manifest(manifest, reveal=reveal)
            results.append(res)
            findings.extend(res.get("findings", []))
        findings.sort(key=lambda f: (f["path"], f["line"], f["rule"]))
        payload = {"ok": True, "root": raw, "manifests": len(results),
                   "findings": findings, "count": len(findings),
                   "masked": not reveal,
                   "summary": scanmod.summarize(findings)}
        return _out(args, payload, _human_findings(payload))

    mode = "secrets" if verb == "secrets" else ("injection" if verb == "injection" else "patterns")
    if target.is_file():
        res = scanmod.scan_file(target, reveal=reveal, mode=mode)
        payload = {"ok": "error" not in res, "root": str(target),
                   "files_scanned": 1, "findings": res.get("findings", []),
                   "count": res.get("count", 0), "masked": not reveal,
                   "summary": scanmod.summarize(res.get("findings", []))}
        if res.get("error"):
            payload["err"] = res["error"]
        return _out(args, payload, _human_findings(payload))

    res = scanmod.scan_tree(target, glob=glob, reveal=reveal, mode=mode,
                            limit=getattr(args, "limit", 500))
    return _out(args, res, _human_findings(res))
