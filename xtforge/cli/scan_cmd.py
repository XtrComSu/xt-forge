"""`xtforge re` and `xtforge scan`: binary inspection and static safety scan.

`scan` is read-only and masks matched values by default.
"""
from __future__ import annotations

import json
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
    elif verb == "diff":
        path = args.value or args.path

    # 'llvm' routes like 'pe': the subverb is the second positional argument.
    # available/tools need no path, so handle this before the path check.
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

    if not path:
        return _out(args, {"ok": False, "error": "re needs a path"},
                    "error: re needs a path", code=2)

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
            res = wasm.inspect(path)
        elif verb == "firmware":
            from ..core.re import firmware
            res = firmware.inspect(path)
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
            target_ref = getattr(args, "target", None) or getattr(args, "symbol", None) or ""
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
        elif verb in ("asar", "netcap", "apk", "decompile", "trace", "triage"):
            from ..core.re import runtimes as rt
            if verb == "asar":
                res = rt.inspect_asar(path, grep=getattr(args, "grep", None) or "", limit=args.limit)
            elif verb == "netcap":
                res = rt.inspect_netcap(path, reveal=bool(getattr(args, "reveal", False)), limit=args.limit)
            elif verb == "apk":
                res = rt.inspect_apk(path)
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
            sub = args.value or "info"
            target_path = args.path or ""
            extra = [str(x) for x in (getattr(args, "extra", []) or [])]
            if not _GSTATE.borer_bin:
                res = {"ok": False, "err": "borer binary not found"}
            else:
                out = _GSTATE.run_borer_cli(sub, target_path, *extra)
                res = {"ok": bool(out), "subcommand": sub, "path": target_path, "output": out or "", "engine": "borer"}
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
        for warning in (dwarf.get("warnings") or [])[:10]:
            lines.append(f"warning         {warning}")
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
            human = "\n".join(lines)
        else:
            lines = [f"{res.get('pinvoke_count', 0)} P/Invoke(s) across "
                     f"{len(res.get('dlls') or [])} DLL(s)"]
            for p_row in (res.get("pinvokes") or [])[:30]:
                lines.append(f"  {p_row.get('dll')}!{p_row.get('import_name')}"
                             f"  -> {p_row.get('managed_method')}")
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
        xrefs = res.get("xrefs", [])
        human = f"{len(xrefs)} cross-references to {res.get('target')}:\n" + "\n".join(
            f"  {x.get('caller')} ({x.get('address')}): {x.get('mnemonic')} {x.get('operands')}"
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
        lines = [f"Hooks & Syscalls for {res.get('path')}: {len(hooks)} hooks, {len(syscalls)} syscall stubs"]
        for h in hooks[:10]:
            lines.append(f"  [HOOK]    {h['function']} @ {h['address']}: {h['type']} -> {h['target']}")
        for sc in syscalls[:10]:
            lines.append(f"  [SYSCALL] {sc['function']} @ {sc['address']}: SSN {sc.get('hex_ssn')} ({sc.get('ssn')})")
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
    elif verb in ("annotate", "asar", "netcap", "apk", "decompile", "trace", "triage", "deep-elf", "anchors", "slice", "live-probe", "rbxm", "ida", "borer"):
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
