"""`xtforge re` and `xtforge scan`: binary inspection and static safety scan.

Both are read-only. `scan` masks matched values by default — a scanner that
echoes a live key into a transcript leaks the thing it found.
"""
from __future__ import annotations

from pathlib import Path

from .common import _out


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

    # Handle 'pe' subverb routing: e.g. xtforge re pe info <path>
    pe_subverb = "info"
    if verb == "pe":
        if args.value in ("info", "sections", "imports", "exports", "tls"):
            pe_subverb = args.value
            extra = getattr(args, "extra", [])
            path = args.path or (extra[0] if extra else None)
        else:
            pe_subverb = "info"
            path = args.path or args.value

    if not path:
        return _out(args, {"ok": False, "error": "re needs a path"},
                    "error: re needs a path", code=2)
    try:
        if verb == "info":
            res = renative.get_info(path)
        elif verb == "needed":
            res = elf.needed(path)
        elif verb == "sections":
            res = renative.get_sections(path)
        elif verb == "symbols":
            res = renative.get_symbols(path, limit=args.limit)
        elif verb == "strings":
            res = elf.strings(path, min_len=getattr(args, "min_len", 4),
                              limit=args.limit)
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
    elif verb == "strings":
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
    else:
        human = (f"entropy {res['entropy']}  {res['verdict']}  "
                 f"({res['bytes']} bytes)")
        if res.get("blocks"):
            human += "\n" + "\n".join(
                f"  @{b['offset']:>8} {b['entropy']:>6} {b['verdict']}"
                for b in res["blocks"])
    return _out(args, res, human or "(no output)")


def cmd_scan(args):
    from ..core import scan as scanmod
    verb = args.scan_verb
    raw = args.path or args.value or "."
    reveal = bool(getattr(args, "reveal", False))
    glob = getattr(args, "glob", None)
    target = Path(raw)

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
