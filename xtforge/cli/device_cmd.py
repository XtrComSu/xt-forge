"""Route, phone, compress, and meta CLI handlers."""
from __future__ import annotations

import json
import sys

from .common import _out, _store


def cmd_route(args):
    from ..core.route import bookmarks
    from ..core.route import tools as routetools
    from ..core.route import shortcuts
    verb = args.route_verb
    if verb == "resolve":
        st = _store(args)
        try:
            res = bookmarks.resolve(args.query, st)
        finally:
            st.close()
        lines = [f"{c['path']} (conf {c['confidence']:.2f}"
                 f"{'' if c['exists'] else ', missing'})"
                 for c in res.get("data", {}).get("candidates", [])]
        return _out(args, res, "\n".join(lines))
    if verb == "tree":
        return _out(args, routetools.route_tree(args.path, args.depth, args.max))
    if verb == "find":
        return _out(args, routetools.route_find(args.path, name=args.name,
                                                regex=args.regex, type_=args.type,
                                                min_size=args.min_size,
                                                limit=args.limit))
    if verb == "grep":
        if getattr(args, "rank", False):
            from pathlib import Path
            from ..core.route import pack as packmod
            ranked = packmod.rank_lines(Path(args.path or "."),
                                        args.pattern or "",
                                        limit=args.limit, glob=args.glob)
            return _out(args, {"root": args.path or ".", "pattern": args.pattern,
                               "count": len(ranked), "matches": ranked},
                        "\n".join(f"{m['score']:>5} {m['path']}:{m['line']} "
                                  f"{m['text']}" for m in ranked))
        return _out(args, routetools.route_grep(args.path, args.pattern,
                                                glob=args.glob,
                                                context=args.context,
                                                limit=args.limit))
    if verb == "peek":
        return _out(args, routetools.route_peek(args.path, mode=args.mode,
                                                start=args.start, count=args.count))
    if verb == "du":
        return _out(args, routetools.route_du(args.path, top=args.top))
    if verb == "recent":
        roots = args.paths or ([args.path] if args.path else ["."])
        return _out(args, routetools.route_recent(roots, args.minutes, args.limit))
    if verb == "where":
        target = args.name or args.path
        if not target:
            return _out(args, {"ok": False, "err": "route where requires a filename"},
                        "route where requires a filename", code=2)
        return _out(args, routetools.route_where(target, limit=args.limit))
    if verb == "index":
        roots = args.paths or ([args.path] if args.path else ["."])
        return _out(args, routetools.build_index(roots))
    if verb in {"context", "batch-peek", "errors"}:
        return _cmd_route_shortcut(args, shortcuts)
    return 1


def _cmd_route_shortcut(args, shortcuts):
    if args.route_verb == "context":
        query = (getattr(args, "query", None) or "").strip()
        if query:
            # Query-aware packing: spend the budget on the lines that answer.
            from ..core.route import pack as packmod
            result = packmod.pack(args.path or ".", query,
                                  token_budget=args.token_budget,
                                  file_limit=args.file_limit,
                                  window=max(1, args.context))
        else:
            result = shortcuts.route_context(args.path or ".", args.token_budget,
                                             args.file_limit)
    elif args.route_verb == "batch-peek":
        paths = args.paths or ([args.path] if args.path else [])
        result = shortcuts.route_batch_peek(paths, args.token_budget,
                                            args.lines_per_file)
    else:
        result = shortcuts.route_errors(args.path or "", args.max_lines,
                                        args.token_budget)
    return _out(args, result)


def cmd_phone(args):
    from ..core.route import phone as phonemod
    verb = args.phone_verb
    if verb == "info":
        return _out(args, phonemod.phone_info())
    if verb == "procs":
        return _out(args, phonemod.phone_procs(args.top, args.by))
    if verb == "net":
        return _out(args, phonemod.phone_net())
    if verb == "clip-get":
        return _out(args, phonemod.phone_clip_get())
    if verb == "clip-set":
        return _out(args, phonemod.phone_clip_set(args.text))
    if verb == "notify":
        return _out(args, phonemod.phone_notify(args.title, args.text))
    if verb == "wakelock":
        return _out(args, phonemod.phone_wakelock(args.on))
    if verb == "adb":
        return _out(args, phonemod.phone_adb(args.text))
    return 1


def cmd_code(args):
    """`xtforge code` — structure extraction (real AST where we can parse)."""
    from ..core.code import parse as codeparse
    verb = args.code_verb
    path = args.path or (args.value if verb != "refs" else None) or "."
    if verb == "symbols":
        info = codeparse.symbols(path)
        human = "\n".join(
            f"{s['line']:>5} {s['kind']:<10} {s['name']:<32} {s['signature']}"
            for s in info["symbols"]) or "(no symbols found)"
        if info.get("error"):
            human += f"\nnote: {info['error']}"
        return _out(args, info, human)
    if verb == "outline":
        info = codeparse.outline(path)

        def render(nodes, depth=0):
            lines = []
            for node in nodes:
                lines.append(f"{'  ' * depth}{node['kind']:<10} {node['name']} "
                             f"(L{node['line']})")
                lines.extend(render(node.get("children", []), depth + 1))
            return lines

        return _out(args, info,
                    "\n".join(render(info.get("tree", []))) or "(empty)")
    if verb == "refs":
        name = args.name or args.value
        if not name:
            return _out(args, {"ok": False, "error": "code refs needs --name"},
                        "error: code refs needs --name", code=2)
        info = codeparse.refs(path, name, limit=args.limit)
        human = "\n".join(f"{r['path']}:{r['line']}"
                          f"{'  [def]' if r['definition'] else ''} {r['text']}"
                          for r in info["refs"]) or "(no references)"
        return _out(args, info, human)
    if verb == "syntax":
        from ..core.code import syntax as codesyntax
        target_path = args.path or args.value or "."
        info = codesyntax.check_syntax(target_path)
        if info.get("ok"):
            human = f"[ok] {info['path']} ({info.get('language')}) syntax clean"
        else:
            errors = info.get("errors", [])
            lines = [f"[error] {info['path']} ({info.get('language')}): {len(errors)} syntax error(s)"]
            for err in errors:
                lines.append(f"  L{err.get('line')}:{err.get('column')} - {err.get('message')}")
                if err.get("snippet"):
                    lines.append(f"    {err['snippet']}")
            human = "\n".join(lines)
        return _out(args, info, human, code=0 if info.get("ok") else 1)
    return _out(args, {"ok": False, "error": f"unknown verb: {verb}"},
                f"error: unknown verb {verb}", code=2)


def cmd_compress(args):
    from ..core.compress import legend, passes
    if args.text is not None:
        text = args.text
    elif args.path:
        text = open(args.path).read()
    else:
        text = sys.stdin.read()
    if args.legend:
        return _out(args, legend.apply_legend(text))
    res = passes.compress(text, args.level)
    if args.stats:
        res["stats"] = passes.line_stats(text)
    return _out(args, res, res["text"])


def cmd_ascii(args):
    from ..core.ascii import render
    banner = render(args.style)
    return _out(args, {"style": args.style, "banner": banner}, banner)


def cmd_version(args):
    from ..version import app_name, version_str, codename, xt_home
    return _out(args, {"name": app_name(), "version": version_str(),
                       "codename": codename(), "xt_home": str(xt_home())},
                f"{app_name()} {version_str()} (XT_HOME={xt_home()})")


def cmd_doctor(args):
    from ..core import diagnostics
    checks = diagnostics.checks()
    return _out(args, checks, json.dumps(checks, indent=2, default=str))
