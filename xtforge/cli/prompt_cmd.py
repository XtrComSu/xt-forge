"""CLI command for prompt inspection, rendering, and agent prompt injection."""
from __future__ import annotations

from .common import _out


def cmd_prompt(args):
    from ..core import prompts as pmod

    verb = args.prompt_verb
    if verb == "inject":
        name = getattr(args, "name_flag", None) or getattr(args, "name", None)
        text = pmod.build_agent_context(
            include_taste=not getattr(args, "no_taste", False),
            include_flash=not getattr(args, "no_flash", False),
            flash_scope=getattr(args, "flash_scope", "global"),
            query=getattr(args, "query", None),
            mem_k=getattr(args, "mem_k", 3),
            harness=getattr(args, "harness", "auto"),
            compact=getattr(args, "compact", False),
            token_budget=getattr(args, "token_budget", None),
            prompt_name=name
        )
        payload = {
            "ok": True,
            "context": text,
            "tokens_approx": len(text) // 4,
            "harness": getattr(args, "harness", "auto"),
            "compact": getattr(args, "compact", False)
        }
        return _out(args, payload, text)
    elif verb == "render":
        name = getattr(args, "name_flag", None) or getattr(args, "name", None)
        if not name:
            return _out(args, {"ok": False, "error": "render requires --name or name argument"}, "error: render requires name", code=2)
        vars_dict = {}
        for item in getattr(args, "var", []) or []:
            if "=" in item:
                k, v = item.split("=", 1)
                vars_dict[k.strip()] = v.strip()
        try:
            text = pmod.render(name, **vars_dict)
            return _out(args, {"ok": True, "prompt": text}, text)
        except Exception as exc:
            return _out(args, {"ok": False, "error": str(exc)}, f"error: {exc}", code=1)
    elif verb == "hash":
        hashes = pmod.hash_all()
        lines = [f"{k:<30} {v}" for k, v in sorted(hashes.items())]
        return _out(args, {"ok": True, "hashes": hashes}, "\n".join(lines) or "(no prompts)")
    else:
        return _out(args, {"ok": False, "error": f"unknown verb {verb}"}, f"error: unknown verb {verb}", code=2)
