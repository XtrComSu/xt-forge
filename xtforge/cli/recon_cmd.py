"""`xtforge recon` — scoped findings ledger with reproducible reports.

Writes only under `$XT_HOME/recon/`. The target is a label, never a path.
"""
from __future__ import annotations

from .common import _out


def cmd_recon(args):
    from ..core import recon as reconmod
    verb = args.recon_verb
    target = (args.target or args.value or "").strip()
    try:
        if verb == "new":
            if not target:
                return _out(args, {"ok": False, "error": "recon new needs a target"},
                            "error: recon new needs a target", code=2)
            res = reconmod.init(target)
            return _out(args, res, f"workspace: {res['path']}")

        if verb == "note":
            if not target:
                return _out(args, {"ok": False, "error": "recon note needs a target"},
                            "error: recon note needs a target", code=2)
            record = reconmod.add_note(target, args.body or args.text or "")
            return _out(args, record, f"note {record['id']}: {record['text'][:70]}")

        if verb == "finding":
            if not target:
                return _out(args, {"ok": False, "error": "recon finding needs a target"},
                            "error: recon finding needs a target", code=2)
            if not (args.title or "").strip():
                return _out(args, {"ok": False, "error": "a finding needs --title"},
                            "error: a finding needs --title", code=2)
            finding = reconmod.add_finding(
                target, severity=args.severity, title=args.title,
                detail=args.detail or "", evidence=args.evidence or "",
                tags=args.tag or [])
            return _out(args, finding,
                        f"{finding['id']} [{finding['severity']}] {finding['title']}")

        if verb in ("list", "stats"):
            data = reconmod.stats(target) if verb == "stats" \
                else reconmod.ledger(target)
            if verb == "stats":
                human = "\n".join(f"{k:<12} {v}" for k, v in data.items()
                                  if k != "by_severity")
                human += "\n" + ", ".join(f"{k} {v}"
                                          for k, v in data["by_severity"].items())
                return _out(args, data, human)
            findings = data["findings"]
            human = "\n".join(
                f"{f['id']:<22} [{f['severity']:<8}] {f['title']}"
                for f in findings) or "(no findings)"
            return _out(args, data, human)

        if verb == "report":
            text = reconmod.report(target)
            payload = {"target": reconmod.sanitize_target(target), "report": text}
            if args.path:
                with open(args.path, "w", encoding="utf-8") as fh:
                    fh.write(text)
                return _out(args, {**payload, "written": args.path},
                            f"wrote {args.path}")
            return _out(args, payload, text)

    except ValueError as exc:
        return _out(args, {"ok": False, "error": str(exc)},
                    f"error: {exc}", code=2)
    except OSError as exc:
        return _out(args, {"ok": False, "error": str(exc)},
                    f"error: {exc}", code=1)
    return _out(args, {"ok": False, "error": f"unknown verb: {verb}"},
                f"error: unknown verb {verb}", code=2)
