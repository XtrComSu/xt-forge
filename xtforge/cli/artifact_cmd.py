"""`xtforge artifact` — record and verify produced files."""

from __future__ import annotations

import json
import sys

from .common import _out


def cmd_artifact(args) -> int:
    from ..core import artifact as art

    verb = args.artifact_verb
    path = (args.path or "").strip()
    try:
        if verb == "record":
            res = art.record(
                path,
                media_type=args.media_type or "application/octet-stream",
                producer=args.producer or "",
                by=args.by or "cli",
            )
            return _out(args, res,
                        f"recorded {res['id'][:12]}  status={res['status']}  ({res['statusReason']})")

        if verb == "check":
            res = art.add_check(
                path,
                check_id=args.check or "",
                result=args.result or "pass",
                detail=args.detail or "",
                version=args.version or "1",
                by=args.by or "cli",
                checker=args.checker or "",
                exit_status=args.exit_status,
                evidence=args.evidence or "",
                declared=bool(args.declared),
            )
            kind = "declared" if args.declared else "executed"
            return _out(args, res,
                        f"{kind} '{args.check}' = {args.result}  status={res['status']}  ({res['statusReason']})")

        if verb == "require":
            res = art.set_requirement(path, args.requires or [], by=args.by or "cli")
            warn = ""
            if res.get("unknownRequired"):
                warn = ("  WARNING: no such check recorded: "
                        + ", ".join(res["unknownRequired"]))
            return _out(args, res,
                        f"required: {', '.join(res.get('requiredChecks') or []) or '(none)'}"
                        f"  status={res['status']}{warn}")

        if verb == "show":
            res = art.inspect(path)
            human = [f"{res['artifact']}",
                     f"  status : {res['status']}  ({res['statusReason']})"]
            if res.get("hasSidecar"):
                human.append(f"  id     : {str(res.get('id'))[:16]}")
                human.append(f"  checks : {len(res.get('checks') or [])}")
                for c in res.get("checks") or []:
                    human.append(f"    - {c.get('id')} = {c.get('result')} "
                                 f"(subject {str(c.get('subjectSha256'))[:12]})")
            else:
                human.append("  no sidecar: this file has never been recorded")
            return _out(args, res, "\n".join(human))

        if verb == "verify":
            # Exit code carries the verdict, so a caller can gate on it.
            res = art.inspect(path)
            _out(args, res, f"{res['status']}: {res['statusReason']}")
            return 0 if res["status"] == art.VERIFIED else 1

        return _out(args, {"ok": False, "error": f"unknown verb {verb}"},
                    f"unknown verb {verb}", code=2)
    except art.ArtifactError as exc:
        return _out(args, {"ok": False, "error": str(exc)}, f"error: {exc}", code=2)
