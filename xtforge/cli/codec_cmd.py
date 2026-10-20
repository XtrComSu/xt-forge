"""`xtforge codec` — hashing, encoding, entropy and format inspection.

Read-only and local: the input is often a credential or evidence, so nothing
here phones home and nothing is written.
"""
from __future__ import annotations

from .common import _out


def _input(args) -> bytes:
    """Value from the positional arg, --text, or --path. Never guesses."""
    raw = getattr(args, "value", None) or getattr(args, "text", None)
    path = getattr(args, "path", None)
    if path:
        with open(path, "rb") as fh:
            return fh.read()
    return (raw or "").encode("utf-8")


def cmd_codec(args):
    from ..core import codec as codecmod
    verb = args.codec_verb
    try:
        if verb == "hash":
            data = _input(args)
            payload = codecmod.digest(data, algo="all" if args.all else args.algo)
            if args.all:
                human = "\n".join(f"{k:<10} {v}"
                                  for k, v in payload["digests"].items())
            else:
                human = f"{payload['digest']}  ({payload['algorithm']}, " \
                        f"{payload['length']} bytes)"
            return _out(args, payload, human)

        if verb in ("encode", "decode"):
            data = _input(args)
            scheme = args.scheme
            if verb == "encode":
                out = codecmod.encode(data, scheme)
                payload = {"scheme": scheme, "input_bytes": len(data), "output": out}
                return _out(args, payload, out)
            text = data.decode("utf-8", "replace")
            out = codecmod.decode(text, scheme)
            printable = all(32 <= b < 127 or b in (9, 10, 13) for b in out)
            payload = {"scheme": scheme, "input_bytes": len(data),
                       "bytes": len(out),
                       "output": out.decode("utf-8", "replace") if printable else None,
                       "hex": out.hex() if not printable else None}
            human = payload["output"] if printable else out.hex()
            return _out(args, payload, human)

        if verb == "roundtrip":
            data = _input(args)
            out = codecmod.decode(codecmod.encode(data, args.scheme), args.scheme)
            ok = out == data
            payload = {"scheme": args.scheme, "ok": ok, "bytes": len(data)}
            return _out(args, payload,
                        f"{args.scheme}: {'round-trips' if ok else 'BROKEN'}",
                        code=0 if ok else 1)

        if verb == "entropy":
            payload = codecmod.entropy_report(_input(args), block=args.block)
            human = (f"length   {payload['length']} bytes\n"
                     f"entropy  {payload['entropy']} bits/byte\n"
                     f"verdict  {payload['verdict']}")
            if payload.get("blocks"):
                human += "\n" + "\n".join(
                    f"  @{b['offset']:>8} {b['entropy']:>6} {b['verdict']}"
                    for b in payload["blocks"])
            return _out(args, payload, human)

        if verb == "inspect":
            text = (getattr(args, "value", None)
                    or _input(args).decode("utf-8", "replace"))
            payload = codecmod.inspect(text)
            human = "\n".join(
                f"{item.get('type', '?'):<16} "
                f"{json_line(item)}"
                for item in payload.get("findings", [])) or "(unrecognised)"
            return _out(args, payload, human)

    except ValueError as exc:
        return _out(args, {"ok": False, "error": str(exc)},
                    f"error: {exc}", code=2)
    except OSError as exc:
        return _out(args, {"ok": False, "error": str(exc)},
                    f"error: {exc}", code=1)
    return _out(args, {"ok": False, "error": f"unknown verb: {verb}"},
                f"error: unknown verb {verb}", code=2)


def json_line(item: dict) -> str:
    import json
    return json.dumps({k: v for k, v in item.items() if k != "type"},
                      ensure_ascii=False, default=str)[:120]
