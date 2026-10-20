"""`xtforge intel` and `xtforge hub` — keyless enrichment and model discovery."""
from __future__ import annotations

from .common import _out


def cmd_intel(args):
    from ..core import intel
    verb = args.intel_verb
    value = (args.value or "").strip()

    try:
        if verb == "sources":
            payload = intel.sources()
            lines = [f"{name:<12} {desc}"
                     for name, desc in payload["sources"].items()]
            keys = payload.get("keys") or {}
            if keys:
                lines.append("")
                lines.append("keys: " + ", ".join(
                    f"{name}={'set' if has else 'absent'}"
                    for name, has in keys.items()))
            return _out(args, payload, "\n".join(lines))

        if verb == "ip":
            payload = intel.ip(value)
            if not payload.get("ok"):
                return _out(args, payload, f"error: {payload['err']}", code=1)
            lines = [f"{payload['ip']}"]
            if payload.get("ports"):
                lines.append(f"  ports      {', '.join(map(str, payload['ports'][:20]))}")
            if payload.get("hostnames"):
                lines.append(f"  hostnames  {', '.join(payload['hostnames'][:6])}")
            info = payload["sources"].get("internetdb") or {}
            if info.get("tags"):
                lines.append(f"  tags       {', '.join(info['tags'][:8])}")
            if payload.get("vulns"):
                lines.append(f"  vulns      {', '.join(payload['vulns'][:8])}")
            noise = payload["sources"].get("greynoise") or {}
            if noise.get("classification"):
                lines.append(f"  greynoise  {noise['classification']}"
                             f" (noise={noise.get('noise')})")
            elif noise.get("verdict"):
                lines.append(f"  greynoise  {noise['verdict']}")
            for flag in payload.get("flags", []):
                lines.append(f"  ! {flag}")
            return _out(args, payload, "\n".join(lines))

        if verb == "domain":
            payload = intel.domain(value)
            if not payload.get("ok"):
                return _out(args, payload, f"error: {payload['err']}", code=1)
            lines = [f"{payload['domain']}"]
            if payload.get("addresses"):
                lines.append(f"  addresses  {', '.join(payload['addresses'][:8])}")
            if payload.get("nameservers"):
                lines.append(f"  nameservers {', '.join(payload['nameservers'][:4])}")
            if payload.get("mail"):
                hosts = [m.get("host") if isinstance(m, dict) else str(m)
                         for m in payload["mail"]][:4]
                lines.append(f"  mail       {', '.join(hosts) or 'none'}")
            for note in payload.get("mail_posture", []):
                lines.append(f"  mail id    {note}")
            if payload.get("nxdomain"):
                lines.append("  ! name does not resolve")
            for error in payload.get("dns_errors", [])[:3]:
                lines.append(f"  dns error  {error}")
            vt = (payload.get("sources") or {}).get("virustotal") or {}
            if vt.get("malicious") is not None:
                lines.append(f"  virustotal {vt['malicious']} malicious")
            return _out(args, payload, "\n".join(lines))

        if verb == "cve":
            payload = intel.cve(value)
            if not payload.get("ok"):
                return _out(args, payload, f"error: {payload['err']}", code=1)
            lines = [f"{payload['cve']}  CVSS {payload.get('cvss')} "
                     f"({payload.get('severity') or 'unrated'})"]
            epss = payload.get("epss") or {}
            if epss.get("score") is not None:
                lines.append(f"  EPSS       {epss['score']:.0%} probability"
                             f" ({epss.get('percentile', 0) * 100:.0f}th pct)")
            if payload["kev"].get("listed"):
                lines.append(f"  KEV        listed {payload['kev'].get('date_added')}"
                             f"  ransomware={payload['kev'].get('ransomware')}")
            else:
                lines.append("  KEV        not in the exploited catalog")
            if payload.get("cwes"):
                lines.append(f"  CWEs       {', '.join(payload['cwes'])}")
            lines.append(f"  published  {str(payload.get('published'))[:10]}")
            for risk in payload.get("risk", []):
                lines.append(f"  ! {risk}")
            lines.append("")
            lines.append(payload.get("description", ""))
            return _out(args, payload, "\n".join(lines))

        if verb == "kev":
            payload = intel.kev(getattr(args, "query", None), args.limit or 20)
            if not payload.get("ok"):
                return _out(args, payload, f"error: {payload['err']}", code=1)
            lines = [f"{payload['matched']} entries (newest first)"]
            for row in payload["entries"]:
                mark = " R" if row.get("ransomware") == "Known" else ""
                lines.append(f"  {row['added']}  {row['cve']:<16} "
                             f"{row['vendor']} {row['product']}{mark}")
            return _out(args, payload, "\n".join(lines))

        if verb == "search":
            payload = intel.search(value, args.limit or 10,
                                   since_days=getattr(args, "since", None))
            if not payload.get("ok"):
                return _out(args, payload, f"error: {payload['err']}", code=1)
            lines = [f"{payload['returned']} of {payload['total']} for "
                     f"{payload['keyword']!r}"]
            for row in payload["results"]:
                lines.append(f"  {row['cve']:<16} {str(row['score'] or '-'):>4} "
                             f"{str(row['severity'] or ''):<8} "
                             f"{row['description'][:70]}")
            return _out(args, payload, "\n".join(lines))

        if verb == "hash":
            payload = intel.file_hash(value)
            if not payload.get("ok"):
                return _out(args, payload, f"error: {payload['err']}", code=1)
            lines = [f"{payload['hash'][:16]}…  {payload.get('algorithm')}"]
            if payload.get("known"):
                lines.append(f"  name       {payload.get('name')} "
                             f"{payload.get('version') or ''}".rstrip())
                lines.append(f"  product    {payload.get('product')}")
                lines.append(f"  publisher  {payload.get('publisher')}")
                lines.append(f"  trust      {payload.get('trust')}/100")
            else:
                lines.append("  circl      unknown to the known-file corpus")
            vt = (payload.get("sources") or {}).get("virustotal") or {}
            if vt.get("malicious") is not None:
                lines.append(f"  virustotal {vt['malicious']} malicious, "
                             f"{vt.get('undetected')} undetected")
            mb = (payload.get("sources") or {}).get("malwarebazaar") or {}
            if mb.get("signature"):
                lines.append(f"  bazaar     {mb['signature']} "
                             f"({mb.get('file_type')})")
            if payload.get("known_malicious"):
                lines.append(f"  ! {payload['known_malicious']}")
            if payload.get("malicious_detections"):
                lines.append(f"  ! {payload['malicious_detections']} engines "
                             "flag this file")
            return _out(args, payload, "\n".join(lines))

    except (ValueError, OSError) as exc:
        return _out(args, {"ok": False, "error": str(exc)},
                    f"error: {exc}", code=1)
    return _out(args, {"ok": False, "error": f"unknown verb: {verb}"},
                f"error: unknown verb {verb}", code=2)


def cmd_hub(args):
    from ..core import hub
    verb = args.hub_verb
    value = (args.value or "").strip()

    try:
        if verb == "models":
            payload = hub.models(value, limit=args.limit or 10,
                                 sort=getattr(args, "sort", None) or "downloads",
                                 gguf=bool(getattr(args, "gguf", False)),
                                 task=getattr(args, "task", None))
            if not payload.get("ok"):
                return _out(args, payload, f"error: {payload['err']}", code=1)
            lines = []
            for row in payload["models"]:
                quant = "gguf" if "gguf" in (row.get("tags") or []) else ""
                lines.append(f"{row['id'][:58]:<58} {str(row['downloads']):>10} "
                             f"{str(row['likes']):>6} {quant}")
            return _out(args, payload, "\n".join(lines) or "(no models matched)")

        if verb == "datasets":
            payload = hub.datasets(value, limit=args.limit or 10)
            if not payload.get("ok"):
                return _out(args, payload, f"error: {payload['err']}", code=1)
            lines = [f"{row['id'][:56]:<56} {str(row['downloads'] or 0):>10} "
                     f"{row.get('license') or ''}" for row in payload["datasets"]]
            return _out(args, payload, "\n".join(lines) or "(no datasets matched)")

        if verb == "show":
            payload = hub.show(value)
            if not payload.get("ok"):
                return _out(args, payload, f"error: {payload['err']}", code=1)
            lines = [f"{payload['repo']}",
                     f"  task       {payload.get('task')}",
                     f"  downloads  {payload.get('downloads')}  "
                     f"likes {payload.get('likes')}",
                     f"  license    {payload.get('license')}",
                     f"  base       {payload.get('base_model')}",
                     f"  updated    {payload.get('updated')}"]
            if payload.get("gguf_files"):
                lines.append(f"  gguf       {len(payload['gguf_files'])} files")
            return _out(args, payload, "\n".join(lines))

        if verb == "files":
            payload = hub.files(value, getattr(args, "revision", None) or "main")
            if not payload.get("ok"):
                return _out(args, payload, f"error: {payload['err']}", code=1)
            lines = [f"{payload['repo']}  {payload['file_count']} files  "
                     f"{payload.get('total_size')}"]
            for row in payload["files"][:20]:
                lines.append(f"  {row['size']:>8}  {row['file']}")
            return _out(args, payload, "\n".join(lines))

    except (ValueError, OSError) as exc:
        return _out(args, {"ok": False, "error": str(exc)},
                    f"error: {exc}", code=1)
    return _out(args, {"ok": False, "error": f"unknown verb: {verb}"},
                f"error: unknown verb {verb}", code=2)
