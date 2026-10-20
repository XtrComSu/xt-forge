"""Keyless threat intelligence.

Every source here answers without an API key, which is why they were chosen:
a tool that needs a signup is a tool that is empty when it matters.

    xtforge intel ip 8.8.8.8            ports, hostnames, vulns, noise
    xtforge intel cve CVE-2024-3094     NVD detail + EPSS + KEV membership
    xtforge intel kev [--query x]       CISA known-exploited catalog
    xtforge intel search openssh        NVD keyword search
    xtforge intel hash <md5|sha1|sha256> known-file lookup

This is the other half of `re ioc`: extract indicators from a binary, then
enrich them. Sources fail independently — a dead upstream degrades one field,
it does not fail the query.

Nothing here sends anything but the indicator itself. Never pass a secret.
"""
from __future__ import annotations

import ipaddress
import re
from typing import Any

from .. import net

SOURCES = {
    "internetdb": "https://internetdb.shodan.io — ports, hostnames, vulns (free)",
    "greynoise": "https://api.greynoise.io/v3/community — scanning noise (free)",
    "nvd": "https://services.nvd.nist.gov/rest/json/cves/2.0 — CVE detail (free)",
    "epss": "https://api.first.org/data/v1/epss — exploit probability (free)",
    "kev": "https://www.cisa.gov/.../known_exploited_vulnerabilities.json (free)",
    "circl": "https://hashlookup.circl.lu — known-file lookup (free)",
    "dns": "system resolver — A, AAAA, MX, NS, TXT, CNAME (free)",
    "virustotal": "https://www.virustotal.com/api/v3 — needs XT_VT_KEY",
    "malwarebazaar": "https://mb-api.abuse.ch/api/v1 — needs XT_ABUSECH_KEY",
}

# Optional keys. When present the source joins the answer; when absent the
# verb still works. That way buying a key later needs no code change.
KEYS = {
    "virustotal": ("XT_VT_KEY", "VT_API_KEY", "VIRUSTOTAL_API_KEY"),
    "malwarebazaar": ("XT_ABUSECH_KEY", "ABUSECH_AUTH_KEY"),
}

CVE_ID = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.IGNORECASE)
HOSTNAME = re.compile(
    r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$",
    re.IGNORECASE)
HASH_LEN = {32: "md5", 40: "sha1", 64: "sha256"}
KEV_TTL = 6 * 3600
NVD_TTL = 24 * 3600
IP_TTL = 3600


def _key(name: str) -> str:
    """First configured env var for a source, or ''."""
    import os
    for candidate in KEYS.get(name, ()):
        value = (os.environ.get(candidate) or "").strip()
        if value:
            return value
    return ""


def key_status() -> dict[str, bool]:
    return {name: bool(_key(name)) for name in KEYS}


def sources() -> dict[str, Any]:
    keys = key_status()
    return {"ok": True, "count": len(SOURCES), "sources": SOURCES,
            "keys": keys,
            "active": [name for name, has in keys.items() if has]
                      + ["internetdb", "greynoise", "nvd", "epss", "kev",
                         "circl"],
            "note": "all free sources need no signup; key-gated ones join "
                    "automatically when the env var is set"}


def _clean(value: str) -> str:
    return (value or "").strip()


# ------------------------------------------------------------------------ ip

def ip(address: str) -> dict[str, Any]:
    """Reputation and exposure for one IP address."""
    value = _clean(address)
    try:
        parsed = ipaddress.ip_address(value)
    except ValueError:
        return {"ok": False, "err": f"not an IP address: {value[:40]!r}"}
    if parsed.is_private or parsed.is_loopback or parsed.is_reserved:
        return {"ok": False, "err": "private, loopback or reserved address — "
                                    "nothing upstream can say anything useful"}

    result: dict[str, Any] = {"ok": True, "ip": str(parsed), "sources": {}}

    ok, payload, err = net.get_json(
        f"https://internetdb.shodan.io/{parsed}", ttl=IP_TTL)
    if ok and isinstance(payload, dict):
        result["sources"]["internetdb"] = {
            "ports": payload.get("ports") or [],
            "hostnames": (payload.get("hostnames") or [])[:10],
            "tags": payload.get("tags") or [],
            "cpes": (payload.get("cpes") or [])[:10],
            "vulns": payload.get("vulns") or [],
        }
        result["ports"] = result["sources"]["internetdb"]["ports"]
        result["vulns"] = result["sources"]["internetdb"]["vulns"]
        result["hostnames"] = result["sources"]["internetdb"]["hostnames"]
    else:
        result["sources"]["internetdb"] = {"error": err or "no data"}

    ok, payload, err = net.get_json(
        f"https://api.greynoise.io/v3/community/{parsed}", ttl=IP_TTL)
    if ok and isinstance(payload, dict):
        result["sources"]["greynoise"] = {
            "noise": payload.get("noise"),
            "riot": payload.get("riot"),
            "classification": payload.get("classification"),
            "name": payload.get("name"),
            "last_seen": payload.get("last_seen"),
        }
        result["noise"] = payload.get("noise")
        result["classification"] = payload.get("classification")
    elif isinstance(payload, dict) and payload.get("message"):
        result["sources"]["greynoise"] = {"verdict": payload.get("message"),
                                          "noise": payload.get("noise", False)}
    else:
        result["sources"]["greynoise"] = {"error": err or "no data"}

    token = _key("virustotal")
    if token:
        ok, payload, err = net.get_json(
            f"https://www.virustotal.com/api/v3/ip_addresses/{parsed}",
            headers={"x-apikey": token}, ttl=IP_TTL)
        if ok and isinstance(payload, dict):
            attrs = (payload.get("data") or {}).get("attributes") or {}
            stats = attrs.get("last_analysis_stats") or {}
            result["sources"]["virustotal"] = {
                "malicious": stats.get("malicious"),
                "suspicious": stats.get("suspicious"),
                "harmless": stats.get("harmless"),
                "undetected": stats.get("undetected"),
                "country": attrs.get("country"),
                "asn": attrs.get("asn"),
                "as_owner": attrs.get("as_owner"),
                "reputation": attrs.get("reputation"),
            }
        else:
            result["sources"]["virustotal"] = {"error": err or "no data"}

    flags = []
    if result.get("vulns"):
        flags.append(f"{len(result['vulns'])} known CVEs exposed")
    if result.get("noise"):
        flags.append("observed scanning")
    if result.get("classification") in ("malicious", "benign"):
        flags.append(f"greynoise: {result['classification']}")
    vt = result["sources"].get("virustotal") or {}
    if (vt.get("malicious") or 0) > 0:
        flags.append(f"virustotal: {vt['malicious']} engines flagged it")
    degraded = [name for name, info in result["sources"].items()
                if isinstance(info, dict) and info.get("error")]
    if degraded and len(degraded) == len(result["sources"]):
        result["degraded"] = True
        flags.append("no source answered (offline or rate-limited)")
    result["flags"] = flags
    result["note"] = "exposure is not intent: open ports and CVEs are facts, " \
                     "attribution is not"
    return result


# -------------------------------------------------------------------- domain

def _spoofability(txt: list[str], dmarc: list[str]) -> list[str]:
    """What an attacker can do with this domain's mail identity."""
    notes: list[str] = []
    spf = next((t for t in txt if t.lower().startswith("v=spf1")), None)
    if not spf:
        notes.append("no SPF record")
    elif "+all" in spf or spf.strip().endswith("?all"):
        notes.append("SPF allows everything (`all`)")
    elif spf.strip().endswith("~all"):
        notes.append("SPF soft-fails (`~all`) — spoofed mail may be delivered")
    elif spf.strip().endswith("-all"):
        notes.append("SPF hard-fails (`-all`)")

    policy = next((t for t in dmarc if "p=" in t.lower()), None)
    if not policy:
        notes.append("no DMARC record — receivers decide alone")
    else:
        lowered = policy.lower()
        for level in ("p=reject", "p=quarantine", "p=none"):
            if level in lowered:
                notes.append(f"DMARC {level.split('=')[1]}"
                             + (" (monitor only)" if level == "p=none" else ""))
                break
    return notes


def domain(name: str) -> dict[str, Any]:
    """DNS records plus the mail-identity posture that makes spoofing easy."""
    value = _clean(name).lower().rstrip(".")
    if not HOSTNAME.match(value):
        return {"ok": False, "err": f"not a domain name: {value[:60]!r}"}

    from .. import dns as dnsclient
    resolved = dnsclient.resolve(value)
    records = resolved.get("records") or {}
    addresses = list(records.get("A") or []) + list(records.get("AAAA") or [])
    txt = records.get("TXT") or []

    dmarc_records: list[str] = []
    if resolved.get("ok"):
        answer = dnsclient.query(f"_dmarc.{value}", "TXT")
        dmarc_records = [r["value"] for r in answer.get("records") or []]

    result: dict[str, Any] = {
        "ok": True, "domain": value,
        "addresses": addresses,
        "nameservers": records.get("NS") or [],
        "mail": records.get("MX") or [],
        "txt": txt[:8],
        "dmarc": dmarc_records,
        "cname": records.get("CNAME") or [],
        "nxdomain": resolved.get("nxdomain", False),
        "resolver": resolved.get("resolver"),
        "dns_errors": resolved.get("errors") or [],
    }
    result["mail_posture"] = _spoofability(txt, dmarc_records)

    token = _key("virustotal")
    if token:
        ok, payload, err = net.get_json(
            f"https://www.virustotal.com/api/v3/domains/{value}",
            headers={"x-apikey": token}, ttl=IP_TTL)
        if ok and isinstance(payload, dict):
            attrs = (payload.get("data") or {}).get("attributes") or {}
            stats = attrs.get("last_analysis_stats") or {}
            result["sources"] = {"virustotal": {
                "malicious": stats.get("malicious"),
                "suspicious": stats.get("suspicious"),
                "categories": list((attrs.get("categories") or {}).values())[:4],
                "reputation": attrs.get("reputation"),
            }}
        else:
            result["sources"] = {"virustotal": {"error": err or "no data"}}
    return result


# ----------------------------------------------------------------------- cve

def _nvd_detail(cve_id: str) -> tuple[dict[str, Any] | None, str]:
    ok, payload, err = net.get_json(
        "https://services.nvd.nist.gov/rest/json/cves/2.0"
        f"?cveId={net.quote(cve_id)}", ttl=NVD_TTL, timeout=30)
    if not ok or not isinstance(payload, dict):
        return None, err or "no data"
    items = payload.get("vulnerabilities") or []
    if not items:
        return None, "not found"
    cve = items[0].get("cve") or {}

    description = ""
    for entry in cve.get("descriptions") or []:
        if entry.get("lang") == "en":
            description = entry.get("value") or ""
            break

    scores: list[dict[str, Any]] = []
    metrics = cve.get("metrics") or {}
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        for entry in metrics.get(key) or []:
            data = entry.get("cvssData") or {}
            scores.append({
                "version": data.get("version") or key.replace("cvssMetricV", ""),
                "score": data.get("baseScore"),
                "severity": data.get("baseSeverity") or entry.get("baseSeverity"),
                "vector": data.get("vectorString"),
                "type": entry.get("type"),
            })
            break          # primary metric of each version is enough

    cwes = []
    for weakness in cve.get("weaknesses") or []:
        for entry in weakness.get("description") or []:
            if entry.get("value", "").startswith("CWE-"):
                cwes.append(entry["value"])
    return {
        "id": cve.get("id") or cve_id,
        "description": description[:1200],
        "published": cve.get("published"),
        "modified": cve.get("lastModified"),
        "status": cve.get("vulnStatus"),
        "scores": scores,
        "cwes": sorted(set(cwes))[:6],
        "references": [r.get("url") for r in (cve.get("references") or [])][:6],
    }, ""


def _epss(cve_id: str) -> dict[str, Any]:
    ok, payload, err = net.get_json(
        f"https://api.first.org/data/v1/epss?cve={net.quote(cve_id)}", ttl=NVD_TTL)
    if not ok or not isinstance(payload, dict):
        return {"error": err or "no data"}
    rows = payload.get("data") or []
    if not rows:
        return {"error": "not scored"}
    row = rows[0]
    return {"score": float(row.get("epss") or 0),
            "percentile": float(row.get("percentile") or 0),
            "date": row.get("date")}


def _kev_catalog() -> tuple[list[dict[str, Any]], str]:
    ok, payload, err = net.get_json(
        "https://www.cisa.gov/sites/default/files/feeds/"
        "known_exploited_vulnerabilities.json", ttl=KEV_TTL, timeout=45)
    if not ok or not isinstance(payload, dict):
        return [], err or "no data"
    return payload.get("vulnerabilities") or [], ""


def _kev_entry(cve_id: str) -> dict[str, Any]:
    entries, err = _kev_catalog()
    if err:
        return {"error": err}
    for entry in entries:
        if (entry.get("cveID") or "").upper() == cve_id.upper():
            return {"listed": True,
                    "date_added": entry.get("dateAdded"),
                    "due_date": entry.get("dueDate"),
                    "vendor": entry.get("vendorProject"),
                    "product": entry.get("product"),
                    "name": entry.get("vulnerabilityName"),
                    "ransomware": entry.get("knownRansomwareCampaignUse")}
    return {"listed": False}


def cve(cve_id: str) -> dict[str, Any]:
    """One CVE: NVD detail, exploit probability, known exploitation."""
    value = _clean(cve_id).upper()
    if not CVE_ID.match(value):
        return {"ok": False, "err": f"not a CVE id: {value[:40]!r}"}

    detail, err = _nvd_detail(value)
    if detail is None:
        return {"ok": False, "err": err, "cve": value}

    epss = _epss(value)
    kev = _kev_entry(value)
    primary = detail["scores"][0] if detail["scores"] else {}

    risk = []
    if kev.get("listed"):
        risk.append("known exploited in the wild (CISA KEV)")
    if kev.get("ransomware") == "Known":
        risk.append("used in ransomware campaigns")
    probability = epss.get("score")
    if isinstance(probability, float) and probability >= 0.5:
        risk.append(f"high exploit probability ({probability:.0%})")

    return {"ok": True, "cve": value, "description": detail["description"],
            "severity": primary.get("severity"),
            "cvss": primary.get("score"), "vector": primary.get("vector"),
            "all_scores": detail["scores"], "published": detail["published"],
            "modified": detail["modified"], "status": detail["status"],
            "cwes": detail["cwes"], "epss": epss, "kev": kev, "risk": risk,
            "references": detail["references"]}


def kev(query: str | None = None, limit: int = 20) -> dict[str, Any]:
    """The CISA known-exploited catalog, newest first."""
    entries, err = _kev_catalog()
    if err:
        return {"ok": False, "err": err}
    needle = _clean(query or "").lower()
    if needle:
        entries = [e for e in entries
                   if needle in " ".join(str(v) for v in e.values()).lower()]
    entries = sorted(entries, key=lambda e: e.get("dateAdded") or "",
                     reverse=True)
    rows = [{"cve": e.get("cveID"), "vendor": e.get("vendorProject"),
             "product": e.get("product"),
             "name": (e.get("vulnerabilityName") or "")[:110],
             "added": e.get("dateAdded"),
             "ransomware": e.get("knownRansomwareCampaignUse")}
            for e in entries[:max(1, int(limit))]]
    return {"ok": True, "query": query or "", "matched": len(entries),
            "total_catalog": len(entries) if not needle else None,
            "entries": rows}


def search(keyword: str, limit: int = 10,
           since_days: int | None = None) -> dict[str, Any]:
    """NVD keyword search, compact. `since_days` narrows to recent entries."""
    value = _clean(keyword)
    if not value:
        return {"ok": False, "err": "search needs a keyword"}
    url = ("https://services.nvd.nist.gov/rest/json/cves/2.0"
           f"?keywordSearch={net.quote(value)}"
           f"&resultsPerPage={max(1, min(int(limit), 50))}")
    if since_days:
        from datetime import datetime, timedelta, timezone
        now = datetime.now(timezone.utc)
        # NVD rejects ranges longer than 120 days with a 404, so clamp rather
        # than fail: a clamped window is useful, an error is not.
        window = max(1, min(int(since_days), 120))
        start = now - timedelta(days=window)
        stamp = "%Y-%m-%dT%H:%M:%S.000"
        url += (f"&pubStartDate={start.strftime(stamp)}"
                f"&pubEndDate={now.strftime(stamp)}")
    ok, payload, err = net.get_json(url, ttl=NVD_TTL, timeout=40)
    if not ok or not isinstance(payload, dict):
        return {"ok": False, "err": err or "no data"}

    rows = []
    for item in payload.get("vulnerabilities") or []:
        cve = item.get("cve") or {}
        description = next((d.get("value") for d in (cve.get("descriptions") or [])
                            if d.get("lang") == "en"), "")
        score, severity = None, None
        metrics = cve.get("metrics") or {}
        for key in ("cvssMetricV31", "cvssMetricV40", "cvssMetricV30"):
            found = metrics.get(key) or []
            if found:
                data = found[0].get("cvssData") or {}
                score, severity = data.get("baseScore"), data.get("baseSeverity")
                break
        rows.append({"cve": cve.get("id"), "score": score,
                     "severity": severity, "published": cve.get("published"),
                     "description": (description or "")[:180]})
    if since_days:
        rows.sort(key=lambda r: r.get("published") or "", reverse=True)
    clamped = bool(since_days) and int(since_days) > 120
    return {"ok": True, "keyword": value,
            "since_days": min(int(since_days), 120) if since_days else None,
            "clamped": clamped,
            "total": payload.get("totalResults"), "returned": len(rows),
            "results": rows,
            "note": ("NVD limits date ranges to 120 days; window clamped"
                     if clamped else "")}


# ---------------------------------------------------------------------- hash

def file_hash(value: str) -> dict[str, Any]:
    """Is this file hash known to the CIRCL hashlookup corpus?"""
    digest = _clean(value).lower()
    if len(digest) not in HASH_LEN or not re.fullmatch(r"[0-9a-f]+", digest):
        return {"ok": False,
                "err": "expected a 32/40/64 character hex digest "
                       f"(got {len(digest)} chars)"}
    algorithm = HASH_LEN[len(digest)]
    result: dict[str, Any] = {"ok": True, "hash": digest, "algorithm": algorithm,
                              "sources": {}}

    ok, payload, err = net.get_json(
        f"https://hashlookup.circl.lu/lookup/{algorithm}/{digest}", ttl=NVD_TTL)
    if ok and isinstance(payload, dict):
        result.update({
            "known": True, "name": payload.get("FileName"),
            "product": payload.get("ProductName"),
            "publisher": payload.get("Publisher"),
            "version": payload.get("FileVersion"),
            "trust": payload.get("hashlookup:trust"),
            "known_malicious": payload.get("KnownMalicious"),
            "first_seen": payload.get("FirstSeen"),
        })
        result["sources"]["circl"] = {"known": True}
    else:
        result.update({"known": False,
                       "note": "not in the CIRCL known-file corpus — that is "
                               "not a verdict, most files are not"})
        result["sources"]["circl"] = {"error": err or "no data"}

    token = _key("virustotal")
    if token:
        ok, payload, err = net.get_json(
            f"https://www.virustotal.com/api/v3/files/{digest}",
            headers={"x-apikey": token}, ttl=NVD_TTL)
        if ok and isinstance(payload, dict):
            attrs = (payload.get("data") or {}).get("attributes") or {}
            stats = attrs.get("last_analysis_stats") or {}
            result["sources"]["virustotal"] = {
                "malicious": stats.get("malicious"),
                "suspicious": stats.get("suspicious"),
                "undetected": stats.get("undetected"),
                "type": attrs.get("type_description"),
                "names": (attrs.get("names") or [])[:4],
                "reputation": attrs.get("reputation"),
                "first_seen": attrs.get("first_submission_date"),
            }
            detections = stats.get("malicious") or 0
            if detections:
                result["malicious_detections"] = detections
        else:
            result["sources"]["virustotal"] = {"error": err or "no data"}

    token = _key("malwarebazaar")
    if token:
        ok, payload, err = net.get_json(
            "https://mb-api.abuse.ch/api/v1/", method="POST",
            form={"query": "get_info", "hash": digest},
            headers={"Auth-Key": token}, ttl=NVD_TTL)
        if ok and isinstance(payload, dict):
            data = (payload.get("data") or [{}])
            entry = data[0] if isinstance(data, list) and data else {}
            result["sources"]["malwarebazaar"] = {
                "status": payload.get("query_status"),
                "signature": entry.get("signature"),
                "file_type": entry.get("file_type"),
                "first_seen": entry.get("first_seen"),
                "tags": entry.get("tags"),
            }
            if entry.get("signature"):
                result["malware_family"] = entry["signature"]
        else:
            result["sources"]["malwarebazaar"] = {"error": err or "no data"}

    return result
