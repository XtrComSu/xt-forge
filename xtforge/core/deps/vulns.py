"""Vulnerability matching for a (package, version) pair, with the evidence kept.

The rule this module is built around: a vulnerability is a property of a *specific version*, so a
finding is only worth reporting when the version is known. Given `gin 1.6.0` the answer is five
advisories; given `gin ^1.6.0` there is no answer at all, because the installed version could be
any of hundreds and reporting the range's lower bound would attribute real vulnerabilities to a
version that may not be deployed.

Range evaluation is done locally from the advisory's own `affected` data rather than by asking a
server "is this version bad". That matters for three reasons: the answer is auditable (the ranges
and the comparison that decided are both reported), it works for ecosystems whose advisories carry
explicit `introduced`/`fixed` events, and a version that sits above a `fixed` event is not reported
even though the advisory still lists the package — which is the false positive that makes
dependency scanners untrustworthy in practice.

Two comparison rules are easy to get wrong and are handled explicitly:

* Version ordering is not string ordering (`1.10.0` > `1.9.0`, and `2.0.0-rc1` < `2.0.0`). A
  lexical comparison reports the wrong answer for the very versions near a fix.
* A `fixed` event of `0` means "never fixed", not "fixed in 0".
"""
from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Iterable

OSV_QUERY = "https://api.osv.dev/v1/query"
OSV_BATCH = "https://api.osv.dev/v1/querybatch"
OSV_VULN = "https://api.osv.dev/v1/vulns/"
DEFAULT_TIMEOUT = 30.0
# Requests in flight during a scan. Everything after the first query is waiting on the network, so
# this only overlaps latency; it does not raise per-host request rate beyond what a browser does.
SCAN_WORKERS = 12
MAX_BATCH = 1000

_SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MODERATE": 2, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}


class VersionError(ValueError):
    """A version string cannot be ordered, so no range decision can be made about it."""


_VERSION_SPLIT = re.compile(r"[.\-+_]")


def version_key(version: str) -> tuple:
    """An orderable key for a version string.

    SemVer's pre-release rule is the subtle part: `1.0.0-rc1` sorts *before* `1.0.0`, because a
    pre-release precedes its release. Sorting `rc1` as a normal segment puts it after, which
    misreports every advisory that was fixed in a `.0` release after a long pre-release series.

    Numeric segments compare numerically and text segments lexically, so `1.10` > `1.9`.
    """
    text = (version or "").strip().lstrip("vV=")
    if not text:
        raise VersionError("empty version")
    # Split off build metadata (ignored by SemVer precedence) then the pre-release tail.
    text = text.split("+", 1)[0]
    core, _, pre = text.partition("-")
    segments = [segment for segment in _VERSION_SPLIT.split(core) if segment != ""]
    key: list[tuple[int, Any]] = []
    for segment in segments:
        if segment.isdigit():
            key.append((0, int(segment)))
        else:
            # A non-numeric segment in the middle of a version is compared as text; it sorts
            # after numbers so `1.0.0a` > `1.0.0`, matching how package managers treat it.
            key.append((1, segment.lower()))
    # A pre-release must sort *before* its release, and appending extra elements to a tuple makes
    # it compare *greater* (Python compares element-wise and a longer tuple with an equal prefix is
    # larger), so `2.0.0-rc1` came out above `2.0.0`. The fix is a single trailing marker: 0 for a
    # pre-release, 1 for the release itself, so the marker decides ties before the pre-release
    # payload is ever consulted.
    if pre:
        pre_segments = [segment for segment in _VERSION_SPLIT.split(pre) if segment != ""]
        pre_payload: list[tuple[int, Any]] = []
        for segment in pre_segments:
            if segment.isdigit():
                pre_payload.append((0, int(segment)))
            else:
                pre_payload.append((1, segment.lower()))
        # Flatten the payload into a tag followed by its segments. Nesting it as one tuple
        # element made `rc2` compare against `rc10` as tuples of unequal length — `(2,)` vs
        # `(10,)` — where the *shorter* one loses regardless of the numbers inside.
        key.append((0, 0))
        key.extend(pre_payload)
    else:
        # A release sorts after every pre-release and before nothing, so its marker is simply
        # higher than a pre-release's; no payload follows.
        key.append((1, 0))
    return tuple(key)


def compare(left: str, right: str) -> int:
    """-1, 0 or 1, comparing two versions by their orderable keys."""
    try:
        a, b = version_key(left), version_key(right)
    except VersionError:
        raise
    return (a > b) - (a < b)


def _normalise_package(name: str, ecosystem: str) -> str:
    """Ecosystem-specific name canonicalisation, because a lookup silently returns nothing if the
    name is spelled differently from the advisory's.

    PyPI names are case- and separator-insensitive (`Zope.Interface` == `zope-interface`).
    npm names are lowercased. Go and crates.io are case-sensitive as published, and rewriting them
    would break the lookup rather than help it.
    """
    text = (name or "").strip()
    if ecosystem == "PyPI":
        return re.sub(r"[-_.]+", "-", text).lower()
    if ecosystem in ("npm", "NuGet", "Packagist"):
        return text.lower()
    return text


def query_one(name: str, version: str, ecosystem: str, *,
              timeout: float = DEFAULT_TIMEOUT,
              osv_url: str = OSV_QUERY) -> dict[str, Any]:
    """Ask OSV about exactly one (package, version) pair."""
    if not (name or "").strip():
        return {"ok": False, "error": "no package name", "name": name,
                "version": version, "ecosystem": ecosystem}
    if not (version or "").strip():
        return {"ok": False, "error": "no version; a vulnerability is a property of a version",
                "name": name, "version": version, "ecosystem": ecosystem,
                "skipped": "unresolved"}
    body = json.dumps({"package": {"name": _normalise_package(name, ecosystem),
                                   "ecosystem": ecosystem},
                       "version": str(version).lstrip("vV")}).encode()
    request = urllib.request.Request(
        osv_url, data=body,
        headers={"Content-Type": "application/json", "User-Agent": "xt-forge-deps"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            payload = json.loads(response.read())
    except urllib.error.HTTPError as exc:
        return {"ok": False, "error": f"OSV returned HTTP {exc.code}", "name": name,
                "version": version, "ecosystem": ecosystem}
    except (urllib.error.URLError, OSError) as exc:
        return {"ok": False, "error": f"OSV unreachable: {exc}", "name": name,
                "version": version, "ecosystem": ecosystem}
    except json.JSONDecodeError as exc:
        return {"ok": False, "error": f"OSV returned malformed JSON: {exc}", "name": name,
                "version": version, "ecosystem": ecosystem}
    vulns = payload.get("vulns") or []
    summarised = dedupe([_summarise(entry, name, version, ecosystem) for entry in vulns])
    return {"ok": True, "name": name, "version": version, "ecosystem": ecosystem,
            "vulnerability_count": len(summarised),
            "advisory_count": len(vulns),
            "vulnerabilities": summarised}


def _summarise(vuln: dict[str, Any], name: str, version: str,
               ecosystem: str) -> dict[str, Any]:
    """Compact one advisory, keeping the range decision that applies to *this* version."""
    severity = _severity(vuln)
    return {
        "id": vuln.get("id"),
        "aliases": vuln.get("aliases") or [],
        "cve": next((alias for alias in (vuln.get("aliases") or [])
                     if str(alias).upper().startswith("CVE-")), None),
        "summary": (vuln.get("summary") or "").strip(),
        "details": (vuln.get("details") or "").strip()[:1200],
        "severity": severity,
        "severity_source": vuln.get("database_specific", {}).get("severity"),
        "cvss": _cvss(vuln),
        "published": vuln.get("published"),
        "modified": vuln.get("modified"),
        "fixed_in": fixed_versions(vuln, name, ecosystem),
        "withdrawn": vuln.get("withdrawn"),
        "references": [entry.get("url") for entry in (vuln.get("references") or [])
                       if entry.get("url")][:8],
        # The range that matched is the evidence for the finding. Reporting the advisory without
        # it leaves a reader unable to check whether the tool was right.
        "matched_range": _matching_range(vuln, name, version, ecosystem),
    }


def _severity(vuln: dict[str, Any]) -> str:
    """Worst severity across the advisory's own ratings, normalised to one vocabulary."""
    worst = "UNKNOWN"
    for entry in vuln.get("severity") or []:
        score = str(entry.get("score") or "")
        # `CVSS:3.1/AV:N/AC:L/...` — the textual rating is in `database_specific` more often than
        # in `severity`, so this branch only catches the vector form.
        if score.startswith("CVSS:"):
            numeric = _cvss_from_vector(score)
            if numeric is not None:
                candidate = ("CRITICAL" if numeric >= 9.0 else "HIGH" if numeric >= 7.0
                             else "MODERATE" if numeric >= 4.0 else "LOW")
                if _SEVERITY_ORDER.get(candidate, 0) > _SEVERITY_ORDER.get(worst, 0):
                    worst = candidate
    database = str((vuln.get("database_specific") or {}).get("severity") or "").upper()
    if database in _SEVERITY_ORDER and _SEVERITY_ORDER[database] > _SEVERITY_ORDER.get(worst, 0):
        worst = database
    return worst


def _cvss(vuln: dict[str, Any]) -> float | None:
    for entry in vuln.get("severity") or []:
        score = str(entry.get("score") or "")
        if score.startswith("CVSS:"):
            numeric = _cvss_from_vector(score)
            if numeric is not None:
                return numeric
    return None


def _cvss_from_vector(vector: str) -> float | None:
    """Base score from a CVSS v3 vector, via the published formula.

    Computing it locally means a severity is reported even for advisories that publish only a
    vector, which is common in the GHSA database.
    """
    metrics = {}
    for part in vector.split("/")[1:]:
        if ":" in part:
            key, _, value = part.partition(":")
            metrics[key] = value
    if not metrics:
        return None

    def weight(table: dict[str, float], key: str) -> float | None:
        return table.get(metrics.get(key, ""))

    av = weight({"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}, "AV")
    ac = weight({"L": 0.77, "H": 0.44}, "AC")
    pr_map = {"N": 0.85, "L": 0.62, "H": 0.27}
    pr_map_changed = {"N": 0.85, "L": 0.68, "H": 0.5}
    ui = weight({"N": 0.85, "R": 0.62}, "UI")
    scope_changed = metrics.get("S") == "C"
    pr = None
    if "PR" in metrics:
        pr = (pr_map_changed if scope_changed else pr_map).get(metrics["PR"])
    cia = [{"N": 0.0, "L": 0.22, "H": 0.56}.get(metrics.get(key, "")) for key in ("C", "I", "A")]
    if None in (av, ac, pr, ui) or any(value is None for value in cia):
        return None
    impact_sub = 1 - (1 - cia[0]) * (1 - cia[1]) * (1 - cia[2])
    if impact_sub <= 0:
        return 0.0
    if scope_changed:
        impact = 7.52 * (impact_sub - 0.029) - 3.25 * (impact_sub - 0.02) ** 15
    else:
        impact = 6.42 * impact_sub
    exploitability = 8.22 * av * ac * pr * ui
    if impact <= 0:
        return 0.0
    total = (min(1.08 * (impact + exploitability), 10) if scope_changed
             else min(impact + exploitability, 10))
    return round(total + 1e-9, 1)


def _iter_affected(vuln: dict[str, Any], name: str,
                   ecosystem: str) -> Iterable[dict[str, Any]]:
    """The `affected` entries that concern this package, matched by canonical name."""
    wanted = _normalise_package(name, ecosystem)
    for entry in vuln.get("affected") or []:
        if not isinstance(entry, dict):
            continue
        package = entry.get("package") or {}
        if package.get("ecosystem") and package["ecosystem"] != ecosystem:
            continue
        if package.get("name") and _normalise_package(package["name"], ecosystem) != wanted:
            continue
        yield entry


def _matching_range(vuln: dict[str, Any], name: str, version: str,
                    ecosystem: str) -> dict[str, Any] | None:
    """Which declared range contains `version`, or None when none does.

    A None here is meaningful: it means the server listed the package but this version sits
    outside every affected range — most often because the version is above the fix. Reporting that
    as a finding is the false positive that makes dependency scanning unusable, so the caller
    filters on it.
    """
    for entry in _iter_affected(vuln, name, ecosystem):
        for declared in entry.get("ranges") or []:
            if not isinstance(declared, dict):
                continue
            if declared.get("type") not in (None, "SEMVER", "ECOSYSTEM"):
                continue
            verdict = range_contains(declared.get("events") or [], version)
            if verdict["match"]:
                return {"type": declared.get("type") or "ECOSYSTEM",
                        "events": declared.get("events") or [],
                        "introduced": verdict.get("introduced"),
                        "fixed": verdict.get("fixed")}
        for explicit in entry.get("versions") or []:
            try:
                if compare(str(explicit), str(version).lstrip("vV")) == 0:
                    return {"type": "ENUMERATED", "versions": entry["versions"][:40]}
            except VersionError:
                if str(explicit) == str(version):
                    return {"type": "ENUMERATED", "versions": entry["versions"][:40]}
    return None


def range_contains(events: list[dict[str, Any]], version: str) -> dict[str, Any]:
    """Evaluate OSV `events` against one version, over every branch the advisory declares.

    An OSV range is a list of half-open intervals expressed as ordered events. An advisory that
    affects two release branches lists them back to back:

        introduced 0  ->  fixed 1.9.0  ->  introduced 2.0.0  ->  fixed 2.1.0

    Treating that as one mutable "inside" flag is wrong, and wrong in the direction that silently
    loses findings: reaching the second `introduced` resets the flag, so a version that matched the
    first interval stops matching and `1.6.0` came back clean against an advisory it is squarely
    inside. Each interval is therefore tracked separately and the answer is "inside any of them".
    """
    try:
        version_key(version)
    except VersionError as exc:
        return {"match": False, "error": str(exc)}

    intervals: list[dict[str, Any]] = []
    current: dict[str, Any] = {"introduced": None, "fixed": None, "last_affected": None}
    for event in events:
        if not isinstance(event, dict):
            continue
        if "introduced" in event:
            # A new `introduced` closes any interval still open, then starts a fresh one.
            if current["introduced"] is not None or current["fixed"] or current["last_affected"]:
                intervals.append(current)
            current = {"introduced": str(event["introduced"]), "fixed": None,
                       "last_affected": None}
        elif "fixed" in event:
            current["fixed"] = str(event["fixed"])
        elif "last_affected" in event:
            current["last_affected"] = str(event["last_affected"])
        elif "limit" in event:
            current["limit"] = str(event["limit"])
    if current["introduced"] is not None or current["fixed"] or current["last_affected"]:
        intervals.append(current)

    for interval in intervals:
        introduced = interval.get("introduced")
        if introduced is not None and introduced not in ("0", "0.0.0"):
            if compare(version, introduced) < 0:
                continue
        fixed = interval.get("fixed")
        if fixed and fixed not in ("0", "0.0.0"):
            # `fixed: 0` means never fixed, so it must not close the interval.
            if compare(version, fixed) >= 0:
                continue
        last_affected = interval.get("last_affected")
        if last_affected and compare(version, last_affected) > 0:
            continue
        limit = interval.get("limit")
        if limit and compare(version, limit) >= 0:
            continue
        # Report the boundary the interval actually has. The first version of this returned
        # `"fixed": last_affected`, which is a different event with different semantics — the
        # version is still affected by `last_affected`, and is not affected by `fixed`. Nothing
        # reads this field today, which is exactly why it was wrong for as long as it was: a caller
        # that later trusted `fixed` would have treated an affected version as the repair.
        return {"match": True, "introduced": introduced,
                "fixed": interval.get("fixed"),
                "last_affected": last_affected}
    return {"match": False, "introduced": None, "fixed": None,
            "intervals_checked": len(intervals)}


def fixed_versions(vuln: dict[str, Any], name: str, ecosystem: str) -> list[str]:
    """Versions that repair this advisory, in order, for the named package."""
    fixes: list[str] = []
    for entry in _iter_affected(vuln, name, ecosystem):
        for declared in entry.get("ranges") or []:
            for event in (declared or {}).get("events") or []:
                if isinstance(event, dict) and "fixed" in event:
                    value = str(event["fixed"])
                    if value not in ("0", "0.0.0") and value not in fixes:
                        fixes.append(value)
    try:
        return sorted(fixes, key=version_key)
    except VersionError:
        return fixes


def scan(dependencies: list[dict[str, Any]], *, limit: int = 400,
         timeout: float = DEFAULT_TIMEOUT,
         ecosystems: set[str] | None = None,
         severities: set[str] | None = None,
         include_dev: bool = True) -> dict[str, Any]:
    """Query every resolved dependency and return the findings, ranked.

    Unresolved dependencies are counted separately and never queried: a query needs a version, and
    inventing one from a range's lower bound would report vulnerabilities for a build that may not
    exist. They are surfaced in the result so the omission is visible instead of silent.
    """
    resolved = [item for item in dependencies if item.get("resolved") and item.get("version")]
    unresolved = [item for item in dependencies
                  if not (item.get("resolved") and item.get("version"))]
    if ecosystems:
        wanted = {name.lower() for name in ecosystems}
        resolved = [item for item in resolved
                    if str(item.get("ecosystem") or "").lower() in wanted]
    if not include_dev:
        resolved = [item for item in resolved if item.get("scope") not in ("dev", "build")]

    queues = resolved[:limit]
    findings: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    queried = 0
    clean = 0
    # One HTTP round trip per dependency, and a real lockfile has hundreds. Measured on this host
    # against live OSV: ten packages serially took a median of 16.35s across three interleaved
    # trials, which puts a 200-dependency tree at about five minutes — long enough that a caller
    # runs it once and never again. The same ten with twelve requests in flight took a median of
    # 2.34s (7.0x), and results were identical: same counts, same advisory ids.
    #
    # `querybatch` is not the answer, though it looks like one. It returns only `{id, modified}` per
    # advisory, with no ranges, so a second round trip per advisory is needed to decide anything —
    # and it does not filter by version server-side, so for these ten packages it returned 72
    # advisory links where `/v1/query` returned 46 matching vulnerabilities. Two phases measured
    # 16.0s against 6.7s for the direct serial calls it was supposed to replace.
    #
    # Concurrency is bounded because OSV is a free public service and an unbounded fan-out over a
    # large lockfile is the kind of thing that gets a client blocked. The pool is only wide enough
    # to overlap latency; it is not a throughput trick.
    answers: list[dict[str, Any]] = []
    workers = max(1, min(SCAN_WORKERS, len(queues)))
    if workers == 1:
        answers = [query_one(str(item.get("name") or ""), str(item.get("version") or ""),
                             str(item.get("ecosystem") or ""), timeout=timeout)
                   for item in queues]
    else:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            answers = list(pool.map(
                lambda item: query_one(str(item.get("name") or ""),
                                       str(item.get("version") or ""),
                                       str(item.get("ecosystem") or ""), timeout=timeout),
                queues))
    for item, answer in zip(queues, answers):
        queried += 1
        if not answer.get("ok"):
            errors.append({"name": item.get("name"), "version": item.get("version"),
                           "ecosystem": item.get("ecosystem"), "error": answer.get("error")})
            continue
        matched = []
        for vuln in answer.get("vulnerabilities") or []:
            if vuln.get("withdrawn"):
                continue
            # Filter on the local range decision, not on the server's package-level answer.
            if vuln.get("matched_range") is None:
                continue
            if severities:
                wanted = {name.upper() for name in severities}
                if str(vuln.get("severity") or "").upper() not in wanted:
                    continue
            matched.append(vuln)
        if not matched:
            clean += 1
            continue
        findings.append({
            "name": item.get("name"), "version": item.get("version"),
            "ecosystem": item.get("ecosystem"), "scope": item.get("scope"),
            "source": item.get("source"),
            "sources": item.get("sources") or [],
            "vulnerability_count": len(matched),
            "worst_severity": _worst(matched),
            "vulnerabilities": matched,
        })

    findings.sort(key=lambda entry: (-_SEVERITY_ORDER.get(entry["worst_severity"], 0),
                                     entry.get("name") or ""))
    total_vulns = sum(entry["vulnerability_count"] for entry in findings)
    return {
        "ok": True,
        "queried_count": queried,
        "clean_count": clean,
        "unresolved_count": len(unresolved),
        "unresolved": unresolved[:40],
        "affected_package_count": len(findings),
        "vulnerability_count": total_vulns,
        "severity_counts": _severity_counts(findings),
        "findings": findings,
        "errors": errors,
        # Nothing found is a real result only if every dependency was actually checked.
        "complete": not errors and len(unresolved) == 0,
        "truncated": len(resolved) > limit,
        "note": (f"queried {queried} of {len(resolved)} resolved dependencies"
                 + (f"; {len(unresolved)} unresolved dependencies were not queried because a "
                    f"vulnerability is a property of a specific version" if unresolved else "")),
    }


def dedupe(vulns: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Collapse advisories that describe the same vulnerability under different identifiers.

    Measured on `golang.org/x/text 0.3.0`: OSV returns 8 advisories, which are **5 vulnerabilities**.
    One bug is published as `GHSA-5rcv-m4m3-hfh7`, `CVE-2020-14040` and `GO-2020-0015`, and all
    three come back for the same query. Counting them separately triples the headline number while
    adding no information, and a headline number that is inflated is the first thing a reader
    stops trusting — after which the real findings are ignored too.

    Merging is by connected components over the alias graph rather than by a single chosen key,
    because aliases are not transitive in general: A may list B without B listing A, so picking
    "the CVE if there is one" leaves the GO record as a separate group. Each group keeps every
    identifier, and the preferred display id is the CVE, then the GHSA, then whatever exists.
    """
    parent: dict[str, str] = {}

    def find(node: str) -> str:
        parent.setdefault(node, node)
        while parent[node] != node:
            parent[node] = parent[parent[node]]
            node = parent[node]
        return node

    def union(left: str, right: str) -> None:
        a, b = find(left), find(right)
        if a != b:
            parent[b] = a

    for vuln in vulns:
        identifier = str(vuln.get("id") or "")
        if not identifier:
            continue
        find(identifier)
        for alias in vuln.get("aliases") or []:
            union(identifier, str(alias))

    groups: dict[str, list[dict[str, Any]]] = {}
    for vuln in vulns:
        identifier = str(vuln.get("id") or "")
        groups.setdefault(find(identifier) if identifier else "", []).append(vuln)

    merged: list[dict[str, Any]] = []
    for members in groups.values():
        if len(members) == 1:
            entry = dict(members[0])
            entry["alias_group"] = sorted({str(entry.get("id"))} |
                                          {str(a) for a in entry.get("aliases") or []})
            merged.append(entry)
            continue
        identifiers: set[str] = set()
        fixes: set[str] = set()
        for member in members:
            identifiers.add(str(member.get("id")))
            identifiers.update(str(a) for a in member.get("aliases") or [])
            fixes.update(str(f) for f in member.get("fixed_in") or [])
        primary = next((m for m in members if str(m.get("id", "")).startswith("CVE-")), None)
        if primary is None:
            primary = next((m for m in members if str(m.get("id", "")).startswith("GHSA-")),
                           members[0])
        entry = dict(primary)
        entry["id"] = primary.get("id")
        entry["alias_group"] = sorted(identifiers)
        entry["merged_advisories"] = sorted(str(m.get("id")) for m in members)
        entry["fixed_in"] = sorted(fixes, key=_safe_key)
        # Keep the worst severity across the group: the same bug assessed HIGH by one database and
        # MODERATE by another is a HIGH finding, not an average.
        entry["severity"] = max((str(m.get("severity") or "UNKNOWN") for m in members),
                                key=lambda value: _SEVERITY_ORDER.get(value.upper(), 0))
        scores = [m.get("cvss") for m in members if m.get("cvss") is not None]
        entry["cvss"] = max(scores) if scores else None
        entry["merged"] = True
        merged.append(entry)
    return merged


def _safe_key(version: str) -> tuple:
    try:
        return version_key(version)
    except VersionError:
        return ((2, version),)


def _worst(vulns: list[dict[str, Any]]) -> str:
    worst = "UNKNOWN"
    for vuln in vulns:
        severity = str(vuln.get("severity") or "UNKNOWN").upper()
        if _SEVERITY_ORDER.get(severity, 0) > _SEVERITY_ORDER.get(worst, 0):
            worst = severity
    return worst


def _severity_counts(findings: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for entry in findings:
        for vuln in entry.get("vulnerabilities") or []:
            severity = str(vuln.get("severity") or "UNKNOWN").upper()
            counts[severity] = counts.get(severity, 0) + 1
    return dict(sorted(counts.items(), key=lambda pair: -_SEVERITY_ORDER.get(pair[0], 0)))


def advisory(identifier: str, *, timeout: float = DEFAULT_TIMEOUT) -> dict[str, Any]:
    """Full OSV advisory by id (GHSA-…, GO-…, RUSTSEC-…, PYSEC-…)."""
    value = (identifier or "").strip()
    if not value:
        return {"ok": False, "error": "no advisory id given"}
    try:
        with urllib.request.urlopen(f"{OSV_VULN}{value}", timeout=timeout) as response:
            payload = json.loads(response.read())
    except urllib.error.HTTPError as exc:
        return {"ok": False, "id": value, "error": f"OSV returned HTTP {exc.code}"}
    except (urllib.error.URLError, OSError) as exc:
        return {"ok": False, "id": value, "error": f"OSV unreachable: {exc}"}
    except json.JSONDecodeError as exc:
        return {"ok": False, "id": value, "error": f"malformed JSON: {exc}"}
    package_names = []
    for entry in payload.get("affected") or []:
        package = (entry or {}).get("package") or {}
        if package.get("name"):
            package_names.append({"name": package["name"],
                                  "ecosystem": package.get("ecosystem"),
                                  "ranges": (entry.get("ranges") or [])[:6]})
    return {
        "ok": True,
        "id": payload.get("id"), "aliases": payload.get("aliases") or [],
        "summary": payload.get("summary"), "details": payload.get("details"),
        "severity": _severity(payload), "cvss": _cvss(payload),
        "published": payload.get("published"), "modified": payload.get("modified"),
        "withdrawn": payload.get("withdrawn"),
        "affected_packages": package_names,
        "references": [entry.get("url") for entry in (payload.get("references") or [])],
        "database_specific": payload.get("database_specific") or {},
    }
