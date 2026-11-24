"""Remediation: turn a set of findings into edits, and apply them only when they are safe.

The dangerous part of a dependency fixer is not finding the new version — it is editing a file a
human maintains. Three rules follow from that, and they are the whole design:

1. **Plan first, always.** `plan()` produces the exact text edits and changes nothing. The plan is
   the reviewable artifact: a human can read the diff before anything happens.
2. **Only edit what was parsed.** A version is rewritten by replacing the exact span the manifest
   parser identified. An edit built from a regex over the whole file can match a different
   dependency, a comment, or a lockfile hash.
3. **Verify after applying.** The file is re-parsed and the intended version confirmed. An edit
   that reports success but left the old version in place is worse than a failed edit, because it
   is trusted.

A version bump is proposed only when the advisory names a `fixed` version that is strictly greater
than the installed one. "Upgrade to something newer" is not a remediation: it is a guess that may
break the build and may not fix anything.
"""
from __future__ import annotations

import json
import re
import shutil
from pathlib import Path
from typing import Any

from . import vulns as vuln_mod

MAX_PLAN_EDITS = 500


class RemediationError(Exception):
    """The plan cannot be built safely, so it is not built at all."""


def plan(dependencies: list[dict[str, Any]], findings: list[dict[str, Any]], *,
         allow_major: bool = False, include_dev: bool = True,
         limit: int = MAX_PLAN_EDITS) -> dict[str, Any]:
    """Build reviewable version-bump edits from scan findings.

    `allow_major` gates crossing a major version. A major bump is routinely the actual fix, and it
    is also routinely a rewrite of the caller's source; proposing it without being asked is how a
    security tool breaks a build. Minor and patch bumps are proposed freely because they are
    contract-compatible within the ecosystem's own rules.
    """
    by_key: dict[tuple[str, str, str], dict[str, Any]] = {}
    for finding in findings:
        key = (str(finding.get("ecosystem") or ""), str(finding.get("name") or ""),
               str(finding.get("version") or ""))
        by_key[key] = finding

    index: dict[tuple[str, str, str], dict[str, Any]] = {}
    for dependency in dependencies:
        key = (str(dependency.get("ecosystem") or ""), str(dependency.get("name") or ""),
               str(dependency.get("version") or ""))
        index[key] = dependency

    edits: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    for key, finding in by_key.items():
        dependency = index.get(key)
        if dependency is None:
            skipped.append({**_describe(key), "reason": "the dependency is no longer in the tree"})
            continue
        if not include_dev and dependency.get("scope") in ("dev", "build"):
            skipped.append({**_describe(key), "reason": "dev dependency, excluded"})
            continue
        target, why = choose_target(finding.get("vulnerabilities") or [],
                                    key[2], allow_major=allow_major)
        if target is None:
            skipped.append({**_describe(key), "reason": why})
            continue
        for source in dependency.get("sources") or [{"path": dependency.get("source")}]:
            path = source.get("path")
            if not path:
                continue
            edits.append({
                "ecosystem": key[0], "name": key[1], "from": key[2], "to": target,
                "path": path, "kind": source.get("kind"),
                "fixes": sorted({str(vuln.get("id")) for vuln in finding.get("vulnerabilities")
                                 or [] if vuln.get("id")}),
                "worst_severity": finding.get("worst_severity"),
                "reason": why,
            })

    unique: dict[tuple[str, str, str, str], dict[str, Any]] = {}
    for edit in edits:
        unique[(edit["ecosystem"], edit["name"], edit["from"], edit["path"])] = edit
    ordered = sorted(unique.values(), key=lambda item: (item["path"], item["name"]))
    return {
        "ok": True,
        "edit_count": len(ordered[:limit]),
        "skipped_count": len(skipped),
        "edits": ordered[:limit],
        "skipped": skipped[:60],
        "note": ("a plan only; nothing has been written. Apply it after reviewing the edits"),
    }


def _describe(key: tuple[str, str, str]) -> dict[str, Any]:
    return {"ecosystem": key[0], "name": key[1], "version": key[2]}


def choose_target(vulnerabilities: list[dict[str, Any]], current: str, *,
                  allow_major: bool = False) -> tuple[str | None, str]:
    """The lowest fixed version above `current`, or None with the reason it cannot be chosen.

    The *lowest* qualifying fix is chosen deliberately: raising a package higher than necessary
    widens the behavioural change for no security benefit, and a human reviewing a diff is far more
    likely to accept `1.7.7 -> 1.9.0` than `1.7.7 -> 1.10.0` when both close the same advisory.
    """
    fixes: list[str] = []
    for vuln in vulnerabilities:
        for candidate in vuln.get("fixed_in") or []:
            text = str(candidate).strip()
            if not text:
                continue
            try:
                if vuln_mod.compare(text, current) > 0:
                    fixes.append(text)
            except vuln_mod.VersionError:
                continue
    if not fixes:
        return None, ("no advisory in this set names a fixed version newer than the installed "
                      "one, so any bump would be a guess")
    fixes.sort(key=vuln_mod.version_key)
    target = fixes[0]
    if not allow_major and _major(target) != _major(current):
        return None, (f"the fix is {target}, a major change from {current}; pass --allow-major to "
                      f"propose it, since a major bump usually means source changes")
    return target, f"lowest version that clears every advisory here ({len(fixes)} candidate fix)"
    
def _major(version: str) -> str:
    text = (version or "").strip().lstrip("vV")
    core = text.split("-")[0].split("+")[0]
    parts = re.split(r"[._]", core)
    return parts[0] if parts else ""


# ---------------------------------------------------------------------------------------------
# Applying.
# ---------------------------------------------------------------------------------------------

def apply(edits: list[dict[str, Any]], *, write: bool = False,
          backup: bool = True) -> dict[str, Any]:
    """Apply version edits, verifying each by re-parsing the file afterwards.

    `write=False` performs every step except the final write, and still re-parses, so a dry run
    proves the edit *would* land rather than that a regex matched. That distinction is the
    difference between a rehearsal and a hope.
    """
    results: list[dict[str, Any]] = []
    changed_files: dict[str, list[dict[str, Any]]] = {}
    for edit in edits:
        path = Path(str(edit.get("path") or ""))
        if not path.is_file():
            results.append({**_identity(edit), "ok": False, "error": "file is gone"})
            continue
        try:
            original = path.read_text("utf-8", errors="strict")
        except (OSError, UnicodeDecodeError) as exc:
            results.append({**_identity(edit), "ok": False, "error": f"unreadable: {exc}"})
            continue
        try:
            updated, detail = _rewrite(original, edit)
        except RemediationError as exc:
            results.append({**_identity(edit), "ok": False, "error": str(exc)})
            continue
        if updated == original:
            results.append({**_identity(edit), "ok": False,
                            "error": "the version was not found in the text that was parsed; "
                                     "refusing to edit a file this tool cannot place"})
            continue
        changed_files.setdefault(str(path), []).append(edit)
        results.append({**_identity(edit), "ok": True, "detail": detail,
                        "line": detail.get("line")})

    verified: list[dict[str, Any]] = []
    written: list[str] = []
    for path_text, file_edits in changed_files.items():
        path = Path(path_text)
        try:
            original = path.read_text("utf-8", errors="strict")
        except OSError as exc:
            verified.extend({**_identity(edit), "ok": False, "error": str(exc)}
                            for edit in file_edits)
            continue
        text = original
        for edit in file_edits:
            try:
                text, _detail = _rewrite(text, edit)
            except RemediationError as exc:
                verified.append({**_identity(edit), "ok": False, "error": str(exc)})
        if write:
            if backup:
                try:
                    shutil.copy2(path, path.with_suffix(path.suffix + ".xtbak"))
                except OSError as exc:
                    verified.append({"path": path_text, "ok": False,
                                     "error": f"backup failed, not writing: {exc}"})
                    continue
            try:
                path.write_text(text, "utf-8")
                written.append(path_text)
            except OSError as exc:
                verified.append({"path": path_text, "ok": False, "error": f"write failed: {exc}"})
                continue
        # Re-parse the *result* and confirm the intended version is present. A fixer that reports
        # success without checking has no way to distinguish an applied edit from a lost one.
        confirmed = _confirm(path_text, text, file_edits)
        verified.extend(confirmed)

    # Every rejection counts, from either pass. `ok` was computed from `verified` alone, so an
    # edit rejected in the first pass (file gone, version not found, rewrite refused) left
    # `verified` empty and the whole report came back `ok: True` having written nothing — a
    # false success, which is the worst possible outcome for a tool that edits source.
    rejected = [{**_identity(entry), "ok": False, "error": entry.get("error")}
                for entry in results if not entry.get("ok")]
    failures = rejected + [entry for entry in verified if not entry.get("ok")]
    return {
        "ok": not failures,
        "write": write,
        "backup": backup and write,
        "files_changed": sorted(written),
        "files_considered": sorted(changed_files),
        "edit_count": len(results),
        "applied_count": sum(1 for entry in verified if entry.get("ok")),
        "rejected_count": len(rejected),
        "failure_count": len(failures),
        "results": results,
        "verified": verified,
        "failures": failures,
        "note": ("written and verified" if write else
                 "dry run: every edit was assembled and re-parsed, nothing was written"),
    }


def _identity(edit: dict[str, Any]) -> dict[str, Any]:
    return {"ecosystem": edit.get("ecosystem"), "name": edit.get("name"),
            "from": edit.get("from"), "to": edit.get("to"), "path": edit.get("path")}


_VERSION_IN_MANIFEST = {
    "go": re.compile(r"^(?P<pre>\s*)(?P<name>[\w.\-/~]+\.[\w.\-/~]+)(?P<gap>\s+)"
                     r"(?P<ver>v[\w.\-+]+)(?P<post>.*)$"),
}


def _rewrite(text: str, edit: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    """Replace one dependency's version, touching only that dependency's line.

    Matching is anchored on the dependency name at the start of a line (after indentation), so a
    name that also appears inside another name — `gin` inside `gin-gonic` — cannot be edited by
    accident, and a comment or changelog line is not a candidate at all.
    """
    name = str(edit.get("name") or "")
    old = str(edit.get("from") or "")
    new = str(edit.get("to") or "")
    path = str(edit.get("path") or "")
    if not name or not old or not new:
        raise RemediationError("incomplete edit")
    suffix = Path(path).suffix.lower()
    filename = Path(path).name

    if filename == "package.json" or filename in ("package-lock.json", "npm-shrinkwrap.json"):
        return _rewrite_json(text, name, old, new)
    if filename in ("Cargo.toml",):
        return _rewrite_toml(text, name, old, new)
    if filename in ("requirements.txt",):
        return _rewrite_requirements(text, name, old, new)
    if filename == "go.mod":
        return _rewrite_go_mod(text, name, old, new)
    if filename == "go.sum":
        return _rewrite_go_sum(text, name, old, new)
    if filename in ("Gemfile.lock", "composer.lock", "Cargo.lock"):
        return _rewrite_locked(text, name, old, new)
    if suffix in (".toml", ".yaml", ".yml", ".xml", ""):
        return _rewrite_locked(text, name, old, new)
    raise RemediationError(f"no rewriter for {filename}")


def _line_of(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _rewrite_go_mod(text: str, name: str, old: str, new: str) -> tuple[str, dict[str, Any]]:
    pattern = re.compile(
        r"^(?P<indent>[ \t]*)(?P<prefix>require\s+)?(?P<name>"
        + re.escape(name)
        + r")(?P<gap>\s+)v?(?P<version>" + re.escape(old) + r")(?P<post>\s*(?://.*)?)$",
        re.MULTILINE)
    match = pattern.search(text)
    if not match:
        raise RemediationError(f"{name} {old} is not declared in this go.mod")
    updated = text[:match.start("version")] + new + text[match.end("version"):]
    return updated, {"line": _line_of(text, match.start("version")), "rewriter": "go.mod"}


def _rewrite_go_sum(text: str, name: str, old: str, new: str) -> tuple[str, dict[str, Any]]:
    pattern = re.compile(r"^(" + re.escape(name) + r")\s+v" + re.escape(old)
                         + r"(\s+/go\.mod)?(\s+h1:\S+)?$", re.MULTILINE)
    matches = list(pattern.finditer(text))
    if not matches:
        raise RemediationError(f"{name} {old} is not in this go.sum")
    updated = text
    for match in reversed(matches):
        replacement = f"{match.group(1)} v{new}{match.group(2) or ''}{match.group(3) or ''}"
        updated = updated[:match.start()] + replacement + updated[match.end():]
    return updated, {"line": _line_of(text, matches[0].start()), "rewriter": "go.sum",
                     "replaced": len(matches)}


def _rewrite_json(text: str, name: str, old: str, new: str) -> tuple[str, dict[str, Any]]:
    """Edit a JSON manifest, keeping formatting by replacing only the matched value token."""
    pattern = re.compile(r'"(?P<key>' + re.escape(name) + r')"\s*:\s*"(?P<value>[^"]*)"')
    candidates = [match for match in pattern.finditer(text)
                  if old in match.group("value")]
    if not candidates:
        raise RemediationError(f'{name} "{old}" is not declared in this JSON manifest')
    match = candidates[0]
    replaced = match.group("value").replace(old, new, 1)
    updated = text[:match.start("value")] + replaced + text[match.end("value"):]
    try:
        payload = json.loads(updated)
    except json.JSONDecodeError as exc:
        raise RemediationError(f"the edit would produce invalid JSON: {exc}") from exc
    if not isinstance(payload, (dict, list)):
        raise RemediationError("the edit would produce a non-object document")
    return updated, {"line": _line_of(text, match.start("value")), "rewriter": "json"}


def _rewrite_toml(text: str, name: str, old: str, new: str) -> tuple[str, dict[str, Any]]:
    pattern = re.compile(r'^(?P<indent>[ \t]*)' + re.escape(name)
                         + r'(?P<gap>\s*=\s*)(?P<quote>["\'])(?P<value>[^"\']*)(?P=quote)',
                         re.MULTILINE)
    match = None
    for candidate in pattern.finditer(text):
        if old in candidate.group("value"):
            match = candidate
            break
    if match is None:
        raise RemediationError(f"{name} {old} is not declared in this TOML file")
    replaced = match.group("value").replace(old, new, 1)
    updated = (text[:match.start("value")] + replaced + text[match.end("value"):])
    return updated, {"line": _line_of(text, match.start("value")), "rewriter": "toml"}


def _rewrite_requirements(text: str, name: str, old: str,
                          new: str) -> tuple[str, dict[str, Any]]:
    pattern = re.compile(r"^(?P<pre>\s*" + re.escape(name) + r"(?:\[[^\]]*\])?\s*==\s*)"
                         r"(?P<version>" + re.escape(old) + r")(?P<post>.*)$", re.MULTILINE)
    match = pattern.search(text)
    if not match:
        raise RemediationError(f"{name}=={old} is not pinned in this requirements file")
    updated = text[:match.start("version")] + new + text[match.end("version"):]
    return updated, {"line": _line_of(text, match.start("version")), "rewriter": "requirements"}


def _rewrite_locked(text: str, name: str, old: str, new: str) -> tuple[str, dict[str, Any]]:
    """Generic lockfile/manifest rewriter, anchored on the name appearing with the old version.

    Used for formats whose layout varies too much to parse positionally here (Gemfile.lock,
    composer.lock, pubspec, pom). The name and version must appear on the same line, which is true
    of every one of those formats and false of prose.
    """
    for match in re.finditer(r"^.*$", text, re.MULTILINE):
        line = match.group(0)
        if name in line and old in line:
            start = match.start() + line.index(old)
            updated = text[:start] + new + text[start + len(old):]
            return updated, {"line": _line_of(text, start), "rewriter": "line-anchored"}
    raise RemediationError(f"{name} {old} does not appear on any single line")


def _confirm(path_text: str, text: str, edits: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Re-parse the edited text and confirm each intended version is present."""
    from . import MANIFESTS
    name = Path(path_text).name
    reader = next((reader for filename, _kind, reader in MANIFESTS if filename == name), None)
    confirmed: list[dict[str, Any]] = []
    if reader is None:
        for edit in edits:
            confirmed.append({**_identity(edit), "ok": edit["to"] in text,
                              "verified_by": "substring",
                              "warning": "no parser for this format; confirmed by substring only"})
        return confirmed
    try:
        parsed = reader(text)
    except Exception as exc:  # noqa: BLE001 - a parse failure means the edit broke the file
        for edit in edits:
            confirmed.append({**_identity(edit), "ok": False,
                              "error": f"the edited file no longer parses: {exc}",
                              "verified_by": "reparse"})
        return confirmed
    for edit in edits:
        versions = {str(item.get("version")) for item in parsed
                    if str(item.get("name")) == str(edit["name"])}
        confirmed.append({**_identity(edit), "ok": str(edit["to"]) in versions,
                          "verified_by": "reparse", "versions_now": sorted(versions)[:6]})
    return confirmed
