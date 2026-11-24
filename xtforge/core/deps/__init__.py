"""Dependency and toolchain discovery: what is this project built from, at what versions?

The question this answers is the one an analyst actually asks on arriving at an unfamiliar
checkout: *what is in here, and at which versions?* That question has to come before any
vulnerability lookup, because a vulnerability is a property of a (package, version) pair — without
the version there is nothing to look up, and guessing it from a range in a manifest answers a
different question than the one asked.

Discovery is deliberately source-based rather than toolchain-based. Running `go list -m all` would
give a better answer about a Go project than parsing `go.mod`, but it needs a toolchain for every
ecosystem, a resolvable module graph, and network access — so it fails exactly when the analyst
most needs an answer: an abandoned tree, a vendored copy, a machine with no SDK. Parsing manifests
works on any tree that has a manifest, in any environment, and says what the file says.

The tradeoff is honest and reported rather than hidden: a lockfile records resolved versions and a
manifest records constraints, so results carry `source` and `resolved` flags. A caller that needs
certainty checks `resolved`; a caller that wants coverage reads the constraint.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Iterable

MAX_FILE_BYTES = 32 * 1024 * 1024
MAX_DEPENDENCIES = 20_000
SKIP_DIRS = {
    ".git", ".hg", ".svn", "node_modules", "__pycache__", ".venv", "venv", ".tox",
    ".mypy_cache", ".pytest_cache", "target", "dist", "build", ".next", ".nuxt",
    "vendor_old", ".terraform", "Pods", ".gradle", ".idea",
}

# Ecosystem names must match OSV's spelling exactly, since they are passed straight through.
GO = "Go"
NPM = "npm"
PYPI = "PyPI"
CRATES = "crates.io"
MAVEN = "Maven"
NUGET = "NuGet"
PACKAGIST = "Packagist"
RUBYGEMS = "RubyGems"
HEX = "Hex"
PUB = "Pub"
COMPOSER = PACKAGIST
CARGO = CRATES


class DependencyError(Exception):
    """A manifest exists but cannot be read as the format it claims to be."""


# ---------------------------------------------------------------------------------------------
# Manifest readers. Each returns (name, version, ecosystem, resolved, extra) tuples.
# ---------------------------------------------------------------------------------------------

_REQUIRE_LINE = re.compile(r"^\s*([\w.\-/~]+\.[\w.\-/~]+)\s+(v[\w.\-+]+)\s*(//.*)?$")
_REPLACE_LINE = re.compile(r"^\s*([\w.\-/~]+(?:\.[\w.\-/~]+)?)\s+v?[\w.\-+]*\s*=>\s*(\S+)\s*(\S+)?")


def parse_go_mod(text: str) -> list[dict[str, Any]]:
    """Modules from a go.mod, including both require forms and replace directives.

    Two details that a naive parser gets wrong, both of which change the answer:

    * `require (...)` blocks span lines, and a `// indirect` comment marks a module that nothing
      imports directly. Indirect modules are still compiled into the binary, so they are still
      attack surface — they are reported with `indirect: true` rather than dropped.
    * A `replace` directive overrides the version that will actually be built. Reporting only the
      `require` version would name a version the build does not use, which is worse than reporting
      nothing.
    """
    dependencies: list[dict[str, Any]] = []
    replacements: dict[str, tuple[str, str]] = {}
    in_require = False
    for raw in text.splitlines():
        line = raw.split("//")[0].rstrip() if "// indirect" not in raw else raw
        stripped = raw.strip()
        if not stripped or stripped.startswith("//"):
            continue
        if stripped.startswith("require ("):
            in_require = True
            continue
        if in_require and stripped == ")":
            in_require = False
            continue
        if stripped.startswith("replace "):
            match = _REPLACE_LINE.match(stripped[len("replace "):])
            if match:
                replacements[match.group(1)] = (match.group(2), match.group(3) or "")
            continue
        candidate = stripped
        if stripped.startswith("require "):
            candidate = stripped[len("require "):].strip()
        elif not in_require:
            continue
        match = _REQUIRE_LINE.match(candidate)
        if not match:
            continue
        name, version = match.group(1), match.group(2)
        indirect = "// indirect" in raw
        dependencies.append({
            "name": name, "version": version.lstrip("v"), "ecosystem": GO,
            "raw_version": version, "resolved": True, "indirect": indirect,
            "source": "go.mod", "scope": "runtime",
        })
    for entry in dependencies:
        if entry["name"] in replacements:
            target, target_version = replacements[entry["name"]]
            entry["replaced_by"] = {"name": target, "version": target_version.lstrip("v")}
    return dependencies


def parse_go_sum(text: str) -> list[dict[str, Any]]:
    """Every module@version in go.sum — the resolved set, wider than go.mod's requirements."""
    seen: dict[tuple[str, str], dict[str, Any]] = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 2:
            continue
        module, version = parts[0], parts[1].split("/go.mod")[0]
        key = (module, version)
        if key in seen:
            continue
        seen[key] = {"name": module, "version": version.lstrip("v"), "ecosystem": GO,
                     "raw_version": version, "resolved": True, "source": "go.sum",
                     "scope": "runtime"}
    return list(seen.values())


def parse_package_json(text: str) -> list[dict[str, Any]]:
    """npm dependencies. A manifest holds ranges; only a lockfile holds resolved versions."""
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        raise DependencyError(f"package.json is not valid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise DependencyError("package.json is not a JSON object")
    dependencies: list[dict[str, Any]] = []
    for field, scope in (("dependencies", "runtime"), ("devDependencies", "dev"),
                         ("peerDependencies", "peer"), ("optionalDependencies", "optional")):
        block = payload.get(field)
        if not isinstance(block, dict):
            continue
        for name, spec in block.items():
            version, resolved = _clean_npm_spec(str(spec))
            dependencies.append({
                "name": name, "version": version, "ecosystem": NPM, "raw_version": str(spec),
                "resolved": resolved, "source": "package.json", "scope": scope,
            })
    return dependencies


def parse_package_lock(text: str) -> list[dict[str, Any]]:
    """npm lockfiles, both the v1 `dependencies` tree and the v2/v3 `packages` map."""
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        raise DependencyError(f"package-lock.json is not valid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise DependencyError("package-lock.json is not a JSON object")
    dependencies: list[dict[str, Any]] = []
    packages = payload.get("packages")
    if isinstance(packages, dict):
        for path, record in packages.items():
            if not isinstance(record, dict) or not path:
                continue
            # `node_modules/foo` and `node_modules/a/node_modules/foo` both name the package
            # `foo`; the version differs per copy, and each copy is a separate finding.
            name = record.get("name") or path.rsplit("node_modules/", 1)[-1]
            version = record.get("version")
            if not name or not version:
                continue
            dependencies.append({
                "name": name, "version": str(version), "ecosystem": NPM,
                "raw_version": str(version), "resolved": True,
                "source": "package-lock.json", "scope": "dev" if record.get("dev") else "runtime",
                "path": path,
            })
        return dependencies
    tree = payload.get("dependencies")
    if isinstance(tree, dict):
        for name, record in tree.items():
            if not isinstance(record, dict):
                continue
            version = record.get("version")
            if not name or not version:
                continue
            dependencies.append({
                "name": name, "version": str(version), "ecosystem": NPM,
                "raw_version": str(version), "resolved": True,
                "source": "package-lock.json",
                "scope": "dev" if record.get("dev") else "runtime",
            })
    return dependencies


def _clean_npm_spec(spec: str) -> tuple[str, bool]:
    """Reduce an npm range to a concrete version when the range denotes exactly one.

    `^1.2.3` is a range and its lower bound is *not* the installed version, so it is returned
    with `resolved: False` and the bare version kept for display. An exact `1.2.3` or a pinned
    `=1.2.3` is resolved. Returning `^1.2.3` as though it were a version would make a
    vulnerability lookup report findings for a version that may not be installed — a false
    positive that destroys trust in every other finding.
    """
    text = spec.strip()
    if text.startswith(("file:", "link:", "git+", "github:", "http:", "https:", "workspace:")):
        return "", False
    for prefix in ("^", "~", ">=", ">", "<=", "<", "="):
        if text.startswith(prefix):
            stripped = text[len(prefix):].strip()
            # `>=1.2.3 <2.0.0` is a range; only a single token can be exact.
            if prefix == "=" and " " not in stripped:
                return stripped, True
            return stripped, False
    if " " in text or "||" in text or "x" in text.lower():
        return text.split()[0] if text else "", False
    return text, bool(re.fullmatch(r"\d+\.\d+\.\d+[\w.\-+]*", text))


def parse_cargo_toml(text: str) -> list[dict[str, Any]]:
    """Cargo dependencies from `[dependencies]`-style tables."""
    try:
        import tomllib
    except ImportError:  # pragma: no cover - Python < 3.11
        return _parse_cargo_fallback(text)
    try:
        payload = tomllib.loads(text)
    except Exception as exc:  # noqa: BLE001 - tomllib raises several decode errors
        raise DependencyError(f"Cargo.toml is not valid TOML: {exc}") from exc
    dependencies: list[dict[str, Any]] = []
    for table, scope in (("dependencies", "runtime"), ("dev-dependencies", "dev"),
                         ("build-dependencies", "build")):
        block = payload.get(table)
        if not isinstance(block, dict):
            continue
        for name, value in block.items():
            version, resolved, extra = "", False, {}
            if isinstance(value, str):
                version, resolved = _clean_npm_spec(value)
            elif isinstance(value, dict):
                extra = {k: v for k, v in value.items()
                         if k in ("features", "default-features", "optional", "registry")}
                if "version" in value:
                    version, resolved = _clean_npm_spec(str(value["version"]))
                elif "git" in value:
                    version = str(value.get("rev") or value.get("tag") or value["git"])
                elif "path" in value:
                    version = f"path:{value['path']}"
            dependencies.append({
                "name": name, "version": version, "ecosystem": CRATES,
                "raw_version": version, "resolved": resolved,
                "source": "Cargo.toml", "scope": scope, **extra,
            })
    return dependencies


def _parse_cargo_fallback(text: str) -> list[dict[str, Any]]:
    """Line-based Cargo parser for Pythons without tomllib. Deliberately minimal and marked."""
    dependencies: list[dict[str, Any]] = []
    table = ""
    for raw in text.splitlines():
        line = raw.split("#")[0].strip()
        if not line:
            continue
        if line.startswith("[") and line.endswith("]"):
            table = line[1:-1]
            continue
        if table not in ("dependencies", "dev-dependencies", "build-dependencies"):
            continue
        if "=" not in line:
            continue
        name, _, value = line.partition("=")
        value = value.strip().strip('"')
        version, resolved = _clean_npm_spec(value)
        dependencies.append({"name": name.strip(), "version": version, "ecosystem": CRATES,
                             "raw_version": value, "resolved": resolved,
                             "source": "Cargo.toml", "scope": "runtime",
                             "parser": "fallback"})
    return dependencies


_CARGO_LOCK = re.compile(r'name\s*=\s*"([^"]+)"\s*\nversion\s*=\s*"([^"]+)"')


def parse_cargo_lock(text: str) -> list[dict[str, Any]]:
    """Cargo.lock: the resolved graph, which has no ranges."""
    dependencies = []
    for match in _CARGO_LOCK.finditer(text):
        dependencies.append({"name": match.group(1), "version": match.group(2),
                             "ecosystem": CRATES, "raw_version": match.group(2),
                             "resolved": True, "source": "Cargo.lock", "scope": "runtime"})
    return dependencies


_PY_REQUIREMENT = re.compile(
    r"^\s*([A-Za-z0-9][A-Za-z0-9._\-]*)\s*(\[[^\]]*\])?\s*"
    r"((?:[=!<>~]=?|===)\s*[^\s;#]+(?:\s*,\s*(?:[=!<>~]=?)\s*[^\s;#]+)*)?"
)


def parse_requirements(text: str) -> list[dict[str, Any]]:
    """Python requirements: exact pins resolve, ranges do not.

    Extras (`requests[security]`) and environment markers (`; python_version < "3.9"`) are
    stripped, and `-r other.txt` includes are reported rather than silently followed, because
    following them can leave the tree entirely.
    """
    dependencies: list[dict[str, Any]] = []
    for raw in text.splitlines():
        line = raw.split("#")[0].strip()
        if not line:
            continue
        if line.startswith(("-r ", "--requirement ", "-c ", "--constraint ")):
            target = line.split(None, 1)[1] if len(line.split(None, 1)) > 1 else ""
            dependencies.append({"name": "", "version": "", "ecosystem": PYPI,
                                 "resolved": False, "source": "requirements", "scope": "runtime",
                                 "include": target})
            continue
        if line.startswith("-"):
            continue  # a pip flag, not a dependency
        match = _PY_REQUIREMENT.match(line)
        if not match or not match.group(1):
            continue
        name = match.group(1)
        spec = (match.group(3) or "").replace(" ", "")
        version, resolved = "", False
        if spec.startswith("==") and "," not in spec:
            version = spec[2:].strip()
            resolved = bool(re.fullmatch(r"[\w.\-+!]+", version))
            if "*" in version:
                resolved = False
        elif spec:
            version = spec
        dependencies.append({
            "name": name, "version": version, "ecosystem": PYPI,
            "raw_version": spec, "resolved": resolved, "source": "requirements",
            "scope": "runtime",
        })
    return dependencies


def parse_pyproject(text: str) -> list[dict[str, Any]]:
    """pyproject.toml: PEP 621 `dependencies` and Poetry's tables."""
    try:
        import tomllib
    except ImportError:  # pragma: no cover
        return []
    try:
        payload = tomllib.loads(text)
    except Exception as exc:  # noqa: BLE001
        raise DependencyError(f"pyproject.toml is not valid TOML: {exc}") from exc
    dependencies: list[dict[str, Any]] = []
    project = payload.get("project")
    if isinstance(project, dict):
        for spec in project.get("dependencies") or []:
            parsed = parse_requirements(str(spec))
            for entry in parsed:
                entry["source"] = "pyproject.toml"
                dependencies.append(entry)
        for group, specs in (project.get("optional-dependencies") or {}).items():
            for spec in specs or []:
                for entry in parse_requirements(str(spec)):
                    entry["source"] = "pyproject.toml"
                    entry["scope"] = f"optional:{group}"
                    dependencies.append(entry)
    tool = payload.get("tool")
    if isinstance(tool, dict) and isinstance(tool.get("poetry"), dict):
        poetry = tool["poetry"]
        for table, scope in (("dependencies", "runtime"), ("dev-dependencies", "dev")):
            block = poetry.get(table)
            if not isinstance(block, dict):
                continue
            for name, value in block.items():
                if name.lower() == "python":
                    continue
                version, resolved = "", False
                if isinstance(value, str):
                    version, resolved = _clean_npm_spec(value)
                elif isinstance(value, dict):
                    version = str(value.get("version") or value.get("git") or "")
                dependencies.append({"name": name, "version": version, "ecosystem": PYPI,
                                     "raw_version": version, "resolved": resolved,
                                     "source": "pyproject.toml[poetry]", "scope": scope})
    return dependencies


def parse_gemfile_lock(text: str) -> list[dict[str, Any]]:
    """Gemfile.lock: a resolved graph, one `name (version)` per line."""
    dependencies = []
    section = ""
    for raw in text.splitlines():
        if raw and not raw.startswith(" "):
            section = raw.strip()
            continue
        if section not in ("GEM", "PATH", "GIT"):
            continue
        match = re.match(r"^\s{4}([\w.\-]+)\s+\(([^)]+)\)", raw)
        if match:
            dependencies.append({"name": match.group(1), "version": match.group(2),
                                 "ecosystem": RUBYGEMS, "raw_version": match.group(2),
                                 "resolved": True, "source": "Gemfile.lock",
                                 "scope": "runtime"})
    return dependencies


def parse_composer_lock(text: str) -> list[dict[str, Any]]:
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        raise DependencyError(f"composer.lock is not valid JSON: {exc}") from exc
    dependencies = []
    for field, scope in (("packages", "runtime"), ("packages-dev", "dev")):
        for record in (payload.get(field) or []) if isinstance(payload, dict) else []:
            if not isinstance(record, dict):
                continue
            name, version = record.get("name"), record.get("version")
            if not name or not version:
                continue
            cleaned = str(version).lstrip("v")
            dependencies.append({"name": name, "version": cleaned, "ecosystem": PACKAGIST,
                                 "raw_version": str(version), "resolved": True,
                                 "source": "composer.lock", "scope": scope})
    return dependencies


def parse_pom(text: str) -> list[dict[str, Any]]:
    """Maven POM `<dependency>` elements, including the parent-inherited groupId case.

    A `<dependency>` that omits `<groupId>` inherits the enclosing `<groupId>`; without that rule
    the coordinate is incomplete and no lookup can be made. Unresolved `${...}` properties are
    reported unresolved rather than printed as if they were versions.
    """
    import xml.etree.ElementTree as ET
    namespace = ""
    stripped = text.strip()
    if stripped.startswith("<?xml") or stripped.startswith("<"):
        match = re.search(r'xmlns\s*=\s*"([^"]+)"', stripped)
        if match:
            namespace = match.group(1)
    tag = (lambda name: f"{{{namespace}}}{name}") if namespace else (lambda name: name)
    try:
        root = ET.fromstring(text)
    except ET.ParseError as exc:
        raise DependencyError(f"pom.xml is not valid XML: {exc}") from exc

    properties: dict[str, str] = {}
    for holder in root.iter():
        if holder.tag.endswith("properties"):
            for prop in holder:
                name = prop.tag.split("}")[-1]
                if prop.text:
                    properties[name] = prop.text.strip()

    parent_group = ""
    for holder in root.iter(tag("parent")):
        node = holder.find(tag("groupId"))
        if node is not None and node.text:
            parent_group = node.text.strip()
    root_group = parent_group
    node = root.find(tag("groupId"))
    if node is not None and node.text:
        root_group = node.text.strip()

    dependencies = []
    for holder in root.iter(tag("dependency")):
        group = holder.find(tag("groupId"))
        artifact = holder.find(tag("artifactId"))
        version = holder.find(tag("version"))
        scope = holder.find(tag("scope"))
        if artifact is None or not artifact.text:
            continue
        group_text = group.text.strip() if group is not None and group.text else root_group
        version_text = version.text.strip() if version is not None and version.text else ""
        resolved = bool(version_text) and "${" not in version_text
        if "${" in version_text:
            placeholder = re.search(r"\$\{([^}]+)\}", version_text)
            if placeholder and placeholder.group(1) in properties:
                version_text = properties[placeholder.group(1)]
                resolved = "${" not in version_text
        coordinates = f"{group_text}:{artifact.text.strip()}"
        dependencies.append({
            "name": coordinates, "version": version_text, "ecosystem": MAVEN,
            "raw_version": version_text, "resolved": resolved, "source": "pom.xml",
            "scope": scope.text.strip() if scope is not None and scope.text else "compile",
        })
    return dependencies


def parse_packages_config(text: str) -> list[dict[str, Any]]:
    """NuGet packages.config."""
    import xml.etree.ElementTree as ET
    try:
        root = ET.fromstring(text)
    except ET.ParseError as exc:
        raise DependencyError(f"packages.config is not valid XML: {exc}") from exc
    dependencies = []
    for package in root.iter("package"):
        name, version = package.get("id"), package.get("version")
        if not name or not version:
            continue
        dependencies.append({"name": name, "version": version, "ecosystem": NUGET,
                             "raw_version": version, "resolved": True,
                             "source": "packages.config", "scope": "runtime"})
    return dependencies


def parse_pubspec(text: str) -> list[dict[str, Any]]:
    """Dart pubspec.yaml — indentation-based, so parsed line by line."""
    dependencies: list[dict[str, Any]] = []
    section = ""
    for raw in text.splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip())
        line = raw.strip()
        if indent == 0 and line.endswith(":"):
            section = line[:-1]
            continue
        if section not in ("dependencies", "dev_dependencies"):
            continue
        if indent == 2 and ":" in line:
            name, _, value = line.partition(":")
            value = value.strip()
            version, resolved = _clean_npm_spec(value) if value else ("", False)
            dependencies.append({"name": name.strip(), "version": version,
                                 "ecosystem": PUB, "raw_version": value,
                                 "resolved": resolved, "source": "pubspec.yaml",
                                 "scope": "dev" if section.startswith("dev") else "runtime"})
    return dependencies


# ---------------------------------------------------------------------------------------------
# Binary toolchain detection. The version a compiler stamped into an artifact is evidence about
# what is deployed, which no manifest can give.
# ---------------------------------------------------------------------------------------------

_GO_VERSION = re.compile(rb"go1\.\d+(?:\.\d+)?(?:beta\d+|rc\d+)?")
# A Go buildinfo blob is a sequence of tab-separated lines:
#
#     path    example.com/real
#     mod     example.com/real        (devel)
#     dep     github.com/google/uuid  v1.3.0  h1:t6JiXgmwXMjEs8VusXIJk2BXHsn+wx8BZdTaoZ5fu7I=
#
# So a module is `dep\t<path>\t<version>\t<sum>`, and the version is already a separate field.
# My first attempt invented a concatenated form (`ginv1.6.0github.com/...`) and then wrote a regex
# to split it, which found one fictional module instead of two real ones. Parsing the actual
# separator is both simpler and correct; the loose fallback below only runs when no `dep\t` line
# exists at all, so it cannot interfere with a well-formed blob.
_GO_DEP = re.compile(rb"(?:^|[\x00\n])dep\t([^\t\x00\n]+)\t(v[^\t\x00\n]+)")
_GO_MOD = re.compile(rb"(?:^|[\x00\n])mod\t([^\t\x00\n]+)\t(v[^\t\x00\n]+)")
# Fallback for a stripped or partial blob: a path followed directly by a version, where the path
# segments recurse so the version cannot swallow the next module and the version's tail cannot
# swallow a dotted path.
_GO_MODULE_LOOSE = re.compile(
    rb"(?:^|[\x00-\x20])"
    rb"((?:[a-z0-9.\-]+\.)+[a-z]{2,}/[a-z0-9.\-/]*)"
    rb"(v\d+\.\d+\.\d+(?:-[\w.]+)?(?:\+[\w.]+)?)"
    rb"(?![\w.\-])")
_NODE_VERSION = re.compile(rb"Node\.js/(v?\d+\.\d+\.\d+)")
_PY_VERSION = re.compile(rb"Python/(\d+\.\d+\.\d+)")
_RUST_VERSION = re.compile(rb"rustc-(\d+\.\d+\.\d+)")


def detect_binary_toolchains(data: bytes, *, limit: int = 500) -> dict[str, Any]:
    """Toolchain strings and embedded module versions in a compiled artifact.

    A Go binary carries its full module graph in the buildinfo blob, and the compiler version
    beside it. That is the deployed truth: it is what is actually running, independent of which
    go.mod happens to be in the tree. The same reasoning applies to the runtime banner strings a
    packaged Node or Python application leaves behind.
    """
    findings: dict[str, Any] = {"toolchains": [], "embedded_modules": []}
    seen_versions: set[str] = set()
    for match in _GO_VERSION.finditer(data[:2 * 1024 * 1024]):
        text = match.group(0).decode("ascii", "replace")
        if text not in seen_versions:
            seen_versions.add(text)
            findings["toolchains"].append({"kind": "go", "version": text.lstrip("go"),
                                           "raw": text})
    for pattern, kind in ((_NODE_VERSION, "node"), (_PY_VERSION, "python"),
                          (_RUST_VERSION, "rust")):
        match = pattern.search(data[:2 * 1024 * 1024])
        if match:
            findings["toolchains"].append({"kind": kind,
                                           "version": match.group(1).decode("ascii", "replace")})

    modules: dict[tuple[str, str], dict[str, Any]] = {}

    def collect(pattern) -> None:
        for match in pattern.finditer(data):
            name = match.group(1).decode("ascii", "replace")
            version = match.group(2).decode("ascii", "replace").lstrip("v")
            if (name, version) in modules or len(modules) >= limit:
                continue
            modules[(name, version)] = {
                "name": name, "version": version, "ecosystem": GO, "raw_version": version,
                "resolved": True, "source": "buildinfo", "scope": "runtime"}

    collect(_GO_DEP)
    if not modules:
        collect(_GO_MOD)
    if not modules:
        collect(_GO_MODULE_LOOSE)

    for match in ():
        name = match.group(1).decode("ascii", "replace")
        version = match.group(2).decode("ascii", "replace")
        # A module path in a Go binary is followed by its version with no separator; the regex
        # requires a dotted first label so that ordinary prose does not match.
        if (name, version) in modules:
            continue
        modules[(name, version)] = {"name": name, "version": version, "ecosystem": GO,
                                    "raw_version": version, "resolved": True,
                                    "source": "buildinfo", "scope": "runtime"}
        if len(modules) >= limit:
            break
    findings["embedded_modules"] = list(modules.values())
    return findings


# ---------------------------------------------------------------------------------------------
# Directory walk.
# ---------------------------------------------------------------------------------------------

MANIFESTS: list[tuple[str, str, Any]] = [
    ("go.mod", "go", parse_go_mod),
    ("go.sum", "go-sum", parse_go_sum),
    ("package.json", "npm", parse_package_json),
    ("package-lock.json", "npm-lock", parse_package_lock),
    ("npm-shrinkwrap.json", "npm-lock", parse_package_lock),
    ("Cargo.toml", "cargo", parse_cargo_toml),
    ("Cargo.lock", "cargo-lock", parse_cargo_lock),
    ("requirements.txt", "pip", parse_requirements),
    ("pyproject.toml", "pep621", parse_pyproject),
    ("Gemfile.lock", "gem", parse_gemfile_lock),
    ("composer.lock", "composer", parse_composer_lock),
    ("pom.xml", "maven", parse_pom),
    ("packages.config", "nuget", parse_packages_config),
    ("pubspec.yaml", "pub", parse_pubspec),
]

MANIFEST_NAMES = {name for name, _kind, _reader in MANIFESTS}
# Lockfiles supersede manifests: a resolved version is strictly better evidence than a range.
LOCK_KINDS = {"go-sum", "npm-lock", "cargo-lock", "gem", "composer"}


def discover(root: str | Path, *, max_files: int = 400, follow_depth: int = 6,
             include_dev: bool = True) -> dict[str, Any]:
    """Walk a tree and return every dependency found, with provenance for each.

    Duplicates are collapsed by (ecosystem, name, version) but *kept* across versions: the same
    package pinned at two versions in one tree is two findings, because a fix for one copy does
    not fix the other. Provenance records every manifest that mentioned the pair so a reader can
    see where it came from rather than having to trust the merge.
    """
    base = Path(root).expanduser()
    if not base.exists():
        return {"ok": False, "root": str(base), "error": "path does not exist"}
    if base.is_file():
        candidates = [base]
    else:
        candidates = _walk(base, max_files=max_files, follow_depth=follow_depth)

    dependencies: dict[tuple[str, str, str], dict[str, Any]] = {}
    manifests: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    for path in candidates:
        kind_reader = next(((kind, reader) for name, kind, reader in MANIFESTS
                            if path.name == name), None)
        if kind_reader is None:
            continue
        kind, reader = kind_reader
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                errors.append({"path": str(path), "error": "file is too large to parse"})
                continue
            text = path.read_text("utf-8", errors="replace")
        except OSError as exc:
            errors.append({"path": str(path), "error": str(exc)})
            continue
        try:
            parsed = reader(text)
        except DependencyError as exc:
            errors.append({"path": str(path), "error": str(exc)})
            continue
        except (ValueError, TypeError, KeyError) as exc:
            errors.append({"path": str(path), "error": f"unexpected {type(exc).__name__}: {exc}"})
            continue
        entry = {"path": str(path), "kind": kind, "dependency_count": len(parsed),
                 "resolved_count": sum(1 for item in parsed if item.get("resolved"))}
        manifests.append(entry)
        for item in parsed:
            name = item.get("name") or ""
            version = item.get("version") or ""
            if not name:
                continue
            if not include_dev and item.get("scope") in ("dev", "build"):
                continue
            key = (item.get("ecosystem") or "", name, version)
            if key in dependencies:
                dependencies[key].setdefault("sources", []).append(
                    {"path": str(path), "kind": kind})
                continue
            item = dict(item)
            item["sources"] = [{"path": str(path), "kind": kind}]
            dependencies[key] = item

    resolved_items = [item for item in dependencies.values() if item.get("resolved")]
    return {
        "ok": True,
        "root": str(base),
        "manifests": manifests,
        "manifest_count": len(manifests),
        "dependency_count": len(dependencies),
        "resolved_count": len(resolved_items),
        "unresolved_count": len(dependencies) - len(resolved_items),
        "ecosystems": _count_by(item.get("ecosystem") or "?" for item in dependencies.values()),
        "scopes": _count_by(item.get("scope") or "?" for item in dependencies.values()),
        "dependencies": sorted(dependencies.values(),
                               key=lambda item: (item.get("ecosystem") or "",
                                                 item.get("name") or "",
                                                 item.get("version") or "")),
        "errors": errors,
        # An unreadable manifest is not a clean tree, and saying so matters more than the count:
        # a green summary over a tree whose Cargo.toml failed to parse is a false assurance.
        "complete": not errors,
    }


def _walk(base: Path, *, max_files: int, follow_depth: int) -> list[Path]:
    found: list[Path] = []
    stack: list[tuple[Path, int]] = [(base, 0)]
    while stack and len(found) < max_files:
        current, depth = stack.pop()
        try:
            entries = sorted(current.iterdir(), key=lambda item: item.name)
        except (OSError, PermissionError):
            continue
        for entry in entries:
            if entry.name in MANIFEST_NAMES:
                found.append(entry)
                if len(found) >= max_files:
                    break
            if depth < follow_depth and entry.is_dir() and not entry.is_symlink():
                if entry.name in SKIP_DIRS:
                    continue
                if entry.name.startswith("."):
                    continue
                stack.append((entry, depth + 1))
    return found


def _count_by(values: Iterable[str]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for value in values:
        counts[value] = counts.get(value, 0) + 1
    return dict(sorted(counts.items(), key=lambda pair: -pair[1]))
