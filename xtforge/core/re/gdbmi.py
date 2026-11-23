"""Drive GDB through its Machine Interface, its documented machine-readable protocol.

The breadth matrix excluded this as "wraps GDB; xt-forge does live probing rather than driving
a debugger". That was a defensible *choice* described as a *constraint*, and it is the weaker
of the two: live probing answers what a process has loaded, but not what it is executing, what
its registers hold, or what a breakpoint sees. Those are questions the tool exists to answer.

MI is not screen-scraping a TUI. It is a line-oriented protocol with `token^class,results`
records, issued over a pipe, stable since 2001 and documented. `gdb --version` prints 18.1 here,
so this is measured rather than assumed.

Scope is deliberate and stated in the output: inspect, disassemble, read memory, set and report
breakpoints, and read registers — the analysis questions. Not a debugger front-end.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

DEFAULT_TIMEOUT = 60.0
MAX_OUTPUT_BYTES = 4 * 1024 * 1024
_MAX_STEPS = 200

_RESULT = re.compile(r"^(?P<token>\d*)\^(?P<kind>done|running|connected|error|exit)(?:,(?P<rest>.*))?$")
# A value is a quoted string, or everything after `=`. The earlier pattern ended in `\S+`,
# which for an aggregate (`asm_insns=[{...},{...}]`) captured only the single character `[` —
# so every list-valued result parsed to one bracket and the disassembly came back empty while
# still reporting success.
_CONST = re.compile(r'^(?P<name>[A-Za-z_][\w-]*)=(?P<value>"(?:[^"\\]|\\.)*"|.*)$')


def find_gdb() -> str | None:
    """Locate a usable gdb, or nothing."""
    found = shutil.which("gdb")
    if found and os.access(found, os.X_OK):
        return found
    for candidate in ("/usr/bin/gdb", "/usr/local/bin/gdb", "/opt/homebrew/bin/gdb"):
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return None


def _unescape(text: str) -> str:
    """Undo MI's C-string escaping, which every value-bearing field uses."""
    return (text.replace("\\\\", "\x00")
                .replace('\\"', '"')
                .replace("\\n", "\n")
                .replace("\\t", "\t")
                .replace("\\r", "\r")
                .replace("\x00", "\\"))


def _parse_results(rest: str) -> dict[str, Any]:
    """Parse the comma-separated `name=value` tail of a result record.

    Only top-level scalars and tuples are extracted. Nested lists such as `stack=[frame=...]`
    are returned as raw text under their name rather than half-parsed, because a wrong
    structure is worse than an honest string.
    """
    results: dict[str, Any] = {}
    if not rest:
        return results
    depth = 0
    in_string = False
    escaped = False
    field = ""
    fields: list[str] = []
    for character in rest:
        if escaped:
            field += character
            escaped = False
            continue
        if character == "\\":
            field += character
            escaped = True
            continue
        if character == '"':
            in_string = not in_string
        elif not in_string:
            if character in "{[":
                depth += 1
            elif character in "}]":
                depth -= 1
            elif character == "," and depth == 0:
                fields.append(field)
                field = ""
                continue
        field += character
    if field:
        fields.append(field)

    for item in fields:
        match = _CONST.match(item)
        if not match:
            continue
        name, value = match.group("name"), match.group("value")
        if value.startswith('"'):
            results[name] = _unescape(value[1:-1] if value.endswith('"') else value[1:])
        elif value in ("{", "["):
            # A nested aggregate whose body was split by the depth counter; keep it raw.
            results[name] = item.split("=", 1)[1]
        else:
            results[name] = value
    return results


class Session:
    """One gdb process spoken to over MI."""

    def __init__(self, binary: str | None = None, *, gdb: str | None = None,
                 timeout: float = DEFAULT_TIMEOUT) -> None:
        self.gdb = gdb or find_gdb()
        if not self.gdb:
            raise RuntimeError("no gdb found on this host")
        argv = [self.gdb, "--interpreter=mi2", "--quiet", "--nx"]
        if binary:
            argv.append(str(binary))
        self._process = subprocess.Popen(
            argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1)
        self._token = 0
        self._timeout = timeout
        self.transcript: list[str] = []

    def __enter__(self) -> "Session":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def command(self, text: str) -> dict[str, Any]:
        """Issue one MI command and return its `^done`/`^error` record."""
        self._token += 1
        token = self._token
        if self._process.stdin is None:
            return {"ok": False, "error": "gdb stdin is closed"}
        self._process.stdin.write(f"{token}{text}\n")
        self._process.stdin.flush()
        return self._read_result(token)

    def _read_result(self, token: int) -> dict[str, Any]:
        if self._process.stdout is None:
            return {"ok": False, "error": "gdb stdout is closed"}
        collected: list[str] = []
        budget = 4000
        while budget > 0:
            budget -= 1
            line = self._process.stdout.readline()
            if not line:
                return {"ok": False, "error": "gdb exited before answering",
                        "transcript": collected[-8:]}
            line = line.rstrip("\n")
            self.transcript.append(line)
            match = _RESULT.match(line)
            if not match or match.group("token") != str(token):
                # Console (`~`), target (`@`) and status (`=`) records are not our answer; keep
                # them as context and keep reading.
                if line.startswith("~"):
                    collected.append(_unescape(line[2:-1] if line.endswith('"') else line[2:]))
                continue
            kind = match.group("kind")
            results = _parse_results(match.group("rest") or "")
            if kind == "error":
                return {"ok": False, "error": results.get("msg", "gdb error"),
                        "console": "".join(collected)}
            return {"ok": True, "results": results, "console": "".join(collected)}
        return {"ok": False, "error": "no result record within the read budget"}

    def close(self) -> None:
        try:
            if self._process.stdin:
                self._process.stdin.write("999-gdb-exit\n")
                self._process.stdin.flush()
        except (OSError, ValueError):
            pass
        try:
            self._process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self._process.kill()
            self._process.wait(timeout=5)


def _stop_at_entry(session: "Session", binary: Path) -> dict[str, Any]:
    """Break at the entry point and run, so there is a live inferior to interrogate.

    `-exec-run` alone runs the program to completion and `--stop-at-start` does not exist in
    gdb 18.1 (`Unknown option "-stop-at-start"`), so both were wrong: the first described a
    process that had already exited, the second failed outright. Breaking on `main` and then
    running leaves the inferior stopped exactly where its state is interesting.
    """
    insert = session.command("-break-insert main")
    started = session.command("-exec-run")
    if not started["ok"]:
        return {"ok": False, "error": started["error"]}
    return {"ok": True, "breakpoint": insert.get("results", {}).get("bkpt")}


def _split_mi_list(raw: str) -> list[str]:
    """Split an MI list body into its top-level element strings."""
    body = raw.strip()
    if body.startswith("[") and body.endswith("]"):
        body = body[1:-1]
    if not body.strip():
        return []
    parts, depth, in_string, escaped, field = [], 0, False, False, ""
    for character in body:
        if escaped:
            field += character
            escaped = False
            continue
        if character == "\\":
            field += character
            escaped = True
            continue
        if character == '"':
            in_string = not in_string
        elif not in_string:
            if character in "{[":
                depth += 1
            elif character in "}]":
                depth -= 1
            elif character == "," and depth == 0:
                parts.append(field)
                field = ""
                continue
        field += character
    if field:
        parts.append(field)
    return parts


def inspect(path: str | Path, **kwargs: Any) -> dict[str, Any]:
    """Sessionless entry point: load a binary and answer the usual first questions."""
    binary = Path(str(path))
    if not binary.is_file():
        return {"ok": False, "error": f"not a file: {path}"}
    gdb = find_gdb()
    if not gdb:
        return {"ok": False, "error": "no gdb found on this host",
                "hint": "install gdb to use debugger-backed inspection"}
    try:
        with Session(binary, gdb=gdb) as session:
            return describe(session, binary)
    except (RuntimeError, OSError) as exc:
        return {"ok": False, "error": str(exc)}


def describe(session: Session, binary: Path) -> dict[str, Any]:
    """The questions worth asking of a binary gdb has just loaded.

    Every command name here was checked against gdb 18.1 rather than assumed. Three did not
    exist in the form first written: `-file-list-exec-sections` is a *CLI* command with no MI
    equivalent (`Undefined MI command`), `-file-list-shared-libraries` returns
    `shared-libraries=` rather than `shlibs=`, and it only lists anything *after* the process
    has started — a loaded-but-unrun binary reports an empty list, which is correct but not what
    the field name suggests.
    """
    report: dict[str, Any] = {"ok": True, "path": str(binary), "gdb": session.gdb}

    files = session.command("-file-list-exec-source-files")
    report["source_file_count"] = len(_split_mi_list(
        files.get("results", {}).get("files", ""))) if files["ok"] else 0

    symbol = session.command("-symbol-info-functions")
    # symbols={debug=[{filename=...,symbols=[...]}],non-debug=[...]}: nested, so count the
    # leaf entries rather than the top-level groups (which is what the first version did,
    # reporting 2 groups as though they were 2 functions).
    names = 0
    if symbol["ok"]:
        # symbols={debug=[{filename=..,symbols=[{name=..}]}],non-debug=[..]}. The group value is
        # itself a list, so it must be split before its `symbols=` field can be read — the first
        # version read `symbols=` off a group whose value was still a raw list, and counted 0.
        raw = symbol["results"].get("symbols", "")
        # The whole result is one tuple: `{debug=[{filename=..,symbols=[..]}],non-debug=[..]}`.
        # Splitting that at the first `=` lands on a brace, so the braces come off first and the
        # `debug`/`non-debug` groups are then separated as list elements.
        for group in _split_mi_list(raw.strip().strip("{}")):
            if "=" not in group:
                continue
            name, _, body = group.partition("=")
            if name.strip() not in ("debug", "non-debug"):
                continue
            for table in _split_mi_list(body):
                fields = _parse_results(table.strip().strip("{}").strip(","))
                names += len(_split_mi_list(fields.get("symbols", "")))
    report["function_symbol_count"] = names

    return report


def segments(path: str | Path) -> dict[str, Any]:
    """Program headers via gdb's `info proc mappings` after a start.

    Sections have no MI verb; `maintenance info sections` is CLI-only and its text output is
    version-dependent, so the mapped-segment view is what is offered instead — it comes from the
    loader and is the thing an analyst usually wants anyway.
    """
    binary = Path(str(path))
    if not binary.is_file():
        return {"ok": False, "error": f"not a file: {path}"}
    if not find_gdb():
        return {"ok": False, "error": "no gdb found on this host"}
    try:
        with Session(binary) as session:
            stopped = _stop_at_entry(session, binary)
            if not stopped["ok"]:
                return {"ok": False, "path": str(binary), "error": stopped["error"]}
            mappings = session.command('-interpreter-exec console "info proc mappings"')
            libraries = session.command("-file-list-shared-libraries")
            text = mappings.get("console", "") if mappings["ok"] else ""
            entries = []
            for line in text.splitlines():
                fields = line.split()
                if len(fields) >= 5 and fields[0].startswith("0x"):
                    try:
                        entries.append({"start": fields[0], "end": fields[1],
                                        "size": int(fields[2], 0),
                                        "offset": fields[3], "perms": fields[4],
                                        "path": fields[5] if len(fields) > 5 else ""})
                    except ValueError:
                        continue
            return {"ok": True, "path": str(binary), "mapping_count": len(entries),
                    "mappings": entries,
                    "shared_library_count": len(_split_mi_list(
                        libraries.get("results", {}).get("shared-libraries", "")))
                    if libraries["ok"] else 0,
                    "note": "read from the loader after the process started, then killed"}
    except (RuntimeError, OSError) as exc:
        return {"ok": False, "error": str(exc)}


def disassemble(path: str | Path, *, function: str | None = None,
                start: str | None = None, count: int = 40) -> dict[str, Any]:
    """Disassemble a function or address range with GDB's own decoder."""
    binary = Path(str(path))
    if not binary.is_file():
        return {"ok": False, "error": f"not a file: {path}"}
    if not find_gdb():
        return {"ok": False, "error": "no gdb found on this host"}
    if count < 1 or count > 5000:
        return {"ok": False, "error": f"count out of range: {count}"}
    try:
        with Session(binary) as session:
            if start:
                # `-e +N` is not accepted either; gdb wants absolute addresses on both sides.
                result = session.command(f"-data-disassemble -s {start} -e {start}+{count} -- 0")
            else:
                # There is no `-n <symbol>` mode. Resolve the symbol to an address the same way
                # the debugger would, then disassemble from there.
                target = function or "main"
                resolved = session.command(f"-data-evaluate-expression &{target}")
                address = resolved["results"].get("value", "") if resolved["ok"] else ""
                if not address:
                    return {"ok": False, "path": str(binary),
                            "error": f"cannot resolve symbol {target!r}: "
                                     f"{resolved.get('error', 'no address')}"}
                address = address.split(" ")[0]
                result = session.command(f"-data-disassemble -a {address} -- 0")
            if not result["ok"]:
                return {"ok": False, "path": str(binary), "error": result["error"]}
            raw = result["results"].get("asm_insns", "")
            # With source (`--source`) gdb nests `src_and_asm_line={line=..,line_asm_insn=[...]}`;
            # without it the elements are bare `{address=..,inst=..}` tuples. Both shapes occur,
            # and the first version assumed only the nested one, so every instruction was
            # skipped and the call returned success with an empty list.
            instructions: list[dict[str, Any]] = []
            for element in _split_mi_list(raw):
                body = element.strip()
                if body.startswith("src_and_asm_line="):
                    body = body[len("src_and_asm_line="):]
                fields = _parse_results(body.strip("{}").strip(","))
                nested = fields.get("line_asm_insn")
                if nested:
                    for instruction in _split_mi_list(nested):
                        parsed = _parse_results(instruction.strip("{}"))
                        if parsed:
                            instructions.append({
                                "address": parsed.get("address"),
                                "function": parsed.get("func-name"),
                                "offset": parsed.get("offset"),
                                "instruction": parsed.get("inst"),
                            })
                    continue
                if fields.get("inst"):
                    instructions.append({
                        "address": fields.get("address"),
                        "function": fields.get("func-name"),
                        "offset": fields.get("offset"),
                        "instruction": fields.get("inst"),
                    })
            return {"ok": True, "path": str(binary), "target": start or function or "main",
                    "count": len(instructions), "instructions": instructions,
                    "note": "decoded by gdb's own disassembler over the MI protocol"}
    except (RuntimeError, OSError) as exc:
        return {"ok": False, "error": str(exc)}


def breakpoints(path: str | Path, symbols: list[str]) -> dict[str, Any]:
    """Resolve symbols to addresses by setting breakpoints and reading GDB's answers.

    This is the part live probing cannot do: it answers where execution *would* stop, using the
    same symbol resolution the debugger will use at run time.
    """
    binary = Path(str(path))
    if not binary.is_file():
        return {"ok": False, "error": f"not a file: {path}"}
    if not find_gdb():
        return {"ok": False, "error": "no gdb found on this host"}
    if not symbols:
        return {"ok": False, "error": "no symbols requested"}
    resolved: list[dict[str, Any]] = []
    try:
        with Session(binary) as session:
            for symbol in symbols[:40]:
                result = session.command(f'-break-insert {symbol}')
                if not result["ok"]:
                    resolved.append({"symbol": symbol, "ok": False,
                                     "error": result["error"]})
                    continue
                # `bkpt={...}` — the braces must come off before the `name=value` parse, or the
                # first field name carries a leading `{` and never matches the pattern. That is
                # why every address came back None while the call still succeeded.
                table = result["results"].get("bkpt", "")
                if table.startswith("bkpt="):
                    table = table[len("bkpt="):]
                fields = _parse_results(table.strip().strip("{}").strip(","))
                resolved.append({"symbol": symbol, "ok": True,
                                 "address": fields.get("addr"),
                                 "function": fields.get("func"),
                                 "file": fields.get("file"),
                                 "line": fields.get("line")})
            return {"ok": True, "path": str(binary), "count": len(resolved),
                    "breakpoints": resolved,
                    "resolved": sum(1 for item in resolved if item["ok"])}
    except (RuntimeError, OSError) as exc:
        return {"ok": False, "error": str(exc)}


def registers(path: str | Path, *, args: list[str] | None = None) -> dict[str, Any]:
    """Run a binary to its entry point and read the initial register state."""
    binary = Path(str(path))
    if not binary.is_file():
        return {"ok": False, "error": f"not a file: {path}"}
    if not find_gdb():
        return {"ok": False, "error": "no gdb found on this host"}
    try:
        with Session(binary) as session:
            if args:
                session.command("-exec-arguments " + " ".join(args[:20]))
            stopped = _stop_at_entry(session, binary)
            if not stopped["ok"]:
                return {"ok": False, "path": str(binary), "error": stopped["error"]}
            values = session.command("-data-list-register-values x")
            if not values["ok"]:
                return {"ok": False, "error": values["error"]}
            names = session.command("-data-list-register-names")
            labels = _split_mi_list(names.get("results", {}).get("register-names", "")) if names["ok"] else []
            out = []
            for element in _split_mi_list(values["results"].get("register-values", "")):
                body = element
                if body.startswith("register-values="):
                    body = body[len("register-values="):]
                # Elements arrive as `{number="0",value="0x.."}`. The braces must come off before
                # the `name=value` parse or the first field name is `{number` and never matches —
                # which left every register's name None and the filtered list empty while the
                # count still reported 265.
                fields = _parse_results(body.strip().strip("{}").strip(","))
                number = fields.get("number")
                try:
                    index = int(number)
                except (TypeError, ValueError):
                    index = None
                label = None
                if index is not None and index < len(labels):
                    label = labels[index].strip('"') or None
                out.append({"number": number, "name": label, "value": fields.get("value")})
            return {"ok": True, "path": str(binary), "count": len(out),
                    "registers": [item for item in out if item["name"] or item["value"]],
                    "note": "read at the process entry point, then the process was killed"}
    except (RuntimeError, OSError) as exc:
        return {"ok": False, "error": str(exc)}
