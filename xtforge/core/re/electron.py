"""Electron `fuses` — the security switches baked into an Electron binary.

WHY: an Electron app ships a full Chromium and Node runtime. Several behaviours that are convenient
during development are dangerous in a shipped product: `RunAsNode` lets anyone launch the binary as
a plain Node interpreter and run their own script with the app's privileges;
`EnableNodeOptionsEnvironmentVariable` lets `NODE_OPTIONS` inject arbitrary code into the process;
`EnableNodeCliInspectArguments` opens a debugger port. Electron's answer is "fuses": a short byte
string compiled into the binary that the runtime reads at startup. An analyst looking at a packaged
Electron app wants to know which switches were flipped, because "this build still honours
`NODE_OPTIONS`" is a finding and "`OnlyLoadAppFromAsar` is disabled" is why a repack attack works.

The wire format is short and fixed, and it is documented in `@electron/fuses`
(`src/constants.ts`, `src/config.ts`, `src/index.ts`), which is the reference implementation:

    sentinel  "dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX"      32 ASCII bytes, searched in the binary
    header    version (1 byte), length (1 byte)        immediately after the sentinel
    wire      `length` bytes, one per fuse, each one of:

                0x30 '0'  disabled
                0x31 '1'  enabled
                0x72 'r'  removed (this fuse no longer does anything)
                0x90      inherit (leave as the build set it)

    FuseV1Options index -> meaning (index is the position in the wire):
        0 RunAsNode                            1 EnableCookieEncryption
        2 EnableNodeOptionsEnvironmentVariable 3 EnableNodeCliInspectArguments
        4 EnableEmbeddedAsarIntegrityValidation 5 OnlyLoadAppFromAsar
        6 LoadBrowserProcessSpecificV8Snapshot 7 GrantFileProtocolExtraPrivileges
        8 WasmTrapHandlers

Three details that decide whether a reader is right or merely plausible:

  * **The sentinel is searched, not located by offset.** The wire sits at a link-time-fixed place
    that moves between Electron versions and between architectures, so the sentinel is the only
    stable anchor. The reference streams the file in chunks with an overlap of
    `len(sentinel) - 1` so a sentinel straddling a chunk boundary is still found; a scanner that
    reads fixed blocks without the overlap silently misses it.

  * **A universal macOS binary has two sentinels**, one per architecture slice. Reporting only the
    first shows the state of one slice, which may differ from the other.

  * **`removed` is not `disabled`.** A removed fuse does nothing at all — the code path it guarded
    is gone — so reporting it as "disabled" would tell a reader a protection is off when in fact
    the thing it protected no longer exists. They are reported distinctly for that reason.
"""
from __future__ import annotations

from typing import Any

from ..route import guard
from ..route.guard import Denied

SENTINEL = b"dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX"
HEADER_LEN = 2
MAX_WIRE_LEN = 255
# Enough to cover a large Electron binary without reading a multi-gigabyte image into memory.
MAX_BYTES = 1024 * 1024 * 1024
CHUNK = 1024 * 1024

FUSE_STATES = {
    0x30: ("disabled", "0"),
    0x31: ("enabled", "1"),
    0x72: ("removed", "r"),
    0x90: ("inherit", "?"),
}

# Index -> (name, what an enabled fuse means for the app's attack surface).
FUSE_V1_OPTIONS: list[tuple[str, str]] = [
    ("RunAsNode",
     "the binary can be launched as a plain Node interpreter, running arbitrary script with the "
     "app's privileges"),
    ("EnableCookieEncryption",
     "cookies are encrypted at rest with an OS keychain-held key"),
    ("EnableNodeOptionsEnvironmentVariable",
     "NODE_OPTIONS is honoured, so the environment can inject code into the process"),
    ("EnableNodeCliInspectArguments",
     "Chromium's --inspect / --remote-debugging arguments open a debugger on the app"),
    ("EnableEmbeddedAsarIntegrityValidation",
     "the embedded app.asar is integrity-checked before it is loaded"),
    ("OnlyLoadAppFromAsar",
     "the app must load from app.asar; a loose app/ directory beside the binary is ignored"),
    ("LoadBrowserProcessSpecificV8Snapshot",
     "the browser process uses its own V8 snapshot"),
    ("GrantFileProtocolExtraPrivileges",
     "file:// URLs get extra privileges beyond the web standard"),
    ("WasmTrapHandlers",
     "WASM trap handlers are compiled in"),
]

# Which direction is the protective one. Used to say plainly whether a fuse is a hardening
# feature that is on, off, or gone — a bare "disabled" leaves the reader to work it out, and for
# `EnableNodeOptionsEnvironmentVariable` "disabled" is good news while for `OnlyLoadAppFromAsar`
# it is bad news. Reporting the name and the state without that reading is a puzzle, not a result.
_PROTECTIVE_WHEN_ENABLED = {
    "EnableCookieEncryption",
    "EnableEmbeddedAsarIntegrityValidation",
    "OnlyLoadAppFromAsar",
    "WasmTrapHandlers",
}


def _scan_for_sentinels(data: bytes) -> list[int]:
    """Every offset where the sentinel appears, in order.

    The reference implementation streams with an overlap of `len(SENTINEL) - 1` so a sentinel that
    straddles a chunk boundary is still found. Here the bytes are already in memory, so the
    equivalent care is to search the whole buffer; the constant `CHUNK` is kept so that a future
    streaming version has the boundary rule written down beside the code that must honour it.
    """
    positions: list[int] = []
    index = data.find(SENTINEL)
    while index != -1:
        positions.append(index)
        index = data.find(SENTINEL, index + 1)
    return positions


def _read_wire(data: bytes, sentinel_at: int) -> dict[str, Any]:
    """Decode the version/length header and the fuse bytes that follow a sentinel."""
    wire_at = sentinel_at + len(SENTINEL)
    if wire_at + HEADER_LEN > len(data):
        return {"ok": False, "sentinel_offset": sentinel_at,
                "error": "the sentinel is at the very end of the file; no fuse header follows"}
    version = data[wire_at]
    length = data[wire_at + 1]
    body_at = wire_at + HEADER_LEN
    body = data[body_at:body_at + length]
    fuses: list[dict[str, Any]] = []
    for index, code in enumerate(body):
        name, meaning = (FUSE_V1_OPTIONS[index] if index < len(FUSE_V1_OPTIONS)
                         else (f"unknown_{index}", "this build has a fuse the reader does not know"))
        state, symbol = FUSE_STATES.get(code, (f"unknown_code_0x{code:02x}", "?"))
        entry: dict[str, Any] = {
            "index": index,
            "name": name,
            "state": state,
            "code": code,
            "symbol": symbol,
            "meaning": meaning,
        }
        if state == "removed":
            entry["hardening"] = None
            entry["note"] = ("this fuse was removed from Electron; the code path it guarded no "
                             "longer exists, so it is neither a protection nor a risk")
        elif state == "inherit":
            # `inherit` means the wire does not set this fuse, so the binary's build-time default
            # applies and that default is not recorded here. Scoring it as exposed put four
            # protective fuses in the exposed list on an all-inherit wire, which reads as four
            # findings where the honest answer is four unknowns.
            entry["hardening"] = None
            entry["note"] = ("not set by the fuse wire, so the build-time default applies; this "
                             "reader cannot tell you what that default was")
        elif state.startswith("unknown_code"):
            # An unrecognised state byte is not evidence of anything. Scoring it fell through to
            # the capability-switch branch below and reported `hardening: True` for a byte whose
            # meaning is unknown — a protection claim invented from a byte that is not one of the
            # four documented values.
            entry["hardening"] = None
            entry["note"] = ("this is not one of the four documented fuse states; reporting it "
                             "as-is rather than guessing what it means")
        elif name in _PROTECTIVE_WHEN_ENABLED:
            entry["hardening"] = state == "enabled"
        else:
            # For RunAsNode and the other capability switches, "enabled" is the exposure.
            entry["hardening"] = state != "enabled"
        fuses.append(entry)
    return {
        "ok": True,
        "sentinel_offset": sentinel_at,
        "version": version,
        "declared_length": length,
        "wire_bytes_read": len(body),
        "fuses": fuses,
    }


def inspect_electron_fuses(path: str | bytes) -> dict[str, Any]:
    """Report the fuse state of an Electron binary.

    Accepts a path or the bytes themselves, so a caller that already has the image in memory (an
    extracted `app.asar` sibling, a carved file) does not have to write it to disk first.
    """
    try:
        if isinstance(path, (bytes, bytearray)):
            data = bytes(path[:MAX_BYTES])
            source = "<bytes>"
        else:
            canonical = guard.read_guard(path)
            if not canonical.is_file():
                return {"ok": False, "path": str(path),
                        "error": f"not a regular file: {path}"}
            data = canonical.read_bytes()[:MAX_BYTES]
            source = str(canonical)
    except (OSError, ValueError, Denied) as exc:
        return {"ok": False, "path": str(path), "error": str(exc)}

    result: dict[str, Any] = {"ok": True, "path": source, "kind": "electron-fuses",
                              "file_size": len(data)}
    positions = _scan_for_sentinels(data)
    result["sentinel_count"] = len(positions)
    if not positions:
        result["ok"] = False
        result["error"] = ("the Electron fuse sentinel was not found, so this is not an Electron "
                           "binary or it predates Electron 12, which introduced fuses")
        result["sentinel"] = SENTINEL.decode()
        return result
    if len(positions) > 2:
        # The reference implementation treats more than two as corruption. Reporting the state of
        # all of them is still more useful than refusing, but the count is called out.
        result["warning"] = (f"{len(positions)} copies of the sentinel were found; at most 2 are "
                             f"expected (one per slice of a universal macOS binary), so this "
                             f"binary may be corrupted or unusually built")

    wires = [_read_wire(data, offset) for offset in positions]
    result["wires"] = wires
    # A universal binary carries one wire per architecture. They are reported separately and the
    # primary set is the first, so a caller comparing two slices can see both.
    primary = next((wire for wire in wires if wire.get("ok")), None)
    if primary is None:
        result["ok"] = False
        # Report the wire's own diagnosis. Overwriting it with a generic sentence threw away the
        # specific reason ("the sentinel is at the very end of the file"), which is the part that
        # tells a caller whether the file is truncated.
        specific = next((wire.get("error") for wire in wires if wire.get("error")), None)
        result["error"] = specific or (
            "a sentinel was found but the fuse wire after it could not be read")
        return result
    result["version"] = primary["version"]
    result["declared_length"] = primary["declared_length"]
    result["wire_bytes_read"] = primary["wire_bytes_read"]
    result["fuse_count"] = len(primary["fuses"])
    result["fuses"] = primary["fuses"]
    if primary["wire_bytes_read"] < primary["declared_length"]:
        result["truncated"] = (f"the wire declares {primary['declared_length']} fuses but only "
                               f"{primary['wire_bytes_read']} bytes were present")
    if len(wires) > 1:
        # Compare the state codes of each readable slice. The previous version built a nested
        # comprehension that compared a list to a list-of-lists, so it returned False for two
        # identical wires — a check that could never succeed is worse than no check.
        slices = [[fuse["code"] for fuse in wire["fuses"]]
                  for wire in wires if wire.get("ok")]
        result["slices_agree"] = bool(slices) and all(
            entry == slices[0] for entry in slices[1:])
    result["exposed"] = [fuse["name"] for fuse in primary["fuses"]
                         if fuse.get("hardening") is False]
    result["hardened"] = [fuse["name"] for fuse in primary["fuses"]
                          if fuse.get("hardening") is True]
    result["removed"] = [fuse["name"] for fuse in primary["fuses"]
                         if fuse["state"] == "removed"]
    result["undetermined"] = [fuse["name"] for fuse in primary["fuses"]
                              if fuse.get("hardening") is None
                              and fuse["state"] == "inherit"]
    return result
