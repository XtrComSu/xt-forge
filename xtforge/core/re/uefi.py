"""UEFI NVRAM variable reader.

Reads the efivarfs surface (`/sys/firmware/efi/efivars`) — a directory of variables,
each a file named `<Name>-<GUID>` whose first 4 bytes are the attribute bitmask and
whose remainder is the value. Also reads a single variable file, and a `Boot####`
entry's EFI_LOAD_OPTION structure, because that is the thing an investigator actually
wants: what this machine boots, and in what order.

WHY this belongs in an RE tool: UEFI variables are where Secure Boot state, boot
order, boot entries and vendor tamper markers live. A bootkit that survives OS
reinstall typically edits exactly these (a `Boot####` entry pointing at a dropped
loader, or a modified `db`/`KEK`). Reading them is the firmware counterpart of
reading an autostart entry.

THREE THINGS THAT REGULARLY GO WRONG HERE, all handled explicitly:

  * The attribute word is LITTLE-endian and precedes the value in the efivarfs file,
    but is ABSENT when the same variable arrives from `GetFirmwareEnvironmentVariable`
    or from a firmware dump. Treating the first 4 bytes of a dump as attributes
    silently eats the start of the value, so the reader decides based on whether the
    input is an efivarfs file (attributes present) or raw data (absent).
  * The filename is `<Name>-<GUID>` and BOTH parts may contain hyphens, so a naive
    split on "-" mangles names like `AmiHardwareSignatureSetupUpdateCountVar`. The
    GUID is the trailing 36 characters in 8-4-4-4-12 form; that is what is matched.
  * A boot entry's EFI_LOAD_OPTION has a UTF-16LE description whose length is
    `file_path_list_length - sizeof(EFI_DEVICE_PATH_PROTOCOL)`; reading it as
    NUL-terminated UTF-16 overshoots into the device path whenever the description
    fills its field, and truncates whenever it is shorter.
"""
from __future__ import annotations

import re
import struct
from pathlib import Path
from typing import Any

from ..route import guard
from ..route.guard import Denied

MAX_BYTES = 64 * 1024 * 1024
MAX_VARIABLES = 4096

# EFI_VARIABLE_* attribute bits (UEFI spec 8.2.3 GetVariable).
_ATTRIBUTES = {
    0x00000001: "NON_VOLATILE",
    0x00000002: "BOOTSERVICE_ACCESS",
    0x00000004: "RUNTIME_ACCESS",
    0x00000008: "HARDWARE_ERROR_RECORD",
    0x00000010: "AUTHENTICATED_WRITE_ACCESS",
    0x00000020: "TIME_BASED_AUTHENTICATED_WRITE_ACCESS",
    0x00000040: "APPEND_WRITE",
}

# Variables whose presence or content decides whether Secure Boot is actually on.
_SECURITY_VARIABLES = {
    "SecureBoot": "Secure Boot enable flag (1 = enabled)",
    "SetupMode": "1 = platform is in setup mode, i.e. keys can be replaced",
    "PK": "Platform Key — the root of trust",
    "KEK": "Key Exchange Key",
    "db": "allowed signature database",
    "dbx": "forbidden signature database (revocations)",
    "PKDefault": "default Platform Key",
    "dbt": "timestamp signature database",
    "OsIndicationsSupported": "which OS-facing features firmware supports",
    "BootOptionSupport": "which boot option types are supported",
    "PlatformLang": "firmware UI language",
}

_GUID_RE = re.compile(
    r"([0-9a-fA-F]{8})-([0-9a-fA-F]{4})-([0-9a-fA-F]{4})-"
    r"([0-9a-fA-F]{4})-([0-9a-fA-F]{12})$")


def _split_filename(name: str) -> tuple[str, str | None]:
    """Split `<Name>-<8-4-4-4-12 GUID>`. Names may contain hyphens; the GUID may not.

    Falls back to treating the name as a bare variable name when no GUID is present:
    firmware dumps are commonly stored as `SecureBoot.raw` or `Boot0000.bin`, and a
    reader that only understood the efivarfs spelling would fail to recognise the
    variable it was handed — reporting no `secure_boot_enabled` field at all rather
    than the answer.
    """
    match = _GUID_RE.search(name)
    if match:
        return name[:match.start()].rstrip("-"), match.group(0)
    stem = name
    for suffix in (".raw", ".bin", ".efi", ".dat", ".txt"):
        if stem.lower().endswith(suffix):
            stem = stem[:-len(suffix)]
            break
    return stem, None


def _attribute_names(mask: int) -> list[str]:
    return [label for bit, label in sorted(_ATTRIBUTES.items()) if mask & bit]


def parse_boot_entry(value: bytes) -> dict[str, Any]:
    """Parse an EFI_LOAD_OPTION structure (UEFI spec 3.1.3).

    Layout: Attributes (u32), FilePathListLength (u16), Description (UTF-16LE,
    NUL-terminated, occupying the whole gap up to FilePathListLength bytes), then the
    device path of FilePathListLength bytes, then optional data.
    """
    if len(value) < 6:
        return {"ok": False, "error": "too short for EFI_LOAD_OPTION"}
    attributes, path_length = struct.unpack_from("<IH", value, 0)
    header_end = 6 + path_length
    if path_length > len(value):
        return {"ok": False,
                "error": f"FilePathListLength {path_length} runs past the variable "
                         f"({len(value)} bytes)"}
    # The description is UTF-16LE and NUL-terminated. Searching for a bare
    # b"\x00\x00" finds the high byte of the *last character* followed by the low
    # byte of the terminator — that is, it stops one character early and leaves a
    # stray byte that decodes to U+FFFD. The terminator must be searched at
    # even offsets relative to the field start.
    cursor = 6
    while cursor + 1 < len(value):
        if value[cursor] == 0 and value[cursor + 1] == 0:
            break
        cursor += 2
    description_end = cursor
    description = value[6:description_end].decode("utf-16-le", "replace")
    # FilePathListLength is the length of the device path, not its offset: the
    # device path begins immediately after the description's terminator. Using
    # 6 + FilePathListLength as the start makes the first node's type/subtype bytes
    # the middle of the path, which decodes as plausible-looking nonsense
    # ("type-92/subtype-0" for a real Windows Boot Manager entry).
    device_path_offset = description_end + 2
    device_path = value[device_path_offset:device_path_offset + path_length]
    optional_data = value[device_path_offset + path_length:]
    return {
        "ok": True,
        "attributes": f"0x{attributes:08x}",
        "attribute_names": _attribute_names(attributes),
        "description": description,
        "device_path_length": path_length,
        "device_path": device_path[:128].hex(),
        "device_path_nodes": _device_path_nodes(device_path),
        "optional_data_length": len(optional_data),
        "optional_data": optional_data[:64].hex() if optional_data else None,
    }


def _device_path_nodes(blob: bytes) -> list[dict[str, Any]]:
    """Decode EFI_DEVICE_PATH_PROTOCOL nodes: (type u8, subtype u8, length u16)."""
    nodes: list[dict[str, Any]] = []
    cursor = 0
    while cursor + 4 <= len(blob) and len(nodes) < 32:
        node_type = blob[cursor]
        subtype = blob[cursor + 1]
        length = struct.unpack_from("<H", blob, cursor + 2)[0]
        if length < 4 or cursor + length > len(blob):
            break
        nodes.append({
            "type": node_type,
            "subtype": subtype,
            "name": _DEVICE_PATH_NAMES.get((node_type, subtype),
                                           f"type-{node_type}/subtype-{subtype}"),
            "length": length,
        })
        if node_type == 0x7F:  # end-of-path marker
            break
        cursor += length
    return nodes


# (type, subtype) -> name, from UEFI spec 10.3. Common nodes only.
_DEVICE_PATH_NAMES = {
    (0x01, 0x01): "Hardware/PCI",
    (0x01, 0x02): "Hardware/PCCARD",
    (0x02, 0x01): "ACPI/ACPI",
    (0x03, 0x01): "Messaging/ATAPI",
    (0x03, 0x05): "Messaging/USB",
    (0x03, 0x0A): "Messaging/MAC",
    (0x03, 0x0B): "Messaging/IPv4",
    (0x03, 0x0C): "Messaging/IPv6",
    (0x03, 0x12): "Messaging/SATA",
    (0x03, 0x17): "Messaging/NVMe",
    (0x03, 0x18): "Messaging/URI",
    (0x04, 0x01): "Media/HardDrive",
    (0x04, 0x02): "Media/CDROM",
    (0x04, 0x03): "Media/Vendor",
    (0x04, 0x04): "Media/FilePath",
    (0x04, 0x06): "Media/FvFile",
    (0x05, 0x01): "BIOS/BootSpecification",
    (0x7F, 0xFF): "End",
}


def _utc_presence_hint(value: bytes) -> str | None:
    """A time-based authenticated variable carries an EFI_TIME creation stamp."""
    if len(value) < 16:
        return None
    year, month, day, hour, minute, second = struct.unpack_from("<HBBBBB", value, 0)
    if 1900 <= year <= 2200 and 1 <= month <= 12 and 1 <= day <= 31 and hour < 24 \
            and minute < 60 and second < 60:
        return f"{year:04d}-{month:02d}-{day:02d}T{hour:02d}:{minute:02d}:{second:02d}Z"
    return None


def inspect_uefi_variables(target: str | Path,
                           has_attributes: bool | None = None) -> dict[str, Any]:
    """Read a single efivarfs variable, or every variable in an efivarfs directory.

    For a directory, returns a per-variable inventory plus the security-relevant
    subset (SecureBoot, SetupMode, PK/KEK/db/dbx) and the boot order — the three
    things anyone asking about firmware state wants first.

    `has_attributes` disambiguates the one case content cannot settle. An efivarfs
    file begins with a 4-byte attribute word; a firmware dump or a
    GetFirmwareEnvironmentVariable export does not. When the first word of a value
    happens to be a valid attribute mask (a `db` whose first four bytes are
    0x00000006, say) the two readings are indistinguishable from content alone, and
    guessing wrong silently eats or prepends four bytes. Pass True or False when the
    provenance is known; None guesses and says so in `attribute_confidence`.
    """
    path = Path(target)
    try:
        canon = guard.read_guard(path)
    except (OSError, ValueError, Denied) as exc:
        return {"ok": False, "path": str(path), "error": str(exc)}

    if canon.is_dir():
        return _inspect_directory(canon)
    return _inspect_single(canon, has_attributes)


def _inspect_single(canon: Path, has_attributes: bool | None = None) -> dict[str, Any]:
    try:
        raw = _read_file(canon)
    except (OSError, ValueError) as exc:
        return {"ok": False, "path": str(canon), "error": str(exc)}
    name, guid = _split_filename(canon.name)
    # An efivarfs file starts with a 4-byte attribute word; a raw dump does not.
    # efivarfs attribute words only use bits 0x01-0x40, so a value whose first word
    # is outside that range cannot be attributes.
    guarded = len(raw) >= 4
    confidence = "known"
    if has_attributes is None:
        has_attributes = guarded
        confidence = "inferred"
        if has_attributes:
            candidate = struct.unpack_from("<I", raw, 0)[0]
            # Only attribute bits 0x01-0x40 are defined, so anything outside that
            # range cannot be an attribute word.
            has_attributes = candidate != 0 and (candidate & ~0x7F) == 0
    elif has_attributes and not guarded:
        has_attributes = False
        confidence = "overridden"
    attributes = 0
    if has_attributes:
        attributes = struct.unpack_from("<I", raw, 0)[0]
    value = raw[4:] if has_attributes else raw
    result: dict[str, Any] = {
        "ok": True,
        "path": str(canon),
        "name": name,
        "guid": guid,
        "size": len(raw),
        "value_size": len(value),
        "attributes": f"0x{attributes:08x}" if has_attributes else None,
        "attribute_names": _attribute_names(attributes) if has_attributes else [],
        "attributes_present": has_attributes,
        "attribute_confidence": confidence,
        "raw_value": value[:512].hex(),
    }
    if name in _SECURITY_VARIABLES:
        result["significance"] = _SECURITY_VARIABLES[name]
    if name == "SecureBoot" and value:
        result["secure_boot_enabled"] = bool(value[0])
    if name == "SetupMode" and value:
        result["setup_mode"] = bool(value[0])
    if re.fullmatch(r"Boot[0-9A-Fa-f]{4}", name):
        result["boot_entry"] = parse_boot_entry(value)
    # Keyboard layout / language variables are UCS-2 text.
    if name in ("PlatformLang", "Lang", "PlatformLangCodes", "LangCodes") and value:
        result["text"] = value.decode("utf-16-le", "replace").rstrip("\x00")
    stamp = _utc_presence_hint(value)
    if stamp:
        result["possible_timestamp"] = stamp
    return result


def _read_file(canon: Path) -> bytes:
    size = canon.stat().st_size
    if size > MAX_BYTES:
        raise ValueError(f"file too large: {size} bytes")
    return canon.read_bytes()


def _inspect_directory(root: Path) -> dict[str, Any]:
    variables: list[dict[str, Any]] = []
    errors: list[str] = []
    try:
        entries = sorted(root.iterdir())
    except OSError as exc:
        return {"ok": False, "path": str(root), "error": str(exc)}

    for entry in entries[:MAX_VARIABLES]:
        if not entry.is_file() and not entry.is_symlink():
            continue
        try:
            raw = _read_file(entry)
        except (OSError, ValueError) as exc:
            # efivarfs refuses reads of write-only or authenticated variables; that
            # refusal is information ("this variable exists and is protected"), not a
            # reason to abandon the inventory.
            errors.append(f"{entry.name}: {exc}")
            continue
        name, guid = _split_filename(entry.name)
        attributes = None
        value = raw
        if len(raw) >= 4:
            candidate = struct.unpack_from("<I", raw, 0)[0]
            if candidate != 0 and (candidate & ~0x7F) == 0:
                attributes = candidate
                value = raw[4:]
        record: dict[str, Any] = {
            "name": name,
            "guid": guid,
            "size": len(raw),
            "value_size": len(value),
            "attributes": f"0x{attributes:08x}" if attributes is not None else None,
        }
        if name in _SECURITY_VARIABLES:
            record["significance"] = _SECURITY_VARIABLES[name]
        if name == "SecureBoot" and value:
            record["secure_boot_enabled"] = bool(value[0])
        if name == "SetupMode" and value:
            record["setup_mode"] = bool(value[0])
        if re.fullmatch(r"Boot[0-9A-Fa-f]{4}", name):
            record["boot_entry"] = parse_boot_entry(value)
        variables.append(record)

    boot_entries = [v for v in variables if "boot_entry" in v]
    boot_order_raw = next((v for v in variables if v["name"] == "BootOrder"), None)
    boot_order: list[str] = []
    if boot_order_raw is not None:
        # BootOrder is a plain array of u16 indices, not an EFI_LOAD_OPTION.
        order_value = _boot_order_value(root, boot_order_raw)
        if order_value:
            boot_order = [f"Boot{index:04X}" for index in order_value]

    security = {v["name"]: v for v in variables if v["name"] in _SECURITY_VARIABLES}
    secure_boot = security.get("SecureBoot", {}).get("secure_boot_enabled")
    setup_mode = security.get("SetupMode", {}).get("setup_mode")

    return {
        "ok": True,
        "path": str(root),
        "variable_count": len(variables) + len(errors),
        "readable_count": len(variables),
        "unreadable_count": len(errors),
        "unreadable": errors[:50],
        "variables": variables[:1000],
        "boot_entries": sorted(boot_entries, key=lambda v: v["name"])[:100],
        "boot_order": boot_order,
        "security": security,
        "secure_boot_enabled": secure_boot,
        "setup_mode": setup_mode,
        "assessment": _assess(secure_boot, setup_mode, security),
    }


def _boot_order_value(root: Path, record: dict[str, Any]) -> list[int]:
    """BootOrder is raw u16 indices; re-read the file to get them."""
    for entry in root.iterdir():
        name, _guid = _split_filename(entry.name)
        if name == "BootOrder" and "_" not in entry.name:
            try:
                raw = _read_file(entry)
            except (OSError, ValueError):
                return []
            value = raw[4:] if len(raw) >= 4 else raw
            count = len(value) // 2
            return list(struct.unpack_from(f"<{count}H", value, 0)) if count else []
    return []


def _assess(secure_boot: bool | None, setup_mode: bool | None,
            security: dict[str, Any]) -> str:
    if secure_boot is None:
        return "SecureBoot variable not present — firmware may not support Secure Boot"
    if setup_mode:
        return ("platform is in SETUP MODE: Secure Boot keys can be replaced by anyone "
                "with local access, and the platform is not enforcing a trust chain")
    if secure_boot:
        keys = [name for name in ("PK", "KEK", "db") if name in security]
        if len(keys) < 3:
            return (f"Secure Boot reported enabled but only {len(keys)} of PK/KEK/db "
                    "are present — the key hierarchy is incomplete")
        return "Secure Boot enabled with PK, KEK and db present"
    return "Secure Boot is DISABLED"
