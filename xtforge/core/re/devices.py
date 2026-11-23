"""Flattened devicetree (.dtb), kernel build config, and Windows shortcut (.lnk).

WHY together: three narrow container formats that each answer one question an
analyst asks about a device or a workstation image — what hardware is described,
how was the kernel configured, and what does this shortcut actually launch. REA
carries `inspect_devicetree`, `inspect_kernel_build_config` and
`inspect_windows_shortcut`; these are the same three questions.

Each reader returns {"ok": bool, ...} and never raises on unexpected input.

Two things in these formats regularly produce confidently wrong output and are
handled explicitly here:

  * A .dtb is frequently embedded inside a larger container — a boot image, an
    Android DTB partition dump, a FIT — at an offset that is not 0. Assuming the
    header is at byte 0 reads the container's own bytes as an FDT header and
    produces nonsense offsets. The magic is searched for instead.
  * FDT struct-block token alignment is relative to the *struct block start*, not
    to the file and not to the header. Per ECMA-style padding rules the struct
    block is itself 4-byte aligned, so the two readings usually coincide; they part
    company as soon as a container places the block at a non-aligned offset, and
    the failure mode is silent token skipping rather than an error. The code uses
    the struct-relative form because that is what the format specifies.
"""
from __future__ import annotations

import datetime as _dt
import struct
from pathlib import Path
from typing import Any

from ..route import guard
from ..route.guard import Denied

MAX_BYTES = 256 * 1024 * 1024

# FDT header magic (big-endian), and the struct-block tokens.
FDT_MAGIC = 0xD00DFEED
FDT_BEGIN_NODE = 0x00000001
FDT_END_NODE = 0x00000002
FDT_PROP = 0x00000003
FDT_NOP = 0x00000004
FDT_END = 0x00000009

MAX_NODES = 20000
MAX_PROPS = 100000
MAX_DEPTH = 64


def _read(path: str | Path, limit: int = MAX_BYTES) -> bytes:
    canon = guard.read_guard(path)
    if not canon.is_file():
        raise FileNotFoundError(f"not a regular file: {path}")
    size = canon.stat().st_size
    if size > limit:
        raise ValueError(f"file too large: {size} bytes (max {limit})")
    return canon.read_bytes()


# ------------------------------------------------------------------ devicetree
def _find_fdt(raw: bytes) -> int | None:
    """Locate the FDT header, which may be inside a container.

    Returns the offset of a header whose declared total size fits in the file.
    A bare magic is not enough: the 4 bytes occur by chance in binaries, and a
    false positive yields an unparseable tree rather than an error, so the size
    consistency check is part of detection.
    """
    magic = struct.pack(">I", FDT_MAGIC)
    start = 0
    while True:
        index = raw.find(magic, start)
        if index < 0:
            return None
        if index + 40 <= len(raw):
            total = struct.unpack_from(">I", raw, index + 4)[0]
            if 40 <= total <= len(raw) - index:
                return index
        start = index + 1


def _parse_fdt(raw: bytes, base: int) -> dict[str, Any]:
    (magic, total, off_struct, off_strings, off_rsvmap, version,
     last_comp, boot_cpu, size_strings, size_struct) = struct.unpack_from(
        ">10I", raw, base)

    if magic != FDT_MAGIC:
        raise ValueError(f"bad FDT magic 0x{magic:08x}")
    if base + total > len(raw):
        raise ValueError(f"FDT declares {total} bytes but only {len(raw) - base} remain")
    if version < 16:
        raise ValueError(f"unsupported FDT version {version}")
    if off_struct + size_struct > total:
        raise ValueError("struct block runs past the declared total size")
    if off_strings + size_strings > total:
        raise ValueError("strings block runs past the declared total size")

    struct_start = base + off_struct
    struct_end = struct_start + size_struct
    strings_start = base + off_strings
    strings_end = strings_start + size_strings

    def string_at(index: int) -> str:
        cursor = strings_start + index
        if cursor >= strings_end:
            return ""
        end = raw.find(b"\0", cursor, strings_end)
        if end < 0:
            return ""
        return raw[cursor:end].decode("utf-8", "replace")

    nodes: list[dict[str, Any]] = []
    properties: list[dict[str, Any]] = []
    stack: list[str] = []
    pos = struct_start
    truncated = False

    while pos + 4 <= struct_end:
        (token,) = struct.unpack_from(">I", raw, pos)
        pos += 4
        if token == FDT_BEGIN_NODE:
            if len(stack) > MAX_DEPTH:
                truncated = True
                break
            end = raw.find(b"\0", pos, struct_end)
            if end < 0:
                raise ValueError("unterminated node name")
            name = raw[pos:end].decode("utf-8", "replace")
            pos = end + 1
            # Alignment is relative to the struct block, not to the file.
            pos += (-(pos - struct_start)) % 4
            unit_address = None
            node_name = name
            if "@" in name:
                node_name, _, unit_address = name.partition("@")
            path = "/" + "/".join([p for p in stack if p] + ([name] if name else []))
            nodes.append({"path": path, "name": node_name or "/",
                          "unit_address": unit_address, "depth": len(stack)})
            stack.append(name)
            if len(nodes) >= MAX_NODES:
                truncated = True
                break
        elif token == FDT_END_NODE:
            if stack:
                stack.pop()
        elif token == FDT_PROP:
            if pos + 8 > struct_end:
                raise ValueError("truncated property header")
            length, name_off = struct.unpack_from(">II", raw, pos)
            pos += 8
            if length > struct_end - pos:
                raise ValueError(f"property length {length} runs past the struct block")
            value = raw[pos:pos + length]
            pos += length
            pos += (-(pos - struct_start)) % 4
            prop_name = string_at(name_off)
            properties.append({
                "node": "/" + "/".join([p for p in stack if p]),
                "name": prop_name,
                "length": length,
                "value": _describe_prop(value),
            })
            if len(properties) >= MAX_PROPS:
                truncated = True
                break
        elif token == FDT_NOP:
            continue
        elif token == FDT_END:
            break
        else:
            raise ValueError(f"unexpected FDT token 0x{token:08x} at offset {pos - 4}")

    if pos > struct_end:
        raise ValueError("struct block walk ran past its declared size")

    # A devicetree's memory reservation block is a list of (address, size) pairs
    # terminated by a zero pair.
    reservations = []
    rsv = base + off_rsvmap
    while rsv + 16 <= base + total and len(reservations) < 64:
        address, size = struct.unpack_from(">QQ", raw, rsv)
        rsv += 16
        if address == 0 and size == 0:
            break
        reservations.append({"address": address, "size": size})

    model = next((p["value"] for p in properties
                  if p["name"] == "model" and p["node"] == "/"), None)
    compatible = next((p["value"] for p in properties
                       if p["name"] == "compatible" and p["node"] == "/"), None)

    return {
        "ok": True,
        "header_offset": base,
        "total_size": total,
        "version": version,
        "last_compatible_version": last_comp,
        "boot_cpuid": boot_cpu,
        "struct_block": {"offset": struct_start, "size": size_struct},
        "strings_block": {"offset": strings_start, "size": size_strings},
        "node_count": len(nodes),
        "property_count": len(properties),
        "max_depth": max((n["depth"] for n in nodes), default=0),
        "model": model,
        "compatible": compatible,
        "memory_reservations": reservations,
        "nodes": nodes[:500],
        "properties": properties[:2000],
        "truncated": truncated,
        "embedded": base != 0,
    }


def _describe_prop(value: bytes) -> Any:
    """Render a property value the way dtc does: strings, cells, or bytes."""
    if not value:
        return ""
    # A string list: printable ASCII ending in NUL.
    if value[-1:] == b"\0" and all(32 <= b < 127 or b == 0 for b in value):
        try:
            text = value[:-1].decode("ascii")
            return text.split("\0") if "\0" in text else text
        except UnicodeDecodeError:
            pass
    # A cell list: 4-byte aligned, big-endian.
    if len(value) % 4 == 0 and len(value) <= 64:
        cells = struct.unpack(f">{len(value) // 4}I", value)
        return {"cells": [f"0x{c:x}" for c in cells]}
    return {"bytes": value[:64].hex() + ("..." if len(value) > 64 else "")}


def inspect_devicetree(path: str | Path) -> dict[str, Any]:
    try:
        raw = _read(path)
    except (OSError, ValueError, Denied) as exc:
        return {"ok": False, "path": str(path), "error": str(exc)}

    base = _find_fdt(raw)
    if base is None:
        return {"ok": False, "path": str(path),
                "error": "no FDT header found (not a devicetree blob)"}
    try:
        result = _parse_fdt(raw, base)
    except (ValueError, struct.error) as exc:
        return {"ok": False, "path": str(path), "header_offset": base,
                "error": f"malformed devicetree: {exc}"}
    result["path"] = str(path)
    return result


# --------------------------------------------------------------- kernel config
_IKCFG_ST = b"IKCFG_ST"
_IKCFG_ED = b"IKCFG_ED"
# config_data holds gzip bytes; config_gz holds the gzip magic. Extracting the
# blob is only a matter of finding the first gzip header between the markers.
_GZIP_MAGIC = b"\x1f\x8b\x08"


def inspect_kernel_config(path: str | Path) -> dict[str, Any]:
    """Extract a kernel's embedded CONFIG_IKCONFIG blob.

    A Linux kernel built with CONFIG_IKCONFIG embeds its own .config between the
    markers IKCFG_ST and IKCFG_ED, gzip-compressed. That is the authoritative
    answer to "how was this kernel built" — a config file sitting next to a kernel
    image is not evidence about the image.

    Also accepts a plain .config or /proc/config.gz so the same verb answers the
    text case.
    """
    try:
        raw = _read(path)
    except (OSError, ValueError, Denied) as exc:
        return {"ok": False, "path": str(path), "error": str(exc)}

    start = raw.find(_IKCFG_ST)
    end = raw.find(_IKCFG_ED)
    source = None
    blob = None

    if start >= 0 and end > start:
        source = "embedded IKCONFIG"
        region = raw[start + len(_IKCFG_ST):end]
        offset = region.find(_GZIP_MAGIC)
        if offset < 0:
            return {"ok": False, "path": str(path), "source": source,
                    "error": "IKCONFIG markers present but no gzip blob between them"}
        blob = region[offset:]
    elif raw[:3] == _GZIP_MAGIC:
        source = "gzip (/proc/config.gz)"
        blob = raw
    elif b"CONFIG_" in raw[:4096]:
        source = "plaintext .config"
        text = raw.decode("utf-8", "replace")
        return _summarise_config(text, path, source)
    else:
        return {"ok": False, "path": str(path),
                "error": "no kernel config found (no IKCONFIG markers, not gzip, "
                         "no CONFIG_ lines)"}

    import gzip
    try:
        decompressed = gzip.decompress(blob)
    except OSError as exc:
        return {"ok": False, "path": str(path), "source": source,
                "error": f"config blob is not valid gzip: {exc}"}
    text = decompressed.decode("utf-8", "replace")
    return _summarise_config(text, path, source)


def _summarise_config(text: str, path: str | Path, source: str) -> dict[str, Any]:
    enabled: list[str] = []
    modules: list[str] = []
    disabled: list[str] = []
    values: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        key, _, value = line.partition("=")
        if not key.startswith("CONFIG_"):
            continue
        if value == "y":
            enabled.append(key)
        elif value == "m":
            modules.append(key)
        elif value == "n":
            disabled.append(key)
        else:
            values[key] = value
    # The settings an investigator reads first.
    interesting = {}
    for key in ("CONFIG_LOCALVERSION", "CONFIG_VERSION_SIGNATURE", "CONFIG_DEVTMPFS",
                "CONFIG_MODULES", "CONFIG_KALLSYMS", "CONFIG_KALLSYMS_ALL",
                "CONFIG_DEBUG_INFO", "CONFIG_STRICT_KERNEL_RWX", "CONFIG_RANDOMIZE_BASE",
                "CONFIG_STACKPROTECTOR", "CONFIG_SECURITY_SELINUX",
                "CONFIG_SECURITY_SELINUX_ENFORCING", "CONFIG_SECURITY",
                "CONFIG_PROC_KCORE", "CONFIG_IKCONFIG", "CONFIG_IKCONFIG_PROC"):
        if key in values:
            interesting[key] = values[key]
        elif key in enabled:
            interesting[key] = "y"
        elif key in modules:
            interesting[key] = "m"
        elif key in disabled:
            interesting[key] = "n"
    return {
        "ok": True,
        "path": str(path),
        "source": source,
        "enabled_count": len(enabled),
        "module_count": len(modules),
        "disabled_count": len(disabled),
        "version": values.get("CONFIG_LOCALVERSION", "").strip('"') or None,
        "settings": interesting,
        "enabled_sample": enabled[:200],
        "truncated": len(enabled) > 200,
    }


# ------------------------------------------------------------ windows shortcut
# ShellLinkHeader flags (MS-SHLLINK 2.1).
_LNK_FLAGS = {
    0x00000001: "HasLinkTargetIDList", 0x00000002: "HasLinkInfo",
    0x00000004: "HasName", 0x00000008: "HasRelativePath",
    0x00000010: "HasWorkingDir", 0x00000020: "HasArguments",
    0x00000040: "HasIconLocation", 0x00000080: "IsUnicode",
    0x00000100: "ForceNoLinkInfo", 0x00000200: "HasExpString",
    0x00000400: "RunInSeparateProcess", 0x00000800: "Unused1",
    0x00001000: "HasDarwinID", 0x00002000: "RunAsUser",
    0x00004000: "HasExpIcon", 0x00008000: "NoPidlAlias",
    0x00010000: "RunWithShimLayer", 0x00020000: "ForceNoLinkTrack",
    0x00040000: "EnableTargetMetadata", 0x00080000: "DisableLinkPathTracking",
    0x00100000: "DisableKnownFolderTracking",
    0x00200000: "DisableKnownFolderAlias", 0x00400000: "AllowLinkToLink",
    0x00800000: "UnaliasOnSave", 0x01000000: "PreferEnvironmentPath",
    0x02000000: "KeepLocalIDListForUNCTarget",
}
_LNK_CLSID = bytes.fromhex("0114020000000000c000000000000046")

# LinkInfoHeaderSize and flags (MS-SHLLINK 2.3).
_VOLUME_ID_AND_LOCAL_BASE_PATH = 0x00000001
_COMMON_NETWORK_RELATIVE_LINK_AND_PATH_SUFFIX = 0x00000002


def inspect_shortcut(path: str | Path) -> dict[str, Any]:
    """Parse a Windows .lnk shell link: the target it launches and with what.

    The analyst question is the same one a .desktop entry answers on Linux: what
    program does this icon actually run? The answer lives in LinkInfo and the
    StringData entries, and both are parsed here.

    A shortcut whose target has been rewritten is a common persistence trick, so
    the CommandLineArguments and WorkingDir strings matter as much as the path.
    """
    try:
        raw = _read(path, limit=1024 * 1024)
    except (OSError, ValueError, Denied) as exc:
        return {"ok": False, "path": str(path), "error": str(exc)}

    if len(raw) < 0x4C:
        return {"ok": False, "path": str(path), "error": "file too small for a shell link"}
    header_size = struct.unpack_from("<I", raw, 0)[0]
    if header_size != 0x4C:
        return {"ok": False, "path": str(path),
                "error": f"unexpected ShellLinkHeader size 0x{header_size:x} "
                         "(expected 0x4c)"}
    if raw[4:20] != _LNK_CLSID:
        return {"ok": False, "path": str(path),
                "error": "CLSID does not match the shell link class"}

    flags = struct.unpack_from("<I", raw, 0x14)[0]
    file_attributes = struct.unpack_from("<I", raw, 0x18)[0]
    (creation, access, write) = struct.unpack_from("<QQQ", raw, 0x1C)
    file_size, icon_index, show_command, hotkey = struct.unpack_from(
        "<IIIH", raw, 0x34)

    result: dict[str, Any] = {
        "ok": True,
        "path": str(path),
        "flags": f"0x{flags:08x}",
        "flag_names": [name for bit, name in sorted(_LNK_FLAGS.items()) if flags & bit],
        "file_attributes": f"0x{file_attributes:08x}",
        "target_file_size": file_size,
        "show_command": {1: "Normal", 3: "Maximized", 7: "Minimized"}.get(
            show_command, str(show_command)),
        "icon_index": icon_index,
        "unicode": bool(flags & 0x00000080),
    }
    for label, stamp in (("creation_time", creation), ("access_time", access),
                         ("write_time", write)):
        result[label] = _filetime(stamp)

    cursor = header_size
    # LinkTargetIDList: a 2-byte size followed by that many bytes of IDList.
    if flags & 0x00000001:
        if cursor + 2 > len(raw):
            result["warning"] = "IDList size runs past end of file"
            return result
        idlist_size = struct.unpack_from("<H", raw, cursor)[0]
        result["id_list_size"] = idlist_size
        cursor += 2 + idlist_size

    if flags & 0x00000002 and cursor + 4 <= len(raw):
        link_info_size = struct.unpack_from("<I", raw, cursor)[0]
        if 0 < link_info_size <= len(raw) - cursor:
            result.update(_parse_link_info(raw, cursor, link_info_size))

    # StringData follows, in the fixed order the spec requires. Its presence is
    # declared by flags, and each entry is a 2-byte count + text in UTF-16 or ANSI.
    string_fields = (
        (0x00000004, "name"),
        (0x00000008, "relative_path"),
        (0x00000010, "working_directory"),
        (0x00000020, "command_line_arguments"),
        (0x00000040, "icon_location"),
    )
    wide = bool(flags & 0x00000080)
    for bit, name in string_fields:
        if not flags & bit:
            continue
        if cursor + 2 > len(raw):
            break
        count = struct.unpack_from("<H", raw, cursor)[0]
        cursor += 2
        length = count * 2 if wide else count
        if cursor + length > len(raw):
            result.setdefault("warnings", []).append(f"{name} runs past end of file")
            break
        chunk = raw[cursor:cursor + length]
        cursor += length
        result[name] = chunk.decode("utf-16-le" if wide else "latin-1", "replace").rstrip("\0")

    # The most useful single field: the command this shortcut runs.
    target = (result.get("local_base_path") or result.get("relative_path")
              or result.get("name") or "")
    arguments = result.get("command_line_arguments") or ""
    result["command"] = (f"{target} {arguments}".strip() or None)
    return result


def _parse_link_info(raw: bytes, offset: int, size: int) -> dict[str, Any]:
    """Parse a LinkInfo structure (MS-SHLLINK 2.3).

    The header grew: the pre-Windows-2000 form is 0x1C bytes and has no
    LocalBasePathOffsetUnicode, so reading the Unicode field unconditionally reads
    into the path string and returns garbage. HeaderSize is the discriminator.
    """
    out: dict[str, Any] = {}
    hdr_size = struct.unpack_from("<I", raw, offset + 4)[0]
    flags = struct.unpack_from("<I", raw, offset + 8)[0]
    base = offset
    if hdr_size >= 0x24:
        (volume_id_offset, local_base_path_offset, _cnrl_offset,
         _suffix_offset, local_base_path_offset_unicode) = struct.unpack_from(
            "<IIIII", raw, offset + 12)
    else:
        (volume_id_offset, local_base_path_offset) = struct.unpack_from(
            "<II", raw, offset + 12)
        local_base_path_offset_unicode = 0

    def ansi_string(relative: int) -> str | None:
        if not relative:
            return None
        start = base + relative
        end = raw.find(b"\0", start, min(len(raw), base + size))
        if end < 0:
            return None
        return raw[start:end].decode("latin-1", "replace")

    def wide_string(relative: int) -> str | None:
        if not relative:
            return None
        start = base + relative
        end = start
        limit = min(len(raw), base + size)
        while end + 1 < limit and raw[end:end + 2] != b"\0\0":
            end += 2
        if end == start:
            return None
        return raw[start:end].decode("utf-16-le", "replace")

    out["link_info_header_size"] = hdr_size
    out["link_info_flags"] = f"0x{flags:08x}"
    if flags & _VOLUME_ID_AND_LOCAL_BASE_PATH and volume_id_offset:
        vol = base + volume_id_offset
        if vol + 16 <= len(raw):
            vol_size, drive_type, serial, label_off = struct.unpack_from(
                "<IIII", raw, vol)
            out["volume"] = {
                "drive_type": {0: "Unknown", 1: "NoRootDir", 2: "Removable",
                               3: "Fixed", 4: "Remote", 5: "CDRom", 6: "RamDisk"}.get(
                                   drive_type, str(drive_type)),
                "serial": f"0x{serial:08x}",
            }
            if label_off:
                start = vol + label_off
                end = raw.find(b"\0", start, min(len(raw), base + size))
                if end > start:
                    out["volume"]["label"] = raw[start:end].decode("latin-1", "replace")

    path = weak = None
    if local_base_path_offset_unicode:
        weak = wide_string(local_base_path_offset_unicode)
    path = ansi_string(local_base_path_offset)
    chosen = weak or path
    if chosen:
        out["local_base_path"] = chosen
    if flags & _COMMON_NETWORK_RELATIVE_LINK_AND_PATH_SUFFIX:
        out["network_relative"] = True
    return out


def _filetime(value: int) -> str | None:
    """FILETIME is 100-ns intervals since 1601-01-01 UTC."""
    if not value:
        return None
    try:
        epoch = _dt.datetime(1601, 1, 1, tzinfo=_dt.UTC)
        return (epoch + _dt.timedelta(microseconds=value // 10)).isoformat()
    except (OverflowError, ValueError):
        return None
