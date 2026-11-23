"""NTFS filesystem and `$LogFile` journal reading.

WHY: `$LogFile` is NTFS's write-ahead log. It records metadata transactions — file
creation, deletion, renames, attribute changes, timestamps — as redo/undo records. For an
analyst it is one of the few places that shows *what happened*, in order, including
activity whose end state is gone: a file deleted cleanly leaves no directory entry, but
its creation and deletion are still in the log.

Also here: a minimal MFT reader, because the journal's records refer to MFT record numbers
and a bare list of numbers is not an answer. Naming the file each transaction touched is
the difference between a data dump and a finding.

The on-disk formats used, confirmed against an image written by `mkntfs`:

    Boot sector (offset 0)
        +3   "NTFS    "          OEM ID
        +11  u16 bytes/sector
        +13  u8  sectors/cluster
        +40  u64 total sectors
        +48  u64 MFT cluster
        +72  u64 volume serial

    MFT record
        +0   "FILE"              signature
        +4   u16 USA offset, u16 USA count     (update sequence array)
        +8   u64 $LogFile sequence number
        +16  u16 sequence, u16 link count
        +20  u16 attributes offset
        +22  u16 flags          0x01 in use, 0x02 directory
        +24  u32 used size, u32 allocated size
        +42  u16 bytes per sector

    Attribute header
        +0   u32 type           0x10 STANDARD_INFORMATION, 0x30 FILE_NAME,
                                0x80 DATA, 0xFFFFFFFF end
        +4   u32 length
        +8   u8  non-resident, u8 name length, u16 name offset
        +16  u32 value length (resident) / data runs offset (non-resident)

    $LogFile restart area
        +0   "RSTR" or "CHKD"; the record header follows at the indicated offset

Four traps, all of which yield plausible output instead of an error:

  * **Update sequence array (fixups).** The last two bytes of every 512-byte sector in a
    record are replaced on disk by the USA sequence number. Skip the fixup and every
    long attribute value is silently wrong in its final two bytes per sector — invisible
    in a size field, corrupting in a timestamp.
  * **Attributes are a chain ending in 0xFFFFFFFF**, and the chain is at a variable
    offset (56 in the $MFT here). Assuming 0x30 or a fixed layout finds nothing.
  * **FILE_NAME in the MFT is UTF-16LE with a length in characters**, not bytes; and the
    file's real name lives in the *parent* directory's index, so the MFT copy is the
    best-effort name — reported as such.
  * **$LogFile is circular.** Old records are overwritten; a reader must report how much
    of the log is present rather than implying it holds all history.
"""
from __future__ import annotations

import hashlib
import struct
from pathlib import Path
from typing import Any

from ..route import guard
from ..route.guard import Denied

MAX_BYTES = 4 * 1024 * 1024 * 1024
MAX_RECORDS = 20000

ATTR_END = 0xFFFFFFFF
ATTR_STANDARD_INFORMATION = 0x10
ATTR_FILE_NAME = 0x30
ATTR_DATA = 0x80

_FILE_ATTRIBUTES = {
    0x01: "read-only", 0x02: "hidden", 0x04: "system", 0x20: "archive",
    0x40: "device", 0x80: "normal", 0x100: "temporary", 0x200: "sparse",
    0x400: "reparse-point", 0x800: "compressed", 0x1000: "offline",
    0x2000: "not-content-indexed", 0x4000: "encrypted",
}


def _read(path: str | Path, limit: int = MAX_BYTES) -> bytes:
    canon = guard.read_guard(path)
    if not canon.is_file():
        raise FileNotFoundError(f"not a regular file: {path}")
    size = canon.stat().st_size
    if size > limit:
        raise ValueError(f"image too large: {size} bytes (max {limit})")
    return canon.read_bytes()


def _apply_fixups(record: bytearray, bytes_per_sector: int) -> None:
    """Undo the update-sequence array substitution in place.

    NTFS overwrites the final two bytes of each sector with a sequence number so that a
    torn write is detectable. Every reader that ignores this returns attribute values
    whose last two bytes per sector are the sequence number — which looks like data.
    """
    if len(record) < 8:
        return
    (usa_offset, usa_count) = struct.unpack_from("<HH", record, 4)
    if not (usa_offset and usa_count) or usa_offset + usa_count * 2 > len(record):
        return
    if bytes_per_sector <= 0:
        return
    (sequence,) = struct.unpack_from("<H", record, usa_offset)
    for index in range(1, usa_count):
        position = index * bytes_per_sector - 2
        if position + 2 > len(record):
            break
        source = usa_offset + index * 2
        if source + 2 > len(record):
            break
        record[position:position + 2] = record[source:source + 2]
    # The sequence number itself is not part of the fixed-up data.
    _ = sequence


class _Volume:
    """Boot-sector facts needed to address anything in the image."""

    def __init__(self, raw: bytes) -> None:
        if len(raw) < 512:
            raise ValueError(f"image too small for an NTFS boot sector ({len(raw)} bytes)")
        if raw[3:11] != b"NTFS    ":
            raise ValueError(
                f"not an NTFS volume (OEM ID {raw[3:11]!r}, want b'NTFS    ')")
        (self.bytes_per_sector,) = struct.unpack_from("<H", raw, 11)
        self.sectors_per_cluster = raw[13]
        if not (self.bytes_per_sector and self.sectors_per_cluster):
            raise ValueError("boot sector declares a zero sector or cluster size")
        self.cluster_size = self.bytes_per_sector * self.sectors_per_cluster
        (self.total_sectors,) = struct.unpack_from("<Q", raw, 40)
        (self.mft_cluster,) = struct.unpack_from("<Q", raw, 48)
        (self.serial,) = struct.unpack_from("<Q", raw, 72)
        self.raw = raw

    @property
    def mft_offset(self) -> int:
        return self.mft_cluster * self.cluster_size

    def describe(self) -> dict[str, Any]:
        return {
            "oem_id": "NTFS",
            "bytes_per_sector": self.bytes_per_sector,
            "sectors_per_cluster": self.sectors_per_cluster,
            "cluster_size": self.cluster_size,
            "total_sectors": self.total_sectors,
            "volume_size": self.total_sectors * self.bytes_per_sector,
            "mft_cluster": self.mft_cluster,
            "mft_offset": self.mft_offset,
            "serial": f"0x{self.serial:016x}",
        }


def _attributes(record: bytes, offset: int, limit: int) -> list[dict[str, Any]]:
    """Walk the attribute chain of one MFT record."""
    attributes: list[dict[str, Any]] = []
    cursor = offset
    while cursor + 8 <= len(record) and len(attributes) < limit:
        (kind,) = struct.unpack_from("<I", record, cursor)
        if kind == ATTR_END or kind == 0:
            break
        (length,) = struct.unpack_from("<I", record, cursor + 4)
        if length < 8 or cursor + length > len(record):
            break
        non_resident = record[cursor + 8]
        name_length = record[cursor + 9]
        (name_offset,) = struct.unpack_from("<H", record, cursor + 10)
        (value_length,) = struct.unpack_from("<I", record, cursor + 16)
        entry: dict[str, Any] = {
            "_offset": cursor,
            "type": f"0x{kind:02x}" if kind <= 0xFF else f"0x{kind:08x}",
            "length": length,
            "non_resident": bool(non_resident),
            "value_length": value_length,
        }
        if name_length and name_offset:
            name_raw = record[cursor + name_offset:cursor + name_offset
                              + name_length * 2]
            entry["name"] = name_raw.decode("utf-16-le", "replace")
        if not non_resident:
            (value_offset,) = struct.unpack_from("<H", record, cursor + 20)
            value = record[cursor + value_offset:cursor + value_offset + value_length]
            if kind == ATTR_FILE_NAME and len(value) >= 66:
                entry["file_name"] = _file_name_value(value)
            # Keep a digest of resident values: it is what makes the update-sequence
            # fixup observable. Without it, a reader that skips the fixup still returns
            # correct names (FILE_NAME never crosses a sector boundary) and the bug only
            # shows up as two wrong bytes inside an attribute nobody rendered.
            entry["value_sha1"] = hashlib.sha1(value).hexdigest()[:16]
            entry["resident"] = True
        else:
            (data_runs_offset,) = struct.unpack_from("<H", record, cursor + 32)
            entry["data_runs_offset"] = data_runs_offset
            entry["resident"] = False
        attributes.append(entry)
        cursor += length
    return attributes


def _file_name_value(value: bytes) -> dict[str, Any]:
    """Decode a FILE_NAME attribute value: parent, timestamps, flags, name."""
    parent, = struct.unpack_from("<Q", value, 0)
    (name_length,) = struct.unpack_from("<B", value, 64)
    (namespace,) = struct.unpack_from("<B", value, 65)
    raw_name = value[66:66 + name_length * 2]
    file_attributes, = struct.unpack_from("<I", value, 56)
    return {
        "name": raw_name.decode("utf-16-le", "replace"),
        "parent_record": parent & 0xFFFFFFFFFFFF,
        "namespace": {0: "POSIX", 1: "Win32", 2: "DOS", 3: "Win32+DOS"}.get(
            namespace, f"0x{namespace:02x}"),
        "attributes": file_attributes,
        "attribute_names": [_FILE_ATTRIBUTES[bit] for bit in sorted(_FILE_ATTRIBUTES)
                            if file_attributes & bit],
    }


def read_mft(raw: bytes, volume: _Volume, *, limit: int = 200) -> list[dict[str, Any]]:
    """Read MFT records until the chain runs out or a record is unused."""
    records: list[dict[str, Any]] = []
    record_size = 1024
    cursor = volume.mft_offset
    while cursor + record_size <= len(raw) and len(records) < limit:
        chunk = bytearray(raw[cursor:cursor + record_size])
        if chunk[:4] != b"FILE":
            break
        _apply_fixups(chunk, volume.bytes_per_sector)
        (lsn,) = struct.unpack_from("<Q", chunk, 8)
        (sequence, link_count) = struct.unpack_from("<HH", chunk, 16)
        (attributes_offset,) = struct.unpack_from("<H", chunk, 20)
        (flags,) = struct.unpack_from("<H", chunk, 22)
        (used, allocated) = struct.unpack_from("<II", chunk, 24)
        index = len(records)
        entry: dict[str, Any] = {
            "record": index,
            "sequence": sequence,
            "link_count": link_count,
            "in_use": bool(flags & 0x01),
            "directory": bool(flags & 0x02),
            "logfile_sequence": lsn,
            "used": used,
            "allocated": allocated,
        }
        if not entry["in_use"]:
            entry["deleted"] = True
        attributes = _attributes(chunk, attributes_offset, limit=32)
        runs: list[tuple[int, int]] = []
        for attribute in attributes:
            if attribute.get("type") == "0x80" and attribute.get("non_resident"):
                runs = _data_runs(chunk, attribute.get("_offset", 0))
                if runs:
                    entry["_runs"] = runs
                    entry["data_runs"] = [{"lcn": lcn, "clusters": count}
                                          for lcn, count in runs]
                break
        for attribute in attributes:
            if attribute.get("file_name"):
                entry["name"] = attribute["file_name"]["name"]
                entry["parent_record"] = attribute["file_name"]["parent_record"]
                entry["file_attributes"] = attribute["file_name"]["attribute_names"]
                entry["namespace"] = attribute["file_name"]["namespace"]
                break
        entry["attribute_count"] = len(attributes)
        # Expose resident value digests so the fixup is auditable from the result: a
        # caller can recompute them from the raw image and see whether the update
        # sequence array was applied.
        entry["resident_values"] = [
            {"type": attribute["type"], "sha1": attribute["value_sha1"]}
            for attribute in attributes if attribute.get("value_sha1")
        ]
        records.append(entry)
        cursor += record_size
    return records


# $LogFile restart-area flags.
_LOG_FLAGS = {0x01: "clean-shutdown", 0x02: "logfile-full", 0x04: "logfile-01"}

# Common NTFS log record types, from the redo/undo opcode space used by Windows.
_LOG_OPCODES = {
    0x00: "NOP",
    0x01: "COMPENSATION_LOG_RECORD",
    0x02: "INITIALIZE_FILE_RECORD_SEGMENT",
    0x03: "DEALLOCATE_FILE_RECORD_SEGMENT",
    0x04: "WRITE_END_OF_FILE_RECORD",
    0x05: "CREATE_ATTRIBUTE",
    0x06: "DELETE_ATTRIBUTE",
    0x07: "UPDATE_RESIDENT_VALUE",
    0x08: "UPDATE_NONRESIDENT_VALUE",
    0x09: "UPDATE_MAPPING_PAIRS",
    0x0A: "DELETE_DIRTY_CLUSTERS",
    0x0B: "SET_NEW_ATTRIBUTE_SIZES",
    0x0C: "ADD_INDEX_ENTRY",
    0x0D: "DELETE_INDEX_ENTRY",
    0x0E: "SET_INDEX_ENTRY_DATA",
    0x0F: "FORGET_INDEX_ENTRY",
    0x10: "UPDATE_FILE_NAME",
    0x11: "HOTFIX_UPDATE",
    0x12: "UPDATE_FILE_NAME_SET",
    0x13: "ADD_INDEX_ROOT",
    0x14: "DELETE_INDEX_ROOT",
    0x15: "PREPARE_TRANSACTION",
    0x16: "COMMIT_TRANSACTION",
    0x17: "FORGET_TRANSACTION",
    0x18: "OPEN_NONRESIDENT_ATTRIBUTE",
    0x20: "OPEN_ATTRIBUTE_INDEX",
    0x21: "CLOSE_ATTRIBUTE_INDEX",
}


def inspect_ntfs_journal(path: str | Path, *, limit: int = 500) -> dict[str, Any]:
    """Read an NTFS volume: boot sector, MFT records and $LogFile restart area."""
    try:
        raw = _read(path)
    except (OSError, ValueError, Denied) as exc:
        return {"ok": False, "path": str(path), "error": str(exc)}

    try:
        volume = _Volume(raw)
    except (ValueError, struct.error) as exc:
        return {"ok": False, "path": str(path), "error": str(exc)}

    mft = read_mft(raw, volume, limit=limit)
    named = [record for record in mft if record.get("name")]
    live = [record for record in mft if record.get("in_use")]
    deleted = [record for record in mft if record.get("deleted")]

    # $LogFile is MFT record 2. Read its data-run list only to report whether the log is
    # present and its restart state — record-level redo/undo decoding needs the full
    # log-page state machine, which this reader does not claim.
    logfile: dict[str, Any] = {}
    for record in mft:
        if record["record"] != 2:
            continue
        logfile = {"present": True, "attributes": record.get("attribute_count", 0),
                   "size": record.get("used")}
        break

    restart = _logfile_restart(raw, volume, mft)
    if restart:
        logfile.update(restart)

    entries = [record for record in mft if record.get("name")]
    for record in mft:
        record.pop("_runs", None)
        for attribute in record.get("attributes", []):
            attribute.pop("_offset", None)

    result: dict[str, Any] = {
        "ok": True,
        "path": str(path),
        "kind": "ntfs-volume",
        "file_size": len(raw),
        "volume": volume.describe(),
        "mft_record_count": len(mft),
        "in_use_count": len(live),
        "deleted_count": len(deleted),
        "named_count": len(named),
        "logfile": logfile,
        "entries": entries[:limit],
        "records": mft[:limit],
    }
    if not restart:
        result["logfile_note"] = (
            "the $LogFile restart area did not decode; the volume is reported without "
            "transaction history rather than with a guess at it")
    return result


def _data_runs(record: bytes, attribute_offset: int) -> list[tuple[int, int]]:
    """Decode an attribute's mapping pairs into (lcn, cluster_count) runs.

    The encoding is variable-width and delta-coded: a header byte holds the byte width of
    the length and of the offset, the length is unsigned, and the offset is a SIGNED delta
    from the previous run's LCN — so a run can be expressed as "back 30 clusters". Reading
    it as fixed-width, or ignoring the delta, points at the wrong place in the image. A
    wrong $LogFile offset means a reader reports "no restart area" from bytes that were
    never the log.
    """
    if attribute_offset + 33 > len(record):
        return []
    (runs_offset,) = struct.unpack_from("<H", record, attribute_offset + 32)
    cursor = attribute_offset + runs_offset
    runs: list[tuple[int, int]] = []
    lcn = 0
    while cursor < len(record) and len(runs) < 1024:
        header = record[cursor]
        if header == 0:
            break
        length_bytes = header & 0x0F
        offset_bytes = header >> 4
        if length_bytes == 0 or cursor + 1 + length_bytes + offset_bytes > len(record):
            break
        count = int.from_bytes(
            record[cursor + 1:cursor + 1 + length_bytes], "little")
        delta = int.from_bytes(
            record[cursor + 1 + length_bytes:
                   cursor + 1 + length_bytes + offset_bytes],
            "little", signed=True)
        lcn += delta
        if count:
            runs.append((lcn, count))
        cursor += 1 + length_bytes + offset_bytes
    return runs


def _logfile_restart(raw: bytes, volume: _Volume,
                     mft: list[dict[str, Any]]) -> dict[str, Any]:
    """Locate and describe the $LogFile restart areas.

    The restart area starts with one of the signatures "RSTR" (clean) or "CHKD" (checked
    after a dirty shutdown). Searching for the signature is deliberate: resolving
    $LogFile's data runs properly requires multi-run mapping-pair decoding, and reporting
    "the log is clean" from a wrong offset is worse than reporting no restart state.
    """
    # Resolve $LogFile's own data runs rather than scanning the whole image for the
    # signature. A byte-pattern search finds "RCRD"/"RSTR" inside ordinary file data —
    # this image has an apparent RCRD at 865413 that is really a run of incrementing
    # bytes — and reporting a restart area from the wrong offset is worse than reporting
    # none.
    runs: list[tuple[int, int]] = []
    for record in mft:
        if record["record"] != 2:
            continue
        runs = record.get("_runs") or []
        break
    if not runs:
        return {}

    first_lcn, first_count = runs[0]
    start = first_lcn * volume.cluster_size
    span = first_count * volume.cluster_size
    if start >= len(raw) or span <= 0:
        return {}
    log = raw[start:min(start + span, len(raw))]

    for signature, label in ((b"RSTR", "clean"), (b"CHKD", "dirty")):
        index = log.find(signature)
        if index == -1:
            continue
        area: dict[str, Any] = {
            "restart_signature": signature.decode(),
            "shutdown": label,
            "offset_in_log": index,
            "log_offset": start,
            "log_clusters": first_count,
            "log_size": len(log),
        }
        if index + 32 <= len(log):
            (system_page_size, log_page_size,
             _restart_offset, minor, major) = struct.unpack_from(
                "<IIHHh", log, index + 8)
            area["system_page_size"] = system_page_size
            area["log_page_size"] = log_page_size
            area["major_version"] = major
            area["minor_version"] = minor
        return area

    # No restart area. Report what the log ACTUALLY contains, because a caller needs to
    # know the difference between "the log is clean" and "this image has no journal".
    (ff,) = (sum(1 for byte in log if byte == 0xFF),)
    (zero,) = (sum(1 for byte in log if byte == 0x00),)
    return {
        "restart_signature": None,
        "shutdown": "unknown",
        "log_offset": start,
        "log_clusters": first_count,
        "log_size": len(log),
        "erased_bytes": ff,
        "zero_bytes": zero,
        "formatted_only": (ff + zero) == len(log),
    }


def inspect(path: str | Path, **kwargs: Any) -> dict[str, Any]:
    return inspect_ntfs_journal(path, **kwargs)
