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
        # Decode the records themselves. The restart area says whether the log is clean; the
        # records say what happened, which is the question an analyst actually has.
        log_start = restart.get("log_offset")
        log_size = restart.get("log_size")
        if log_start is not None and log_size:
            restart_area = restart.get("restart_area") or {}
            decoded = _decode_log_records(
                raw[log_start:log_start + log_size],
                page_data_offset=restart_area.get("log_page_data_offset") or 0,
                page_size=restart.get("log_page_size") or 0)
            logfile["records"] = {
                "record_count": decoded["record_count"],
                "page_count": decoded["page_count"],
                "transaction_count": decoded["transaction_count"],
                "orphan_record_count": decoded["orphan_record_count"],
                "transactions": decoded["transactions"],
            }
            # @@@LOG_RECORDS@@@

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
        # Field offsets per ntfs-3g's logfile.h, which is the authority here:
        #   0  magic          4  usa_ofs        6  usa_count
        #   8  chkdsk_lsn (8 bytes)
        #  16  system_page_size   20  log_page_size
        #  24  restart_area_offset  26 minor_ver  28 major_ver
        # The first version of this read every field 8 bytes early — it took the low half of
        # chkdsk_lsn as system_page_size — so a real journal would have been reported with a
        # nonsense page size and version. Caught by writing a restart page with known values
        # and comparing against what ntfsrecover makes of it.
        if index + 32 <= len(log):
            system_page_size = struct.unpack_from("<I", log, index + 16)[0]
            log_page_size = struct.unpack_from("<I", log, index + 20)[0]
            restart_offset = struct.unpack_from("<H", log, index + 24)[0]
            minor = struct.unpack_from("<H", log, index + 26)[0]
            major = struct.unpack_from("<H", log, index + 28)[0]
            area["system_page_size"] = system_page_size
            area["log_page_size"] = log_page_size
            area["restart_area_offset"] = restart_offset
            area["major_version"] = major
            area["minor_version"] = minor
            # chkdsk_lsn is meaningful: non-zero means chkdsk modified the log, which is a
            # stronger statement than the RSTR/CHKD signature alone.
            area["chkdsk_lsn"] = struct.unpack_from("<Q", log, index + 8)[0]

            # RESTART_AREA follows at `restart_area_offset` from the page header. Its fields are
            # what the record walk actually needs: `log_page_data_offset` is the authoritative
            # offset to the first log record in a page, and `file_size` bounds the log. Searching
            # for "RCRD" and guessing 0x40 instead of reading this is how a reader ends up decoding
            # a page's fixup array as a record header.
            #
            #   +0  u64 current_lsn         +16 u32 seq_number_bits
            #   +8  u16 log_clients         +20 u16 restart_area_length
            #   +10 u16 client_free_list    +22 u16 client_array_offset
            #   +12 u16 client_in_use_list  +24 s64 file_size
            #   +14 u16 flags               +32 u32 last_lsn_data_length
            #                               +36 u16 log_record_header_length
            #                               +38 u16 log_page_data_offset
            #                               +40 u32 restart_log_open_count
            restart_at = index + restart_offset
            if restart_offset and restart_at + 48 <= len(log):
                (current_lsn,) = struct.unpack_from("<Q", log, restart_at)
                (log_clients, client_free, client_in_use, rest_flags) = struct.unpack_from(
                    "<HHHH", log, restart_at + 8)
                (seq_number_bits, area_length, client_array_offset) = struct.unpack_from(
                    "<IHH", log, restart_at + 16)
                (file_size,) = struct.unpack_from("<q", log, restart_at + 24)
                (last_lsn_data_length, record_header_length, page_data_offset,
                 open_count) = struct.unpack_from("<IHHI", log, restart_at + 32)
                area["restart_area"] = {
                    "current_lsn": current_lsn,
                    "log_clients": log_clients,
                    "client_free_list": client_free,
                    "client_in_use_list": client_in_use,
                    "volume_is_clean": bool(rest_flags & 0x0002),
                    "seq_number_bits": seq_number_bits,
                    "restart_area_length": area_length,
                    "client_array_offset": client_array_offset,
                    "file_size": file_size,
                    "log_record_header_length": record_header_length,
                    "log_page_data_offset": page_data_offset,
                    "restart_log_open_count": open_count,
                }
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


# ---------------------------------------------------------------------------
# $LogFile record pages
#
# The restart area says whether the log is clean; it does not say what happened. The records do,
# and until now this reader stopped at the restart area. The layouts below come from ntfs-3g's
# `include/ntfs-3g/logfile.h`, which is the reference used by `ntfsrecover`:
#
#     RECORD_PAGE_HEADER (0x40 bytes after the fixup array)
#         +0   "RCRD"          magic
#         +4   u16 usa_ofs, u16 usa_count
#         +8   u64 last_lsn / file_offset   (union: copy)
#         +16  u32 flags
#         +20  u16 page_count, u16 page_position
#         +24  u16 next_record_offset, 6 reserved, u64 last_end_lsn
#
#     LOG_RECORD (constant 0x70 bytes; the header is padded to a 64-bit boundary so the client
#     data that follows is 64-bit aligned)
#         +0    u64 this_lsn
#         +8    u64 client_previous_lsn
#         +16   u64 client_undo_next_lsn
#         +24   u32 client_data_length
#         +28   u16 client_id.seq_number, u16 client_id.client_index
#         +32   u32 record_type
#         +36   u32 transaction_id
#         +40   u16 flags
#         +42   u16 reserved[3]
#         +48   u16 redo_operation, u16 undo_operation
#         +52   u16 redo_offset, u16 redo_length
#         +56   u16 undo_offset, u16 undo_length
#         +60   u16 target_attribute, u16 lcns_to_follow
#         +64   u16 record_offset, u16 attribute_offset
#         +68   u32 alignment, u64 target_vcn
#
# The deliverable the row was missing is the *transaction* view: a flat list of LSNs says nothing,
# whereas grouping records by `transaction_id` says "these four log records were one atomic
# operation". That grouping is what a transaction record is.
# ---------------------------------------------------------------------------

RECORD_PAGE_MAGIC = b"RCRD"
LOG_RECORD_SIZE = 0x70
RECORD_PAGE_HEADER_SIZE = 0x40


def _decode_log_records(log: bytes, *, page_data_offset: int = 0,
                        page_size: int = 0, limit: int = 2000) -> dict[str, Any]:
    """Walk every "RCRD" page in a log buffer and decode the LOG_RECORD headers in it.

    Beyond the structures, three things about this format shape the code:

      * **Pages are fixed-size but records are not.** Each page is `log_page_size` bytes and holds
        headers back to back until `next_record_offset` says where the next one starts (0 meaning
        the end of the page). Records are packed, not aligned to a fixed stride, so the walk
        follows the length the header states.
      * **A record's data follows its header**, padded to a 64-bit boundary. Advancing by
        `LOG_RECORD_SIZE` alone therefore lands mid-data on the next iteration and decodes noise as
        an LSN — the failure mode that produces confident garbage rather than an error.
      * **The log is circular.** Records arrive out of LSN order across wrap-around, so they are
        reported in the order found and sorted by LSN only for the transaction view, which is a
        property of the ids rather than of the layout.
    """
    chunks: list[dict[str, Any]] = []
    pages: list[dict[str, Any]] = []
    offset = log.find(RECORD_PAGE_MAGIC)
    seen_offsets: set[int] = set()
    while offset != -1 and len(chunks) < limit:
        if offset in seen_offsets:
            break
        seen_offsets.add(offset)
        page = log[offset:]
        if len(page) < RECORD_PAGE_HEADER_SIZE:
            break
        page_flags = struct.unpack_from("<I", page, 16)[0]
        page_count, page_position = struct.unpack_from("<HH", page, 20)[0:2]
        next_record = struct.unpack_from("<H", page, 24)[0]
        pages.append({"offset": offset, "flags": page_flags, "page_count": page_count,
                      "page_position": page_position, "next_record_offset": next_record})

        # Records begin at the restart area's `log_page_data_offset`, which accounts for the
        # page header AND its update-sequence array. `next_record_offset` is where the *next
        # record starts*, i.e. after the first one — not where the first one is. Using it as the
        # start skipped the first record of every page; using 0x40 decoded fixup bytes as a header.
        start = page_data_offset if page_data_offset else RECORD_PAGE_HEADER_SIZE
        cursor = start if 0 < start < len(page) else RECORD_PAGE_HEADER_SIZE
        guard_steps = 0
        while cursor + LOG_RECORD_SIZE <= len(page) and len(chunks) < limit:
            guard_steps += 1
            if guard_steps > 4096:
                break
            this_lsn = struct.unpack_from("<Q", page, cursor)[0]
            previous_lsn = struct.unpack_from("<Q", page, cursor + 8)[0]
            undo_next_lsn = struct.unpack_from("<Q", page, cursor + 16)[0]
            data_length = struct.unpack_from("<I", page, cursor + 24)[0]
            client_seq, client_index = struct.unpack_from("<HH", page, cursor + 28)[0:2]
            record_type = struct.unpack_from("<I", page, cursor + 32)[0]
            transaction_id = struct.unpack_from("<I", page, cursor + 36)[0]
            record_flags = struct.unpack_from("<H", page, cursor + 40)[0]
            redo_op, undo_op = struct.unpack_from("<HH", page, cursor + 48)[0:2]
            redo_off, redo_len = struct.unpack_from("<HH", page, cursor + 52)[0:2]
            undo_off, undo_len = struct.unpack_from("<HH", page, cursor + 56)[0:2]
            target_attribute, lcns_to_follow = struct.unpack_from("<HH", page, cursor + 60)[0:2]
            record_offset, attribute_offset = struct.unpack_from("<HH", page, cursor + 64)[0:2]
            target_vcn = struct.unpack_from("<Q", page, cursor + 72)[0]                 if cursor + 80 <= len(page) else None

            # Reject an implausible header rather than reporting it. A real record has a non-zero
            # LSN and a data length that fits the page; a stride landing mid-data almost never
            # satisfies both, and reporting the few that do is far better than reporting all of
            # them as transactions.
            if not this_lsn:
                cursor += LOG_RECORD_SIZE
                continue
            if data_length > len(page):
                cursor += LOG_RECORD_SIZE
                continue

            chunk: dict[str, Any] = {
                "this_lsn": this_lsn,
                "client_previous_lsn": previous_lsn,
                "client_undo_next_lsn": undo_next_lsn,
                "client_data_length": data_length,
                "client_id": {"sequence_number": client_seq, "index": client_index},
                "record_type": record_type,
                "transaction_id": transaction_id,
                "flags": record_flags,
                "redo": {"operation": redo_op, "offset": redo_off, "length": redo_len},
                "undo": {"operation": undo_op, "offset": undo_off, "length": undo_len},
                "target_attribute": target_attribute,
                "lcn_count": lcns_to_follow,
                "record_offset": record_offset,
                "attribute_offset": attribute_offset,
                "target_vcn": target_vcn,
                "page_offset": offset,
                "page_cursor": cursor,
            }
            chunks.append(chunk)
            # Advance past the header AND its padded data. Advancing by the header alone decodes
            # the record's own payload as the next header.
            advance = LOG_RECORD_SIZE + ((data_length + 7) & ~7)
            cursor += advance if advance > 0 else LOG_RECORD_SIZE

        following = log.find(RECORD_PAGE_MAGIC, offset + 4)
        if following == -1 or following <= offset:
            break
        offset = following

    transactions: dict[int, dict[str, Any]] = {}
    for chunk in chunks:
        identifier = chunk["transaction_id"]
        group = transactions.setdefault(identifier, {
            "transaction_id": identifier,
            "record_count": 0,
            "lsns": [],
            "record_types": [],
            "redo_operations": [],
            "undo_operations": [],
            "target_attributes": [],
            "client_data_bytes": 0,
        })
        group["record_count"] += 1
        group["lsns"].append(chunk["this_lsn"])
        if chunk["record_type"] not in group["record_types"]:
            group["record_types"].append(chunk["record_type"])
        if chunk["redo"]["operation"] not in group["redo_operations"]:
            group["redo_operations"].append(chunk["redo"]["operation"])
        if chunk["undo"]["operation"] not in group["undo_operations"]:
            group["undo_operations"].append(chunk["undo"]["operation"])
        if chunk["target_attribute"] not in group["target_attributes"]:
            group["target_attributes"].append(chunk["target_attribute"])
        group["client_data_bytes"] += chunk["client_data_length"]

    ordered = []
    for group in transactions.values():
        group["lsns"].sort()
        group["first_lsn"] = group["lsns"][0]
        group["last_lsn"] = group["lsns"][-1]
        # A transaction whose id is 0 is what NTFS uses for records that belong to no transaction
        # (client restart records and similar). Calling each of those its own "transaction" would
        # inflate the count with things that are not transactions.
        group["is_transaction"] = group["transaction_id"] != 0 and group["record_count"] > 0
        ordered.append(group)
    ordered.sort(key=lambda entry: (-entry["record_count"], entry["transaction_id"]))

    return {
        "record_count": len(chunks),
        "records": chunks,
        "page_count": len(pages),
        "pages": pages[:50],
        "transaction_count": sum(1 for entry in ordered if entry["is_transaction"]),
        "transactions": ordered[:200],
        "orphan_record_count": sum(1 for entry in ordered
                                   if not entry["is_transaction"]),
    }


def inspect(path: str | Path, **kwargs: Any) -> dict[str, Any]:
    return inspect_ntfs_journal(path, **kwargs)
