"""PE/CLI (.NET) metadata reader — pure static parsing, no execution.

WHY this exists: a .NET assembly is a PE file whose real code lives in CIL, not
in machine instructions. Every native RE surface on this engine looks at the
machine-code view and therefore describes a .NET binary's *stub* while saying
nothing about the types and methods that are the entire program. REA exposes three
tools for this (`inspect_managed_artifact`, `inspect_managed_members`,
`inspect_managed_native_boundaries`); this module covers all three from the CLI
side.

Nothing here executes or JITs the assembly. The COM descriptor directory
(IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR, index 14) is read from the PE headers, the
CLI header is parsed from it, and the ECMA-335 metadata root is walked by hand.

The parts that are easy to get subtly wrong, and are handled explicitly:

  * Table row sizes depend on the *heap index sizes* declared in the metadata
    root's #~ stream header, which change when a module has many strings. A fixed
    row layout parses small assemblies correctly and large ones into garbage.
  * Coded indexes (TypeDefOrRef, MemberRefParent, HasConstant, ...) are a tag in
    the low bits plus a table id; the tag width varies per column.
  * A table can be absent, present-but-empty, or sorted; the row cursor only
    advances past tables that exist.
  * An assembly with no #~ stream (rare, but seen in obfuscated or native-image
    output) must be reported as unreadable rather than as empty.

Reference: ECMA-335 II.22-24, and the layout used by System.Reflection.Metadata.
"""
from __future__ import annotations

import struct
from pathlib import Path
from typing import Any

from ..route import guard
from ..route.guard import Denied

MAX_BYTES = 512 * 1024 * 1024
MAX_ROWS = 200_000
MAX_NAME = 1024

# ECMA-335 II.22 table ids.
TABLE_NAMES = {
    0x00: "Module", 0x01: "TypeRef", 0x02: "TypeDef", 0x03: "FieldPtr",
    0x04: "Field", 0x05: "MethodPtr", 0x06: "MethodDef", 0x07: "ParamPtr",
    0x08: "Param", 0x09: "InterfaceImpl", 0x0A: "MemberRef", 0x0B: "Constant",
    0x0C: "CustomAttribute", 0x0D: "FieldMarshal", 0x0E: "DeclSecurity",
    0x0F: "ClassLayout", 0x10: "FieldLayout", 0x11: "StandAloneSig",
    0x12: "EventMap", 0x13: "EventPtr", 0x14: "Event", 0x15: "PropertyMap",
    0x16: "PropertyPtr", 0x17: "Property", 0x18: "MethodSemantics",
    0x19: "MethodImpl", 0x1A: "ModuleRef", 0x1B: "TypeSpec", 0x1C: "ImplMap",
    0x1D: "FieldRVA", 0x1E: "ENCLog", 0x1F: "ENCMap", 0x20: "Assembly",
    0x21: "AssemblyProcessor", 0x22: "AssemblyOS", 0x23: "AssemblyRef",
    0x24: "AssemblyRefProcessor", 0x25: "AssemblyRefOS", 0x26: "File",
    0x27: "ExportedType", 0x28: "ManifestResource", 0x29: "NestedClass",
    0x2A: "GenericParam", 0x2B: "MethodSpec", 0x2C: "GenericParamConstraint",
}
TABLE_IDS = {name: tid for tid, name in TABLE_NAMES.items()}

# Column layout per table: a tuple of descriptors. A descriptor is either
#   ('u8'|'u16'|'u32'|'str'|'guid'|'blob', None)          fixed width / heap index
#   ('table', 'Name')  or ('table', ('A','B',...))       simple or coded index
# Coded index name -> (tables in tag order, bits of tag)
CODED = {
    "TypeDefOrRef": (("TypeDef", "TypeRef", "TypeSpec"), 2),
    "HasConstant": (("Field", "Param", "Property"), 2),
    "HasCustomAttribute": ((("MethodDef", "Field", "TypeRef", "TypeDef", "Param",
                             "InterfaceImpl", "MemberRef", "Module", "DeclSecurity",
                             "Property", "Event", "StandAloneSig", "ModuleRef",
                             "TypeSpec", "Assembly", "AssemblyRef", "File",
                             "ExportedType", "ManifestResource", "GenericParam",
                             "GenericParamConstraint", "MethodSpec")), 5),
    "HasFieldMarshal": (("Field", "Param"), 1),
    "HasDeclSecurity": (("TypeDef", "MethodDef", "Assembly"), 2),
    "MemberRefParent": (("TypeDef", "TypeRef", "ModuleRef", "MethodDef", "TypeSpec"), 3),
    "HasSemantics": (("Event", "Property"), 1),
    "MethodDefOrRef": (("MethodDef", "MemberRef"), 1),
    "MemberForwarded": (("Field", "MethodDef"), 1),
    "Implementation": (("File", "AssemblyRef", "ExportedType"), 2),
    "CustomAttributeType": ((None, None, "MethodDef", "MemberRef", None), 3),
    "ResolutionScope": (("Module", "ModuleRef", "AssemblyRef", "TypeRef"), 2),
    "TypeOrMethodDef": (("TypeDef", "MethodDef"), 1),
}

# Every column carries its own name. An earlier version used (kind, None) for the
# fixed-width columns, which made them all collide on the dict key `None`: each
# one overwrote the previous, so a Module row came back as {None: 0} and every
# name in the assembly read as absent. Names are not decoration here.
SCHEMA: dict[str, tuple] = {
    "Module": (("generation", "u16"), ("name", "str"), ("mvid", "guid"),
               ("enc_id", "guid"), ("enc_base_id", "guid")),
    "TypeRef": (("resolution_scope", "ResolutionScope"), ("name", "str"),
                ("namespace", "str")),
    "TypeDef": (("flags", "u32"), ("name", "str"), ("namespace", "str"),
                ("extends", "TypeDefOrRef"), ("Field", "table:Field"),
                ("MethodDef", "table:MethodDef")),
    "Field": (("flags", "u16"), ("name", "str"), ("signature", "blob")),
    "MethodDef": (("rva", "u32"), ("impl_flags", "u16"), ("flags", "u16"),
                  ("name", "str"), ("signature", "blob"), ("Param", "table:Param")),
    "Param": (("flags", "u16"), ("sequence", "u16"), ("name", "str")),
    "InterfaceImpl": (("class", "table:TypeDef"), ("interface", "TypeDefOrRef")),
    "MemberRef": (("class", "MemberRefParent"), ("name", "str"), ("signature", "blob")),
    "Constant": (("type", "u16"), ("parent", "HasConstant"), ("value", "blob")),
    "CustomAttribute": (("parent", "HasCustomAttribute"), ("type", "CustomAttributeType"),
                        ("value", "blob")),
    "FieldMarshal": (("parent", "HasFieldMarshal"), ("native_type", "blob")),
    "DeclSecurity": (("action", "u16"), ("parent", "HasDeclSecurity"),
                     ("permission_set", "blob")),
    "ClassLayout": (("packing_size", "u16"), ("class_size", "u32"),
                    ("parent", "table:TypeDef")),
    "FieldLayout": (("offset", "u32"), ("field", "table:Field")),
    "StandAloneSig": (("signature", "blob"),),
    "EventMap": (("parent", "table:TypeDef"), ("Event", "table:Event")),
    "Event": (("event_flags", "u16"), ("name", "str"), ("event_type", "TypeDefOrRef")),
    "PropertyMap": (("parent", "table:TypeDef"), ("Property", "table:Property")),
    "Property": (("flags", "u16"), ("name", "str"), ("type", "blob")),
    "MethodSemantics": (("semantics", "u16"), ("method", "table:MethodDef"),
                        ("association", "HasSemantics")),
    "MethodImpl": (("class", "table:TypeDef"), ("method_body", "MethodDefOrRef"),
                   ("method_declaration", "MethodDefOrRef")),
    "ModuleRef": (("name", "str"),),
    "TypeSpec": (("signature", "blob"),),
    "ImplMap": (("mapping_flags", "u16"), ("MemberForwarded", "MemberForwarded"),
                ("import_name", "str"), ("ModuleRef", "table:ModuleRef")),
    "FieldRVA": (("rva", "u32"), ("field", "table:Field")),
    "Assembly": (("hash_algorithm", "u32"), ("major_version", "u16"),
                 ("minor_version", "u16"), ("build_number", "u16"),
                 ("revision_number", "u16"), ("flags", "u32"),
                 ("public_key", "blob"), ("name", "str"), ("culture", "str")),
    "AssemblyProcessor": (("processor", "u32"),),
    "AssemblyOS": (("os_platform", "u32"), ("os_major", "u32"), ("os_minor", "u32")),
    "AssemblyRef": (("major_version", "u16"), ("minor_version", "u16"),
                    ("build_number", "u16"), ("revision_number", "u16"),
                    ("flags", "u32"), ("public_key_or_token", "blob"),
                    ("name", "str"), ("culture", "str"), ("hash_value", "blob")),
    "AssemblyRefProcessor": (("processor", "u32"), ("assembly_ref", "table:AssemblyRef")),
    "AssemblyRefOS": (("os_platform", "u32"), ("os_major", "u32"), ("os_minor", "u32"),
                      ("assembly_ref", "table:AssemblyRef")),
    "File": (("flags", "u32"), ("name", "str"), ("hash_value", "blob")),
    "ExportedType": (("flags", "u32"), ("type_def_id", "u32"), ("name", "str"),
                     ("namespace", "str"), ("implementation", "Implementation")),
    "ManifestResource": (("offset", "u32"), ("flags", "u32"), ("name", "str"),
                         ("implementation", "Implementation")),
    "NestedClass": (("nested_class", "table:TypeDef"),
                    ("enclosing_class", "table:TypeDef")),
    "GenericParam": (("number", "u16"), ("flags", "u16"),
                     ("owner", "TypeOrMethodDef"), ("name", "str")),
    "MethodSpec": (("method", "MethodDefOrRef"), ("instantiation", "blob")),
    "GenericParamConstraint": (("owner", "table:GenericParam"),
                               ("constraint", "TypeDefOrRef")),
    # The *Ptr tables are indirection layers that appear only in uncompressed (#-)
    # metadata, i.e. in an assembly being edited. They are in TABLE_NAMES, so a
    # file that declares one must be sizeable or the row cursor loses track of
    # every following table. Their absence here let a mutated file escape as a
    # KeyError instead of a ManagedError, which is why they are listed.
    "FieldPtr": (("field", "table:Field"),),
    "MethodPtr": (("method", "table:MethodDef"),),
    "ParamPtr": (("param", "table:Param"),),
    "EventPtr": (("event", "table:Event"),),
    "PropertyPtr": (("property", "table:Property"),),
    "ENCLog": (("token", "u32"), ("func_code", "u32")),
    "ENCMap": (("token", "u32"),),
}

# MethodDef flags (ECMA-335 II.23.1.10) — the ones that change an interpretation.
METHOD_FLAGS = {
    0x0001: "CompilerControlled", 0x0002: "Private", 0x0003: "FamANDAssem",
    0x0004: "Assembly", 0x0005: "Family", 0x0006: "FamORAssem", 0x0007: "Public",
    0x0008: "Static", 0x0010: "Final", 0x0020: "Virtual", 0x0040: "HideBySig",
    0x0080: "ReuseSlot", 0x0100: "NewSlot", 0x0200: "Abstract", 0x0400: "SpecialName",
    0x0800: "RTSpecialName", 0x1000: "UnmanagedExport", 0x2000: "HasSecurity",
    0x4000: "RequireSecObject",
}
# MethodImplAttributes, where P/Invoke and runtime-provided bodies are declared.
IMPL_FLAGS = {
    0x0000: "IL", 0x0001: "Native", 0x0002: "OPTIL", 0x0003: "Runtime",
    0x0004: "Unmanaged", 0x0008: "ManagedMask_Managed", 0x0010: "NoInlining",
    0x0020: "AggressiveInlining", 0x0040: "Synchronized", 0x0080: "NoOptimization",
    0x0100: "InternalCall", 0x0400: "ForwardRef", 0x1000: "PreserveSig",
    0x2000: "PreserveSigMask",
}


class ManagedError(ValueError):
    """Raised when a file cannot be read as a PE/CLI assembly."""


ACCESS_NAMES = {0: "CompilerControlled", 1: "Private", 2: "FamANDAssem",
                3: "Assembly", 4: "Family", 5: "FamORAssem", 6: "Public",
                7: "NestedPublic"}


def _method_access(flags: int) -> str:
    """MemberAccessMask (0x0007) is an exclusive range, not a bitfield.

    An earlier version ANDed the whole flags word against the mask after clearing
    bits, so 0x0006 (Public) decoded as FamORAssem. An exclusive range must be
    masked first and never treated as bits to clear.
    """
    return ACCESS_NAMES.get(flags & 0x0007, "unknown")


def _method_flags(flags: int) -> list[str]:
    """Decode MethodAttributes (ECMA-335 II.23.1.10).

    The bit positions are taken from the spec, not from memory. Getting them wrong
    is invisible: a method whose Virtual bit is misread as HideBySig still produces
    a plausible-looking list of names.
    """
    names = [_method_access(flags)]
    for bit, label in ((0x0010, "Static"), (0x0020, "Final"), (0x0040, "Virtual"),
                       (0x0080, "HideBySig"), (0x0100, "NewSlot"),
                       (0x0400, "Abstract"), (0x0800, "SpecialName"),
                       (0x1000, "RTSpecialName"), (0x2000, "UnmanagedExport"),
                       (0x4000, "HasSecurity"), (0x8000, "RequireSecObject")):
        if flags & bit:
            names.append(label)
    return names


def _impl_flags(impl: int) -> list[str]:
    """Decode MethodImplAttributes. CodeTypeMask (0x0003) is exclusive."""
    code_type = {0: "IL", 1: "Native", 2: "OPTIL", 3: "Runtime"}.get(impl & 0x0003,
                                                                    "unknown")
    names = [code_type]
    for bit, label in ((0x0004, "Unmanaged"), (0x0008, "Managed"),
                       (0x0010, "NoInlining"), (0x0020, "AggressiveInlining"),
                       (0x0040, "Synchronized"), (0x0080, "NoOptimization"),
                       (0x0100, "InternalCall"), (0x0200, "PreserveSig"),
                       (0x0400, "ForwardRef")):
        if impl & bit:
            names.append(label)
    return names


class ManagedAssembly:
    """A PE/CLI assembly read without executing it."""

    def __init__(self, target: str | Path | bytes):
        if isinstance(target, (str, Path)):
            canon = guard.read_guard(target)
            if not canon.is_file():
                raise ManagedError(f"file not found or not regular: {target}")
            size = canon.stat().st_size
            if size > MAX_BYTES:
                raise ManagedError(f"file too large: {size} bytes")
            try:
                self.data = canon.read_bytes()
            except OSError as exc:
                raise ManagedError(f"cannot read {target}: {exc}") from exc
            self.path = str(canon)
        elif isinstance(target, (bytes, bytearray)):
            if len(target) > MAX_BYTES:
                raise ManagedError(f"data too large: {len(target)} bytes")
            self.data = bytes(target)
            self.path = "<memory>"
        else:
            raise ManagedError(f"unsupported target type: {type(target)}")

        self.cli: dict[str, Any] = {}
        self.tables: dict[str, list[dict[str, Any]]] = {}
        self._heap_sizes = (2, 2, 2)
        self._row_counts: dict[str, int] = {}
        self._parse()

    # ------------------------------------------------------------------ helpers
    def _u(self, fmt: str, offset: int) -> Any:
        size = struct.calcsize(fmt)
        if offset < 0 or offset + size > len(self.data):
            raise ManagedError(f"truncated CLI metadata at 0x{offset:x}")
        return struct.unpack_from(fmt, self.data, offset)[0]

    def _at(self, offset: int, size: int) -> bytes:
        if offset < 0 or offset + size > len(self.data):
            raise ManagedError(f"CLI metadata range 0x{offset:x}+{size} is out of bounds")
        return self.data[offset:offset + size]

    # -------------------------------------------------------------------- parse
    def _parse(self) -> None:
        if len(self.data) < 0x40 or self.data[:2] != b"MZ":
            raise ManagedError("not a PE file (no MZ signature)")
        e_lfanew = self._u("<I", 0x3C)
        if self._at(e_lfanew, 4) != b"PE\0\0":
            raise ManagedError("not a PE file (no PE signature)")
        coff = e_lfanew + 4
        num_sections = self._u("<H", coff + 2)
        opt_size = self._u("<H", coff + 16)
        opt = coff + 20
        magic = self._u("<H", opt)
        if magic == 0x010B:
            dirs_off = opt + 96
            self.cli["pe_magic"] = "PE32"
        elif magic == 0x020B:
            dirs_off = opt + 112
            self.cli["pe_magic"] = "PE32+"
        else:
            raise ManagedError(f"unrecognized optional header magic 0x{magic:04x}")

        self._sections = []
        section_table = opt + opt_size
        for i in range(num_sections):
            hdr = section_table + i * 40
            if hdr + 40 > len(self.data):
                raise ManagedError("truncated section table")
            name = self.data[hdr:hdr + 8].rstrip(b"\0").decode("ascii", "replace")
            vsize, vaddr, raw_size, raw_ptr = struct.unpack_from("<IIII", self.data, hdr + 8)
            self._sections.append({"name": name, "vaddr": vaddr, "vsize": vsize,
                                   "raw_size": raw_size, "raw_ptr": raw_ptr})

        num_dirs = self._u("<I", opt + (108 if magic == 0x020B else 92))
        if num_dirs <= 14:
            raise ManagedError(
                "PE has no COM descriptor directory — this is a native image, not a "
                ".NET assembly")
        com_rva, com_size = struct.unpack_from("<II", self.data, dirs_off + 14 * 8)
        if not com_rva or not com_size:
            raise ManagedError(
                "PE has no COM descriptor directory — this is a native image, not a "
                ".NET assembly")

        cli_off = self._rva_to_offset(com_rva)
        if cli_off is None:
            raise ManagedError("COM descriptor RVA is not mapped")

        (cb, major, minor) = self._u("<I", cli_off), self._u("<H", cli_off + 4), \
            self._u("<H", cli_off + 6)
        (md_rva, md_size) = struct.unpack_from("<II", self.data, cli_off + 8)
        flags = self._u("<I", cli_off + 16)
        entry_token = self._u("<I", cli_off + 20)
        self.cli.update({
            "header_size": cb,
            "runtime_version": f"{major}.{minor}",
            "metadata_rva": md_rva,
            "metadata_size": md_size,
            "flags": flags,
            "flags_decoded": [
                label for bit, label in (
                    (0x00000001, "ILOnly"), (0x00000002, "32BitRequired"),
                    (0x00000004, "IL_Library"), (0x00000008, "StrongNameSigned"),
                    (0x00000010, "NativeEntryPoint"), (0x00010000, "Prefer32Bit"),
                    (0x00020000, "TrackDebugData"),
                ) if flags & bit
            ],
            "requires_32bit": bool(flags & 0x2),
            "il_only": bool(flags & 0x1),
            "entry_point_token": entry_token,
        })
        self.cli["entry_point"] = self._describe_token(entry_token)

        if not md_rva or not md_size:
            raise ManagedError("CLI header declares no metadata")
        md_off = self._rva_to_offset(md_rva)
        if md_off is None:
            raise ManagedError("metadata RVA is not mapped")
        self._parse_metadata_root(md_off)

    def _rva_to_offset(self, rva: int) -> int | None:
        for section in self._sections:
            start = section["vaddr"]
            span = max(section["vsize"], section["raw_size"])
            if start <= rva < start + span:
                return section["raw_ptr"] + (rva - start)
        # A header-directory RVA (below the first section) maps 1:1.
        if self._sections and rva < self._sections[0]["vaddr"]:
            return rva
        return None

    def _parse_metadata_root(self, offset: int) -> None:
        signature = self._u("<I", offset)
        if signature != 0x424A5342:
            raise ManagedError(
                f"bad metadata signature 0x{signature:08x} (expected 0x424A5342 'BSJB')")
        major, minor = self._u("<H", offset + 4), self._u("<H", offset + 6)
        _reserved, version_len = struct.unpack_from("<II", self.data, offset + 8)
        version_len = min(version_len, 256)
        version = self._at(offset + 16, version_len).rstrip(b"\0").decode("utf-8", "replace")
        self.cli.update({"metadata_version": version,
                         "metadata_runtime": f"{major}.{minor}"})

        cursor = offset + 16 + version_len
        cursor += (-cursor) % 4  # streams are 4-byte aligned
        flags, streams = self._u("<H", cursor), self._u("<H", cursor + 2)
        self.cli["streams"] = []
        cursor += 4
        stream_offsets: dict[str, tuple[int, int]] = {}
        for _ in range(min(streams, 32)):
            s_off, s_size = struct.unpack_from("<II", self.data, cursor)
            cursor += 8
            end = self.data.find(b"\0", cursor, min(len(self.data), cursor + 64))
            if end < 0:
                raise ManagedError("unterminated stream name")
            name = self._at(cursor, end - cursor).decode("ascii", "replace")
            cursor = end + 1
            cursor += (-cursor) % 4
            stream_offsets[name] = (offset + s_off, s_size)
            self.cli["streams"].append({"name": name, "offset": offset + s_off,
                                        "size": s_size})

        if "#Strings" in stream_offsets:
            self._strings_at, self._strings_len = stream_offsets["#Strings"]
        else:
            self._strings_at, self._strings_len = 0, 0
        if "#Blob" in stream_offsets:
            self._blob_at, self._blob_len = stream_offsets["#Blob"]
        else:
            self._blob_at, self._blob_len = 0, 0
        if "#US" in stream_offsets:
            self._us_at, self._us_len = stream_offsets["#US"]
        else:
            self._us_at, self._us_len = 0, 0

        table_stream = "#~" if "#~" in stream_offsets else "#-"
        if table_stream not in stream_offsets:
            raise ManagedError(
                "no #~ table stream — metadata tables are unavailable "
                f"(streams: {', '.join(stream_offsets) or 'none'})")
        self._parse_table_stream(*stream_offsets[table_stream])

    def _parse_table_stream(self, offset: int, size: int) -> None:
        _reserved = self._u("<I", offset)
        major, _minor, heap_sizes = self._u("<B", offset + 4), self._u("<B", offset + 5), \
            self._u("<B", offset + 6)
        _rid, valid, sorted_mask = struct.unpack_from("<BQQ", self.data, offset + 7)
        self.cli["table_stream"] = {"major": major, "heap_sizes": heap_sizes,
                                    "sorted": sorted_mask}
        if major != 2:
            raise ManagedError(f"unsupported table stream major version {major}")

        # Heap index widths are declared here and nowhere else. Getting them wrong
        # parses small assemblies correctly and large ones into noise, which is why
        # they are read rather than assumed.
        self._heap_sizes = (4 if heap_sizes & 0x01 else 2,   # #Strings
                            4 if heap_sizes & 0x02 else 2,   # #GUID
                            4 if heap_sizes & 0x04 else 2)   # #Blob

        cursor = offset + 24
        self._row_counts = {}
        for tid in range(64):
            if valid & (1 << tid):
                count = self._u("<I", cursor)
                cursor += 4
                name = TABLE_NAMES.get(tid)
                if name is None:
                    # An unknown table cannot be sized, so every table after it is
                    # unreachable. Say so instead of silently returning garbage.
                    raise ManagedError(
                        f"metadata declares unimplemented table 0x{tid:02x}; "
                        "cannot locate later tables")
                if count > MAX_ROWS:
                    raise ManagedError(f"table {name} declares {count} rows (cap {MAX_ROWS})")
                self._row_counts[name] = count
        self.cli["row_counts"] = dict(self._row_counts)

        for name in self._row_counts:
            if name not in SCHEMA:
                raise ManagedError(
                    f"metadata declares table {name} with no known row layout; "
                    "cannot locate later tables")
            row_size = self._row_size(name)
            rows: list[dict[str, Any]] = []
            for _ in range(self._row_counts[name]):
                row: dict[str, Any] = {}
                for column, kind in SCHEMA[name]:
                    row[column] = self._read_column(kind, cursor)
                    cursor += self._column_width(kind)
                rows.append(row)
            self.tables[name] = rows

    def _coded_width(self, tables: tuple, bits: int) -> int:
        largest = 0
        for entry in tables:
            if entry:
                largest = max(largest, self._row_counts.get(entry, 0))
        return 2 if largest < (1 << (16 - bits)) else 4

    def _column_width(self, kind: str) -> int:
        if kind == "u8":
            return 1
        if kind == "u16":
            return 2
        if kind == "u32":
            return 4
        if kind == "str":
            return self._heap_sizes[0]
        if kind == "guid":
            return self._heap_sizes[1]
        if kind == "blob":
            return self._heap_sizes[2]
        if kind.startswith("table:"):
            return 2 if self._row_counts.get(kind[6:], 0) < 0x10000 else 4
        if kind in CODED:
            tables, bits = CODED[kind]
            return self._coded_width(tables, bits)
        raise ManagedError(f"unknown column kind {kind}")

    def _read_column(self, kind: str, cursor: int) -> Any:
        width = self._column_width(kind)
        if kind == "u8":
            return self._u("<B", cursor)
        if kind == "u16":
            return self._u("<H", cursor)
        if kind == "u32":
            return self._u("<I", cursor)
        if kind == "str":
            return self._string(self._u("<H" if width == 2 else "<I", cursor))
        if kind == "guid":
            return self._u("<H" if width == 2 else "<I", cursor)
        if kind == "blob":
            return self._blob(self._u("<H" if width == 2 else "<I", cursor))
        if kind.startswith("table:"):
            return self._u("<H" if width == 2 else "<I", cursor)
        tables, bits = CODED[kind]
        value = self._u("<H" if width == 2 else "<I", cursor)
        tag = value & ((1 << bits) - 1)
        rid = value >> bits
        target = tables[tag] if tag < len(tables) else None
        return {"table": target, "rid": rid, "raw": value}

    def _row_size(self, name: str) -> int:
        return sum(self._column_width(kind) for _column, kind in SCHEMA[name])

    # -------------------------------------------------------------------- heaps
    def _string(self, index: int) -> str:
        if not index or not self._strings_at:
            return ""
        start = self._strings_at + index
        if start >= len(self.data):
            return ""
        end = self.data.find(b"\0", start, min(len(self.data), start + MAX_NAME))
        if end < 0:
            end = min(len(self.data), start + MAX_NAME)
        return self.data[start:end].decode("utf-8", "replace")

    def _blob(self, index: int) -> bytes:
        if not index or not self._blob_at:
            return b""
        start = self._blob_at + index
        if start >= len(self.data):
            return b""
        length, cursor = self._compressed_uint(start)
        return self.data[cursor:cursor + min(length, 1 << 20)]

    def _compressed_uint(self, offset: int) -> tuple[int, int]:
        """ECMA-335 II.23.2 compressed integer."""
        if offset >= len(self.data):
            return 0, offset
        first = self.data[offset]
        if first & 0x80 == 0:
            return first, offset + 1
        if first & 0xC0 == 0x80:
            second = self.data[offset + 1] if offset + 1 < len(self.data) else 0
            return ((first & 0x3F) << 8) | second, offset + 2
        word = struct.unpack_from("<I", self.data, offset)[0]
        return ((first & 0x1F) << 24) | (word >> 8), offset + 4

    # ------------------------------------------------------------------ reports
    def _describe_token(self, token: int) -> dict[str, Any] | None:
        """Turn a metadata token (0xTTBBBBBB) into a readable name."""
        if not token:
            return None
        table_id = token >> 24
        rid = token & 0xFFFFFF
        name = TABLE_NAMES.get(table_id)
        if name is None:
            return {"token": f"0x{token:08x}", "table": None, "rid": rid}
        rows = self.tables.get(name) or []
        entry: dict[str, Any] = {"token": f"0x{token:08x}", "table": name, "rid": rid}
        if 0 < rid <= len(rows):
            row = rows[rid - 1]
            if name == "MethodDef":
                entry["name"] = row.get("name")
            elif name == "Field":
                entry["name"] = row.get("name")
        return entry

    def artifact(self) -> dict[str, Any]:
        """Identity and inventory: the `inspect_managed_artifact` question."""
        assembly = self.tables.get("Assembly") or []
        module = self.tables.get("Module") or []
        result: dict[str, Any] = {
            "ok": True,
            "path": self.path,
            "kind": "managed",
            "pe_magic": self.cli.get("pe_magic"),
            "runtime_version": self.cli.get("runtime_version"),
            "metadata_version": self.cli.get("metadata_version"),
            "flags": self.cli.get("flags"),
            "flags_decoded": self.cli.get("flags_decoded"),
            "il_only": self.cli.get("il_only"),
            "requires_32bit": self.cli.get("requires_32bit"),
            "entry_point": self.cli.get("entry_point"),
            "streams": self.cli.get("streams"),
            "table_counts": dict(self._row_counts),
            "module": module[0].get("name") if module else None,
        }
        if assembly:
            row = assembly[0]
            result["assembly"] = {
                "name": row.get("name"),
                "culture": row.get("culture"),
                "version": "{}.{}.{}.{}".format(
                    row.get("major_version", 0), row.get("minor_version", 0),
                    row.get("build_number", 0), row.get("revision_number", 0)),
                "flags": row.get("flags"),
                "public_key": len(row.get("public_key") or b"") * 8,
                "hash_algorithm": row.get("hash_algorithm"),
            }
        else:
            result["assembly"] = None
            result["warning"] = "no Assembly table — this is a module, not an assembly"
        refs = []
        for row in self.tables.get("AssemblyRef") or []:
            refs.append({
                "name": row.get("name"),
                "version": "{}.{}.{}.{}".format(
                    row.get("major_version", 0), row.get("minor_version", 0),
                    row.get("build_number", 0), row.get("revision_number", 0)),
            })
        result["references"] = refs
        result["module_refs"] = [r.get("name") for r in self.tables.get("ModuleRef") or []]
        return result

    def members(self, *, limit: int = 500) -> dict[str, Any]:
        """Types and methods: the `inspect_managed_members` question."""
        type_defs = self.tables.get("TypeDef") or []
        method_defs = self.tables.get("MethodDef") or []
        field_defs = self.tables.get("Field") or []
        types: list[dict[str, Any]] = []
        for index, row in enumerate(type_defs[:limit]):
            method_start = row.get("MethodDef") or 0
            field_start = row.get("Field") or 0
            # A TypeDef owns the run of methods/fields up to the next TypeDef's start.
            next_method = (type_defs[index + 1].get("MethodDef") or len(method_defs) + 1) \
                if index + 1 < len(type_defs) else len(method_defs) + 1
            next_field = (type_defs[index + 1].get("Field") or len(field_defs) + 1) \
                if index + 1 < len(type_defs) else len(field_defs) + 1
            methods = []
            for rid in range(method_start, min(next_method, len(method_defs) + 1)):
                if rid <= 0:
                    continue
                m = method_defs[rid - 1]
                flags = m.get("flags", 0)
                impl = m.get("impl_flags", 0)
                methods.append({
                    "name": m.get("name"),
                    "rid": rid,
                    "access": _method_access(flags),
                    "modifiers": _method_flags(flags),
                    "impl": _impl_flags(impl),
                    "is_static": bool(flags & 0x0010),
                    "is_virtual": bool(flags & 0x0040),
                    "is_abstract": bool(flags & 0x0400),
                    "is_pinvoke": bool(impl & 0x2000) or bool(impl & 0x0004),
                    "rva": m.get("rva"),
                    "signature_size": len(m.get("signature") or b""),
                })
            fields = []
            for rid in range(field_start, min(next_field, len(field_defs) + 1)):
                if rid <= 0:
                    continue
                f = field_defs[rid - 1]
                fields.append({"name": f.get("name"), "rid": rid,
                               "flags": f.get("flags")})
            types.append({
                "name": row.get("name"),
                "namespace": row.get("namespace"),
                "full_name": ".".join(x for x in (row.get("namespace"), row.get("name")) if x),
                "flags": row.get("flags"),
                "methods": methods,
                "fields": fields,
            })
        return {
            "ok": True,
            "path": self.path,
            "types": types,
            "type_count": len(type_defs),
            "method_count": len(method_defs),
            "field_count": len(field_defs),
            "truncated": len(type_defs) > limit,
        }

    def boundaries(self) -> dict[str, Any]:
        """P/Invoke and native entry points: the `inspect_managed_native_boundaries` question.

        A managed assembly that calls native code is the interesting case for RE:
        the imported names say which Win32 APIs the CIL reaches, which is exactly
        the seam between the readable half and the native half of an application.
        """
        module_refs = self.tables.get("ModuleRef") or []
        impl_map = self.tables.get("ImplMap") or []
        method_defs = self.tables.get("MethodDef") or []
        pinvokes = []
        for row in impl_map:
            scope = row.get("ModuleRef") or 0
            forwarded = row.get("MemberForwarded") or {}
            rid = forwarded.get("rid") or 0
            target = forwarded.get("table")
            entry: dict[str, Any] = {
                "import_name": row.get("import_name"),
                "dll": module_refs[scope - 1].get("name")
                if 0 < scope <= len(module_refs) else None,
                "mapping_flags": row.get("mapping_flags"),
                "forwarded_table": target,
            }
            if target == "MethodDef" and 0 < rid <= len(method_defs):
                entry["managed_method"] = method_defs[rid - 1].get("name")
                entry["managed_rva"] = method_defs[rid - 1].get("rva")
            pinvokes.append(entry)

        native_methods = []
        for rid, m in enumerate(method_defs, start=1):
            impl = m.get("impl_flags", 0)
            # Native (0x1) or Runtime (0x3) means the body is not IL.
            if (impl & 0x0003) in (0x0001, 0x0003) or impl & 0x1000:
                native_methods.append({
                    "name": m.get("name"), "rid": rid,
                    "impl": _impl_flags(impl),
                    "rva": m.get("rva"),
                })
        entry_point = self.cli.get("entry_point") or {}
        return {
            "ok": True,
            "path": self.path,
            "pinvokes": pinvokes,
            "pinvoke_count": len(pinvokes),
            "native_methods": native_methods,
            "dlls": sorted({p["dll"] for p in pinvokes if p["dll"]}),
            "entry_point": entry_point,
            "has_native_entry": bool(self.cli.get("flags", 0) & 0x10),
        }


def inspect_artifact(path: str | Path) -> dict[str, Any]:
    try:
        return ManagedAssembly(path).artifact()
    except (ManagedError, Denied) as exc:
        return {"ok": False, "path": str(path), "error": str(exc)}


def inspect_members(path: str | Path, *, limit: int = 500) -> dict[str, Any]:
    try:
        return ManagedAssembly(path).members(limit=limit)
    except (ManagedError, Denied) as exc:
        return {"ok": False, "path": str(path), "error": str(exc)}


def inspect_boundaries(path: str | Path) -> dict[str, Any]:
    try:
        return ManagedAssembly(path).boundaries()
    except (ManagedError, Denied) as exc:
        return {"ok": False, "path": str(path), "error": str(exc)}
