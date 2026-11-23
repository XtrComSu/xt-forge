"""Objective-C class, protocol and method metadata in Mach-O images.

WHY: `re info` parses Mach-O headers and load commands, which says nothing about the
Objective-C objects inside. For iOS and macOS analysis the interesting unit is the
class — its name, superclass, methods and the protocols it conforms to — because that
is what an analyst greps for when looking for a feature, a leaked API, or code that
handles a URL scheme.

The metadata is a set of pointer graphs, not a record format:

    __objc_classlist  -> class_t*
      class_t          { isa, superclass, cache, vtable, class_ro_t* data, ... }
      class_ro_t       { flags, instanceStart, instanceSize, ..., name, baseMethods,
                         baseProtocols, ivars, ... }
      method_list_t    { entsize_and_flags, count, method_t[count] }
      method_t         { name SEL, types, imp }
      protocol_list_t  { count, protocol_t*[count] }
      protocol_t       { isa, name, protocols, instanceMethods, ..., }

Every one of those is a file offset in an object file but a *virtual address* in a
linked image, and the two differ by the segment's vmaddr-to-fileoff slide. Reading the
pointers without applying that slide lands somewhere plausible-looking but wrong, which
is why the slide is computed from the segment whose vmaddr contains the pointer rather
than assumed.

Two more traps handled here:

  * `class_ro_t` has two layouts. The classic one starts with `flags`; the newer one is
    `class_rw_t`-style and the flags word is at a different offset. The low bit of the
    `data` pointer says which (the "Swift/ro-pointer" tagging). Guessing wrong puts
    `name` at the flags field and yields a class called "\\x02".
  * An `entsize_and_flags` low bit of 1 on a method_list means the entries are
    *relative* offsets, not pointers — small method lists in a linked cache. Reading
    those as pointers yields wild addresses.

Only 64-bit little-endian Mach-O is handled; 32-bit iOS images exist but are rare and a
half-correct reader that silently returns nothing is worse than one that says so.
"""
from __future__ import annotations

import struct
from pathlib import Path
from typing import Any

from ..route import guard
from ..route.guard import Denied

MH_MAGIC_64 = 0xFEEDFACF
FAT_MAGIC = 0xCAFEBABE
LC_SEGMENT_64 = 0x19
LC_SYMTAB = 0x2

MACHO_ERR = "not a 64-bit little-endian Mach-O image"

# class_ro_t.flags bits.
RO_META = 0x01
RO_ROOT = 0x02

# class_ro_t: flags, instanceStart, instanceSize, reserved, ivarLayout, name,
#             baseMethods, baseProtocols, ivars, weakIvarLayout, baseProperties.
# The offsets from `name` onwards are fixed for both layouts; only the fields before
# `name` differ, and `name` is at 24 for the classic layout.
_RO_NAME_OFFSET = 24

_MAX_NAME = 512
_MAX_METHODS = 2000


class MachOObjCError(Exception):
    """Raised when the image cannot be read as 64-bit Mach-O."""


def _read(path: str | Path, limit: int = 512 * 1024 * 1024) -> bytes:
    canon = guard.read_guard(path)
    if not canon.is_file():
        raise FileNotFoundError(f"not a regular file: {path}")
    size = canon.stat().st_size
    if size > limit:
        raise ValueError(f"file too large: {size} bytes (max {limit})")
    return canon.read_bytes()


class _Image:
    """A single 64-bit Mach-O slice with segment mapping and string reads."""

    def __init__(self, data: bytes, offset: int = 0) -> None:
        self.data = data
        self.base = offset
        magic = struct.unpack_from("<I", data, offset)[0]
        if magic != MH_MAGIC_64:
            raise MachOObjCError(MACHO_ERR)
        self.cputype, self.cpusubtype, self.filetype, ncmds, sizeofcmds, self.flags, \
            _reserved = struct.unpack_from("<iiIIIII", data, offset + 4)
        self.segments: list[dict[str, Any]] = []
        self._sections: dict[str, tuple[int, int]] = {}
        cursor = offset + 32
        for _ in range(ncmds):
            if cursor + 8 > len(data):
                break
            cmd, cmdsize = struct.unpack_from("<II", data, cursor)
            if cmdsize < 8 or cursor + cmdsize > len(data):
                break
            if cmd == LC_SEGMENT_64:
                self._read_segment(cursor)
            cursor += cmdsize

    def _read_segment(self, cursor: int) -> None:
        name = self.data[cursor + 8:cursor + 24].split(b"\x00")[0].decode("latin-1")
        vmaddr, vmsize, fileoff, filesize = struct.unpack_from("<QQQQ", self.data,
                                                               cursor + 24)
        nsects = struct.unpack_from("<I", self.data, cursor + 64)[0]
        self.segments.append({"name": name, "vmaddr": vmaddr, "vmsize": vmsize,
                              "fileoff": fileoff, "filesize": filesize,
                              "nsects": nsects})
        section_cursor = cursor + 72
        for _ in range(nsects):
            if section_cursor + 80 > len(self.data):
                break
            sect_name = self.data[section_cursor:section_cursor + 16].split(b"\x00")[0]
            seg_name = self.data[section_cursor + 16:section_cursor + 32].split(b"\x00")[0]
            addr, size = struct.unpack_from("<QQ", self.data, section_cursor + 32)
            # Section offset is a 32-bit field at +48 in a 64-bit section header.
            sect_offset = struct.unpack_from("<I", self.data, section_cursor + 48)[0]
            key = f"{seg_name.decode('latin-1')},{sect_name.decode('latin-1')}"
            self._sections[key] = (sect_offset, size)
            section_cursor += 80

    def section(self, name: str) -> tuple[int, int] | None:
        for key, value in self._sections.items():
            if key.endswith("," + name):
                return value
        return None

    def file_offset(self, vmaddr: int) -> int | None:
        """Map a virtual address to a file offset using the containing segment.

        In an object file vmaddr equals fileoff, so the slide is zero and this is an
        identity; in a linked dylib it is not, and assuming zero reads unrelated bytes.
        """
        if vmaddr == 0:
            return None
        for segment in self.segments:
            start = segment["vmaddr"]
            if start <= vmaddr < start + segment["vmsize"]:
                delta = vmaddr - start
                if delta >= segment["filesize"]:
                    return None
                offset = segment["fileoff"] + delta
                if offset >= len(self.data) - self.base:
                    return None
                return self.base + offset
        # A zero-vmaddr segment (common for __DATA in object files) is identity-mapped.
        for segment in self.segments:
            if segment["vmaddr"] == 0 and vmaddr < segment["filesize"]:
                return self.base + vmaddr
        return None

    def pointer(self, offset: int) -> int:
        if offset + 8 > len(self.data):
            return 0
        return struct.unpack_from("<Q", self.data, offset)[0]

    def u32(self, offset: int) -> int:
        if offset + 4 > len(self.data):
            return 0
        return struct.unpack_from("<I", self.data, offset)[0]

    def cstring(self, vmaddr: int) -> str:
        offset = self.file_offset(vmaddr)
        if offset is None:
            return ""
        end = self.data.find(b"\x00", offset, offset + _MAX_NAME)
        if end < 0:
            return ""
        return self.data[offset:end].decode("utf-8", "replace")

    def cstring_at_offset(self, offset: int) -> str:
        if offset is None or offset < 0 or offset >= len(self.data):
            return ""
        end = self.data.find(b"\x00", offset, offset + _MAX_NAME)
        if end < 0:
            return ""
        return self.data[offset:end].decode("utf-8", "replace")


def _looks_like_text(blob: bytes) -> bool:
    """Is this a plausible selector or type encoding rather than raw pointer bytes?"""
    if not blob:
        return False
    end = blob.find(b"\x00")
    if end <= 0:
        return False
    body = blob[:end]
    return all(32 <= byte < 127 for byte in body)


def _relative_string(image: _Image, base: int, delta: int) -> str:
    """Resolve a relative method_list string reference.

    Two shapes turn up, and which one appears depends on how the image was linked:

      * the offset points straight at the name string;
      * the offset points at a slot in __objc_selrefs, which holds the real pointer.

    The second is what a linker using chained fixups produces for the `name` field,
    because a rebasable pointer cannot live in a 32-bit relative field. There is no
    flag that distinguishes them, so the bytes are checked: a selector is printable
    ASCII and a pointer slot is not. Trying the direct form first keeps ordinary
    images on the fast path; falling back keeps linked ones correct.
    """
    target = base + delta
    candidate = image.cstring_at_offset(target)
    if candidate and _looks_like_text(image.data[target:target + 64]):
        return candidate
    if target + 4 <= len(image.data):
        slot = struct.unpack_from("<I", image.data, target)[0]
        for resolved in (slot, slot + target):
            text = image.cstring_at_offset(resolved)
            if text and _looks_like_text(image.data[resolved:resolved + 64]):
                return text
    return candidate


def _method_list(image: _Image, vmaddr: int, *, limit: int = _MAX_METHODS) -> list[dict]:
    """Decode a method_list_t and its method_t entries."""
    offset = image.file_offset(vmaddr)
    if offset is None:
        return []
    entsize_and_flags = image.u32(offset)
    count = image.u32(offset + 4)
    if count == 0 or count > 100000:
        return []
    # entsize_and_flags packs two things: the entry size in the low 30 bits and the
    # "relative" marker in bit 31 (not bit 0 — masking with 1 reads the size's low bit
    # and gets the mode wrong on every list whose entsize is odd, which is none, while
    # missing every relative list). Relative method lists store 32-bit offsets from the
    # entry itself to its name/types/imp, because a pointer would need rebasing.
    relative = bool(entsize_and_flags & 0x80000000)
    entsize = entsize_and_flags & 0x3FFFFFFF
    if entsize < 12:
        entsize = 12 if relative else 24
    methods: list[dict[str, Any]] = []
    entry = offset + 8
    for _ in range(min(count, limit)):
        if entry + entsize > len(image.data):
            break
        if relative:
            name_ref, types_ref, imp_ref = struct.unpack_from("<iii", image.data, entry)
            methods.append({
                "name": _relative_string(image, entry, name_ref),
                "types": _relative_string(image, entry + 4, types_ref),
            })
        else:
            name_ptr, types_ptr, imp_ptr = struct.unpack_from("<QQQ", image.data, entry)
            methods.append({"name": image.cstring(name_ptr),
                            "types": image.cstring(types_ptr),
                            "imp": imp_ptr or None})
        entry += entsize
    return methods


def _protocol_list(image: _Image, vmaddr: int) -> list[dict[str, Any]]:
    offset = image.file_offset(vmaddr)
    if offset is None:
        return []
    count = image.pointer(offset)
    if count == 0 or count > 10000:
        return []
    out: list[dict[str, Any]] = []
    for index in range(min(int(count), 200)):
        protocol_ptr = image.pointer(offset + 8 + index * 8)
        record = _protocol(image, protocol_ptr)
        if record:
            out.append(record)
    return out


def _protocol(image: _Image, vmaddr: int) -> dict[str, Any] | None:
    offset = image.file_offset(vmaddr)
    if offset is None:
        return None
    # protocol_t: isa, name, protocols, instanceMethods, classMethods, optionalInstance,
    #             optionalClass, instanceProperties, size, flags, extendedMethodTypes...
    name_ptr = image.pointer(offset + 8)
    name = image.cstring(name_ptr)
    if not name:
        return None
    instance_methods = _method_list(image, image.pointer(offset + 24))
    class_methods = _method_list(image, image.pointer(offset + 32))
    optional_instance = _method_list(image, image.pointer(offset + 40))
    inherited = _protocol_list(image, image.pointer(offset + 16))
    record: dict[str, Any] = {"name": name}
    if instance_methods:
        record["instance_methods"] = instance_methods
    if class_methods:
        record["class_methods"] = class_methods
    if optional_instance:
        record["optional_methods"] = optional_instance
    if inherited:
        record["inherited_protocols"] = [p["name"] for p in inherited]
    return record


def _class(image: _Image, vmaddr: int) -> dict[str, Any] | None:
    offset = image.file_offset(vmaddr)
    if offset is None:
        return None
    # class_t: isa, superclass, cache, vtable, data (class_ro_t*), ...
    superclass_ptr = image.pointer(offset + 8)
    data_ptr = image.pointer(offset + 32)
    if data_ptr == 0:
        return None
    record: dict[str, Any] = {}
    if superclass_ptr:
        super_offset = image.file_offset(superclass_ptr)
        if super_offset is not None:
            super_name = image.cstring(image.pointer(super_offset + 32 + 24)) \
                if False else None
            # The superclass name lives in its own class_ro_t; resolve it the same way.
            super_data = image.pointer(super_offset + 32)
            if super_data:
                super_ro = image.file_offset(super_data & ~0x7)
                if super_ro is not None:
                    record["superclass"] = image.cstring(
                        image.pointer(super_ro + _RO_NAME_OFFSET))
    ro_ptr = data_ptr & ~0x7
    ro_offset = image.file_offset(ro_ptr)
    if ro_offset is None:
        # The low bits of `data` are flags in the tagged ("ro-pointer") form. If the
        # masked address does not resolve, the untagged form is the one in use.
        ro_offset = image.file_offset(data_ptr)
    if ro_offset is None:
        return None
    flags = image.u32(ro_offset)
    name = image.cstring(image.pointer(ro_offset + _RO_NAME_OFFSET))
    if not name:
        return None
    record["name"] = name
    record["root_class"] = bool(flags & RO_ROOT)
    # Class methods ("+foo") are not in the class's own class_ro_t — they live in the
    # metaclass, reached through class_t.isa. Reading only the class reports every
    # class as having instance methods and none else, which is exactly wrong for any
    # class whose interesting surface is its factory or shared-instance methods.
    metaclass_ptr = image.pointer(offset)
    if metaclass_ptr:
        metaclass_offset = image.file_offset(metaclass_ptr)
        if metaclass_offset is not None:
            meta_data = image.pointer(metaclass_offset + 32)
            if meta_data:
                meta_ro = image.file_offset(meta_data & ~0x7) \
                    or image.file_offset(meta_data)
                if meta_ro is not None and image.u32(meta_ro) & RO_META:
                    class_methods = _method_list(image, image.pointer(meta_ro + 32))
                    if class_methods:
                        record["class_methods"] = class_methods
    record["instance_size"] = image.u32(ro_offset + 12)
    methods = _method_list(image, image.pointer(ro_offset + 32))
    if methods:
        record["methods"] = methods
    protocols = _protocol_list(image, image.pointer(ro_offset + 40))
    if protocols:
        record["protocols"] = [p["name"] for p in protocols]
    properties = _method_list(image, image.pointer(ro_offset + 64))
    if properties:
        record["properties"] = properties
    return record


def inspect_objc(path: str | Path, *, limit: int = 500) -> dict[str, Any]:
    """Report Objective-C classes, protocols and methods from a Mach-O image."""
    try:
        data = _read(path)
    except (OSError, ValueError, Denied) as exc:
        return {"ok": False, "path": str(path), "error": str(exc)}

    if len(data) < 4:
        return {"ok": False, "path": str(path), "error": MACHO_ERR}

    slices: list[tuple[str, int]] = []
    magic_be = struct.unpack_from(">I", data, 0)[0]
    if magic_be == FAT_MAGIC:
        nfat = struct.unpack_from(">I", data, 4)[0]
        for index in range(min(nfat, 20)):
            _cpu, _sub, offset, _size, _align = struct.unpack_from(
                ">iiIII", data, 8 + index * 20)
            slices.append((f"slice{index}", offset))
    else:
        slices.append(("", 0))

    images: list[dict[str, Any]] = []
    errors: list[str] = []
    for label, offset in slices:
        try:
            image = _Image(data, offset)
        except (MachOObjCError, struct.error) as exc:
            errors.append(f"{label or 'image'}: {exc}")
            continue

        classes: list[dict[str, Any]] = []
        # Class list: new-style (__objc_classlist) plus the legacy __objc_catlist
        # categories, which add methods to a class defined elsewhere.
        section = image.section("__objc_classlist")
        if section:
            sect_offset, size = section
            for index in range(min(size // 8, limit)):
                class_ptr = image.pointer(sect_offset + index * 8)
                record = _class(image, class_ptr)
                if record:
                    classes.append(record)

        protocols: list[dict[str, Any]] = []
        section = image.section("__objc_protolist")
        if section:
            sect_offset, size = section
            for index in range(min(size // 8, limit)):
                record = _protocol(image, image.pointer(sect_offset + index * 8))
                if record:
                    protocols.append(record)

        categories: list[dict[str, Any]] = []
        section = image.section("__objc_catlist")
        if section:
            sect_offset, size = section
            for index in range(min(size // 8, 100)):
                cat_offset = image.file_offset(image.pointer(sect_offset + index * 8))
                if cat_offset is None:
                    continue
                cat_name = image.cstring(image.pointer(cat_offset))
                cat_class = image.cstring(image.pointer(cat_offset + 8))
                methods = _method_list(image, image.pointer(cat_offset + 16))
                if cat_name or cat_class:
                    categories.append({"name": cat_name, "class": cat_class,
                                       "methods": methods})

        images.append({
            "cputype": image.cputype,
            "filetype": image.filetype,
            "classes": classes[:limit],
            "class_count": len(classes),
            "protocols": protocols[:limit],
            "protocol_count": len(protocols),
            "categories": categories,
            "has_objc": bool(classes or protocols or categories),
            "sections": sorted(key for key in image._sections
                               if "__objc" in key),
        })

    if not images:
        return {"ok": False, "path": str(path), "error": MACHO_ERR, "details": errors}

    total_classes = sum(image["class_count"] for image in images)
    total_protocols = sum(image["protocol_count"] for image in images)
    result: dict[str, Any] = {
        "ok": True,
        "path": str(path),
        "image_count": len(images),
        "images": images,
        "class_count": total_classes,
        "protocol_count": total_protocols,
        "has_objc": any(image["has_objc"] for image in images),
    }
    if errors:
        result["errors"] = errors
    if not result["has_objc"]:
        result["hint"] = ("no Objective-C metadata in this image "
                          "(a C or C++ binary, or the metadata was stripped)")
    return result


def inspect(path: str | Path) -> dict[str, Any]:
    """Alias used by the shared verb dispatcher."""
    return inspect_objc(path)
