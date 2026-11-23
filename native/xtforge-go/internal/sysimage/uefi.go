package sysimage

import (
	"encoding/binary"
	"fmt"
	"io"
)

// A UEFI firmware volume (FV) begins with EFI_FIRMWARE_VOLUME_HEADER, a little
// endian structure whose fields this reader uses are:
//
//	+0  ZeroVector[16]       +16 FileSystemGuid[16]
//	+32 FvLength u64         +40 Signature u32 == 0x4856465F ("_FVH" in memory)
//	+44 Attributes u32       +48 HeaderLength u16
//	+50 Checksum u16         +52 ExtHeaderOffset u16
//	+54 Reserved u8, followed by Revision and the 8-byte block-map entries
//
// The block map describes erase-block geometry, not file placement, and its
// exact start shifts between published revisions of the structure. Neither it
// nor the revision byte is consumed here: HeaderLength alone locates the file
// area, so the reader is insensitive to that variation.
//
// Files in the area are EFI_FFS_FILE_HEADERs, 8-byte aligned:
//
//	+0 Name[16] GUID         +16 IntegrityCheck u16
//	+18 Type u8              +19 Attributes u8
//	+20 Size[3] (24-bit LE)  +23 State u8
//
// A Size of 0xFFFFFF is a marker for EFI_FFS_FILE_HEADER2, which carries the
// real 64-bit size at +24. This is a read-only inventory: file names, offsets,
// sizes and types are reported, but no section payload is extracted and no
// compression (including the 0xFF LZMA marker type) is undone.

const (
	uefiFVSignature = 0x4856465F // "_FVH" stored as four little-endian bytes

	// uefiFVHeaderBytes is the fixed prefix through the fields consumed above.
	// It deliberately stops before the revision/block-map area.
	uefiFVHeaderBytes = 56
	uefiMaxVolume     = 512 << 20 // same ceiling as the other firmware readers
	uefiDefaultFiles  = 4096

	uefiFFSHeaderBytes = 24
	uefiFFSExtSizeOff  = 24       // EFI_FFS_FILE_HEADER2.ExtendedSize (u64)
	uefiFFSLargeSize   = 0xFFFFFF // Size[3] marker for an extended-size file
	uefiFileAlign      = 8
)

// UEFIFile is one FFS file header found in a firmware volume. Name is the
// formatted Name GUID: FFS names are GUIDs and this package has no registry of
// friendly names to substitute. Type is reported verbatim; a type of 0xFF is
// an LZMA-compressed section marker in some firmware and is never decompressed.
type UEFIFile struct {
	Name   string `json:"name"`
	GUID   string `json:"guid"`
	Offset uint32 `json:"offset"`
	Size   uint32 `json:"size"`
	Type   uint8  `json:"type"`
}

// UEFIVolume is the header inventory of one firmware volume. Extracted is
// always false: the reader inventories headers and does not extract payloads.
type UEFIVolume struct {
	GUID         string     `json:"guid"`
	Length       uint64     `json:"length"`
	HeaderLength uint16     `json:"header_length"`
	FileCount    int        `json:"file_count"`
	Files        []UEFIFile `json:"files"`
	Extracted    bool       `json:"extracted"`
}

// IsUEFIVolume reports whether head is long enough to hold the firmware volume
// signature and carries that signature at +40. It is safe on a short probe
// prefix: random bytes and nil do not produce a false positive.
func IsUEFIVolume(head []byte) bool {
	return len(head) >= 44 && binary.LittleEndian.Uint32(head[40:44]) == uefiFVSignature
}

// ReadUEFIVolume parses the firmware volume at the start of r. size bounds the
// input; limit caps the number of FFS files walked (<=0 means 4096). A volume
// larger than 512 MiB, one whose FvLength runs past the file, a bad signature
// or an inconsistent file size is rejected. The walk stops at an all-zero or
// all-0xFF (erased) name GUID and never panics on malformed input.
func ReadUEFIVolume(r io.ReaderAt, size int64, limit int) (UEFIVolume, error) {
	var volume UEFIVolume
	if r == nil {
		return volume, fmt.Errorf("uefi firmware volume requires a reader")
	}
	if size < uefiFVHeaderBytes {
		return volume, fmt.Errorf("uefi firmware volume is only %d bytes; a header needs at least %d", size, uefiFVHeaderBytes)
	}
	if size > uefiMaxVolume {
		return volume, fmt.Errorf("uefi firmware volume of %d bytes exceeds the %d MiB inspection limit", size, uefiMaxVolume>>20)
	}
	if limit <= 0 {
		limit = uefiDefaultFiles
	}

	var head [uefiFVHeaderBytes]byte
	if _, err := r.ReadAt(head[:], 0); err != nil {
		return volume, fmt.Errorf("read uefi firmware volume header: %w", err)
	}
	if !IsUEFIVolume(head[:]) {
		return volume, fmt.Errorf("not a uefi firmware volume: bad signature %q", head[40:44])
	}

	fvLength := binary.LittleEndian.Uint64(head[32:40])
	if fvLength > uint64(size) {
		return volume, fmt.Errorf("uefi firmware volume length %d exceeds the %d-byte file", fvLength, size)
	}
	if fvLength > uefiMaxVolume {
		return volume, fmt.Errorf("uefi firmware volume length %d exceeds the %d MiB inspection limit", fvLength, uefiMaxVolume>>20)
	}
	if fvLength < uefiFVHeaderBytes {
		return volume, fmt.Errorf("uefi firmware volume length %d is shorter than its %d-byte header", fvLength, uefiFVHeaderBytes)
	}
	headerLength := binary.LittleEndian.Uint16(head[48:50])
	if headerLength < uefiFVHeaderBytes || uint64(headerLength) > fvLength {
		return volume, fmt.Errorf("uefi firmware volume header length %d is invalid for a %d-byte volume", headerLength, fvLength)
	}

	volume.GUID = formatGUIDBytes(head[16:32])
	volume.Length = fvLength
	volume.HeaderLength = headerLength
	// Extracted stays false: no file section is unpacked by this reader.

	for offset := uefiAlignUp(uint64(headerLength)); offset+uefiFFSHeaderBytes <= fvLength && volume.FileCount < limit; {
		var fileHead [uefiFFSHeaderBytes]byte
		if _, err := r.ReadAt(fileHead[:], int64(offset)); err != nil {
			return volume, fmt.Errorf("read uefi file header at offset %#x: %w", offset, err)
		}
		if uefiAllByte(fileHead[:16], 0) || uefiAllByte(fileHead[:16], 0xff) {
			break // zero GUID ends the list; 0xFF is erased free space
		}

		fileSize := uint32(fileHead[20]) | uint32(fileHead[21])<<8 | uint32(fileHead[22])<<16
		if fileSize == uefiFFSLargeSize {
			// Large-file entries are handled: EFI_FFS_FILE_HEADER2 extends the
			// 24-byte header with an 8-byte ExtendedSize at +24.
			var ext [8]byte
			if _, err := r.ReadAt(ext[:], int64(offset)+uefiFFSExtSizeOff); err != nil {
				return volume, fmt.Errorf("read large uefi file size at offset %#x: %w", offset, err)
			}
			extended := binary.LittleEndian.Uint64(ext[:])
			if extended < uefiFFSHeaderBytes+8 || extended > uint64(^uint32(0)) || extended > fvLength-offset {
				return volume, fmt.Errorf("large uefi file at offset %#x has invalid extended size %d", offset, extended)
			}
			fileSize = uint32(extended)
		}
		if fileSize < uefiFFSHeaderBytes || uint64(fileSize) > fvLength-offset {
			return volume, fmt.Errorf("uefi file at offset %#x has invalid size %d", offset, fileSize)
		}

		guid := formatGUIDBytes(fileHead[:16])
		volume.Files = append(volume.Files, UEFIFile{
			Name:   guid,
			GUID:   guid,
			Offset: uint32(offset),
			Size:   fileSize,
			Type:   fileHead[18], // 0xFF: LZMA marker, reported but not decompressed
		})
		volume.FileCount++
		offset = uefiAlignUp(offset + uint64(fileSize))
	}
	return volume, nil
}

func uefiAlignUp(offset uint64) uint64 {
	return (offset + uefiFileAlign - 1) &^ uint64(uefiFileAlign-1)
}

func uefiAllByte(b []byte, value byte) bool {
	for _, v := range b {
		if v != value {
			return false
		}
	}
	return true
}
