package sysimage

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// PEDebugDirectory is one entry of the PE debug data directory.
type PEDebugDirectory struct {
	Type    uint32 `json:"type"`
	Size    uint32 `json:"size"`
	Address uint32 `json:"address"` // RVA of the record
	Pointer uint32 `json:"pointer"` // file offset of the record
}

// CodeViewInfo identifies the PDB a PE was linked against.
type CodeViewInfo struct {
	Signature string `json:"signature"` // e.g. "RSDS"
	Path      string `json:"path"`
	GUID      string `json:"guid"` // formatted 8-4-4-4-12, lowercase hex
	Age       uint32 `json:"age"`
}

const (
	peDebugDirectoryEntryLen = 28
	peCodeViewRSDSHeaderLen  = 24
	peCodeViewNB10HeaderLen  = 16
)

// ReadPEDebugDirectory parses the debug data directory blob, a sequence of
// 28-byte IMAGE_DEBUG_DIRECTORY entries. All entries are returned, not just
// those of type IMAGE_DEBUG_TYPE_CODEVIEW (2). Incomplete trailing entries and
// blobs shorter than one entry yield nil (or the complete entries decoded so
// far). Every read is bounds-checked.
func ReadPEDebugDirectory(blob []byte) []PEDebugDirectory {
	if len(blob) < peDebugDirectoryEntryLen {
		return nil
	}
	entries := make([]PEDebugDirectory, 0, len(blob)/peDebugDirectoryEntryLen)
	for off := 0; off+peDebugDirectoryEntryLen <= len(blob); off += peDebugDirectoryEntryLen {
		e := blob[off : off+peDebugDirectoryEntryLen]
		entries = append(entries, PEDebugDirectory{
			Type:    binary.LittleEndian.Uint32(e[12:16]),
			Size:    binary.LittleEndian.Uint32(e[16:20]),
			Address: binary.LittleEndian.Uint32(e[20:24]),
			Pointer: binary.LittleEndian.Uint32(e[24:28]),
		})
	}
	return entries
}

// ReadCodeView parses a CodeView record (the bytes at a debug directory
// entry's file pointer). Both the RSDS and older NB10 formats are accepted;
// ok is false for an unknown signature or a record too short to hold the
// format's fixed fields. A path that runs to the end of the record without a
// NUL terminator is kept in full, and one ending at a NUL is cut there.
func ReadCodeView(record []byte) (CodeViewInfo, bool) {
	if len(record) < 4 {
		return CodeViewInfo{}, false
	}
	switch string(record[:4]) {
	case "RSDS":
		if len(record) < peCodeViewRSDSHeaderLen {
			return CodeViewInfo{}, false
		}
		guid := formatGUIDBytes(record[4:20])
		return CodeViewInfo{
			Signature: "RSDS",
			Path:      peCodeViewPath(record[peCodeViewRSDSHeaderLen:]),
			GUID:      guid,
			Age:       binary.LittleEndian.Uint32(record[20:24]),
		}, true
	case "NB10":
		if len(record) < peCodeViewNB10HeaderLen {
			return CodeViewInfo{}, false
		}
		return CodeViewInfo{
			Signature: "NB10",
			Path:      peCodeViewPath(record[peCodeViewNB10HeaderLen:]),
			Age:       binary.LittleEndian.Uint32(record[12:16]),
		}, true
	default:
		return CodeViewInfo{}, false
	}
}

// peCodeViewPath reads a NUL-terminated UTF-8 path, or all remaining bytes
// when the record ends without a terminator.
func peCodeViewPath(b []byte) string {
	if nul := bytes.IndexByte(b, 0); nul >= 0 {
		b = b[:nul]
	}
	return string(b)
}

// CodeViewMatches reports whether a CodeView record and a PDB's own identity
// agree. pdbGUID and pdbAge come from the PDB. An empty pdbGUID matches only
// an empty GUID.
func CodeViewMatches(info CodeViewInfo, pdbGUID string, pdbAge uint32) bool {
	return info.GUID == pdbGUID && info.Age == pdbAge
}

// formatGUIDBytes renders a 16-byte GUID in canonical 8-4-4-4-12 form.
//
// Data1/Data2/Data3 are little-endian on the wire and Data4 is literal, which is why
// the first three fields are read through the byte order and the last ten bytes are
// not. Both the CodeView record and the PDB info stream store GUIDs this way, so one
// formatter keeps them comparable.
func formatGUIDBytes(raw []byte) string {
	if len(raw) < 16 {
		return ""
	}
	return fmt.Sprintf("%08x-%04x-%04x-%x-%x",
		binary.LittleEndian.Uint32(raw[0:4]),
		binary.LittleEndian.Uint16(raw[4:6]),
		binary.LittleEndian.Uint16(raw[6:8]),
		raw[8:10],
		raw[10:16],
	)
}
