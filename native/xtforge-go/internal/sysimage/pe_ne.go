package sysimage

import (
	"encoding/binary"
	"fmt"
	"io"
)

// The DOS header's e_lfanew field lives at 0x3c and points at the signature that
// follows it. A PE puts "PE\0\0" there; a 16-bit New Executable puts "NE".
const (
	eLfanewOffset    = 0x3c
	eLfanewLen       = 4
	neSignatureLen   = 2
	neFlagsOffset    = 12 // ne_flags, a WORD in the NE header
	neTargetOSOffset = 54 // ne_exetyp, the target operating system byte
	neHeaderLen      = 56 // through ne_exetyp; segment tables are not needed to identify NE
)

// NEImage is the cheaply readable part of a 16-bit Windows New Executable.
// Segment tables and resources are deliberately not parsed: identifying the
// format and reporting the fields in the header is the point.
type NEImage struct {
	ELfanew  uint32 `json:"e_lfanew"`  // offset of the "NE" signature in the DOS file
	TargetOS uint8  `json:"target_os"` // NE ne_exetyp: 2 is Windows
	Flags    uint16 `json:"flags"`     // NE ne_flags
}

// NEHeader is an alias for callers that name the structure after the NE header
// it describes.
type NEHeader = NEImage

// dosLfanew reads the DOS header's e_lfanew pointer. A short or unreadable DOS
// header is not an NE file as far as this reader is concerned.
func dosLfanew(r io.ReaderAt, size uint64) (uint32, bool) {
	if size < eLfanewOffset+eLfanewLen {
		return 0, false
	}
	var field [eLfanewLen]byte
	if _, err := r.ReadAt(field[:], eLfanewOffset); err != nil {
		return 0, false
	}
	return binary.LittleEndian.Uint32(field[:]), true
}

// isNEAt reports whether an MZ file's e_lfanew points at an NE signature.
func isNEAt(r io.ReaderAt, lfanew uint32) bool {
	var signature [neSignatureLen]byte
	if _, err := r.ReadAt(signature[:], int64(lfanew)); err != nil {
		return false
	}
	return string(signature[:]) == "NE"
}

// readNEImage decodes the fields that fit in the first 56 bytes of the NE
// header. It never follows the segment, resource, or entry-table pointers.
func readNEImage(r io.ReaderAt, lfanew uint32, size uint64) (*NEImage, error) {
	if uint64(lfanew)+neHeaderLen > size {
		return nil, fmt.Errorf("NE header at offset %#x is truncated", lfanew)
	}
	header := make([]byte, neHeaderLen)
	if _, err := r.ReadAt(header, int64(lfanew)); err != nil {
		return nil, fmt.Errorf("read NE header: %w", err)
	}
	if string(header[:neSignatureLen]) != "NE" {
		return nil, fmt.Errorf("invalid NE signature: % x", header[:neSignatureLen])
	}
	return &NEImage{
		ELfanew:  lfanew,
		TargetOS: header[neTargetOSOffset],
		Flags:    binary.LittleEndian.Uint16(header[neFlagsOffset : neFlagsOffset+2]),
	}, nil
}
