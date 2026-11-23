package sysimage

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"strconv"
)

// COFF object files use the same machine table as PE images but have no DOS
// header, no optional header and no entry point. They are what a compiler emits
// before linking; archives of them are handled by archive.go.
const (
	coffHeaderLen         = 20         // Machine u16, NumberOfSections u16, timestamp u32, symbol pointer u32, symbol count u32, optional-header size u16, characteristics u16
	coffSectionHeaderLen  = 40         // Name[8] plus nine numeric fields
	coffSymbolLen         = 18         // Name[8], value, section, type, class, aux count
	coffDefaultMaxSymbols = 20000      // a bound for callers that pass limit <= 0; large objects still need a ceiling
	coffMaxPrealloc       = 4096       // preallocating from the declared u32 count could request billions of entries on corrupt input
	coffMaxStringTable    = 16 << 20   // its length is a u32; names this long are already implausible, so a corrupt length cannot force a 4 GiB allocation
	coffSCNMemExecute     = 0x20000000 // IMAGE_SCN_MEM_EXECUTE: the section contains executable code
)

// COFFSection is one section header of a COFF object. VirtualSize and
// VirtualAddress are zero in most unlinked objects: the linker assigns them.
type COFFSection struct {
	Name            string `json:"name"`
	VirtualSize     uint32 `json:"virtual_size"`
	VirtualAddress  uint32 `json:"virtual_address"`
	RawSize         uint32 `json:"raw_size"`
	RawOffset       uint32 `json:"raw_offset"`
	Characteristics uint32 `json:"characteristics"`
	Executable      bool   `json:"executable"`
}

// COFFSymbol is one non-auxiliary symbol record. Section is signed because -1
// means ABS and -2 means DEBUG in the COFF encoding.
type COFFSymbol struct {
	Name         string `json:"name"`
	Value        uint32 `json:"value"`
	Section      int    `json:"section"`
	Type         uint16 `json:"type"`
	StorageClass uint8  `json:"storage_class"`
}

// COFFObject is the parsed content of a standalone COFF object file.
type COFFObject struct {
	Machine         uint16        `json:"machine"`
	MachineName     string        `json:"machine_name"`
	Sections        []COFFSection `json:"sections"`
	Symbols         []COFFSymbol  `json:"symbols"`
	TimeDateStamp   uint32        `json:"time_date_stamp"`
	Characteristics uint16        `json:"characteristics"`
}

// IsCOFF reports whether head is the start of a COFF object for a machine this
// package understands. SizeOfOptionalHeader at bytes 16..18 is zero in an
// object and non-zero in a PE image: that is the check that stops a PE with an
// unusual first bytes from being mistaken for an object. Eighteen bytes are
// required because both fields must be present before the answer is meaningful.
func IsCOFF(head []byte) bool {
	if len(head) < 18 {
		return false
	}
	switch binary.LittleEndian.Uint16(head[:2]) {
	case 0x014c, // x86
		0x8664, // x86-64
		0xaa64, // arm64
		0x01c0, // arm
		0x01c4, // armnt (thumb-2)
		0xa641: // arm64ec
	default:
		return false
	}
	return binary.LittleEndian.Uint16(head[16:18]) == 0
}

// ReadCOFF parses a standalone COFF object. limit caps the number of symbols
// returned (limit <= 0 means 20000); AUXILIARY records do not count as symbols.
// All offsets are checked against size before a read, so malformed inputs
// produce an error rather than a panic or an unbounded allocation.
func ReadCOFF(r io.ReaderAt, size int64, limit int) (COFFObject, error) {
	var object COFFObject
	if r == nil {
		return object, fmt.Errorf("coff: nil reader")
	}
	// The whole 20-byte header must exist; size also has to be non-negative so
	// the uint64 offsets derived from it cannot wrap past EOF.
	if size < coffHeaderLen {
		return object, fmt.Errorf("coff: file is too short for a %d-byte header", coffHeaderLen)
	}
	if limit <= 0 {
		limit = coffDefaultMaxSymbols
	}
	var header [coffHeaderLen]byte
	if err := readCOFFRecord(r, header[:], 0); err != nil {
		return object, fmt.Errorf("coff: read header: %w", err)
	}
	if !IsCOFF(header[:]) {
		return object, fmt.Errorf("coff: not a supported COFF object header")
	}

	numSections := uint64(binary.LittleEndian.Uint16(header[2:4]))
	symbolOffset := uint64(binary.LittleEndian.Uint32(header[8:12]))
	numSymbols := uint64(binary.LittleEndian.Uint32(header[12:16]))
	object.Machine = binary.LittleEndian.Uint16(header[:2])
	object.MachineName = coffMachineName(object.Machine)
	object.TimeDateStamp = binary.LittleEndian.Uint32(header[4:8])
	object.Characteristics = binary.LittleEndian.Uint16(header[18:20])

	// Section headers start directly after the header. A u16 count can claim
	// 65535 * 40 bytes, so reject a range that does not fit in this file before
	// allocating or reading any of it.
	sectionBytes := numSections * coffSectionHeaderLen
	if sectionBytes > uint64(size)-coffHeaderLen {
		return object, fmt.Errorf("coff: %d section headers exceed the file", numSections)
	}
	sectionsEnd := uint64(coffHeaderLen) + sectionBytes
	// The declared symbol count includes AUX records and is a u32; validate the
	// entire table against the file before walking it, or a bogus count becomes
	// a multi-billion-record loop.
	if symbolOffset != 0 {
		if symbolOffset > uint64(size) || numSymbols*coffSymbolLen > uint64(size)-symbolOffset {
			return object, fmt.Errorf("coff: symbol table exceeds the file")
		}
	}
	stringTable := coffStringTable(r, uint64(size), symbolOffset, numSymbols, sectionsEnd)

	object.Sections = make([]COFFSection, 0, int(numSections))
	for i := uint64(0); i < numSections; i++ {
		var raw [coffSectionHeaderLen]byte
		offset := uint64(coffHeaderLen) + i*coffSectionHeaderLen
		if err := readCOFFRecord(r, raw[:], offset); err != nil {
			return object, fmt.Errorf("coff: read section header %d: %w", i, err)
		}
		characteristics := binary.LittleEndian.Uint32(raw[36:40])
		object.Sections = append(object.Sections, COFFSection{
			Name:            coffSectionName(raw[:8], stringTable),
			VirtualSize:     binary.LittleEndian.Uint32(raw[8:12]),
			VirtualAddress:  binary.LittleEndian.Uint32(raw[12:16]),
			RawSize:         binary.LittleEndian.Uint32(raw[16:20]),
			RawOffset:       binary.LittleEndian.Uint32(raw[20:24]),
			Characteristics: characteristics,
			Executable:      characteristics&coffSCNMemExecute != 0,
		})
	}

	if symbolOffset == 0 || numSymbols == 0 {
		return object, nil
	}
	// Cap the preallocation independently of the caller's limit and the
	// declared count: both can be enormous, but only symbols actually read
	// should cost memory.
	capacity := uint64(limit)
	if capacity > numSymbols {
		capacity = numSymbols
	}
	if capacity > coffMaxPrealloc {
		capacity = coffMaxPrealloc
	}
	object.Symbols = make([]COFFSymbol, 0, int(capacity))
	for i := uint64(0); i < numSymbols && len(object.Symbols) < limit; {
		var raw [coffSymbolLen]byte
		offset := symbolOffset + i*coffSymbolLen
		if err := readCOFFRecord(r, raw[:], offset); err != nil {
			return object, fmt.Errorf("coff: read symbol %d: %w", i, err)
		}
		aux := uint64(raw[17])
		object.Symbols = append(object.Symbols, COFFSymbol{
			Name:         coffSymbolName(raw[:8], stringTable),
			Value:        binary.LittleEndian.Uint32(raw[8:12]),
			Section:      int(int16(binary.LittleEndian.Uint16(raw[12:14]))),
			Type:         binary.LittleEndian.Uint16(raw[14:16]),
			StorageClass: raw[16],
		})
		// AUX records are extensions of the preceding symbol, not symbols of
		// their own. Skipping 18 * (1 + aux) bytes is essential: reading them as
		// symbols would shift every name after the first AUX record.
		if aux > numSymbols-i-1 {
			aux = numSymbols - i - 1 // tolerate a corrupt count at the end of the table
		}
		i += 1 + aux
	}
	return object, nil
}

// readCOFFRecord fills buf from an offset already checked against the file
// size. ReaderAt may return a short read with a nil error, which must still be
// treated as truncation; int64 is safe because offsets come from a bounded
// int64 file size.
func readCOFFRecord(r io.ReaderAt, buf []byte, offset uint64) error {
	n, err := r.ReadAt(buf, int64(offset))
	if n != len(buf) {
		if err == nil {
			err = io.ErrUnexpectedEOF
		}
		return err
	}
	return nil
}

// coffStringTable returns the string-table bytes after the 4-byte length word.
// The table follows the last symbol record (AUX records included); when an
// object has no symbol table it follows the section headers instead. A missing
// or corrupt table is simply absent: long names then keep their raw form.
func coffStringTable(r io.ReaderAt, size uint64, symbolOffset, numSymbols, sectionsEnd uint64) []byte {
	offset := sectionsEnd
	if symbolOffset != 0 {
		offset = symbolOffset + numSymbols*coffSymbolLen
	}
	if offset > size || size-offset < 4 {
		return nil
	}
	var lengthBytes [4]byte
	if err := readCOFFRecord(r, lengthBytes[:], offset); err != nil {
		return nil
	}
	declared := uint64(binary.LittleEndian.Uint32(lengthBytes[:]))
	if declared < 4 { // the length includes the length word itself
		return nil
	}
	available := size - offset - 4
	want := min(declared-4, available, uint64(coffMaxStringTable-4))
	if want == 0 {
		return nil
	}
	buf := make([]byte, want)
	// A short read still resolves names earlier in the table, so keep the
	// prefix rather than refusing the whole object.
	n, _ := r.ReadAt(buf, int64(offset+4))
	return buf[:max(n, 0)]
}

// coffStringAt resolves an offset measured from the start of the string table.
// strTab holds the bytes after its 4-byte length word, so the first string is
// at offset 4. Reads never escape the bounded table slice.
func coffStringAt(strTab []byte, offset uint64) string {
	if offset < 4 || offset-4 >= uint64(len(strTab)) {
		return ""
	}
	name := strTab[offset-4:]
	if end := bytes.IndexByte(name, 0); end >= 0 {
		name = name[:end]
	}
	return string(name)
}

// coffSectionName resolves the three COFF section-name encodings: a NUL-ended
// short name, a GNU-style "/123" decimal reference, or a binary little-endian
// string-table offset. An eight-character literal such as ".debug$S" looks
// like the third form, but the lookup fails for it and the literal is kept.
func coffSectionName(field []byte, strTab []byte) string {
	if len(field) == 8 {
		if field[0] == '/' {
			if name := coffDecimalName(field, strTab); name != "" {
				return name
			}
		}
		if value := binary.LittleEndian.Uint64(field); value>>32 == 0 {
			if name := coffStringAt(strTab, value); name != "" {
				return name
			}
		}
		if binary.LittleEndian.Uint32(field[:4]) == 0 {
			if name := coffStringAt(strTab, uint64(binary.LittleEndian.Uint32(field[4:8]))); name != "" {
				return name
			}
		}
	}
	return coffShortName(field)
}

// coffDecimalName parses the "/123" form used by GNU COFF writers.
func coffDecimalName(field []byte, strTab []byte) string {
	digits := field[1:]
	if end := bytes.IndexByte(digits, 0); end >= 0 {
		digits = digits[:end]
	}
	if len(digits) == 0 {
		return ""
	}
	for _, digit := range digits {
		if digit < '0' || digit > '9' {
			return ""
		}
	}
	offset, err := strconv.ParseUint(string(digits), 10, 32)
	if err != nil {
		return ""
	}
	return coffStringAt(strTab, offset)
}

// coffSymbolName treats four leading zero bytes as the marker for a long name
// stored at the string-table offset in the following four bytes. Unlike a
// section name, a fully occupied 8-byte symbol name is a literal name.
func coffSymbolName(field []byte, strTab []byte) string {
	if len(field) == 8 && binary.LittleEndian.Uint32(field[:4]) == 0 {
		if name := coffStringAt(strTab, uint64(binary.LittleEndian.Uint32(field[4:8]))); name != "" {
			return name
		}
	}
	return coffShortName(field)
}

func coffShortName(field []byte) string {
	if end := bytes.IndexByte(field, 0); end >= 0 {
		field = field[:end]
	}
	return string(field)
}

// coffMachineName uses Windows machine names so a report matches the compiler
// target that produced the object.
func coffMachineName(machine uint16) string {
	switch machine {
	case 0x014c:
		return "x86"
	case 0x8664:
		return "x86-64"
	case 0xaa64:
		return "arm64"
	case 0x01c0:
		return "arm"
	case 0x01c4:
		return "armnt"
	case 0xa641:
		return "arm64ec"
	default:
		return fmt.Sprintf("unknown-0x%04x", machine)
	}
}

// coffArchBits maps an object's machine to the architecture vocabulary and
// word size used by the rest of the engine.
func coffArchBits(machine uint16) (string, int) {
	switch machine {
	case 0x014c:
		return "x86", 32
	case 0x8664:
		return "x86_64", 64
	case 0xaa64, 0xa641:
		return "arm64", 64
	case 0x01c0, 0x01c4:
		return "arm", 32
	default:
		return archName(coffMachineName(machine)), 64
	}
}
