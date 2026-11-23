package sysimage

import (
	"debug/pe"
	"encoding/binary"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// openPE parses a PE image with debug/pe. Some shipped DLLs (measured on Wine's
// kernelbase.dll) carry a COFF symbol table whose string-table length runs past
// EOF and whose symbol records are not COFF symbols at all. That table is
// optional linker metadata: a broken one must not make the whole image
// unreadable. On that specific failure, retry with the symbol table hidden from
// the loader and with long section names that refer to it blanked. The returned
// note explains the omission to callers that surface warnings.
//
// Only PE header fields are overlaid. Patching bytes inside the string table
// itself would corrupt real image data on these files: kernelbase's COFF
// string-table offset lands in the middle of its export name table.
func openPE(r io.ReaderAt, size uint64) (*pe.File, string, error) {
	file, err := pe.NewFile(r)
	if err == nil || !strings.Contains(err.Error(), "string table") {
		return file, "", err
	}
	lfanew, ok := dosLfanew(r, size)
	if !ok || uint64(lfanew)+4+coffHeaderLen > size {
		return file, "", err
	}
	var coff [coffHeaderLen]byte
	if _, readErr := r.ReadAt(coff[:], int64(lfanew)+4); readErr != nil {
		return file, "", err
	}
	pointer := binary.LittleEndian.Uint32(coff[8:12])
	count := binary.LittleEndian.Uint32(coff[12:16])
	if pointer == 0 || count == 0 {
		return file, "", err
	}
	// PointerToSymbolTable and NumberOfSymbols: skip both the bogus symbol
	// records and the string table they point at.
	headerOffset := int64(lfanew) + 4
	patches := []coffBytePatch{{start: headerOffset + 8, data: make([]byte, 8)}}

	// A section name of the form "/N" is an offset into that unusable string
	// table. Blank those names; every other section name stays as the file
	// recorded it.
	sectionCount := int(binary.LittleEndian.Uint16(coff[2:4]))
	optionalSize := uint64(binary.LittleEndian.Uint16(coff[16:18]))
	sectionTable := uint64(lfanew) + 4 + coffHeaderLen + optionalSize
	if sectionCount > 4096 || sectionTable+uint64(sectionCount)*40 > size {
		return file, "", err
	}
	for i := 0; i < sectionCount; i++ {
		var name [8]byte
		at := int64(sectionTable) + int64(i)*40
		if _, readErr := r.ReadAt(name[:], at); readErr != nil {
			continue
		}
		if len(name) < 2 || name[0] != '/' {
			continue
		}
		token := strings.TrimRight(string(name[1:]), "\x00")
		if _, convErr := strconv.ParseUint(token, 10, 32); convErr != nil {
			continue
		}
		patches = append(patches, coffBytePatch{start: at, data: make([]byte, 8)})
	}

	fixed, fixErr := pe.NewFile(&coffSymbolStripReader{r: r, patches: patches})
	if fixErr != nil {
		return file, "", err
	}
	return fixed, fmt.Sprintf("COFF symbols ignored: unreadable string table at offset %#x (%v)", pointer, err), nil
}

// coffBytePatch replaces len(data) bytes at start in the underlying reader.
type coffBytePatch struct {
	start int64
	data  []byte
}

// coffSymbolStripReader is a read-only overlay that replaces a few PE header
// fields while leaving the rest of a possibly large image untouched.
type coffSymbolStripReader struct {
	r       io.ReaderAt
	patches []coffBytePatch
	pos     int64
}

func (s *coffSymbolStripReader) Read(b []byte) (int, error) {
	n, err := s.ReadAt(b, s.pos)
	s.pos += int64(n)
	return n, err
}

func (s *coffSymbolStripReader) Seek(offset int64, whence int) (int64, error) {
	switch whence {
	case io.SeekStart:
		s.pos = offset
	case io.SeekCurrent:
		s.pos += offset
	default:
		return 0, fmt.Errorf("coff symbol overlay: SeekEnd is unsupported")
	}
	if s.pos < 0 {
		return 0, fmt.Errorf("coff symbol overlay: negative seek offset")
	}
	return s.pos, nil
}

func (s *coffSymbolStripReader) ReadAt(b []byte, off int64) (int, error) {
	n, err := s.r.ReadAt(b, off)
	for _, patch := range s.patches {
		lo := max(off, patch.start)
		hi := min(off+int64(n), patch.start+int64(len(patch.data)))
		for at := lo; at < hi; at++ {
			b[at-off] = patch.data[at-patch.start]
		}
	}
	return n, err
}
