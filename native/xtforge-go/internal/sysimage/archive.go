package sysimage

import (
	"bytes"
	"fmt"
	"io"
	"math"
	"strconv"
	"strings"
)

// archiveMagic is the signature at the start of a classic ar archive.
const archiveMagic = "!<arch>\n"

const (
	archiveHeaderLen  = 60        // name[16] mtime[12] uid[6] gid[6] mode[8] size[10] fmag[2]
	archiveNameLen    = 16        // width of the name field in a header
	archiveSizeOff    = 48        // offset of the decimal size field
	archiveSizeLen    = 10        // width of the decimal size field
	archiveDefaultMax = 10000     // member cap when limit <= 0
	archiveLongName   = "//"      // GNU long-name table
	archiveSymbolIdx  = "/"       // first linker member
	archiveSym64Idx   = "/SYM64/" // COFF64 symbol table
)

// ArchiveMember is one member of a Unix/COFF static archive.
type ArchiveMember struct {
	Name   string `json:"name"`
	Offset int64  `json:"offset"`
	Size   int64  `json:"size"`
}

// IsArchive reports whether the bytes begin a classic `ar` archive ("!<arch>\n").
func IsArchive(head []byte) bool {
	return len(head) >= len(archiveMagic) && string(head[:len(archiveMagic)]) == archiveMagic
}

// ListArchiveMembers returns the ordinary members of an archive, skipping the
// symbol index ("/"), the long-name table ("//") and the string table ("/SYM64/").
// Member offsets point at their 60-byte headers. limit <= 0 means 10000 members.
func ListArchiveMembers(r io.ReaderAt, size int64, limit int) ([]ArchiveMember, error) {
	if r == nil {
		return nil, fmt.Errorf("archive: nil reader")
	}
	if size < int64(len(archiveMagic)) {
		return nil, fmt.Errorf("archive: file is too short to hold an archive magic")
	}
	var magic [len(archiveMagic)]byte
	if _, err := r.ReadAt(magic[:], 0); err != nil {
		return nil, fmt.Errorf("archive: read magic: %w", err)
	}
	if !IsArchive(magic[:]) {
		return nil, fmt.Errorf("archive: bad magic")
	}
	if limit <= 0 {
		limit = archiveDefaultMax
	}

	members := make([]ArchiveMember, 0)
	var longNames []byte
	off := int64(len(archiveMagic))
	for len(members) < limit {
		// A whole header must fit before the declared end of the archive.
		if off > size-int64(archiveHeaderLen) {
			break
		}
		var hdr [archiveHeaderLen]byte
		n, err := r.ReadAt(hdr[:], off)
		if n != archiveHeaderLen {
			if err == nil {
				err = io.ErrUnexpectedEOF
			}
			return nil, fmt.Errorf("archive: truncated header at offset %d: %w", off, err)
		}
		if hdr[58] != '`' || hdr[59] != '\n' {
			return nil, fmt.Errorf("archive: bad header magic at offset %d", off)
		}
		memberSize, err := parseArchiveSize(hdr[archiveSizeOff : archiveSizeOff+archiveSizeLen])
		if err != nil {
			return nil, fmt.Errorf("archive: member header at offset %d: %w", off, err)
		}

		dataOff := off + archiveHeaderLen // off is bounded by size, so this cannot overflow
		if memberSize > size-dataOff {
			return nil, fmt.Errorf("archive: member at offset %d exceeds file size", off)
		}
		dataEnd := dataOff + memberSize
		nameField := strings.TrimRight(string(hdr[:archiveNameLen]), " ")
		switch nameField {
		case archiveSymbolIdx, archiveSym64Idx:
			// Special index members carry no object data to report.
		case archiveLongName:
			longNames, err = readArchiveData(r, dataOff, memberSize)
			if err != nil {
				return nil, fmt.Errorf("archive: read long-name table: %w", err)
			}
		default:
			members = append(members, ArchiveMember{
				Name:   archiveMemberName(nameField, longNames),
				Offset: off,
				Size:   memberSize,
			})
		}

		// ar pads each member to an even file offset: after an odd-sized data
		// section one pad byte follows. Forgetting this pad shifts every later
		// header by a byte and silently corrupts the rest of the listing.
		if dataEnd%2 != 0 {
			if dataEnd == math.MaxInt64 {
				break
			}
			dataEnd++
		}
		if dataEnd > size || dataEnd <= off {
			break
		}
		off = dataEnd
	}
	return members, nil
}

// parseArchiveSize decodes the decimal, space-padded size field of a header.
func parseArchiveSize(field []byte) (int64, error) {
	text := strings.TrimSpace(string(field))
	if text == "" {
		return 0, fmt.Errorf("empty size field")
	}
	for i := 0; i < len(text); i++ {
		if text[i] < '0' || text[i] > '9' {
			return 0, fmt.Errorf("invalid size field %q", text)
		}
	}
	n, err := strconv.ParseInt(text, 10, 64)
	if err != nil || n < 0 {
		return 0, fmt.Errorf("invalid size field %q", text)
	}
	return n, nil
}

// readArchiveData copies a member's payload; callers have already bounds-checked it.
func readArchiveData(r io.ReaderAt, off, size int64) ([]byte, error) {
	if size == 0 {
		return nil, nil
	}
	if size > math.MaxInt {
		return nil, fmt.Errorf("member is too large to buffer")
	}
	buf := make([]byte, int(size))
	n, err := r.ReadAt(buf, off)
	if n != len(buf) {
		if err == nil {
			err = io.ErrUnexpectedEOF
		}
		return nil, err
	}
	return buf, nil
}

// archiveMemberName strips the GNU short-name terminator, resolving "/<decimal>"
// through the "//" table when that table has already been seen.
func archiveMemberName(nameField string, longNames []byte) string {
	if ref, ok := parseLongNameRef(nameField); ok && ref < int64(len(longNames)) {
		if name := resolveArchiveLongName(longNames[ref:]); name != "" {
			return name
		}
	}
	if slash := strings.IndexByte(nameField, '/'); slash >= 0 {
		nameField = nameField[:slash]
	}
	return strings.TrimRight(nameField, " ")
}

// resolveArchiveLongName reads one entry out of a GNU "//" long-name table.
//
// GNU terminates each entry with "/\n", not with NUL — the table is a sequence of
// "<name>/\n" strings. Looking only for a NUL finds nothing, and the reference then
// resolves to the empty string, which is exactly what a real `ar rcs` archive
// produced before this was fixed. Some writers do use NUL, so both terminators are
// accepted and the earlier one wins.
func resolveArchiveLongName(table []byte) string {
	end := len(table)
	if n := bytes.IndexByte(table, 0); n >= 0 && n < end {
		end = n
	}
	if n := bytes.Index(table, []byte("/\n")); n >= 0 && n < end {
		end = n
	}
	return string(table[:end])
}

// parseLongNameRef recognizes the "/123" form of a GNU long-name reference.
func parseLongNameRef(nameField string) (int64, bool) {
	if len(nameField) < 2 || nameField[0] != '/' {
		return 0, false
	}
	for i := 1; i < len(nameField); i++ {
		if nameField[i] < '0' || nameField[i] > '9' {
			return 0, false
		}
	}
	ref, err := strconv.ParseInt(nameField[1:], 10, 64)
	return ref, err == nil
}
