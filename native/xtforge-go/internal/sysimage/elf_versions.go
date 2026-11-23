package sysimage

import (
	"bytes"
	"encoding/binary"
)

// ElfSymbolVersion is one versioned symbol requirement.
type ElfSymbolVersion struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"` // e.g. "GLIBC_2.34"
	Library string `json:"library,omitempty"`
}

// DebugLink describes a separate debug file referenced by .gnu_debuglink.
type DebugLink struct {
	Name string `json:"name"`
	CRC  uint32 `json:"crc"`
}

// Chain caps keep inspection bounded on malformed or hostile binaries: the
// offsets in these sections are untrusted and can describe arbitrarily long
// (or self-referential) chains, so no loop may run for an unbounded count.
const (
	maxVerneedEntries = 4096
	maxVernauxEntries = 4096
)

// ReadElfSymbolVersions returns the version requirements of undefined symbols.
// verneed is the .gnu.version_r section, versym the .gnu.version section,
// dynsym the dynamic symbol table, dynstr the dynamic string table, and bits
// the ELF class (32 or 64), which selects the dynamic symbol entry layout.
func ReadElfSymbolVersions(verneed, versym, dynsym, dynstr []byte, bits int) []ElfSymbolVersion {
	if len(verneed) == 0 || len(versym) == 0 || len(dynsym) == 0 || len(dynstr) == 0 {
		return nil
	}
	var stride, shndxAt int
	switch bits {
	case 32:
		stride, shndxAt = 16, 14 // Elf32_Sym: name, value, size, info, other, shndx.
	case 64:
		stride, shndxAt = 24, 6 // Elf64_Sym: name, info, other, shndx, value, size.
	default:
		return nil
	}

	// vn_other in each Vernaux is the version index used by Versym entries.
	versions := make(map[uint16]ElfSymbolVersion)
	pos := uint64(0)
	for n := 0; n < maxVerneedEntries; n++ {
		count, ok := elfU16At(verneed, pos+2)
		if !ok {
			break // Truncated header: keep whatever earlier records yielded.
		}
		file, ok := elfU32At(verneed, pos+4)
		if !ok {
			break
		}
		aux, ok := elfU32At(verneed, pos+8)
		if !ok {
			break
		}
		next, ok := elfU32At(verneed, pos+12)
		if !ok {
			break
		}
		library := elfStringAt(dynstr, file)
		auxPos := pos + uint64(aux)
		for i := 0; i < min(int(count), maxVernauxEntries); i++ {
			other, ok := elfU16At(verneed, auxPos+6)
			if !ok {
				break // Truncated auxiliary record: stop this chain only.
			}
			nameOff, ok := elfU32At(verneed, auxPos+8)
			if !ok {
				break
			}
			auxNext, ok := elfU32At(verneed, auxPos+12)
			if !ok {
				break
			}
			name := elfStringAt(dynstr, nameOff)
			if name != "" && other > 1 {
				versions[other] = ElfSymbolVersion{Version: name, Library: library}
			}
			if auxNext == 0 {
				break
			}
			auxPos += uint64(auxNext)
		}
		if next == 0 {
			break
		}
		pos += uint64(next)
	}

	var out []ElfSymbolVersion
	symbols := min(uint64(len(versym))/2, uint64(len(dynsym))/uint64(stride))
	for i := uint64(0); i < symbols; i++ {
		raw, ok := elfU16At(versym, i*2)
		if !ok {
			break
		}
		index := raw & 0x7fff // The high bit marks a hidden version, not an index.
		if index <= 1 {
			continue // 0 is local, 1 is the global base: neither is a requirement.
		}
		base := i * uint64(stride)
		shndx, ok := elfU16At(dynsym, base+uint64(shndxAt))
		if !ok || shndx != 0 {
			continue // Only undefined symbols need a version from another object.
		}
		nameOff, ok := elfU32At(dynsym, base)
		if !ok {
			continue
		}
		name := elfStringAt(dynstr, nameOff)
		version, ok := versions[index]
		if !ok || name == "" || version.Version == "" {
			continue
		}
		out = append(out, ElfSymbolVersion{Name: name, Version: version.Version, Library: version.Library})
	}
	return out
}

// ReadDebugLink parses a .gnu_debuglink section: a NUL-terminated filename,
// padded to a 4-byte boundary, followed by a little-endian u32 CRC.
func ReadDebugLink(section []byte) (DebugLink, bool) {
	nul := bytes.IndexByte(section, 0)
	if nul <= 0 {
		return DebugLink{}, false
	}
	crcAt := (uint64(nul) + 4) &^ uint64(3)
	crc, ok := elfU32At(section, crcAt)
	if !ok {
		return DebugLink{}, false
	}
	return DebugLink{Name: string(section[:nul]), CRC: crc}, true
}

func elfU16At(b []byte, off uint64) (uint16, bool) {
	if off > uint64(len(b)) || uint64(len(b))-off < 2 {
		return 0, false
	}
	return binary.LittleEndian.Uint16(b[off : off+2]), true
}

func elfU32At(b []byte, off uint64) (uint32, bool) {
	if off > uint64(len(b)) || uint64(len(b))-off < 4 {
		return 0, false
	}
	return binary.LittleEndian.Uint32(b[off : off+4]), true
}

func elfStringAt(table []byte, off uint32) string {
	start := uint64(off)
	if start >= uint64(len(table)) {
		return ""
	}
	end := bytes.IndexByte(table[start:], 0)
	if end < 0 {
		return ""
	}
	return string(table[start : start+uint64(end)])
}
