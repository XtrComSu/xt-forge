package sysimage

import (
	"debug/elf"
	"encoding/binary"
	"sort"
)

// ELFImport is one imported symbol and the GOT slot that holds its address.
type ELFImport struct {
	Name       string `json:"name"`
	Slot       uint64 `json:"slot"` // virtual address of the GOT entry
	Library    string `json:"library,omitempty"`
	Relocation string `json:"relocation"` // "JUMP_SLOT" or "GLOB_DAT"
}

// Relocation types of the four native architectures whose code this package
// decodes. debug/elf does not export the R_* constants, so the values are
// named here instead of being repeated as bare numbers at the use site.
const (
	elfRelX8664GlobDat    = 6
	elfRelX8664JumpSlot   = 7
	elfRelAArch64GlobDat  = 1025
	elfRelAArch64JumpSlot = 1026
	elfRelArmGlobDat      = 21
	elfRelArmJumpSlot     = 22
	elfRel386GlobDat      = 6
	elfRel386JumpSlot     = 7
)

// elfImportRelocation reports whether a relocation type fills a GOT slot with
// an imported address, and returns the stable name used in the report.
func elfImportRelocation(machine elf.Machine, typ uint64) (string, bool) {
	switch machine {
	case elf.EM_X86_64:
		switch typ {
		case elfRelX8664JumpSlot:
			return "JUMP_SLOT", true
		case elfRelX8664GlobDat:
			return "GLOB_DAT", true
		}
	case elf.EM_AARCH64:
		switch typ {
		case elfRelAArch64JumpSlot:
			return "JUMP_SLOT", true
		case elfRelAArch64GlobDat:
			return "GLOB_DAT", true
		}
	case elf.EM_ARM:
		switch typ {
		case elfRelArmJumpSlot:
			return "JUMP_SLOT", true
		case elfRelArmGlobDat:
			return "GLOB_DAT", true
		}
	case elf.EM_386:
		switch typ {
		case elfRel386JumpSlot:
			return "JUMP_SLOT", true
		case elfRel386GlobDat:
			return "GLOB_DAT", true
		}
	}
	return "", false
}

// ReadELFImports returns imported symbols keyed by their GOT slot address.
// It reads .rela.plt (or .rel.plt) and .rela.dyn (or .rel.dyn), following the
// relocation's symbol index into .dynsym for the name. 64-bit entries carry a
// 64-bit offset/info pair (RELA); 32-bit entries carry a 32-bit pair (REL).
// Malformed or truncated sections yield no entry rather than a panic.
func ReadELFImports(file *elf.File) []ELFImport {
	if file == nil {
		return nil
	}
	order := file.ByteOrder
	if order == nil {
		order = binary.LittleEndian
	}
	word := 4 // Size of r_offset and r_info in this ELF class.
	symStride := 16
	bits := 32
	if file.Class == elf.ELFCLASS64 {
		word, symStride, bits = 8, 24, 64
	}

	dynsym := elfSectionBytes(file, ".dynsym")
	dynstr := elfSectionBytes(file, ".dynstr")
	if len(dynsym) < symStride || len(dynstr) == 0 {
		return nil
	}

	// Version requirements identify the library that supplies each versioned
	// name (for example puts@GLIBC_2.2.5 comes from libc.so.6).
	libraries := make(map[string]string)
	for _, version := range ReadElfSymbolVersions(
		elfSectionBytes(file, ".gnu.version_r"), elfSectionBytes(file, ".gnu.version"),
		dynsym, dynstr, bits) {
		if version.Name != "" && version.Library != "" {
			if _, exists := libraries[version.Name]; !exists {
				libraries[version.Name] = version.Library
			}
		}
	}

	bySlot := make(map[uint64]ELFImport)
	for _, sectionName := range []string{".rela.plt", ".rel.plt", ".rela.dyn", ".rel.dyn"} {
		section := file.Section(sectionName)
		if section == nil {
			continue
		}
		data, err := section.Data()
		if err != nil {
			continue
		}
		stride := 2 * word // Elf*_Rel: r_offset, r_info.
		if section.Type == elf.SHT_RELA {
			stride += word // Elf*_Rela also has r_addend, which is unused here.
		}
		if uint64(len(data)) < uint64(stride) {
			continue
		}
		for offset := uint64(0); offset+uint64(stride) <= uint64(len(data)); offset += uint64(stride) {
			slot, ok := elfWordAt(order, data, offset, word)
			if !ok {
				break
			}
			info, ok := elfWordAt(order, data, offset+uint64(word), word)
			if !ok {
				break
			}
			var symbolIndex, relocType uint64
			if word == 8 {
				symbolIndex, relocType = info>>32, info&0xffffffff
			} else {
				symbolIndex, relocType = info>>8, info&0xff
			}
			relocation, ok := elfImportRelocation(file.Machine, relocType)
			if !ok || symbolIndex == 0 {
				continue
			}
			nameOffset, ok := elfWordAt(order, dynsym, symbolIndex*uint64(symStride), 4)
			if !ok {
				continue
			}
			name := elfStringAt(dynstr, uint32(nameOffset))
			if name == "" {
				continue
			}
			imported := ELFImport{Name: name, Slot: slot, Library: libraries[name], Relocation: relocation}
			existing, seen := bySlot[slot]
			if !seen || (existing.Relocation == "GLOB_DAT" && relocation == "JUMP_SLOT") {
				bySlot[slot] = imported
			}
		}
	}
	if len(bySlot) == 0 {
		return nil
	}
	imports := make([]ELFImport, 0, len(bySlot))
	for _, imported := range bySlot {
		imports = append(imports, imported)
	}
	sort.Slice(imports, func(i, j int) bool { return imports[i].Slot < imports[j].Slot })
	return imports
}

// elfWordAt reads an unsigned 1-, 2-, 4-, or 8-byte field at a byte offset,
// checking both the offset and the width before indexing the slice.
func elfWordAt(order binary.ByteOrder, data []byte, offset uint64, size int) (uint64, bool) {
	if size != 1 && size != 2 && size != 4 && size != 8 {
		return 0, false
	}
	if offset > uint64(len(data)) || uint64(len(data))-offset < uint64(size) {
		return 0, false
	}
	field := data[offset : offset+uint64(size)]
	switch size {
	case 1:
		return uint64(field[0]), true
	case 2:
		return uint64(order.Uint16(field)), true
	case 4:
		return uint64(order.Uint32(field)), true
	default:
		return order.Uint64(field), true
	}
}
