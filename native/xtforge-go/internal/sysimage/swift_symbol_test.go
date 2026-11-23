package sysimage

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A hand-built 64-bit Mach-O whose symbol table holds one defined mangled
// Swift name and one ordinary C name. No toolchain is needed to produce it:
// the file is a header, a __TEXT segment with one executable section, and an
// LC_SYMTAB command pointing at nlist_64 entries and a string table.

const swiftSymbolFixtureName = "_$s10Foundation10CocoaErrorV4CodeV16fileReadTooLargeAEvgZ"

func machoSwiftSymbolFixture(swiftName string) []byte {
	const (
		textAddr    = 0x100000000
		codeAddr    = textAddr + 0x100
		plainAddr   = textAddr + 0x140
		fileSize    = 0x400
		segmentSize = 72 + 80 // LC_SEGMENT_64 with one section_64
		segmentAt   = 32
		symtabAt    = segmentAt + segmentSize
		symoff      = 0x300
		stroff      = 0x340
	)
	data := make([]byte, fileSize)
	put32 := func(offset int, value uint32) { binary.LittleEndian.PutUint32(data[offset:], value) }
	put64 := func(offset int, value uint64) { binary.LittleEndian.PutUint64(data[offset:], value) }

	// mach_header_64: MH_MAGIC_64, x86_64, MH_EXECUTE, two load commands.
	copy(data, []byte{0xcf, 0xfa, 0xed, 0xfe})
	put32(4, 0x0100000c) // CPU_TYPE_X86_64
	put32(12, 2)         // MH_EXECUTE
	put32(16, 2)         // ncmds
	put32(20, segmentSize+24)

	put32(segmentAt, 0x19) // LC_SEGMENT_64
	put32(segmentAt+4, segmentSize)
	copy(data[segmentAt+8:], "__TEXT")
	put64(segmentAt+24, textAddr)
	put64(segmentAt+32, fileSize)
	put64(segmentAt+40, 0)
	put64(segmentAt+48, fileSize)
	put32(segmentAt+56, 5) // maxprot
	put32(segmentAt+60, 5) // initprot
	put32(segmentAt+64, 1) // nsects

	sectionAt := segmentAt + 72
	copy(data[sectionAt:], "__text")
	copy(data[sectionAt+16:], "__TEXT")
	put64(sectionAt+32, codeAddr)
	put64(sectionAt+40, 0x100)
	put32(sectionAt+48, 0x100)      // file offset of the section
	put32(sectionAt+52, 2)          // alignment
	put32(sectionAt+64, 0x80000400) // S_ATTR_PURE_INSTRUCTIONS

	put32(symtabAt, 0x2) // LC_SYMTAB
	put32(symtabAt+4, 24)
	put32(symtabAt+8, symoff)
	put32(symtabAt+12, 2) // nsyms
	put32(symtabAt+16, stroff)

	var strtab bytes.Buffer
	strtab.WriteByte(0)
	swiftNameIndex := strtab.Len()
	strtab.WriteString(swiftName)
	strtab.WriteByte(0)
	plainNameIndex := strtab.Len()
	strtab.WriteString("plain_c_function")
	strtab.WriteByte(0)
	copy(data[stroff:], strtab.Bytes())
	put32(symtabAt+20, uint32(strtab.Len()))

	// nlist_64: strx, type N_SECT, sect 1, desc, value.
	writeSym := func(at, nameIndex int, value uint64) {
		put32(at, uint32(nameIndex))
		data[at+4] = 0x0e // N_SECT: a defined symbol in section 1
		data[at+5] = 1
		binary.LittleEndian.PutUint16(data[at+6:], 0)
		put64(at+8, value)
	}
	writeSym(symoff, swiftNameIndex, codeAddr)
	writeSym(symoff+16, plainNameIndex, plainAddr)
	return data
}

func TestMachOSwiftSymbolGetsDemangledName(t *testing.T) {
	path := filepath.Join(t.TempDir(), "SwiftFixture")
	if err := os.WriteFile(path, machoSwiftSymbolFixture(swiftSymbolFixtureName), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := Functions(path, "", "", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Images) != 1 {
		t.Fatalf("images = %d, want 1", len(res.Images))
	}
	functions := res.Images[0].Functions
	if len(functions) != 2 {
		t.Fatalf("functions = %d, want 2: %+v", len(functions), functions)
	}
	var swift, plain *Function
	for i := range functions {
		switch {
		case functions[i].Address == 0x100000100:
			swift = &functions[i]
		case functions[i].Address == 0x100000140:
			plain = &functions[i]
		}
	}
	if swift == nil || plain == nil {
		t.Fatalf("expected both symbol addresses in the index: %+v", functions)
	}
	want := DemangleSwift(swiftSymbolFixtureName)
	if want == "" {
		t.Fatal("fixture symbol is not demangleable")
	}
	if swift.Name != want {
		t.Errorf("Swift symbol name = %q, want %q", swift.Name, want)
	}
	if strings.Contains(swift.Name, "$s") {
		t.Errorf("raw Swift mangling leaked into function name: %q", swift.Name)
	}
	if swift.Source != "macho_swift_symbol" || swift.NameSource != "macho_swift_symbol" {
		t.Errorf("Swift symbol sources = (%q, %q), want macho_swift_symbol for both", swift.Source, swift.NameSource)
	}
	if plain.Name != "plain_c_function" || plain.Source != "macho_code_symbol" {
		t.Errorf("ordinary symbol = %+v, want its raw name and macho_code_symbol source", plain)
	}
}
