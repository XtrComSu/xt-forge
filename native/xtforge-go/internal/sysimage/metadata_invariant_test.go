package sysimage

import (
	"debug/pe"
	"encoding/binary"
	"os"
	"testing"
)

// This file guards the naming rule the package documents but did not assert:
// reconstructed metadata (ObjC method pointers, DWARF rows) may only NAME
// addresses already in the function index, never ADD function starts. PE
// exports are the documented exception, because the binary itself declares
// them as callable entry points; the last test pins that contrast down.

// TestObjCDoesNotAddFunctionStarts corrupts the fixture's method implementation
// pointer so it names an address that is not in the function index. The class
// and selector must still be recovered, but no phantom function may appear.
func TestObjCDoesNotAddFunctionStarts(t *testing.T) {
	// In the absolute-form fixture the implementation pointer of the single
	// method lives at file offset 0x738 (method list at 0x720 + 8 header + 16).
	// 0x100000800 is a different, file-backed address inside __TEXT, so a
	// future change that used addFunction here would visibly add a function.
	const (
		implOffset = 0x738
		bogusImpl  = uint64(0x100000800)
	)

	run := func(data []byte) FunctionIndex {
		t.Helper()
		path := t.TempDir() + "/Fixture"
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		res, err := Functions(path, "", "", 0)
		if err != nil {
			t.Fatal(err)
		}
		if len(res.Images) != 1 {
			t.Fatalf("images = %d, want 1", len(res.Images))
		}
		return res.Images[0]
	}

	corrupt := objcFixture(false)
	binary.LittleEndian.PutUint64(corrupt[implOffset:implOffset+8], bogusImpl)
	index := run(corrupt)

	meta := index.ObjC
	if meta == nil {
		t.Fatal("no Objective-C metadata recovered")
	}
	recovered := false
	for _, class := range meta.Classes {
		if class.Name == "FixtureClass" {
			recovered = true
		}
	}
	if !recovered {
		t.Fatalf("FixtureClass not recovered after corrupting its method pointer: %+v", meta.Classes)
	}
	for _, fn := range index.Functions {
		if fn.Address == bogusImpl {
			t.Fatalf("ObjC method pointer added a function at %#x: %+v", bogusImpl, fn)
		}
	}

	// Strip baseMethods (class_ro_t+32 lives at file offset 0x3070): the class
	// still decodes, but there are no method pointers to act on. Both fixtures
	// must therefore report the same function count.
	stripped := objcFixture(false)
	for offset := 0x3070; offset < 0x3078; offset++ {
		stripped[offset] = 0
	}
	baseline := run(stripped)
	if index.Total != baseline.Total {
		t.Fatalf("function total with method pointers = %d, stripped = %d", index.Total, baseline.Total)
	}
	if len(index.Functions) != len(baseline.Functions) {
		t.Fatalf("function list with method pointers = %d, stripped = %d", len(index.Functions), len(baseline.Functions))
	}
}

// TestDWARFDoesNotAddFunctionStarts applies hand-built DWARF rows to a populated
// image: a LowPC no function occupies must stay empty, and an inverted HighPC
// must not wrap into an enormous size on an existing function.
func TestDWARFDoesNotAddFunctionStarts(t *testing.T) {
	const (
		known = uint64(0x100000000)
		bogus = uint64(0x100001000)
	)
	image := &Image{functions: map[uint64]Function{
		known: {Address: known, Size: 32, Source: "elf_dynsym"},
	}}
	meta := &dwarfMetadata{Functions: []dwarfSubprogram{
		{Name: "phantom", LowPC: bogus, HighPC: bogus + 16},
	}}
	image.applyDWARF(meta)
	if len(image.functions) != 1 {
		t.Fatalf("functions after DWARF row = %d, want 1: %+v", len(image.functions), image.functions)
	}
	if _, exists := image.functions[bogus]; exists {
		t.Fatalf("DWARF row added a function at %#x", bogus)
	}

	// A HighPC below the LowPC is not a size; the existing size must survive.
	meta = &dwarfMetadata{Functions: []dwarfSubprogram{
		{Name: "inverted", LowPC: known, HighPC: known - 4},
	}}
	image.applyDWARF(meta)
	if fn := image.functions[known]; fn.Size != 32 {
		t.Fatalf("size after inverted HighPC = %d, want 32", fn.Size)
	}
	if len(image.functions) != 1 {
		t.Fatalf("functions after inverted HighPC = %d, want 1", len(image.functions))
	}
}

// TestApplyObjCDoesNotOverwriteExistingNames checks that an exact symbol name,
// and the source that produced it, win over a reconstructed Objective-C name.
func TestApplyObjCDoesNotOverwriteExistingNames(t *testing.T) {
	const address = uint64(0x100000800)
	image := &Image{functions: map[uint64]Function{
		address: {
			Address:    address,
			Name:       "_real_symbol",
			Source:     "macho_code_symbol",
			NameSource: "macho_code_symbol",
		},
	}}
	// Cover both the class-method and category-method loops in applyObjC.
	meta := &objcMetadata{
		Classes: []objcClass{{
			Name:    "FixtureClass",
			Methods: []objcMethod{{Name: "doThing:", Implementation: address}},
		}},
		Categories: []objcCategory{{
			Name:    "Fixture",
			Class:   "FixtureClass",
			Methods: []objcMethod{{Name: "categoryThing", Implementation: address}},
		}},
	}
	image.applyObjC(meta, "-")
	fn := image.functions[address]
	if fn.Name != "_real_symbol" {
		t.Fatalf("name = %q, want %q", fn.Name, "_real_symbol")
	}
	if fn.NameSource != "macho_code_symbol" {
		t.Fatalf("name source = %q, want %q", fn.NameSource, "macho_code_symbol")
	}
	if fn.Source != "macho_code_symbol" {
		t.Fatalf("function source = %q, want %q", fn.Source, "macho_code_symbol")
	}
	if meta.Named != 0 {
		t.Fatalf("ObjC reports %d names written, want 0", meta.Named)
	}
}

// TestPEExportsMayAddFunctionStarts pins the exception: namePEExports runs on an
// empty index and the export must become a function sourced from "pe_export".
func TestPEExportsMayAddFunctionStarts(t *testing.T) {
	handle, err := os.Open(buildPEWithExport(t))
	if err != nil {
		t.Fatal(err)
	}
	defer handle.Close()
	file, err := pe.NewFile(handle)
	if err != nil {
		t.Fatal(err)
	}
	header, ok := file.OptionalHeader.(*pe.OptionalHeader64)
	if !ok {
		t.Fatalf("optional header is %T, want *pe.OptionalHeader64", file.OptionalHeader)
	}
	directory := header.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_EXPORT]
	if directory.VirtualAddress == 0 || directory.Size == 0 {
		t.Fatal("built PE has no export directory")
	}
	base := header.ImageBase

	// Map the PE's sections into an Image so addFunction can resolve the
	// exported address to a file offset; the function index starts empty.
	image := &Image{}
	for _, section := range file.Sections {
		image.Sections = append(image.Sections, Region{
			Name:     section.Name,
			Address:  base + uint64(section.VirtualAddress),
			Size:     max(uint64(section.VirtualSize), uint64(section.Size)),
			Offset:   uint64(section.Offset),
			FileSize: uint64(section.Size),
		})
	}
	if len(image.functions) != 0 {
		t.Fatalf("function index is not empty: %+v", image.functions)
	}

	namePEExports(image, file, directory, base)

	var exported Function
	found := false
	for _, fn := range image.functions {
		if fn.Name == "helper_add" {
			exported, found = fn, true
			break
		}
	}
	if !found {
		t.Fatalf("export did not become a function: %+v", image.functions)
	}
	if exported.Source != "pe_export" {
		t.Errorf("exported function source = %q, want %q", exported.Source, "pe_export")
	}
	if exported.NameSource != "pe_export" {
		t.Errorf("exported function name source = %q, want %q", exported.NameSource, "pe_export")
	}
}
