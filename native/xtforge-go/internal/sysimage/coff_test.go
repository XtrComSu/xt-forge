package sysimage

import (
	"bytes"
	"encoding/binary"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// clangCOFFObject compiles a small Windows object with two functions and a
// static variable. clang's section symbols carry AUXILIARY records, followed by
// the named symbols we assert on below.
func clangCOFFObject(t *testing.T) []byte {
	t.Helper()
	clang, err := exec.LookPath("clang")
	if err != nil {
		t.Skip("clang is not installed; skipping the real COFF object test")
	}
	dir := t.TempDir()
	sourcePath := filepath.Join(dir, "object.c")
	objectPath := filepath.Join(dir, "object.obj")
	source := `static int counter = 7;
int alpha(int x) { return x + counter; }
int beta(int x) { return x * 2 - counter; }
`
	if err := os.WriteFile(sourcePath, []byte(source), 0o600); err != nil {
		t.Fatalf("write C source: %v", err)
	}
	command := exec.Command(clang, "-target", "x86_64-pc-windows-msvc", "-c", sourcePath, "-o", objectPath)
	if output, err := command.CombinedOutput(); err != nil {
		t.Skipf("clang cannot produce an x86_64 Windows COFF object here: %v\n%s", err, output)
	}
	data, err := os.ReadFile(objectPath)
	if err != nil {
		t.Fatalf("read COFF object: %v", err)
	}
	return data
}

func TestIsCOFF(t *testing.T) {
	object := clangCOFFObject(t)
	if !IsCOFF(object[:18]) {
		t.Fatal("IsCOFF = false for a real x86_64 COFF object")
	}

	// A real PE starts with MZ and carries a PE signature and optional header.
	pe := make([]byte, 128)
	copy(pe, "MZ")
	binary.LittleEndian.PutUint32(pe[0x3c:], 0x40)
	copy(pe[0x40:], "PE\x00\x00")
	binary.LittleEndian.PutUint16(pe[0x44:], 0x8664)
	binary.LittleEndian.PutUint16(pe[0x44+16:], 0x00f0)
	if IsCOFF(pe) {
		t.Fatal("IsCOFF = true for a PE executable")
	}
	// Strip the DOS stub: the COFF machine is still there, but a non-zero
	// SizeOfOptionalHeader is exactly what marks the header as an image.
	if IsCOFF(pe[0x44:]) {
		t.Fatal("IsCOFF = true for a PE COFF header with an optional header")
	}
	if IsCOFF(object[:2]) {
		t.Fatal("IsCOFF = true for a header shorter than 18 bytes")
	}
	for seed := int64(0); seed < 8; seed++ {
		noise := make([]byte, 128)
		if _, err := rand.New(rand.NewSource(seed)).Read(noise); err != nil {
			t.Fatalf("fill random bytes: %v", err)
		}
		if IsCOFF(noise) {
			t.Fatalf("IsCOFF = true for random bytes (seed %d)", seed)
		}
	}
}

func TestReadCOFF(t *testing.T) {
	data := clangCOFFObject(t)
	object, err := ReadCOFF(bytes.NewReader(data), int64(len(data)), 0)
	if err != nil {
		t.Fatalf("ReadCOFF: %v", err)
	}
	if object.Machine != 0x8664 || object.MachineName != "x86-64" {
		t.Fatalf("machine = %#x (%s), want 0x8664 (x86-64)", object.Machine, object.MachineName)
	}
	if len(object.Sections) < 2 {
		t.Fatalf("len(Sections) = %d, want at least 2", len(object.Sections))
	}
	names := make(map[string]bool)
	for _, section := range object.Sections {
		names[section.Name] = true
		if section.Name == ".text" && !section.Executable {
			t.Error(".text section is not marked executable")
		}
	}
	for _, want := range []string{".text", ".data"} {
		if !names[want] {
			t.Errorf("section %q is missing", want)
		}
	}

	symbols := make(map[string]COFFSymbol)
	for _, symbol := range object.Symbols {
		symbols[symbol.Name] = symbol
	}
	for _, name := range []string{"alpha", "beta", "counter"} {
		if _, ok := symbols[name]; !ok {
			t.Errorf("symbol %q is missing (AUX records skipped incorrectly?)", name)
		}
	}
	// counter follows several AUX-bearing section symbols in the real object;
	// finding it with the correct storage class proves the records were skipped
	// by 18 * (1 + aux) rather than read as ordinary symbols.
	if counter, ok := symbols["counter"]; ok && counter.StorageClass != 3 {
		t.Errorf("counter storage class = %d, want 3 (static)", counter.StorageClass)
	}
	if alpha, ok := symbols["alpha"]; ok && (alpha.Section != 1 || alpha.StorageClass != 2) {
		t.Errorf("alpha = (section %d, class %d), want (1, 2)", alpha.Section, alpha.StorageClass)
	}
	if beta, ok := symbols["beta"]; ok && (beta.Section != 1 || beta.StorageClass != 2) {
		t.Errorf("beta = (section %d, class %d), want (1, 2)", beta.Section, beta.StorageClass)
	}
}

// syntheticCOFF builds an object with a long section name, a long symbol name,
// and an AUX record between two symbols whose values identify them.
func syntheticCOFF(t *testing.T) []byte {
	t.Helper()
	const (
		numSymbols = 4 // primary, AUX, primary, primary
		symOffset  = 20 + 40
	)
	table := make([]byte, 4)
	sectionNameOffset := uint32(len(table))
	table = append(table, []byte(".longsection")...)
	table = append(table, 0)
	symbolNameOffset := uint32(len(table))
	table = append(table, []byte("long_symbol_name")...)
	table = append(table, 0)
	binary.LittleEndian.PutUint32(table[:4], uint32(len(table)))

	buf := make([]byte, 0, symOffset+numSymbols*18+len(table))
	header := make([]byte, 20)
	binary.LittleEndian.PutUint16(header[0:2], 0x8664)
	binary.LittleEndian.PutUint16(header[2:4], 1)
	binary.LittleEndian.PutUint32(header[4:8], 0x12345678)
	binary.LittleEndian.PutUint32(header[8:12], symOffset)
	binary.LittleEndian.PutUint32(header[12:16], numSymbols)
	binary.LittleEndian.PutUint16(header[16:18], 0)
	buf = append(buf, header...)

	section := make([]byte, 40)
	binary.LittleEndian.PutUint64(section[0:8], uint64(sectionNameOffset))
	binary.LittleEndian.PutUint32(section[16:20], 0x10)
	binary.LittleEndian.PutUint32(section[20:24], 0x100)
	binary.LittleEndian.PutUint32(section[36:40], 0x60000020)
	buf = append(buf, section...)

	first := make([]byte, 18)
	copy(first, ".text")
	first[16], first[17] = 3, 1
	buf = append(buf, first...)
	buf = append(buf, bytes.Repeat([]byte{0xaa}, 18)...) // AUX record

	longName := make([]byte, 18)
	binary.LittleEndian.PutUint32(longName[4:8], symbolNameOffset)
	binary.LittleEndian.PutUint32(longName[8:12], 0x1234)
	binary.LittleEndian.PutUint16(longName[12:14], 1)
	binary.LittleEndian.PutUint16(longName[14:16], 0x20)
	longName[16] = 2
	buf = append(buf, longName...)

	afterAux := make([]byte, 18)
	copy(afterAux, "afteraux") // COFF names fit in eight bytes
	binary.LittleEndian.PutUint32(afterAux[8:12], 0x5678)
	binary.LittleEndian.PutUint16(afterAux[12:14], 1)
	afterAux[16] = 2
	buf = append(buf, afterAux...)
	return append(buf, table...)
}

func TestReadCOFFSynthetic(t *testing.T) {
	data := syntheticCOFF(t)
	object, err := ReadCOFF(bytes.NewReader(data), int64(len(data)), 0)
	if err != nil {
		t.Fatalf("ReadCOFF: %v", err)
	}
	if object.TimeDateStamp != 0x12345678 {
		t.Errorf("TimeDateStamp = %#x, want 0x12345678", object.TimeDateStamp)
	}
	if len(object.Sections) != 1 {
		t.Fatalf("len(Sections) = %d, want 1", len(object.Sections))
	}
	section := object.Sections[0]
	if section.Name != ".longsection" || section.RawSize != 0x10 || section.RawOffset != 0x100 || !section.Executable {
		t.Errorf("section = %+v, want .longsection, raw 0x10@0x100, executable", section)
	}
	if len(object.Symbols) != 3 {
		t.Fatalf("len(Symbols) = %d, want 3 (AUX records are not symbols)", len(object.Symbols))
	}
	if got := object.Symbols[0]; got.Name != ".text" || got.StorageClass != 3 {
		t.Errorf("symbols[0] = %+v, want .text with static class", got)
	}
	if got := object.Symbols[1]; got.Name != "long_symbol_name" || got.Value != 0x1234 || got.Section != 1 || got.Type != 0x20 {
		t.Errorf("symbols[1] = %+v, want long_symbol_name at 0x1234 in section 1", got)
	}
	if got := object.Symbols[2]; got.Name != "afteraux" || got.Value != 0x5678 {
		t.Errorf("symbols[2] = %+v, want afteraux at 0x5678", got)
	}

	limited, err := ReadCOFF(bytes.NewReader(data), int64(len(data)), 1)
	if err != nil {
		t.Fatalf("ReadCOFF with limit 1: %v", err)
	}
	if len(limited.Symbols) != 1 {
		t.Errorf("len(Symbols) with limit 1 = %d, want 1", len(limited.Symbols))
	}
}

func TestCOFFOverview(t *testing.T) {
	data := clangCOFFObject(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "object.obj")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write COFF object: %v", err)
	}
	result, err := Overview(path, "")
	if err != nil {
		t.Fatalf("Overview: %v", err)
	}
	if result.Format != "coff" || len(result.Images) != 1 {
		t.Fatalf("format = %q, images = %d, want coff and one image", result.Format, len(result.Images))
	}
	image := result.Images[0]
	if image.COFF == nil || image.COFF.Machine != 0x8664 || image.EntryPoint != nil {
		t.Fatalf("image = %+v, want a COFF object without an entry point", image)
	}
	if len(image.functions) != 0 {
		t.Errorf("an unlinked object has %d functions, want none", len(image.functions))
	}
}

func TestReadCOFFMalformed(t *testing.T) {
	if _, err := ReadCOFF(nil, 20, 0); err == nil {
		t.Error("ReadCOFF(nil reader) did not fail")
	}
	if _, err := ReadCOFF(bytes.NewReader([]byte{0x64, 0x86, 0x00}), 3, 0); err == nil {
		t.Error("ReadCOFF with a truncated header did not fail")
	}

	// A declared symbol count of 0xffffffff must not drive billions of reads,
	// and an impossible section count must not allocate 65535 headers.
	cases := []struct {
		name   string
		header func() []byte
	}{
		{"huge symbol count", func() []byte {
			header := make([]byte, 20)
			binary.LittleEndian.PutUint16(header[0:2], 0x8664)
			binary.LittleEndian.PutUint32(header[8:12], 20)
			binary.LittleEndian.PutUint32(header[12:16], 0xffffffff)
			return header
		}},
		{"huge section count", func() []byte {
			header := make([]byte, 20)
			binary.LittleEndian.PutUint16(header[0:2], 0x8664)
			binary.LittleEndian.PutUint16(header[2:4], 0xffff)
			return header
		}},
		{"truncated symbol record", func() []byte {
			header := make([]byte, 20)
			binary.LittleEndian.PutUint16(header[0:2], 0x8664)
			binary.LittleEndian.PutUint32(header[8:12], 20)
			binary.LittleEndian.PutUint32(header[12:16], 1)
			return header
		}},
		{"PE optional header", func() []byte {
			header := make([]byte, 20)
			binary.LittleEndian.PutUint16(header[0:2], 0x8664)
			binary.LittleEndian.PutUint16(header[16:18], 0x00f0)
			return header
		}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			data := test.header()
			object, err := ReadCOFF(bytes.NewReader(data), int64(len(data)), 0)
			if err == nil && len(object.Symbols) != 0 {
				t.Errorf("ReadCOFF returned %d symbols without an error", len(object.Symbols))
			}
		})
	}
}
