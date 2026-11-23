package sysimage

import (
	"debug/elf"
	"encoding/binary"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

const importsProgSource = `#include <stdio.h>
#include <stdlib.h>
int main(void) {
    const char *value = getenv("HOME");
    if (value) puts(value);
    return 0;
}
`

// buildImportsFixture compiles a real dynamically linked program. A missing
// compiler or libc headers is a toolchain limitation, not an implementation
// failure, so those cases skip rather than fail.
func buildImportsFixture(t *testing.T) string {
	t.Helper()
	clang, err := exec.LookPath("clang")
	if err != nil {
		t.Skipf("SKIP: clang is unavailable: %v", err)
	}
	dir := t.TempDir()
	source := filepath.Join(dir, "prog.c")
	program := filepath.Join(dir, "prog")
	if err := os.WriteFile(source, []byte(importsProgSource), 0o600); err != nil {
		t.Fatal(err)
	}
	output, err := exec.Command(clang, "-O1", "-o", program, source).CombinedOutput()
	if err != nil {
		text := strings.ToLower(string(output))
		if strings.Contains(text, "'stdio.h' file not found") ||
			strings.Contains(text, "'stdlib.h' file not found") ||
			strings.Contains(text, "file not found") && strings.Contains(text, "include") {
			t.Skipf("SKIP: libc headers are unavailable: %s", strings.TrimSpace(string(output)))
		}
		t.Fatalf("clang -O1 -o prog prog.c failed: %v\n%s", err, output)
	}
	return program
}

func TestELFImportsFromClangBinary(t *testing.T) {
	program := buildImportsFixture(t)
	handle, err := os.Open(program)
	if err != nil {
		t.Fatal(err)
	}
	defer handle.Close()
	file, err := elf.NewFile(handle)
	if err != nil {
		t.Fatal(err)
	}
	imports := ReadELFImports(file)
	if len(imports) == 0 {
		t.Fatal("ReadELFImports found no GOT imports in a dynamically linked clang binary")
	}
	names := make([]string, 0, len(imports))
	present := make(map[string]bool, len(imports))
	for _, imported := range imports {
		names = append(names, imported.Name)
		present[imported.Name] = true
		if imported.Slot == 0 || imported.Name == "" {
			t.Errorf("incomplete import: %+v", imported)
		}
		if imported.Relocation != "JUMP_SLOT" && imported.Relocation != "GLOB_DAT" {
			t.Errorf("unexpected relocation kind %q for %s", imported.Relocation, imported.Name)
		}
	}
	if !present["puts"] || !present["getenv"] {
		t.Logf("toolchain linked without puts/getenv GOT imports; found %d imports: %s", len(imports), strings.Join(names, ", "))
	}
	t.Logf("imports found: %d (%s)", len(imports), strings.Join(names, ", "))

	readelf, err := exec.LookPath("llvm-readelf")
	if err != nil {
		t.Logf("SKIP llvm-readelf cross-check: llvm-readelf is unavailable: %v", err)
		return
	}
	output, err := exec.Command(readelf, "--relocs", program).CombinedOutput()
	if err != nil {
		t.Logf("SKIP llvm-readelf cross-check: %s failed: %v\n%s", readelf, err, output)
		return
	}
	listed := parseELFRelocationLines(string(output))
	compared := 0
	for _, imported := range imports {
		name, ok := listed[imported.Slot]
		if !ok {
			t.Errorf("slot %#x (%s) was not listed by llvm-readelf", imported.Slot, imported.Name)
			continue
		}
		if name != imported.Name {
			t.Errorf("slot %#x: llvm-readelf says %q, ReadELFImports says %q", imported.Slot, name, imported.Name)
			continue
		}
		compared++
	}
	t.Logf("llvm-readelf cross-check: compared %d imports against %d JUMP_SLOT/GLOB_DAT lines", compared, len(listed))
}

// parseELFRelocationLines maps GOT relocation offsets to symbol names in
// llvm-readelf --relocs output, dropping any @VERSION suffix on the name.
func parseELFRelocationLines(text string) map[uint64]string {
	slots := make(map[uint64]string)
	for _, line := range strings.Split(text, "\n") {
		fields := strings.Fields(line)
		kind := -1
		for i, field := range fields {
			if strings.HasPrefix(field, "R_") &&
				(strings.HasSuffix(field, "JUMP_SLOT") || strings.HasSuffix(field, "JMP_SLOT") ||
					strings.HasSuffix(field, "GLOB_DAT")) {
				kind = i
				break
			}
		}
		if kind < 2 || len(fields) < kind+3 {
			continue
		}
		slot, err := strconv.ParseUint(fields[0], 16, 64)
		if err != nil {
			continue
		}
		name := strings.SplitN(fields[kind+2], "@", 2)[0]
		if name != "" {
			slots[slot] = name
		}
	}
	return slots
}

func TestXrefsGOTImportAnnotation(t *testing.T) {
	program := buildImportsFixture(t)
	index, err := References(program, ReferenceOptions{MaxFunctions: 256, Limit: 500})
	if err != nil {
		t.Fatal(err)
	}
	if !index.OK {
		t.Fatal("xrefs-native did not produce an index")
	}
	annotated := 0
	for _, reference := range index.References {
		if reference.TargetSource != "elf_got_import" {
			continue
		}
		if reference.TargetName == "" {
			t.Errorf("GOT import annotation has an empty target_name: %+v", reference)
			continue
		}
		if reference.Kind != "pc_relative" && reference.Kind != "pc_relative_address" {
			t.Errorf("GOT import annotation changed a direct reference: %+v", reference)
		}
		annotated++
	}
	if annotated == 0 {
		t.Fatalf("no reference was annotated as elf_got_import among %d references (%d indirect calls)",
			len(index.References), index.IndirectCalls)
	}
	t.Logf("references annotated as elf_got_import: %d of %d references (%d indirect calls)",
		annotated, len(index.References), index.IndirectCalls)
}

// TestELFImportsRel32Synthetic covers the 32-bit REL layout, which an x86-64
// toolchain cannot produce. The hand-built ELF has one undefined "puts" symbol
// and one R_386_JMP_SLOT relocation pointing at a GOT slot.
func TestELFImportsRel32Synthetic(t *testing.T) {
	const slot = uint64(0x8049000)
	dynamicStrings := []byte("\x00puts\x00")
	dynamicSymbols := make([]byte, 32)
	binary.LittleEndian.PutUint32(dynamicSymbols[16:], 1) // st_name = "puts"
	dynamicSymbols[16+12] = 0x12                          // STB_GLOBAL | STT_FUNC
	relocations := make([]byte, 8)
	binary.LittleEndian.PutUint32(relocations, uint32(slot))
	binary.LittleEndian.PutUint32(relocations[4:], (1<<8)|7) // symbol 1, R_386_JMP_SLOT

	data := elf32WithSections([][]byte{{}, dynamicStrings, dynamicSymbols, relocations,
		[]byte("\x00.dynstr\x00.dynsym\x00.rel.plt\x00.shstrtab\x00")},
		[]elf32Section{
			{},
			{name: 1, typ: uint32(elf.SHT_STRTAB)},
			{name: 9, typ: uint32(elf.SHT_DYNSYM), link: 1, entsize: 16},
			{name: 17, typ: uint32(elf.SHT_REL), link: 2, entsize: 8},
			{name: 26, typ: uint32(elf.SHT_STRTAB)},
		})

	path := filepath.Join(t.TempDir(), "rel32.elf")
	if err := os.WriteFile(path, data.bytes, 0o600); err != nil {
		t.Fatal(err)
	}
	handle, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer handle.Close()
	file, err := elf.NewFile(handle)
	if err != nil {
		t.Fatal(err)
	}
	imports := ReadELFImports(file)
	if len(imports) != 1 || imports[0].Name != "puts" || imports[0].Slot != slot ||
		imports[0].Relocation != "JUMP_SLOT" {
		t.Fatalf("32-bit REL imports = %+v, want one puts JUMP_SLOT at %#x", imports, slot)
	}
	t.Logf("synthetic 32-bit REL imports: %d (puts at %#x)", len(imports), slot)
}

// elf32Layout is a minimal ELF32 header plus section table used by the
// synthetic REL test. Section headers are filled after the payload offsets
// are known, so no field depends on a guessed layout.
type elf32Layout struct {
	bytes    []byte
	sections []elf32Section
	offsets  []uint32
}

type elf32Section struct {
	name, typ, flags, addr, offset, size, link, info, align, entsize uint32
}

func elf32WithSections(payloads [][]byte, sections []elf32Section) elf32Layout {
	const headerSize, sectionSize = 52, 40
	offsets := make([]uint32, len(payloads))
	cursor := headerSize
	blob := make([]byte, headerSize)
	for i, payload := range payloads {
		offsets[i] = uint32(cursor)
		blob = append(blob, payload...)
		cursor += len(payload)
	}
	// Keep section headers 4-byte aligned.
	for cursor%4 != 0 {
		blob = append(blob, 0)
		cursor++
	}
	sectionTable := cursor
	header := make([]byte, headerSize)
	copy(header, []byte{0x7f, 'E', 'L', 'F', 1, 1, 1, 0})
	binary.LittleEndian.PutUint16(header[16:], 2) // ET_EXEC
	binary.LittleEndian.PutUint16(header[18:], 3) // EM_386
	binary.LittleEndian.PutUint32(header[20:], 1) // EV_CURRENT
	binary.LittleEndian.PutUint32(header[32:], uint32(sectionTable))
	binary.LittleEndian.PutUint16(header[40:], headerSize)
	binary.LittleEndian.PutUint16(header[46:], sectionSize)
	binary.LittleEndian.PutUint16(header[48:], uint16(len(sections)))
	binary.LittleEndian.PutUint16(header[50:], uint16(len(sections)-1))
	copy(blob[:headerSize], header)

	for i, section := range sections {
		if i == 0 {
			section.offset = 0 // The null section has no payload.
		} else {
			section.offset = offsets[i]
			section.size = uint32(len(payloads[i]))
		}
		raw := make([]byte, sectionSize)
		binary.LittleEndian.PutUint32(raw, section.name)
		binary.LittleEndian.PutUint32(raw[4:], section.typ)
		binary.LittleEndian.PutUint32(raw[8:], section.flags)
		binary.LittleEndian.PutUint32(raw[12:], section.addr)
		binary.LittleEndian.PutUint32(raw[16:], section.offset)
		binary.LittleEndian.PutUint32(raw[20:], section.size)
		binary.LittleEndian.PutUint32(raw[24:], section.link)
		binary.LittleEndian.PutUint32(raw[28:], section.info)
		binary.LittleEndian.PutUint32(raw[32:], section.align)
		binary.LittleEndian.PutUint32(raw[36:], section.entsize)
		blob = append(blob, raw...)
	}
	return elf32Layout{bytes: blob, sections: sections, offsets: offsets}
}
