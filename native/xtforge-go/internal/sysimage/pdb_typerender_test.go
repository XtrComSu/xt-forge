package sysimage

import (
	"encoding/binary"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// LF_ARRAY / LF_MODIFIER rendering is checked against a real PDB built here and
// against llvm-pdbutil dump -types, plus synthetic records for the byte layouts.
// The raw bytes observed in the fixture (verified, body after the u16 length):
//
//	LF_ARRAY 0x1004 (`int a[4]`): 74 00 00 00 | 23 00 00 00 | 10 00 | 00 F1
//	  +0 elementType 0x0074 (int), +4 indexType 0x0023 (unsigned __int64),
//	  +8 NumericLeaf 0x0010 = 16, +10 empty name NUL and padding.
//	LF_MODIFIER 0x1005 (`const int`):    74 00 00 00 01 00 F2 F1
//	LF_MODIFIER 0x1007 (`volatile short`): 11 00 00 00 02 00 F2 F1
//	  +0 modifiedType u32, +4 modifier mask u16, then padding.
//
// llvm-pdbutil reported "size: 16, index type: 0x0023 (unsigned __int64),
// element type: 0x0074 (int)" and "modifiers = const"/"modifiers = volatile".

const typeRenderFixture = `
struct P { int a[4]; const int *p; volatile short v; };
int use(struct P *p, int arr[4]) { return arr[1] + *p->p + p->v; }
`

func buildTypeRenderPDB(t *testing.T, dir string) string {
	t.Helper()
	for _, tool := range []string{"clang", "lld-link"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not available", tool)
		}
	}
	// A plain array parameter decays to a pointer in C (clang emits 0x0674,
	// "int *"), so the fixture's LF_ARRAY only appears as a struct member; and
	// `const int *p` is a member too, not an argument. Add two functions whose
	// parameters are LF_POINTER -> LF_ARRAY and LF_POINTER -> LF_MODIFIER so
	// "int[4]" and "const" become observable in recovered signatures.
	code := typeRenderFixture + `
int take_array(int (*arr)[4]) { return (*arr)[1]; }
int read_const(const int *p) { return *p; }
int main(void) { return 0; }
`
	source := filepath.Join(dir, "typerender.c")
	if err := os.WriteFile(source, []byte(code), 0600); err != nil {
		t.Fatal(err)
	}
	obj := filepath.Join(dir, "typerender.obj")
	pdbPath := filepath.Join(dir, "typerender.pdb")
	exe := filepath.Join(dir, "typerender.exe")
	for _, step := range [][]string{
		{"clang", "-target", "x86_64-pc-windows-msvc", "-O0", "-g", "-gcodeview", "-c", source, "-o", obj},
		{"lld-link", "/entry:main", "/subsystem:console", "/nodefaultlib", "/debug",
			"/pdb:" + pdbPath, "/out:" + exe, obj},
	} {
		command := exec.Command(step[0], step[1:]...)
		if output, err := command.CombinedOutput(); err != nil {
			t.Skipf("%s failed: %v: %s", step[0], err, output)
		}
	}
	return pdbPath
}

func openRenderPDB(t *testing.T, path string) (*os.File, int64) {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { file.Close() })
	stat, err := file.Stat()
	if err != nil {
		t.Fatal(err)
	}
	return file, stat.Size()
}

func TestPDBTypeRenderRealPDB(t *testing.T) {
	pdbPath := buildTypeRenderPDB(t, t.TempDir())
	file, size := openRenderPDB(t, pdbPath)
	signatures, err := ReadPDBSignatures(file, size, 0)
	if err != nil {
		t.Fatalf("signatures: %v", err)
	}
	if len(signatures) == 0 {
		t.Fatal("no procedures decoded")
	}
	sawArray, sawConst := false, false
	for _, signature := range signatures {
		t.Logf("0x%x -> %s (args %v)", signature.Index, signature.Rendered, signature.Arguments)
		if signature.ReturnType == "" || signature.Rendered == "" {
			t.Errorf("signature 0x%x rendered an empty string: %+v", signature.Index, signature)
		}
		for _, argument := range signature.Arguments {
			if argument == "" {
				t.Errorf("signature 0x%x has an empty argument", signature.Index)
			}
			if strings.Contains(argument, "int[4]") {
				sawArray = true
			}
			if strings.Contains(argument, "const") && strings.Contains(argument, "*") {
				sawConst = true
			}
		}
	}
	if !sawArray {
		t.Error("no signature argument rendered int[4]")
	}
	if !sawConst {
		t.Error("no const-qualified pointer argument rendered with 'const'")
	}

	// Cross-check the raw LF_ARRAY / LF_MODIFIER bytes in this PDB against the
	// layout recorded above (independent of llvm-pdbutil's textual rendering).
	types, err := pdbLoadTypeStream(file, size)
	if err != nil {
		t.Fatalf("type stream: %v", err)
	}
	checked := 0
	for _, record := range types.records {
		switch record.leaf {
		case pdbLeafArray:
			if len(record.body) < 10 || binary.LittleEndian.Uint32(record.body[0:4]) != 0x0074 ||
				binary.LittleEndian.Uint16(record.body[8:10]) != 16 {
				t.Errorf("LF_ARRAY 0x%x body = % X, want int/16-byte size", record.index, record.body)
			}
			checked++
		case pdbLeafModifier:
			if len(record.body) < 6 {
				t.Errorf("LF_MODIFIER 0x%x body too short: % X", record.index, record.body)
			}
			checked++
		}
	}
	if checked == 0 {
		t.Error("no LF_ARRAY or LF_MODIFIER records in the fixture")
	}
}

func TestPDBTypeRenderTable(t *testing.T) {
	record := func(leaf uint16, body ...byte) pdbTypeRecord {
		return pdbTypeRecord{leaf: leaf, body: body}
	}
	// Named struct with a name at body[18:] (the layout pdbTypeName already uses).
	structBody := make([]byte, 18)
	structBody = append(structBody, []byte("Foo\x00")...)
	records := map[uint32]pdbTypeRecord{
		0x1000: record(pdbLeafPointer, 0x74, 0, 0, 0, 0x0c, 0, 1, 0), // int *
		0x1001: record(pdbLeafArray, // int[4], short NumericLeaf
			0x74, 0, 0, 0, 0x23, 0, 0, 0, 0x10, 0, 0, 0),
		0x1002: record(pdbLeafArray, // struct Foo[], element width unknown
			0x05, 0x10, 0, 0, 0x23, 0, 0, 0, 0x10, 0, 0, 0),
		0x1003: record(pdbLeafModifier, 0x74, 0, 0, 0, 0x01, 0),    // const int
		0x1004: record(pdbLeafModifier, 0x03, 0x10, 0, 0, 0x02, 0), // volatile const int
		0x1005: record(pdbLeafStructure, structBody...),
		0x1006: record(pdbLeafArray, // wide NumericLeaf: 0x8fa0 - 0x8000 = 4000, /4
			0x74, 0, 0, 0, 0x23, 0, 0, 0, 0xa0, 0x8f, 0, 0, 0, 0),
		0x1007: record(pdbLeafPointer, 0x03, 0x10, 0, 0, 0x0c, 0, 1, 0), // const int *
		0x1008: record(pdbLeafPointer, 0x01, 0x10, 0, 0, 0x0c, 0, 1, 0), // int[4] *
		0x1009: record(pdbLeafArray, 0x74, 0),                           // truncated array
		0x100a: record(pdbLeafModifier, 0x74, 0, 0, 0),                  // truncated modifier
		0x100b: record(pdbLeafModifier, 0x0b, 0x10, 0, 0, 0x01, 0),      // cyclic const chain
	}
	for index, r := range records {
		r.index = index
		records[index] = r
	}
	tests := []struct {
		name  string
		index uint32
		want  string
	}{
		{"simple type", 0x0074, "int"},
		{"pointer to simple type", 0x1000, "int *"},
		{"array of known-width simple type", 0x1001, "int[4]"},
		{"array of unknown-width element", 0x1002, "struct Foo[]"},
		{"wide numeric leaf", 0x1006, "int[1000]"},
		{"const modifier", 0x1003, "const int"},
		{"modifier chain", 0x1004, "volatile const int"},
		{"const pointer recursion", 0x1007, "const int *"},
		{"array pointer recursion", 0x1008, "int[4] *"},
		{"truncated array", 0x1009, "type(0x1009)"},
		{"truncated modifier", 0x100a, "type(0x100a)"},
		{"unresolvable index", 0xdeadbeef, "type(0xdeadbeef)"},
	}
	for _, tc := range tests {
		got := pdbTypeName(tc.index, records, 0)
		if got != tc.want {
			t.Errorf("%s: pdbTypeName(0x%x) = %q, want %q", tc.name, tc.index, got, tc.want)
		}
		if got == "" {
			t.Errorf("%s: pdbTypeName(0x%x) returned an empty string", tc.name, tc.index)
		}
	}
	// A cyclic modifier chain must terminate at the depth guard and stay non-empty.
	cyclic := pdbTypeName(0x100b, records, 0)
	if cyclic == "" || !strings.Contains(cyclic, "type(0x100b)") {
		t.Errorf("cyclic modifier chain rendered %q", cyclic)
	}
	// No rendering path, for any record kind, may return an empty string.
	for index := range records {
		if got := pdbTypeName(index, records, 0); got == "" {
			t.Errorf("pdbTypeName(0x%x) returned an empty string", index)
		}
	}
	for index := range pdbSimpleTypes {
		if got := pdbTypeName(index, records, 0); got == "" {
			t.Errorf("pdbTypeName(0x%x) returned an empty string", index)
		}
	}
}
