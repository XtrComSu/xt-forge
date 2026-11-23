package sysimage

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// PDB simple types and pointers.
//
// Two gaps were measured against llvm-pdbutil:
//
//   - the simple-type table was missing the real-number and unsigned families, so a
//     `double` field rendered as `type(0x0041)` — the oracle names that index "double";
//   - pointers were not decoded at all, so `short*` rendered as `type(0x0611)`. A pointer
//     is a mode in bits 8-11 over a base index: 0x0611 is a 64-bit near pointer to 0x0011.
//
// Both now render the way the oracle prints them. The table keeps its rule — only indices
// confirmed against `llvm-pdbutil dump -types` are listed.

const pdbTypesSource = `
struct All {
    char c; signed char sc; unsigned char uc;
    short s; unsigned short us;
    int i; unsigned int ui;
    long l; unsigned long ul;
    long long ll; unsigned long long ull;
    float f; double d; long double ld;
    _Bool b; short* ps; int* pi; void* pv;
};
int main(void){ struct All a = {0}; return a.i; }
`

func buildPDBFixture(t *testing.T, dir, source string) string {
	t.Helper()
	for _, tool := range []string{"clang-cl", "lld-link"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not available", tool)
		}
	}
	file := filepath.Join(dir, "types.c")
	if err := os.WriteFile(file, []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	object := filepath.Join(dir, "types.obj")
	binary := filepath.Join(dir, "types.exe")
	pdb := filepath.Join(dir, "types.pdb")
	if output, err := exec.Command("clang-cl", "-Z7", "-c", file, "-o", object).CombinedOutput(); err != nil {
		t.Skipf("clang-cl cannot compile the fixture: %v: %s", err, output)
	}
	// /force:unresolved keeps the link working without a CRT; the PDB is what is wanted.
	if _, err := os.Stat(pdb); err == nil {
		os.Remove(pdb)
	}
	exec.Command("lld-link", "/entry:main", "/subsystem:console", "/nodefaultlib", "/debug",
		"/out:"+binary, object, "/force:unresolved").CombinedOutput()
	if _, err := os.Stat(pdb); err != nil {
		t.Skipf("no PDB produced: %v", err)
	}
	return pdb
}

func TestPDBTypeRenderingMatchesOracle(t *testing.T) {
	pdb := buildPDBFixture(t, t.TempDir(), pdbTypesSource)
	file, err := os.Open(pdb)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		t.Fatal(err)
	}
	aggregates, err := ReadPDBAggregates(file, info.Size(), 200)
	if err != nil {
		t.Fatalf("pdb aggregates: %v", err)
	}
	var rendered string
	for _, aggregate := range aggregates {
		if aggregate.Name == "All" {
			rendered = aggregate.Rendered
		}
	}
	if rendered == "" {
		t.Fatalf("struct All not recovered: %+v", aggregates)
	}
	for _, want := range []string{
		"signed char sc", "unsigned char uc", "short s", "unsigned short us",
		"long l", "unsigned long ul", "__int64 ll", "unsigned __int64 ull",
		"float f", "double d", "bool b",
		"short* ps", "int* pi", "void* pv",
	} {
		if !strings.Contains(rendered, want) {
			t.Errorf("rendered output lacks %q:\n  %s", want, rendered)
		}
	}
	if strings.Contains(rendered, "type(0x") {
		t.Errorf("unresolved type index in output:\n  %s", rendered)
	}
}

// TestPDBTypeNamesMatchOracleIndices checks the table itself against the oracle's names,
// so a hand-written entry cannot drift from what the format actually means.
func TestPDBTypeNamesMatchOracleIndices(t *testing.T) {
	if _, err := exec.LookPath("llvm-pdbutil"); err != nil {
		t.Skip("llvm-pdbutil not available")
	}
	pdb := buildPDBFixture(t, t.TempDir(), pdbTypesSource)
	output, err := exec.Command("llvm-pdbutil", "dump", "-types", pdb).CombinedOutput()
	if err != nil {
		t.Skipf("llvm-pdbutil failed: %v", err)
	}
	oracle := map[uint32]string{}
	for _, line := range strings.Split(string(output), "\n") {
		// Type = 0x0041 (double)
		parts := strings.Split(line, "Type = 0x")
		if len(parts) != 2 {
			continue
		}
		rest := parts[1]
		closing := strings.Index(rest, ")")
		open := strings.Index(rest, " (")
		if open < 0 || closing < open {
			continue
		}
		var index uint32
		if _, err := fmt.Sscanf(rest[:open], "%x", &index); err != nil {
			continue
		}
		if _, simple := pdbSimpleTypes[index]; simple {
			oracle[index] = strings.TrimSpace(rest[open+2 : closing])
		}
	}
	if len(oracle) == 0 {
		t.Skip("oracle reported no simple types")
	}
	for index, want := range oracle {
		if got := pdbSimpleTypes[index]; got != want {
			t.Errorf("index 0x%04x: table says %q, llvm-pdbutil says %q", index, got, want)
		}
	}
	t.Logf("checked %d simple type indices against llvm-pdbutil", len(oracle))
}

// Array dimensions and forward references.
//
// `int grid[2][3]` rendered as `int[3][]`: the count needs the *element's* width, and the
// element was an array, a struct or a pointer rather than a simple type. `struct Rec list[2]`
// was worse — the element record was a forward reference carrying sizeof 0, pointing at the
// real definition elsewhere in the stream.
//
// Expected text matches the C source and llvm-pdbutil's sizes (24/12, 32/16, 32/8).
const pdbArraySource = `
struct Rec { int a; double b; };
struct Deep { int grid[2][3]; struct Rec list[2]; char *names[4]; };
int use(struct Deep *d){ return d->grid[1][2] + d->list[0].a + (d->names[0] ? 1 : 0); }
int main(void){ struct Deep d = {{{0}}}; return use(&d); }
`

func TestPDBArrayDimensions(t *testing.T) {
	pdb := buildPDBFixture(t, t.TempDir(), pdbArraySource)
	file, err := os.Open(pdb)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		t.Fatal(err)
	}
	aggregates, err := ReadPDBAggregates(file, info.Size(), 200)
	if err != nil {
		t.Fatalf("pdb aggregates: %v", err)
	}
	var rendered string
	for _, aggregate := range aggregates {
		if aggregate.Name == "Deep" {
			rendered = aggregate.Rendered
		}
	}
	if rendered == "" {
		t.Fatalf("struct Deep not recovered: %+v", aggregates)
	}
	// Dimensions must be outermost-first, as C declares them.
	for _, want := range []string{"int[2][3] grid", "struct Rec[2] list", "char*[4] names"} {
		if !strings.Contains(rendered, want) {
			t.Errorf("rendered output lacks %q:\n  %s", want, rendered)
		}
	}
	if strings.Contains(rendered, "[]") {
		t.Errorf("an array dimension lost its count:\n  %s", rendered)
	}
}

// Parameter names.
//
// A signature knows the argument *types* and never their names, so `int*, unsigned long,
// struct Rec *` leaves the reader guessing which is the buffer and which is the count. The
// names live in the symbol stream as S_LOCAL records with the param flag inside each
// S_GPROC32 scope.
//
// The offsets are body-relative. Using record-absolute values (4/8/10) put the walk two
// bytes late and produced a parameter named "t" with type index 0x6f630001 — a wrong
// answer that still looked like a name and an index.
func TestPDBParameterNames(t *testing.T) {
	pdb := buildPDBFixture(t, t.TempDir(), `
typedef unsigned long my_size;
struct Rec { int a; double b; };
int takes_array(int values[8], my_size count, struct Rec *r) {
    return values[0] + (int)count + r->a;
}
int main(void) { int v[8] = {1}; struct Rec r = {2, 3.0}; return takes_array(v, 8, &r); }
`)
	file, err := os.Open(pdb)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		t.Fatal(err)
	}
	procedures, err := ReadPDBProcedures(file, info.Size(), 0)
	if err != nil {
		t.Fatalf("read procedures: %v", err)
	}
	var found *PDBProcedure
	for index := range procedures {
		if procedures[index].Name == "takes_array" {
			found = &procedures[index]
		}
	}
	if found == nil {
		t.Fatalf("takes_array not recovered: %d procedures", len(procedures))
	}
	names := make([]string, 0, len(found.Parameters))
	for _, parameter := range found.Parameters {
		names = append(names, parameter.Name)
	}
	want := []string{"values", "count", "r"}
	if len(names) != len(want) {
		t.Fatalf("parameters = %v, want %v", names, want)
	}
	for index, expected := range want {
		if names[index] != expected {
			t.Errorf("parameter %d = %q, want %q", index, names[index], expected)
		}
	}
	// A type index that is really part of the name string is the signature of the
	// two-byte misalignment.
	for _, parameter := range found.Parameters {
		if parameter.TypeIndex > 0x0000ffff {
			t.Errorf("%s has implausible type index 0x%x (misaligned record)",
				parameter.Name, parameter.TypeIndex)
		}
	}
}
