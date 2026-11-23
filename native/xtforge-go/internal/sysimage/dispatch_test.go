package sysimage

import (
	"encoding/binary"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestJumpTableEntriesDecodePerArchitecture(t *testing.T) {
	cases := []struct {
		name   string
		raw    []byte
		base   uint64
		decode entryDecoder
		want   uint64
	}{
		{"x86 signed offset", []byte{0x10, 0, 0, 0}, 0x2000, signedEntries, 0x2010},
		{"x86 negative offset", []byte{0xf0, 0xff, 0xff, 0xff}, 0x2000, signedEntries, 0x1ff0},
		{"arm64 byte offset scaled by 4", []byte{0x08}, 0x1200, byteEntriesFor(4), 0x1220},
		{"arm64 word offset", []byte{0x20, 0, 0, 0}, 0x1200, signedEntries, 0x1220},
		{"absolute pointer", []byte{0x00, 0x30, 0, 0, 0, 0, 0, 0}, 0, absoluteEntries, 0x3000},
	}
	for _, tc := range cases {
		got, ok := tc.decode(tc.raw, tc.base)
		if !ok || got != tc.want {
			t.Errorf("%s: got %#x ok=%v, want %#x", tc.name, got, ok, tc.want)
		}
	}
}

func TestCanonicalRegisterCollapsesWidthAliases(t *testing.T) {
	pairs := [][2]string{
		{"w11", "x11"},
		{"edi", "rdi"},
		{"eax", "rax"},
		{"al", "rax"},
		{"r8d", "r8"},
		{"r8w", "r8"},
		{"lr", "x30"},
	}
	for _, pair := range pairs {
		if got, want := canonicalRegister(pair[0]), canonicalRegister(pair[1]); got != want {
			t.Errorf("%q and %q should share a canonical name, got %q and %q", pair[0], pair[1], got, want)
		}
	}
	if canonicalRegister("x10") == canonicalRegister("x11") {
		t.Error("distinct registers collapsed onto one name")
	}
}

func TestTrackBackFindsDefinitionAcrossWidthAliases(t *testing.T) {
	ops := []Operation{
		{Address: 0x10, Opcode: "copy", Destination: &Operand{Kind: "register", Register: "w11", Width: 32}},
		{Address: 0x14, Opcode: "add", Destination: &Operand{Kind: "register", Register: "x10", Width: 64}},
	}
	got := trackBack(ops, 1, "x11", 8)
	if !got.found || got.index != 0 || got.op.Address != 0x10 {
		t.Fatalf("expected the w11 definition, got %#v", got)
	}
	if other := trackBack(ops, 1, "x12", 8); other.found {
		t.Fatalf("x12 has no definition, got %#v", other)
	}
}

func TestBuildJumpTableStopsAtFirstNonExecutableEntry(t *testing.T) {
	const (
		base    = 0x1000
		table   = 0x1100
		entries = 4
	)
	data := make([]byte, 0x200)
	for i := 0; i < entries; i++ {
		// A valid table: each entry points at base+0x40+i*4.
		offset := int32(int(base) + 0x40 + i*4 - table)
		binary.LittleEndian.PutUint32(data[int(table-base)+i*4:], uint32(offset))
	}
	// The table is mapped but not executable; only code addresses are valid targets.
	image := Image{
		Arch: "x86_64", fileSize: uint64(len(data)),
		Segments:   []Region{{Address: base, Size: uint64(len(data)), FileSize: uint64(len(data))}},
		Executable: []Region{{Address: base, Size: 0x80, FileSize: 0x80}},
	}
	reader := &sliceReader{data: data}
	table1, ok := buildJumpTable(reader, &image, JumpTable{Table: table, Base: table, EntrySize: 4}, signedEntries)
	if !ok || len(table1.Targets) != entries {
		t.Fatalf("expected %d executable targets, got %#v", entries, table1)
	}
	for i, target := range table1.Targets {
		if want := uint64(base + 0x40 + i*4); target != want {
			t.Errorf("target %d = %#x, want %#x", i, target, want)
		}
	}

	// Terminate the table early: a non-executable target ends it.
	binary.LittleEndian.PutUint32(data[int(table-base)+4:], 0)
	stunted, ok := buildJumpTable(reader, &image, JumpTable{Table: table, Base: table, EntrySize: 4}, signedEntries)
	if !ok || len(stunted.Targets) != 1 {
		t.Fatalf("expected the scan to stop at the first non-executable entry, got %#v", stunted)
	}
}

// sliceReader adapts a byte slice to io.ReaderAt.
type sliceReader struct{ data []byte }

func (r *sliceReader) ReadAt(p []byte, off int64) (int, error) {
	if off >= int64(len(r.data)) {
		return 0, os.ErrDeadlineExceeded
	}
	n := copy(p, r.data[off:])
	return n, nil
}

func TestFindJumpTablesReportsUnresolvedIndirectBranch(t *testing.T) {
	image := Image{
		Arch: "x86_64", fileSize: 0x40,
		Segments:   []Region{{Address: 0x1000, Size: 0x40, FileSize: 0x40}},
		Executable: []Region{{Address: 0x1000, Size: 0x40, FileSize: 0x40}},
	}
	ops := []Operation{
		{Address: 0x1000, Opcode: "jump", Inputs: []Operand{{Kind: "register", Register: "rax"}}},
	}
	got := findJumpTables("x86_64", &sliceReader{data: make([]byte, 0x40)}, &image, nil, ops)
	if len(got.Tables) != 0 || got.Indirect != 1 || got.Resolved != 0 {
		t.Fatalf("expected one unresolved indirect branch, got %#v", got)
	}
}

// TestRecoverDispatchOnCompiledSwitch compiles a dense switch and checks that
// recovery returns every case body the compiler put in the table.
func TestRecoverDispatchOnCompiledSwitch(t *testing.T) {
	compiler := ""
	for _, candidate := range []string{"cc", "gcc", "clang"} {
		if path, err := exec.LookPath(candidate); err == nil {
			compiler = path
			break
		}
	}
	if compiler == "" {
		t.Skip("no C compiler available")
	}
	source := filepath.Join(t.TempDir(), "switch.c")
	cases := ""
	for i := 0; i < 8; i++ {
		cases += "    case " + itoa(i) + ": return x + " + itoa(i*7+3) + ";\n"
	}
	body := "__attribute__((noinline)) int dense(int op, int x) {\n    switch (op) {\n" +
		cases + "    default: return x;\n    }\n}\nint main(void) { return dense(3, 5) - 24; }\n"
	if err := os.WriteFile(source, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(t.TempDir(), "dense")
	compile := exec.Command(compiler, "-O2", "-o", binary, source)
	if out, err := compile.CombinedOutput(); err != nil {
		t.Skipf("compiler cannot build the fixture: %v: %s", err, out)
	}
	got, err := RecoverDispatch(binary, DispatchOptions{Target: "dense"})
	if err != nil {
		t.Fatalf("recover dispatch: %v", err)
	}
	if len(got.Tables) == 0 {
		t.Fatalf("no jump table recovered: %#v", got)
	}
	table := got.Tables[0]
	if table.Bound == nil || *table.Bound != 7 {
		t.Errorf("bound = %v, want 7", table.Bound)
	}
	if table.Kind != "x86_offset_table" {
		t.Errorf("kind = %q, want x86_offset_table", table.Kind)
	}
	// Targets stay in index order, one per case, so the count is exactly the
	// number of case values even when bodies repeat.
	if len(table.Targets) != 8 {
		t.Errorf("recovered %d targets, want 8: %x", len(table.Targets), table.Targets)
	}
	for _, target := range table.Targets {
		if _, err := os.Stat(binary); err != nil {
			t.Fatal(err)
		}
		if target == 0 {
			t.Errorf("recovered a zero target")
		}
	}
}

// TestAddressConstantResolvesAdrpAddPair checks the arm64 page pair that builds
// a jump-table address: adrp materialises the page, add applies the offset.
func TestAddressConstantResolvesAdrpAddPair(t *testing.T) {
	const page = uint64(0x100004000)
	ops := []Operation{
		{Address: 0x100, Opcode: "address", Destination: &Operand{Kind: "register", Register: "x10", Width: 64},
			Inputs: []Operand{{Kind: "immediate", Immediate: "0x100004000", Width: 64}}},
		{Address: 0x104, Opcode: "add", Destination: &Operand{Kind: "register", Register: "x10", Width: 64},
			Inputs: []Operand{
				{Kind: "register", Register: "x10", Width: 64},
				{Kind: "immediate", Immediate: "0x294", Width: 64},
			}},
	}
	got, ok := addressConstant(ops, 2, "x10", 4)
	if !ok || got != page+0x294 {
		t.Fatalf("addressConstant = %#x ok=%v, want %#x", got, ok, page+0x294)
	}
	// A register that was never defined cannot be resolved.
	if _, ok := addressConstant(ops, 2, "x11", 4); ok {
		t.Error("resolved an undefined register")
	}
	// The depth bound stops cycles from looping forever.
	if _, ok := addressConstant(ops, 2, "x10", 0); ok {
		t.Error("depth 0 should not resolve")
	}
}

func itoa(v int) string {
	if v == 0 {
		return "0"
	}
	digits := ""
	for v > 0 {
		digits = string(rune('0'+v%10)) + digits
		v /= 10
	}
	return digits
}

// TestRecoverDispatchWithoutTargetScansFunctions pins the sweep.
//
// With no target the entry point was analysed, which for a normal executable is CRT glue.
// The result then reported `tables: 0`, which reads as "this binary has no jump tables" —
// a false claim about the binary, when in fact only `_start` had been looked at. The
// fixture below has a table in `dense`, so a zero would mean the sweep is not running.
func TestRecoverDispatchWithoutTargetScansFunctions(t *testing.T) {
	compiler := ""
	for _, candidate := range []string{"cc", "gcc", "clang"} {
		if path, err := exec.LookPath(candidate); err == nil {
			compiler = path
			break
		}
	}
	if compiler == "" {
		t.Skip("no C compiler available")
	}
	cases := ""
	for index := 0; index < 8; index++ {
		cases += "    case " + itoa(index) + ": return x + " + itoa(index*7+3) + ";\n"
	}
	body := "__attribute__((noinline)) int dense(int op, int x) {\n    switch (op) {\n" +
		cases + "    default: return x;\n    }\n}\nint main(void) { return dense(3, 5) - 24; }\n"
	source := filepath.Join(t.TempDir(), "sweep.c")
	if err := os.WriteFile(source, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(t.TempDir(), "sweep")
	if out, err := exec.Command(compiler, "-O2", "-o", binary, source).CombinedOutput(); err != nil {
		t.Skipf("compiler cannot build the fixture: %v: %s", err, out)
	}
	got, err := RecoverDispatch(binary, DispatchOptions{})
	if err != nil {
		t.Fatalf("recover dispatch: %v", err)
	}
	if got.FunctionsScanned < 2 {
		t.Fatalf("scanned %d functions; the sweep is not running", got.FunctionsScanned)
	}
	if len(got.Tables) == 0 {
		t.Fatalf("no jump table found while sweeping %d functions", got.FunctionsScanned)
	}
	if got.Tables[0].FunctionName != "dense" {
		t.Errorf("table attributed to %q, want dense", got.Tables[0].FunctionName)
	}
}
