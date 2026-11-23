package sysimage

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// Union, bitfield and enum-field rendering is checked against
// `llvm-pdbutil dump -types` for a fixture compiled with clang-cl -Z7 and
// linked with lld-link /debug /force:unresolved. The oracle reports:
//
//	0x1004 | LF_UNION [size = 20] `Value` ... options: sealed, sizeof 4
//	0x1008 | LF_BITFIELD ... type = 0x0075 (unsigned), bit offset = 0, # bits = 3
//	0x1009 | LF_BITFIELD ... type = 0x0075 (unsigned), bit offset = 3, # bits = 5
//	0x100B | LF_ENUM [size = 24] `Shade`
//	        - LF_MEMBER [name = `shade`, Type = 0x100B, offset = 4, attrs = public]
//
// The LF_MEMBER attrs in this fixture are 0x0003 (public) for every member:
// the bit widths come from LF_BITFIELD type records, not from high attr bits.
var (
	unionOracleLine = regexp.MustCompile("LF_UNION[^\n]*`([^`]+)`")
	unionSizeLine   = regexp.MustCompile(`sizeof (\d+)`)
	bitfieldLine    = regexp.MustCompile(`# bits = (\d+)`)
	enumOracleLine  = regexp.MustCompile("LF_ENUM[^\n]*`([^`]+)`")
)

const unionFixture = `
enum Shade { RED, GREEN, BLUE };
union Value { int i; short s; };
struct Bits { unsigned a : 3; unsigned b : 5; enum Shade shade; };
union Value use_union(union Value v) { return v; }
struct Bits use_bits(struct Bits v) { return v; }
`

func buildUnionPDB(t *testing.T, dir string) string {
	t.Helper()
	for _, tool := range []string{"clang-cl", "lld-link"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not available: %v", tool, err)
		}
	}
	source := filepath.Join(dir, "union.c")
	if err := os.WriteFile(source, []byte(unionFixture), 0600); err != nil {
		t.Fatal(err)
	}
	obj := filepath.Join(dir, "union.obj")
	pdbPath := filepath.Join(dir, "union.pdb")
	exe := filepath.Join(dir, "union.exe")
	for _, step := range [][]string{
		{"clang-cl", "-Z7", "-c", source, "/Fo" + obj},
		{"lld-link", "/debug", "/force:unresolved", "/nodefaultlib", "/subsystem:console",
			"/pdb:" + pdbPath, "/out:" + exe, obj},
	} {
		command := exec.Command(step[0], step[1:]...)
		if output, err := command.CombinedOutput(); err != nil {
			t.Skipf("%s failed: %v: %s", step[0], err, output)
		}
	}
	return pdbPath
}

func openUnionPDB(t *testing.T, path string) (*os.File, int64) {
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

func unionOracle(t *testing.T, pdbPath string) (string, []int, []string) {
	t.Helper()
	if _, err := exec.LookPath("llvm-pdbutil"); err != nil {
		t.Logf("skipping llvm-pdbutil cross-check: %v", err)
		return "", nil, nil
	}
	out, err := exec.Command("llvm-pdbutil", "dump", "-types", pdbPath).CombinedOutput()
	if err != nil {
		t.Logf("skipping llvm-pdbutil cross-check: %v", err)
		return "", nil, nil
	}
	var widths []int
	var enums []string
	unionSize := ""
	lines := strings.Split(string(out), "\n")
	for index, line := range lines {
		if match := bitfieldLine.FindStringSubmatch(line); match != nil {
			width, err := strconv.Atoi(match[1])
			if err != nil {
				t.Fatalf("bad oracle bit width %q: %v", match[1], err)
			}
			widths = append(widths, width)
		}
		if match := enumOracleLine.FindStringSubmatch(line); match != nil {
			enums = append(enums, match[1])
		}
		if match := unionOracleLine.FindStringSubmatch(line); match != nil && match[1] == "Value" {
			for _, following := range lines[index+1:] {
				if strings.Contains(following, "0x") && strings.Contains(following, " | ") {
					break // next top-level record
				}
				if size := unionSizeLine.FindStringSubmatch(following); size != nil {
					if value, err := strconv.Atoi(size[1]); err == nil && value > 0 {
						unionSize = size[1] // ignore the forward ref's sizeof 0
					}
				}
			}
		}
	}
	return unionSize, widths, enums
}

func TestPDBUnion(t *testing.T) {
	pdbPath := buildUnionPDB(t, t.TempDir())
	file, size := openUnionPDB(t, pdbPath)
	aggregates, err := ReadPDBAggregates(file, size, 0)
	if err != nil {
		t.Fatalf("aggregates: %v", err)
	}
	var value *PDBAggregate
	for index := range aggregates {
		aggregate := &aggregates[index]
		t.Logf("%s", aggregate.Rendered)
		if aggregate.Name == "Value" && len(aggregate.Fields) > 0 {
			value = aggregate
		}
	}
	if value == nil {
		t.Fatalf("union Value not recovered: %+v", aggregates)
	}
	if !value.Union {
		t.Error("Value.Union = false, want true")
	}
	if !strings.HasPrefix(value.Rendered, "union Value") || strings.HasPrefix(value.Rendered, "struct ") {
		t.Errorf("Rendered = %q, want the union keyword and full name", value.Rendered)
	}
	if value.Size != 4 {
		t.Errorf("union Value size = %d, want 4", value.Size)
	}
	if len(value.Fields) != 2 || value.Fields[0].Name != "i" || value.Fields[1].Name != "s" {
		t.Errorf("union Value fields = %+v, want i and s", value.Fields)
	}
	types, err := pdbLoadTypeStream(file, size)
	if err != nil {
		t.Fatalf("type stream: %v", err)
	}
	if got := pdbTypeName(value.Index, types.records, 0); got != "union Value" {
		t.Errorf("pdbTypeName(0x%x) = %q, want %q", value.Index, got, "union Value")
	}
	signatures, err := ReadPDBSignatures(file, size, 0)
	if err != nil {
		t.Fatalf("signatures: %v", err)
	}
	sawUnionSignature := false
	for _, signature := range signatures {
		t.Logf("signature: %s", signature.Rendered)
		if strings.Contains(signature.Rendered, "union Value") {
			sawUnionSignature = true
		}
	}
	if !sawUnionSignature {
		t.Error("no recovered signature rendered union Value")
	}

	oracleSize, _, _ := unionOracle(t, pdbPath)
	if oracleSize != "" && strconv.Itoa(int(value.Size)) != oracleSize {
		t.Errorf("union Value size: ours %d, llvm-pdbutil %s", value.Size, oracleSize)
	}
}

func TestPDBBitfield(t *testing.T) {
	pdbPath := buildUnionPDB(t, t.TempDir())
	file, size := openUnionPDB(t, pdbPath)
	aggregates, err := ReadPDBAggregates(file, size, 0)
	if err != nil {
		t.Fatalf("aggregates: %v", err)
	}
	var bits *PDBAggregate
	for index := range aggregates {
		if aggregates[index].Name == "Bits" {
			bits = &aggregates[index]
		}
		t.Logf("%s", aggregates[index].Rendered)
	}
	if bits == nil {
		t.Fatalf("struct Bits not recovered: %+v", aggregates)
	}
	widths := map[string]int{}
	for _, field := range bits.Fields {
		widths[field.Name] = field.BitWidth
	}
	if widths["a"] != 3 || widths["b"] != 5 {
		t.Errorf("bit widths = %v, want a:3 and b:5 (fields %+v)", widths, bits.Fields)
	}
	if !strings.Contains(bits.Rendered, "unsigned a : 3") || !strings.Contains(bits.Rendered, "unsigned b : 5") {
		t.Errorf("Rendered = %q, want C bitfield declarations", bits.Rendered)
	}
	// The enum-typed member must carry the enum's name, not its type index.
	var enumField *PDBField
	for index := range bits.Fields {
		if bits.Fields[index].Name == "shade" {
			enumField = &bits.Fields[index]
		}
	}
	if enumField == nil || enumField.Type != "enum Shade" {
		t.Errorf("shade field = %+v, want type enum Shade", enumField)
	}
	if !strings.Contains(bits.Rendered, "enum Shade shade") {
		t.Errorf("Rendered = %q, want enum Shade shade", bits.Rendered)
	}
	enums, err := ReadPDBEnums(file, size, 0)
	if err != nil {
		t.Fatalf("enums: %v", err)
	}
	knownEnum := false
	for _, enum := range enums {
		if enum.Name == "Shade" {
			knownEnum = true
		}
	}
	if !knownEnum {
		t.Errorf("enum Shade not decoded: %+v", enums)
	}

	_, oracleWidths, oracleEnums := unionOracle(t, pdbPath)
	if oracleWidths != nil {
		sort.Ints(oracleWidths)
		ours := []int{widths["a"], widths["b"]}
		sort.Ints(ours)
		if len(oracleWidths) != len(ours) {
			t.Errorf("bit widths: ours %v, llvm-pdbutil %v", ours, oracleWidths)
		} else {
			for index := range ours {
				if ours[index] != oracleWidths[index] {
					t.Errorf("bit widths: ours %v, llvm-pdbutil %v", ours, oracleWidths)
					break
				}
			}
		}
	}
	if oracleEnums != nil {
		found := false
		for _, name := range oracleEnums {
			if name == "Shade" {
				found = true
			}
		}
		if !found {
			t.Errorf("llvm-pdbutil did not report enum Shade: %v", oracleEnums)
		}
	}
}

// The type-name paths are also exercised without a Windows toolchain: an enum
// resolved by record renders by name, while an index with no record keeps its index.
func TestPDBTypeNameUnionEnumBitfield(t *testing.T) {
	enumBody := make([]byte, 12)
	enumBody = append(enumBody, []byte("Color\x00")...)
	unionBody := make([]byte, 10) // count u16, props u16, field list u32, size NumericLeaf u16
	unionBody = append(unionBody, []byte("Choice\x00")...)
	records := map[uint32]pdbTypeRecord{
		0x1000: {leaf: pdbLeafEnum, body: enumBody},
		0x1001: {leaf: pdbLeafUnion, body: unionBody},
		0x1002: {leaf: pdbLeafBitfield, body: []byte{0x74, 0, 0, 0, 3, 0}},
	}
	for index, record := range records {
		record.index = index
		records[index] = record
	}
	for _, test := range []struct {
		index uint32
		want  string
	}{
		{0x1000, "enum Color"},
		{0x1001, "union Choice"},
		{0x1002, "int : 3"},
		{0x1234, "type(0x1234)"}, // unknown enum keeps its index
	} {
		if got := pdbTypeName(test.index, records, 0); got != test.want {
			t.Errorf("pdbTypeName(0x%x) = %q, want %q", test.index, got, test.want)
		}
	}
}
