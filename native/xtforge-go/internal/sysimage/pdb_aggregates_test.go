package sysimage

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// Aggregate layouts are checked against llvm-pdbutil dump -types, which prints the
// member names, their types and their offsets for the same records.

func buildAggregatePDB(t *testing.T, dir string) string {
	t.Helper()
	for _, tool := range []string{"clang", "lld-link"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not available", tool)
		}
	}
	source := filepath.Join(dir, "agg.c")
	if err := os.WriteFile(source, []byte(`
struct Point { int x; int y; };
struct Pair { char tag; long long value; };
union Value { int i; short s; };
struct Point make(int x, int y) { struct Point p; p.x = x; p.y = y; return p; }
int use(struct Point p) { return p.x + p.y; }
int main(void) { struct Point p = make(1, 2); return use(p); }
`), 0600); err != nil {
		t.Fatal(err)
	}
	obj := filepath.Join(dir, "agg.obj")
	pdbPath := filepath.Join(dir, "agg.pdb")
	exe := filepath.Join(dir, "agg.exe")
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

func TestReadPDBAggregatesDecodesLayout(t *testing.T) {
	dir := t.TempDir()
	pdbPath := buildAggregatePDB(t, dir)
	file, err := os.Open(pdbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	stat, err := file.Stat()
	if err != nil {
		t.Fatal(err)
	}
	aggregates, err := ReadPDBAggregates(file, stat.Size(), 0)
	if err != nil {
		t.Fatalf("aggregates: %v", err)
	}
	byName := map[string]PDBAggregate{}
	for _, aggregate := range aggregates {
		byName[aggregate.Name] = aggregate
		t.Logf("%s", aggregate.Rendered)
	}
	point, ok := byName["Point"]
	if !ok {
		t.Fatalf("struct Point not recovered; got %v", byName)
	}
	if point.Size != 8 {
		t.Errorf("Point size = %d, want 8", point.Size)
	}
	if len(point.Fields) != 2 {
		t.Fatalf("Point fields = %v", point.Fields)
	}
	if point.Fields[0].Name != "x" || point.Fields[0].Offset != 0 || point.Fields[0].Type != "int" {
		t.Errorf("field 0 = %+v", point.Fields[0])
	}
	if point.Fields[1].Name != "y" || point.Fields[1].Offset != 4 {
		t.Errorf("field 1 = %+v", point.Fields[1])
	}
	if pair, ok := byName["Pair"]; ok {
		// A long long forces padding: char at 0, long long at 8.
		if len(pair.Fields) == 2 && pair.Fields[1].Offset != 8 {
			t.Errorf("Pair second field offset = %d, want 8 (alignment)", pair.Fields[1].Offset)
		}
	}
	if value, ok := byName["Value"]; ok && !value.Union {
		t.Errorf("Value should be a union, got %+v", value)
	}
}

func TestReadPDBAggregatesMatchLlvmPdbutil(t *testing.T) {
	if _, err := exec.LookPath("llvm-pdbutil"); err != nil {
		t.Skip("llvm-pdbutil not available")
	}
	dir := t.TempDir()
	pdbPath := buildAggregatePDB(t, dir)
	file, err := os.Open(pdbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	stat, err := file.Stat()
	if err != nil {
		t.Fatal(err)
	}
	aggregates, err := ReadPDBAggregates(file, stat.Size(), 0)
	if err != nil {
		t.Fatalf("aggregates: %v", err)
	}
	ours := map[string]PDBAggregate{}
	for _, aggregate := range aggregates {
		ours[aggregate.Name] = aggregate
	}
	out, err := exec.Command("llvm-pdbutil", "dump", "-types", pdbPath).CombinedOutput()
	if err != nil {
		t.Skipf("llvm-pdbutil failed: %v", err)
	}
	// Reference lines look like:
	//   - LF_MEMBER [name = `x`, Type = 0x0074 (int), offset = 0, attrs = public]
	compared := 0
	current := ""
	for _, line := range strings.Split(string(out), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.Contains(trimmed, "LF_STRUCTURE") || strings.Contains(trimmed, "LF_UNION") {
			if open := strings.LastIndex(trimmed, "`"); open >= 0 {
				if start := strings.Index(trimmed, "`"); start >= 0 && start < open {
					current = trimmed[start+1 : open]
				}
			}
			continue
		}
		if !strings.Contains(trimmed, "LF_MEMBER") || current == "" {
			continue
		}
		aggregate, ok := ours[current]
		if !ok {
			continue
		}
		nameStart := strings.Index(trimmed, "`")
		nameEnd := strings.Index(trimmed, "`,")
		if nameStart < 0 || nameEnd <= nameStart {
			continue
		}
		fieldName := trimmed[nameStart+1 : nameEnd]
		offsetAt := strings.Index(trimmed, "offset = ")
		if offsetAt < 0 {
			continue
		}
		offsetText := trimmed[offsetAt+len("offset = "):]
		if comma := strings.IndexAny(offsetText, ", \t"); comma > 0 {
			offsetText = offsetText[:comma]
		}
		parsed, err := strconv.ParseUint(strings.TrimSpace(offsetText), 10, 32)
		if err != nil {
			continue
		}
		wantOffset := uint32(parsed)
		var found *PDBField
		for index := range aggregate.Fields {
			if aggregate.Fields[index].Name == fieldName {
				found = &aggregate.Fields[index]
			}
		}
		if found == nil {
			t.Errorf("%s: member %q missing from our output", current, fieldName)
			continue
		}
		if found.Offset != wantOffset {
			t.Errorf("%s.%s offset: ours %d, llvm-pdbutil %d", current, fieldName, found.Offset, wantOffset)
		}
		compared++
	}
	if compared == 0 {
		t.Fatal("no members compared with llvm-pdbutil")
	}
	t.Logf("compared %d members with llvm-pdbutil", compared)
}
