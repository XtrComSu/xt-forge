package sysimage

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The census is checked against `llvm-pdbutil dump -types`, which is an independent
// implementation of the same format. "A kind appears" would pass on a wrong table; an
// exact per-kind count match against a reference tool will not.

func TestReadPDBTypeCensusMatchesLlvmPdbutil(t *testing.T) {
	for _, tool := range []string{"clang", "lld-link", "llvm-pdbutil"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not available", tool)
		}
	}
	dir := t.TempDir()
	source := filepath.Join(dir, "r.c")
	if err := os.WriteFile(source, []byte(`
struct Point { int x; int y; };
enum Color { Red, Green };
union Value { int i; float f; };
struct Point make(int x, int y) { struct Point p = {x, y}; return p; }
int dist(struct Point *p, struct Point q) { return p->x + q.y; }
int main(void) { struct Point p = make(1, 2); return dist(&p, p); }
`), 0600); err != nil {
		t.Fatal(err)
	}
	obj := filepath.Join(dir, "r.obj")
	pdbPath := filepath.Join(dir, "r.pdb")
	exe := filepath.Join(dir, "r.exe")
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
	file, err := os.Open(pdbPath)
	if err != nil {
		t.Skipf("no PDB produced: %v", err)
	}
	defer file.Close()
	stat, err := file.Stat()
	if err != nil {
		t.Fatal(err)
	}
	census, err := ReadPDBTypeCensus(file, stat.Size())
	if err != nil {
		t.Fatalf("census: %v", err)
	}
	t.Logf("census: version %#x, %d records, kinds %v", census.Version, census.RecordCount, census.Kinds)
	if census.RecordCount == 0 {
		t.Fatal("no type records found")
	}

	// Reference counts. Nested records (members inside a field list) are excluded on
	// purpose: llvm-pdbutil reports them, a top-level census cannot.
	out, err := exec.Command("llvm-pdbutil", "dump", "-types", pdbPath).CombinedOutput()
	if err != nil {
		t.Skipf("llvm-pdbutil failed: %v", err)
	}
	reference := map[string]int{}
	for _, line := range strings.Split(string(out), "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "0x") {
			continue
		}
		if pipe := strings.Index(trimmed, "| "); pipe >= 0 {
			fields := strings.Fields(trimmed[pipe+2:])
			if len(fields) > 0 {
				// llvm-pdbutil prints LF_ARGLIST; our names are ArgList. Compare
				// case-insensitively rather than reshaping one side to the other.
				kind := strings.ToLower(strings.TrimPrefix(fields[0], "LF_"))
				// Our table names match llvm's after the prefix, except these.
				reference[kind]++
			}
		}
	}
	// Members only appear nested, so compare the kinds a top-level walk can see.
	for kind, count := range census.Kinds {
		key := strings.ToLower(kind)
		if key == "member" {
			continue
		}
		if reference[key] == 0 {
			t.Errorf("kind %q reported by the census does not appear in llvm-pdbutil output %v", kind, reference)
			continue
		}
		if reference[key] != count {
			t.Errorf("kind %q: census %d, llvm-pdbutil %d", kind, count, reference[key])
		}
	}
}

func TestReadPDBTypeCensusRejectsBadInput(t *testing.T) {
	dir := t.TempDir()
	for _, tc := range []struct {
		name string
		data []byte
	}{
		{"empty", nil},
		{"wrong magic", append(make([]byte, 48), []byte("not a pdb at all")...)},
		{"truncated", []byte("Microsoft C/C++ MSF 7.00\r\n\x1aDS\x00\x00\x00")},
	} {
		path := filepath.Join(dir, "bad.pdb")
		if err := os.WriteFile(path, tc.data, 0600); err != nil {
			t.Fatal(err)
		}
		file, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		stat, _ := file.Stat()
		if _, err := ReadPDBTypeCensus(file, stat.Size()); err == nil {
			t.Errorf("%s: expected an error", tc.name)
		}
		file.Close()
	}
}
