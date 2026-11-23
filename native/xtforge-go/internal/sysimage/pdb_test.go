package sysimage

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// PDB reader tests.
//
// There is deliberately no hand-built MSF fixture here. One was written and got the
// container layout wrong twice (wrong stream index, then a 33-byte magic that shifted
// BlockSize), and a fixture built from the same understanding as the parser cannot
// falsify it. The real-PDB test below drives lld-link and asserts names taken from the
// C source, which is evidence the parser cannot fake.

func TestReadPDBPublicSymbolsRejectsBadInput(t *testing.T) {
	dir := t.TempDir()
	for _, tc := range []struct {
		name string
		data []byte
	}{
		{"empty", nil},
		{"wrong magic", append(make([]byte, 56), []byte("not a pdb")...)},
		{"truncated header", []byte("Microsoft C/C++ MSF 7.00")},
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
		if _, err := ReadPDBPublicSymbols(file, stat.Size(), 0); err == nil {
			t.Errorf("%s: expected an error", tc.name)
		}
		file.Close()
	}
}

// TestReadPDBPublicSymbolsReal builds a real PDB with the Windows toolchain.
//
// This is the test that can falsify the parser: the expected names come from the C
// source, not from my own encoder.
func TestReadPDBPublicSymbolsReal(t *testing.T) {
	if _, err := exec.LookPath("clang"); err != nil {
		t.Skip("clang not available")
	}
	if _, err := exec.LookPath("lld-link"); err != nil {
		t.Skip("lld-link not available")
	}
	dir := t.TempDir()
	source := filepath.Join(dir, "q.c")
	if err := os.WriteFile(source, []byte(
		"int helper_add(int a, int b) { return a + b; }\n"+
			"int compute(int a, int b) { return helper_add(a, b) * 2; }\n"+
			"int main(void) { return compute(2, 3); }\n"), 0600); err != nil {
		t.Fatal(err)
	}
	obj := filepath.Join(dir, "q.obj")
	pdbPath := filepath.Join(dir, "q.pdb")
	exe := filepath.Join(dir, "q.exe")
	steps := [][]string{
		{"clang", "-target", "x86_64-pc-windows-msvc", "-O1", "-g", "-gcodeview", "-c", source, "-o", obj},
		{"lld-link", "/entry:main", "/subsystem:console", "/nodefaultlib", "/debug",
			"/pdb:" + pdbPath, "/out:" + exe, obj},
	}
	for _, step := range steps {
		command := exec.Command(step[0], step[1:]...)
		if output, err := command.CombinedOutput(); err != nil {
			t.Skipf("%s failed (toolchain incomplete): %v: %s", step[0], err, output)
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
	symbols, err := ReadPDBPublicSymbols(file, stat.Size(), 0)
	if err != nil {
		t.Fatalf("read real pdb: %v", err)
	}
	found := map[string]PDBSymbol{}
	for _, symbol := range symbols {
		found[symbol.Name] = symbol
	}
	for _, want := range []string{"helper_add", "compute", "main"} {
		if _, ok := found[want]; !ok {
			t.Errorf("missing symbol %q; got %d symbols", want, len(symbols))
		}
	}
	if symbol, ok := found["helper_add"]; ok && symbol.Segment == 0 {
		t.Errorf("helper_add has segment 0")
	}
	t.Logf("real PDB: %d public symbols", len(symbols))
}

// TestPENamingFromPDB is the integration test: build a PE plus its PDB, then assert
// that Functions() reports the source-level names. Without this the PDB reader could
// keep passing while nothing in the pipeline ever called it.
func TestPENamingFromPDB(t *testing.T) {
	if _, err := exec.LookPath("clang"); err != nil {
		t.Skip("clang not available")
	}
	if _, err := exec.LookPath("lld-link"); err != nil {
		t.Skip("lld-link not available")
	}
	dir := t.TempDir()
	source := filepath.Join(dir, "n.c")
	if err := os.WriteFile(source, []byte(
		"int helper_add(int a, int b) { return a + b; }\n"+
			"int compute(int a, int b) { return helper_add(a, b) * 2; }\n"+
			"int main(void) { return compute(2, 3); }\n"), 0600); err != nil {
		t.Fatal(err)
	}
	obj := filepath.Join(dir, "n.obj")
	exe := filepath.Join(dir, "n.exe")
	pdbPath := filepath.Join(dir, "n.pdb")
	for _, step := range [][]string{
		{"clang", "-target", "x86_64-pc-windows-msvc", "-O1", "-g", "-gcodeview", "-c", source, "-o", obj},
		{"lld-link", "/entry:main", "/subsystem:console", "/nodefaultlib", "/debug",
			"/pdb:" + pdbPath, "/out:" + exe, obj},
	} {
		command := exec.Command(step[0], step[1:]...)
		if output, err := command.CombinedOutput(); err != nil {
			t.Skipf("%s failed: %v: %s", step[0], err, output)
		}
	}
	result, err := Functions(exe, "", "", 0)
	if err != nil {
		t.Fatal(err)
	}
	named := map[string]string{}
	for _, function := range result.Images[0].Functions {
		if function.Name != "" {
			named[function.Name] = function.NameSource
		}
	}
	// S_GPROC32 records carry name, size and type, so they take precedence over the
	// public symbol table. Both sources are PDB-derived; assert the PDB origin rather
	// than one specific stream.
	for _, want := range []string{"helper_add", "compute", "main"} {
		source, ok := named[want]
		if !ok {
			t.Errorf("%q was not recovered from the PDB; named: %v", want, named)
			continue
		}
		if source != "pdb_procedure" && source != "pdb_public" {
			t.Errorf("%q came from %q, want a PDB source", want, source)
		}
	}
}

// TestPDBIdentityMismatchIsRejected proves the safety property: a PDB from a different
// build must not be used to name functions, because that attaches wrong names to wrong
// addresses. Both candidates point at the wrong file here, so the correct outcome is
// zero names plus an explicit warning.
func TestPDBIdentityMismatchIsRejected(t *testing.T) {
	for _, tool := range []string{"clang", "lld-link"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not available", tool)
		}
	}
	dir := t.TempDir()
	source := filepath.Join(dir, "good.c")
	if err := os.WriteFile(source, []byte(
		"int helper_add(int a, int b) { return a + b; }\nint main(void) { return helper_add(1, 2); }\n"), 0600); err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(dir, "other.c")
	if err := os.WriteFile(other, []byte(
		"int different_func(int a) { return a * 7; }\nint main(void) { return different_func(4); }\n"), 0600); err != nil {
		t.Fatal(err)
	}
	build := func(src, stem string) bool {
		obj := filepath.Join(dir, stem+".obj")
		exe := filepath.Join(dir, stem+".exe")
		for _, step := range [][]string{
			{"clang", "-target", "x86_64-pc-windows-msvc", "-O1", "-g", "-gcodeview", "-c", src, "-o", obj},
			{"lld-link", "/entry:main", "/subsystem:console", "/nodefaultlib", "/debug",
				"/pdb:" + filepath.Join(dir, stem+".pdb"), "/out:" + exe, obj},
		} {
			command := exec.Command(step[0], step[1:]...)
			if output, err := command.CombinedOutput(); err != nil {
				t.Skipf("%s failed: %v: %s", step[0], err, output)
			}
		}
		return true
	}
	if !build(source, "good") || !build(other, "other") {
		return
	}
	// Overwrite the good PDB with the mismatched one, so every candidate is wrong.
	mismatched, err := os.ReadFile(filepath.Join(dir, "other.pdb"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "good.pdb"), mismatched, 0600); err != nil {
		t.Fatal(err)
	}
	result, err := Functions(filepath.Join(dir, "good.exe"), "", "", 0)
	if err != nil {
		t.Fatal(err)
	}
	image := result.Images[0]
	if matched := image.PDB; matched != nil && matched.Matched {
		t.Fatalf("a mismatched PDB was reported as matching: %+v", matched)
	}
	named := 0
	for _, function := range image.Functions {
		if function.NameSource == "pdb_public" {
			named++
		}
	}
	if named != 0 {
		t.Fatalf("%d functions were named from a mismatched PDB", named)
	}
	found := false
	for _, warning := range image.Warnings {
		if strings.Contains(warning, "does not match") {
			found = true
		}
	}
	if !found {
		t.Fatalf("no mismatch warning; warnings: %v", image.Warnings)
	}
}
