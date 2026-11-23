package sysimage

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// Enum and modifier layouts are checked against real CodeView records and
// cross-checked with llvm-pdbutil dump -types, which prints the same values.

var (
	enumeratorLine = regexp.MustCompile(`LF_ENUMERATE\s+\[([^ ]+)\s*=\s*([0-9]+)\]`)
	enumNameLine   = regexp.MustCompile("LF_ENUM\\s+\\[[^]]*\\]\\s+`([^`]+)`")
)

func buildEnumsPDB(t *testing.T, dir, sourceName, code string) string {
	t.Helper()
	for _, tool := range []string{"clang", "lld-link"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not available", tool)
		}
	}
	source := filepath.Join(dir, sourceName)
	if err := os.WriteFile(source, []byte(code), 0600); err != nil {
		t.Fatal(err)
	}
	obj := filepath.Join(dir, "enums.obj")
	pdbPath := filepath.Join(dir, "enums.pdb")
	exe := filepath.Join(dir, "enums.exe")
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

func openTestPDB(t *testing.T, path string) (*os.File, int64) {
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

func TestReadPDBEnums(t *testing.T) {
	dir := t.TempDir()
	pdbPath := buildEnumsPDB(t, dir, "enums.c", `
enum Color { Red, Green = 5, Blue };
int shade(enum Color c) { return (int)c; }
int main(void) { return shade(Green); }
`)
	file, size := openTestPDB(t, pdbPath)
	enums, err := ReadPDBEnums(file, size, 0)
	if err != nil {
		t.Fatalf("enums: %v", err)
	}
	var color *PDBEnum
	for index := range enums {
		if enums[index].Name == "Color" {
			color = &enums[index]
		}
		t.Logf("%s", enums[index].Rendered)
	}
	if color == nil {
		t.Fatalf("enum Color not recovered; got %v", enums)
	}
	want := map[string]int64{"Red": 0, "Green": 5, "Blue": 6}
	got := map[string]int64{}
	for _, member := range color.Members {
		got[member.Name] = member.Value
	}
	if len(got) != len(want) {
		t.Fatalf("Color members = %v, want %v", color.Members, want)
	}
	for name, value := range want {
		if got[name] != value {
			t.Errorf("Color.%s = %d, want %d", name, got[name], value)
		}
	}
	if !strings.Contains(color.Rendered, "Color") {
		t.Errorf("Rendered = %q, want it to contain Color", color.Rendered)
	}

	// Cross-check the same records with llvm-pdbutil when it is installed.
	if _, err := exec.LookPath("llvm-pdbutil"); err != nil {
		t.Logf("skipping llvm-pdbutil cross-check: %v", err)
	} else {
		out, err := exec.Command("llvm-pdbutil", "dump", "-types", pdbPath).CombinedOutput()
		if err != nil {
			t.Logf("skipping llvm-pdbutil cross-check: %v", err)
		} else {
			// llvm-pdbutil prints LF_FIELDLIST (and its LF_ENUMERATE lines)
			// before the LF_ENUM that names it, so match by member name rather
			// than by the most recently seen enum name.
			ourMembers := map[string]int64{}
			for _, enum := range enums {
				for _, member := range enum.Members {
					ourMembers[member.Name] = member.Value
				}
			}
			compared := 0
			for _, line := range strings.Split(string(out), "\n") {
				if enumNameLine.MatchString(line) {
					continue
				}
				match := enumeratorLine.FindStringSubmatch(line)
				if match == nil {
					continue
				}
				value, err := strconv.ParseInt(match[2], 10, 64)
				if err != nil {
					continue
				}
				if found, ok := ourMembers[match[1]]; !ok {
					t.Errorf("llvm-pdbutil member %q missing from our output", match[1])
				} else if found != value {
					t.Errorf("%s: ours %d, llvm-pdbutil %d", match[1], found, value)
				}
				compared++
			}
			if compared == 0 {
				t.Error("no enumerators compared with llvm-pdbutil")
			}
			t.Logf("compared %d enumerators with llvm-pdbutil", compared)
		}
	}

	// A file that is not a PDB must fail cleanly, not panic.
	if _, err := ReadPDBEnums(bytes.NewReader([]byte("not a pdb")), 9, 0); err == nil {
		t.Error("non-PDB input: want an error, got nil")
	}
}

func TestReadPDBModifiers(t *testing.T) {
	dir := t.TempDir()
	pdbPath := buildEnumsPDB(t, dir, "mods.c", `
enum Color { Red, Green = 5, Blue };
int shade(const volatile int x, const enum Color c) { return x + (int)c; }
int main(void) { return shade(1, Red); }
`)
	file, size := openTestPDB(t, pdbPath)
	modifiers, err := ReadPDBModifiers(file, size, 0)
	if err != nil {
		t.Fatalf("modifiers: %v", err)
	}
	found := false
	for _, modifier := range modifiers {
		t.Logf("index=0x%x modified=%q attribute=%q", modifier.Index, modifier.Modified, modifier.Attribute)
		if strings.Contains(modifier.Modified, "int") && strings.Contains(modifier.Attribute, "const") && strings.Contains(modifier.Attribute, "volatile") {
			found = true
		}
	}
	if !found {
		t.Fatalf("const volatile int modifier not recovered; got %v", modifiers)
	}
	if _, err := ReadPDBModifiers(bytes.NewReader([]byte("not a pdb")), 9, 0); err == nil {
		t.Error("non-PDB input: want an error, got nil")
	}
}
