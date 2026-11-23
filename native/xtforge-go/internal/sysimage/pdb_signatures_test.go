package sysimage

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// Signatures are checked against llvm-pdbutil, which renders the same records
// independently. Comparing our text with its text is the only way to catch a decoder
// that is self-consistently wrong.

func buildSignaturePDB(t *testing.T, dir string) string {
	t.Helper()
	for _, tool := range []string{"clang", "lld-link"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not available", tool)
		}
	}
	source := filepath.Join(dir, "sig.c")
	if err := os.WriteFile(source, []byte(`
void nothing(void) { }
char take_char(char c) { return c; }
unsigned int take_u(unsigned int u) { return u; }
long long take_ll(long long v) { return v; }
short take_s(short s) { return s; }
int main(void) { nothing(); return take_char(1) + take_u(2) + (int)take_ll(3) + take_s(4); }
`), 0600); err != nil {
		t.Fatal(err)
	}
	obj := filepath.Join(dir, "sig.obj")
	pdbPath := filepath.Join(dir, "sig.pdb")
	exe := filepath.Join(dir, "sig.exe")
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

func TestReadPDBSignaturesDecodesKnownTypes(t *testing.T) {
	dir := t.TempDir()
	pdbPath := buildSignaturePDB(t, dir)
	file, err := os.Open(pdbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	stat, err := file.Stat()
	if err != nil {
		t.Fatal(err)
	}
	signatures, err := ReadPDBSignatures(file, stat.Size(), 0)
	if err != nil {
		t.Fatalf("signatures: %v", err)
	}
	if len(signatures) == 0 {
		t.Fatal("no procedures decoded")
	}
	rendered := map[string]bool{}
	for _, signature := range signatures {
		rendered[signature.Rendered] = true
		t.Logf("0x%x -> %s   (cc=%s)", signature.Index, signature.Rendered, signature.CallingConvention)
	}
	// These four render entirely from verified primitive types, so they must be exact.
	for _, want := range []string{
		"void (void)",
		"char (char)",
		"unsigned (unsigned)",
		"__int64 (__int64)",
		"short (short)",
	} {
		if !rendered[want] {
			t.Errorf("missing signature %q; got %v", want, rendered)
		}
	}
}

// TestReadPDBSignaturesMatchLlvmPdbutil compares return types with the reference tool
// for every procedure both implementations report.
func TestReadPDBSignaturesMatchLlvmPdbutil(t *testing.T) {
	if _, err := exec.LookPath("llvm-pdbutil"); err != nil {
		t.Skip("llvm-pdbutil not available")
	}
	dir := t.TempDir()
	pdbPath := buildSignaturePDB(t, dir)
	file, err := os.Open(pdbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	stat, err := file.Stat()
	if err != nil {
		t.Fatal(err)
	}
	signatures, err := ReadPDBSignatures(file, stat.Size(), 0)
	if err != nil {
		t.Fatalf("signatures: %v", err)
	}
	ours := map[uint32]string{}
	for _, signature := range signatures {
		ours[signature.Index] = signature.ReturnType
	}
	out, err := exec.Command("llvm-pdbutil", "dump", "-types", pdbPath).CombinedOutput()
	if err != nil {
		t.Skipf("llvm-pdbutil failed: %v", err)
	}
	// Lines look like: "0x1003 | LF_PROCEDURE [size = 16]" followed by
	// "return type = 0x0070 (char), # args = 1, param list = 0x1002".
	lines := strings.Split(string(out), "\n")
	checked := 0
	for index, line := range lines {
		trimmed := strings.TrimSpace(line)
		if !strings.Contains(trimmed, "LF_PROCEDURE") || !strings.HasPrefix(trimmed, "0x") {
			continue
		}
		// The line is "0x1003 | LF_PROCEDURE [size = 16]"; Sscanf cannot be used
		// because Go's %x does not consume the "0x" prefix here.
		head := strings.TrimPrefix(trimmed, "0x")
		if space := strings.IndexAny(head, " \t|"); space > 0 {
			head = head[:space]
		}
		parsed, err := strconv.ParseUint(head, 16, 32)
		if err != nil {
			continue
		}
		recordIndex := uint32(parsed)
		if index+1 >= len(lines) {
			continue
		}
		detail := strings.TrimSpace(lines[index+1])
		// Extract the "(name)" that follows the return type index.
		open := strings.Index(detail, "(")
		closeIndex := strings.Index(detail, ")")
		if open < 0 || closeIndex < open {
			continue
		}
		reference := detail[open+1 : closeIndex]
		got, ok := ours[recordIndex]
		if !ok {
			t.Errorf("procedure 0x%x missing from our output", recordIndex)
			continue
		}
		if got != reference {
			t.Errorf("procedure 0x%x: ours %q, llvm-pdbutil %q", recordIndex, got, reference)
		}
		checked++
	}
	if checked == 0 {
		t.Fatal("nothing was compared")
	}
	t.Logf("compared %d return types with llvm-pdbutil", checked)
}

func TestReadPDBSignaturesRejectsBadInput(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.pdb")
	if err := os.WriteFile(path, []byte("not a pdb at all, just text"), 0600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	stat, _ := file.Stat()
	if _, err := ReadPDBSignatures(file, stat.Size(), 0); err == nil {
		t.Fatal("expected an error for a non-PDB")
	}
}
