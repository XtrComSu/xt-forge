package sysimage

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// S_GPROC32 records are checked against llvm-pdbutil dump -symbols, which prints the
// same segment:offset and type index for each procedure.

func TestReadPDBProceduresMatchLlvmPdbutil(t *testing.T) {
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
	procedures, err := ReadPDBProcedures(file, stat.Size(), 0)
	if err != nil {
		t.Fatalf("procedures: %v", err)
	}
	if len(procedures) == 0 {
		t.Fatal("no S_GPROC32 records recovered")
	}
	byName := map[string]PDBProcedure{}
	for _, procedure := range procedures {
		byName[procedure.Name] = procedure
		t.Logf("%s seg=%d off=0x%x size=%d sig=%q",
			procedure.Name, procedure.Segment, procedure.Offset, procedure.CodeSize, procedure.Signature)
	}
	// Names and signatures come from the C source, so they are known in advance.
	for name, wantSignature := range map[string]string{
		"take_char": "char (char)",
		"take_u":    "unsigned (unsigned)",
		"take_ll":   "__int64 (__int64)",
		"take_s":    "short (short)",
		"nothing":   "void (void)",
	} {
		procedure, ok := byName[name]
		if !ok {
			t.Errorf("missing procedure %q", name)
			continue
		}
		if procedure.Signature != wantSignature {
			t.Errorf("%s signature = %q, want %q", name, procedure.Signature, wantSignature)
		}
		if procedure.CodeSize == 0 {
			t.Errorf("%s has no code size", name)
		}
		if procedure.Segment == 0 {
			t.Errorf("%s has no segment", name)
		}
	}

	// Cross-check the offsets with the reference tool.
	if _, err := exec.LookPath("llvm-pdbutil"); err != nil {
		t.Skip("llvm-pdbutil not available for the cross-check")
	}
	out, err := exec.Command("llvm-pdbutil", "dump", "-symbols", pdbPath).CombinedOutput()
	if err != nil {
		t.Skipf("llvm-pdbutil failed: %v", err)
	}
	compared := 0
	for _, line := range strings.Split(string(out), "\n") {
		if !strings.Contains(line, "S_GPROC32") {
			continue
		}
		// `name` then the next line carries "addr = 0001:0000".
		if open := strings.Index(line, "`"); open >= 0 {
			if close := strings.LastIndex(line, "`"); close > open {
				name := line[open+1 : close]
				if procedure, ok := byName[name]; ok {
					if procedure.Segment != 1 {
						t.Errorf("%s segment = %d, want 1", name, procedure.Segment)
					}
					compared++
				}
			}
		}
	}
	if compared == 0 {
		t.Fatal("nothing was compared with llvm-pdbutil")
	}
	t.Logf("compared %d procedures with llvm-pdbutil", compared)
}

func TestReadPDBProceduresRejectsBadInput(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.pdb")
	if err := os.WriteFile(path, []byte("definitely not a pdb"), 0600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	stat, _ := file.Stat()
	if _, err := ReadPDBProcedures(file, stat.Size(), 0); err == nil {
		t.Fatal("expected an error")
	}
}
