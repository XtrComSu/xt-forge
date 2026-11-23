package sysimage

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// String-literal annotation, and the NOBITS bug it exposed.
//
// The first version of this feature reported a reference into `.bss` as the string
// "GCC: (GNU) 16.2.1". The target address was right; the mapping was not. `.bss` is
// SHT_NOBITS — it occupies memory but has no bytes in the file — yet elf.Section.FileSize
// reports its size, so address-to-file mapping treated it as file-backed and read whatever
// sat at that offset, which happened to be `.comment`.

func TestNOBITSSectionHasNoFileBytes(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "bss.c")
	if err := os.WriteFile(source, []byte(
		"static char buffer[512];\nint main(void) { buffer[0] = 1; return buffer[0]; }\n"), 0600); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(dir, "bss")
	command := exec.Command("clang", "-O1", source, "-o", binary)
	if output, err := command.CombinedOutput(); err != nil {
		t.Skipf("clang unavailable: %v: %s", err, output)
	}
	result, err := Overview(binary, "")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, section := range result.Images[0].Sections {
		if section.Name != ".bss" {
			continue
		}
		found = true
		if section.FileSize != 0 {
			t.Errorf(".bss reports file_size %d; a NOBITS section has no bytes in the file",
				section.FileSize)
		}
		if section.Size == 0 {
			t.Error(".bss has no size at all; the fixture should have populated one")
		}
	}
	if !found {
		t.Skip("fixture has no .bss section")
	}
}

func TestReferencesAnnotateStringLiterals(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "str.c")
	if err := os.WriteFile(source, []byte(`
#include <stdio.h>
__attribute__((noinline)) void report(int v) { printf("value=%d\n", v); }
__attribute__((noinline)) void warn(const char *m) { fprintf(stderr, "warn: %s\n", m); }
int main(void) { report(7); warn("careful"); return 0; }
`), 0600); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(dir, "strbin")
	if output, err := exec.Command("clang", "-O1", "-fno-inline", source, "-o", binary).CombinedOutput(); err != nil {
		t.Skipf("clang unavailable: %v: %s", err, output)
	}
	result, err := References(binary, ReferenceOptions{})
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, reference := range result.References {
		if reference.TargetSource == "rodata_string" {
			seen[reference.TargetName] = true
		}
	}
	for _, want := range []string{"value=%d\\n", "warn: %s\\n", "careful"} {
		if !seen[want] {
			t.Errorf("string %q not annotated; annotated: %v", want, seen)
		}
	}
	// The NOBITS bug produced a compiler-version string out of .comment.
	for name := range seen {
		if len(name) > 5 && name[:5] == "GCC: " {
			t.Errorf("a .bss reference was annotated with %q — NOBITS mapping is broken", name)
		}
	}
}
