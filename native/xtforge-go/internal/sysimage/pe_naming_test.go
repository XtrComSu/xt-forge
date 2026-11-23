package sysimage

import (
	"debug/pe"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// helper_add calls a non-leaf helper so the ARM64 compiler emits .pdata; the
// linker is asked to export helper_add through the PE export directory.
const peExportTestSource = `
int helper_inner(int a) {
    volatile int buf[16];
    for (int i = 0; i < 16; ++i) buf[i] = a + i;
    return buf[3] + buf[7];
}
int helper_add(int a, int b) { return helper_inner(a) + b; }
int main(void) { return helper_add(1, 2); }
`

// buildPEWithExport compiles a Windows ARM64 PE at test time. The test skips
// when the toolchain is missing; a build failure is reported as a failure.
func buildPEWithExport(t *testing.T) string {
	t.Helper()
	clang, err := exec.LookPath("clang")
	if err != nil {
		t.Skipf("clang is unavailable: %v", err)
	}
	linker, err := exec.LookPath("lld-link")
	if err != nil {
		t.Skipf("lld-link is unavailable: %v", err)
	}

	dir := t.TempDir()
	source := filepath.Join(dir, "x.c")
	object := filepath.Join(dir, "x.obj")
	executable := filepath.Join(dir, "x.exe")
	if err := os.WriteFile(source, []byte(peExportTestSource), 0o600); err != nil {
		t.Fatal(err)
	}
	steps := []struct {
		tool string
		args []string
	}{
		{clang, []string{"-target", "arm64-pc-windows-msvc", "-O1", "-funwind-tables", "-c", source, "-o", object}},
		{linker, []string{"/entry:main", "/subsystem:console", "/nodefaultlib", "/dll", "/export:helper_add", "/out:" + executable, object}},
	}
	for _, step := range steps {
		output, err := exec.Command(step.tool, step.args...).CombinedOutput()
		if err != nil {
			t.Fatalf("%s failed: %v\n%s", step.tool, err, output)
		}
	}
	return executable
}

func TestPEExportNamesFunction(t *testing.T) {
	executable := buildPEWithExport(t)
	result, err := Functions(executable, "", "arm64", 200)
	if err != nil {
		t.Fatalf("Functions(%q): %v", executable, err)
	}
	if len(result.Images) != 1 {
		t.Fatalf("Functions() returned %d images, want 1", len(result.Images))
	}
	named := false
	for _, fn := range result.Images[0].Functions {
		if fn.Name != "helper_add" {
			continue
		}
		named = true
		if fn.NameSource != "pe_export" {
			t.Errorf("helper_add name source = %q, want %q", fn.NameSource, "pe_export")
		}
	}
	if !named {
		t.Fatalf("built PE has no function named helper_add; functions: %#v", result.Images[0].Functions)
	}
}

func TestPEExportNamingSkipsMalformedDirectories(t *testing.T) {
	handle, err := os.Open(buildPEWithExport(t))
	if err != nil {
		t.Fatal(err)
	}
	defer handle.Close()
	parsed, err := pe.NewFile(handle)
	if err != nil {
		t.Fatal(err)
	}
	// Keep a real section reader, but shrink the raw bytes so an oversized
	// directory size has to be clamped instead of indexing past the section.
	section := parsed.Sections[0]
	section.SectionHeader.Size = 4

	address := uint64(0x180001000)
	image := &Image{functions: map[uint64]Function{address: {Address: address, Source: "pe_exception_directory"}}}
	file := &pe.File{Sections: []*pe.Section{nil, section}}
	for _, directory := range []pe.DataDirectory{
		{},                                    // zero size
		{VirtualAddress: 0x1000},              // zero size with an RVA
		{VirtualAddress: 0x9000, Size: 0x100}, // outside every section
		{VirtualAddress: 0x1000, Size: 0x100}, // extends past section bytes
	} {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("namePEExports(%#v) panicked: %v", directory, r)
				}
			}()
			namePEExports(image, file, directory, 0x180000000)
		}()
		if got := image.functions[address].Name; got != "" {
			t.Fatalf("namePEExports(%#v) wrote name %q to an unlisted address", directory, got)
		}
	}
	namePEExports(image, nil, pe.DataDirectory{VirtualAddress: 0x1000, Size: 0x100}, 0)
	namePEExports(nil, file, pe.DataDirectory{VirtualAddress: 0x1000, Size: 0x100}, 0)
}
