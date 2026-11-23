package sysimage

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Real 32-bit PE end-to-end measurement.
//
// The earlier PE32 evidence came from a clang-cl fixture. This test uses the real i386
// Windows DLLs installed with Wine: they carry genuine export tables, import descriptors
// and x86 code, so Overview -> Functions -> Disassemble -> Decompile are exercised on
// binaries the engine was never built around. No engine behaviour is changed here; the
// test reports what happens, including any file that fails.
//
// XTF_PE32_DIR selects the directory. It defaults to /usr/lib/wine/i386-windows when that
// directory exists, and skips cleanly when neither it nor the Go toolchain is present.

const defaultPE32Dir = "/usr/lib/wine/i386-windows"

func pe32RealDirectory(t *testing.T) (string, []string) {
	t.Helper()
	if _, err := exec.LookPath("go"); err != nil {
		t.Skipf("Go toolchain is not available: %v", err)
	}
	dir := os.Getenv("XTF_PE32_DIR")
	if dir == "" {
		if stat, err := os.Stat(defaultPE32Dir); err != nil || !stat.IsDir() {
			t.Skipf("default PE32 directory %s is absent", defaultPE32Dir)
		}
		dir = defaultPE32Dir
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Skipf("cannot read PE32 directory %s: %v", dir, err)
	}
	var files []string
	for _, entry := range entries {
		if entry.IsDir() || !strings.EqualFold(filepath.Ext(entry.Name()), ".dll") {
			continue
		}
		files = append(files, filepath.Join(dir, entry.Name()))
		if len(files) == 20 {
			break
		}
	}
	if len(files) == 0 {
		t.Skipf("no .dll files in %s", dir)
	}
	return dir, files
}

func TestPE32Real(t *testing.T) {
	dir, files := pe32RealDirectory(t)

	var failures []string
	parsed, functionsOK := 0, 0
	// The first DLL with an indexed function is the disassembly/decompilation subject.
	subject, subjectAddress := "", uint64(0)

	for _, path := range files {
		name := filepath.Base(path)
		overview, err := Overview(path, "")
		if err != nil {
			failures = append(failures, fmt.Sprintf("%s: Overview: %v", name, err))
			t.Errorf("%s: Overview: %v", name, err)
			continue
		}
		if overview.Format != "pe" || len(overview.Images) == 0 ||
			overview.Images[0].Bits != 32 || overview.Images[0].Arch != "x86" {
			format, bits, arch := overview.Format, -1, ""
			if len(overview.Images) != 0 {
				bits, arch = overview.Images[0].Bits, overview.Images[0].Arch
			}
			problem := fmt.Sprintf("%s: Overview format=%q bits=%d arch=%q, want pe/32/x86",
				name, format, bits, arch)
			failures = append(failures, problem)
			t.Error(problem)
			continue
		}
		parsed++

		// Function recovery through the public API, without reading a PDB by hand.
		index, err := Functions(path, "", "x86", 0)
		if err != nil || !index.OK || len(index.Images) == 0 {
			failures = append(failures, fmt.Sprintf("%s: Functions: ok=%v images=%d err=%v",
				name, index.OK, len(index.Images), err))
			t.Errorf("%s: Functions: ok=%v images=%d err=%v", name, index.OK, len(index.Images), err)
			continue
		}
		functionsOK++
		if subject == "" && len(index.Images[0].Functions) > 0 {
			subject = path
			subjectAddress = index.Images[0].Functions[0].Address
		}
	}

	if subject == "" {
		t.Fatalf("none of the %d real PE32 DLLs indexed a function", len(files))
	}

	target := fmt.Sprintf("0x%x", subjectAddress)
	opts := DisassemblyOptions{Target: target, Count: 8}
	disassembly, err := Disassemble(subject, opts)
	if err != nil {
		t.Fatalf("Disassemble(%s, %s): %v", filepath.Base(subject), target, err)
	}
	empty, opaque := 0, 0
	for _, instruction := range disassembly.Instructions {
		if instruction.Mnemonic == "" {
			empty++
		}
		if instruction.Mnemonic == "opaque" {
			opaque++
		}
	}
	totalInstructions := len(disassembly.Instructions)
	if totalInstructions == 0 {
		t.Fatalf("Disassemble(%s, %s): no instructions", filepath.Base(subject), target)
	}
	if empty != 0 {
		t.Errorf("%s: %d of %d instructions have an empty mnemonic", filepath.Base(subject), empty, totalInstructions)
	}
	opaqueRatio := float64(opaque) / float64(totalInstructions)
	if opaqueRatio > 0.20 {
		t.Errorf("%s: %d of %d instructions opaque (%.1f%%), want at most 20%%",
			filepath.Base(subject), opaque, totalInstructions, opaqueRatio*100)
	}

	decompilation, err := Decompile(subject, opts)
	if err != nil {
		failures = append(failures, fmt.Sprintf("%s: Decompile: %v", filepath.Base(subject), err))
		t.Fatalf("Decompile(%s, %s): %v", filepath.Base(subject), target, err)
	}
	decoded := decompilation.Coverage.Decoded
	decompiled := 0
	if decoded > 0 {
		decompiled = 1
	}
	if decoded == 0 {
		failures = append(failures, fmt.Sprintf("%s: Decompile: coverage.decoded = 0", filepath.Base(subject)))
		t.Errorf("%s: Decompile: coverage.decoded = 0", filepath.Base(subject))
	}

	if len(failures) != 0 {
		t.Logf("PE32 failures (%d): %s", len(failures), strings.Join(failures, " | "))
	}
	t.Logf("PE32 REAL SUMMARY: dir=%s candidates=%d files_parsed=%d files_functions_ok=%d "+
		"files_disassembled=1 files_decompiled=%d subject=%s@%s "+
		"instructions_decoded=%d/%d coverage_decoded=%d opaque=%d/%d (%.1f%%) "+
		"empty_mnemonics=%d failures=%d",
		dir, len(files), parsed, functionsOK, decompiled,
		filepath.Base(subject), target, totalInstructions-empty, totalInstructions, decoded,
		opaque, totalInstructions, opaqueRatio*100, empty, len(failures))
}
