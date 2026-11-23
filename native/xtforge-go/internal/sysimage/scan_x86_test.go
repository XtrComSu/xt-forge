package sysimage

import (
	"bytes"
	"encoding/binary"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

// putX86Call writes a direct E8 rel32 call at "at" whose target is "target".
func putX86Call(code []byte, at int, pc, target uint64) {
	code[at] = 0xE8
	rel := int64(target) - int64(pc) - 5
	binary.LittleEndian.PutUint32(code[at+1:at+5], uint32(int32(rel)))
}

func x86ScanFixture(code []byte, base uint64) *Image {
	region := Region{
		Name: ".text", Address: base, Size: uint64(len(code)),
		Offset: 0, FileSize: uint64(len(code)),
	}
	return &Image{
		Arch: "x86_64", Bits: 64, functions: map[uint64]Function{},
		Segments: []Region{region}, Executable: []Region{region}, fileSize: uint64(len(code)),
	}
}

// TestScanX86CallTargetsSynthetic pins the four decisions in one hand-built region: an
// in-range target is kept, an out-of-range target is rejected, a duplicate collapses into
// one entry, and the later of two starts four bytes apart is dropped while an eight-byte
// gap is kept.
func TestScanX86CallTargetsSynthetic(t *testing.T) {
	const base = 0x1000
	code := make([]byte, 0x80)
	for i := range code {
		code[i] = 0x90 // nop: no accidental E8 in the filler
	}
	putX86Call(code, 0x00, base+0x00, base+0x40)   // in-range
	putX86Call(code, 0x05, base+0x05, base+0x9000) // out of the executable region
	putX86Call(code, 0x0A, base+0x0A, base+0x50)   // first of the adjacent pair
	putX86Call(code, 0x0F, base+0x0F, base+0x54)   // exactly four bytes later: drop
	putX86Call(code, 0x14, base+0x14, base+0x50)   // duplicate of 0x1050
	putX86Call(code, 0x19, base+0x19, base+0x58)   // eight bytes after the pair: keep

	image := x86ScanFixture(code, base)
	added := scanX86CallTargets(image, bytes.NewReader(code), 0)
	if added != 3 {
		t.Fatalf("added %d functions, want 3 (in-range, pair head, 8-byte gap)", added)
	}
	for _, tc := range []struct {
		address uint64
		want    bool
	}{
		{base + 0x40, true},  // in-range call target
		{base + 0x50, true},  // first of the adjacent pair; duplicate deduped
		{base + 0x54, false}, // four bytes after an earlier start
		{base + 0x58, true},  // eight bytes after an earlier start
		{base + 0x9000, false},
	} {
		function, ok := image.functions[tc.address]
		if ok != tc.want {
			t.Errorf("target 0x%x present=%v, want %v", tc.address, ok, tc.want)
			continue
		}
		if ok && function.Source != "x86_call_target" {
			t.Errorf("target 0x%x has source %q, want x86_call_target", tc.address, function.Source)
		}
		if ok && function.Name != "" {
			t.Errorf("target 0x%x was given invented name %q", tc.address, function.Name)
		}
	}
}

func TestScanX86CallTargetsSkipsNonX86(t *testing.T) {
	for _, tc := range []struct {
		name string
		arch string
		bits int
	}{
		{"arm64", "arm64", 64},
		{"32-bit x86", "x86", 32},
		{"32-bit i386", "x86_64", 32},
	} {
		t.Run(tc.name, func(t *testing.T) {
			region := Region{Address: 0x1000, Size: 64, FileSize: 64}
			image := &Image{
				Arch: tc.arch, Bits: tc.bits, functions: map[uint64]Function{},
				Segments: []Region{region}, Executable: []Region{region}, fileSize: 64,
			}
			if added := scanX86CallTargets(image, bytes.NewReader(make([]byte, 64)), 0); added != 0 {
				t.Fatalf("scanned a non-x86-64 image: %d", added)
			}
		})
	}
}

func TestScanX86CallTargetsRespectsLimit(t *testing.T) {
	const base = 0x2000
	code := make([]byte, 0x100)
	for i := range code {
		code[i] = 0x90
	}
	for i := 0; i+5 <= 0x40; i += 8 {
		putX86Call(code, i, base+uint64(i), base+0x80)
	}
	image := x86ScanFixture(code, base)
	if added := scanX86CallTargets(image, bytes.NewReader(code), 1); added != 1 {
		t.Fatalf("added %d with limit 1, want 1", added)
	}
}

// TestScanX86CallTargetsDenseELFNotScanned checks the trigger's other side: a normal
// -O1 ELF has dense function metadata (dynsym plus .eh_frame), so the heuristic pass
// must not add a single x86_call_target entry to its index.
func TestScanX86CallTargetsDenseELFNotScanned(t *testing.T) {
	if runtime.GOARCH != "amd64" {
		t.Skip("clang on this host would not produce an x86-64 ELF")
	}
	clang, err := exec.LookPath("clang")
	if err != nil {
		t.Skip("clang is not installed")
	}
	dir := t.TempDir()
	source := filepath.Join(dir, "tiny.c")
	program := `#include <stdio.h>
static int add(int a, int b) { return a + b; }
int main(int argc, char **argv) {
    if (argc > 1) puts(argv[0]);
    return add(argc, 1);
}
`
	if err := os.WriteFile(source, []byte(program), 0o600); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(dir, "tiny")
	if out, err := exec.Command(clang, "-O1", "-o", binary, source).CombinedOutput(); err != nil {
		t.Skipf("clang -O1 could not build the fixture: %v: %s", err, out)
	}
	result, err := analyze(binary, "", true)
	if err != nil {
		t.Fatal(err)
	}
	total, heuristic, executableBytes := 0, 0, uint64(0)
	for _, image := range result.Images {
		total += len(image.functions)
		for _, region := range image.Executable {
			executableBytes += region.FileSize
		}
		for _, function := range image.functions {
			if function.Source == "x86_call_target" {
				heuristic++
			}
		}
	}
	if total == 0 {
		t.Fatal("the -O1 ELF yielded no functions; a dense-trigger test would be vacuous")
	}
	if heuristic != 0 {
		t.Fatalf("the dense ELF gained %d x86_call_target functions; trigger should not fire", heuristic)
	}
	t.Logf("dense -O1 ELF: %d functions, %d executable bytes, %d added by x86 scan",
		total, executableBytes, heuristic)
}

// TestScanX86CallTargetsRealBinary validates against a real large stripped x86-64
// binary. Set XTF_REAL_X86 to its path (for example /usr/bin/opencode).
func TestScanX86CallTargetsRealBinary(t *testing.T) {
	path := os.Getenv("XTF_REAL_X86")
	if path == "" {
		t.Skip("set XTF_REAL_X86 to a large stripped x86-64 binary to run this test")
	}
	result, err := analyze(path, "", true)
	if err != nil {
		t.Fatal(err)
	}
	executableBytes, heuristic, total := uint64(0), 0, 0
	for _, image := range result.Images {
		total += len(image.functions)
		for _, region := range image.Executable {
			executableBytes += region.FileSize
		}
		for _, function := range image.functions {
			if function.Source == "x86_call_target" {
				heuristic++
			}
		}
	}
	if executableBytes == 0 {
		t.Fatal("no file-backed executable bytes found")
	}
	if heuristic <= 1000 {
		t.Fatalf("x86 scan added only %d functions, want more than 1000", heuristic)
	}
	// A function needs at least eight bytes of body, so more than one start per eight
	// executable bytes would be nonsense.
	if uint64(heuristic) > executableBytes/8 {
		t.Fatalf("x86 scan added %d functions for %d executable bytes (limit %d)",
			heuristic, executableBytes, executableBytes/8)
	}
	t.Logf("real x86-64 binary %s: %d executable bytes, %d functions total, %d added by x86 scan",
		path, executableBytes, total, heuristic)
}
