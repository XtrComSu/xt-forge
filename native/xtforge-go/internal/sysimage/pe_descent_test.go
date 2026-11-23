package sysimage

import (
	"bytes"
	"os"
	"sort"
	"testing"
	"time"
)

const (
	peDescentPE32 = "/usr/lib/wine/i386-windows/kernel32.dll"
	peDescentPE64 = "/usr/lib/wine/x86_64-windows/kernel32.dll"
)

// TestPEDescentPE32Real measures the sparse case: Wine's i386 kernel32.dll
// indexes essentially its export table, and direct calls reach internal
// functions no PE directory names.
func TestPEDescentPE32Real(t *testing.T) {
	if _, err := os.Stat(peDescentPE32); err != nil {
		t.Skipf("%s is not installed: %v", peDescentPE32, err)
	}
	start := time.Now()
	result, err := Functions(peDescentPE32, "", "", 200000)
	if err != nil || len(result.Images) == 0 {
		t.Fatalf("Functions(%s): images=%d err=%v", peDescentPE32, len(result.Images), err)
	}
	elapsed := time.Since(start)
	functions := result.Images[0].Functions
	present := make(map[uint64]bool, len(functions))
	before, added := 0, 0
	for _, function := range functions {
		present[function.Address] = true
		if function.Source == "pe_descent" {
			added++
		} else {
			before++
		}
	}
	if len(functions) < 2000 {
		t.Errorf("i386 kernel32.dll: %d indexed functions, want at least 2000 (before descent %d)",
			len(functions), before)
	}
	overview, err := Overview(peDescentPE32, "")
	if err != nil || len(overview.Images) == 0 {
		t.Fatalf("Overview(%s): %v", peDescentPE32, err)
	}
	exports := overview.Images[0].Exports
	missing := 0
	var firstMissing uint64
	for _, export := range exports {
		if export.Address == 0 || present[export.Address] {
			continue
		}
		missing++
		if firstMissing == 0 || export.Address < firstMissing {
			firstMissing = export.Address
		}
	}
	if missing != 0 {
		t.Errorf("%d of %d exports lost from the index (first %#x)", missing, len(exports), firstMissing)
	}
	t.Logf("i386 kernel32.dll: %d before, %d after, %d added by descent, %d exports checked, %v elapsed",
		before, len(functions), added, len(exports), elapsed)
}

// TestPEDescentX64Unchanged pins the gate: x86-64 kernel32.dll already indexes
// every .pdata begin, so descent must neither fire nor disturb those entries.
func TestPEDescentX64Unchanged(t *testing.T) {
	if _, err := os.Stat(peDescentPE64); err != nil {
		t.Skipf("%s is not installed: %v", peDescentPE64, err)
	}
	declared := peDataStarts(t, peDescentPE64)
	if len(declared) == 0 {
		t.Skip("no .pdata entries in the 64-bit sample")
	}
	start := time.Now()
	result, err := Functions(peDescentPE64, "", "", 200000)
	if err != nil || len(result.Images) == 0 {
		t.Fatalf("Functions(%s): images=%d err=%v", peDescentPE64, len(result.Images), err)
	}
	elapsed := time.Since(start)
	functions := result.Images[0].Functions
	present := make(map[uint64]bool, len(functions))
	added, pdata := 0, 0
	for _, function := range functions {
		present[function.Address] = true
		if function.Source == "pe_descent" {
			added++
		}
		if function.Source == "pe_exception_directory" {
			pdata++
		}
	}
	if len(functions) != 2776 {
		t.Errorf("x86-64 kernel32.dll: %d indexed functions, want unchanged 2776", len(functions))
	}
	if added != 0 {
		t.Errorf("x86-64 kernel32.dll gained %d descent entries; the gate should not fire", added)
	}
	missing := 0
	for address := range declared {
		if !present[address] {
			missing++
		}
	}
	if missing != 0 {
		t.Errorf("%d of %d .pdata begins missing", missing, len(declared))
	}
	t.Logf("x86-64 kernel32.dll: %d before and after, %d added by descent, %d .pdata entries (%d indexed), %v elapsed",
		len(functions), added, len(declared), pdata, elapsed)
}

// TestPEDescentDeterministic compares the address sets of two independent
// indexing runs. A real sparse DLL is used when installed; a small synthetic
// image keeps the check meaningful elsewhere.
func TestPEDescentDeterministic(t *testing.T) {
	if _, err := os.Stat(peDescentPE32); err == nil {
		first, err := analyze(peDescentPE32, "", true)
		if err != nil || len(first.Images) == 0 {
			t.Fatalf("first pass: %v", err)
		}
		second, err := analyze(peDescentPE32, "", true)
		if err != nil || len(second.Images) == 0 {
			t.Fatalf("second pass: %v", err)
		}
		a, b := descentAddresses(first.Images[0].functions), descentAddresses(second.Images[0].functions)
		if len(a) != len(b) {
			t.Fatalf("two passes returned %d and %d functions", len(a), len(b))
		}
		for i := range a {
			if a[i] != b[i] {
				t.Fatalf("two passes disagree at %d: %#x vs %#x", i, a[i], b[i])
			}
		}
		t.Logf("two passes over i386 kernel32.dll returned the same %d addresses", len(a))
		return
	}

	code := descentFixtureCode()
	first := descentFixture(code)
	second := descentFixture(code)
	if got, want := RecoverFunctionsByDescent(first, bytes.NewReader(code), 0),
		RecoverFunctionsByDescent(second, bytes.NewReader(code), 0); got != want {
		t.Fatalf("descent added %d and %d functions in two runs", got, want)
	}
	a, b := descentAddresses(first.functions), descentAddresses(second.functions)
	for i := range a {
		if a[i] != b[i] {
			t.Fatalf("two passes disagree at %d: %#x vs %#x", i, a[i], b[i])
		}
	}
}

// TestPEDescentZeroImage proves a zero-filled region contributes no starts and
// terminates: decoding zeros as x86 instructions would otherwise walk forever.
func TestPEDescentZeroImage(t *testing.T) {
	code := make([]byte, 4096)
	image := descentFixture(code)
	if added := RecoverFunctionsByDescent(image, bytes.NewReader(code), 0); added != 0 {
		t.Fatalf("zero image added %d functions, want 0", added)
	}
	if len(image.functions) != 1 {
		t.Fatalf("zero image has %d functions, want only the seed", len(image.functions))
	}
}

func descentAddresses(functions map[uint64]Function) []uint64 {
	addresses := make([]uint64, 0, len(functions))
	for address := range functions {
		addresses = append(addresses, address)
	}
	sort.Slice(addresses, func(i, j int) bool { return addresses[i] < addresses[j] })
	return addresses
}

func descentFixture(code []byte) *Image {
	const base = 0x1000
	region := Region{Name: ".text", Address: base, Size: uint64(len(code)), Offset: 0, FileSize: uint64(len(code))}
	image := &Image{
		Arch: "x86", Bits: 32, functions: map[uint64]Function{},
		Segments: []Region{region}, Executable: []Region{region}, fileSize: uint64(len(code)),
	}
	image.addFunction(base, 0, "", "test_seed")
	return image
}

// descentFixtureCode has a seed that calls a push-ebp function, which calls a
// third one, followed by returns and alignment padding.
func descentFixtureCode() []byte {
	const base = 0x1000
	code := make([]byte, 0x100)
	for i := range code {
		code[i] = 0xCC
	}
	putX86Call(code, 0x00, base, base+0x40) // defined in scan_x86_test.go
	code[0x05] = 0xC3
	copy(code[0x40:], []byte{0x55, 0x89, 0xE5, 0x90, 0x90, 0x90})
	putX86Call(code, 0x46, base+0x46, base+0x80)
	code[0x4B] = 0xC3
	copy(code[0x80:], []byte{0x55, 0x89, 0xE5, 0x5D, 0xC3})
	return code
}
