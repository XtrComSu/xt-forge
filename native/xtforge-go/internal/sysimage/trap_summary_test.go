package sysimage

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// A `svc` stub must summarise as a void callee.
//
// The walk had no `trap` case, so `void trap(void){ svc }` returned a nil summary and every
// caller of it declined with `call could not be summarised under the calling convention` —
// which read like a caller problem and was not. The trap case now ends the body without
// claiming a return value, because the encoding does not say whether a supervisor call
// returns or exits and inventing one would be a guess.
//
// This pins the callee's own summary and the caller's decline moving past it.
func TestTrapStubSummarisesAsVoidCallee(t *testing.T) {
	if _, err := exec.LookPath("clang"); err != nil {
		t.Skip("clang unavailable")
	}
	dir := t.TempDir()
	source := filepath.Join(dir, "stub.c")
	if err := os.WriteFile(source, []byte(
		"void trap(void){ __asm__ volatile(\"svc #0\"); }\n"+
			"void caller(void){ trap(); }\n"+
			"int main(void){ caller(); return 0; }\n"), 0600); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(dir, "stub")
	build := exec.Command("clang", "-target", "thumbv7-none-eabi", "-mthumb", "-O1",
		"-fno-inline", "-nostdlib", "-fuse-ld=lld", "-Wl,-e,main", source, "-o", binary)
	if output, err := build.CombinedOutput(); err != nil {
		t.Skipf("cannot link Thumb fixture: %v: %s", err, output)
	}

	overview, err := Overview(binary, "")
	if err != nil {
		t.Fatal(err)
	}
	entry := overview.Images[0].EntryPoint
	if entry == nil {
		t.Fatal("fixture has no entry point")
	}

	// Find the trap stub: the function that disassembles to a single svc.
	result, err := Functions(binary, "", "", 200)
	if err != nil {
		t.Fatal(err)
	}
	trapAt := uint64(0)
	for _, function := range result.Images[0].Functions {
		decoded, err := Disassemble(binary, DisassemblyOptions{
			Target: "0x" + hexString(function.Address), Count: 4})
		if err != nil || len(decoded.Instructions) == 0 {
			continue
		}
		if strings.HasPrefix(decoded.Instructions[0].Mnemonic, "svc") {
			trapAt = function.Address
			break
		}
	}
	if trapAt == 0 {
		t.Skip("fixture has no svc stub the engine indexes")
	}

	stub, err := Decompile(binary, DisassemblyOptions{Target: "0x" + hexString(trapAt)})
	if err != nil {
		t.Fatalf("decompile stub: %v", err)
	}
	if stub.StructuredDeclined != "" {
		t.Errorf("svc stub declined: %s", stub.StructuredDeclined)
	}

	caller, err := Decompile(binary, DisassemblyOptions{Target: "0x" + hexString(*entry)})
	if err != nil {
		t.Fatalf("decompile entry: %v", err)
	}
	if strings.Contains(caller.StructuredDeclined, "trap") {
		t.Errorf("caller still blames the trap stub: %s", caller.StructuredDeclined)
	}
	t.Logf("stub declined=%q caller declined=%q", stub.StructuredDeclined, caller.StructuredDeclined)
}

// hexString renders an address for DisassemblyOptions.Target, which takes text.
func hexString(value uint64) string {
	const digits = "0123456789abcdef"
	if value == 0 {
		return "0"
	}
	var out [16]byte
	position := len(out)
	for value > 0 {
		position--
		out[position] = digits[value&0xf]
		value >>= 4
	}
	return string(out[position:])
}

// TestCalleeDeclineReasonIsReported pins the diagnostic added when the resolver stopped
// discarding it.
//
// Before this, a caller that could not be summarised reported only
// "call could not be summarised under the calling convention" — the same string whether the
// callee was missing, loop-shaped or opaque. Six rounds went into locating a cause that the
// resolver already knew and threw away. The caller now names the callee and its reason.
func TestCalleeDeclineReasonIsReported(t *testing.T) {
	if _, err := exec.LookPath("clang"); err != nil {
		t.Skip("clang unavailable")
	}
	dir := t.TempDir()
	source := filepath.Join(dir, "loop.c")
	if err := os.WriteFile(source, []byte(
		"int sum(int n){ int s = 0; for (int i = 0; i < n; i++) s += i; return s; }\n"+
			"int main(void){ return sum(3); }\n"), 0600); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(dir, "loop")
	build := exec.Command("clang", "-target", "thumbv7-none-eabi", "-mthumb", "-O1",
		"-fno-inline", "-nostdlib", "-fuse-ld=lld", "-Wl,-e,main", source, "-o", binary)
	if output, err := build.CombinedOutput(); err != nil {
		t.Skipf("cannot link Thumb fixture: %v: %s", err, output)
	}
	overview, err := Overview(binary, "")
	if err != nil {
		t.Fatal(err)
	}
	if overview.Images[0].EntryPoint == nil {
		t.Skip("fixture has no entry point")
	}
	result, err := Decompile(binary, DisassemblyOptions{
		Target: "0x" + hexString(*overview.Images[0].EntryPoint)})
	if err != nil {
		t.Fatalf("decompile: %v", err)
	}
	if result.StructuredDeclined == "" {
		t.Skip("caller summarised; nothing to report")
	}
	mentioned := false
	for _, warning := range result.Warnings {
		if strings.HasPrefix(warning, "callee 0x") && strings.Count(warning, ":") >= 1 {
			mentioned = true
			t.Logf("reported: %s", warning)
		}
	}
	if !mentioned {
		t.Errorf("decline %q carried no callee reason; warnings: %v",
			result.StructuredDeclined, result.Warnings)
	}
}
