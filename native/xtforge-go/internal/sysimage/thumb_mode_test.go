package sysimage

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Thumb mode wiring.
//
// The decoder itself is verified against llvm-objdump in thumb_test.go. What these tests
// cover is the part that makes it reachable: a real Thumb binary must be *detected* as
// Thumb from the entry point's low bit, and the disassembler must then use the Thumb
// decoder rather than A32 over the same bytes.

func buildThumbExecutable(t *testing.T, dir string) string {
	t.Helper()
	for _, tool := range []string{"clang", "llvm-objdump"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not available", tool)
		}
	}
	source := filepath.Join(dir, "thumb.c")
	if err := os.WriteFile(source, []byte(`
struct P { int a; int b; };
int sum(int *v, int n) { int s = 0; for (int i = 0; i < n; i++) s += v[i]; return s; }
int main(void) { struct P p = {1, 2}; return sum(&p.a, 2); }
`), 0600); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(dir, "thumb_exe")
	command := exec.Command("clang", "-target", "thumbv7-none-eabi", "-mthumb", "-O1",
		"-fno-inline", "-nostdlib", "-fuse-ld=lld", "-Wl,-e,main", source, "-o", binary)
	if output, err := command.CombinedOutput(); err != nil {
		t.Skipf("cannot link a Thumb executable: %v: %s", err, output)
	}
	return binary
}

func TestThumbModeDetectedFromEntryPoint(t *testing.T) {
	dir := t.TempDir()
	binary := buildThumbExecutable(t, dir)
	result, err := Overview(binary, "")
	if err != nil {
		t.Fatal(err)
	}
	image := result.Images[0]
	if image.Arch != "arm" {
		t.Fatalf("arch = %q, want arm", image.Arch)
	}
	if image.Mode != "thumb" {
		t.Fatalf("mode = %q, want thumb (the entry point carries the Thumb bit)", image.Mode)
	}
	if image.EntryPoint == nil {
		t.Fatal("no entry point")
	}
	if *image.EntryPoint&1 != 0 {
		t.Fatalf("entry point %#x still has the Thumb bit set; it must be cleared", *image.EntryPoint)
	}
}

// TestThumbDisassemblyMatchesOracle is the wiring test that matters: it decodes the real
// binary through Disassemble and compares every instruction with llvm-objdump.
func TestThumbDisassemblyMatchesOracle(t *testing.T) {
	dir := t.TempDir()
	binary := buildThumbExecutable(t, dir)
	overview, err := Overview(binary, "")
	if err != nil {
		t.Fatal(err)
	}
	entry := *overview.Images[0].EntryPoint
	disassembly, err := Disassemble(binary, DisassemblyOptions{
		Target: "0x" + fmt.Sprintf("%x", entry), Count: 12,
	})
	if err != nil {
		t.Fatalf("disassemble: %v", err)
	}
	if len(disassembly.Instructions) < 4 {
		t.Fatalf("decoded %d instructions", len(disassembly.Instructions))
	}
	out, err := exec.Command("llvm-objdump", "-d", "--triple=thumbv7-none-eabi",
		"--no-show-raw-insn", binary).CombinedOutput()
	if err != nil {
		t.Skipf("llvm-objdump failed: %v", err)
	}
	// Index the oracle by address so the comparison does not depend on our ordering.
	oracle := map[uint64]string{}
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.SplitN(strings.TrimSpace(line), ":", 2)
		if len(fields) != 2 {
			continue
		}
		var address uint64
		if _, err := fmt.Sscanf(strings.TrimSpace(fields[0]), "%x", &address); err != nil {
			continue
		}
		text := strings.Fields(fields[1])
		if len(text) == 0 {
			continue
		}
		oracle[address] = strings.Join(text, " ")
	}
	compared, matched := 0, 0
	for _, instruction := range disassembly.Instructions {
		want, ok := oracle[instruction.Address]
		if !ok {
			continue
		}
		compared++
		got := strings.Join(strings.Fields(instruction.Text), " ")
		// llvm prints branch targets as "bl 0x2014c <trap>" and appends a comment;
		// compare only the mnemonic and the first operand token for branches.
		if strings.HasPrefix(want, "bl ") || strings.HasPrefix(want, "b ") {
			if strings.HasPrefix(got, strings.SplitN(want, " ", 2)[0]) {
				matched++
			} else {
				t.Errorf("%#x: ours %q, llvm %q", instruction.Address, got, want)
			}
			continue
		}
		if got == want {
			matched++
		} else {
			t.Errorf("%#x: ours %q, llvm %q", instruction.Address, got, want)
		}
	}
	if compared == 0 {
		t.Fatal("nothing compared with llvm-objdump")
	}
	if float64(matched)/float64(compared) < 0.90 {
		t.Fatalf("match rate %d/%d below 0.90", matched, compared)
	}
	t.Logf("Thumb wiring: %d/%d instructions match llvm-objdump", matched, compared)
}

// TestARMSymbolThumbBitIsMasked is the regression test for a real bug.
//
// ARM sets bit 0 on every Thumb code address, including ELF symbol values. Indexing the
// raw value produced odd function addresses that cannot be decoded, plus a duplicate of
// the even entry-point function: on a real Thumb binary, 5 of 6 indexed functions were
// odd and `main` appeared twice.
func TestARMSymbolThumbBitIsMasked(t *testing.T) {
	dir := t.TempDir()
	binary := buildThumbExecutable(t, dir)
	result, err := Functions(binary, "", "", 0)
	if err != nil {
		t.Fatal(err)
	}
	image := result.Images[0]
	if len(image.Functions) == 0 {
		t.Fatal("no functions indexed")
	}
	odd := 0
	seen := map[uint64]int{}
	for _, function := range image.Functions {
		if function.Address&1 != 0 {
			odd++
			t.Errorf("function %q has odd address %#x (Thumb bit not masked)",
				function.Name, function.Address)
		}
		seen[function.Address]++
	}
	for address, count := range seen {
		if count > 1 {
			t.Errorf("%#x appears %d times in the index", address, count)
		}
	}
	if odd != 0 {
		t.Fatalf("%d functions carry a Thumb-tagged address", odd)
	}
	// Mode must come from the symbols as well as the entry point, and FunctionIndex
	// carries it so callers of `re functions` see the same answer as `re overview`.
	if image.Mode != "thumb" {
		t.Errorf("mode = %q, want thumb", image.Mode)
	}
}

// TestARMLiftDeclinesWithReason checks that a structured decline is reported with
// an architecture-specific reason once the ARM32 lifter has run, not as the old
// "no lifter" answer and not as a per-instruction decode failure.
func TestARMLiftDeclinesWithReason(t *testing.T) {
	dir := t.TempDir()
	binary := buildThumbExecutable(t, dir)
	overview, err := Overview(binary, "")
	if err != nil {
		t.Fatal(err)
	}
	entry := *overview.Images[0].EntryPoint
	result, err := Decompile(binary, DisassemblyOptions{Target: "0x" + fmt.Sprintf("%x", entry)})
	if err != nil {
		t.Fatalf("decompile should decline, not fail: %v", err)
	}
	if !result.OK {
		t.Fatal("declined result should still be ok")
	}
	if result.Coverage.Decoded == 0 || result.Coverage.Lifted == 0 {
		t.Fatalf("nothing lifted: decoded %d, lifted %d", result.Coverage.Decoded, result.Coverage.Lifted)
	}
	if result.StructuredDeclined == "" && result.Structured == nil {
		t.Fatal("no structured result and no decline reason recorded")
	}
	if strings.Contains(strings.ToLower(result.StructuredDeclined), "no lifter") {
		t.Fatalf("stale decline reason: %q", result.StructuredDeclined)
	}
	t.Logf("thumb: decoded=%d lifted=%d ratio=%.2f; declined: %s", result.Coverage.Decoded,
		result.Coverage.Lifted, float64(result.Coverage.Lifted)/float64(result.Coverage.Decoded),
		result.StructuredDeclined)
}

// buildARMLiftFixture builds a real bare-metal ARM executable at -O1. The A32
// form uses the exact flags from the coverage requirement; the Thumb form adds
// -mthumb. Both are skipped when the toolchain is unavailable.
func buildARMLiftFixture(t *testing.T, dir string, thumb bool) string {
	t.Helper()
	for _, tool := range []string{"clang", "llvm-objdump"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not available", tool)
		}
	}
	source := filepath.Join(dir, "lift_fixture.c")
	program := `
struct P { int a; int b; };
int sum(int *v, int n) { int s = 0; for (int i = 0; i < n; i++) s += v[i]; return s; }
int main(void) { struct P p = {1, 2}; return sum(&p.a, 2); }
`
	if err := os.WriteFile(source, []byte(program), 0600); err != nil {
		t.Fatal(err)
	}
	args := []string{"-target", "armv7-none-eabi", "-O1", "-nostdlib",
		"-fuse-ld=lld", "-Wl,-e,main"}
	if thumb {
		args = append(args, "-mthumb")
	}
	name := "a32_exe"
	if thumb {
		name = "thumb_exe"
	}
	binary := filepath.Join(dir, name)
	args = append(args, source, "-o", binary)
	if output, err := exec.Command("clang", args...).CombinedOutput(); err != nil {
		t.Skipf("cannot link an ARM executable: %v: %s", err, output)
	}
	return binary
}

// checkARMLiftCoverage compares `re disasm-native` (Disassemble) with
// `re decompile-native` (Decompile) over the same function window, and checks
// that structured output or an architecture-specific decline is reported.
func checkARMLiftCoverage(t *testing.T, binary string, wantThumb bool) {
	t.Helper()
	overview, err := Overview(binary, "")
	if err != nil {
		t.Fatal(err)
	}
	image := overview.Images[0]
	if image.Arch != "arm" {
		t.Fatalf("arch = %q, want arm", image.Arch)
	}
	if wantThumb && image.Mode != "thumb" {
		t.Fatalf("mode = %q, want thumb", image.Mode)
	}
	if !wantThumb && image.Mode == "thumb" {
		t.Fatalf("mode = %q, want A32", image.Mode)
	}
	if image.EntryPoint == nil {
		t.Fatal("no entry point")
	}
	entry := *image.EntryPoint
	opts := DisassemblyOptions{
		Target: "0x" + fmt.Sprintf("%x", entry),
		Bytes:  functionWindow(image, entry),
		Flow:   true,
	}
	disassembly, err := Disassemble(binary, opts)
	if err != nil {
		t.Fatalf("disasm-native: %v", err)
	}
	decompiled, err := Decompile(binary, opts)
	if err != nil {
		t.Fatalf("decompile-native: %v", err)
	}
	if !decompiled.OK {
		t.Fatal("decompile result is not ok")
	}
	if decompiled.Coverage.Decoded <= 0 || decompiled.Coverage.Lifted <= 0 {
		t.Fatalf("decoded %d, lifted %d", decompiled.Coverage.Decoded, decompiled.Coverage.Lifted)
	}
	if len(disassembly.Instructions) != decompiled.Coverage.Decoded {
		t.Fatalf("disasm-native counted %d instructions, decompile counted %d",
			len(disassembly.Instructions), decompiled.Coverage.Decoded)
	}
	operations := 0
	for _, block := range decompiled.IR {
		operations += len(block.Operations)
	}
	if operations != decompiled.Coverage.Decoded {
		t.Fatalf("IR has %d operations, expected %d", operations, decompiled.Coverage.Decoded)
	}
	ratio := float64(decompiled.Coverage.Lifted) / float64(decompiled.Coverage.Decoded)
	if ratio < 0.70 {
		t.Fatalf("lifted/decoded ratio %.2f (%d/%d) below 0.70", ratio,
			decompiled.Coverage.Lifted, decompiled.Coverage.Decoded)
	}
	if decompiled.Structured == nil {
		reason := strings.ToLower(decompiled.StructuredDeclined)
		if reason == "" {
			t.Fatal("no structured output and no decline reason")
		}
		if strings.Contains(reason, "no arm32/thumb lifter") || strings.Contains(reason, "no lifter") {
			t.Fatalf("stale decline reason: %q", decompiled.StructuredDeclined)
		}
		if !strings.Contains(reason, "arm") && !strings.Contains(reason, "thumb") {
			t.Fatalf("decline reason does not mention the architecture: %q", decompiled.StructuredDeclined)
		}
	}
	mode := "A32"
	if wantThumb {
		mode = "Thumb"
	}
	t.Logf("%s: decoded=%d lifted=%d opaque=%d lifted/decoded=%.2f; structured=%v; declined=%q",
		mode, decompiled.Coverage.Decoded, decompiled.Coverage.Lifted,
		decompiled.Coverage.Opaque, ratio, decompiled.Structured != nil, decompiled.StructuredDeclined)
}

func TestARM32LiftCoverage(t *testing.T) {
	binary := buildARMLiftFixture(t, t.TempDir(), false)
	checkARMLiftCoverage(t, binary, false)
}

func TestThumbLiftCoverage(t *testing.T) {
	binary := buildARMLiftFixture(t, t.TempDir(), true)
	checkARMLiftCoverage(t, binary, true)
}

// TestARMLiftMnemonicTable checks one real encoding and one unmodelled encoding
// for every mnemonic the ARM32/Thumb lifter claims to model. The mnemonic and
// operand spellings are the ones produced by decodeARM32/decodeThumb.
func TestARMLiftMnemonicTable(t *testing.T) {
	cases := []struct {
		mnemonic, operands, opcode string
		ok                         bool
	}{
		{"mov", "r0, #1", "copy", true},
		{"mov", "r0", "", false},
		{"movs", "r0, r1", "copy", true},
		{"movs", "r0, [r1]", "", false},
		{"movw", "r0, #0x1234", "copy", true},
		{"movw", "r0, r1", "", false},
		{"movt", "r0, #0xabcd", "add", true},
		{"movt", "r0, r1", "", false},
		{"add", "r0, r1, #2", "add", true},
		{"add", "r0, [r1], #2", "", false},
		{"adds", "r0, #0x2", "add", true},
		{"adds", "r0, #1, #2", "", false},
		{"sub", "sp, sp, #8", "sub", true},
		{"sub", "#1, r0", "", false},
		{"subs", "r1, r1, #1", "sub", true},
		{"subs", "r1, #1, #2", "", false},
		{"and", "r0, r1, #0xf", "and", true},
		{"and", "r0, [r1], #2", "", false},
		{"orr", "r0, r1, r2", "or", true},
		{"orr", "r0", "", false},
		{"eor", "r0, r1, #3", "xor", true},
		{"eor", "r0, r1, ror #2", "", false},
		{"bic", "r0, r1, #0xf0", "and", true},
		{"bic", "r0, r1, r2", "", false},
		{"lsl", "r0, r1, lsl #2", "shl", true},
		{"lsl", "r0, r1, rrx", "", false},
		{"lsr", "r0, r1, #2", "shr", true},
		{"lsr", "r0, [r1], #2", "", false},
		{"asr", "r0, r1, #3", "sar", true},
		{"asr", "r0, r1, ror #1", "", false},
		{"cmp", "r1, #1", "flags", true},
		{"cmp", "r1", "", false},
		{"cmn", "r0, r1", "flags", true},
		{"cmn", "[r0], r1", "", false},
		{"tst", "r0, r0", "flags", true},
		{"tst", "r0", "", false},
		{"mvn", "r0, #0", "copy", true},
		{"mvn", "r0, r1", "", false},
		{"ldr", "r3, [r2], #4", "copy", true},
		{"ldr", "r0, [r1, r2, ror #1]", "", false},
		{"str", "r0, [sp, #0x4]", "copy", true},
		{"str", "[r0], r1", "", false},
		{"ldrb", "r0, [r1, #0x1]", "copy", true},
		{"ldrb", "r0", "", false},
		{"strb", "r0, [r1]", "copy", true},
		{"strb", "r0, [r1, r2, asr #1]", "", false},
		{"ldrh", "r0, [r1, #0x2]", "copy", true},
		{"ldrh", "r0, [r1, r2, lsr #1]", "", false},
		{"strh", "r0, [r1, #0x2]", "copy", true},
		{"strh", "r0, [r1, r2, ror #1]", "", false},
		{"push", "{r4, r5}", "copy_pair", true},
		// A wide list is modelled as stack_push_list rather than copy_pair: the IR carries
		// two destinations, so the faithful copy form is impossible, but refusing the
		// instruction made every ARM32 prologue opaque.
		{"push", "{r4, r5, r6, lr}", "stack_push_list", true},
		{"pop", "{r4, r5, r6, pc}", "stack_pop_list", true},
		{"pop", "{r4, r5}", "copy_pair", true},
		{"pop", "{}", "", false},
		{"bl", "0x1000", "call", true},
		{"bl", "", "", false},
		{"blx", "r3", "call", true},
		{"blx", "", "", false},
		{"bx", "lr", "return", true},
		{"bx", "#3", "", false},
		{"b", "0x1000", "jump", true},
		{"b", "", "", false},
		{"cbz", "r0, 0x1000", "branch", true},
		{"cbz", "#0, 0x1000", "", false},
		{"cbnz", "r1, 0x1000", "branch", true},
		{"cbnz", "r1", "", false},
		{"nop", "", "nop", true},
		{"nop", "r0", "", false},
		{"svc", "#0x0", "trap", true},
		{"svc", "r0", "", false},
		// Thumb spellings of the same operations.
		{"adds", "r0, r3", "add", true},
		{"subs", "r1, #0x1", "sub", true},
		{"ands", "r0, r1", "and", true},
		{"orrs", "r0, r1", "or", true},
		{"eors", "r0, r1", "xor", true},
		{"bics", "r0, r1, #0xf0", "and", true},
		{"mvns", "r0, #0x1", "copy", true},
		{"lsls", "r0, r1, #0x2", "shl", true},
		{"lsrs", "r0, r1, #0x1", "shr", true},
		{"asrs", "r0, r1, #0x3", "sar", true},
		{"ldr.w", "r3, [r1, r2, lsl #2]", "copy", true},
		{"str.w", "r0, [r1, #0x4]", "copy", true},
		{"push.w", "{r4, r5}", "copy_pair", true},
		{"pop.w", "{r4, r5}", "copy_pair", true},
		{"bne", "0x1000", "branch", true},
		{"adr", "r0, #0x8", "address", true},
	}
	for _, tc := range cases {
		text := tc.mnemonic
		if tc.operands != "" {
			text += " " + tc.operands
		}
		op := Operation{Address: 0x100}
		got := liftARM32(text, tc.mnemonic, arm32OperandTokens(tc.operands), &op)
		if got != tc.ok {
			t.Errorf("%q: lift = %v, want %v", text, got, tc.ok)
			continue
		}
		if got && op.Opcode != tc.opcode {
			t.Errorf("%q: opcode = %q, want %q", text, op.Opcode, tc.opcode)
		}
		if got && op.Opcode == "branch" && op.Fallthrough != nil {
			t.Errorf("%q: fallthrough is set by the caller, not the lifter", text)
		}
	}
	t.Logf("table: %d ARM32/Thumb encodings checked (modelled and unmodelled)", len(cases))
}

// TestARMLiftAllOpaqueReason verifies the other side of the decline contract:
// when no instruction is modelled, the reason says so instead of claiming the
// architecture has no lifter.
func TestARMLiftAllOpaqueReason(t *testing.T) {
	for _, tool := range []string{"clang", "llvm-objdump"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not available", tool)
		}
	}
	dir := t.TempDir()
	source := filepath.Join(dir, "opaque.c")
	program := `
int main(void) {
  __asm__ volatile("mvn r0, r1\n\t"
                   "bic r2, r3, r4\n\t"
                   "mrc p15, 0, r0, c1, c0, 0\n\t"
                   "ldc p1, c0, [r0]" ::: "memory");
  return 0;
}
`
	if err := os.WriteFile(source, []byte(program), 0600); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(dir, "opaque_exe")
	command := exec.Command("clang", "-target", "armv7-none-eabi", "-O1", "-nostdlib",
		"-fuse-ld=lld", "-Wl,-e,main", source, "-o", binary)
	if output, err := command.CombinedOutput(); err != nil {
		t.Skipf("cannot link an ARM executable: %v: %s", err, output)
	}
	result, err := Decompile(binary, DisassemblyOptions{Target: "entry"})
	if err != nil {
		t.Fatal(err)
	}
	if result.Coverage.Decoded == 0 || result.Coverage.Lifted != 0 {
		t.Fatalf("expected all opaque: decoded %d, lifted %d", result.Coverage.Decoded, result.Coverage.Lifted)
	}
	if !strings.Contains(strings.ToLower(result.StructuredDeclined), "opaque") {
		t.Fatalf("decline reason does not describe opaque instructions: %q", result.StructuredDeclined)
	}
	if strings.Contains(strings.ToLower(result.StructuredDeclined), "no lifter") {
		t.Fatalf("stale decline reason: %q", result.StructuredDeclined)
	}
	t.Logf("all-opaque: %s", result.StructuredDeclined)
}
