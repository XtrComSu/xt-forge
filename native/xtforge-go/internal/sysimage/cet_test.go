package sysimage

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Intel CET landing pads.
//
// Debian and Ubuntu build with -fcf-protection by default, so most functions on this
// machine begin with `endbr64`. The vendored x86asm reports that encoding as Op(0) with
// Len 1, and the validity check rejects Op(0) — which meant the FIRST instruction of every
// hardened function failed and disassembly stopped immediately. Measured on a plain system
// binary compiled here: disassembly and decompilation both failed outright before this.

// The shadow-stack register forms need the same treatment from the decoder, but not from
// the lifter: F3 REX.W 0F 1E /1 (RDSSPQ) and F3 REX.W 0F AE /5 (INCSSPQ) are five bytes
// and write state, while the two landing pads are four-byte no-ops.
var cetEncodings = []struct {
	name string
	data []byte
	text string
	size int
	ok   bool
}{
	{"endbr64", []byte{0xF3, 0x0F, 0x1E, 0xFA}, "endbr64", 4, true},
	{"endbr32", []byte{0xF3, 0x0F, 0x1E, 0xFB}, "endbr32", 4, true},
	{"endbr + code after", []byte{0xF3, 0x0F, 0x1E, 0xFA, 0x55}, "endbr64", 4, true},
	{"rdsspq rax", []byte{0xF3, 0x48, 0x0F, 0x1E, 0xC8}, "rdsspq rax", 5, true},
	{"rdsspq r8 (REX.B)", []byte{0xF3, 0x49, 0x0F, 0x1E, 0xC8}, "rdsspq r8", 5, true},
	{"incsspq rax", []byte{0xF3, 0x48, 0x0F, 0xAE, 0xE8}, "incsspq rax", 5, true},
	{"incsspq r8 (REX.B)", []byte{0xF3, 0x49, 0x0F, 0xAE, 0xE8}, "incsspq r8", 5, true},
	// Near misses: no guessed length for anything outside the recognised forms.
	{"rdssp without REX.W", []byte{0xF3, 0x0F, 0x1E, 0xC8}, "", 0, false},
	{"rdsspq wrong /reg", []byte{0xF3, 0x48, 0x0F, 0x1E, 0xC0}, "", 0, false},
	{"rdsspq memory operand", []byte{0xF3, 0x48, 0x0F, 0x1E, 0x08}, "", 0, false},
	{"incsspq wrong /reg", []byte{0xF3, 0x48, 0x0F, 0xAE, 0xE0}, "", 0, false},
	{"legacy 0fae form", []byte{0x0F, 0xAE, 0xE8}, "", 0, false},
	{"push rbp", []byte{0x55}, "", 0, false},
	{"unknown 0f1e form", []byte{0xF3, 0x0F, 0x1E, 0x00}, "", 0, false},
	{"truncated", []byte{0xF3, 0x0F, 0x1E}, "", 0, false},
	{"truncated register form", []byte{0xF3, 0x48, 0x0F, 0x1E}, "", 0, false},
	{"empty", nil, "", 0, false},
}

func TestX86CETInstruction(t *testing.T) {
	for _, tc := range cetEncodings {
		text, size, ok := x86CETInstruction(tc.data)
		if ok != tc.ok || text != tc.text || size != tc.size {
			t.Errorf("%s: got (%q,%d,%v), want (%q,%d,%v)",
				tc.name, text, size, ok, tc.text, tc.size, tc.ok)
		}
	}
}

// TestX86CETLinearDecode checks the decoder surface: every recognised CET encoding
// must survive a linear pass with its exact length and without becoming "opaque".
// The lifter's opaque decisions are checked separately below.
func TestX86CETLinearDecode(t *testing.T) {
	var stream []byte
	var wantText []string
	var wantSize []int
	for _, tc := range cetEncodings {
		if !tc.ok {
			continue
		}
		stream = append(stream, tc.data[:tc.size]...)
		wantText = append(wantText, tc.text)
		wantSize = append(wantSize, tc.size)
	}

	instructions, warnings := linearDecode("x86_64", 0x1000, stream, len(wantText)+1)
	if len(warnings) != 0 {
		t.Fatalf("linearDecode warnings: %v", warnings)
	}
	if len(instructions) != len(wantText) {
		t.Fatalf("decoded %d instructions, want %d", len(instructions), len(wantText))
	}
	address := uint64(0x1000)
	for i, ins := range instructions {
		if ins.Address != address {
			t.Errorf("%s: address %#x, want %#x", wantText[i], ins.Address, address)
		}
		if ins.Size != wantSize[i] {
			t.Errorf("%s: size %d, want %d", wantText[i], ins.Size, wantSize[i])
		}
		if ins.Text != wantText[i] {
			t.Errorf("instruction %d: text %q, want %q", i, ins.Text, wantText[i])
		}
		if ins.Mnemonic == "opaque" || strings.Contains(strings.ToLower(ins.Text), "opaque") {
			t.Errorf("%s: decoded as opaque", wantText[i])
		}
		address += uint64(ins.Size)
	}
}

// TestX86CETLift records the honest IR boundary: landing pads are nops, but the
// shadow-stack register forms are opaque rather than invented register writes.
func TestX86CETLift(t *testing.T) {
	for _, tc := range cetEncodings {
		if !tc.ok {
			continue
		}
		ins, err := decodeInstruction("x86_64", 0x1000, tc.data)
		if err != nil {
			t.Fatalf("%s: decode: %v", tc.name, err)
		}
		if ins.Size != tc.size || ins.Text != tc.text {
			t.Errorf("%s: got (%q,%d), want (%q,%d)", tc.name, ins.Text, ins.Size, tc.text, tc.size)
		}
		op := liftInstruction("x86_64", ins)
		want := "nop"
		if strings.HasPrefix(tc.text, "rdsspq ") || strings.HasPrefix(tc.text, "incsspq ") {
			want = "opaque"
		}
		if op.Opcode != want {
			t.Errorf("%s: lifted as %q, want %q", tc.name, op.Opcode, want)
		}
		if want == "opaque" && op.Raw != tc.text {
			t.Errorf("%s: opaque raw text %q, want %q", tc.name, op.Raw, tc.text)
		}
	}
}

// TestDisassemblySurvivesCETPrologue drives a real CET-hardened binary through both
// surfaces and requires that nothing is opaque: an opaque `endbr64` would mean the prologue
// is being reported as a decode failure.
func TestDisassemblySurvivesCETPrologue(t *testing.T) {
	if _, err := exec.LookPath("clang"); err != nil {
		t.Skip("clang not available")
	}
	dir := t.TempDir()
	source := filepath.Join(dir, "cet.c")
	if err := os.WriteFile(source, []byte(
		"int helper(int a, int b) { return a * 3 + b; }\n"+
			"int main(void) { return helper(2, 5); }\n"), 0600); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(dir, "cet")
	// -fcf-protection is the default on most distribution toolchains; pass it explicitly
	// so the fixture is CET whatever the host default is.
	command := exec.Command("clang", "-O1", "-fcf-protection=full", source, "-o", binary)
	if output, err := command.CombinedOutput(); err != nil {
		t.Skipf("clang cannot build the CET fixture: %v: %s", err, output)
	}
	overview, err := Overview(binary, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(overview.Images) == 0 || overview.Images[0].EntryPoint == nil {
		t.Skip("fixture has no entry point to disassemble")
	}
	entry := "0x" + fmt.Sprintf("%x", *overview.Images[0].EntryPoint)
	disassembly, err := Disassemble(binary, DisassemblyOptions{Target: entry, Count: 16})
	if err != nil {
		t.Fatalf("disassembly failed on a CET binary: %v", err)
	}
	if len(disassembly.Instructions) < 4 {
		t.Fatalf("only %d instructions decoded", len(disassembly.Instructions))
	}
	opaque := 0
	for _, instruction := range disassembly.Instructions {
		if instruction.Mnemonic == "opaque" {
			opaque++
		}
	}
	if opaque != 0 {
		t.Errorf("%d of %d instructions opaque; the CET prologue is not decoding",
			opaque, len(disassembly.Instructions))
	}
	decompilation, err := Decompile(binary, DisassemblyOptions{Target: entry})
	if err != nil {
		t.Fatalf("decompilation failed on a CET binary: %v", err)
	}
	if decompilation.Coverage.Lifted == 0 {
		t.Fatal("nothing lifted; endbr64 is still arriving as an opaque operation")
	}
	t.Logf("CET binary: %d instructions, %d lifted, %d opaque",
		len(disassembly.Instructions), decompilation.Coverage.Lifted, decompilation.Coverage.Opaque)
}
