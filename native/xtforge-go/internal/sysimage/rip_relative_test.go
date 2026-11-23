package sysimage

import (
	"encoding/hex"
	"testing"
)

// Negative RIP-relative displacements.
//
// The vendored decoder reports `Mem.Disp` as an unsigned value: `leaq -0x3f(%rip)` arrives
// as 4294967233. Adding that to the instruction end gave 0x100001070 instead of 0x1070, so
// **every backwards memory reference in a 64-bit binary was wrong by 2^32** — and reported
// as `target_class: unknown`, which is what made it visible at all.
//
// `x86asm.Rel` is already signed, which is why branch targets were correct and only memory
// operands suffered.
func TestRIPRelativeNegativeDisplacement(t *testing.T) {
	for _, tc := range []struct {
		name    string
		bytes   string
		address uint64
		want    uint64
	}{
		// leaq -0x3f(%rip), %rdi at 0x10a8; llvm-objdump says 0x1070 <main>.
		{"backwards lea", "488d3dc1ffffff", 0x10a8, 0x1070},
		// leaq 0x3f(%rip), %rdi at 0x10a8 -> 0x10ee, forwarded.
		{"forwards lea", "488d3d3f000000", 0x10a8, 0x10ee},
		// A displacement of zero must land on the next instruction.
		{"zero displacement", "488d3d00000000", 0x1000, 0x1007},
	} {
		data, err := hex.DecodeString(tc.bytes)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		instruction, err := decodeInstruction("x86_64", tc.address, data)
		if err != nil {
			t.Fatalf("%s: decode: %v", tc.name, err)
		}
		if len(instruction.References) == 0 {
			t.Fatalf("%s: no reference recorded", tc.name)
		}
		got := instruction.References[0].Address
		if got != tc.want {
			t.Errorf("%s: target %#x, want %#x (difference %#x)",
				tc.name, got, tc.want, got-tc.want)
		}
	}
}
