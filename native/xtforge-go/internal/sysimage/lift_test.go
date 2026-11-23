package sysimage

import (
	"strings"
	"testing"
)

func TestARMVariableShiftPreservesFlags(t *testing.T) {
	ins, err := decodeInstruction("arm64", 0x1000, []byte{0x20, 0x28, 0xc2, 0x1a})
	if err != nil {
		t.Fatal(err)
	}
	op := liftInstruction("arm64", ins)
	if op.Opcode != "sar" || len(op.Inputs) != 2 || op.Inputs[1].Register != "w2" {
		t.Fatalf("arm64 variable shift lost operands: %#v", op)
	}
	abi, _ := nativeABI("macho", "arm64")
	a := structuredAnalysis{abi: abi, arch: "arm64", parameterUse: make([]int, 8)}
	state := symbolicState{registers: map[string]symbolicValue{"sp": {width: 64, stack: true}},
		slots: make(map[int64]symbolicValue), flags: symbolicFlags{kind: "previous"}}
	if !a.apply(&state, op) || state.registers["x0"].text == "" || state.flags.kind != "previous" {
		t.Fatalf("arm64 shift modified flags or failed: %#v", state)
	}
}

func TestX86VariableShiftUsesCountRegister(t *testing.T) {
	ins, err := decodeInstruction("x86_64", 0x1000, []byte{0xd3, 0xff})
	if err != nil {
		t.Fatal(err)
	}
	op := liftInstruction("x86_64", ins)
	if op.Opcode != "sar" || len(op.Inputs) != 2 || op.Inputs[1].Register != "cl" {
		t.Fatalf("variable shift count lost: %#v", op)
	}
	abi, _ := nativeABI("elf", "x86_64")
	a := structuredAnalysis{abi: abi, arch: "x86_64", parameterUse: make([]int, 6)}
	state := symbolicState{registers: map[string]symbolicValue{
		"rsp": {width: 64, stack: true}, "rcx": {width: 32, text: "count"},
	}, slots: make(map[int64]symbolicValue)}
	if !a.apply(&state, op) || state.registers["rdi"].text == "" {
		t.Fatal("variable arithmetic shift did not recover")
	}
}

func TestX86ImmediateShiftCountAndFlags(t *testing.T) {
	ins, err := decodeInstruction("x86_64", 0x1000, []byte{0xc1, 0xe7, 0x20})
	if err != nil {
		t.Fatal(err)
	}
	op := liftInstruction("x86_64", ins)
	if op.Opcode != "shl" || len(op.Inputs) != 2 {
		t.Fatalf("shift was not lifted: %#v", op)
	}
	abi, _ := nativeABI("elf", "x86_64")
	a := structuredAnalysis{abi: abi, arch: "x86_64", parameterUse: make([]int, 6)}
	state := symbolicState{registers: map[string]symbolicValue{"rsp": {width: 64, stack: true}},
		slots: make(map[int64]symbolicValue), flags: symbolicFlags{kind: "previous"}}
	if !a.apply(&state, op) || state.registers["rdi"].text != "arg0" || state.flags.kind != "previous" {
		t.Fatalf("masked zero-count shift changed value or flags: %#v", state)
	}
}

func TestLiftX86IMulHasUnknownZeroFlag(t *testing.T) {
	ins, err := decodeInstruction("x86_64", 0x1000, []byte{0x6b, 0xc7, 0x07})
	if err != nil {
		t.Fatal(err)
	}
	op := liftInstruction("x86_64", ins)
	if op.Opcode != "mul" || op.Flags != "x86_imul" || len(op.Inputs) != 2 ||
		op.Inputs[0].Register != "edi" || op.Inputs[1].Immediate != "0x7" {
		t.Fatalf("imul operands lost: %#v", op)
	}
	abi, _ := nativeABI("elf", "x86_64")
	a := structuredAnalysis{abi: abi, arch: "x86_64", parameterUse: make([]int, 6)}
	state := symbolicState{registers: map[string]symbolicValue{"rsp": {width: 64, stack: true}}, slots: make(map[int64]symbolicValue)}
	if !a.apply(&state, op) || state.registers["rax"].text == "" {
		t.Fatal("imul value was not recovered")
	}
	if a.predicate(state, Operation{Condition: "x86.je"}) != "" {
		t.Fatal("imul incorrectly gave a defined zero flag")
	}
}

func TestStructuredIndexOnlyLEA(t *testing.T) {
	data := []byte{0x8d, 0x04, 0xbd, 0x11, 0, 0, 0, 0xc3}
	fn := analyzeTestFunction("elf", "x86_64", data)
	if fn == nil || !strings.Contains(fn.Pseudocode, "arg0") {
		t.Fatalf("index-only LEA was not recovered: %#v", fn)
	}
}

func TestStructuredIndexedLEA(t *testing.T) {
	ins, err := decodeInstruction("x86_64", 0x1000, []byte{0x8d, 0x0c, 0x38})
	if err != nil {
		t.Fatal(err)
	}
	abi, _ := nativeABI("macho", "x86_64")
	a := structuredAnalysis{abi: abi, arch: "x86_64", parameterUse: make([]int, 6)}
	state := symbolicState{registers: map[string]symbolicValue{
		"rsp": {width: 64, stack: true}, "rax": {width: 32, text: "value"},
	}, slots: make(map[int64]symbolicValue)}
	if !a.apply(&state, liftInstruction("x86_64", ins)) || state.registers["rcx"].text == "" {
		t.Fatalf("indexed LEA was not recovered: %#v", state.registers["rcx"])
	}
}

func TestLiftX86DecrementPreservesCarry(t *testing.T) {
	ins, err := decodeInstruction("x86_64", 0x1000, []byte{0x41, 0xff, 0xce})
	if err != nil {
		t.Fatal(err)
	}
	op := liftInstruction("x86_64", ins)
	if op.Opcode != "sub" || op.Flags != "x86_dec" || len(op.Inputs) != 2 || op.Inputs[1].Immediate != "0x1" {
		t.Fatalf("decrement semantics lost: %#v", op)
	}
	abi, _ := nativeABI("macho", "x86_64")
	a := structuredAnalysis{abi: abi, parameterUse: make([]int, 6)}
	state := symbolicState{registers: map[string]symbolicValue{
		"rsp": {width: 64, stack: true}, "r14": {width: 32, text: "value"},
	}, slots: make(map[int64]symbolicValue)}
	if !a.apply(&state, op) || a.predicate(state, Operation{Condition: "x86.jne"}) == "" {
		t.Fatal("decrement zero flag was not recovered")
	}
	if a.predicate(state, Operation{Condition: "x86.jb"}) != "" {
		t.Fatal("decrement incorrectly replaced the carry flag")
	}
}

func TestShiftedSameRegisterIsNotZero(t *testing.T) {
	for _, data := range [][]byte{{0x20, 0x04, 0x01, 0x4a}, {0x20, 0x04, 0x41, 0x4b}} {
		ins, err := decodeInstruction("arm64", 0x1000, data)
		if err != nil {
			t.Fatal(err)
		}
		op := liftInstruction("arm64", ins)
		abi, _ := nativeABI("macho", "arm64")
		a := structuredAnalysis{abi: abi, parameterUse: make([]int, 8)}
		state := symbolicState{registers: map[string]symbolicValue{"sp": {width: 64, stack: true}}, slots: make(map[int64]symbolicValue)}
		if !a.apply(&state, op) || state.registers["x0"].text == "0x0" || state.registers["x0"].text == "" {
			t.Fatalf("shifted same-register operation was folded to zero: %#v", op)
		}
	}
}

func TestLiftARMArithmeticShift(t *testing.T) {
	ins, err := decodeInstruction("arm64", 0x1000, []byte{0, 0x1c, 0x81, 0x0b})
	if err != nil {
		t.Fatal(err)
	}
	op := liftInstruction("arm64", ins)
	if op.Opcode != "add" || len(op.Inputs) != 2 || op.Inputs[1].Shift != "asr" || op.Inputs[1].Scale != 7 {
		t.Fatalf("arithmetic shift was not preserved: %#v", op)
	}
	abi, _ := nativeABI("macho", "arm64")
	a := structuredAnalysis{abi: abi, parameterUse: make([]int, 8)}
	state := symbolicState{registers: map[string]symbolicValue{"sp": {width: 64, stack: true}}, slots: make(map[int64]symbolicValue)}
	if !a.apply(&state, op) || state.registers["x0"].text == "" {
		t.Fatalf("arithmetic shift could not be recovered: %#v", state.registers["x0"])
	}
}

func TestLiftARMShiftedRegisterPreservesShift(t *testing.T) {
	ins, err := decodeInstruction("arm64", 0x1000, []byte{0x28, 0x05, 0x48, 0xcb})
	if err != nil {
		t.Fatal(err)
	}
	op := liftInstruction("arm64", ins)
	if op.Opcode != "sub" || len(op.Inputs) != 2 || op.Inputs[1].Shift != "lsr" || op.Inputs[1].Scale != 1 {
		t.Fatalf("shifted subtraction lost its right shift: %#v", op)
	}
	abi, _ := nativeABI("macho", "arm64")
	a := structuredAnalysis{abi: abi, parameterUse: make([]int, 8)}
	state := symbolicState{registers: map[string]symbolicValue{
		"sp": {width: 64, stack: true},
		"x9": {width: 64, text: "left"},
		"x8": {width: 64, text: "right"},
	}, slots: make(map[int64]symbolicValue)}
	if !a.apply(&state, op) || state.registers["x8"].text != "(left - (right >> 1u))" {
		t.Fatalf("shifted subtraction recovered incorrectly: %#v", state.registers["x8"])
	}
}

func TestLiftARMUnsignedWideningMultiply(t *testing.T) {
	ins, err := decodeInstruction("arm64", 0x1000, []byte{0x20, 0x7c, 0xa2, 0x9b})
	if err != nil {
		t.Fatal(err)
	}
	op := liftInstruction("arm64", ins)
	if op.Opcode != "umull" || op.Destination == nil || op.Destination.Width != 64 ||
		len(op.Inputs) != 2 || op.Inputs[0].Width != 32 || op.Inputs[1].Width != 32 {
		t.Fatalf("widening multiply lost its operand widths: %#v", op)
	}
	abi, _ := nativeABI("macho", "arm64")
	a := structuredAnalysis{abi: abi, parameterUse: make([]int, 8)}
	state := symbolicState{registers: map[string]symbolicValue{"sp": {width: 64, stack: true}}, slots: make(map[int64]symbolicValue)}
	if !a.apply(&state, op) || state.registers["x0"].text != "((uint64_t)(arg1) * (uint64_t)(arg2))" {
		t.Fatalf("widening multiply lost its 64-bit product: %#v", state.registers["x0"])
	}
}

func TestLiftARMMultiplyAdd(t *testing.T) {
	ins, err := decodeInstruction("arm64", 0x1000, []byte{0x20, 0x0c, 0x02, 0x1b})
	if err != nil {
		t.Fatal(err)
	}
	op := liftInstruction("arm64", ins)
	if op.Opcode != "madd" || op.Destination == nil || op.Destination.Register != "w0" ||
		len(op.Inputs) != 3 || op.Inputs[0].Register != "w1" || op.Inputs[1].Register != "w2" ||
		op.Inputs[2].Register != "w3" {
		t.Fatalf("multiply-add lost its operands: %#v", op)
	}
	abi, _ := nativeABI("macho", "arm64")
	a := structuredAnalysis{abi: abi, parameterUse: make([]int, 8)}
	state := symbolicState{registers: map[string]symbolicValue{"sp": {width: 64, stack: true}}, slots: make(map[int64]symbolicValue)}
	if !a.apply(&state, op) || state.registers["x0"].text != "((arg1 * arg2) + arg3)" {
		t.Fatalf("multiply-add was not recovered: %#v", state.registers["x0"])
	}
}

func TestLiftKnownIntegerOperations(t *testing.T) {
	cases := []struct {
		arch, register string
		data           []byte
	}{
		{"x86_64", "eax", []byte{0x83, 0xc0, 0x03}},
		{"x86_64", "r8d", []byte{0x41, 0x83, 0xc0, 0x03}},
		{"arm64", "w0", []byte{0, 0x0c, 0, 0x11}},
	}
	for _, tc := range cases {
		ins, err := decodeInstruction(tc.arch, 0x1000, tc.data)
		if err != nil {
			t.Fatal(err)
		}
		op := liftInstruction(tc.arch, ins)
		if op.Opcode != "add" || op.Destination == nil || op.Destination.Register != tc.register ||
			op.Destination.Width != 32 || len(op.Inputs) != 2 || op.Inputs[1].Immediate != "0x3" {
			t.Fatalf("%s: unexpected operation: %#v", tc.arch, op)
		}
		if strings.Contains(renderOperation(op), "opaque") {
			t.Fatalf("known operation rendered as opaque: %#v", op)
		}
	}
}

func TestLiftDoesNotInventUnknownEffects(t *testing.T) {
	ins, err := decodeInstruction("x86_64", 0x1000, []byte{0x0f, 0xc8}) // bswap eax
	if err != nil {
		t.Fatal(err)
	}
	op := liftInstruction("x86_64", ins)
	if op.Opcode != "opaque" || op.Raw == "" || op.Destination != nil || len(op.Inputs) != 0 {
		t.Fatalf("unknown operation has inferred effects: %#v", op)
	}
}

func TestLiftRetainsBothConditionalDestinations(t *testing.T) {
	ins, err := decodeInstruction("arm64", 0x1000, []byte{0x40, 0, 0, 0x34})
	if err != nil {
		t.Fatal(err)
	}
	op := liftInstruction("arm64", ins)
	if op.Opcode != "branch" || op.Condition != "arm64.cbz" || op.Target == nil || *op.Target != 0x1008 ||
		op.Fallthrough == nil || *op.Fallthrough != 0x1004 || len(op.Inputs) != 1 || op.Inputs[0].Register != "w0" {
		t.Fatalf("unexpected branch semantics: %#v", op)
	}
}

func TestLiftStackFrameInstructions(t *testing.T) {
	push, err := decodeInstruction("x86_64", 0x1000, []byte{0x55})
	if err != nil {
		t.Fatal(err)
	}
	x := liftInstruction("x86_64", push)
	if x.Opcode != "copy" || x.Destination == nil || x.Destination.Memory == nil ||
		x.Destination.Memory.Displacement != -8 || x.Writeback == nil || x.Writeback.Delta != -8 ||
		x.Writeback.Register != "rsp" || x.Inputs[0].Register != "rbp" {
		t.Fatalf("push did not retain stack effect: %#v", x)
	}
	ldp, err := decodeInstruction("arm64", 0x1000, []byte{0xfd, 0x7b, 0xc1, 0xa8})
	if err != nil {
		t.Fatal(err)
	}
	a := liftInstruction("arm64", ldp)
	if a.Opcode != "copy_pair" || a.Destination == nil || a.SecondDestination == nil || a.Writeback == nil ||
		a.Writeback.Register != "sp" || a.Writeback.Delta != 16 ||
		len(a.Inputs) != 2 || a.Inputs[0].Memory.Displacement != 0 || a.Inputs[1].Memory.Displacement != 8 {
		t.Fatalf("ldp did not retain both reads and writeback: %#v", a)
	}
}
