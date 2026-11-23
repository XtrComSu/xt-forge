package sysimage

import (
	"fmt"
	"strings"

	"xtforge-hub/internal/thirdparty/xarch/arm64asm"
)

func liftARM(inst arm64asm.Inst, ins Instruction, op *Operation) bool {
	if ins.Kind != "" {
		switch ins.Kind {
		case "conditional":
			return liftARMBranch(inst, ins, op)
		case "call", "jump":
			op.Opcode = ins.Kind
			if op.Target != nil {
				return true
			}
			if value, ok := armOperand(inst.Args[0], 64); ok && value.Kind == "register" {
				op.Inputs = []Operand{value}
				return true
			}
			return false
		case "return":
			if ins.Mnemonic != "ret" {
				return false
			}
			op.Opcode = "return"
			if arg, ok := armOperand(inst.Args[0], 64); ok {
				op.Inputs = []Operand{arg}
			}
			return true
		case "trap":
			op.Opcode = "trap"
			return true
		}
	}
	if ins.Mnemonic == "nop" {
		op.Opcode = "nop"
		return true
	}
	if ins.Mnemonic == "ldp" || ins.Mnemonic == "stp" {
		return liftARMPair(inst, ins.Mnemonic, op)
	}
	if strings.HasPrefix(ins.Mnemonic, "ld") || strings.HasPrefix(ins.Mnemonic, "st") {
		return liftARMMemory(inst, ins, op)
	}
	dest, ok := armOperand(inst.Args[0], 0)
	if !ok || dest.Kind != "register" {
		return false
	}
	switch ins.Mnemonic {
	case "umull", "umaddl", "umsubl":
		if dest.Width != 64 {
			return false
		}
		count := 2
		if ins.Mnemonic != "umull" {
			count = 3
		}
		inputs := make([]Operand, 0, count)
		for i := 1; i <= count; i++ {
			width := 32
			if i == 3 {
				width = 64
			}
			input, valid := armOperand(inst.Args[i], width)
			if !valid || input.Kind != "register" || input.Width != width {
				return false
			}
			inputs = append(inputs, input)
		}
		op.Opcode, op.Destination, op.Inputs = ins.Mnemonic, &dest, inputs
	case "madd", "msub", "mul":
		count := 3
		if ins.Mnemonic == "mul" {
			count = 2
		}
		inputs := make([]Operand, 0, count)
		for i := 1; i <= count; i++ {
			input, valid := armOperand(inst.Args[i], dest.Width)
			if !valid || input.Kind != "register" || input.Width != dest.Width {
				return false
			}
			inputs = append(inputs, input)
		}
		op.Opcode, op.Destination, op.Inputs = ins.Mnemonic, &dest, inputs
	case "csel", "csinc", "csinv", "csneg", "cset", "csetm":
		return liftARMSelect(inst, ins.Mnemonic, dest, op)
	case "adr", "adrp":
		if len(ins.References) != 1 {
			return false
		}
		op.Opcode, op.Destination = "address", &dest
		op.Inputs = []Operand{immediate(ins.References[0].Address, dest.Width)}
	case "mov", "movz", "movn":
		value, ok := armOperand(inst.Args[1], dest.Width)
		if inst.Enc&0x1f800000 == 0x12800000 {
			shift := uint((inst.Enc>>21)&3) * 16
			constant := uint64((inst.Enc>>5)&0xffff) << shift
			switch (inst.Enc >> 29) & 3 {
			case 0:
				value, ok = immediate(^constant, dest.Width), true
			case 2:
				value, ok = immediate(constant, dest.Width), true
			default:
				return false
			}
		}
		if !ok {
			return false
		}
		op.Opcode, op.Destination, op.Inputs = "copy", &dest, []Operand{value}
	case "add", "adds", "sub", "subs", "and", "ands", "orr", "eor":
		left, ok := armOperand(inst.Args[1], dest.Width)
		right, rightOK := armArithmeticOperand(inst, 2, dest.Width)
		if !ok || !rightOK {
			return false
		}
		op.Opcode, op.Destination, op.Inputs = ins.Mnemonic, &dest, []Operand{left, right}
		switch ins.Mnemonic {
		case "adds", "subs", "ands":
			op.Opcode = strings.TrimSuffix(ins.Mnemonic, "s")
			op.Flags = "arm64_" + op.Opcode
		case "orr":
			op.Opcode = "or"
		case "eor":
			op.Opcode = "xor"
		}
	case "cmp", "cmn", "tst":
		right, ok := armArithmeticOperand(inst, 1, dest.Width)
		if !ok {
			return false
		}
		op.Opcode, op.Flags, op.Inputs = "flags", fmt.Sprintf("arm64_%s%d", ins.Mnemonic, dest.Width), []Operand{dest, right}
	case "lsl", "lsr", "asr", "ror":
		// A variable shift takes its amount from a register rather than the
		// encoding, so it is a distinct instruction form: `asr w0, w1, w2`
		// shifts w1 right by w2, and the amount is a second input rather than a
		// Scale on the first. A constant shift of the same mnemonic arrives as a
		// shifted-register operand of add/sub/and and never reaches here.
		left, ok := armOperand(inst.Args[1], dest.Width)
		right, rightOK := armOperand(inst.Args[2], dest.Width)
		if !ok || !rightOK || left.Kind != "register" || right.Kind != "register" {
			return false
		}
		op.Opcode, op.Destination, op.Inputs = shiftOpcode(ins.Mnemonic), &dest, []Operand{left, right}
	default:
		return false
	}
	return true
}

func liftARMSelect(inst arm64asm.Inst, mnemonic string, dest Operand, op *Operation) bool {
	var cond arm64asm.Cond
	var ok bool
	var yes, no Operand
	if mnemonic != "cset" && mnemonic != "csetm" {
		cond, ok = inst.Args[3].(arm64asm.Cond)
		left, leftOK := armOperand(inst.Args[1], dest.Width)
		right, rightOK := armOperand(inst.Args[2], dest.Width)
		if !leftOK || !rightOK || left.Width != dest.Width || right.Width != dest.Width {
			return false
		}
		yes, no = left, right
		switch mnemonic {
		case "csinc":
			op.SelectFalseOp = "increment"
		case "csinv":
			op.SelectFalseOp = "invert"
		case "csneg":
			op.SelectFalseOp = "negate"
		}
	} else {
		cond, ok = inst.Args[1].(arm64asm.Cond)
		value := uint64(1)
		if mnemonic == "csetm" {
			value = ^uint64(0)
		}
		yes, no = immediate(value, dest.Width), immediate(0, dest.Width)
	}
	if !ok {
		return false
	}
	op.Opcode, op.Destination, op.Inputs = "select", &dest, []Operand{yes, no}
	op.Condition = "arm64." + strings.ToLower(cond.String())
	return true
}

func liftARMPair(inst arm64asm.Inst, mnemonic string, op *Operation) bool {
	first, firstOK := armOperand(inst.Args[0], 0)
	second, secondOK := armOperand(inst.Args[1], 0)
	address, addressOK := inst.Args[2].(arm64asm.MemImmediate)
	if !firstOK || !secondOK || !addressOK || first.Kind != "register" ||
		second.Kind != "register" || first.Width != second.Width {
		return false
	}
	rn, rt, rt2 := (inst.Enc>>5)&31, inst.Enc&31, (inst.Enc>>10)&31
	if mnemonic == "ldp" && rt == rt2 {
		return false
	}
	base := strings.ToLower(address.Base.String())
	stride := int64(first.Width / 8)
	delta := int64(int32(inst.Enc<<10)>>25) * stride
	disp := delta
	switch address.Mode {
	case arm64asm.AddrOffset:
	case arm64asm.AddrPostIndex, arm64asm.AddrPreIndex:
		if rn != 31 && (rn == rt || rn == rt2) {
			return false
		}
		op.Writeback = &RegisterUpdate{Register: base, Delta: delta}
		if address.Mode == arm64asm.AddrPostIndex {
			disp = 0
		}
	default:
		return false
	}
	mem1 := Operand{Kind: "memory", Width: first.Width, Memory: &MemoryAddress{Base: base, Displacement: disp}}
	mem2 := Operand{Kind: "memory", Width: second.Width, Memory: &MemoryAddress{Base: base, Displacement: disp + stride}}
	op.Opcode, op.Destination, op.SecondDestination, op.Inputs = "copy_pair", &first, &second, []Operand{mem1, mem2}
	if mnemonic == "stp" {
		op.Destination, op.SecondDestination, op.Inputs = &mem1, &mem2, []Operand{first, second}
	}
	return true
}

func armArithmeticOperand(inst arm64asm.Inst, index, width int) (Operand, bool) {
	// Add/sub immediate operands store the optional shift in the encoding.
	if inst.Enc&0x1f800000 == 0x11000000 {
		value := uint64((inst.Enc >> 10) & 0xfff)
		if inst.Enc&(1<<22) != 0 {
			value <<= 12
		}
		return immediate(value, width), true
	}
	// Add/sub shifted-register and logical shifted-register forms carry Rm in a
	// fixed encoding position. Bits 15:10 hold imm6 and bits 23:22 the shift type;
	// LSL with a non-zero amount is preserved as a scaled operand so index
	// arithmetic (table[i << 2]) stays visible to consumers.
	form := inst.Enc & 0x1f200000
	if form == 0x0b000000 || form == 0x0a000000 {
		reg := arm64asm.W0 + arm64asm.Reg((inst.Enc>>16)&31)
		if width == 64 {
			reg += arm64asm.X0 - arm64asm.W0
		}
		operand, ok := armOperand(reg, width)
		if !ok {
			return Operand{}, false
		}
		shiftKind := (inst.Enc >> 22) & 3
		amount := (inst.Enc >> 10) & 0x3f
		if amount != 0 {
			switch shiftKind {
			case 0:
				operand.Scale = uint8(amount)
			case 1:
				operand.Scale, operand.Shift = uint8(amount), "lsr"
			case 2:
				operand.Scale, operand.Shift = uint8(amount), "asr"
			default:
				return Operand{}, false
			}
		}
		return operand, true
	}
	return armOperand(inst.Args[index], width)
}

func liftARMBranch(inst arm64asm.Inst, ins Instruction, op *Operation) bool {
	if ins.Target == nil {
		return false
	}
	op.Opcode, op.Condition = "branch", "arm64."+ins.Mnemonic
	op.Fallthrough = relativeAddress(ins.Address, 4)
	switch ins.Mnemonic {
	case "b":
		if cond, ok := inst.Args[0].(arm64asm.Cond); ok {
			op.Condition = "arm64." + strings.ToLower(cond.String())
			return true
		}
	case "cbz", "cbnz", "tbz", "tbnz":
		reg, ok := armOperand(inst.Args[0], 0)
		if !ok {
			return false
		}
		op.Inputs = []Operand{reg}
		if ins.Mnemonic[0] == 't' {
			bit, ok := armOperand(inst.Args[1], 0)
			if !ok || bit.Kind != "immediate" {
				return false
			}
			op.Inputs = append(op.Inputs, bit)
		}
		return true
	}
	return false
}

func liftARMMemory(inst arm64asm.Inst, ins Instruction, op *Operation) bool {
	// All single-register load/store forms share one lifting path; the access
	// width comes from the encoding rather than the mnemonic.
	switch ins.Mnemonic {
	case "ldr", "str", "ldur", "stur", "ldrb", "strb", "ldrh", "strh",
		"ldrsw", "ldrsb", "ldrsh", "ldurb", "sturb", "ldurh", "sturh",
		"ldursb", "ldursh", "ldursw":
	default:
		return false
	}
	reg, ok := armOperand(inst.Args[0], 0)
	if !ok || reg.Kind != "register" {
		return false
	}
	mem := Operand{Kind: "memory", Width: reg.Width, Memory: &MemoryAddress{}}
	switch address := inst.Args[1].(type) {
	case arm64asm.PCRel:
		if ins.Mnemonic != "ldr" || len(ins.References) != 1 {
			return false
		}
		mem.Memory.Absolute = fmt.Sprintf("%#x", ins.References[0].Address)
	case arm64asm.MemImmediate:
		if address.Mode != arm64asm.AddrOffset || loadStoreWidth(inst.Enc) != reg.Width {
			return false
		}
		mem.Memory.Base = strings.ToLower(address.Base.String())
		switch {
		case inst.Enc&0x3f000000 == 0x39000000:
			mem.Memory.Displacement = int64((inst.Enc>>10)&0xfff) * int64(reg.Width/8)
		case inst.Enc&0x3f200c00 == 0x38000000:
			mem.Memory.Displacement = int64(int32(inst.Enc<<11) >> 23)
		default:
			return false
		}
	case arm64asm.MemExtend:
		// Register-offset addressing: [Xn, Xm] or [Xn, Xm, LSL #n].
		base := strings.ToLower(address.Base.String())
		index := strings.ToLower(address.Index.String())
		if base == "" || index == "" || strings.HasPrefix(index, "xzr") || strings.HasPrefix(index, "wzr") {
			return false
		}
		scale := address.Amount
		if scale == 0 && !address.ShiftMustBeZero {
			scale = uint8(reg.Width / 8)
		}
		mem.Memory.Base, mem.Memory.Index, mem.Memory.Scale = base, index, scale
	default:
		return false
	}
	op.Opcode, op.Destination, op.Inputs = "copy", &reg, []Operand{mem}
	if ins.Mnemonic[0] == 's' {
		op.Destination, op.Inputs = &mem, []Operand{reg}
	}
	return true
}

// loadStoreWidth returns the access size in bits encoded in a load/store
// instruction. Width is not simply 8 << size for the smaller accesses, because
// size 0 covers both 8-bit and 16-bit forms.
func loadStoreWidth(enc uint32) int {
	size := (enc >> 30) & 3
	if size == 0 {
		if (enc>>26)&1 == 1 {
			return 8
		}
		return 16
	}
	return int(8 << size)
}

func armOperand(arg arm64asm.Arg, width int) (Operand, bool) {
	switch value := arg.(type) {
	case arm64asm.Reg:
		if value >= arm64asm.X0 && value <= arm64asm.XZR {
			return register(value.String(), 64), true
		}
		if value <= arm64asm.WZR {
			return register(value.String(), 32), true
		}
	case arm64asm.RegSP:
		if name := value.String(); strings.HasPrefix(name, "W") {
			return register(name, 32), true
		} else if strings.HasPrefix(name, "X") || name == "SP" {
			return register(name, 64), true
		}
	case arm64asm.Imm:
		return immediate(uint64(value.Imm), width), true
	case arm64asm.Imm64:
		return immediate(value.Imm, width), true
	}
	return Operand{}, false
}

// shiftOpcode maps an arm64 shift mnemonic to the shared shift opcodes the
// structured state already understands, so one implementation covers both
// architectures.
func shiftOpcode(mnemonic string) string {
	switch mnemonic {
	case "lsl":
		return "shl"
	case "lsr":
		return "shr"
	case "asr":
		return "sar"
	}
	// ror has no cross-architecture spelling yet; keep it distinct rather than
	// pretending it is a shift.
	return "ror"
}
