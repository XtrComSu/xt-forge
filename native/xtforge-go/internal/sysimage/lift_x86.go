package sysimage

import (
	"fmt"
	"strings"

	"xtforge-hub/internal/thirdparty/xarch/x86asm"
)

func liftX86(inst x86asm.Inst, ins Instruction, op *Operation) bool {
	for _, prefix := range inst.Prefix {
		if byte(prefix) == 0xf0 {
			return false
		}
	}
	if ins.Kind != "" {
		switch ins.Kind {
		case "conditional":
			if strings.HasPrefix(ins.Mnemonic, "loop") {
				return false
			}
			op.Opcode, op.Condition = "branch", "x86."+ins.Mnemonic
			op.Fallthrough = relativeAddress(ins.Address, int64(ins.Size))
			return op.Target != nil
		case "call", "jump":
			op.Opcode = ins.Kind
			if op.Target != nil {
				return true
			}
			value, ok := x86Operand(inst.Args[0], inst, ins, inst.DataSize)
			if ok && (value.Kind == "register" || value.Kind == "memory") {
				op.Inputs = []Operand{value}
				return true
			}
			return false
		case "return":
			if ins.Mnemonic != "ret" {
				return false
			}
			op.Opcode = "return"
			if count, ok := inst.Args[0].(x86asm.Imm); ok {
				op.Inputs = []Operand{immediate(uint64(count), 16)}
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
	if ins.Mnemonic == "push" || ins.Mnemonic == "pop" {
		return liftX86Stack(inst, ins, op)
	}
	if ins.Mnemonic == "leave" {
		for _, prefix := range inst.Prefix {
			if byte(prefix) == 0x66 || byte(prefix) == 0x67 {
				return false
			}
		}
		base, stack, segment := "ebp", "esp", "ss"
		if inst.Mode == 64 {
			base, stack, segment = "rbp", "rsp", ""
		}
		frame := register(base, inst.Mode)
		mem := Operand{Kind: "memory", Width: inst.Mode, Memory: &MemoryAddress{Base: base, Segment: segment}}
		op.Opcode, op.Destination, op.Inputs = "copy", &frame, []Operand{mem}
		op.Writeback = &RegisterUpdate{Register: stack, Base: base, Delta: int64(inst.Mode / 8)}
		return true
	}
	left, ok := x86Operand(inst.Args[0], inst, ins, inst.DataSize)
	if !ok || left.Width == 0 || left.Kind == "immediate" {
		return false
	}
	if ins.Mnemonic == "inc" || ins.Mnemonic == "dec" {
		op.Opcode = "add"
		if ins.Mnemonic == "dec" {
			op.Opcode = "sub"
		}
		op.Destination, op.Inputs = &left, []Operand{left, immediate(1, left.Width)}
		op.Flags = "x86_" + ins.Mnemonic
		return true
	}
	right, ok := x86Operand(inst.Args[1], inst, ins, left.Width)
	if !ok {
		return false
	}
	if strings.HasPrefix(ins.Mnemonic, "cmov") && left.Kind == "register" && right.Width == left.Width {
		op.Opcode, op.Destination, op.Inputs = "select", &left, []Operand{right, left}
		op.Condition = "x86.j" + strings.TrimPrefix(ins.Mnemonic, "cmov")
		return true
	}
	switch ins.Mnemonic {
	case "shl", "sal", "shr", "sar":
		if left.Width != 32 && left.Width != 64 ||
			right.Kind != "immediate" && (right.Kind != "register" || right.Register != "cl") {
			return false
		}
		op.Opcode = ins.Mnemonic
		if op.Opcode == "sal" {
			op.Opcode = "shl"
		}
		op.Destination, op.Inputs, op.Flags = &left, []Operand{left, right}, "x86_shift"
	case "imul":
		if left.Kind != "register" || left.Width < 32 {
			return false
		}
		inputs := []Operand{left, right}
		if inst.Args[2] != nil {
			third, valid := x86Operand(inst.Args[2], inst, ins, left.Width)
			if !valid || third.Kind != "immediate" {
				return false
			}
			inputs = []Operand{right, third}
		}
		op.Opcode, op.Destination, op.Inputs, op.Flags = "mul", &left, inputs, "x86_imul"
	case "mov":
		op.Opcode, op.Destination, op.Inputs = "copy", &left, []Operand{right}
	case "movzx", "movsx", "movsxd":
		if right.Kind == "immediate" || right.Width >= left.Width {
			return false
		}
		op.Opcode, op.Destination, op.Inputs = "sign_extend", &left, []Operand{right}
		if ins.Mnemonic == "movzx" {
			op.Opcode = "zero_extend"
		}
	case "lea":
		if right.Kind != "memory" || right.Memory.Segment != "" {
			return false
		}
		op.Opcode, op.Destination, op.Inputs = "address", &left, []Operand{right}
	case "add", "sub", "and", "or", "xor":
		op.Opcode, op.Destination, op.Inputs = ins.Mnemonic, &left, []Operand{left, right}
		op.Flags = "x86_" + ins.Mnemonic
	case "cmp", "test":
		op.Opcode, op.Flags, op.Inputs = "flags", fmt.Sprintf("x86_%s%d", ins.Mnemonic, left.Width), []Operand{left, right}
	default:
		return false
	}
	return true
}

func liftX86Stack(inst x86asm.Inst, ins Instruction, op *Operation) bool {
	reg, ok := x86Operand(inst.Args[0], inst, ins, inst.DataSize)
	if !ok || reg.Kind != "register" {
		return false
	}
	stack, segment := "esp", "ss"
	if inst.Mode == 64 {
		stack, segment = "rsp", ""
	}
	step := int64(reg.Width / 8)
	mem := Operand{Kind: "memory", Width: reg.Width, Memory: &MemoryAddress{Base: stack, Segment: segment}}
	op.Opcode = "copy"
	if ins.Mnemonic == "push" {
		step = -step
		mem.Memory.Displacement = step
		op.Destination, op.Inputs = &mem, []Operand{reg}
	} else {
		if reg.Register == "sp" || reg.Register == "esp" || reg.Register == "rsp" {
			return false
		}
		op.Destination, op.Inputs = &reg, []Operand{mem}
	}
	op.Writeback = &RegisterUpdate{Register: stack, Delta: step}
	return true
}

func x86Operand(arg x86asm.Arg, inst x86asm.Inst, ins Instruction, width int) (Operand, bool) {
	switch value := arg.(type) {
	case x86asm.Reg:
		switch {
		case value >= x86asm.AL && value <= x86asm.R15B:
			width = 8
		case value >= x86asm.AX && value <= x86asm.R15W:
			width = 16
		case value >= x86asm.EAX && value <= x86asm.R15L:
			width = 32
		case value >= x86asm.RAX && value <= x86asm.R15:
			width = 64
		default:
			return Operand{}, false
		}
		return register(x86RegisterName(value), width), true
	case x86asm.Imm:
		return immediate(uint64(value), width), true
	case x86asm.Mem:
		if value.Base == x86asm.EIP || value.Base == x86asm.IP || inst.AddrSize != inst.Mode {
			return Operand{}, false
		}
		memory := &MemoryAddress{Displacement: value.Disp, Scale: value.Scale}
		if value.Base == x86asm.RIP {
			if next := relativeAddress(ins.Address, int64(ins.Size)); next != nil {
				if address := relativeAddress(*next, value.Disp); address != nil {
					memory.Absolute, memory.Displacement = fmt.Sprintf("%#x", *address), 0
				}
			}
			if memory.Absolute == "" {
				return Operand{}, false
			}
		} else if value.Base != 0 {
			memory.Base = x86RegisterName(value.Base)
		}
		if value.Index != 0 {
			memory.Index = x86RegisterName(value.Index)
		}
		if value.Segment != 0 {
			memory.Segment = strings.ToLower(value.Segment.String())
		}
		if inst.MemBytes != 0 {
			width = inst.MemBytes * 8
		}
		return Operand{Kind: "memory", Width: width, Memory: memory}, true
	default:
		return Operand{}, false
	}
}

func x86RegisterName(reg x86asm.Reg) string {
	name := strings.ToLower(reg.String())
	if reg >= x86asm.R8L && reg <= x86asm.R15L {
		return strings.TrimSuffix(name, "l") + "d"
	}
	if reg >= x86asm.SPB && reg <= x86asm.DIB {
		return strings.TrimSuffix(name, "b") + "l"
	}
	return name
}
