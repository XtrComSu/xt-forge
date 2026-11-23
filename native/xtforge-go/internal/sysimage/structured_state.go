package sysimage

import (
	"fmt"
	"maps"
	"strconv"
	"strings"
)

type symbolicValue struct {
	text, origin string
	width        int
	stack        bool
	offset       int64
}

type symbolicFlags struct {
	kind                string
	left, right, result symbolicValue
}

type symbolicState struct {
	registers map[string]symbolicValue
	slots     map[int64]symbolicValue
	flags     symbolicFlags
}

func (s symbolicState) clone() symbolicState {
	return symbolicState{registers: maps.Clone(s.registers), slots: maps.Clone(s.slots), flags: s.flags}
}

// canonicalRegister maps width aliases of one physical register onto a single
// name. "sp" is deliberately left alone: it is the stack pointer on arm64 and
// the 16-bit alias on x86, and no caller can tell them apart here.
func canonicalRegister(name string) string {
	switch name {
	case "eax", "ebx", "ecx", "edx":
		return "r" + name[1:]
	case "edi", "esi", "esp", "ebp":
		return "r" + name[1:]
	case "ax", "bx", "cx", "dx":
		return "r" + name[1:] + "x"
	case "al", "ah":
		return "rax"
	case "bl", "bh":
		return "rbx"
	case "cl", "ch":
		return "rcx"
	case "dl", "dh":
		return "rdx"
	case "si", "sil":
		return "rsi"
	case "di", "dil":
		return "rdi"
	case "bp", "bpl":
		return "rbp"
	case "spl":
		return "rsp"
	case "lr":
		return "x30"
	case "fp":
		return "x29"
	case "wsp":
		return "sp"
	case "wzr":
		return "xzr"
	}
	if strings.HasPrefix(name, "w") && len(name) > 1 {
		return "x" + name[1:]
	}
	if strings.HasPrefix(name, "r") && len(name) > 2 {
		if suffix := name[len(name)-1]; suffix == 'd' || suffix == 'w' || suffix == 'b' {
			if name[1] >= '0' && name[1] <= '9' {
				return name[:len(name)-1]
			}
		}
	}
	return name
}

func (a *structuredAnalysis) read(state symbolicState, operand Operand) symbolicValue {
	unknown := symbolicValue{width: operand.Width}
	switch operand.Kind {
	case "immediate":
		return symbolicValue{text: operand.Immediate, width: operand.Width}
	case "register":
		if a.arch != "arm64" && (operand.Width == 8 || operand.Width == 16) {
			key := canonicalRegister(operand.Register)
			value := a.read(state, register(key, 32))
			if value.text == "" {
				return unknown
			}
			expression := value.text
			if operand.Register == "ah" || operand.Register == "bh" ||
				operand.Register == "ch" || operand.Register == "dh" {
				expression = "(" + expression + " >> 8)"
			}
			return symbolicValue{text: fmt.Sprintf("(uint%d_t)(%s)", operand.Width, expression), width: operand.Width}
		}
		if operand.Width != 64 && operand.Width != 32 {
			return unknown
		}
		key := canonicalRegister(operand.Register)
		if key == "xzr" {
			return symbolicValue{text: "0x0", width: operand.Width}
		}
		if value, ok := state.registers[key]; ok {
			if value.width == operand.Width {
				return value
			}
			if value.text != "" {
				return symbolicValue{text: fmt.Sprintf("(uint%d_t)(%s)", operand.Width, value.text), width: operand.Width}
			}
			return unknown
		}
		for i, reg := range a.abi.parameters {
			if reg != key {
				continue
			}
			if a.parameterUse[i] != 0 && a.parameterUse[i] != operand.Width {
				if a.parameterUse[i] == 64 && operand.Width == 32 {
					return symbolicValue{text: fmt.Sprintf("(uint32_t)(arg%d)", i), width: 32}
				}
				if a.parameterUse[i] == 32 && operand.Width == 64 && i < len(a.promote) {
					a.promote[i] = true
				}
				return unknown
			}
			a.parameterUse[i] = operand.Width
			return symbolicValue{text: fmt.Sprintf("arg%d", i), width: operand.Width}
		}
		// A callee-saved register can leave the state when it is spilled to the
		// frame and come back with the same identity on reload. ARM32 saves
		// 32-bit registers, while the other ABIs track this at 64 bits.
		if operand.Width == 64 || isARM32(a.arch) {
			unknown.origin = key
		}
	case "memory":
		sp := state.registers[a.abi.stack]
		if offset, ok := a.stackSlot(state, operand, sp.offset); ok {
			if value, known := state.slots[offset]; known && value.width == operand.Width {
				return value
			}
		}
	}
	return unknown
}

const maxStackExtent = 1 << 20

func (a *structuredAnalysis) stackSlot(state symbolicState, operand Operand, floor int64) (int64, bool) {
	m := operand.Memory
	if m == nil || m.Base == "" || m.Index != "" || m.Absolute != "" || m.Segment != "" ||
		m.Displacement < -maxStackExtent || m.Displacement > maxStackExtent {
		return 0, false
	}
	base := state.registers[canonicalRegister(m.Base)]
	sp := state.registers[a.abi.stack]
	if !base.stack || !sp.stack || operand.Width < 8 || operand.Width > 64 || operand.Width%8 != 0 {
		return 0, false
	}
	start := base.offset + m.Displacement
	end := start + int64(operand.Width/8)
	private := start >= floor-a.abi.redZone && end <= 0
	home := a.abi.homeBytes != 0 && start >= 8 && end <= 8+a.abi.homeBytes
	return start, private || home
}

func (a *structuredAnalysis) write(state *symbolicState, operand Operand, value symbolicValue, floor int64) bool {
	if operand.Width != value.width {
		return false
	}
	switch operand.Kind {
	case "register":
		if operand.Width != 32 && operand.Width != 64 {
			return false
		}
		key := canonicalRegister(operand.Register)
		if key == "xzr" {
			return true
		}
		if key == a.abi.stack && (!value.stack || value.offset > 0 || value.offset < -maxStackExtent) {
			return false
		}
		state.registers[key] = value
		return true
	case "memory":
		start, ok := a.stackSlot(*state, operand, floor)
		if !ok {
			return false
		}
		end := start + int64(operand.Width/8)
		for off, slot := range state.slots {
			if off < end && off+int64(slot.width/8) > start {
				delete(state.slots, off)
			}
		}
		state.slots[start] = value
		return true
	}
	return false
}

func (a *structuredAnalysis) apply(state *symbolicState, op Operation) bool {
	if isARM32(a.arch) && op.Opcode != "branch" && op.Condition != "" && op.Condition != "arm.al" {
		a.declineHere(fmt.Sprintf("conditional instruction %q at %#x is not modelled", op.Condition, op.Address))
		return false
	}
	if op.Opcode == "nop" {
		return true
	}
	if op.Opcode == "opaque" || op.Opcode == "call" || op.Opcode == "trap" {
		return false
	}
	sp := state.registers[a.abi.stack]
	if op.Opcode == "address" {
		// LEA builds an integer value. Resolve simple register-relative
		// expressions without reading memory or assuming a load address.
		if op.Destination == nil || len(op.Inputs) != 1 || op.Inputs[0].Memory == nil {
			return false
		}
		m := op.Inputs[0].Memory
		if m.Base == "" && m.Index == "" || m.Segment != "" || m.Absolute != "" {
			return false
		}
		width := op.Destination.Width
		left := symbolicValue{text: "0x0", width: width}
		if m.Base != "" {
			left = a.read(*state, register(m.Base, width))
		}
		if m.Index != "" {
			if m.Scale != 1 && m.Scale != 2 && m.Scale != 4 && m.Scale != 8 {
				return false
			}
			index := a.read(*state, register(m.Index, width))
			if m.Scale != 1 {
				index = binaryValue("mul", index, a.read(*state, immediate(uint64(m.Scale), width)), width)
			}
			if m.Base == "" {
				left = index
			} else {
				left = binaryValue("add", left, index, width)
			}
		}
		if m.Displacement == 0 && !left.stack {
			return a.write(state, *op.Destination, left, sp.offset)
		}
		right := a.read(*state, immediate(uint64(m.Displacement), width))
		return a.write(state, *op.Destination, binaryValue("add", left, right, width), sp.offset)
	}
	floor := sp.offset
	var update symbolicValue
	var updateKey string
	if op.Writeback != nil {
		updateKey = canonicalRegister(op.Writeback.Register)
		source := updateKey
		if op.Writeback.Base != "" {
			source = canonicalRegister(op.Writeback.Base)
		}
		update = state.registers[source]
		delta := op.Writeback.Delta
		if !update.stack || delta < -maxStackExtent || delta > maxStackExtent {
			return false
		}
		update.offset += delta
		if update.offset < -maxStackExtent || update.offset > 0 {
			return false
		}
		if updateKey == a.abi.stack {
			floor = min(floor, update.offset)
		}
	}
	inputs := make([]symbolicValue, len(op.Inputs))
	for i, operand := range op.Inputs {
		if operand.Kind == "memory" {
			if _, ok := a.stackSlot(*state, operand, floor); !ok {
				return false
			}
		}
		inputs[i] = a.read(*state, operand)
		if operand.Scale != 0 {
			if inputs[i].text == "" || operand.Scale >= uint8(operand.Width) {
				return false
			}
			operator := "<<"
			if operand.Shift == "asr" {
				value := typedTerm(inputs[i])
				inputs[i].text = fmt.Sprintf("((%s >> %du) | ((0u - (%s >> %du)) << %du))",
					value, operand.Scale, value, operand.Width-1, operand.Width-int(operand.Scale))
				continue
			} else if operand.Shift == "lsr" {
				operator = ">>"
			} else if operand.Shift != "" {
				return false
			}
			inputs[i].text = fmt.Sprintf("(%s %s %du)", typedTerm(inputs[i]), operator, operand.Scale)
		}
	}
	switch op.Opcode {
	case "select":
		if op.Destination == nil || len(inputs) != 2 || inputs[0].text == "" || inputs[1].text == "" ||
			inputs[0].width != op.Destination.Width || inputs[1].width != op.Destination.Width {
			return false
		}
		width := op.Destination.Width
		other := inputs[1]
		switch op.SelectFalseOp {
		case "":
		case "increment":
			other = binaryValue("add", other, symbolicValue{text: "0x1", width: width}, width)
		case "invert":
			mask := "0xffffffff"
			if width == 64 {
				mask = "0xffffffffffffffff"
			}
			other = binaryValue("xor", other, symbolicValue{text: mask, width: width}, width)
		case "negate":
			other = binaryValue("sub", symbolicValue{text: "0x0", width: width}, other, width)
		default:
			return false
		}
		test := a.predicate(*state, Operation{Condition: op.Condition})
		if test == "" || other.text == "" || len(test)+len(inputs[0].text)+len(other.text) > 480 {
			return false
		}
		value := symbolicValue{text: fmt.Sprintf("(%s ? %s : %s)", test, typedTerm(inputs[0]), typedTerm(other)),
			width: op.Destination.Width}
		return a.write(state, *op.Destination, value, floor)
	case "flags":
		if len(inputs) != 2 {
			return false
		}
		state.flags = symbolicFlags{kind: op.Flags, left: inputs[0], right: inputs[1]}
	case "copy", "copy_pair":
		if len(inputs) == 0 || op.Destination == nil || !a.write(state, *op.Destination, inputs[0], floor) {
			return false
		}
		if op.Opcode == "copy_pair" && (op.SecondDestination == nil || len(inputs) != 2 ||
			!a.write(state, *op.SecondDestination, inputs[1], floor)) {
			return false
		}
	case "umull", "umaddl", "umsubl":
		if op.Destination == nil || op.Destination.Width != 64 || len(inputs) < 2 ||
			inputs[0].width != 32 || inputs[1].width != 32 || inputs[0].text == "" || inputs[1].text == "" {
			return false
		}
		left := symbolicValue{text: fmt.Sprintf("(uint64_t)(%s)", inputs[0].text), width: 64}
		right := symbolicValue{text: fmt.Sprintf("(uint64_t)(%s)", inputs[1].text), width: 64}
		product := binaryValue("mul", left, right, 64)
		value := product
		if op.Opcode != "umull" {
			if len(inputs) != 3 || inputs[2].width != 64 {
				return false
			}
			value = binaryValue("add", product, inputs[2], 64)
			if op.Opcode == "umsubl" {
				value = binaryValue("sub", inputs[2], product, 64)
			}
		}
		if !a.write(state, *op.Destination, value, floor) {
			return false
		}
	case "shl", "shr", "sar":
		if op.Destination == nil || len(inputs) != 2 ||
			inputs[0].text == "" || (op.Destination.Width != 32 && op.Destination.Width != 64) {
			return false
		}
		if op.Inputs[1].Kind == "register" {
			// x86 shifts by CL only. arm64 names the count register in the
			// instruction, so any register is valid there: requiring "cl" would
			// have declined every arm64 variable shift.
			if a.arch != "arm64" && op.Inputs[1].Register != "cl" {
				return false
			}
			if inputs[1].text == "" {
				return false
			}
			value := inputs[0]
			term := typedTerm(value)
			count := fmt.Sprintf("(%s & %du)", typedTerm(inputs[1]), value.width-1)
			switch op.Opcode {
			case "shl":
				value.text = fmt.Sprintf("(%s << %s)", term, count)
			case "shr":
				value.text = fmt.Sprintf("(%s >> %s)", term, count)
			case "sar":
				value.text = fmt.Sprintf("(%s == 0u ? %s : ((%s >> %s) | ((0u - (%s >> %du)) << (%du - %s))))",
					count, term, term, count, term, value.width-1, value.width, count)
			}
			// x86 shifts write flags; arm64 shifts leave them untouched, so
			// clearing is only correct for x86.
			if a.arch != "arm64" {
				state.flags = symbolicFlags{}
			}
			return a.write(state, *op.Destination, value, floor)
		}
		if op.Inputs[1].Kind != "immediate" {
			return false
		}
		count, err := strconv.ParseUint(op.Inputs[1].Immediate, 0, 64)
		if err != nil {
			return false
		}
		count &= uint64(op.Destination.Width - 1)
		value := inputs[0]
		if count != 0 {
			term := typedTerm(value)
			switch op.Opcode {
			case "shl":
				value.text = fmt.Sprintf("(%s << %du)", term, count)
			case "shr":
				value.text = fmt.Sprintf("(%s >> %du)", term, count)
			case "sar":
				value.text = fmt.Sprintf("((%s >> %du) | ((0u - (%s >> %du)) << %du))",
					term, count, term, value.width-1, value.width-int(count))
			}
			if a.arch != "arm64" {
				state.flags = symbolicFlags{}
			}
		}
		if !a.write(state, *op.Destination, value, floor) {
			return false
		}
	case "madd", "msub":
		if len(inputs) != 3 || op.Destination == nil {
			return false
		}
		product := binaryValue("mul", inputs[0], inputs[1], op.Destination.Width)
		value := binaryValue("add", product, inputs[2], op.Destination.Width)
		if op.Opcode == "msub" {
			value = binaryValue("sub", inputs[2], product, op.Destination.Width)
		}
		if !a.write(state, *op.Destination, value, floor) {
			return false
		}
	case "stack_push_list", "stack_pop_list":
		// A wide push/pop: sp moves four bytes per register and those registers become
		// unknown (a pop loads them). The slot contents are not modelled, so anything
		// relying on them stays unknown rather than being guessed.
		if len(inputs) == 0 {
			return false
		}
		delta := int64(4 * len(op.Inputs))
		if op.Opcode == "stack_push_list" {
			delta = -delta
		}
		offset := sp.offset + delta
		if offset < -maxStackExtent || offset > 0 {
			return false
		}
		state.registers[a.abi.stack] = symbolicValue{width: sp.width, stack: true, offset: offset}
		for _, operand := range op.Inputs {
			if operand.Kind == "register" {
				state.registers[canonicalRegister(operand.Register)] = symbolicValue{}
			}
		}
		return true
	case "add", "sub", "and", "xor", "or", "mul":
		if len(inputs) != 2 || op.Destination == nil {
			return false
		}
		// A function whose first instruction adjusts the stack — `sub sp, #8`, which every
		// Thumb prologue does after `push` — has an sp that is not yet marked as stack, so
		// `inputs[0].stack` was false and the branch was skipped. The write to sp then failed
		// downstream and the whole function declined as `unsupported operation "sub"`.
		// Treat the stack register itself as the zero offset it is.
		base := inputs[0]
		if isARM32(a.arch) && !base.stack && op.Inputs[0].Kind == "register" &&
			canonicalRegister(op.Inputs[0].Register) == a.abi.stack {
			base = symbolicValue{width: op.Inputs[0].Width, stack: true, offset: 0}
			inputs[0] = base
		}
		if isARM32(a.arch) && (op.Opcode == "add" || op.Opcode == "sub") &&
			canonicalRegister(op.Destination.Register) == a.abi.stack && inputs[0].stack {
			// ARM32 adjusts the stack with 32-bit registers, while binaryValue
			// only tracks stack arithmetic at 64 bits.
			// ARM assembly writes immediates with a '#' prefix ("#8"), which ParseUint
			// rejects. Without stripping it, `sub sp, #8` declined as an unsupported
			// operation on every real ARM32 function whose first act is a stack adjustment.
			immediateText := strings.TrimPrefix(inputs[1].text, "#")
			imm, err := strconv.ParseUint(immediateText, 0, 64)
			if err != nil || imm > uint64(maxStackExtent) {
				return false
			}
			delta := int64(imm)
			if op.Opcode == "sub" {
				delta = -delta
			}
			offset := inputs[0].offset + delta
			if offset < -maxStackExtent || offset > 0 {
				return false
			}
			value := symbolicValue{width: op.Destination.Width, stack: true, offset: offset}
			if !a.write(state, *op.Destination, value, floor) {
				return false
			}
			if op.Flags != "" {
				state.flags = symbolicFlags{kind: op.Flags, left: inputs[0], right: inputs[1], result: value}
			}
			return true
		}
		value := binaryValue(op.Opcode, inputs[0], inputs[1], op.Destination.Width)
		if (op.Opcode == "xor" || op.Opcode == "sub") && op.Inputs[0].Kind == "register" &&
			op.Inputs[1].Kind == "register" && op.Inputs[0].Register == op.Inputs[1].Register &&
			op.Inputs[0].Scale == op.Inputs[1].Scale && op.Inputs[0].Shift == op.Inputs[1].Shift {
			value.text = "0x0"
		}
		if !a.write(state, *op.Destination, value, floor) {
			return false
		}
		if op.Flags != "" {
			if op.Flags == "x86_imul" {
				state.flags = symbolicFlags{}
			} else {
				state.flags = symbolicFlags{kind: op.Flags, left: inputs[0], right: inputs[1], result: value}
			}
		}
	default:
		return false
	}
	if op.Writeback != nil {
		state.registers[updateKey] = update
	}
	nextSP := state.registers[a.abi.stack]
	if nextSP.offset > sp.offset {
		for offset := range state.slots {
			if offset < nextSP.offset {
				delete(state.slots, offset)
			}
		}
	}
	return true
}

func binaryValue(op string, left, right symbolicValue, width int) symbolicValue {
	value := symbolicValue{width: width}
	if left.stack && (op == "add" || op == "sub") && width == 64 {
		imm, err := strconv.ParseUint(right.text, 0, 64)
		delta := int64(imm)
		if err != nil || delta < -maxStackExtent || delta > maxStackExtent {
			return value
		}
		if op == "sub" {
			delta = -delta
		}
		offset := left.offset + delta
		if offset >= -maxStackExtent && offset <= 0 {
			value.stack, value.offset = true, offset
		}
		return value
	}
	if left.text == "" || right.text == "" || left.width != width || right.width != width ||
		(width != 32 && width != 64) || len(left.text)+len(right.text) > 480 {
		return value
	}
	if op == "xor" && left.text == right.text {
		value.text = "0x0"
		return value
	}
	operators := map[string]string{"add": "+", "sub": "-", "and": "&", "xor": "^", "or": "|", "mul": "*"}
	value.text = "(" + typedTerm(left) + " " + operators[op] + " " + typedTerm(right) + ")"
	return value
}

func typedTerm(value symbolicValue) string {
	if !strings.HasPrefix(value.text, "0x") {
		return value.text
	}
	if value.width == 64 {
		return value.text + "ull"
	}
	return value.text + "u"
}
