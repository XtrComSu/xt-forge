package sysimage

import (
	"fmt"
	"strconv"
	"strings"
)

// liftARM32 lifts one decoded A32 or Thumb instruction into the typed IR.
// It returns false when the instruction is not modelled, which keeps it opaque.
//
// The opcodes and operand shapes are the same ones liftX86 and liftARM use:
// "copy" for moves and single-register memory transfers, "copy_pair" for
// two-register stack transfers, "add"/"sub"/"and"/"or"/"xor" for arithmetic,
// "shl"/"shr"/"sar" for shifts, "flags" for comparisons, "call"/"jump"/
// "branch"/"return" for control flow, and "nop"/"trap" for hints and calls
// into the supervisor. Constructs with no faithful IR primitive (for example
// register complements, carry arithmetic, or register lists wider than two)
// are deliberately left opaque rather than given a misleading opcode.
func liftARM32(text string, mnemonic string, operands []string, op *Operation) bool {
	base, cond, ok := arm32SplitMnemonic(mnemonic)
	if !ok {
		return false
	}
	if cond != "" {
		op.Condition = "arm." + arm32Condition(cond)
	}
	switch base {
	case "nop":
		return len(operands) == 0 && setARM32Op(op, "nop")

	case "mov", "movs":
		if len(operands) == 3 {
			return liftARM32Shift(op, "copy", operands)
		}
		return liftARM32Copy(op, operands)

	case "movw":
		if len(operands) != 2 {
			return false
		}
		dest, ok := arm32Operand(operands[0])
		if !ok || dest.Kind != "register" {
			return false
		}
		value, ok := arm32Operand(operands[1])
		if !ok || value.Kind != "immediate" {
			return false
		}
		op.Opcode, op.Destination, op.Inputs = "copy", &dest, []Operand{value}
		return true

	case "movt":
		// MOVT replaces the high halfword; keeping the destination as an input
		// preserves the low halfword that MOVW installed.
		if len(operands) != 2 {
			return false
		}
		dest, ok := arm32Operand(operands[0])
		if !ok || dest.Kind != "register" {
			return false
		}
		value, ok := arm32Operand(operands[1])
		if !ok || value.Kind != "immediate" {
			return false
		}
		number, ok := arm32Integer(operands[1])
		if !ok {
			return false
		}
		op.Opcode, op.Destination, op.Inputs = "add", &dest,
			[]Operand{dest, immediate(uint64(number)<<16, dest.Width)}
		return true

	case "mvn", "mvns":
		if len(operands) != 2 {
			return false
		}
		dest, ok := arm32Operand(operands[0])
		if !ok || dest.Kind != "register" {
			return false
		}
		number, ok := arm32Integer(operands[1])
		if !ok {
			// A register complement has no typed IR primitive.
			return false
		}
		op.Opcode, op.Destination, op.Inputs = "copy", &dest,
			[]Operand{immediate(^uint64(number), dest.Width)}
		return true

	case "add", "adds", "sub", "subs", "rsb", "rsbs":
		return liftARM32Binary(op, base, operands)

	case "and", "ands", "orr", "orrs", "eor", "eors", "bic", "bics":
		return liftARM32Logical(op, base, operands)

	case "lsl", "lsls", "lsr", "lsrs", "asr", "asrs":
		return liftARM32Shift(op, base, operands)

	case "cmp", "cmn", "tst", "teq":
		if len(operands) < 2 {
			return false
		}
		left, ok := arm32Operand(operands[0])
		if !ok {
			return false
		}
		rightText := operands[1]
		if len(operands) > 2 && arm32IsShift(operands[2]) {
			rightText += " " + operands[2]
		}
		right, ok := arm32ArithmeticOperand(rightText)
		if !ok || len(operands) > 2 && !arm32IsShift(operands[2]) {
			return false
		}
		op.Opcode, op.Flags, op.Inputs = "flags",
			fmt.Sprintf("arm_%s32", base), []Operand{left, right}
		return true

	case "ldr", "str", "ldrb", "strb", "ldrh", "strh",
		"ldrsb", "ldrsh":
		return liftARM32Memory(op, base, operands)

	case "push", "pop":
		return liftARM32StackList(op, base, operands)

	case "bl", "blx":
		op.Opcode = "call"
		if arm32SetTarget(op, operands) {
			return true
		}
		if len(operands) != 1 {
			return false
		}
		reg, ok := arm32Operand(operands[0])
		if !ok || reg.Kind != "register" {
			return false
		}
		op.Inputs = []Operand{reg}
		return true

	case "bx":
		if len(operands) != 1 {
			return false
		}
		reg, ok := arm32Operand(operands[0])
		if !ok || reg.Kind != "register" {
			return false
		}
		if reg.Register == "lr" {
			return setARM32Op(op, "return")
		}
		op.Opcode, op.Inputs = "jump", []Operand{reg}
		return true

	case "b":
		if !arm32SetTarget(op, operands) {
			return false
		}
		if cond == "" {
			return setARM32Op(op, "jump")
		}
		return setARM32Op(op, "branch")

	case "cbz", "cbnz":
		if len(operands) < 1 || !arm32SetTarget(op, operands[1:]) {
			return false
		}
		reg, ok := arm32Operand(operands[0])
		if !ok || reg.Kind != "register" {
			return false
		}
		op.Opcode, op.Condition, op.Inputs = "branch", "arm."+base, []Operand{reg}
		return true

	case "svc", "udf":
		if len(operands) != 1 {
			return false
		}
		value, ok := arm32Operand(operands[0])
		if !ok || value.Kind != "immediate" {
			return false
		}
		op.Opcode, op.Inputs = "trap", []Operand{value}
		return true

	case "adr":
		if len(operands) != 2 {
			return false
		}
		dest, ok := arm32Operand(operands[0])
		if !ok || dest.Kind != "register" {
			return false
		}
		value, ok := arm32Operand(operands[1])
		if !ok {
			return false
		}
		op.Opcode, op.Destination, op.Inputs = "address", &dest, []Operand{value}
		return true
	}
	return false
}

func setARM32Op(op *Operation, opcode string) bool {
	op.Opcode = opcode
	return true
}

func liftARM32Copy(op *Operation, operands []string) bool {
	if len(operands) != 2 {
		return false
	}
	dest, ok := arm32Operand(operands[0])
	if !ok || dest.Kind != "register" {
		return false
	}
	value, ok := arm32Operand(operands[1])
	if !ok {
		return false
	}
	op.Opcode, op.Destination, op.Inputs = "copy", &dest, []Operand{value}
	return true
}

func liftARM32Binary(op *Operation, mnemonic string, operands []string) bool {
	opcode := strings.TrimSuffix(mnemonic, "s")
	reverse := opcode == "rsb"
	if len(operands) < 2 || len(operands) > 4 {
		return false
	}
	dest, ok := arm32Operand(operands[0])
	if !ok || dest.Kind != "register" {
		return false
	}
	left := dest
	rightIndex := 1
	if len(operands) >= 3 {
		left, ok = arm32Operand(operands[1])
		if !ok || left.Kind != "register" {
			return false
		}
		rightIndex = 2
	}
	rightText := operands[rightIndex]
	if rightIndex+1 < len(operands) {
		if !arm32IsShift(operands[rightIndex+1]) {
			return false
		}
		rightText += " " + operands[rightIndex+1]
	}
	right, ok := arm32ArithmeticOperand(rightText)
	if !ok {
		return false
	}
	if reverse {
		left, right = right, left
	}
	op.Opcode, op.Destination, op.Inputs = opcode, &dest, []Operand{left, right}
	if strings.HasSuffix(mnemonic, "s") {
		op.Flags = "arm_" + opcode
	}
	return true
}

func liftARM32Logical(op *Operation, mnemonic string, operands []string) bool {
	opcode := strings.TrimSuffix(mnemonic, "s")
	switch opcode {
	case "orr":
		opcode = "or"
	case "eor":
		opcode = "xor"
	case "bic":
		opcode = "and"
	}
	if len(operands) < 2 || len(operands) > 4 {
		return false
	}
	dest, ok := arm32Operand(operands[0])
	if !ok || dest.Kind != "register" {
		return false
	}
	left := dest
	rightIndex := 1
	if len(operands) >= 3 {
		left, ok = arm32Operand(operands[1])
		if !ok || left.Kind != "register" {
			return false
		}
		rightIndex = 2
	}
	rightText := operands[rightIndex]
	if rightIndex+1 < len(operands) {
		if !arm32IsShift(operands[rightIndex+1]) {
			return false
		}
		rightText += " " + operands[rightIndex+1]
	}
	right, ok := arm32ArithmeticOperand(rightText)
	if !ok {
		return false
	}
	if mnemonic == "bic" || mnemonic == "bics" {
		// BIC is rn & ~operand. Only the immediate form has an IR equivalent:
		// a register complement would need a new opcode.
		if right.Kind != "immediate" || strings.Contains(rightText, " ") {
			return false
		}
		number, ok := arm32Integer(operands[rightIndex])
		if !ok {
			return false
		}
		right = immediate(^uint64(number), dest.Width)
	}
	op.Opcode, op.Destination, op.Inputs = opcode, &dest, []Operand{left, right}
	if strings.HasSuffix(mnemonic, "s") {
		op.Flags = "arm_" + strings.TrimSuffix(mnemonic, "s")
	}
	return true
}

func liftARM32Shift(op *Operation, mnemonic string, operands []string) bool {
	base := strings.TrimSuffix(mnemonic, "s")
	if len(operands) < 2 || len(operands) > 3 {
		return false
	}
	dest, ok := arm32Operand(operands[0])
	if !ok || dest.Kind != "register" {
		return false
	}
	source := dest
	countText := operands[1]
	if len(operands) == 3 {
		source, ok = arm32Operand(operands[1])
		if !ok || source.Kind != "register" {
			return false
		}
		countText = operands[2]
	}
	// A32 MOV with a shifted source is a shift instruction in disguise:
	// "mov r0, r1, lsl #2" has no separate shift mnemonic. Three operands
	// without a shift token are not an ARM encoding this lifter knows.
	if base == "copy" && len(operands) == 3 && !arm32IsShift(countText) {
		return false
	}
	if arm32IsShift(countText) {
		fields := strings.Fields(countText)
		count, ok := arm32Operand(fields[1])
		if !ok || count.Kind != "immediate" {
			return false
		}
		base = fields[0]
		countText = fields[1]
	}
	count, ok := arm32Operand(countText)
	if !ok {
		return false
	}
	op.Opcode, op.Destination, op.Inputs = shiftOpcode(base), &dest,
		[]Operand{source, count}
	if strings.HasSuffix(mnemonic, "s") {
		op.Flags = "arm_shift"
	}
	return true
}

func liftARM32Memory(op *Operation, mnemonic string, operands []string) bool {
	if len(operands) < 2 || len(operands) > 3 {
		return false
	}
	width := 32
	switch mnemonic {
	case "ldrb", "strb", "ldrsb":
		width = 8
	case "ldrh", "strh", "ldrsh":
		width = 16
	}
	reg, ok := arm32Operand(operands[0])
	if !ok || reg.Kind != "register" {
		return false
	}
	memory, writeback, ok := arm32MemoryOperand(operands[1:], width)
	if !ok {
		return false
	}
	op.Opcode, op.Writeback = "copy", writeback
	if strings.HasPrefix(mnemonic, "ld") {
		op.Destination, op.Inputs = &reg, []Operand{memory}
	} else {
		op.Destination, op.Inputs = &memory, []Operand{reg}
	}
	return true
}

func arm32MemoryOperand(parts []string, width int) (Operand, *RegisterUpdate, bool) {
	if len(parts) == 0 {
		return Operand{}, nil, false
	}
	token := parts[0]
	if !strings.HasSuffix(token, "]") && !strings.HasSuffix(token, "]!") {
		return Operand{}, nil, false
	}
	preIndex := strings.HasSuffix(token, "]!")
	inner := strings.TrimSuffix(token, "]")
	inner = strings.TrimSuffix(inner, "!")
	inner = strings.TrimPrefix(inner, "[")
	fields := strings.Split(inner, ",")
	base, ok := arm32Operand(strings.TrimSpace(fields[0]))
	if !ok || base.Kind != "register" {
		return Operand{}, nil, false
	}
	address := &MemoryAddress{Base: base.Register, Scale: 1}
	var displacement int64
	if len(fields) > 1 {
		switch {
		case len(fields) > 2:
			index, ok := arm32Operand(strings.TrimSpace(fields[1]))
			if !ok || index.Kind != "register" {
				return Operand{}, nil, false
			}
			shift := strings.Fields(fields[2])
			if len(shift) != 2 || shift[0] != "lsl" {
				// MemoryAddress has no direction for lsr/asr indexing.
				return Operand{}, nil, false
			}
			scale, err := strconv.ParseUint(strings.TrimPrefix(shift[1], "#"), 0, 8)
			if err != nil || scale == 0 {
				return Operand{}, nil, false
			}
			address.Index, address.Scale = index.Register, uint8(scale)
		case arm32IsRegister(fields[1]):
			index, _ := arm32Operand(strings.TrimSpace(fields[1]))
			address.Index = index.Register
		default:
			displacement, ok = arm32Integer(fields[1])
			if !ok {
				return Operand{}, nil, false
			}
			address.Displacement = displacement
		}
	}
	var update *RegisterUpdate
	if preIndex {
		update = &RegisterUpdate{Register: base.Register, Delta: displacement}
	}
	if len(parts) > 1 {
		// Post-indexed: the access uses the unmodified base and the offset is
		// applied afterwards.
		delta, ok := arm32Integer(parts[1])
		if !ok {
			return Operand{}, nil, false
		}
		address.Displacement, address.Index, address.Scale = 0, "", 1
		update = &RegisterUpdate{Register: base.Register, Delta: delta}
	}
	return Operand{Kind: "memory", Width: width, Memory: address}, update, true
}

func liftARM32StackList(op *Operation, mnemonic string, operands []string) bool {
	if len(operands) != 1 {
		return false
	}
	registers, ok := arm32ListRegisters(operands[0])
	if !ok || len(registers) == 0 {
		return false
	}
	if len(registers) > 2 {
		// The IR carries two destinations, so a wide list cannot be a faithful copy_pair.
		// It is still modelled, because a prologue pushing four registers is the norm on
		// ARM32 and refusing it made every such function opaque. "stack_*_list" means
		// exactly what the analyser needs: move sp by four bytes per register and treat
		// those registers as clobbered. The individual slot writes are not claimed.
		opcode := "stack_push_list"
		if mnemonic == "pop" {
			opcode = "stack_pop_list"
		}
		op.Opcode, op.Destination, op.SecondDestination = opcode, nil, nil
		op.Inputs = make([]Operand, 0, len(registers))
		for _, name := range registers {
			op.Inputs = append(op.Inputs, register(name, 32))
		}
		return true
	}
	bytes := len(registers) * 4
	var mem []Operand
	var regs []Operand
	for i, name := range registers {
		offset := int64(i * 4)
		if mnemonic == "push" {
			offset = int64(i*4 - bytes)
		}
		memory := Operand{Kind: "memory", Width: 32,
			Memory: &MemoryAddress{Base: "sp", Displacement: offset}}
		reg := register(name, 32)
		regs = append(regs, reg)
		mem = append(mem, memory)
	}
	var first, second *Operand
	if len(mem) == 1 {
		first, second = &mem[0], nil
	} else {
		first, second = &mem[0], &mem[1]
	}
	var destFirst, destSecond *Operand
	if len(regs) == 1 {
		destFirst, destSecond = &regs[0], nil
	} else {
		destFirst, destSecond = &regs[0], &regs[1]
	}
	if mnemonic == "push" {
		op.Opcode, op.Destination, op.SecondDestination, op.Inputs = "copy_pair", first, second, regs
	} else {
		op.Opcode, op.Destination, op.SecondDestination, op.Inputs = "copy_pair", destFirst, destSecond, mem
	}
	if len(regs) == 1 {
		op.Opcode, op.SecondDestination = "copy", nil
		if mnemonic == "push" {
			op.Destination, op.Inputs = first, regs
		} else {
			op.Destination, op.Inputs = destFirst, mem
		}
	}
	delta := int64(bytes)
	if mnemonic == "push" {
		delta = -delta
	}
	op.Writeback = &RegisterUpdate{Register: "sp", Delta: delta}
	return true
}

func arm32ListRegisters(text string) ([]string, bool) {
	text = strings.TrimSpace(text)
	if len(text) < 2 || text[0] != '{' || text[len(text)-1] != '}' {
		return nil, false
	}
	var names []string
	for _, part := range strings.Split(text[1:len(text)-1], ",") {
		part = strings.TrimSpace(part)
		parts := strings.Split(part, "-")
		if len(parts) > 2 {
			return nil, false
		}
		first, ok := arm32RegNumber(parts[0])
		if !ok {
			return nil, false
		}
		last := first
		if len(parts) == 2 {
			last, ok = arm32RegNumber(parts[1])
			if !ok || last < first {
				return nil, false
			}
		}
		for reg := first; reg <= last; reg++ {
			names = append(names, arm32RegName(uint32(reg)))
		}
	}
	return names, true
}

func arm32RegNumber(name string) (int, bool) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "sp":
		return 13, true
	case "lr":
		return 14, true
	case "pc":
		return 15, true
	}
	if len(name) > 1 && (name[0] == 'r' || name[0] == 'R') {
		value, err := strconv.Atoi(name[1:])
		if err == nil && value >= 0 && value <= 15 {
			return value, true
		}
	}
	return 0, false
}

func arm32IsRegister(text string) bool {
	_, ok := arm32RegNumber(strings.TrimSpace(text))
	return ok
}

func arm32Operand(text string) (Operand, bool) {
	text = strings.TrimSpace(text)
	if arm32IsRegister(text) {
		return register(text, 32), true
	}
	if number, ok := arm32Integer(text); ok {
		return immediate(uint64(number), 32), true
	}
	return Operand{}, false
}

func arm32Integer(text string) (int64, bool) {
	text = strings.TrimSpace(text)
	text = strings.TrimPrefix(text, "#")
	if text == "" {
		return 0, false
	}
	value, err := strconv.ParseInt(text, 0, 64)
	if err != nil {
		return 0, false
	}
	return value, true
}

func arm32IsShift(text string) bool {
	fields := strings.Fields(text)
	return len(fields) == 2 && (fields[0] == "lsl" || fields[0] == "lsr" || fields[0] == "asr")
}

func arm32ArithmeticOperand(text string) (Operand, bool) {
	fields := strings.Fields(text)
	if len(fields) == 3 && arm32IsShift(fields[1]+" "+fields[2]) {
		value, ok := arm32Operand(fields[0])
		if !ok || value.Kind != "register" {
			return Operand{}, false
		}
		amount, ok := arm32Operand(fields[2])
		if !ok || amount.Kind != "immediate" {
			return Operand{}, false
		}
		number, err := strconv.ParseUint(strings.TrimPrefix(fields[2], "#"), 0, 8)
		if err != nil || number == 0 {
			return Operand{}, false
		}
		value.Scale, value.Shift = uint8(number), fields[1]
		return value, true
	}
	return arm32Operand(text)
}

func arm32SetTarget(op *Operation, operands []string) bool {
	if op.Target != nil {
		return true
	}
	if len(operands) == 0 {
		return false
	}
	value, ok := arm32Integer(operands[0])
	if !ok || value < 0 {
		return false
	}
	target := uint64(value)
	op.Target = &target
	return true
}

func arm32Condition(name string) string {
	switch name {
	case "hs":
		return "cs"
	case "lo":
		return "cc"
	}
	return name
}

var arm32MnemonicBases = []string{
	"movs", "movw", "movt", "mov", "adds", "add", "subs", "sub", "rsbs", "rsb",
	"ands", "and", "orrs", "orr", "eors", "eor", "bics", "bic", "lsls", "lsl",
	"lsrs", "lsr", "asrs", "asr", "cmp", "cmn", "tst", "teq", "mvns", "mvn",
	"ldrsb", "ldrsh", "ldrb", "ldrh", "ldr", "strb", "strh", "str", "push", "pop",
	"blx", "bl", "bx", "cbnz", "cbz", "b", "nop", "svc", "udf", "adr",
}

func arm32SplitMnemonic(mnemonic string) (string, string, bool) {
	name := strings.ToLower(strings.TrimSpace(mnemonic))
	name = strings.TrimSuffix(name, ".w")
	best, cond := "", ""
	for _, base := range arm32MnemonicBases {
		if !strings.HasPrefix(name, base) || len(base) <= len(best) {
			continue
		}
		suffix := name[len(base):]
		if suffix == "" || arm32IsCondition(suffix) {
			best, cond = base, suffix
		}
	}
	return best, cond, best != ""
}

func arm32IsCondition(name string) bool {
	switch name {
	case "eq", "ne", "cs", "cc", "mi", "pl", "vs", "vc", "hi", "ls",
		"ge", "lt", "gt", "le", "hs", "lo", "al":
		return true
	}
	return false
}

// arm32OperandTokens splits a decoded operand string on top-level commas, so
// "[sp, #4]" and "{r4, r5, lr}" remain single operands.
func arm32OperandTokens(text string) []string {
	if strings.TrimSpace(text) == "" {
		return nil
	}
	var parts []string
	start, depth := 0, 0
	for i, char := range text {
		switch char {
		case '[', '{', '(':
			depth++
		case ']', '}', ')':
			depth--
		case ',':
			if depth == 0 {
				parts = append(parts, strings.TrimSpace(text[start:i]))
				start = i + 1
			}
		}
	}
	parts = append(parts, strings.TrimSpace(text[start:]))
	return parts
}
