package sysimage

import (
	"fmt"
	"math/bits"
	"strconv"
	"strings"
)

// decodeARM32 decodes one 32-bit ARM (A32) instruction.
// It returns ok=false for an encoding it does not implement; callers then emit an
// opaque instruction rather than a wrong one.
func decodeARM32(word uint32, address uint64) (Instruction, bool) {
	d := arm32Decoder{
		word:    word,
		address: address,
		cond:    arm32CondSuffix(word >> 28),
		ins:     Instruction{Address: address, Size: 4},
	}
	if word>>28 == 0xf {
		// The only unconditional-space encoding we understand is BLX
		// with an immediate branch target.
		if word&0x0e000000 == 0x0a000000 && word&0x01000000 != 0 {
			operands := ""
			if target := arm32BranchTarget(address, word); target != nil {
				d.ins.Target = target
				operands = fmt.Sprintf("0x%x", *target)
			}
			return d.done("blx", operands, "call")
		}
		return d.ins, false
	}

	// Miscellaneous instructions sharing the data-processing register space.
	switch word & 0x0ffffff0 {
	case 0x012fff10: // BX
		rm := arm32RegName(word & 0xf)
		kind := "jump"
		if word&0xf == 14 {
			kind = "return"
		}
		return d.done(d.name("bx"), rm, kind)
	case 0x012fff30: // BLX (register)
		return d.done(d.name("blx"), arm32RegName(word&0xf), "call")
	}
	if word&0x0fffffff == 0x0320f000 { // NOP hint
		return d.done(d.name("nop"), "", "")
	}

	// MOVW and MOVT live in the otherwise-invalid TEQ-without-S slot.
	switch word & 0x0ff00000 {
	case 0x03000000, 0x03400000:
		base := "movw"
		if word&0x00400000 != 0 {
			base = "movt"
		}
		imm := ((word >> 4) & 0xf000) | (word & 0xfff)
		return d.done(d.name(base), fmt.Sprintf("%s, #0x%x", arm32RegName((word>>12)&0xf), imm), "")
	}

	// Supervisor call and permanently undefined instructions.
	if word&0x0f000000 == 0x0f000000 {
		return d.done(d.name("svc"), fmt.Sprintf("#0x%x", word&0xffffff), "trap")
	}
	if word&0x0ff000f0 == 0x07f000f0 { // UDF: imm4:imm4 with a fixed 0xf nibble
		imm := ((word>>8)&0xf)<<4 | (word & 0xf)
		return d.done(d.name("udf"), fmt.Sprintf("#0x%x", imm), "trap")
	}

	// B, BL and their conditional forms use PC+8 as the offset base.
	if word&0x0e000000 == 0x0a000000 {
		base := "b"
		kind := "jump"
		if word&0x01000000 != 0 {
			base, kind = "bl", "call"
		}
		target := arm32BranchTarget(address, word)
		operands := ""
		if target != nil {
			d.ins.Target = target
			operands = fmt.Sprintf("0x%x", *target)
		}
		return d.done(d.name(base), operands, kind)
	}

	// Halfword and signed byte/halfword transfers (immediate offset only).
	if word&0x0e400090 == 0x00400090 {
		if word&0x10 == 0 {
			return d.ins, false // register offset is not implemented
		}
		load := word&(1<<20) != 0
		signed, halfword := word&(1<<6) != 0, word&(1<<5) != 0
		var base string
		switch {
		case signed && halfword:
			if !load {
				return d.ins, false
			}
			base = "ldrsh"
		case signed:
			if !load {
				return d.ins, false
			}
			base = "ldrsb"
		case halfword:
			if load {
				base = "ldrh"
			} else {
				base = "strh"
			}
		default:
			return d.ins, false
		}
		imm := int64(((word>>8)&0xf)<<4 | (word & 0xf))
		if word&(1<<23) == 0 {
			imm = -imm
		}
		decimal := fmt.Sprintf("#%d", imm)
		addressText, ok := arm32AddressText(word, decimal, decimal, imm == 0)
		if !ok {
			return d.ins, false
		}
		return d.done(d.name(base), arm32RegName((word>>12)&0xf)+", "+addressText, "")
	}

	// MUL and MLA.
	if word&0x0fc000f0 == 0x00000090 || word&0x0fc000f0 == 0x00200090 {
		base := "mul"
		operands := fmt.Sprintf("%s, %s, %s", arm32RegName((word>>16)&0xf), arm32RegName(word&0xf), arm32RegName((word>>8)&0xf))
		if word&(1<<21) != 0 {
			base = "mla"
			operands += ", " + arm32RegName((word>>12)&0xf)
		}
		if word&(1<<20) != 0 {
			base += "s"
		}
		return d.done(d.name(base), operands, "")
	}

	// LDM/STM, including the push/pop aliases.
	if word&0x0e000000 == 0x08000000 {
		return d.decodeLoadStoreMultiple()
	}

	// Single data transfer with an immediate offset.
	if word&0x0e000000 == 0x04000000 {
		base := "str"
		if word&(1<<20) != 0 {
			base = "ldr"
		}
		if word&(1<<22) != 0 {
			base += "b"
		}
		imm := int64(word & 0xfff)
		if word&(1<<23) == 0 {
			imm = -imm
		}
		addressText, ok := arm32AddressText(word, arm32HexImmediate(imm), fmt.Sprintf("#%d", imm), imm == 0)
		if !ok {
			return d.ins, false
		}
		return d.done(d.name(base), arm32RegName((word>>12)&0xf)+", "+addressText, "")
	}

	// Data-processing with an immediate operand.
	if word&0x0e000000 == 0x02000000 {
		opcode := (word >> 21) & 0xf
		imm12 := word & 0xfff
		if (imm12>>8)&1 != 0 { // odd rotation counts are not encodable
			return d.ins, false
		}
		imm := bits.RotateLeft32(imm12&0xff, -int((imm12>>8)&0xf)*2)
		return d.decodeDataProcessing(opcode, arm32SignedImmediate(imm), true)
	}

	// Data-processing with a register operand and an immediate shift.
	if word&0x0e000000 == 0x00000000 {
		if word&0x10 != 0 { // register-shifted register is not implemented
			return d.ins, false
		}
		shift, ok := arm32ShiftText(word)
		if !ok {
			return d.ins, false
		}
		return d.decodeDataProcessing((word>>21)&0xf, arm32RegName(word&0xf)+shift, false)
	}

	return d.ins, false
}

type arm32Decoder struct {
	word    uint32
	address uint64
	cond    string
	ins     Instruction
}

func (d *arm32Decoder) name(base string) string { return base + d.cond }

func (d *arm32Decoder) done(mnemonic, operands, kind string) (Instruction, bool) {
	d.ins.Mnemonic = strings.ToLower(mnemonic)
	d.ins.Operands = operands
	if operands == "" {
		d.ins.Text = d.ins.Mnemonic
	} else {
		d.ins.Text = d.ins.Mnemonic + " " + operands
	}
	d.ins.Kind = kind
	return d.ins, true
}

func (d *arm32Decoder) decodeDataProcessing(opcode uint32, operand string, immediate bool) (Instruction, bool) {
	_ = immediate
	base := [...]string{"and", "eor", "sub", "rsb", "add", "adc", "sbc", "rsc", "tst", "teq", "cmp", "cmn", "orr", "mov", "bic", "mvn"}[opcode]
	setFlags := d.word&(1<<20) != 0
	compare := opcode >= 8 && opcode <= 11
	if compare && !setFlags {
		return d.ins, false
	}
	rd := arm32RegName((d.word >> 12) & 0xf)
	rn := arm32RegName((d.word >> 16) & 0xf)
	if (opcode == 13 || opcode == 15) && (d.word>>16)&0xf != 0 {
		return d.ins, false
	}
	if setFlags && !compare {
		base += "s"
	}
	var operands string
	switch {
	case compare:
		operands = rn + ", " + operand
	case opcode == 13 || opcode == 15:
		operands = rd + ", " + operand
	default:
		operands = rd + ", " + rn + ", " + operand
	}
	return d.done(d.name(base), operands, "")
}

func (d *arm32Decoder) decodeLoadStoreMultiple() (Instruction, bool) {
	word := d.word
	if word&(1<<22) != 0 { // user-mode register form is not implemented
		return d.ins, false
	}
	list := uint16(word & 0xffff)
	if list == 0 {
		return d.ins, false
	}
	registers := arm32RegisterList(list)
	load := word&(1<<20) != 0
	writeback := word&(1<<21) != 0
	baseReg := (word >> 16) & 0xf
	pre, up := word&(1<<24) != 0, word&(1<<23) != 0
	if baseReg == 13 && writeback {
		if !load && pre && !up { // STMDB sp!, {...}
			return d.done(d.name("push"), registers, "")
		}
		if load && !pre && up { // LDMIA sp!, {...}
			kind := ""
			if list&(1<<15) != 0 {
				kind = "return"
			}
			return d.done(d.name("pop"), registers, kind)
		}
	}
	mode := ""
	switch {
	case pre && up:
		mode = "ib"
	case pre:
		mode = "db"
	case !up:
		mode = "da"
	}
	base := arm32RegName(baseReg)
	if writeback {
		base += "!"
	}
	name := "stm" + mode
	kind := ""
	if load {
		name = "ldm" + mode
	}
	return d.done(d.name(name), base+", "+registers, kind)
}

var arm32CondNames = [16]string{"eq", "ne", "cs", "cc", "mi", "pl", "vs", "vc", "hi", "ls", "ge", "lt", "gt", "le", "", ""}

func arm32CondSuffix(cond uint32) string {
	if cond == 0xf {
		return ""
	}
	if cond == 14 {
		return ""
	}
	return arm32CondNames[cond]
}

func arm32RegName(reg uint32) string {
	switch reg {
	case 13:
		return "sp"
	case 14:
		return "lr"
	case 15:
		return "pc"
	default:
		return "r" + strconv.FormatUint(uint64(reg), 10)
	}
}

func arm32RegisterList(list uint16) string {
	parts := make([]string, 0, 16)
	for i := 0; i < 16; {
		if list&(1<<i) == 0 {
			i++
			continue
		}
		last := i
		for last+1 < 16 && list&(1<<(last+1)) != 0 {
			last++
		}
		if last > i {
			parts = append(parts, arm32RegName(uint32(i))+"-"+arm32RegName(uint32(last)))
		} else {
			parts = append(parts, arm32RegName(uint32(i)))
		}
		i = last + 1
	}
	return "{" + strings.Join(parts, ", ") + "}"
}

func arm32ShiftText(word uint32) (string, bool) {
	kind, amount := (word>>5)&3, (word>>7)&0x1f
	switch kind {
	case 0: // LSL
		if amount == 0 {
			return "", true
		}
		return fmt.Sprintf(", lsl #%d", amount), true
	case 1: // LSR
		if amount == 0 {
			return ", lsr #32", true
		}
		return fmt.Sprintf(", lsr #%d", amount), true
	case 2: // ASR
		if amount == 0 {
			return ", asr #32", true
		}
		return fmt.Sprintf(", asr #%d", amount), true
	default: // ROR, with #0 denoting RRX
		if amount == 0 {
			return ", rrx", true
		}
		return fmt.Sprintf(", ror #%d", amount), true
	}
}

func arm32AddressText(word uint32, offset, postOffset string, zero bool) (string, bool) {
	base := arm32RegName((word >> 16) & 0xf)
	pre, writeback := word&(1<<24) != 0, word&(1<<21) != 0
	switch {
	case pre && writeback:
		return fmt.Sprintf("[%s, %s]!", base, offset), true
	case pre && zero:
		return "[" + base + "]", true
	case pre:
		return fmt.Sprintf("[%s, %s]", base, offset), true
	case !writeback:
		return fmt.Sprintf("[%s], %s", base, postOffset), true
	default:
		return "", false
	}
}

func arm32HexImmediate(value int64) string {
	if value < 0 {
		return fmt.Sprintf("#-0x%x", -value)
	}
	return fmt.Sprintf("#0x%x", value)
}

func arm32SignedImmediate(value uint32) string {
	return fmt.Sprintf("#%d", int64(int32(value)))
}

func arm32BranchTarget(address uint64, word uint32) *uint64 {
	offset := int64(word & 0xffffff)
	if offset&0x800000 != 0 {
		offset -= 0x1000000
	}
	return relativeAddress(address, offset*4+8)
}
