package sysimage

import (
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
)

// decodeThumb decodes one Thumb instruction of 2 or 4 bytes.
// length is how many bytes the instruction occupies (2 or 4), and is zero when
// the encoding is not implemented. Unknown encodings are refused rather than
// decoded incorrectly. It never reads beyond len(data).
func decodeThumb(data []byte, address uint64) (ins Instruction, length int, ok bool) {
	if len(data) < 2 {
		return Instruction{Address: address}, 0, false
	}
	hw := binary.LittleEndian.Uint16(data)
	reg := func(value uint16) string { return arm32RegName(uint32(value)) }
	rd := func() string { return reg(hw & 7) }         // low-register destination
	rn := func() string { return reg((hw >> 3) & 7) }  // low-register source
	rm := func() string { return reg((hw >> 6) & 7) }  // low-register index
	rd8 := func() string { return reg((hw >> 8) & 7) } // destination in 8-bit-immediate forms
	imm8 := func() uint64 { return uint64(hw & 0xff) }
	done := func(mnemonic, operands, kind string) (Instruction, int, bool) {
		return thumbDone(address, 2, mnemonic, operands, kind)
	}
	branch := func(mnemonic, operands string, target uint64) (Instruction, int, bool) {
		ins, _, _ := thumbDone(address, 2, mnemonic, operands, "jump")
		ins.Target = &target
		return ins, 2, true
	}

	switch {
	case hw&0xf800 <= 0x1000: // shift by immediate (LSL/LSR/ASR); op is bits 15:11
		amount := (hw >> 6) & 0x1f
		name := [...]string{"lsls", "lsrs", "asrs"}[(hw>>11)&3]
		source := reg((hw >> 3) & 7)
		if name == "lsls" && amount == 0 {
			return done("movs", rd()+", "+source, "")
		}
		if name != "lsls" && amount == 0 {
			amount = 32
		}
		return done(name, fmt.Sprintf("%s, %s, #0x%x", rd(), source, amount), "")

	case hw&0xfe00 == 0x1800 || hw&0xfe00 == 0x1a00: // add/subtract register
		name := "adds"
		if hw&0x0200 != 0 {
			name = "subs"
		}
		return done(name, rd()+", "+rn()+", "+rm(), "")

	case hw&0xfe00 == 0x1c00 || hw&0xfe00 == 0x1e00: // add/subtract immediate3
		amount := (hw >> 6) & 7
		if amount == 0 {
			return done("movs", rd()+", "+rn(), "")
		}
		name := "adds"
		if hw&0x0200 != 0 {
			name = "subs"
		}
		return done(name, fmt.Sprintf("%s, %s, #0x%x", rd(), rn(), amount), "")

	case hw&0xe000 == 0x2000: // movs/cmp/adds/subs immediate8
		name := [...]string{"movs", "cmp", "adds", "subs"}[(hw>>11)&3]
		return done(name, rd8()+", #0x"+strconv.FormatUint(imm8(), 16), "")

	case hw&0xfc00 == 0x4000: // data-processing register
		op := (hw >> 6) & 0xf
		name := [...]string{
			"ands", "eors", "lsls", "lsrs", "asrs", "adcs", "sbcs", "rors",
			"tst", "rsbs", "cmp", "cmn", "orrs", "muls", "bics", "mvns",
		}[op]
		switch op {
		case 8, 10, 11: // tst, cmp, cmn
			return done(name, rn()+", "+rn(), "")
		case 9: // rsbs Rd, Rm, #0
			return done(name, rn()+", "+rn()+", #0", "")
		case 13: // muls Rd, Rdn, Rm
			return done(name, rd()+", "+rd()+", "+rn(), "")
		default:
			return done(name, rd()+", "+rn(), "")
		}

	case hw&0xfc00 == 0x4400: // high-register add/cmp/mov and bx/blx
		switch (hw >> 8) & 3 {
		case 0, 1, 2:
			name := [...]string{"add", "cmp", "mov"}[(hw>>8)&3]
			highRM := reg((hw >> 3) & 0xf)
			highRD := reg(hw&7 | (hw>>4)&8)
			return done(name, highRD+", "+highRM, "")
		case 3:
			regName := reg((hw >> 3) & 0xf)
			if hw&0x80 != 0 {
				return done("blx", regName, "call")
			}
			kind := "jump"
			if hw&0x78 == 0x70 { // Rm == lr
				kind = "return"
			}
			return done("bx", regName, kind)
		}

	case hw&0xf800 == 0x4800: // ldr literal: PC is (address+4) & ~3
		base := (address + 4) &^ uint64(3)
		if target := relativeAddress(base, int64(imm8()*4)); target != nil {
			load, _, _ := thumbDone(address, 2, "ldr",
				fmt.Sprintf("%s, [pc, #0x%x]", rd8(), imm8()*4), "")
			load.References = append(load.References, Reference{*target, "pc_relative"})
			return load, 2, true
		}
		return done("ldr", fmt.Sprintf("%s, [pc, #0x%x]", rd8(), imm8()*4), "")

	case hw&0xf000 == 0x5000: // load/store with register offset
		name, ok := thumbRegisterOffsetName(hw)
		if !ok {
			return Instruction{Address: address}, 0, false
		}
		return done(name, rd()+", ["+rn()+", "+rm()+"]", "")

	case hw>>12 >= 0x6 && hw>>12 <= 0x8: // load/store with immediate offset
		name, scale, ok := thumbImmediateOffsetName(hw)
		if !ok {
			return Instruction{Address: address}, 0, false
		}
		return done(name, rd()+", "+thumbBracket(rn(), (hw>>6)&0x1f, scale), "")

	case hw&0xf000 == 0x9000: // str/ldr [sp, #imm8*4]
		name := "str"
		if hw&0x0800 != 0 {
			name = "ldr"
		}
		return done(name, rd8()+", "+thumbBracket("sp", uint16(hw&0xff), 4), "")

	case hw&0xf000 == 0xa000: // adr / add or subtract sp
		if hw&0x0800 == 0 { // ADR: add Rd, pc, #imm8*4
			return done("adr", fmt.Sprintf("%s, #0x%x", rd8(), imm8()*4), "")
		}
		name := "add"
		if hw&0x0400 != 0 {
			name = "sub"
		}
		return done(name, rd8()+", sp, #0x"+strconv.FormatUint(imm8()*4, 16), "")

	case hw&0xf000 == 0xb000:
		if hw&0xfe00 == 0xb400 || hw&0xfe00 == 0xbc00 { // push/pop
			list, ok := thumbRegisterList(hw)
			if !ok {
				return Instruction{Address: address}, 0, false
			}
			name := "push"
			kind := ""
			if hw&0x0800 != 0 {
				name = "pop"
				if hw&0x0100 != 0 {
					kind = "return"
				}
			}
			return done(name, list, kind)
		}
		if hw&0xfe00 != 0xb000 { // other 0xbx00 space (hints, rev, ...) is out of scope
			return Instruction{Address: address}, 0, false
		}
		name := "add" // add/sub sp, #imm7*4
		if hw&0x0080 != 0 {
			name = "sub"
		}
		return done(name, "sp, #0x"+strconv.FormatUint(uint64(hw&0x7f)*4, 16), "")

	case hw&0xf000 == 0xc000: // stm/ldm with writeback
		list := thumbRegisterListBits(uint16(hw & 0xff))
		if hw&0xff == 0 {
			return Instruction{Address: address}, 0, false
		}
		name := "stmia"
		if hw&0x0800 != 0 {
			name = "ldmia"
		}
		return done(name, reg((hw>>10)&7)+"!, "+list, "")

	case hw&0xf000 == 0xd000: // conditional branch, udf and svc
		cond := (hw >> 8) & 0xf
		switch cond {
		case 0xe, 0xf:
			name := "udf"
			if cond == 0xf {
				name = "svc"
			}
			return done(name, "#0x"+strconv.FormatUint(imm8(), 16), "trap")
		}
		delta := int64(int8(hw&0xff)) * 2
		target := relativeAddress(address+4, delta)
		if target == nil {
			return Instruction{Address: address}, 0, false
		}
		return branch("b"+thumbCondNames[cond], fmt.Sprintf("0x%x", *target), *target)

	case hw&0xf800 == 0xe800 || hw&0xf800 == 0xf800: // other Thumb-2 32-bit forms
		return decodeThumb32(data, address)

	case hw&0xf800 == 0xe000: // unconditional 11-bit branch
		imm11 := int64(hw & 0x7ff)
		if imm11&0x400 != 0 {
			imm11 -= 0x800
		}
		target := relativeAddress(address+4, imm11*2)
		if target == nil {
			return Instruction{Address: address}, 0, false
		}
		return branch("b", fmt.Sprintf("0x%x", *target), *target)

	case hw&0xf800 == 0xf000: // Thumb-2 branch forms and other F0xx-F7xx forms
		// F24x/F2Cx is MOVW/MOVT territory: a halfword with bit 15 set in the
		// tail is a VFP/NEON encoding, not a BL/BLX, so do not guess a branch.
		if hw&0xfbf0 == 0xf240 || hw&0xfbf0 == 0xf2c0 {
			return decodeThumb32(data, address)
		}
		if ins, length, ok := decodeThumbBranch(data, address); ok {
			return ins, length, true
		}
		return decodeThumb32(data, address)
	}
	return Instruction{Address: address}, 0, false
}

// decodeThumb32 handles the common non-branch Thumb-2 32-bit encodings. A
// first halfword that matches only part of a form is refused, so unsupported
// encodings never acquire a guessed length or mnemonic.
func decodeThumb32(data []byte, address uint64) (Instruction, int, bool) {
	if len(data) < 4 {
		return Instruction{Address: address}, 0, false
	}
	first := binary.LittleEndian.Uint16(data)
	second := binary.LittleEndian.Uint16(data[2:])
	reg4 := func(value uint16) string { return arm32RegName(uint32(value)) }
	wide := func(mnemonic, operands, kind string) (Instruction, int, bool) {
		return thumbDone(address, 4, mnemonic, operands, kind)
	}
	refuse := func() (Instruction, int, bool) { return Instruction{Address: address}, 0, false }

	switch {
	case first&0xfff0 == 0xfb00:
		// Thumb-2 MUL: 1111 1011 0000 Rn / 1111 Rd 0000 Rm. Rendered with three
		// explicit registers, matching llvm-objdump ("mul r2, r0, r1"). It appeared in a
		// compiled switch and made that function undecodable, which in turn blocked its
		// caller's summary.
		if second&0xf0f0 != 0xf000 {
			return refuse()
		}
		return wide("mul", reg4(second>>8&0xf)+", "+reg4(first&0xf)+", "+reg4(second&0xf), "")

	case first&0xfff0 == 0xf8c0 || first&0xfff0 == 0xf8d0:
		// LDR/STR (immediate, 12-bit): 1111 1000 110T Rn / Rt imm12.
		name := "str.w"
		if first&0x00f0 == 0xd0 {
			name = "ldr.w"
		}
		operands := reg4(second>>12) + ", " + thumbBracket(reg4(first&0xf), second&0xfff, 1)
		return wide(name, operands, "")

	case first&0xfff0 == 0xf840 || first&0xfff0 == 0xf850:
		// LDR/STR (immediate, 8-bit): 1111 1000 010T Rn / Rt 1100 imm8.
		// 1101/1111 are the writeback forms and 1110 the unprivileged form;
		// those are out of scope and must stay undecoded.
		if second&0x0f00 != 0x0c00 {
			return refuse()
		}
		name := "str"
		if first&0x0010 != 0 {
			name = "ldr"
		}
		operands := fmt.Sprintf("%s, [%s, #-%d]", reg4(second>>12), reg4(first&0xf), second&0xff)
		return wide(name, operands, "")

	case first&0xfbf0 == 0xf240 || first&0xfbf0 == 0xf2c0:
		// MOVW/MOVT: 11110 i 100100 imm4 / imm4 0 Rd imm3 imm8.
		if second&0x8000 != 0 {
			return refuse()
		}
		name := "movw"
		if first&0x0080 != 0 { // MOVT has bit 7 set in the fixed field.
			name = "movt"
		}
		imm := uint16((first&0xf)<<12 | (second>>12)<<8 | (second & 0xff))
		operands := reg4((second>>8)&0xf) + ", #0x" + strconv.FormatUint(uint64(imm), 16)
		return wide(name, operands, "")

	case first&0xfbe0 == 0xf100 || first&0xfbe0 == 0xf1a0:
		// ADD/SUB (immediate) T3: bit 15 of the second halfword selects the
		// out-of-scope T4 encoding; the modified immediate is i:imm3:imm8.
		if second&0x8000 != 0 {
			return refuse()
		}
		name := "add.w"
		if first&0x0080 != 0 {
			name = "sub.w"
		}
		imm12 := uint16((first>>10)&1<<11 | (second>>12)&7<<8 | second&0xff)
		operands := fmt.Sprintf("%s, %s, #0x%x", reg4((second>>8)&0xf), reg4(first&0xf), thumbExpandImm(imm12))
		return wide(name, operands, "")

	case first == 0xe92d || first == 0xe8bd:
		// PUSH.W/POP.W.
		if second == 0 {
			return refuse()
		}
		name, kind := "push.w", ""
		if first == 0xe8bd {
			name, kind = "pop.w", ""
			if second&0x8000 != 0 {
				kind = "return"
			}
		}
		return wide(name, thumbRegisterListBits(second), kind)

	case first&0xfff0 == 0xe880 || first&0xfff0 == 0xe890 ||
		first&0xfff0 == 0xe8a0 || first&0xfff0 == 0xe8b0:
		// LDM.W/STM.W; bit 5 is writeback, bit 4 selects load.
		if second == 0 {
			return refuse()
		}
		name := "stm.w"
		if first&0x0010 != 0 {
			name = "ldm.w"
		}
		base := reg4(first & 0xf)
		if first&0x0020 != 0 {
			base += "!"
		}
		return wide(name, base+", "+thumbRegisterListBits(second), "")
	}
	return refuse()
}

// thumbExpandImm decodes Thumb's modified immediate (i:imm3:imm8) the same way
// llvm-objdump prints it, including the replicated-byte cases.
func thumbExpandImm(imm12 uint16) uint32 {
	imm8 := uint32(imm12 & 0xff)
	switch imm12 >> 10 {
	case 0:
		switch (imm12 >> 8) & 3 {
		case 0:
			return imm8
		case 1:
			return imm8<<16 | imm8
		case 2:
			return imm8<<24 | imm8<<8
		default:
			return imm8<<24 | imm8<<16 | imm8<<8 | imm8
		}
	default:
		unrotated := uint32(0x80 | uint16(imm12&0x7f))
		rotation := uint((imm12 >> 7) & 0x1f)
		return unrotated>>rotation | unrotated<<(32-rotation)
	}
}

// decodeThumbBranch handles the 32-bit BL, BLX (immediate) and B.W forms.
func decodeThumbBranch(data []byte, address uint64) (Instruction, int, bool) {
	if len(data) < 4 {
		return Instruction{Address: address}, 0, false
	}
	first := binary.LittleEndian.Uint16(data)
	second := binary.LittleEndian.Uint16(data[2:])
	s := int64((first >> 10) & 1)
	j1 := int64((second >> 13) & 1)
	j2 := int64((second >> 11) & 1)

	// BL: 11110 S imm10 / 11 J1 1 J2 imm11.
	if second&0xd000 == 0xd000 {
		i1, i2 := 1-(j1^s), 1-(j2^s)
		delta := (s << 24) | (i1 << 23) | (i2 << 22) |
			(int64(first&0x3ff) << 12) | (int64(second&0x7ff) << 1)
		if s != 0 {
			delta -= 1 << 25
		}
		target := relativeAddress(address+4, delta)
		if target == nil {
			return Instruction{Address: address}, 0, false
		}
		return thumbBranchDone(address, 4, "bl", fmt.Sprintf("0x%x", *target), "call", *target)
	}
	// BLX (immediate): 11110 S imm10H / 11 J1 0 J2 imm10L 00; base is PC aligned to 4.
	if second&0xd003 == 0xc000 {
		i1, i2 := 1-(j1^s), 1-(j2^s)
		delta := (s << 24) | (i1 << 23) | (i2 << 22) |
			(int64((first>>1)&0x3ff) << 12) | (int64((second>>2)&0x3ff) << 2)
		if s != 0 {
			delta -= 1 << 25
		}
		target := relativeAddress((address+4)&^uint64(3), delta)
		if target == nil {
			return Instruction{Address: address}, 0, false
		}
		return thumbBranchDone(address, 4, "blx", fmt.Sprintf("0x%x", *target), "call", *target)
	}
	// B.W / B<cond>.W: 11110 S cond imm6 / 10 J1 bit12 J2 imm11.
	if second&0xc000 == 0x8000 {
		cond := (first >> 6) & 0xf
		imm6 := int64(first & 0x3f)
		imm11 := int64(second & 0x7ff)
		name := "b.w"
		var delta int64
		if second&0x1000 != 0 { // unconditional B.W uses inverted J bits
			i1, i2 := 1-(j1^s), 1-(j2^s)
			delta = (s << 20) | (i1 << 19) | (i2 << 18) | (imm6 << 12) | (imm11 << 1)
		} else {
			if cond >= 0xe {
				return Instruction{Address: address}, 0, false
			}
			name = "b" + thumbCondNames[cond] + ".w"
			delta = (s << 20) | (j2 << 19) | (j1 << 18) | (imm6 << 12) | (imm11 << 1)
		}
		if s != 0 {
			delta -= 1 << 21
		}
		target := relativeAddress(address+4, delta)
		if target == nil {
			return Instruction{Address: address}, 0, false
		}
		return thumbBranchDone(address, 4, name, fmt.Sprintf("0x%x", *target), "jump", *target)
	}
	return Instruction{Address: address}, 0, false
}

func thumbBranchDone(address uint64, length int, mnemonic, operands, kind string, target uint64) (Instruction, int, bool) {
	ins, _, _ := thumbDone(address, length, mnemonic, operands, kind)
	ins.Target = &target
	return ins, length, true
}

func thumbDone(address uint64, length int, mnemonic, operands, kind string) (Instruction, int, bool) {
	ins := Instruction{Address: address, Size: length, Mnemonic: mnemonic, Operands: operands, Kind: kind}
	if operands == "" {
		ins.Text = mnemonic
	} else {
		ins.Text = mnemonic + " " + operands
	}
	return ins, length, true
}

var thumbCondNames = [14]string{
	"eq", "ne", "hs", "lo", "mi", "pl", "vs", "vc", "hi", "ls", "ge", "lt", "gt", "le",
}

// thumbBracket renders a scaled immediate offset, omitting a zero displacement
// to match llvm-objdump's syntax.
func thumbBracket(base string, imm uint16, scale uint16) string {
	offset := uint64(imm) * uint64(scale)
	if offset == 0 {
		return "[" + base + "]"
	}
	return fmt.Sprintf("[%s, #0x%x]", base, offset)
}

func thumbRegisterOffsetName(hw uint16) (string, bool) {
	// Load/store (register offset): bits 11:9 pick the access type and width.
	op := (hw >> 9) & 7
	return [...]string{"str", "strh", "strb", "ldrsb", "ldr", "ldrh", "ldrb", "ldrsh"}[op], true
}

func thumbImmediateOffsetName(hw uint16) (string, uint16, bool) {
	switch hw >> 12 {
	case 0x6:
		if hw&0x0800 == 0 {
			return "str", 4, true
		}
		return "ldr", 4, true
	case 0x7:
		if hw&0x0800 == 0 {
			return "strb", 1, true
		}
		return "ldrb", 1, true
	case 0x8:
		if hw&0x0800 == 0 {
			return "strh", 2, true
		}
		return "ldrh", 2, true
	}
	return "", 0, false
}

// thumbRegisterList maps the 8-bit Thumb push/pop list onto ARM register names,
// where bit 8 stands for lr (push) or pc (pop).
func thumbRegisterList(hw uint16) (string, bool) {
	mask := uint16(hw&0xff) &^ uint16(0x100)
	link := uint16(14) // push
	if hw&0x0800 != 0 {
		link = 15 // pop
	}
	if hw&0x0100 != 0 {
		mask |= 1 << link
	}
	if mask == 0 {
		return "", false
	}
	return thumbRegisterListBits(mask), true
}

// thumbRegisterListBits renders every set register separately. This matches
// llvm-objdump's Thumb output; collapsing adjacent registers into r4-r7 would
// count as an operand mismatch in the oracle comparison.
func thumbRegisterListBits(mask uint16) string {
	parts := make([]string, 0, 16)
	for i := uint(0); i < 16; i++ {
		if mask&(1<<i) != 0 {
			parts = append(parts, arm32RegName(uint32(i)))
		}
	}
	return "{" + strings.Join(parts, ", ") + "}"
}
