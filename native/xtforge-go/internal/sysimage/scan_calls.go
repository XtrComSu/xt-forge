package sysimage

import (
	"io"
	"sort"
)

// Function recovery for binaries with no section table.
//
// This file is deliberately NOT named scan_arm64.go: a _arm64 suffix makes Go build it
// only for GOARCH=arm64, so on an amd64 host the package silently loses the symbol and
// every reference reports "undefined". The scanner itself is host-independent — it
// inspects target bytes, it does not run them.
//
// A stripped firmware ELF often has program headers and nothing else: no sections, no
// symbol table, no .eh_frame. Measured on a real vendor firehose programmer (629 KB,
// aarch64, "no sections in this file"), the engine recovered exactly one function — the
// entry point. That is technically honest and practically useless.
//
// What such a binary does still contain is calls. Every BL or B instruction encodes its
// target directly, and a target inside an executable segment is a function entry with
// very high probability. That is a heuristic, so it is labelled as one: functions found
// this way carry source "arm64_call_target" and the pass only runs when the binary has
// no section headers at all, so a well-described image never gets invented starts.

const (
	// arm64ScanChunk bounds how much is read at once per region.
	arm64ScanChunk = 1 << 20
	// arm64CallTargetLimit bounds how many functions the scan may add, so a pathological
	// binary cannot turn one analysis into hundreds of thousands of entries.
	arm64CallTargetLimit = 50000
)

// ARM64 instruction masks for the branch forms that name a target.
const (
	arm64MaskBranch = 0xFC000000
	arm64OpBL       = 0x94000000
	arm64OpB        = 0x14000000
)

// scanARM64CallTargets adds a function for every in-range branch target.
// It returns how many functions it added.
func scanARM64CallTargets(image *Image, r io.ReaderAt, limit int) int {
	if image.Arch != "arm64" || image.Bits != 64 {
		return 0
	}
	if limit <= 0 || limit > arm64CallTargetLimit {
		limit = arm64CallTargetLimit
	}
	regions := image.Executable
	if len(regions) == 0 {
		return 0
	}
	candidates := map[uint64]bool{}
	for _, region := range regions {
		if len(candidates) >= limit {
			break
		}
		if region.FileSize < 4 {
			continue
		}
		read := region.FileSize
		if read > arm64ScanChunk*8 {
			read = arm64ScanChunk * 8
		}
		// Read in chunks so one large segment does not allocate the whole file again.
		for base := uint64(0); base < read && len(candidates) < limit; base += arm64ScanChunk {
			size := arm64ScanChunk
			if remain := read - base; remain < uint64(size) {
				size = int(remain)
			}
			// Keep word alignment: a partial chunk must not shift the instruction grid.
			size &^= 3
			if size == 0 {
				break
			}
			buffer := make([]byte, size)
			if _, err := r.ReadAt(buffer, int64(region.Offset+base)); err != nil {
				break
			}
			for offset := 0; offset+4 <= len(buffer); offset += 4 {
				word := uint32(buffer[offset]) | uint32(buffer[offset+1])<<8 |
					uint32(buffer[offset+2])<<16 | uint32(buffer[offset+3])<<24
				target, isCall, ok := arm64BranchTarget(word, region.Address+base+uint64(offset))
				if !ok {
					continue
				}
				if !image.inExecutable(target) {
					continue
				}
				// Measured on a real 579 KB firmware image: BL targets are 54% prologue-like,
				// while plain B targets are only 8.4% — the rest are jump labels inside a
				// function, mostly switch and loop targets. So a call is taken as evidence of
				// a function entry, and an unconditional branch only when the target actually
				// starts like a function. That drops ~2400 junk entries on that image while
				// keeping the plausible ones.
				if !isCall && !image.isARM64Prologue(r, target) {
					continue
				}
				if _, exists := image.functions[target]; exists {
					continue
				}
				candidates[target] = true
			}
		}
	}
	// Two entries four bytes apart cannot both be functions: the second would be a
	// single instruction, and an ARM64 function needs at least a body and a return.
	// Measured on a real image, 91 of 1787 entries were exactly that, so the later one
	// of each such pair is dropped. An eight-byte gap is left alone, because an
	// eight-byte leaf function is entirely normal.
	ordered := make([]uint64, 0, len(candidates))
	for address := range candidates {
		ordered = append(ordered, address)
	}
	sort.Slice(ordered, func(i, j int) bool { return ordered[i] < ordered[j] })
	added := 0
	previous := uint64(0)
	havePrevious := false
	for _, address := range ordered {
		if havePrevious && address == previous+4 {
			havePrevious = true
			continue
		}
		image.addFunction(address, 0, "", "arm64_call_target")
		if _, exists := image.functions[address]; exists {
			added++
		}
		previous, havePrevious = address, true
	}
	return added
}

// arm64BranchTarget decodes the target of a branch at pc, if the instruction has one.
//
// BL and B use a 26-bit word offset; B.cond uses 19 bits. Both are scaled by four. The
// immediates are signed two's complement, so a backward branch yields a lower target.
func arm64BranchTarget(word uint32, pc uint64) (target uint64, isCall bool, ok bool) {
	switch {
	case word&arm64MaskBranch == arm64OpBL, word&arm64MaskBranch == arm64OpB:
		offset := int64(int32(word<<6) >> 6) // sign-extend bits 25..0
		return pc + uint64(offset<<2), word&arm64MaskBranch == arm64OpBL, true
	}
	// B.cond is deliberately excluded. Its targets are overwhelmingly intra-function
	// labels: counting them took a real 579 KB firmware image from 4088 plausible
	// entries to 6522, and the extra 2400 were jump labels, not functions. A call
	// target is a function entry; a conditional branch target usually is not.
	return 0, false, false
}

// isARM64Prologue reports whether the instruction at address starts a function in the
// forms compilers actually emit: a callee-saved register pair or store with pre-index, a
// stack adjustment, or pointer authentication.
//
// It is a filter, not a proof: a leaf function legitimately starts with none of these, so
// this is only used to reject branch targets whose first instruction is plainly
// mid-function code.
func (image *Image) isARM64Prologue(r io.ReaderAt, address uint64) bool {
	offset, ok := image.fileRange(address, 4)
	if !ok {
		return false
	}
	var raw [4]byte
	if _, err := r.ReadAt(raw[:], int64(offset)); err != nil {
		return false
	}
	word := uint32(raw[0]) | uint32(raw[1])<<8 | uint32(raw[2])<<16 | uint32(raw[3])<<24
	switch {
	case word&0xFFC07FFF == 0xA9807BFD, word&0xFFC07FFF == 0xA9007BFD:
		return true // stp x29, x30, [sp, #±imm]
	case word&0xFFC00000 == 0xA9800000:
		return true // any stp with pre-index writeback
	case word&0xFFC00000 == 0xF8000000 && (word>>10)&3 == 3:
		return true // str with pre-index writeback
	case word&0xFFC003FF == 0xD10003FF:
		return true // sub sp, sp, #imm
	case word == 0xD503233F, word == 0xD503237F:
		return true // paciasp / pacibsp
	}
	return false
}

// inExecutable reports whether an address falls inside a file-backed executable region.
func (image *Image) inExecutable(address uint64) bool {
	for _, region := range image.Executable {
		if address >= region.Address && address < region.Address+region.Size {
			return true
		}
	}
	return false
}
