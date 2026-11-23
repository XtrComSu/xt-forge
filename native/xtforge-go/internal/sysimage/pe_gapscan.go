package sysimage

import (
	"io"
	"math"
	"sort"
)

// Tight gap scanning for sparse PE images.
//
// Recursive descent follows direct calls, so a function entered only through an
// IAT slot or a vtable is invisible to it even though its prologue is sitting
// in the executable section. The previous scan treated any plausible prologue
// in such bytes as a function start; that produced 34-51 bytes of .text per
// indexed function on real DLLs, which is below the size of a compiled x86
// function. This pass keeps the same sweep but requires the surrounding
// evidence described by rules A-E below before it invents a start.
//
// Every invented entry is labelled "pe_gapscan" and carries no name, so an
// export or PDB name is never replaced. Images with a PE exception directory
// keep their .pdata index untouched: this pass returns before doing any work
// when descentSeeds is non-empty.

const (
	gapScanDefaultLimit = 20000
	// gapScanMaxBytes is a whole-image work budget: every swept byte and every
	// byte consumed by a candidate's validation decode is charged to it.
	gapScanMaxBytes = 64 << 20
	// gapScanMinSpacing is rule E: two accepted starts in one region must be
	// at least this far apart.
	gapScanMinSpacing = 8
	// gapScanWindow is rule D's validation horizon: six or more instructions
	// must decode and a terminator must appear inside this span.
	gapScanWindow = 256
	// gapScanMinInstructions is rule D's minimum decode length.
	gapScanMinInstructions = 6
	// functionExtentMaxBytes caps the body decoded for one known start when
	// deciding which bytes the sweep may skip.
	functionExtentMaxBytes = 4096
	gapScanSource          = "pe_gapscan"
)

// ScanUncoveredCode adds function starts in executable bytes that no known
// function covers, and returns how many starts it added. Rejecting a candidate
// never stops the sweep: the next byte is tried until the gap, the limit, or
// the work budget ends.
func ScanUncoveredCode(image *Image, r io.ReaderAt, limit int) int {
	if image == nil || r == nil || !descentArch(image) || len(image.Executable) == 0 {
		return 0
	}
	// Do not run for images with an exception directory (the x86-64 .pdata
	// case). That index must stay byte-identical to today's.
	if len(image.descentSeeds) != 0 {
		return 0
	}
	if limit <= 0 {
		limit = gapScanDefaultLimit
	}
	mode := 32
	if image.Bits == 64 {
		mode = 64
	}

	regions := append([]Region(nil), image.Executable...)
	sort.Slice(regions, func(i, j int) bool { return regions[i].Address < regions[j].Address })
	added, scanned := 0, 0
	type interval struct{ start, end uint64 }
	for _, section := range regions {
		size := min(section.Size, section.FileSize)
		if size == 0 {
			continue
		}
		region := descentRegion{start: section.Address, end: section.Address + size}

		// A known start covers its decoded body, not every byte up to the next
		// start. Bytes after a return and before the following function are
		// sweepable space; that is where the sparse DLLs hide their entries.
		// Bodies come from sorted addresses, so map iteration never decides
		// which byte is examined next.
		starts := make([]uint64, 0, len(image.functions)+1)
		for address := range image.functions {
			if address >= region.start && address < region.end {
				starts = append(starts, address)
			}
		}
		if image.EntryPoint != nil && *image.EntryPoint >= region.start && *image.EntryPoint < region.end {
			starts = append(starts, *image.EntryPoint)
		}
		sort.Slice(starts, func(i, j int) bool { return starts[i] < starts[j] })
		bodies := make([]interval, 0, len(starts))
		for _, start := range starts {
			if scanned >= gapScanMaxBytes {
				break
			}
			budget := gapScanMaxBytes - scanned
			maxBytes := functionExtentMaxBytes
			if budget < maxBytes {
				maxBytes = budget
			}
			end, ok := functionExtent(image, r, start, maxBytes)
			if ok && end > start {
				scanned += int(end - start)
			}
			if !ok || end <= start {
				end = start
			}
			if end > region.end {
				end = region.end
			}
			bodies = append(bodies, interval{start, end})
		}
		sort.Slice(bodies, func(i, j int) bool { return bodies[i].start < bodies[j].start })
		merged := bodies[:0]
		for _, body := range bodies {
			if last := len(merged) - 1; last >= 0 && body.start <= merged[last].end {
				if body.end > merged[last].end {
					merged[last].end = body.end
				}
				continue
			}
			merged = append(merged, body)
		}
		gaps := make([]interval, 0, len(merged)+1)
		cursor := region.start
		for _, body := range merged {
			if body.start > cursor {
				gaps = append(gaps, interval{cursor, body.start})
			}
			if body.end > cursor {
				cursor = body.end
			}
		}
		if cursor < region.end {
			gaps = append(gaps, interval{cursor, region.end})
		}

		var lastAccepted uint64
		var coveredUntil uint64
		haveAccepted, haveCovered := false, false
		for _, bounds := range gaps {
			gapStart, gapEnd := bounds.start, bounds.end
			if added >= limit || scanned >= gapScanMaxBytes {
				break
			}
			if gapEnd <= gapStart {
				continue
			}
			// An accepted run may reach past the next known body. Its decoded
			// body stays covered instead of being swept again from the start
			// of the following gap.
			pc := gapStart
			if haveCovered && pc < coveredUntil {
				pc = coveredUntil
			}
			var window []byte
			var windowStart uint64
			for pc < gapEnd && added < limit && scanned < gapScanMaxBytes {
				scanned++
				// Rule A: a known start is never re-proposed, and the entry
				// point keeps its own source label when Functions() adds it.
				if _, known := image.functions[pc]; known || (image.EntryPoint != nil && pc == *image.EntryPoint) {
					pc++
					continue
				}
				// Rule B: a strict, bitness-specific entry signature.
				if len(window) == 0 || pc < windowStart || pc-windowStart >= uint64(len(window)) ||
					uint64(len(window))-(pc-windowStart) < 8 {
					windowStart = pc
					var ok bool
					window, ok = descentRead(image, r, region, pc)
					if !ok || len(window) == 0 {
						break
					}
				}
				offset := int(pc - windowStart)
				if !gapStrictPrologue(image.Bits, window[offset:]) {
					pc++
					continue
				}
				// Rule C: the byte before a start must end the previous
				// function or be alignment; the region start also qualifies.
				if !gapPrecedingByte(image, r, region, pc) {
					pc++
					continue
				}
				// Rule E: keep accepted starts apart, per region.
				if haveAccepted && pc-lastAccepted < gapScanMinSpacing {
					pc++
					continue
				}
				// Rule D: a real decode run, not just a prologue-shaped word.
				end, ok := gapValidatedRun(image, r, region, pc, mode, &scanned)
				if !ok {
					pc++
					continue
				}
				image.addFunction(pc, 0, "", gapScanSource)
				if _, recorded := image.functions[pc]; !recorded {
					pc++
					continue
				}
				added++
				lastAccepted, haveAccepted = pc, true
				// The validated run is one function. Its decoded body, not the
				// whole validation horizon, is what the sweep may skip: rule D
				// can decode past an indirect jump into the next function.
				body, bodyOK := functionExtent(image, r, pc, functionExtentMaxBytes)
				if !bodyOK || body <= pc || body > region.end {
					body = end
				}
				coveredUntil, haveCovered = body, true
				next := body
				if next-pc < gapScanMinSpacing {
					next = pc + gapScanMinSpacing
				}
				if next <= pc {
					pc++
					continue
				}
				for next < gapEnd && window != nil && next >= windowStart && next-windowStart < uint64(len(window)) &&
					(window[next-windowStart] == 0x90 || window[next-windowStart] == 0xCC) {
					next++
				}
				coveredUntil, pc = next, next
			}
		}
	}
	return added
}

// functionExtent decodes from start until a terminator and returns the address one
// past the last byte of the body, bounded by the containing region and maxBytes.
// C3/C2 returns, E9/EB jumps, CC int3, and the FF /4 and FF /5 indirect jumps end
// a body. FF /2 and FF /3 indirect calls fall through instead. An undecodable
// byte ends the body at the last instruction that decoded; if none decoded the
// extent is not usable.
func functionExtent(image *Image, r io.ReaderAt, start uint64, maxBytes int) (uint64, bool) {
	if image == nil || r == nil || maxBytes <= 0 {
		return 0, false
	}
	region, ok := descentContainingRegion(image, start)
	if !ok {
		return 0, false
	}
	limit := uint64(min(maxBytes, functionExtentMaxBytes))
	if remain := region.end - start; remain < limit {
		limit = remain
	}
	if limit == 0 {
		return 0, false
	}
	data, ok := descentRead(image, r, region, start)
	if !ok || len(data) == 0 {
		return 0, false
	}
	if uint64(len(data)) > limit {
		data = data[:limit]
	}
	mode := 32
	if image.Bits == 64 {
		mode = 64
	}
	pc, offset := start, 0
	for offset < len(data) {
		first := data[offset]
		size := 0
		if _, n, cet := x86CETInstruction(data[offset:]); cet {
			size = n
		} else {
			inst, err := safeX86Decode(data[offset:], mode)
			if err != nil || inst.Len <= 0 || inst.Len > len(data)-offset || inst.Op == 0 {
				break
			}
			size = inst.Len
		}
		terminates := first == 0xC3 || first == 0xC2 || first == 0xE9 || first == 0xEB || first == 0xCC
		if first == 0xFF && offset+1 < len(data) {
			opcode := (data[offset+1] >> 3) & 7
			terminates = opcode == 4 || opcode == 5 // FF /4, FF /5 are indirect jumps
		}
		offset += size
		pc = start + uint64(offset)
		if terminates {
			return pc, true
		}
	}
	return pc, offset != 0
}

// gapDedupeSorted removes adjacent duplicates from an already sorted slice.
func gapDedupeSorted(values []uint64) []uint64 {
	if len(values) < 2 {
		return values
	}
	out := values[:1]
	for _, value := range values[1:] {
		if value != out[len(out)-1] {
			out = append(out, value)
		}
	}
	return out
}

// gapStrictPrologue is rule B. It checks raw bytes rather than decoded
// mnemonics: a prologue is evidence about an entry point, not about the
// instruction that happens to decode at that offset.
func gapStrictPrologue(bits int, data []byte) bool {
	if bits == 64 {
		switch {
		case len(data) >= 4 && data[0] == 0xF3 && data[1] == 0x0F && data[2] == 0x1E && data[3] == 0xFA: // endbr64
			return true
		case len(data) >= 1 && data[0] == 0x55: // push rbp
			return true
		case len(data) >= 4 && data[0] == 0x48 && data[1] == 0x83 && data[2] == 0xEC: // REX.W sub rsp, imm8
			return true
		case len(data) >= 7 && data[0] == 0x48 && data[1] == 0x81 && data[2] == 0xEC: // REX.W sub rsp, imm32
			return true
		case len(data) >= 3 && data[0] == 0x48 && data[1] == 0x89 && data[2] == 0xE5: // mov rbp, rsp
			return true
		}
		return false
	}
	switch {
	case len(data) >= 1 && data[0] == 0x55: // push ebp
		return true
	case len(data) >= 3 && data[0] == 0x83 && data[1] == 0xEC: // sub esp, imm8
		return true
	case len(data) >= 6 && data[0] == 0x81 && data[1] == 0xEC: // sub esp, imm32
		return true
	case len(data) >= 4 && data[0] == 0xF3 && data[1] == 0x0F && data[2] == 0x1E && data[3] == 0xFB: // endbr32
		return true
	case len(data) >= 3 && data[0] == 0x8B && data[1] == 0xFF && data[2] == 0x55: // mov edi,edi; push ebp
		return true
	}
	return false
}

// gapPrecedingByte is rule C. A failed read is a rejection, not a reason to
// accept: an unmapped predecessor is no evidence of a function boundary.
func gapPrecedingByte(image *Image, r io.ReaderAt, region descentRegion, address uint64) bool {
	if address == region.start {
		return true
	}
	if address == 0 {
		return false
	}
	offset, ok := image.fileOffset(address - 1)
	if !ok || offset > math.MaxInt64 {
		return false
	}
	var prev [1]byte
	n, err := r.ReadAt(prev[:], int64(offset))
	if n != 1 || err != nil {
		return false
	}
	switch prev[0] {
	case 0x00, 0x90, 0xCC, 0xC3, 0xCB:
		return true
	}
	return false
}

// gapValidatedRun is rule D: decode at least six consecutive instructions from
// the candidate and find ret/jmp/int3 within the first 256 bytes. It reports
// the exclusive end of the terminating instruction on success. CET landing
// pads are recognised explicitly because the raw x86 decoder reports them as
// a one-byte Op(0); decodeInstruction uses the same table for that reason.
func gapValidatedRun(image *Image, r io.ReaderAt, region descentRegion, address uint64, mode int, scanned *int) (uint64, bool) {
	data, ok := descentRead(image, r, region, address)
	if !ok || len(data) < gapScanMinInstructions {
		return 0, false
	}
	offset, instructions := 0, 0
	for offset < len(data) && offset < gapScanWindow {
		first := data[offset]
		size := 0
		if _, n, cet := x86CETInstruction(data[offset:]); cet {
			size = n
		} else {
			inst, err := safeX86Decode(data[offset:], mode)
			if err != nil || inst.Len <= 0 || inst.Len > len(data)-offset || inst.Op == 0 {
				return 0, false
			}
			size = inst.Len
		}
		*scanned += size
		offset += size
		instructions++
		if first == 0xC3 || first == 0xC2 || first == 0xE9 || first == 0xEB || first == 0xCC {
			if instructions < gapScanMinInstructions {
				return 0, false
			}
			return address + uint64(offset), true
		}
	}
	return 0, false
}
