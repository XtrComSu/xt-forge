package sysimage

import (
	"io"
	"sort"
)

// Recursive-descent function discovery for 32- and 64-bit x86 PE images.
//
// An export table names the functions a DLL offers to callers, not the ones it
// calls itself. On the Wine i386 kernel32.dll measured here that is almost the
// whole index: 1411 functions against 3530 procedures reported by an external
// disassembler. Walking the code from every known start and adding direct call
// targets, prologue-shaped jump targets, and the functions following a return
// recovers entries that no PE directory declares.
//
// This is a heuristic, so every entry it invents carries source "pe_descent"
// and no name. It runs only on PE images whose metadata is sparse: the x86-64
// kernel32.dll already indexes every .pdata begin and must not be re-scanned.

const (
	descentDefaultLimit = 50000
	// descentMaxBytes caps the total decoded bytes for one image. It is a work
	// budget, not a function limit: a pathological image cannot make one call
	// to Functions() decode without end.
	descentMaxBytes = 64 << 20
	// descentWindow is read at a time per linear run; x86 instructions are at
	// most 15 bytes, so an 8 KiB window keeps ReadAt calls rare without holding
	// a whole section in memory.
	descentWindow = 8 << 10
	// descentZeroRun stops a linear run once it enters padding. Zeros decode as
	// harmless-looking x86 instructions, which would otherwise walk right out
	// of a function into unrelated bytes.
	descentZeroRun = 4
	// descentPadding is how far past a return the walker may look for the next
	// function. Compilers separate functions with 0x90 and 0xCC padding.
	descentPadding = 32
	// descentPatternBytes is the length of the known-start signature compared
	// when deciding whether a jump or fall-through target looks like a prologue.
	descentPatternBytes = 4
	// descentMinLeading is how often a first opcode must occur among the
	// image's known starts before a jump target sharing it is accepted. One
	// occurrence is an accident; repeated ones are a local convention.
	descentMinLeading = 3
)

type descentPatterns struct {
	exact   map[string]bool
	leading map[byte]int
}

type descentRegion struct {
	start uint64
	end   uint64 // exclusive, file-backed end of the containing executable region
}

// RecoverFunctionsByDescent walks executable code from known function starts,
// decoding instructions and treating the target of every direct call as a new
// function start. It returns how many functions it added.
func RecoverFunctionsByDescent(image *Image, r io.ReaderAt, limit int) int {
	if image == nil || r == nil || !descentArch(image) || len(image.Executable) == 0 {
		return 0
	}
	if limit <= 0 || limit > descentDefaultLimit {
		limit = descentDefaultLimit
	}
	arch := "x86"
	if image.Bits == 64 {
		arch = "x86_64"
	}

	// Signatures come from the starts known *before* descent runs. Taking them
	// from a live map would let one false positive certify the next one.
	patterns := descentKnownPatterns(image, r)

	queued := make(map[uint64]bool)
	var work []uint64
	seed := func(address uint64) {
		if !descentCanStart(image, address) || queued[address] {
			return
		}
		queued[address] = true
		work = append(work, address)
	}
	// Map iteration is random; sort the initial starts so two runs over the
	// same image make the same decisions when the limits cut work short.
	seeds := make([]uint64, 0, len(image.functions)+len(image.descentSeeds)+1)
	for address := range image.functions {
		seeds = append(seeds, address)
	}
	seeds = append(seeds, image.descentSeeds...)
	if image.EntryPoint != nil {
		seeds = append(seeds, *image.EntryPoint)
	}
	sort.Slice(seeds, func(i, j int) bool { return seeds[i] < seeds[j] })
	for _, address := range seeds {
		seed(address)
	}

	visited := make(map[uint64]bool)
	added := 0
	decoded := 0
	for i := 0; i < len(work) && added < limit && decoded < descentMaxBytes; i++ {
		start := work[i]
		if visited[start] {
			continue
		}
		region, ok := descentContainingRegion(image, start)
		if !ok {
			continue
		}
		var window []byte
		var windowStart uint64
	walk:
		for pc := start; pc < region.end && added < limit && decoded < descentMaxBytes; {
			if visited[pc] {
				break
			}
			visited[pc] = true
			// Refill the read window only when the current instruction is near
			// its end; an x86 instruction is at most 15 bytes.
			if len(window) == 0 || pc < windowStart || pc-windowStart >= uint64(len(window)-16) {
				windowStart = pc
				var ok bool
				window, ok = descentRead(image, r, region, pc)
				if !ok || len(window) == 0 {
					break
				}
			}
			data := window[pc-windowStart:]
			if descentZeroPadding(data) {
				break
			}
			inst, err := decodeInstruction(arch, pc, data)
			if err != nil || inst.Size <= 0 || inst.Size > len(data) {
				break
			}
			decoded += inst.Size
			next := pc + uint64(inst.Size)

			// addTarget both records a new function and queues its own walk.
			addTarget := func(target *uint64, needPrologue bool) {
				if target == nil || !descentCanStart(image, *target) {
					return
				}
				if needPrologue && !descentPlausibleStart(image, r, *target, patterns) {
					return
				}
				if !queued[*target] {
					if _, exists := image.functions[*target]; !exists {
						image.addFunction(*target, 0, "", "pe_descent")
						if _, exists := image.functions[*target]; exists {
							added++
						}
					}
				}
				seed(*target)
			}

			switch {
			case inst.Kind == "call":
				if inst.Target != nil && data[0] == 0xE8 {
					// E8 rel32: the direct call target is a function entry.
					addTarget(inst.Target, false)
				} else {
					// FF /2 and other indirect calls have no target to add.
					break walk
				}
			case inst.Kind == "jump" && inst.Target != nil:
				// E9/EB rel32/rel8 targets are only function entries when the
				// bytes there look like a start. Execution may still fall through
				// to the next instruction in this run, so keep decoding.
				addTarget(inst.Target, true)
			case inst.Kind == "jump":
				// FF /2 and FF /4 have no computable target; the run stops here
				// rather than inventing one.
				break walk
			case inst.Kind == "return" || inst.Kind == "trap":
				// The linear run ends at ret/int3. Look past the alignment
				// padding for the next function and start a *new* run there if
				// its bytes match a prologue or a known start.
				if after, ok := descentAfterPadding(image, r, region, next, patterns); ok {
					addTarget(&after, false)
				}
				break walk
			}
			pc = next
		}
	}
	return added
}

// descentArch reports whether this image's x86 decoder can be reused.
func descentArch(image *Image) bool {
	return (image.Arch == "x86" && image.Bits == 32) || (image.Arch == "x86_64" && image.Bits == 64)
}

// shouldRecoverByDescent is the wiring gate. Sparse PE32 images are scanned;
// an image with a complete function table is left alone. Density is measured
// against the file-backed image footprint: on this machine i386 kernel32.dll
// has 1411 functions over 461551 bytes (one per 327) while x86-64 kernel32.dll
// has 2776 over 446138 bytes (one per 161), so a one-per-256 rule selects the
// i386 image and keeps every x64 .pdata entry untouched.
func shouldRecoverByDescent(image *Image) bool {
	if image == nil || image.fileSize == 0 || !descentArch(image) || len(image.Executable) == 0 {
		return false
	}
	// A PE exception directory already declares the non-leaf functions. Even
	// when the file looks sparse (a large debug directory inflates its size),
	// re-scanning such an image only invents starts beside complete ground truth.
	if len(image.descentSeeds) != 0 {
		return false
	}
	return uint64(len(image.functions))*256 < image.fileSize
}

func descentContainingRegion(image *Image, address uint64) (descentRegion, bool) {
	for _, region := range image.Executable {
		span := min(region.Size, region.FileSize)
		if span == 0 || address < region.Address || address-region.Address >= span {
			continue
		}
		return descentRegion{start: region.Address, end: region.Address + span}, true
	}
	return descentRegion{}, false
}

func descentCanStart(image *Image, address uint64) bool {
	if _, ok := descentContainingRegion(image, address); !ok {
		return false
	}
	_, ok := image.fileOffset(address)
	return ok
}

// descentRead returns a contiguous file-backed window starting at address.
// It shrinks the request when the mapping ends early, but never reads past the
// containing executable region.
func descentRead(image *Image, r io.ReaderAt, region descentRegion, address uint64) ([]byte, bool) {
	if address < region.start || address >= region.end {
		return nil, false
	}
	want := uint64(descentWindow)
	if remain := region.end - address; remain < want {
		want = remain
	}
	for want >= 16 {
		offset, ok := image.fileRange(address, want)
		if ok {
			data := make([]byte, want)
			n, err := r.ReadAt(data, int64(offset))
			if n == len(data) {
				return data, true
			}
			_ = err
			return nil, false
		}
		want /= 2
	}
	return nil, false
}

// descentZeroPadding reports the start of a run of zero bytes, which is data
// or alignment rather than a function body.
func descentZeroPadding(data []byte) bool {
	run := 0
	for _, b := range data {
		if b != 0 {
			break
		}
		run++
		if run >= descentZeroRun {
			return true
		}
	}
	return false
}

// descentKnownPatterns collects the leading bytes of function starts already
// present in the image. A jump target that shares such a signature is likely
// to be another function rather than a mid-function label.
func descentKnownPatterns(image *Image, r io.ReaderAt) descentPatterns {
	patterns := descentPatterns{exact: make(map[string]bool), leading: make(map[byte]int)}
	for address := range image.functions {
		if !descentCanStart(image, address) {
			continue
		}
		if data, ok := descentRead(image, r, descentRegionOf(image, address), address); ok && len(data) >= descentPatternBytes {
			signature := string(data[:descentPatternBytes])
			if signature != "\x00\x00\x00\x00" {
				patterns.exact[signature] = true
				patterns.leading[data[0]]++
			}
		}
	}
	return patterns
}

// descentRegionOf is descentContainingRegion without the failure check; the
// callers have already verified that the address lies in a region.
func descentRegionOf(image *Image, address uint64) descentRegion {
	region, _ := descentContainingRegion(image, address)
	return region
}

// descentPlausibleStart applies the prologue filter for indirect and jump
// targets: a push of the frame pointer, a stack adjustment, an CET landing
// pad, or the byte signature of a function this image already declares.
func descentPlausibleStart(image *Image, r io.ReaderAt, address uint64, patterns descentPatterns) bool {
	region, ok := descentContainingRegion(image, address)
	if !ok {
		return false
	}
	data, ok := descentRead(image, r, region, address)
	if !ok || len(data) < 2 {
		return false
	}
	switch {
	case data[0] == 0x55: // push ebp / push rbp
		return true
	case data[0] == 0xF3 && data[1] == 0x0F && len(data) >= 4 && data[2] == 0x1E &&
		(data[3] == 0xFA || data[3] == 0xFB): // endbr64 / endbr32
		return true
	case len(data) >= 3 && data[0] == 0x48 && data[1] == 0x89 && data[2] == 0xE5: // mov rbp, rsp
		return true
	case len(data) >= 3 && data[0] == 0x83 && data[1] == 0xEC: // sub esp, imm8
		return true
	case len(data) >= 3 && data[0] == 0x81 && data[1] == 0xEC: // sub esp, imm32
		return true
	case len(data) >= 4 && data[0] == 0x48 && data[1] == 0x83 && data[2] == 0xEC: // sub rsp, imm8
		return true
	case len(data) >= 4 && data[0] == 0x48 && data[1] == 0x81 && data[2] == 0xEC: // sub rsp, imm32
		return true
	}
	if len(data) >= descentPatternBytes && patterns.exact[string(data[:descentPatternBytes])] {
		return true
	}
	return patterns.leading[data[0]] >= descentMinLeading
}

// descentAfterPadding skips 0x90/0xCC bytes after a terminating instruction
// and returns the first following address. It does not extend the linear run;
// the caller starts a fresh run there only if a prologue test passes.
func descentAfterPadding(image *Image, r io.ReaderAt, region descentRegion, address uint64, patterns descentPatterns) (uint64, bool) {
	if address < region.start || address >= region.end {
		return 0, false
	}
	data, ok := descentRead(image, r, region, address)
	if !ok {
		return 0, false
	}
	limit := min(uint64(descentPadding), region.end-address)
	if limit > uint64(len(data)) {
		limit = uint64(len(data))
	}
	for i := uint64(0); i < limit; i++ {
		if data[i] == 0x90 || data[i] == 0xCC {
			continue
		}
		candidate := address + i
		if descentPlausibleStart(image, r, candidate, patterns) {
			_, backed := image.fileOffset(candidate)
			return candidate, backed
		}
	}
	return 0, false
}
