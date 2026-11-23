package sysimage

import (
	"bytes"
	"encoding/binary"
	"os"
	"testing"
)

// arm64 branch encoders for the tests: target is a byte offset relative to pc.
func arm64BL(pc, target uint64) uint32 {
	offset := int64(target) - int64(pc)
	return 0x94000000 | uint32((offset>>2)&0x03FFFFFF)
}

func arm64B(pc, target uint64) uint32 {
	offset := int64(target) - int64(pc)
	return 0x14000000 | uint32((offset>>2)&0x03FFFFFF)
}

func arm64BCond(pc, target uint64) uint32 {
	offset := int64(target) - int64(pc)
	// bits 23..5 hold imm19; condition 0 in bits 3..0.
	return 0x54000000 | uint32(((offset>>2)&0x7FFFF)<<5)
}

func scanFixture(words []uint32, base uint64) (*Image, []byte) {
	code := make([]byte, len(words)*4)
	for index, word := range words {
		binary.LittleEndian.PutUint32(code[index*4:], word)
	}
	// Segments is what fileRange maps through and fileSize bounds it. Without both,
	// addFunction rejects every address and the scan looks broken while decoding fine.
	region := Region{
		Name: "__TEXT,__text", Address: base, Size: uint64(len(code)),
		Offset: 0, FileSize: uint64(len(code)),
	}
	image := &Image{
		Arch:       "arm64",
		Bits:       64,
		functions:  map[uint64]Function{},
		Segments:   []Region{region},
		Executable: []Region{region},
		fileSize:   uint64(len(code)),
	}
	return image, code
}

func TestScanARM64CallTargetsFindsBL(t *testing.T) {
	const base = 0x1000
	// pc 0x1000: BL 0x1020 ; pc 0x1004: BL 0x1040 (in range) ; pc 0x1008: BL 0x9000 (out)
	words := []uint32{
		arm64BL(base+0, base+0x20),
		0xd503201f, // nop: a second BL here would also be in range once widened
		arm64BL(base+8, base+0x9000),
		0xd503201f, // nop at 0x1010
		0xd503201f, // 0x1014
		0xd503201f, // 0x1018
		0xd503201f, // 0x101c
		0xd503201f, // 0x1020  <- the first target, inside the region
		0xd503201f, // 0x1024
		0xd503201f, // 0x1028
		0xd503201f, // 0x102c
		0xd503201f, 0xd503201f, 0xd503201f, 0xd503201f,
		0xd503201f, 0xd503201f, 0xd503201f, 0xd503201f, // up to 0x1040
	}
	image, code := scanFixture(words, base)
	added := scanARM64CallTargets(image, bytes.NewReader(code), 0)
	if added != 1 {
		t.Fatalf("added %d, want 1 (only the in-range BL)", added)
	}
	if _, ok := image.functions[base+0x20]; !ok {
		t.Fatalf("0x%x not recovered: %v", base+0x20, image.functions)
	}
	if _, ok := image.functions[base+0x9000]; ok {
		t.Fatal("an out-of-range target was treated as a function")
	}
}

// TestScanARM64CallTargetsFiltersBranchForms pins the two corrections that came out of a
// real 579 KB firmware image:
//
//   - B.cond targets are loop/if labels, never entries (they took that image from 4088
//     plausible entries to 6522).
//   - a plain B target is only an entry when the target starts like a function; BL
//     targets are 54% prologue-like on that image while B targets are 8.4%.
func TestScanARM64CallTargetsFiltersBranchForms(t *testing.T) {
	const base = 0x2000
	const prologue = 0xa9bf7bfd // stp x29, x30, [sp, #-16]!
	words := make([]uint32, 40)
	words[0] = arm64BCond(base, base+0x40) // label, must NOT create a function
	words[1] = arm64B(base+4, base+0x44)   // target is a prologue -> accepted
	words[2] = arm64B(base+8, base+0x48)   // target is a nop -> rejected
	words[3] = arm64BL(base+12, base+0x4c) // a call is always accepted
	for index := 4; index < len(words); index++ {
		words[index] = 0xd503201f
	}
	words[0x44/4] = prologue
	words[0x48/4] = 0xd503201f
	words[0x4c/4] = 0xd503201f

	image, code := scanFixture(words, base)
	scanARM64CallTargets(image, bytes.NewReader(code), 0)

	if _, ok := image.functions[base+0x40]; ok {
		t.Error("a B.cond target was treated as a function entry")
	}
	if _, ok := image.functions[base+0x44]; !ok {
		t.Error("a B target starting with a prologue was rejected")
	}
	if _, ok := image.functions[base+0x48]; ok {
		t.Error("a B target starting mid-function (nop) was accepted")
	}
	if _, ok := image.functions[base+0x4c]; !ok {
		t.Error("a BL target was rejected")
	}
}

func TestScanARM64CallTargetsSkipsNonArm64(t *testing.T) {
	region := Region{Address: 0x1000, Size: 64, FileSize: 64}
	image := &Image{Arch: "x86_64", Bits: 64, functions: map[uint64]Function{},
		Segments: []Region{region}, Executable: []Region{region}, fileSize: 64}
	if added := scanARM64CallTargets(image, bytes.NewReader(make([]byte, 64)), 0); added != 0 {
		t.Fatalf("scanned a non-arm64 image: %d", added)
	}
}

func TestScanARM64CallTargetsRespectsLimit(t *testing.T) {
	const base = 0x3000
	words := make([]uint32, 40)
	for index := range words {
		words[index] = arm64BL(base+uint64(index*4), base+uint64(4*(len(words)-1)))
	}
	image, code := scanFixture(words, base)
	if added := scanARM64CallTargets(image, bytes.NewReader(code), 3); added > 3 {
		t.Fatalf("added %d with limit 3", added)
	}
}

// TestScanARM64CallTargetsRealFirmware validates against a real sectionless aarch64 ELF.
// Expected values were confirmed by an independent Python scan of the same program
// headers: 1652 BL targets, plus 135 prologue-like B targets, plus the entry point.
func TestScanARM64CallTargetsRealFirmware(t *testing.T) {
	path := os.Getenv("XTF_REAL_ELF")
	if path == "" {
		t.Skip("set XTF_REAL_ELF to a real sectionless arm64 ELF to run this test")
	}
	result, err := Functions(path, "", "", 1)
	if err != nil {
		t.Fatal(err)
	}
	total := result.Images[0].Total
	// 1788 is the measured value (1652 calls + 135 prologue-like branches + entry point).
	// Assert a band rather than the exact number: a different compiler or image differs.
	if total < 1000 {
		t.Fatalf("recovered only %d functions from a real firmware image", total)
	}
	if total > 3000 {
		t.Fatalf("recovered %d functions: the branch filter is admitting jump labels again", total)
	}
	t.Logf("real firmware: %d functions recovered", total)
}

// TestScanARM64CallTargetsDropsAdjacentPairs pins the spacing rule.
//
// Two recovered starts four bytes apart cannot both be functions: the second would be a
// single instruction, and an ARM64 function needs at least a body and a return. On a real
// image 91 of 1787 entries were exactly that. An eight-byte gap is left alone, because an
// eight-byte leaf function is normal.
func TestScanARM64CallTargetsDropsAdjacentPairs(t *testing.T) {
	const base = 0x4000
	words := make([]uint32, 24)
	words[0] = arm64BL(base+0, base+0x20) // first of an adjacent pair
	words[1] = arm64BL(base+4, base+0x24) // four bytes later: must be dropped
	words[2] = arm64BL(base+8, base+0x28) // eight bytes after the first: must be kept
	for index := 3; index < len(words); index++ {
		words[index] = 0xd503201f
	}
	image, code := scanFixture(words, base)
	scanARM64CallTargets(image, bytes.NewReader(code), 0)

	if _, ok := image.functions[base+0x20]; !ok {
		t.Error("the first of the pair was dropped")
	}
	if _, ok := image.functions[base+0x24]; ok {
		t.Error("a start four bytes after another was kept as a function")
	}
	if _, ok := image.functions[base+0x28]; !ok {
		t.Error("a start eight bytes after another was wrongly dropped")
	}
}
