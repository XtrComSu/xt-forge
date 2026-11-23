package sysimage

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

func TestReferenceScanSeparatesPCRelativeDataFromFunctionDiscovery(t *testing.T) {
	data := make([]byte, 0x30)
	copy(data, []byte{0xe8, 0x1b, 0, 0, 0, 0x48, 0x8d, 0x05, 0x14, 0, 0, 0, 0xc3})
	entry := uint64(0x1000)
	image := Image{
		Arch: "x86_64", EntryPoint: &entry, fileSize: uint64(len(data)),
		Segments:   []Region{{Address: entry, Size: 0x30, FileSize: 0x30}},
		Executable: []Region{{Address: entry, Size: 0x20, FileSize: 0x20}},
	}
	target := uint64(0x1020)
	index := ReferenceIndex{Target: &target}
	scanReferences(bytes.NewReader(data), &image, ReferenceOptions{MaxFunctions: 10, Limit: 10}, &index)
	if index.Discovered != 0 || len(index.References) != 2 ||
		index.References[0].Kind != "call" || index.References[1].Kind != "pc_relative" {
		t.Fatalf("unexpected data references: %#v", index)
	}
}

func TestReferenceScanKeepsJumpToKnownFunctionAsCandidate(t *testing.T) {
	data := make([]byte, 0x20)
	copy(data, []byte{0xe9, 0x0b, 0, 0, 0})
	data[0x10] = 0xc3
	entry := uint64(0x1000)
	region := Region{Address: entry, Size: 0x20, FileSize: 0x20}
	image := Image{Arch: "x86_64", EntryPoint: &entry, fileSize: uint64(len(data)),
		Segments: []Region{region}, Executable: []Region{region}}
	image.addFunction(0x1010, 1, "fixture_callee", "test")
	var index ReferenceIndex
	scanReferences(bytes.NewReader(data), &image, ReferenceOptions{MaxFunctions: 10, Limit: 10}, &index)
	if index.Discovered != 0 || index.LimitedFunctions != 0 || len(index.References) != 1 ||
		index.References[0].Kind != "tail_jump_candidate" || index.References[0].TargetName != "fixture_callee" {
		t.Fatalf("unexpected jump classification: %#v", index)
	}
}

func TestReferenceScanResolvesAdjacentArm64PageOffset(t *testing.T) {
	data := make([]byte, 0x200)
	for i, word := range []uint32{
		0x90000000, // adrp x0, same page
		0x9104a000, // add x0, x0, #0x128
		0xd65f03c0, // ret
	} {
		binary.LittleEndian.PutUint32(data[4*i:], word)
	}
	entry := uint64(0x1000)
	image := Image{Arch: "arm64", EntryPoint: &entry, fileSize: uint64(len(data)),
		Segments:   []Region{{Address: entry, Size: 0x200, FileSize: 0x200}},
		Executable: []Region{{Address: entry, Size: 0x20, FileSize: 0x20}}}
	target := uint64(0x1128)
	index := ReferenceIndex{Target: &target}
	scanReferences(bytes.NewReader(data), &image, ReferenceOptions{MaxFunctions: 10, Limit: 10}, &index)
	if len(index.References) != 1 || index.References[0].Site != 0x1004 ||
		index.References[0].Kind != "pc_relative_address" {
		t.Fatalf("unexpected arm64 references: %#v", index)
	}
}

func TestReferencesDiscoverDirectCalleeWithoutMetadata(t *testing.T) {
	data := append(machFixture(), make([]byte, 16)...)
	binary.LittleEndian.PutUint32(data[4:], 0x01000007)
	binary.LittleEndian.PutUint64(data[80:], uint64(len(data)))
	copy(data[0x100:], []byte{0xe8, 0x0b, 0, 0, 0, 0xc3})
	data[0x110] = 0xc3
	path := filepath.Join(t.TempDir(), "fixture")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	result, err := References(path, ReferenceOptions{Target: "0x100000110", MaxFunctions: 10, Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if result.Seeds != 1 || result.Scanned != 2 || result.Discovered != 1 || len(result.References) != 1 {
		t.Fatalf("unexpected scan: %#v", result)
	}
	got := result.References[0]
	if got.Kind != "call" || got.Site != 0x100000100 || got.Target != 0x100000110 ||
		got.TargetSource != "direct_call_target" || got.Function != 0x100000100 {
		t.Fatalf("unexpected reference: %#v", got)
	}
}

func TestReferenceScanBudgetReportsUnscannedCallee(t *testing.T) {
	data := append(machFixture(), make([]byte, 16)...)
	binary.LittleEndian.PutUint32(data[4:], 0x01000007)
	binary.LittleEndian.PutUint64(data[80:], uint64(len(data)))
	copy(data[0x100:], []byte{0xe8, 0x0b, 0, 0, 0, 0xc3})
	data[0x110] = 0xc3
	path := filepath.Join(t.TempDir(), "fixture")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	result, err := References(path, ReferenceOptions{MaxFunctions: 1})
	if err != nil || result.Scanned != 1 || result.Pending != 1 || result.Discovered != 1 {
		t.Fatalf("unexpected bounded scan: %#v, %v", result, err)
	}
}
