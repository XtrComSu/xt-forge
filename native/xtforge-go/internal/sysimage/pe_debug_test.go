package sysimage

import (
	"encoding/binary"
	"testing"
)

// PE debug-directory and CodeView tests.
//
// Unlike the PDB reader, this format is small enough that a hand-built fixture is
// trustworthy: every field is a fixed offset with no container indirection, so the
// fixture cannot hide a layout mistake the way an MSF stream table could.

func debugDirectoryEntry(recordType, size, address, pointer uint32) []byte {
	entry := make([]byte, 28)
	binary.LittleEndian.PutUint32(entry[12:], recordType)
	binary.LittleEndian.PutUint32(entry[16:], size)
	binary.LittleEndian.PutUint32(entry[20:], address)
	binary.LittleEndian.PutUint32(entry[24:], pointer)
	return entry
}

func rsdsRecord(guid [16]byte, age uint32, path string) []byte {
	record := append([]byte("RSDS"), guid[:]...)
	record = binary.LittleEndian.AppendUint32(record, age)
	record = append(record, path...)
	return append(record, 0)
}

func TestReadPEDebugDirectory(t *testing.T) {
	blob := append(debugDirectoryEntry(2, 40, 0x2000, 0x400), debugDirectoryEntry(16, 8, 0x2100, 0x500)...)
	entries := ReadPEDebugDirectory(blob)
	if len(entries) != 2 {
		t.Fatalf("entries = %d, want 2", len(entries))
	}
	if entries[0].Type != 2 || entries[0].Size != 40 || entries[0].Address != 0x2000 || entries[0].Pointer != 0x400 {
		t.Fatalf("first entry = %+v", entries[0])
	}
	if entries[1].Type != 16 || entries[1].Pointer != 0x500 {
		t.Fatalf("second entry = %+v", entries[1])
	}
	if got := ReadPEDebugDirectory(blob[:20]); got != nil {
		t.Fatalf("short blob returned %d entries, want nil", len(got))
	}
}

func TestReadCodeView(t *testing.T) {
	// Data1/Data2/Data3 are little-endian, Data4 is literal: the canonical example
	// GUID in Windows documentation.
	guid := [16]byte{
		0xe0, 0x04, 0x25, 0x3f, // Data1 = 3f2504e0
		0x89, 0x4f, // Data2 = 4f89
		0xd3, 0x11, // Data3 = 11d3
		0x9a, 0x0c, 0x03, 0x05, 0xe8, 0x2c, 0x33, 0x01,
	}
	record := rsdsRecord(guid, 3, `C:\build\app.pdb`)
	info, ok := ReadCodeView(record)
	if !ok {
		t.Fatal("RSDS record rejected")
	}
	if info.Signature != "RSDS" {
		t.Errorf("signature = %q", info.Signature)
	}
	if info.GUID != "3f2504e0-4f89-11d3-9a0c-0305e82c3301" {
		t.Errorf("guid = %q", info.GUID)
	}
	if info.Age != 3 {
		t.Errorf("age = %d", info.Age)
	}
	if info.Path != `C:\build\app.pdb` {
		t.Errorf("path = %q", info.Path)
	}

	// NB10 carries no GUID.
	nb10 := []byte("NB10")
	nb10 = binary.LittleEndian.AppendUint32(nb10, 0)
	nb10 = binary.LittleEndian.AppendUint32(nb10, 0x5f000000)
	nb10 = binary.LittleEndian.AppendUint32(nb10, 7)
	nb10 = append(nb10, []byte("legacy.pdb")...)
	nb10 = append(nb10, 0)
	legacy, ok := ReadCodeView(nb10)
	if !ok || legacy.Signature != "NB10" || legacy.Path != "legacy.pdb" || legacy.GUID != "" {
		t.Fatalf("NB10 = %+v ok=%v", legacy, ok)
	}

	if _, ok := ReadCodeView([]byte("XXXXnot codeview")); ok {
		t.Fatal("unknown signature accepted")
	}
	if _, ok := ReadCodeView(record[:10]); ok {
		t.Fatal("truncated RSDS accepted")
	}
	// A path with no terminator must not panic.
	unterminated := rsdsRecord(guid, 1, "")
	unterminated = unterminated[:len(unterminated)-1]
	if info, ok := ReadCodeView(unterminated); ok && info.Path != "" {
		t.Fatalf("unterminated path = %q", info.Path)
	}
}

func TestCodeViewMatches(t *testing.T) {
	guid := "3f2504e0-4f89-11d3-9a0c-0305e82c3301"
	info := CodeViewInfo{GUID: guid, Age: 3}
	if !CodeViewMatches(info, guid, 3) {
		t.Error("identical identity did not match")
	}
	if CodeViewMatches(info, guid, 4) {
		t.Error("different age matched")
	}
	if CodeViewMatches(info, "00000000-0000-0000-0000-000000000000", 3) {
		t.Error("different GUID matched")
	}
	if !CodeViewMatches(CodeViewInfo{}, "", 0) {
		t.Error("empty identity did not match empty")
	}
	if CodeViewMatches(CodeViewInfo{}, guid, 0) {
		t.Error("empty GUID matched a real one")
	}
}
