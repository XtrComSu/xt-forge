package sysimage

import (
	"encoding/binary"
	"reflect"
	"testing"
)

const (
	testPEDirectoryRVA uint32 = 0x2000
	testPEImageBase    uint64 = 0x180000000
)

// makeExportDir builds a minimal PE export directory. The three table RVAs in
// the header are relative to directoryRVA, just like in a real image; the
// tables and NUL-terminated name strings live inside the directory bytes.
func makeExportDir(directoryRVA, ordinalBase uint32, funcRVAs []uint32, names []string) []byte {
	const headerLen = 40
	funcOff := headerLen
	namesOff := funcOff + 4*len(funcRVAs)
	ordsOff := namesOff + 4*len(names)
	strOff := ordsOff + 2*len(names)

	nameRVAs := make([]uint32, len(names))
	strs := make([]byte, 0, 64)
	for i, n := range names {
		nameRVAs[i] = directoryRVA + uint32(strOff+len(strs))
		strs = append(strs, n...)
		strs = append(strs, 0)
	}

	buf := make([]byte, strOff+len(strs))
	binary.LittleEndian.PutUint32(buf[16:20], ordinalBase)                   // Base
	binary.LittleEndian.PutUint32(buf[20:24], uint32(len(funcRVAs)))         // NumberOfFunctions
	binary.LittleEndian.PutUint32(buf[24:28], uint32(len(names)))            // NumberOfNames
	binary.LittleEndian.PutUint32(buf[28:32], directoryRVA+uint32(funcOff))  // AddressOfFunctions
	binary.LittleEndian.PutUint32(buf[32:36], directoryRVA+uint32(namesOff)) // AddressOfNames
	binary.LittleEndian.PutUint32(buf[36:40], directoryRVA+uint32(ordsOff))  // AddressOfNameOrdinals
	for i, rva := range funcRVAs {
		binary.LittleEndian.PutUint32(buf[funcOff+i*4:funcOff+i*4+4], rva)
	}
	for i, rva := range nameRVAs {
		binary.LittleEndian.PutUint32(buf[namesOff+i*4:namesOff+i*4+4], rva)
	}
	for i := range names {
		binary.LittleEndian.PutUint16(buf[ordsOff+i*2:ordsOff+i*2+2], uint16(i))
	}
	copy(buf[strOff:], strs)
	return buf
}

func TestParsePEExports(t *testing.T) {
	t.Run("two exports", func(t *testing.T) {
		dir := makeExportDir(testPEDirectoryRVA, 1, []uint32{0x1000, 0x2000}, []string{"alpha", "beta"})
		got := ParsePEExports(dir, testPEDirectoryRVA, testPEImageBase)
		want := []PEExport{
			{Name: "alpha", Address: testPEImageBase + 0x1000, Ordinal: 1},
			{Name: "beta", Address: testPEImageBase + 0x2000, Ordinal: 2},
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("ParsePEExports() = %#v, want %#v", got, want)
		}
	})

	t.Run("oversized name count returns partial list", func(t *testing.T) {
		dir := makeExportDir(testPEDirectoryRVA, 1, []uint32{0x1000, 0x2000}, []string{"alpha", "beta"})
		binary.LittleEndian.PutUint32(dir[24:28], 1000) // claim far more names than the table holds
		got := ParsePEExports(dir, testPEDirectoryRVA, testPEImageBase)
		if len(got) != 2 {
			t.Fatalf("ParsePEExports() returned %d exports, want 2: %#v", len(got), got)
		}
	})

	t.Run("truncated directory", func(t *testing.T) {
		for _, n := range []int{0, 1, 20, 39} {
			got := ParsePEExports(make([]byte, n), testPEDirectoryRVA, testPEImageBase)
			if got != nil {
				t.Fatalf("ParsePEExports(len=%d) = %#v, want nil", n, got)
			}
		}
	})

	t.Run("nil directory", func(t *testing.T) {
		if got := ParsePEExports(nil, testPEDirectoryRVA, testPEImageBase); got != nil {
			t.Fatalf("ParsePEExports(nil) = %#v, want nil", got)
		}
	})

	t.Run("zero function RVA gap is skipped", func(t *testing.T) {
		dir := makeExportDir(testPEDirectoryRVA, 5, []uint32{0x1000, 0, 0x3000}, []string{"alpha", "gap", "gamma"})
		got := ParsePEExports(dir, testPEDirectoryRVA, testPEImageBase)
		want := []PEExport{
			{Name: "alpha", Address: testPEImageBase + 0x1000, Ordinal: 5},
			{Name: "gamma", Address: testPEImageBase + 0x3000, Ordinal: 7},
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("ParsePEExports() = %#v, want %#v", got, want)
		}
	})

	t.Run("sorted by address then name", func(t *testing.T) {
		dir := makeExportDir(testPEDirectoryRVA, 1, []uint32{0x2000, 0x1000, 0x1000}, []string{"zeta", "alpha", "beta"})
		got := ParsePEExports(dir, testPEDirectoryRVA, testPEImageBase)
		want := []PEExport{
			{Name: "alpha", Address: testPEImageBase + 0x1000, Ordinal: 2},
			{Name: "beta", Address: testPEImageBase + 0x1000, Ordinal: 3},
			{Name: "zeta", Address: testPEImageBase + 0x2000, Ordinal: 1},
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("ParsePEExports() = %#v, want %#v", got, want)
		}
	})
}
