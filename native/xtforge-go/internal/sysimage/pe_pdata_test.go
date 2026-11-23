package sysimage

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

// PE x64 exception-directory coverage.
//
// `.pdata` holds one RUNTIME_FUNCTION per non-leaf function, so on a 64-bit PE it is the
// strongest available ground truth for "which addresses are function starts". This test
// asserts that every entry is present in our function index.
//
// The reason to pin it: a comparison against Ghidra reported 3,955 procedures on kernel32
// where we reported 2,776, and the gap was read as us missing 42% of the functions. It was
// a count difference, not a coverage difference — `.pdata` declares 1,870 non-leaf
// functions on that binary and we already had all 1,870. The extra entries on both sides
// are leaf functions and analysis candidates, which no directory attests to.
func TestPEDataCoversEveryDeclaredFunction(t *testing.T) {
	dir, err := os.UserHomeDir()
	if err != nil {
		t.Skip("no home directory")
	}
	candidates := []string{
		"/usr/lib/wine/x86_64-windows/kernel32.dll",
		"/usr/lib/wine/x86_64-windows/kernelbase.dll",
		"/usr/lib/wine/x86_64-windows/ucrtbase.dll",
		filepath.Join(dir, ".wine", "drive_c", "windows", "system32", "kernel32.dll"),
	}
	checked := 0
	for _, path := range candidates {
		if _, err := os.Stat(path); err != nil {
			continue
		}
		declared := peDataStarts(t, path)
		if len(declared) == 0 {
			continue
		}
		result, err := Functions(path, "", "", 200000)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		index := make(map[uint64]bool, len(result.Images[0].Functions))
		for _, function := range result.Images[0].Functions {
			index[function.Address] = true
		}
		missing := 0
		var firstMissing uint64
		for address := range declared {
			if !index[address] {
				missing++
				if firstMissing == 0 || address < firstMissing {
					firstMissing = address
				}
			}
		}
		if missing != 0 {
			t.Errorf("%s: %d of %d .pdata functions missing (first %#x)",
				filepath.Base(path), missing, len(declared), firstMissing)
		}
		t.Logf("%s: %d .pdata entries, %d indexed, %d missing",
			filepath.Base(path), len(declared), len(index), missing)
		checked++
	}
	if checked == 0 {
		t.Skip("no 64-bit PE samples with an exception directory on this machine")
	}
}

// peDataStarts reads the x64 exception directory and returns the declared begin addresses.
func peDataStarts(t *testing.T, path string) map[uint64]bool {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if len(data) < 0x40 || data[0] != 'M' || data[1] != 'Z' {
		return nil
	}
	peOffset := int(binary.LittleEndian.Uint32(data[0x3c:]))
	if peOffset+24 > len(data) || string(data[peOffset:peOffset+4]) != "PE\x00\x00" {
		return nil
	}
	coff := peOffset + 4
	sections := int(binary.LittleEndian.Uint16(data[coff+2:]))
	optionalSize := int(binary.LittleEndian.Uint16(data[coff+16:]))
	optional := coff + 20
	if optional+24 > len(data) {
		return nil
	}
	magic := binary.LittleEndian.Uint16(data[optional:])
	if magic != 0x20b { // PE32+ only; the exception directory is an x64 structure
		return nil
	}
	imageBase := binary.LittleEndian.Uint64(data[optional+24:])
	directories := optional + 112
	if directories+4*8 > len(data) {
		return nil
	}
	exceptionRVA := binary.LittleEndian.Uint32(data[directories+3*8:])
	exceptionSize := binary.LittleEndian.Uint32(data[directories+3*8+4:])
	if exceptionRVA == 0 || exceptionSize == 0 {
		return nil
	}

	type section struct {
		virtual, size, raw uint32
	}
	table := make([]section, 0, sections)
	sectionTable := optional + optionalSize
	for i := 0; i < sections; i++ {
		base := sectionTable + i*40
		if base+40 > len(data) {
			break
		}
		virtualSize := binary.LittleEndian.Uint32(data[base+8:])
		virtualAddress := binary.LittleEndian.Uint32(data[base+12:])
		rawSize := binary.LittleEndian.Uint32(data[base+16:])
		rawOffset := binary.LittleEndian.Uint32(data[base+20:])
		size := virtualSize
		if rawSize > size {
			size = rawSize
		}
		table = append(table, section{virtualAddress, size, rawOffset})
	}
	offsetOf := func(rva uint32) (uint32, bool) {
		for _, s := range table {
			if rva >= s.virtual && rva < s.virtual+s.size {
				return s.raw + (rva - s.virtual), true
			}
		}
		return 0, false
	}
	offset, ok := offsetOf(exceptionRVA)
	if !ok {
		return nil
	}
	starts := make(map[uint64]bool)
	for i := uint32(0); i < exceptionSize/12; i++ {
		base := int(offset + i*12)
		if base+12 > len(data) {
			break
		}
		begin := binary.LittleEndian.Uint32(data[base:])
		if begin != 0 {
			starts[imageBase+uint64(begin)] = true
		}
	}
	return starts
}
