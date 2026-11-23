package sysimage

import (
	"debug/pe"
	"encoding/binary"
	"fmt"
	"sort"
)

// PEExport is one exported symbol from a PE image.
type PEExport struct {
	Name    string `json:"name"`
	Address uint64 `json:"address"`
	Ordinal uint32 `json:"ordinal"`
}

const (
	peExportHeaderLen  = 40
	peExportMaxEntries = 65536
)

// ParsePEExports decodes an export directory that has already been mapped into
// memory (the bytes of the PE's export data directory). directoryRVA is the
// image-relative virtual address at which directory begins; the function, name
// and name-ordinal table RVAs stored in the header are relative to the image
// base and are converted to offsets within directory by subtracting
// directoryRVA. base is the image base added to each export's function RVA to
// form Address.
//
// Returns nil when the directory is nil, shorter than the 40-byte export
// directory header, or when a table RVA points before directory. Every read is
// bounds-checked: a table entry outside directory stops decoding and returns
// the exports decoded so far; an individual out-of-range name or function is
// skipped. The result is sorted by Address ascending, then by Name. A caller
// that wants to report *why* exports are incomplete uses
// parsePEExportsWithReason.
func ParsePEExports(directory []byte, directoryRVA uint32, base uint64) []PEExport {
	exports, _ := parsePEExportsWithReason(directory, directoryRVA, base)
	return exports
}

// parsePEExportsWithReason is ParsePEExports plus a human-readable reason for
// an incomplete or absent export list. A bad export directory is data, not a
// parse failure: the image still parses and the reason is reported instead.
func parsePEExportsWithReason(directory []byte, directoryRVA uint32, base uint64) ([]PEExport, string) {
	if len(directory) < peExportHeaderLen {
		return nil, fmt.Sprintf("export directory is %d bytes, need %d", len(directory), peExportHeaderLen)
	}

	ordinalBase := binary.LittleEndian.Uint32(directory[16:20]) // Base
	numFuncs := binary.LittleEndian.Uint32(directory[20:24])    // NumberOfFunctions
	numNames := binary.LittleEndian.Uint32(directory[24:28])    // NumberOfNames
	funcsRVA := binary.LittleEndian.Uint32(directory[28:32])    // AddressOfFunctions
	namesRVA := binary.LittleEndian.Uint32(directory[32:36])    // AddressOfNames
	ordsRVA := binary.LittleEndian.Uint32(directory[36:40])     // AddressOfNameOrdinals

	if numFuncs > peExportMaxEntries {
		numFuncs = peExportMaxEntries
	}
	if numNames > peExportMaxEntries {
		numNames = peExportMaxEntries
	}

	funcOff, ok := peExportOffset(funcsRVA, directoryRVA, len(directory))
	if !ok {
		return nil, fmt.Sprintf("export function table RVA %#x is outside the directory at %#x", funcsRVA, directoryRVA)
	}
	namesOff, ok := peExportOffset(namesRVA, directoryRVA, len(directory))
	if !ok {
		return nil, fmt.Sprintf("export name table RVA %#x is outside the directory at %#x", namesRVA, directoryRVA)
	}
	ordsOff, ok := peExportOffset(ordsRVA, directoryRVA, len(directory))
	if !ok {
		return nil, fmt.Sprintf("export ordinal table RVA %#x is outside the directory at %#x", ordsRVA, directoryRVA)
	}

	var exports []PEExport
	reason := ""
	for i := uint32(0); i < numNames; i++ {
		nameEntry := namesOff + int(i)*4
		if nameEntry+4 > len(directory) {
			reason = fmt.Sprintf("name table entry %d lies past the %d-byte export directory", i, len(directory))
			break
		}
		nameRVA := binary.LittleEndian.Uint32(directory[nameEntry : nameEntry+4])

		ordEntry := ordsOff + int(i)*2
		if ordEntry+2 > len(directory) {
			reason = fmt.Sprintf("ordinal table entry %d lies past the %d-byte export directory", i, len(directory))
			break
		}
		funcIndex := uint32(binary.LittleEndian.Uint16(directory[ordEntry : ordEntry+2]))

		nameOff, ok := peExportOffset(nameRVA, directoryRVA, len(directory))
		if !ok || nameOff == len(directory) {
			continue
		}
		name := peExportCString(directory[nameOff:])
		if name == "" {
			continue
		}

		if funcIndex >= numFuncs {
			continue
		}
		funcEntry := funcOff + int(funcIndex)*4
		if funcEntry+4 > len(directory) {
			reason = fmt.Sprintf("function table entry %d lies past the %d-byte export directory", funcIndex, len(directory))
			continue
		}
		funcRVA := binary.LittleEndian.Uint32(directory[funcEntry : funcEntry+4])
		if funcRVA == 0 { // a hole in the functions table
			continue
		}

		exports = append(exports, PEExport{
			Name:    name,
			Address: base + uint64(funcRVA),
			Ordinal: ordinalBase + funcIndex,
		})
	}

	sort.Slice(exports, func(i, j int) bool {
		if exports[i].Address != exports[j].Address {
			return exports[i].Address < exports[j].Address
		}
		return exports[i].Name < exports[j].Name
	})
	return exports, reason
}

// parsePEExportsInFile decodes an export directory from the mapped image. A real
// PE may put the function, name and ordinal tables in a different section from
// the 40-byte export directory (measured on Wine's kernelbase.dll: the
// directory is in .edata, the tables are in a later section), so every RVA is
// resolved against the sections rather than assumed to be relative to the
// directory. Short reads yield a partial list and a reason, never a parse
// failure for the whole image.
func parsePEExportsInFile(file *pe.File, directory pe.DataDirectory, base uint64) ([]PEExport, string) {
	if file == nil || directory.VirtualAddress == 0 || directory.Size == 0 {
		return nil, ""
	}
	if directory.Size < peExportHeaderLen {
		return nil, fmt.Sprintf("export directory is %d bytes, need %d", directory.Size, peExportHeaderLen)
	}
	header, err := peMappedBytes(file, directory.VirtualAddress, peExportHeaderLen)
	if err != nil {
		return nil, "export directory RVA " + err.Error()
	}
	if len(header) < peExportHeaderLen {
		return nil, fmt.Sprintf("export directory header at RVA %#x is truncated", directory.VirtualAddress)
	}

	ordinalBase := binary.LittleEndian.Uint32(header[16:20]) // Base
	numFuncs := binary.LittleEndian.Uint32(header[20:24])    // NumberOfFunctions
	numNames := binary.LittleEndian.Uint32(header[24:28])    // NumberOfNames
	funcsRVA := binary.LittleEndian.Uint32(header[28:32])    // AddressOfFunctions
	namesRVA := binary.LittleEndian.Uint32(header[32:36])    // AddressOfNames
	ordsRVA := binary.LittleEndian.Uint32(header[36:40])     // AddressOfNameOrdinals

	if numFuncs > peExportMaxEntries {
		numFuncs = peExportMaxEntries
	}
	if numNames > peExportMaxEntries {
		numNames = peExportMaxEntries
	}
	if numFuncs == 0 || numNames == 0 {
		return nil, ""
	}

	funcs, funcsErr := peMappedBytes(file, funcsRVA, uint64(numFuncs)*4)
	names, namesErr := peMappedBytes(file, namesRVA, uint64(numNames)*4)
	ords, ordsErr := peMappedBytes(file, ordsRVA, uint64(numNames)*2)
	if funcsErr != nil || namesErr != nil || ordsErr != nil {
		reason := "export table is not mapped: "
		if funcsErr != nil {
			reason += "functions " + funcsErr.Error() + "; "
		}
		if namesErr != nil {
			reason += "names " + namesErr.Error() + "; "
		}
		if ordsErr != nil {
			reason += "ordinals " + ordsErr.Error()
		}
		return nil, reason
	}

	reason := ""
	if len(funcs) < int(numFuncs)*4 {
		reason = fmt.Sprintf("function table has %d bytes, need %d", len(funcs), numFuncs*4)
	}
	if len(names) < int(numNames)*4 {
		reason = fmt.Sprintf("name table has %d bytes, need %d", len(names), numNames*4)
	}
	if len(ords) < int(numNames)*2 {
		reason = fmt.Sprintf("ordinal table has %d bytes, need %d", len(ords), numNames*2)
	}

	var exports []PEExport
	for i := uint32(0); i < numNames; i++ {
		if int(i)*4+4 > len(names) || int(i)*2+2 > len(ords) {
			break
		}
		nameRVA := binary.LittleEndian.Uint32(names[int(i)*4 : int(i)*4+4])
		funcIndex := uint32(binary.LittleEndian.Uint16(ords[int(i)*2 : int(i)*2+2]))
		if funcIndex >= numFuncs || int(funcIndex)*4+4 > len(funcs) {
			continue
		}
		nameBytes, nameErr := peMappedBytes(file, nameRVA, peExportMaxNameLen)
		if nameErr != nil || len(nameBytes) == 0 {
			continue
		}
		name := peExportCString(nameBytes)
		if name == "" {
			continue
		}
		funcRVA := binary.LittleEndian.Uint32(funcs[int(funcIndex)*4 : int(funcIndex)*4+4])
		if funcRVA == 0 { // a hole or a forwarder without an address here
			continue
		}
		exports = append(exports, PEExport{
			Name:    name,
			Address: base + uint64(funcRVA),
			Ordinal: ordinalBase + funcIndex,
		})
	}

	sort.Slice(exports, func(i, j int) bool {
		if exports[i].Address != exports[j].Address {
			return exports[i].Address < exports[j].Address
		}
		return exports[i].Name < exports[j].Name
	})
	return exports, reason
}

// peMappedBytes returns up to want bytes at an image RVA, using the section
// that contains it. The slice is a view of the section's bytes, not a copy; a
// short slice means the table was truncated by the end of the section.
func peMappedBytes(file *pe.File, rva uint32, want uint64) ([]byte, error) {
	if file == nil || rva == 0 || want == 0 {
		return nil, fmt.Errorf("%#x: no mapped bytes", rva)
	}
	for _, section := range file.Sections {
		if section == nil {
			continue
		}
		start := uint64(section.VirtualAddress)
		span := uint64(section.VirtualSize)
		if raw := uint64(section.Size); raw > span {
			span = raw
		}
		if uint64(rva) < start || uint64(rva)-start >= span {
			continue
		}
		data, err := section.Data()
		if err != nil {
			return nil, fmt.Errorf("%#x: read section %q: %w", rva, section.Name, err)
		}
		offset := uint64(rva) - start
		if offset >= uint64(len(data)) {
			return nil, fmt.Errorf("%#x: past the raw bytes of section %q", rva, section.Name)
		}
		available := uint64(len(data)) - offset
		return data[offset : offset+min(want, available)], nil
	}
	return nil, fmt.Errorf("%#x: not covered by a section", rva)
}

const peExportMaxNameLen = 4096

// peExportOffset converts an RVA into an offset within the export directory,
// rejecting RVAs that point before directory or beyond limit. Using uint64
// arithmetic keeps an out-of-range uint32 RVA from wrapping a 32-bit int.
func peExportOffset(rva, directoryRVA uint32, limit int) (int, bool) {
	if rva < directoryRVA {
		return 0, false
	}
	off := uint64(rva - directoryRVA)
	if off > uint64(limit) {
		return 0, false
	}
	return int(off), true
}

// peExportCString reads a NUL-terminated string from b, returning "" when the
// bytes run out before a terminator is found.
func peExportCString(b []byte) string {
	end := 0
	for end < len(b) && b[end] != 0 {
		end++
	}
	if end == len(b) {
		return ""
	}
	return string(b[:end])
}
