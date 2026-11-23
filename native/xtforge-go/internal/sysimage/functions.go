package sysimage

import (
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const (
	// maxFunctionOutput bounds one response. It used to be 2000, which silently made
	// every function past the two-thousandth unreachable — a 50,670-function binary
	// reported a total it could never deliver, however large a limit the caller asked
	// for. The bound still exists so a single response cannot be unbounded, but it is
	// now high enough to be a guard rather than a wall, and hitting it is reported.
	maxFunctionOutput = 100000
	maxFunctionTable  = 8 << 20
)

type Function struct {
	Address    uint64 `json:"address"`
	FileOffset uint64 `json:"file_offset"`
	Name       string `json:"name,omitempty"`
	Size       uint64 `json:"size,omitempty"`
	Source     string `json:"source"`
	NameSource string `json:"name_source,omitempty"`
	// Signature is the C form of the function's type, when a PDB supplied one.
	Signature string `json:"signature,omitempty"`
}

type FunctionIndex struct {
	Arch string `json:"arch"`
	// Mode names the instruction set within an architecture (32-bit ARM only).
	Mode        string     `json:"mode,omitempty"`
	SliceOffset uint64     `json:"slice_offset,omitempty"`
	Total       int        `json:"total"`
	Truncated   bool       `json:"truncated"`
	Functions   []Function `json:"functions"`
	// ObjC reports the Objective-C metadata recovered while naming, so a
	// recovered name can be traced back to the structure it came from.
	ObjC     *objcMetadata  `json:"objc,omitempty"`
	DWARF    *dwarfMetadata `json:"dwarf,omitempty"`
	PDB      *PDBReference  `json:"pdb,omitempty"`
	Warnings []string       `json:"warnings,omitempty"`
}

type FunctionsResult struct {
	OK     bool            `json:"ok"`
	Engine string          `json:"engine"`
	Path   string          `json:"path"`
	Format string          `json:"format"`
	Member string          `json:"member,omitempty"`
	Images []FunctionIndex `json:"images"`
}

func Functions(filename, member, arch string, limit int) (FunctionsResult, error) {
	result, err := analyze(filename, member, true)
	if err != nil {
		return FunctionsResult{}, err
	}
	if limit <= 0 {
		limit = 200
	}
	requested := limit
	limit = min(limit, maxFunctionOutput)
	clamped := requested > maxFunctionOutput
	out := FunctionsResult{OK: true, Engine: result.Engine, Path: result.Path, Format: result.Format, Member: result.Member}
	for _, image := range result.Images {
		if arch != "" && !strings.EqualFold(arch, image.Arch) {
			continue
		}
		if image.EntryPoint != nil && image.EntryFileOffset != nil {
			image.addFunction(*image.EntryPoint, 0, "", "entry_point")
		}
		index := FunctionIndex{
			Arch: image.Arch, Mode: image.Mode,
			SliceOffset: image.SliceOffset, Total: len(image.functions),
			Functions: make([]Function, 0, len(image.functions)), ObjC: image.ObjC, DWARF: image.DWARF, PDB: image.PDB, Warnings: image.warnings,
		}
		for _, function := range image.functions {
			index.Functions = append(index.Functions, function)
		}
		sort.Slice(index.Functions, func(i, j int) bool { return index.Functions[i].Address < index.Functions[j].Address })
		if index.Total > limit {
			index.Truncated = true
			if clamped {
				index.Warnings = append(index.Warnings, fmt.Sprintf(
					"limit clamped to %d; %d more functions are not shown — page by address",
					maxFunctionOutput, index.Total-limit))
			}
			index.Functions = index.Functions[:limit]
		}
		out.Images = append(out.Images, index)
	}
	if len(out.Images) == 0 {
		return FunctionsResult{}, fmt.Errorf("no image with architecture %q", arch)
	}
	return out, nil
}

func (image *Image) addFunction(address, size uint64, name, source string) {
	offset, ok := image.fileOffset(address)
	if !ok {
		return
	}
	if size != 0 {
		if start, ok := image.fileRange(address, size); !ok || start != offset {
			size = 0
		}
	}
	if image.functions == nil {
		image.functions = make(map[uint64]Function)
	}
	if prior, exists := image.functions[address]; exists {
		if prior.Name == "" && name != "" {
			prior.Name, prior.NameSource = name, source
		}
		if prior.Size == 0 {
			prior.Size = size
		}
		image.functions[address] = prior
		return
	}
	fn := Function{Address: address, FileOffset: offset, Size: size, Name: name, Source: source}
	if name != "" {
		fn.NameSource = source
	}
	image.functions[address] = fn
}

// nameFunction gives an existing function a name, keeping its recorded source
// when the function already had one. It reports whether a name was written.
//
// This is what metadata recovery uses: the function index decides *which*
// addresses are functions, and metadata only supplies names for them. Letting
// metadata invent function starts would put addresses in the index that the
// binary's own tables do not list.
func (image *Image) nameFunction(address uint64, name, source string) bool {
	if name == "" {
		return false
	}
	fn, exists := image.functions[address]
	if !exists || fn.Name != "" {
		return false
	}
	fn.Name, fn.NameSource = name, source
	image.functions[address] = fn
	return true
}

func indexELF(image *Image, r io.ReaderAt, file *elf.File) {
	// sawThumbSymbol records that at least one ARM symbol carried the Thumb bit. A
	// symbol is stronger evidence of the instruction set than the entry point alone.
	sawThumbSymbol := false
	for _, table := range []struct {
		source string
		read   func() ([]elf.Symbol, error)
	}{
		{"elf_symtab", file.Symbols},
		{"elf_dynsym", file.DynamicSymbols},
	} {
		symbols, err := table.read()
		if err != nil && !errors.Is(err, elf.ErrNoSymbols) {
			image.warnings = append(image.warnings, table.source+": "+err.Error())
		}
		for _, sym := range symbols {
			if elf.ST_TYPE(sym.Info) != elf.STT_FUNC || sym.Section == elf.SHN_UNDEF ||
				int(sym.Section) >= len(file.Sections) || file.Sections[sym.Section].Flags&elf.SHF_EXECINSTR == 0 {
				continue
			}
			value := sym.Value
			// ARM sets bit 0 on every Thumb code address, including symbol values. Left
			// unmasked it produces odd function addresses that cannot be decoded and that
			// duplicate the even entry-point function — measured on a real Thumb binary,
			// 5 of 6 indexed functions were odd. The bit is also the best mode signal
			// available, so it is recorded rather than merely discarded.
			if file.Machine == elf.EM_ARM && value&1 == 1 {
				value &^= 1
				sawThumbSymbol = true
			}
			image.addFunction(value, sym.Size, sym.Name, table.source)
		}
	}
	indexELFUnwind(image, r, file)
	if sawThumbSymbol {
		image.Mode = "thumb"
	}
	// The descent and gap-scan passes were written for PE and gated to it, so an ELF with
	// a thin symbol table stayed sparse: on this machine /tmp/dy is a 16 KB PIE with 10
	// indexed functions where Ghidra reports 23. The machinery is architecture-generic
	// over the x86 decoder, so the same density gate applies here.
	if shouldRecoverByDescent(image) {
		RecoverFunctionsByDescent(image, r, 0)
		ScanUncoveredCode(image, r, 0)
	}
	// A sectionless binary has no symbol table, no .eh_frame and no function starts, so
	// the unwind pass above finds nothing. Branch targets are the only structural signal
	// left; run the scan only in that specific case so a well-described image never gets
	// heuristic starts mixed into its real ones.
	if len(file.Sections) == 0 {
		scanARM64CallTargets(image, r, 0)
	}
	// A binary whose executable bytes are large relative to the number of recovered
	// functions has no usable function metadata. Measured threshold: fewer than one
	// function per 4 KiB of executable code. A binary with .eh_frame or a full symbol
	// table has far more than that — libgfortran, for instance, has one function per
	// ~800 bytes — and must not be polluted with heuristic starts; a large stripped
	// Go binary has one per ~120 KB and has essentially nothing else to go on.
	if image.Arch == "x86_64" && image.Bits == 64 {
		var executableBytes uint64
		for _, region := range image.Executable {
			executableBytes += region.FileSize
		}
		blocks := executableBytes / 4096
		if executableBytes%4096 != 0 {
			blocks++
		}
		if blocks > 0 && uint64(len(image.functions)) < blocks {
			scanX86CallTargets(image, r, 0)
		}
	}
}

func indexMachO(image *Image, r io.ReaderAt, file *macho.File) {
	if text := file.Segment("__TEXT"); text != nil {
		const lcFunctionStarts = 0x26
		for _, load := range file.Loads {
			raw := load.Raw()
			if len(raw) < 16 || file.ByteOrder.Uint32(raw) != lcFunctionStarts {
				continue
			}
			offset, size := file.ByteOrder.Uint32(raw[8:]), file.ByteOrder.Uint32(raw[12:])
			if size > maxFunctionTable {
				image.warnings = append(image.warnings, "Mach-O function-start table exceeds inspection limit")
				continue
			}
			data := make([]byte, size)
			if _, err := r.ReadAt(data, int64(offset)); err != nil {
				image.warnings = append(image.warnings, "read Mach-O function starts: "+err.Error())
				continue
			}
			address := text.Addr
			for len(data) > 0 {
				delta, n := binary.Uvarint(data)
				if n <= 0 || delta > math.MaxUint64-address {
					image.warnings = append(image.warnings, "invalid Mach-O function-start delta")
					break
				}
				if delta == 0 {
					break
				}
				data = data[n:]
				address += delta
				if address-text.Addr >= text.Filesz {
					image.warnings = append(image.warnings, "Mach-O function start lies outside file-backed __TEXT")
					break
				}
				image.addFunction(address, 0, "", "macho_function_starts")
			}
		}
	}
	if file.Symtab == nil {
		indexMachOObjC(image, r, file)
		return
	}
	for _, sym := range file.Symtab.Syms {
		const nStab, nType, nSect = 0xe0, 0x0e, 0x0e
		const instructionFlags = 0x80000400
		if sym.Type&nStab != 0 || sym.Type&nType != nSect || sym.Sect == 0 || int(sym.Sect) > len(file.Sections) ||
			file.Sections[sym.Sect-1].Flags&instructionFlags == 0 {
			continue
		}
		name, source := sym.Name, "macho_code_symbol"
		if demangled := DemangleSwift(sym.Name); demangled != "" {
			name, source = demangled, "macho_swift_symbol"
		}
		image.addFunction(sym.Value, 0, name, source)
	}
	// Objective-C naming runs last so a symbol-table name, which is exact, is
	// never overwritten by a reconstructed one.
	indexMachOObjC(image, r, file)
}

// indexMachOObjC recovers Objective-C metadata and names the functions it can.
func indexMachOObjC(image *Image, r io.ReaderAt, file *macho.File) {
	meta := readObjC(image, r, file)
	if meta == nil {
		return
	}
	image.ObjC = meta
	image.applyObjC(meta, "-")
}

func indexPE(image *Image, r io.ReaderAt, file *pe.File) {
	var base uint64
	var table, exports pe.DataDirectory
	const exception = pe.IMAGE_DIRECTORY_ENTRY_EXCEPTION
	switch h := file.OptionalHeader.(type) {
	case *pe.OptionalHeader64:
		base = h.ImageBase
		if h.NumberOfRvaAndSizes > exception {
			table = h.DataDirectory[exception]
		}
		if h.NumberOfRvaAndSizes > pe.IMAGE_DIRECTORY_ENTRY_EXPORT {
			exports = h.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_EXPORT]
		}
	case *pe.OptionalHeader32:
		base = uint64(h.ImageBase)
		if h.NumberOfRvaAndSizes > pe.IMAGE_DIRECTORY_ENTRY_EXPORT {
			exports = h.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_EXPORT]
		}
	}
	toAddress := func(rva uint32) (uint64, bool) {
		return base + uint64(rva), uint64(rva) <= math.MaxUint64-base
	}
	var stride uint32
	switch file.Machine {
	case pe.IMAGE_FILE_MACHINE_AMD64:
		stride = 12
	case pe.IMAGE_FILE_MACHINE_ARM64:
		stride = 8
	}
	if stride != 0 && table.VirtualAddress != 0 && table.Size != 0 {
		addr, valid := toAddress(table.VirtualAddress)
		if !valid || table.Size > maxFunctionTable || table.Size%stride != 0 {
			image.warnings = append(image.warnings, "invalid PE exception directory bounds")
		} else if data, err := image.readMapped(r, addr, table.Size); err != nil {
			image.warnings = append(image.warnings, "read PE exception directory: "+err.Error())
		} else {
			for len(data) >= int(stride) {
				begin := binary.LittleEndian.Uint32(data)
				address, valid := toAddress(begin)
				var size uint64
				if stride == 12 {
					end := binary.LittleEndian.Uint32(data[4:])
					if end > begin {
						size = uint64(end - begin)
					} else {
						valid = false
					}
				}
				if valid && begin != 0 && peCodeAddress(file, base, address) {
					image.addFunction(address, size, "", "pe_exception_directory")
					image.descentSeeds = append(image.descentSeeds, address)
				}
				data = data[stride:]
			}
		}
	}
	for _, sym := range file.Symbols {
		const functionType = 0x20
		if sym.SectionNumber <= 0 || int(sym.SectionNumber) > len(file.Sections) || sym.Type&0x30 != functionType {
			continue
		}
		section := file.Sections[sym.SectionNumber-1]
		if section.Characteristics&pe.IMAGE_SCN_MEM_EXECUTE == 0 || sym.Value >= section.VirtualSize {
			continue
		}
		rva := uint64(section.VirtualAddress) + uint64(sym.Value)
		if rva <= math.MaxUint64-base {
			image.addFunction(base+rva, 0, sym.Name, "pe_coff_symbol")
		}
	}
	// Exports are the PE equivalent of ELF's exported dynsym entries: the binary
	// itself declares these as callable entry points, so they both add function
	// starts and supply names. That is different from reconstructed metadata
	// (Objective-C method pointers, DWARF rows), which only ever names addresses
	// something else already established as code.
	namePEExports(image, file, exports, base)
	// A PDB beside the binary is the richest name source Windows offers; it is
	// consulted last so export names, which ship with the binary itself, win.
	namePEFromPDB(image, file, base)
	// Sparse PE32 images have almost nothing but their export table indexed.
	// Walk the code from the starts already known and add direct call targets;
	// a PE whose metadata is dense (the x86-64 case, with full .pdata coverage)
	// is deliberately left alone.
	if shouldRecoverByDescent(image) {
		RecoverFunctionsByDescent(image, r, 0)
		// The gap sweep uses the same sparse-PE gate. ScanUncoveredCode also
		// refuses images with an exception directory, so the x86-64 .pdata
		// index is never touched.
		ScanUncoveredCode(image, r, 0)
	}
}

// namePEFromPDB names functions from the PDB that belongs to the binary.
//
// A PE carries no symbol table, so without this every function in a Windows build is
// anonymous. Two things matter more than the lookup itself:
//
//   - The PDB is located through the PE's own debug directory when possible, falling
//     back to the sibling convention (<binary>.pdb). A build machine's absolute path
//     rarely exists here, so the recorded *basename* beside the binary is tried too.
//   - The PDB's identity is checked against the CodeView record. Using a PDB from a
//     different build silently attaches wrong names to wrong addresses, which is worse
//     than leaving them anonymous. A mismatch is reported, not used.
func namePEFromPDB(image *Image, file *pe.File, base uint64) {
	if image.path == "" {
		return
	}
	want, haveRecord := peCodeViewInfo(file, image.path)
	candidates := pdbCandidates(image.path, want.Path)
	if len(candidates) == 0 {
		return
	}
	for _, candidate := range candidates {
		pdb, err := os.Open(candidate)
		if err != nil {
			continue
		}
		stat, statErr := pdb.Stat()
		if statErr != nil || !stat.Mode().IsRegular() {
			pdb.Close()
			continue
		}
		const maxPDB = 512 << 20
		if stat.Size() > maxPDB {
			image.warnings = append(image.warnings, "PDB exceeds inspection limit: "+candidate)
			pdb.Close()
			return
		}
		if haveRecord {
			info, infoErr := ReadPDBInfo(pdb, stat.Size())
			if infoErr != nil {
				image.warnings = append(image.warnings, "read PDB identity: "+infoErr.Error())
				pdb.Close()
				continue
			}
			if !CodeViewMatches(want, info.GUID, info.Age) {
				image.warnings = append(image.warnings,
					fmt.Sprintf("PDB %s does not match the binary (GUID/age differ); not used", filepath.Base(candidate)))
				pdb.Close()
				continue
			}
			image.PDB = &PDBReference{Path: candidate, GUID: info.GUID, Age: info.Age, Matched: true}
		} else {
			// No CodeView record means the binary records no expectation, so the
			// file cannot be proven correct. It is still used — a sibling PDB is
			// strong evidence — but it is reported as unmatched so a report can
			// distinguish "verified" from "assumed".
			image.PDB = &PDBReference{Path: candidate, Matched: false}
			image.warnings = append(image.warnings,
				"binary carries no CodeView record; PDB identity could not be verified")
		}
		// S_GPROC32 records carry a name, a size and a type index, so they replace the
		// public symbols as the primary source. Public symbols still matter: they cover
		// code the module streams do not describe, such as compiler-generated helpers.
		procedures, procErr := ReadPDBProcedures(pdb, stat.Size(), 0)
		publicSymbols, pubErr := ReadPDBPublicSymbols(pdb, stat.Size(), 0)
		pdb.Close()
		if procErr != nil {
			image.warnings = append(image.warnings, "read PDB procedures: "+procErr.Error())
		}
		if pubErr != nil {
			image.warnings = append(image.warnings, "read PDB symbols: "+pubErr.Error())
		}
		for _, procedure := range procedures {
			index := int(procedure.Segment) - 1
			if index < 0 || index >= len(file.Sections) {
				continue
			}
			section := file.Sections[index]
			address := base + uint64(section.VirtualAddress) + uint64(procedure.Offset)
			image.addFunction(address, uint64(procedure.CodeSize), procedure.Name, "pdb_procedure")
			if procedure.Signature != "" {
				if existing, ok := image.functions[address]; ok && existing.Signature == "" {
					existing.Signature = procedure.Signature
					image.functions[address] = existing
				}
			}
		}
		for _, symbol := range publicSymbols {
			index := int(symbol.Segment) - 1
			if index < 0 || index >= len(file.Sections) {
				continue
			}
			section := file.Sections[index]
			address := base + uint64(section.VirtualAddress) + uint64(symbol.Offset)
			image.addFunction(address, 0, symbol.Name, "pdb_public")
		}
		return
	}
}

// PDBReference records which PDB was used, so a report can show where names came from.
type PDBReference struct {
	Path    string `json:"path"`
	GUID    string `json:"guid,omitempty"`
	Age     uint32 `json:"age,omitempty"`
	Matched bool   `json:"matched"`
}

// pdbCandidates lists the PDB files worth opening, most specific first.
func pdbCandidates(binaryPath, recorded string) []string {
	dir := filepath.Dir(binaryPath)
	stem := strings.TrimSuffix(filepath.Base(binaryPath), filepath.Ext(binaryPath))
	var out []string
	seen := map[string]bool{}
	add := func(path string) {
		if path == "" || seen[path] {
			return
		}
		seen[path] = true
		out = append(out, path)
	}
	// 1. The sibling convention: same basename with a .pdb extension.
	add(filepath.Join(dir, stem+".pdb"))
	// 2. The basename the PE recorded, looked for beside the binary.
	if recorded != "" {
		base := filepath.Base(strings.ReplaceAll(recorded, "\\", "/"))
		add(filepath.Join(dir, base))
		// 3. The recorded absolute path, in case the build tree is present.
		add(recorded)
	}
	return out
}

// peCodeViewInfo reads the PE debug directory and returns its CodeView record.
func peCodeViewInfo(file *pe.File, path string) (CodeViewInfo, bool) {
	var table pe.DataDirectory
	switch h := file.OptionalHeader.(type) {
	case *pe.OptionalHeader64:
		if h.NumberOfRvaAndSizes > pe.IMAGE_DIRECTORY_ENTRY_DEBUG {
			table = h.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_DEBUG]
		}
	case *pe.OptionalHeader32:
		if h.NumberOfRvaAndSizes > pe.IMAGE_DIRECTORY_ENTRY_DEBUG {
			table = h.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_DEBUG]
		}
	}
	if table.VirtualAddress == 0 || table.Size == 0 {
		return CodeViewInfo{}, false
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return CodeViewInfo{}, false
	}
	// The debug directory is RVA-based; translate through the section table.
	for _, section := range file.Sections {
		if section == nil {
			continue
		}
		start := uint64(section.VirtualAddress)
		span := uint64(section.VirtualSize)
		if span == 0 {
			span = uint64(section.Size)
		}
		if uint64(table.VirtualAddress) < start || uint64(table.VirtualAddress)-start >= span {
			continue
		}
		offset := uint64(section.Offset) + (uint64(table.VirtualAddress) - start)
		size := uint64(table.Size)
		if offset >= uint64(len(raw)) {
			return CodeViewInfo{}, false
		}
		if size > uint64(len(raw))-offset {
			size = uint64(len(raw)) - offset
		}
		entries := ReadPEDebugDirectory(raw[offset : offset+size])
		for _, entry := range entries {
			const codeViewType = 2
			if entry.Type != codeViewType || entry.Pointer == 0 {
				continue
			}
			recordSize := uint64(entry.Size)
			start := uint64(entry.Pointer)
			if start >= uint64(len(raw)) {
				continue
			}
			if recordSize > uint64(len(raw))-start {
				recordSize = uint64(len(raw)) - start
			}
			if info, ok := ReadCodeView(raw[start : start+recordSize]); ok {
				return info, true
			}
		}
		return CodeViewInfo{}, false
	}
	return CodeViewInfo{}, false
}

// namePEExports maps the PE export data directory into its section and records
// the exported entry points. An absent, unmapped, or truncated directory is
// skipped silently.
//
// Exports are added as function starts, not merely names. A PE with no unwind
// table and no COFF symbols otherwise yields only its entry point, so naming
// alone found nothing to name — measured on a hand-linked arm64 PE: the export
// table listed exported_add at RVA 0x1008 and the index still held one function.
func namePEExports(image *Image, file *pe.File, directory pe.DataDirectory, base uint64) {
	if image == nil || file == nil || directory.VirtualAddress == 0 || directory.Size == 0 {
		return
	}
	if !image.exportsParsed {
		exports, reason := parsePEExportsInFile(file, directory, base)
		if reason != "" {
			image.warnings = append(image.warnings, "exports unavailable, reason "+reason)
		}
		image.Exports, image.ExportCount, image.exportsParsed = exports, len(exports), true
	}
	for _, export := range image.Exports {
		// Skip forwarder entries, which carry no address in this image.
		if export.Address == 0 {
			continue
		}
		image.addFunction(export.Address, 0, export.Name, "pe_export")
	}
}

func peCodeAddress(file *pe.File, base, address uint64) bool {
	if address < base {
		return false
	}
	rva := address - base
	for _, section := range file.Sections {
		start := uint64(section.VirtualAddress)
		if section.Characteristics&pe.IMAGE_SCN_MEM_EXECUTE != 0 && rva >= start && rva-start < uint64(section.VirtualSize) {
			return true
		}
	}
	return false
}

func (image Image) readMapped(r io.ReaderAt, address uint64, size uint32) ([]byte, error) {
	start, ok := image.fileRange(address, uint64(size))
	if !ok || start > math.MaxInt64-uint64(size)+1 {
		return nil, fmt.Errorf("range is not contiguous and file-backed")
	}
	data := make([]byte, size)
	if _, err := r.ReadAt(data, int64(start)); err != nil {
		return nil, err
	}
	return data, nil
}
