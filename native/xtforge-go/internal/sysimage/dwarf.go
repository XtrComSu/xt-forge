package sysimage

import (
	"debug/dwarf"
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"io"
)

// DWARF symbol import.
//
// When a binary still carries debug information, function names and sizes are
// recorded exactly — no heuristics. This reads DW_TAG_subprogram entries and
// names the addresses they describe, which is what lets a debug build come out
// fully named.
//
// The function index is still built first from the binary's own tables, and DWARF
// only names addresses already in it. That keeps one rule across this package:
// metadata supplies names, never new function starts. A stale or bogus DWARF
// entry therefore produces nothing instead of a phantom function.
//
// The standard library's per-format DWARF() accessors are used rather than
// assembling sections by hand: they handle DWARF version differences and
// compressed sections, and hand-rolling that is how subtle off-by-one decoding
// bugs get in.

// dwarfEntryLimit bounds decoding so a hostile binary cannot turn inspection into
// a memory-exhaustion exercise.
const dwarfEntryLimit = 100000

// dwarfSubprogram is one recovered function record.
type dwarfSubprogram struct {
	Name     string `json:"name"`
	LowPC    uint64 `json:"low_pc"`
	HighPC   uint64 `json:"high_pc"`
	DeclLine int64  `json:"decl_line,omitempty"`
}

// dwarfMetadata is what one image's debug information provided.
type dwarfMetadata struct {
	Functions []dwarfSubprogram `json:"functions"`
	CompUnits int               `json:"comp_units"`
	Named     int               `json:"named"`
}

// readDWARF decodes debug information from whichever format the file is.
//
// No debug information is a normal outcome, not a failure: shipped binaries
// almost never carry it, so this returns nil rather than an error.
func readDWARF(r io.ReaderAt, format string) *dwarfMetadata {
	data := dwarfData(r, format)
	if data == nil {
		return nil
	}
	meta := &dwarfMetadata{}
	reader := data.Reader()
	for len(meta.Functions) < dwarfEntryLimit {
		tag, err := reader.Next()
		if err != nil || tag == nil {
			break
		}
		if tag.Tag != dwarf.TagCompileUnit {
			continue
		}
		meta.CompUnits++
		for len(meta.Functions) < dwarfEntryLimit {
			child, err := reader.Next()
			if err != nil || child == nil {
				break
			}
			if child.Tag != dwarf.TagSubprogram {
				continue
			}
			if subprogram, ok := dwarfFunction(child); ok {
				meta.Functions = append(meta.Functions, subprogram)
			}
		}
	}
	if len(meta.Functions) == 0 {
		return nil
	}
	return meta
}

// dwarfData returns the debug information for a file, or nil when it has none.
func dwarfData(r io.ReaderAt, format string) *dwarf.Data {
	var (
		data *dwarf.Data
		err  error
	)
	switch format {
	case "elf":
		file, openErr := elf.NewFile(r)
		if openErr != nil {
			return nil
		}
		data, err = file.DWARF()
	case "macho":
		file, openErr := macho.NewFile(r)
		if openErr != nil {
			return nil
		}
		data, err = file.DWARF()
	case "pe":
		file, openErr := pe.NewFile(r)
		if openErr != nil {
			return nil
		}
		data, err = file.DWARF()
	default:
		return nil
	}
	if err != nil || data == nil {
		return nil
	}
	return data
}

// dwarfFunction builds a record from one subprogram entry.
func dwarfFunction(entry *dwarf.Entry) (dwarfSubprogram, bool) {
	var subprogram dwarfSubprogram
	var highRaw uint64
	for _, field := range entry.Field {
		switch field.Attr {
		case dwarf.AttrName:
			if name, ok := field.Val.(string); ok && name != "" {
				subprogram.Name = name
			}
		case dwarf.AttrLowpc:
			if address, ok := field.Val.(uint64); ok {
				subprogram.LowPC = address
			}
		case dwarf.AttrHighpc:
			// The decoded value's Go type depends on the attribute's form class:
			// an address arrives as uint64, a constant offset as int64. Handling
			// only uint64 left HighPC at zero for ordinary clang output, which
			// showed up as functions with a negative size.
			switch value := field.Val.(type) {
			case uint64:
				highRaw = value
			case int64:
				if value > 0 {
					highRaw = uint64(value)
				}
			}
		}
	}
	// DW_AT_high_pc is either an absolute address or an offset from the low PC,
	// and the forms are indistinguishable without the attribute's class. The
	// practical test: an "absolute" value at or below the low PC cannot be an
	// address, so it must be an offset. Getting this wrong yields a wildly wrong
	// size, which is what makes it worth stating.
	if highRaw > subprogram.LowPC {
		subprogram.HighPC = highRaw
	} else if highRaw != 0 {
		subprogram.HighPC = subprogram.LowPC + highRaw
	}
	if subprogram.Name == "" || subprogram.LowPC == 0 {
		return dwarfSubprogram{}, false
	}
	return subprogram, true
}

// applyDWARF names functions from debug information.
func (image *Image) applyDWARF(meta *dwarfMetadata) {
	if meta == nil {
		return
	}
	for index := range meta.Functions {
		function := &meta.Functions[index]
		if function.HighPC > function.LowPC {
			if existing, ok := image.functions[function.LowPC]; ok && existing.Size == 0 {
				existing.Size = function.HighPC - function.LowPC
				image.functions[function.LowPC] = existing
			}
		}
		if image.nameFunction(function.LowPC, function.Name, "dwarf") {
			meta.Named++
		}
	}
}
