package sysimage

import (
	"encoding/binary"
	"fmt"
	"io"
	"sort"
)

// Jump tables are the most common form of indirect dispatch in compiled code.
// This file recognises the table lookup idiom inside a lifted function and turns
// it into concrete destinations, so callers get resolved targets instead of an
// opaque indirect branch.
//
// Recognised x86-64 idiom (GCC and Clang, -O1 and above):
//
//	cmp     $bound, %edi
//	ja      default
//	lea     table(%rip), %rax      ; address of a 32-bit offset table
//	mov     %edi, %edi             ; zero-extend the index
//	movslq  (%rax,%rdi,4), %rdx    ; sign-extend a table entry
//	add     %rax, %rdx
//	jmp     *%rdx
//
// Recognised arm64 idiom (Clang, dense switch over 10+ cases):
//
//	cmp     w0, #bound
//	b.hi    default
//	adrp    x9, page
//	add     x9, x9, #offset        ; base of a byte offset table
//	adr     x10, table             ; anchor: first case body
//	ldrb    w11, [x9, x8]
//	add     x10, x10, x11, lsl #2
//	br      x10
//
// Both shapes reduce to: base + scale*table[index], where base and table are
// file-backed addresses and index is bounded by the preceding compare.

const (
	maxJumpTableEntries = 4096
	maxJumpTableBytes   = 4 * 1024 * 1024
	// A table whose entries are not all executable is rejected; a real jump
	// table only ever points into code.
	jumpTableMaxRejects = 0
)

type JumpTable struct {
	// Function and FunctionName identify the function the table was found in, which
	// matters once one call scans more than a single function.
	Function     uint64   `json:"function,omitempty"`
	FunctionName string   `json:"function_name,omitempty"`
	Site         uint64   `json:"site"`
	Kind         string   `json:"kind"`
	Table        uint64   `json:"table"`
	EntrySize    int      `json:"entry_size"`
	Entries      int      `json:"entries"`
	Base         uint64   `json:"base,omitempty"`
	BaseRegister string   `json:"base_register,omitempty"`
	Targets      []uint64 `json:"targets"`
	Index        string   `json:"index,omitempty"`
	Bound        *uint64  `json:"bound,omitempty"`
	Truncated    bool     `json:"truncated,omitempty"`
	Warnings     []string `json:"warnings,omitempty"`
}

// JumpTableResult summarises dispatch recovery for one function.
type JumpTableResult struct {
	Tables   []JumpTable `json:"tables,omitempty"`
	Resolved int         `json:"resolved_targets"`
	Indirect int         `json:"unresolved_indirect"`
}

func (result JumpTableResult) targets() []uint64 {
	var out []uint64
	for _, table := range result.Tables {
		out = append(out, table.Targets...)
	}
	return out
}

// findJumpTables scans a lifted function for recognised table dispatch.
// r must address the function's image; base is the address of data[0].
func findJumpTables(arch string, r io.ReaderAt, image *Image, instructions []Instruction, ops []Operation) JumpTableResult {
	var result JumpTableResult
	byAddress := make(map[uint64]int, len(ops))
	for i, op := range ops {
		byAddress[op.Address] = i
	}
	seen := make(map[uint64]bool)
	for i, op := range ops {
		if !isIndirectBranch(op) {
			continue
		}
		if seen[op.Address] {
			continue
		}
		seen[op.Address] = true
		table, ok := recoverJumpTable(arch, r, image, ops[:i+1], byAddress[op.Address])
		if !ok {
			result.Indirect++
			continue
		}
		table.Site = op.Address
		result.Tables = append(result.Tables, table)
		result.Resolved += len(table.Targets)
	}
	return result
}

// RecoverDispatch finds indirect-dispatch tables in one function of an image and
// returns concrete destinations. It is the entry point used by the CLI and MCP
// surfaces; callers can then index or decompile the recovered targets.
func RecoverDispatch(filename string, opts DispatchOptions) (DispatchResult, error) {
	if err := validateDisassemblyOptions(DisassemblyOptions{Target: opts.Target, Member: opts.Member, Arch: opts.Arch}); err != nil {
		return DispatchResult{}, err
	}
	var result DispatchResult
	_, err := analyzeFile(filename, opts.Member, true, func(r io.ReaderAt, info OverviewResult) error {
		image, err := selectNativeImage(info.Images, opts.Arch)
		if err != nil {
			return err
		}
		// Without an explicit target the entry point used to be analysed, which for a
		// normal executable is CRT glue: the result said `tables: 0` while the binary's
		// own switches were never looked at. That reads as "no jump tables here", which
		// is a different and false claim. Scan the whole function index instead, bounded,
		// and say how much was covered.
		var targets []uint64
		if opts.Target == "" {
			for address := range image.functions {
				targets = append(targets, address)
			}
			sort.Slice(targets, func(i, j int) bool { return targets[i] < targets[j] })
			if len(targets) > dispatchScanLimit {
				targets = targets[:dispatchScanLimit]
			}
		} else {
			address, err := resolveTarget(*image, opts.Target)
			if err != nil {
				return err
			}
			targets = []uint64{address}
		}
		result.OK = true
		result.Engine, result.Path, result.Format = info.Engine, info.Path, info.Format
		result.Member, result.Arch, result.SliceOffset = info.Member, image.Arch, image.SliceOffset
		result.FunctionsScanned = 0
		for _, address := range targets {
			window := functionWindow(*image, address)
			if window == 0 {
				continue
			}
			data, err := image.readMapped(r, address, uint32(window))
			if err != nil {
				continue
			}
			instructions, blocks, warnings := recoverFlow(image.Arch, address, data, maxInstructions)
			decompiled := liftDisassembly(Disassembly{
				Engine: info.Engine, Path: info.Path, Format: info.Format, Member: info.Member,
				Arch: image.Arch, Address: address, Instructions: instructions, Blocks: blocks,
				Warnings: warnings,
			}, false)
			var flat []Operation
			for _, block := range decompiled.IR {
				flat = append(flat, block.Operations...)
			}
			dispatch := findJumpTables(image.Arch, r, image, instructions, flat)
			result.FunctionsScanned++
			result.Indirect += dispatch.Indirect
			result.Resolved += dispatch.Resolved
			for _, table := range dispatch.Tables {
				table.Function = address
				if name := image.functions[address].Name; name != "" {
					table.FunctionName = name
				}
				result.Tables = append(result.Tables, table)
			}
			if len(warnings) > 0 {
				result.Warnings = append(result.Warnings, warnings...)
			}
			if opts.Target == "" && len(result.Tables) >= dispatchTableLimit {
				result.Warnings = append(result.Warnings, fmt.Sprintf(
					"stopped after %d jump tables", dispatchTableLimit))
				break
			}
		}
		if len(targets) == 0 {
			return fmt.Errorf("no functions to analyse in this image")
		}
		return nil
	})
	if err != nil {
		return DispatchResult{}, err
	}
	return result, nil
}

const (
	// dispatchScanLimit bounds how many functions one call will traverse when no target
	// is given, so a 50,000-function binary does not run unbounded.
	dispatchScanLimit = 4096
	// dispatchTableLimit stops the sweep once this many tables are found.
	dispatchTableLimit = 512
)

// DispatchOptions selects the function to scan.
type DispatchOptions struct {
	Member string
	Arch   string
	Target string
}

// DispatchResult reports recovered dispatch tables for one function.
type DispatchResult struct {
	OK               bool   `json:"ok"`
	Engine           string `json:"engine"`
	Path             string `json:"path"`
	Format           string `json:"format"`
	Member           string `json:"member,omitempty"`
	Arch             string `json:"arch"`
	SliceOffset      uint64 `json:"slice_offset,omitempty"`
	FunctionsScanned int    `json:"functions_scanned"`
	Function         uint64 `json:"function"`
	FunctionName     string `json:"function_name,omitempty"`
	JumpTableResult
	Warnings []string `json:"warnings,omitempty"`
}

func isIndirectBranch(op Operation) bool {
	switch op.Opcode {
	case "jump", "branch":
	default:
		return false
	}
	if op.Target != nil || len(op.Inputs) != 1 {
		return false
	}
	input := op.Inputs[0]
	return input.Kind == "register" && input.Register != "" && input.Memory == nil
}

// registerState tracks the last definition of a register while rewinding.
type registerState struct {
	op    Operation
	index int
	found bool
}

func trackBack(ops []Operation, at int, register string, depth int) registerState {
	limit := max(0, at-depth)
	want := canonicalRegister(register)
	for i := at - 1; i >= limit; i-- {
		op := ops[i]
		if op.Destination != nil && op.Destination.Kind == "register" &&
			canonicalRegister(op.Destination.Register) == want {
			return registerState{op: op, index: i, found: true}
		}
		// A second destination (for example a flag-setting add that also writes
		// the source register) terminates tracking as well.
		if op.SecondDestination != nil && op.SecondDestination.Kind == "register" &&
			canonicalRegister(op.SecondDestination.Register) == want {
			return registerState{op: op, index: i, found: true}
		}
	}
	return registerState{}
}

// classifyRegister identifies whether a register holds a dispatch table base or
// a table entry. It traces the last definition before limit.
func classifyRegister(ops []Operation, limit int, register string) (kind string, def registerState) {
	def = trackBack(ops, limit, register, 16)
	if !def.found {
		return "", def
	}
	switch def.op.Opcode {
	case "address":
		return "base", def
	case "sign_extend", "load":
		for _, input := range def.op.Inputs {
			if input.Kind == "memory" && input.Memory != nil {
				return "entry", def
			}
		}
		return "entry", def
	case "copy", "zero_extend":
		// A lifted load stores its memory operand as the single input.
		for _, input := range def.op.Inputs {
			if input.Kind == "memory" && input.Memory != nil {
				return "entry", def
			}
		}
	case "opaque":
		// Loads that the lifter does not model keep the original text in Raw.
		if _, ok := armMemoryBase(def.op.Raw); ok {
			return "entry", def
		}
	}
	return "other", def
}

func baseAddress(def registerState) (uint64, bool) {
	if def.op.Opcode != "address" || len(def.op.Inputs) != 1 {
		return 0, false
	}
	input := def.op.Inputs[0]
	if input.Kind == "immediate" {
		return parseImmediateHex(input.Immediate)
	}
	if input.Kind == "memory" && input.Memory != nil && input.Memory.Absolute != "" {
		return parseImmediateHex(input.Memory.Absolute)
	}
	return 0, false
}

// addressConstant resolves a register to a link-time constant, following the
// arm64 adrp/add page pair as well as direct address materialisation.
func addressConstant(ops []Operation, at int, register string, depth int) (uint64, bool) {
	if depth == 0 {
		return 0, false
	}
	def := trackBack(ops, at, register, 16)
	if !def.found {
		return 0, false
	}
	switch def.op.Opcode {
	case "address":
		return baseAddress(def)
	case "add":
		if len(def.op.Inputs) != 2 {
			return 0, false
		}
		var total uint64
		for _, input := range def.op.Inputs {
			switch input.Kind {
			case "immediate":
				value, ok := parseImmediateHex(input.Immediate)
				if !ok {
					return 0, false
				}
				total += value
			case "register":
				value, ok := addressConstant(ops, def.index, input.Register, depth-1)
				if !ok {
					return 0, false
				}
				total += value
			default:
				return 0, false
			}
		}
		return total, true
	}
	return 0, false
}

// recoverJumpTable rewinds from an indirect branch over the preceding operations
// and reconstructs base + scale*table[index]. Both supported idioms end in an add
// that joins a table base with a loaded entry, but which operand carries the base
// differs by architecture, so the registers are classified by their definitions.
func recoverJumpTable(arch string, r io.ReaderAt, image *Image, ops []Operation, at int) (JumpTable, bool) {
	branch := ops[at]
	register := branch.Inputs[0].Register
	add := trackBack(ops, at, register, 12)
	if !add.found || add.op.Opcode != "add" {
		return JumpTable{}, false
	}
	candidates := make([]string, 0, 3)
	candidates = append(candidates, register)
	for _, input := range add.op.Inputs {
		if input.Kind == "register" && input.Register != register {
			candidates = append(candidates, input.Register)
		}
	}
	var baseRegister, entryRegister string
	var baseDef, entryDef registerState
	for _, candidate := range candidates {
		kind, def := classifyRegister(ops, add.index, candidate)
		switch kind {
		case "base":
			if baseRegister == "" {
				baseRegister, baseDef = candidate, def
			}
		case "entry":
			if entryRegister == "" {
				entryRegister, entryDef = candidate, def
			}
		}
	}
	if baseRegister == "" || entryRegister == "" {
		return JumpTable{}, false
	}
	// The table is the memory the entry load reads. x86 addresses it through the
	// base register; arm64 usually keeps the table in a second register built by
	// adrp+add and the case anchor in the base register.
	anchorAddress, anchorKnown := baseAddress(baseDef)
	var tableAddress uint64
	for _, input := range entryDef.op.Inputs {
		if input.Kind != "memory" || input.Memory == nil || input.Memory.Base == "" {
			continue
		}
		if address, ok := addressConstant(ops, entryDef.index, input.Memory.Base, 4); ok {
			tableAddress = address
		}
	}
	if tableAddress == 0 {
		if address, ok := baseAddress(baseDef); ok {
			tableAddress = address
		}
	}
	if tableAddress == 0 {
		return JumpTable{}, false
	}
	// The scaling left for the add tells the entry size: byte tables are scaled
	// by the instruction stride, while a full-word load needs no extra scale.
	entryShift := 0
	for _, input := range add.op.Inputs {
		if input.Kind == "register" && canonicalRegister(input.Register) == canonicalRegister(entryRegister) {
			if input.Shift != "" {
				return JumpTable{}, false
			}
			entryShift = int(input.Scale)
		}
	}
	bound, index := boundAndIndex(ops, at, entryDef, arch)
	switch arch {
	case "x86", "x86_64":
		scale := 4
		for _, input := range entryDef.op.Inputs {
			if input.Kind == "memory" && input.Memory != nil && input.Memory.Scale != 0 {
				scale = int(input.Memory.Scale)
			}
		}
		return buildJumpTable(r, image, JumpTable{
			Kind: "x86_offset_table", Table: tableAddress, EntrySize: scale,
			Base: tableAddress, BaseRegister: baseRegister, Index: index, Bound: bound,
			Warnings: []string{"table entries are signed 32-bit offsets relative to the table"},
		}, signedEntries)
	case "arm64":
		if !anchorKnown {
			return JumpTable{}, false
		}
		if entryShift == 0 {
			// ldrsw form: signed 32-bit offsets relative to the anchor.
			return buildJumpTable(r, image, JumpTable{
				Kind: "arm64_offset_table", Table: tableAddress, EntrySize: 4,
				Base: anchorAddress, BaseRegister: baseRegister, Index: index, Bound: bound,
				Warnings: []string{"table entries are signed 32-bit offsets relative to the anchor address"},
			}, signedEntries)
		}
		// ldrb form: one byte per case, scaled by the instruction stride.
		factor := int64(1) << uint(entryShift)
		return buildJumpTable(r, image, JumpTable{
			Kind: "arm64_byte_table", Table: tableAddress, EntrySize: 1,
			Base: anchorAddress, BaseRegister: baseRegister, Index: index, Bound: bound,
			Warnings: []string{fmt.Sprintf(
				"table holds byte offsets scaled by %d and added to the anchor address", factor)},
		}, byteEntriesFor(factor))
	}
	return JumpTable{}, false
}

// boundAndIndex finds the compare that bounds the dispatch index.
func boundAndIndex(ops []Operation, at int, entryDef registerState, arch string) (*uint64, string) {
	// The index is the memory operand's index register when the entry load is
	// register-scaled, otherwise the first operand of the bounding compare.
	index := ""
	for _, input := range entryDef.op.Inputs {
		if input.Kind == "memory" && input.Memory != nil {
			index = input.Memory.Index
		}
	}
	// A dedicated compare (x86 "cmp"/"test", arm64 "cmp") lifts to a standalone
	// flags operation. arm64 instead often bounds the index with a flag-setting
	// subs, which is an ordinary arithmetic op carrying Flags. Prefer the
	// dedicated compare so a flag-setting add inside the dispatch sequence
	// cannot shadow it.
	var bound *uint64
	found := false
	for pass := 0; pass < 2 && !found; pass++ {
		for i := at - 1; i >= 0 && i >= at-20; i-- {
			op := ops[i]
			dedicated := op.Opcode == "flags"
			if pass == 0 && !dedicated {
				continue
			}
			if pass == 1 && (dedicated || op.Flags == "") {
				continue
			}
			if len(op.Inputs) < 2 {
				continue
			}
			if op.Inputs[1].Kind == "immediate" {
				if value, ok := parseImmediateHex(op.Inputs[1].Immediate); ok {
					bound = &value
				}
			}
			if index == "" && op.Inputs[0].Kind == "register" {
				index = op.Inputs[0].Register
			}
			found = true
			break
		}
	}
	return bound, index
}

func parseImmediateHex(text string) (uint64, bool) {
	if len(text) < 3 || text[0] != '0' || (text[1] != 'x' && text[1] != 'X') {
		return 0, false
	}
	var value uint64
	for _, c := range text[2:] {
		value <<= 4
		switch {
		case c >= '0' && c <= '9':
			value |= uint64(c - '0')
		case c >= 'a' && c <= 'f':
			value |= uint64(c-'a') + 10
		case c >= 'A' && c <= 'F':
			value |= uint64(c-'A') + 10
		default:
			return 0, false
		}
	}
	return value, true
}

// armMemoryBase pulls the base register out of "[x9, x8]" style operand text.
func armMemoryBase(text string) (string, bool) {
	open := -1
	for i := 0; i < len(text); i++ {
		if text[i] == '[' {
			open = i
			break
		}
	}
	if open < 0 {
		return "", false
	}
	start := open + 1
	for start < len(text) && text[start] == ' ' {
		start++
	}
	end := start
	for end < len(text) && text[end] != ',' && text[end] != ']' && text[end] != ' ' {
		end++
	}
	if end == start {
		return "", false
	}
	return text[start:end], true
}

type entryDecoder func(raw []byte, base uint64) (uint64, bool)

func signedEntries(raw []byte, base uint64) (uint64, bool) {
	if len(raw) < 4 {
		return 0, false
	}
	offset := int64(int32(binary.LittleEndian.Uint32(raw)))
	return applyOffset(base, offset)
}

func absoluteEntries(raw []byte, base uint64) (uint64, bool) {
	if len(raw) < 8 {
		return 0, false
	}
	return binary.LittleEndian.Uint64(raw), true
}

// byteEntriesFor decodes ldrb-dispatched table entries: one unsigned byte per
// case, scaled by the instruction stride and added to the anchor address.
func byteEntriesFor(factor int64) entryDecoder {
	return func(raw []byte, base uint64) (uint64, bool) {
		if len(raw) < 1 {
			return 0, false
		}
		return applyOffset(base, int64(raw[0])*factor)
	}
}

func applyOffset(base uint64, offset int64) (uint64, bool) {
	if offset >= 0 {
		return base + uint64(offset), true
	}
	distance := uint64(-(offset + 1)) + 1
	if distance > base {
		return 0, false
	}
	return base - distance, true
}

// buildJumpTable reads table entries until the table stops pointing at code.
func buildJumpTable(r io.ReaderAt, image *Image, table JumpTable, decode entryDecoder) (JumpTable, bool) {
	entries := maxJumpTableEntries
	if table.Bound != nil {
		entries = int(*table.Bound) + 1
		if entries < 1 {
			return JumpTable{}, false
		}
		if entries > maxJumpTableEntries {
			entries = maxJumpTableEntries
		}
	} else {
		// No compare bounds the index; cap by the mapped data available.
		span := executableSpan(*image, table.Table)
		if span == 0 {
			if _, ok := image.fileRange(table.Table, 1); !ok {
				return JumpTable{}, false
			}
			span = maxJumpTableBytes
		}
		if limit := int(span) / table.EntrySize; limit < entries {
			entries = limit
		}
	}
	if entries < 1 {
		return JumpTable{}, false
	}
	if entries*table.EntrySize > maxJumpTableBytes {
		entries = maxJumpTableBytes / table.EntrySize
		table.Truncated = true
	}
	// Tables can sit at the end of a mapped region; shrink until the read fits.
	var buffer []byte
	for size := entries; size >= 1; size /= 2 {
		data, err := image.readMapped(r, table.Table, uint32(size*table.EntrySize))
		if err == nil {
			buffer, entries = data, size
			break
		}
	}
	if len(buffer) == 0 {
		return JumpTable{}, false
	}
	table.Entries = len(buffer) / table.EntrySize
	seen := make(map[uint64]bool)
	for i := 0; i < table.Entries; i++ {
		target, ok := decode(buffer[i*table.EntrySize:], table.Base)
		if !ok || executableSpan(*image, target) == 0 {
			break
		}
		if table.Bound == nil && seen[target] {
			// Without a bound, a repeated target marks the end of the table.
			break
		}
		seen[target] = true
		table.Targets = append(table.Targets, target)
	}
	if len(table.Targets) == 0 {
		return JumpTable{}, false
	}
	// Targets stay in index order: the table is a case-to-address map, and
	// several cases legitimately share one body.
	table.Entries = len(table.Targets)
	return table, true
}
