package sysimage

import (
	"fmt"
	"io"
	"math"
	"sort"
	"strconv"
	"strings"
)

const (
	// maxReferenceFunctions bounds how many functions one call will decode. It was
	// 4096, which capped a 50,670-function binary at 8% coverage with no way to ask for
	// more — the output reported "pending" honestly but the answer was unreachable. A
	// measured 0.26 ms per function means a full scan of that binary costs about 13 s,
	// which is a fine price for an explicit flag.
	maxReferenceFunctions = 200000
	maxReferenceOutput    = 2000
	referenceWindow       = 4096
)

type ReferenceOptions struct {
	Member       string
	Arch         string
	Target       string
	MaxFunctions int
	Limit        int
}

type CrossReference struct {
	Function     uint64 `json:"function"`
	FunctionName string `json:"function_name,omitempty"`
	Site         uint64 `json:"site"`
	Target       uint64 `json:"target"`
	TargetName   string `json:"target_name,omitempty"`
	TargetSource string `json:"target_source,omitempty"`
	// TargetClass says what kind of memory the target lands in. A name answers "what is
	// this", which only exists for symbolised targets; the class answers "is this code,
	// data or nothing I can map" for every reference, including the unnamed ones.
	TargetClass string `json:"target_class,omitempty"`
	Kind        string `json:"kind"`
}

type ReferenceIndex struct {
	OK               bool             `json:"ok"`
	Engine           string           `json:"engine"`
	Path             string           `json:"path"`
	Format           string           `json:"format"`
	Member           string           `json:"member,omitempty"`
	Arch             string           `json:"arch"`
	SliceOffset      uint64           `json:"slice_offset,omitempty"`
	Target           *uint64          `json:"target,omitempty"`
	Seeds            int              `json:"seeds"`
	Scanned          int              `json:"scanned"`
	Discovered       int              `json:"discovered"`
	DiscoveryLimited bool             `json:"discovery_limited"`
	Pending          int              `json:"pending"`
	LimitedFunctions int              `json:"limited_functions"`
	IndirectCalls    int              `json:"indirect_calls"`
	TotalReferences  int              `json:"total_references"`
	References       []CrossReference `json:"references"`
	Warnings         []string         `json:"warnings,omitempty"`
}

// dataStringIndex resolves addresses inside read-only data sections to the C string that
// starts there, so a data reference can be reported as the literal it points at.
type dataStringIndex struct {
	reader  io.ReaderAt
	regions []Region
}

// at returns the NUL-terminated string starting at address, bounded and printable only.
// A non-printable or unterminated run yields ok=false: guessing would put binary noise in
// a report next to real names.
func (index *dataStringIndex) at(address uint64) (string, bool) {
	for _, region := range index.regions {
		if address < region.Address || address >= region.Address+region.FileSize {
			continue
		}
		offset := region.Offset + (address - region.Address)
		buffer := make([]byte, 128)
		read, err := index.reader.ReadAt(buffer, int64(offset))
		if err != nil && read == 0 {
			return "", false
		}
		buffer = buffer[:read]
		end := 0
		for end < len(buffer) && buffer[end] != 0 {
			// Tab, newline and carriage return are ordinary in string literals
			// ("warn: %s\n" is the common case); other control bytes mean this is
			// binary data rather than a string, so the reference stays unnamed.
			switch buffer[end] {
			case '\t', '\n', '\r':
			case 0x20, 0x7f:
			default:
				if buffer[end] < 0x20 || buffer[end] > 0x7e {
					return "", false
				}
			}
			end++
		}
		if end == 0 || end == len(buffer) {
			return "", false
		}
		return escapeStringLiteral(string(buffer[:end])), true
	}
	return "", false
}

// escapeStringLiteral makes a C string safe for a single-line report.
func escapeStringLiteral(text string) string {
	replacer := strings.NewReplacer("\n", "\\n", "\t", "\\t", "\r", "\\r")
	return replacer.Replace(text)
}

// readOnlyStringRegions collects the file-backed, non-executable sections that hold data.
func readOnlyStringRegions(image Image) []Region {
	var regions []Region
	for _, section := range image.Sections {
		if section.FileSize == 0 {
			continue
		}
		executable := false
		for _, region := range image.Executable {
			if section.Address == region.Address {
				executable = true
				break
			}
		}
		if !executable {
			regions = append(regions, section)
		}
	}
	return regions
}

func References(filename string, options ReferenceOptions) (ReferenceIndex, error) {
	var out ReferenceIndex
	if options.MaxFunctions < 0 || options.MaxFunctions > maxReferenceFunctions ||
		options.Limit < 0 || options.Limit > maxReferenceOutput {
		return out, fmt.Errorf("reference limits are %d scanned functions and %d returned references", maxReferenceFunctions, maxReferenceOutput)
	}
	if options.MaxFunctions == 0 {
		options.MaxFunctions = 512
	}
	if options.Limit == 0 {
		options.Limit = 200
	}
	_, err := analyzeFile(filename, options.Member, true, func(r io.ReaderAt, info OverviewResult) error {
		image, err := selectNativeImage(info.Images, options.Arch)
		if err != nil {
			return err
		}
		out = ReferenceIndex{
			OK: true, Engine: info.Engine, Path: info.Path, Format: info.Format,
			Member: info.Member, Arch: image.Arch, SliceOffset: image.SliceOffset,
			Warnings: image.warnings, References: []CrossReference{},
		}
		if options.Target != "" {
			target, err := resolveTarget(*image, options.Target)
			if err != nil {
				return err
			}
			out.Target = &target
		}
		slice := io.NewSectionReader(r, int64(image.SliceOffset), int64(image.fileSize))
		scanReferences(slice, image, options, &out)
		return nil
	})
	return out, err
}

func executableSpan(image Image, address uint64) uint64 {
	var span uint64
	for _, region := range image.Executable {
		if address < region.Address {
			continue
		}
		size := min(region.Size, region.FileSize)
		if relative := address - region.Address; relative < size {
			span = max(span, size-relative)
		}
	}
	return span
}

func scanReferences(r io.ReaderAt, image *Image, options ReferenceOptions, out *ReferenceIndex) {
	if image.EntryPoint != nil {
		image.addFunction(*image.EntryPoint, 0, "", "entry_point")
	}
	starts := make([]uint64, 0, len(image.functions))
	for address := range image.functions {
		if executableSpan(*image, address) > 0 {
			starts = append(starts, address)
		}
	}
	sort.Slice(starts, func(i, j int) bool { return starts[i] < starts[j] })
	queue := append([]uint64(nil), starts...)
	out.Seeds = len(queue)
	if image.EntryPoint != nil {
		i := sort.Search(len(queue), func(i int) bool { return queue[i] >= *image.EntryPoint })
		if i < len(queue) && queue[i] == *image.EntryPoint {
			copy(queue[1:i+1], queue[:i])
			queue[0] = *image.EntryPoint
		}
	}
	type referenceKey struct {
		site, target uint64
		kind         string
	}
	seen := make(map[referenceKey]bool)
	seenIndirect := make(map[uint64]bool)
	// A pc-relative operand can point at a GOT slot rather than at code. Name
	// that slot from the ELF relocations so an indirect call says which import
	// it reaches. Direct call/jump targets keep their own names and sources.
	// Classify every target once: code, data, stack or unknown. ClassifyAddress existed
	// and was tested but called by nothing, so no surface ever said what a target was.
	codeRegions := image.Executable
	dataRegions := []Region{}
	for _, section := range image.Sections {
		if section.FileSize == 0 {
			continue
		}
		executable := false
		for _, region := range codeRegions {
			if section.Address == region.Address {
				executable = true
				break
			}
		}
		if !executable {
			dataRegions = append(dataRegions, section)
		}
	}
	var dataStrings *dataStringIndex
	if regions := readOnlyStringRegions(*image); len(regions) > 0 {
		dataStrings = &dataStringIndex{reader: r, regions: regions}
	}
	gotImports := make(map[uint64]string, len(image.Imports))
	for _, imported := range image.Imports {
		gotImports[imported.Slot] = imported.Name
	}
	add := func(fn Function, site, target uint64, kind string) {
		if out.Target != nil && *out.Target != target {
			return
		}
		key := referenceKey{site, target, kind}
		if seen[key] {
			return
		}
		seen[key] = true
		out.TotalReferences++
		if len(out.References) == options.Limit {
			return
		}
		destination := image.functions[target]
		reference := CrossReference{
			Function: fn.Address, FunctionName: fn.Name, Site: site, Target: target,
			TargetName: destination.Name, TargetSource: destination.Source, Kind: kind,
			TargetClass: string(ClassifyAddress(target, codeRegions, dataRegions, Region{})),
		}
		if kind != "call" && kind != "tail_jump_candidate" {
			if name, ok := gotImports[target]; ok {
				reference.TargetName, reference.TargetSource = name, "elf_got_import"
			} else if reference.TargetName == "" && dataStrings != nil {
				// A reference into read-only data is almost always a string literal,
				// and the literal at a call site is worth far more than an address.
				if text, ok := dataStrings.at(target); ok {
					reference.TargetName, reference.TargetSource = text, "rodata_string"
				}
			}
		}
		out.References = append(out.References, reference)
	}
	nextStart := func(address uint64) int {
		return sort.Search(len(starts), func(i int) bool { return starts[i] > address })
	}
	var inferred []uint64
	nextInferred := func(address uint64) int {
		return sort.Search(len(inferred), func(i int) bool { return inferred[i] > address })
	}
	discover := func(instruction Instruction, local []Instruction) {
		target := *instruction.Target
		if target == instruction.Address+uint64(instruction.Size) ||
			(image.Arch == "arm64" && target%4 != 0) || executableSpan(*image, target) == 0 {
			return
		}
		if _, known := image.functions[target]; known {
			return
		}
		site := sort.Search(len(local), func(i int) bool { return local[i].Address >= target })
		if site < len(local) && local[site].Address == target {
			return
		}
		if i := nextStart(target); i > 0 && target-starts[i-1] < image.functions[starts[i-1]].Size {
			return
		}
		if out.Discovered == maxReferenceFunctions {
			out.DiscoveryLimited = true
			return
		}
		image.addFunction(target, 0, "", "direct_call_target")
		if _, mapped := image.functions[target]; !mapped {
			return
		}
		queue = append(queue, target)
		i := nextInferred(target)
		inferred = append(inferred, 0)
		copy(inferred[i+1:], inferred[i:])
		inferred[i] = target
		out.Discovered++
	}
	for out.Scanned < len(queue) && out.Scanned < options.MaxFunctions {
		address := queue[out.Scanned]
		out.Scanned++
		fn := image.functions[address]
		span := min(executableSpan(*image, address), referenceWindow)
		if fn.Size != 0 {
			span = min(span, fn.Size)
		}
		if next := nextStart(address); next < len(starts) {
			span = min(span, starts[next]-address)
		}
		if next := nextInferred(address); next < len(inferred) {
			span = min(span, inferred[next]-address)
		}
		if span == 0 || span > math.MaxUint64-address {
			out.LimitedFunctions++
			continue
		}
		if _, ok := image.fileRange(address, span); !ok {
			span = uint64(sort.Search(int(span), func(i int) bool {
				_, ok := image.fileRange(address, uint64(i+1))
				return !ok
			}))
		}
		data, err := image.readMapped(r, address, uint32(span))
		if err != nil {
			out.LimitedFunctions++
			continue
		}
		instructions, blocks, warnings := recoverFlow(image.Arch, address, data, maxInstructions)
		if len(warnings) > 0 || hasUnresolvedFlow(blocks, image.functions) {
			out.LimitedFunctions++
		}
		blockStarts := make(map[uint64]bool)
		if image.Arch == "arm64" {
			for _, block := range blocks {
				blockStarts[block.Address] = true
			}
		}
		for i, instruction := range instructions {
			if instruction.Kind == "call" && instruction.Target == nil && !seenIndirect[instruction.Address] {
				seenIndirect[instruction.Address] = true
				out.IndirectCalls++
			}
			if target := instruction.Target; target != nil {
				switch instruction.Kind {
				case "call":
					discover(instruction, instructions)
					add(fn, instruction.Address, *target, "call")
				case "jump":
					if _, known := image.functions[*target]; known && *target != address &&
						(*target < address || *target-address >= span) {
						add(fn, instruction.Address, *target, "tail_jump_candidate")
					}
				}
			}
			for _, ref := range instruction.References {
				add(fn, instruction.Address, ref.Address, ref.Kind)
			}
			if image.Arch == "arm64" && i > 0 && !blockStarts[instruction.Address] {
				if target, ok := adjacentArmPageReference(instructions[i-1], instruction); ok {
					add(fn, instruction.Address, target, "pc_relative_address")
				}
			}
		}
	}
	out.Pending = len(queue) - out.Scanned
}

func adjacentArmPageReference(previous, current Instruction) (uint64, bool) {
	if previous.Mnemonic != "adrp" || previous.Address+4 != current.Address ||
		len(previous.References) != 1 || previous.References[0].Kind != "pc_relative_page" {
		return 0, false
	}
	switch current.Mnemonic {
	case "add", "ldr", "str", "ldur", "stur":
	default:
		return 0, false
	}
	page := liftInstruction("arm64", previous)
	if page.Destination == nil || page.Destination.Register == "xzr" {
		return 0, false
	}
	base := page.Destination.Register
	op := liftInstruction("arm64", current)
	var delta uint64
	switch op.Opcode {
	case "add":
		if len(op.Inputs) != 2 || op.Inputs[0].Register != base ||
			op.Inputs[0].Width != 64 || op.Inputs[1].Kind != "immediate" {
			return 0, false
		}
		value, err := strconv.ParseUint(op.Inputs[1].Immediate, 0, 64)
		if err != nil {
			return 0, false
		}
		delta = value
	case "copy":
		if op.Destination == nil || len(op.Inputs) != 1 {
			return 0, false
		}
		mem := op.Destination.Memory
		if mem == nil {
			mem = op.Inputs[0].Memory
		}
		if mem == nil || mem.Base != base || mem.Displacement < 0 {
			return 0, false
		}
		delta = uint64(mem.Displacement)
	default:
		return 0, false
	}
	address := previous.References[0].Address
	if delta > 0xfff || delta > math.MaxUint64-address {
		return 0, false
	}
	return address + delta, true
}

func hasUnresolvedFlow(blocks []Block, known map[uint64]Function) bool {
	for _, block := range blocks {
		for _, edge := range block.Edges {
			if edge.Internal {
				continue
			}
			switch edge.Kind {
			case "conditional", "fallthrough":
				return true
			case "jump":
				if edge.Target == nil {
					return true
				}
				if _, ok := known[*edge.Target]; !ok {
					return true
				}
			}
		}
	}
	return false
}
