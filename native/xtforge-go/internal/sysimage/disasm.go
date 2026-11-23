package sysimage

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"math"
	"sort"
	"strconv"
	"strings"

	"xtforge-hub/internal/thirdparty/xarch/arm64asm"
	"xtforge-hub/internal/thirdparty/xarch/x86asm"
)

const (
	maxNativeWindow = 16 << 10
	maxInstructions = 512
)

type DisassemblyOptions struct {
	Member string
	Arch   string
	Target string
	Bytes  int
	Count  int
	Flow   bool
}

type Disassembly struct {
	OK           bool          `json:"ok"`
	Engine       string        `json:"engine"`
	Path         string        `json:"path"`
	Format       string        `json:"format"`
	Member       string        `json:"member,omitempty"`
	Arch         string        `json:"arch"`
	SliceOffset  uint64        `json:"slice_offset,omitempty"`
	Address      uint64        `json:"address"`
	Name         string        `json:"name,omitempty"`
	NameSource   string        `json:"name_source,omitempty"`
	FileOffset   uint64        `json:"file_offset"`
	WindowBytes  int           `json:"window_bytes"`
	Mode         string        `json:"mode"`
	Instructions []Instruction `json:"instructions"`
	Blocks       []Block       `json:"blocks,omitempty"`
	Warnings     []string      `json:"warnings,omitempty"`
}

func Disassemble(filename string, opts DisassemblyOptions) (Disassembly, error) {
	var out Disassembly
	if err := validateDisassemblyOptions(opts); err != nil {
		return out, err
	}
	_, err := analyzeFile(filename, opts.Member, opts.Bytes == 0 || !isAddress(opts.Target), func(r io.ReaderAt, info OverviewResult) error {
		image, err := selectNativeImage(info.Images, opts.Arch)
		if err != nil {
			return err
		}
		address, err := resolveTarget(*image, opts.Target)
		if err != nil {
			return err
		}
		out, err = disassembleImage(r, info, *image, address, opts)
		return err
	})
	return out, err
}

func validateDisassemblyOptions(opts DisassemblyOptions) error {
	if opts.Bytes < 0 || opts.Bytes > maxNativeWindow || opts.Count < 0 || opts.Count > maxInstructions {
		return fmt.Errorf("native disassembly limits are %d bytes and %d instructions", maxNativeWindow, maxInstructions)
	}
	return nil
}

func disassembleImage(r io.ReaderAt, info OverviewResult, image Image, address uint64, opts DisassemblyOptions) (Disassembly, error) {
	window := opts.Bytes
	if window == 0 {
		window = 256
		if fn := image.functions[address]; fn.Size > 0 {
			window = int(min(fn.Size, maxNativeWindow))
		}
	}
	count := opts.Count
	if count == 0 {
		count = 200
	}
	// Find the largest safe prefix if the requested window crosses the
	// end of its contiguous mapping.
	valid := sort.Search(window, func(i int) bool {
		_, ok := image.fileRange(address, uint64(i+1))
		return !ok
	})
	if valid == 0 {
		return Disassembly{}, fmt.Errorf("address %#x has no unambiguous file mapping", address)
	}
	if uint64(valid) > math.MaxUint64-address {
		return Disassembly{}, fmt.Errorf("address window exceeds virtual address range")
	}
	slice := io.NewSectionReader(r, int64(image.SliceOffset), int64(image.fileSize))
	data, err := image.readMapped(slice, address, uint32(valid))
	if err != nil {
		return Disassembly{}, err
	}
	offset, _ := image.fileOffset(address)
	out := Disassembly{
		OK: true, Engine: info.Engine, Path: info.Path, Format: info.Format, Member: info.Member,
		Arch: image.Arch, SliceOffset: image.SliceOffset, Address: address, FileOffset: offset,
		WindowBytes: valid, Mode: "linear",
	}
	if index, indexed := image.functions[address]; indexed && index.Name != "" {
		out.Name, out.NameSource = index.Name, index.Source
	}
	// A 32-bit ARM image may be Thumb, and the two are different instruction sets over
	// the same bytes. The mode comes from the image, never guessed per instruction: an
	// odd entry point is the ARM convention for "the code is Thumb".
	decodeArch := image.Arch
	if image.Arch == "arm" && image.Mode == "thumb" {
		decodeArch = "arm-thumb"
	}
	if opts.Flow {
		out.Mode = "flow"
		out.Instructions, out.Blocks, out.Warnings = recoverFlow(decodeArch, address, data, count)
	} else {
		out.Instructions, out.Warnings = linearDecode(decodeArch, address, data, count)
	}
	if len(out.Instructions) == 0 {
		return Disassembly{}, fmt.Errorf("no instructions decoded at %#x: %s", address, strings.Join(out.Warnings, "; "))
	}
	if valid < window {
		out.Warnings = append(out.Warnings, "window clipped to the contiguous file mapping")
	}
	return out, nil
}

func selectNativeImage(images []Image, arch string) (*Image, error) {
	var image *Image
	for i := range images {
		if arch != "" && !strings.EqualFold(images[i].Arch, arch) {
			continue
		}
		if image != nil {
			return nil, fmt.Errorf("more than one matching slice; specify an unambiguous --arch")
		}
		image = &images[i]
	}
	if image == nil {
		return nil, fmt.Errorf("no image with architecture %q", arch)
	}
	if !image.littleEndian || (image.Arch != "x86" && image.Arch != "x86_64" && image.Arch != "arm" && image.Arch != "arm64") {
		return nil, fmt.Errorf("native decoding supports little-endian x86, x86-64, arm, and arm64 images")
	}
	return image, nil
}

func isAddress(target string) bool {
	_, err := parseAddress(target)
	return err == nil
}

func parseAddress(target string) (uint64, error) {
	if strings.HasPrefix(strings.ToLower(target), "0x") {
		return strconv.ParseUint(target[2:], 16, 64)
	}
	return strconv.ParseUint(target, 10, 64)
}

func resolveTarget(image Image, target string) (uint64, error) {
	if address, err := parseAddress(target); err == nil {
		return address, nil
	}
	if target == "" || target == "entry" {
		if image.EntryPoint == nil {
			return 0, fmt.Errorf("image has no entry point; specify a function name or preferred address")
		}
		return *image.EntryPoint, nil
	}
	var match *uint64
	for _, fn := range image.functions {
		if fn.Name != target {
			continue
		}
		if match != nil {
			return 0, fmt.Errorf("function name %q is ambiguous; use its address", target)
		}
		address := fn.Address
		match = &address
	}
	if match == nil {
		return 0, fmt.Errorf("function %q was not found in this image", target)
	}
	return *match, nil
}

func linearDecode(arch string, address uint64, data []byte, limit int) ([]Instruction, []string) {
	var instructions []Instruction
	offset := 0
	for offset < len(data) && len(instructions) < limit {
		pc := address + uint64(offset)
		inst, err := decodeInstruction(arch, pc, data[offset:])
		if err != nil {
			return instructions, []string{fmt.Sprintf("decode at %#x: %v", pc, err)}
		}
		instructions = append(instructions, inst)
		offset += inst.Size
	}
	if offset < len(data) {
		return instructions, []string{"instruction limit reached"}
	}
	return instructions, nil
}

type Instruction struct {
	Address    uint64      `json:"address"`
	Size       int         `json:"size"`
	Bytes      string      `json:"bytes"`
	Text       string      `json:"text"`
	Mnemonic   string      `json:"mnemonic"`
	Operands   string      `json:"operands,omitempty"`
	Kind       string      `json:"kind,omitempty"`
	Target     *uint64     `json:"target,omitempty"`
	References []Reference `json:"references,omitempty"`
}

type Reference struct {
	Address uint64 `json:"address"`
	Kind    string `json:"kind"`
}

type Block struct {
	Address uint64 `json:"address"`
	End     uint64 `json:"end"`
	Edges   []Edge `json:"edges"`
}

type Edge struct {
	From     uint64  `json:"from"`
	Target   *uint64 `json:"target,omitempty"`
	Kind     string  `json:"kind"`
	Internal bool    `json:"internal"`
}

func relativeAddress(base uint64, delta int64) *uint64 {
	if delta >= 0 && uint64(delta) <= math.MaxUint64-base {
		address := base + uint64(delta)
		return &address
	}
	if delta < 0 {
		distance := uint64(-(delta + 1)) + 1
		if distance <= base {
			address := base - distance
			return &address
		}
	}
	return nil
}

// safeX86Decode calls x86asm.Decode, converting a panic into an error.
//
// The vendored decoder panics on some malformed or truncated prefixes: an EVEX (0x62)
// sequence indexes inst.Prefix past its length, which crashed the whole process with
// "index out of range [4] with length 4" while scanning a real 81 MB binary. A decoder
// that aborts the tool on one bad byte sequence is worse than one that reports it, and
// the recovery is scoped to this call so a genuine bug elsewhere is not swallowed
// silently — it becomes a decode error naming the bytes.
func safeX86Decode(data []byte, mode int) (inst x86asm.Inst, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("x86 decoder panic on %x: %v", firstBytes(data, 8), recovered)
		}
	}()
	return x86asm.Decode(data, mode)
}

// firstBytes returns at most n bytes for an error message.
func firstBytes(data []byte, n int) []byte {
	if len(data) < n {
		return data
	}
	return data[:n]
}

// x86CETForm describes one CET encoding x86asm does not decode.
//
// pattern holds the bytes before ModRM. rexAt marks a REX.W slot (0x48..0x4f):
// its B bit extends the register number in ModRM.rm. regExt is the required
// ModRM.reg opcode extension, or -1 when the form has no ModRM byte at all.
type x86CETForm struct {
	text    string
	pattern []byte
	rexAt   int
	regExt  int
}

// x86CETRegisters uses the same 64-bit GPR names x86asm's Intel syntax produces,
// lowercased as elsewhere in this package. ModRM.rm plus REX.B indexes this table.
var x86CETRegisters = [16]string{
	"rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
	"r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
}

var x86CETForms = []x86CETForm{
	// F3 0F 1E FA/FB are the four-byte landing pads. They are no-ops on
	// processors without CET, and have no ModRM byte.
	{text: "endbr64", pattern: []byte{0xF3, 0x0F, 0x1E, 0xFA}, rexAt: -1, regExt: -1},
	{text: "endbr32", pattern: []byte{0xF3, 0x0F, 0x1E, 0xFB}, rexAt: -1, regExt: -1},
	// F3 REX.W 0F 1E /1 and F3 REX.W 0F AE /5 are five-byte register forms:
	// ModRM.mod must be 11 and ModRM.rm names the destination register.
	{text: "rdsspq", pattern: []byte{0xF3, 0x48, 0x0F, 0x1E}, rexAt: 1, regExt: 1},
	{text: "incsspq", pattern: []byte{0xF3, 0x48, 0x0F, 0xAE}, rexAt: 1, regExt: 5},
}

// x86CETInstruction recognises the CET encodings in x86CETForms. Anything else
// in the 0F 1E / 0F AE space is left to x86asm rather than given a guessed length.
func x86CETInstruction(data []byte) (text string, size int, ok bool) {
	for _, form := range x86CETForms {
		if len(data) < len(form.pattern) {
			continue
		}
		var rex byte
		matched := true
		for i, want := range form.pattern {
			if i == form.rexAt {
				if data[i]&0xf8 != 0x48 { // REX prefix with W=1, any B/R/X
					matched = false
					break
				}
				rex = data[i]
				continue
			}
			if data[i] != want {
				matched = false
				break
			}
		}
		if !matched {
			continue
		}
		size = len(form.pattern)
		if form.regExt >= 0 {
			if len(data) <= size {
				continue
			}
			modrm := data[size]
			if modrm>>6 != 3 || int((modrm>>3)&7) != form.regExt {
				continue
			}
			size++
			reg := int(modrm & 7)
			if rex&1 != 0 { // REX.B extends ModRM.rm to r8..r15
				reg += 8
			}
			return fmt.Sprintf("%s %s", form.text, x86CETRegisters[reg]), size, true
		}
		return form.text, size, true
	}
	return "", 0, false
}

func decodeInstruction(arch string, address uint64, data []byte) (Instruction, error) {
	ins := Instruction{Address: address}
	switch arch {
	case "x86", "x86_64":
		mode := 32
		if arch == "x86_64" {
			mode = 64
		}
		// CET instructions are decoded here because x86asm reports Op(0) with Len 1
		// for them, which the validity check below would reject. Debian and Ubuntu
		// build with -fcf-protection by default, so without this the FIRST instruction
		// of most functions fails and disassembly stops immediately — measured on a
		// plain system binary compiled here. The shadow-stack register forms are
		// control-flow no-ops too, so the same Kind is correct for the whole group.
		if padding, size, ok := x86CETInstruction(data); ok {
			ins.Size, ins.Text, ins.Mnemonic, ins.Kind = size, padding, padding, "nop"
			// The common tail that fills Bytes is skipped by this early return, and the
			// lifter needs the encoding to re-decode the instruction.
			ins.Bytes = hex.EncodeToString(data[:size])
			return ins, nil
		}
		inst, err := safeX86Decode(data, mode)
		if err != nil {
			return ins, err
		}
		if inst.Len <= 0 || inst.Len > len(data) || inst.Op == 0 {
			return ins, fmt.Errorf("invalid x86 instruction")
		}
		ins.Size, ins.Text = inst.Len, x86asm.IntelSyntax(inst, address, nil)
		ins.Mnemonic = strings.ToLower(inst.Op.String())
		switch ins.Mnemonic {
		case "call", "lcall":
			ins.Kind = "call"
		case "jmp", "ljmp":
			ins.Kind = "jump"
		case "ret", "lret", "iret", "iretd", "iretq":
			ins.Kind = "return"
		case "ud2", "int3", "hlt":
			ins.Kind = "trap"
		default:
			if strings.HasPrefix(ins.Mnemonic, "j") || strings.HasPrefix(ins.Mnemonic, "loop") {
				ins.Kind = "conditional"
			}
		}
		if next := relativeAddress(address, int64(inst.Len)); next != nil {
			for _, arg := range inst.Args {
				switch value := arg.(type) {
				case x86asm.Rel:
					if ins.Kind == "call" || ins.Kind == "jump" || ins.Kind == "conditional" {
						ins.Target = relativeAddress(*next, int64(value))
					}
				case x86asm.Mem:
					if value.Base == x86asm.RIP {
						// A RIP-relative displacement is a signed 32-bit field, but the
						// decoder reports Mem.Disp unsigned: `leaq -0x3f(%rip)` arrives as
						// 4294967233 and produced a target of 0x100001070 instead of 0x1070.
						// Every backwards reference in a 64-bit binary was wrong by 2^32.
						// x86asm.Rel is already signed, which is why branch targets were
						// fine and only memory operands suffered.
						if ref := relativeAddress(*next, int64(int32(uint32(value.Disp)))); ref != nil {
							ins.References = append(ins.References, Reference{*ref, "pc_relative"})
						}
					}
				}
			}
		}
	case "arm":
		if address%4 != 0 {
			return ins, fmt.Errorf("unaligned arm instruction")
		}
		if len(data) < 4 {
			return ins, fmt.Errorf("truncated arm instruction")
		}
		word := binary.LittleEndian.Uint32(data)
		decoded, ok := decodeARM32(word, address)
		if !ok {
			return ins, fmt.Errorf("unsupported ARM32 instruction word %#08x at %#x", word, address)
		}
		ins = decoded
	case "arm-thumb", "thumb":
		// Thumb instructions are halfword-aligned; a 32-bit form is only
		// decoded when all four bytes are available.
		decoded, length, ok := decodeThumb(data, address)
		if !ok {
			return ins, fmt.Errorf("unsupported Thumb instruction at %#x", address)
		}
		ins = decoded
		if ins.Size != length || ins.Size < 2 || ins.Size > len(data) {
			return ins, fmt.Errorf("invalid Thumb instruction length at %#x", address)
		}
	case "arm64":
		if address%4 != 0 {
			return ins, fmt.Errorf("unaligned arm64 instruction")
		}
		inst, err := arm64asm.Decode(data)
		if err != nil {
			return ins, err
		}
		ins.Size, ins.Text = 4, arm64asm.GNUSyntax(inst)
		ins.Mnemonic = strings.ToLower(inst.Op.String())
		switch ins.Mnemonic {
		case "bl", "blr":
			ins.Kind = "call"
		case "b":
			ins.Kind = "jump"
			if inst.Enc&0xff000010 == 0x54000000 {
				ins.Kind = "conditional"
			}
		case "br":
			ins.Kind = "jump"
		case "cbz", "cbnz", "tbz", "tbnz":
			ins.Kind = "conditional"
		case "ret", "eret":
			ins.Kind = "return"
		case "brk", "hlt", "udf":
			ins.Kind = "trap"
		}
		for _, arg := range inst.Args {
			if delta, ok := arg.(arm64asm.PCRel); ok {
				base := address
				kind := "pc_relative"
				if ins.Mnemonic == "adrp" {
					base &= ^uint64(4095)
					kind = "pc_relative_page"
				}
				if ref := relativeAddress(base, int64(delta)); ref != nil {
					if ins.Kind == "call" || ins.Kind == "jump" || ins.Kind == "conditional" {
						ins.Target = ref
					} else {
						ins.References = append(ins.References, Reference{*ref, kind})
					}
				}
			}
		}
	default:
		return ins, fmt.Errorf("unsupported instruction architecture %q", arch)
	}
	if ins.Operands == "" {
		ins.Operands = instructionOperands(ins.Text)
	}
	ins.Bytes = hex.EncodeToString(data[:ins.Size])
	return ins, nil
}

func instructionOperands(text string) string {
	if i := strings.IndexByte(text, ' '); i >= 0 {
		return text[i+1:]
	}
	return ""
}

func recoverFlow(arch string, address uint64, data []byte, limit int) ([]Instruction, []Block, []string) {
	decoded := make(map[uint64]Instruction)
	used := make([]bool, len(data))
	work := []uint64{address}
	leaders := map[uint64]bool{address: true}
	var warnings []string
	enqueue := func(target *uint64) {
		if target != nil && *target >= address && *target-address < uint64(len(data)) && !leaders[*target] {
			leaders[*target] = true
			work = append(work, *target)
		}
	}
	for i := 0; i < len(work) && len(decoded) < limit; i++ {
		for pc := work[i]; pc >= address && pc-address < uint64(len(data)) && len(decoded) < limit; {
			off := int(pc - address)
			if _, exists := decoded[pc]; exists {
				break
			}
			if used[off] {
				warnings = append(warnings, fmt.Sprintf("branch enters the interior of an instruction at %#x", pc))
				break
			}
			inst, err := decodeInstruction(arch, pc, data[off:])
			if err != nil {
				warnings = append(warnings, fmt.Sprintf("decode at %#x: %v", pc, err))
				break
			}
			overlap := false
			for _, occupied := range used[off : off+inst.Size] {
				overlap = overlap || occupied
			}
			if overlap {
				warnings = append(warnings, fmt.Sprintf("instruction at %#x overlaps a decoded instruction", pc))
				break
			}
			decoded[pc] = inst
			for i := off; i < off+inst.Size; i++ {
				used[i] = true
			}
			next := pc + uint64(inst.Size)
			switch inst.Kind {
			case "conditional":
				enqueue(&next)
				enqueue(inst.Target)
			case "jump":
				enqueue(inst.Target)
			}
			if isTerminator(inst.Kind) {
				break
			}
			pc = next
		}
	}
	if len(decoded) >= limit {
		warnings = append(warnings, "instruction limit reached")
	}
	instructions := make([]Instruction, 0, len(decoded))
	for _, inst := range decoded {
		instructions = append(instructions, inst)
	}
	sort.Slice(instructions, func(i, j int) bool { return instructions[i].Address < instructions[j].Address })
	blocks := makeBlocks(instructions, leaders, decoded)
	return instructions, blocks, warnings
}

func isTerminator(kind string) bool {
	return kind == "jump" || kind == "conditional" || kind == "return" || kind == "trap"
}

func makeBlocks(instructions []Instruction, leaders map[uint64]bool, decoded map[uint64]Instruction) []Block {
	blocks := make([]Block, 0)
	var block Block
	edge := func(from uint64, kind string, target *uint64) Edge {
		internal := false
		if target != nil {
			_, internal = decoded[*target]
		}
		return Edge{From: from, Kind: kind, Target: target, Internal: internal}
	}
	for i, inst := range instructions {
		if i == 0 || leaders[inst.Address] || block.End != inst.Address {
			block = Block{Address: inst.Address, Edges: []Edge{}}
		}
		end := inst.Address + uint64(inst.Size)
		block.End = end
		switch inst.Kind {
		case "call", "jump", "conditional":
			block.Edges = append(block.Edges, edge(inst.Address, inst.Kind, inst.Target))
		}
		last := i+1 == len(instructions) || instructions[i+1].Address != end || leaders[end] || isTerminator(inst.Kind)
		if last {
			if inst.Kind == "conditional" || !isTerminator(inst.Kind) {
				block.Edges = append(block.Edges, edge(inst.Address, "fallthrough", &end))
			}
			blocks = append(blocks, block)
		}
	}
	return blocks
}
