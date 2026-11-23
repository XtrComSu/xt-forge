package sysimage

import (
	"encoding/hex"
	"fmt"
	"io"
	"strings"

	"xtforge-hub/internal/thirdparty/xarch/arm64asm"
)

// Operand widths are in bits. Immediate strings preserve the underlying
// bit pattern when the JSON consumer cannot represent 64-bit integers.
type Operand struct {
	Kind      string         `json:"kind"`
	Width     int            `json:"width,omitempty"`
	Register  string         `json:"register,omitempty"`
	Immediate string         `json:"immediate,omitempty"`
	Memory    *MemoryAddress `json:"memory,omitempty"`
	// Scale records a left shift applied to a register operand, as in
	// "add x10, x10, x11, lsl #2". Zero means no shift.
	Scale uint8  `json:"scale,omitempty"`
	Shift string `json:"shift,omitempty"`
}

type MemoryAddress struct {
	Segment      string `json:"segment,omitempty"`
	Base         string `json:"base,omitempty"`
	Index        string `json:"index,omitempty"`
	Scale        uint8  `json:"scale,omitempty"`
	Displacement int64  `json:"displacement,omitempty"`
	Absolute     string `json:"absolute,omitempty"`
}

// Inputs read pre-instruction state. A flag-setting primitive updates
// the architecture's flags together with its destination.
type Operation struct {
	Address           uint64          `json:"address"`
	Opcode            string          `json:"opcode"`
	Destination       *Operand        `json:"destination,omitempty"`
	SecondDestination *Operand        `json:"second_destination,omitempty"`
	Inputs            []Operand       `json:"inputs,omitempty"`
	Flags             string          `json:"flags,omitempty"`
	Condition         string          `json:"condition,omitempty"`
	SelectFalseOp     string          `json:"select_false_op,omitempty"`
	Target            *uint64         `json:"target,omitempty"`
	Fallthrough       *uint64         `json:"fallthrough,omitempty"`
	Raw               string          `json:"raw,omitempty"`
	Writeback         *RegisterUpdate `json:"writeback,omitempty"`
}

type RegisterUpdate struct {
	Register string `json:"register"`
	Base     string `json:"base,omitempty"`
	Delta    int64  `json:"delta"`
}

type IRBlock struct {
	Address    uint64      `json:"address"`
	Operations []Operation `json:"operations"`
	Edges      []Edge      `json:"edges"`
}

type LiftCoverage struct {
	Decoded int `json:"decoded"`
	Lifted  int `json:"lifted"`
	Opaque  int `json:"opaque"`
}

type Decompilation struct {
	OK         bool                `json:"ok"`
	Engine     string              `json:"engine"`
	Path       string              `json:"path"`
	Format     string              `json:"format"`
	Member     string              `json:"member,omitempty"`
	Arch       string              `json:"arch"`
	Address    uint64              `json:"address"`
	Name       string              `json:"name,omitempty"`
	NameSource string              `json:"name_source,omitempty"`
	Coverage   LiftCoverage        `json:"coverage"`
	IR         []IRBlock           `json:"ir"`
	Pseudocode string              `json:"pseudocode"`
	Warnings   []string            `json:"warnings,omitempty"`
	Structured *StructuredFunction `json:"structured,omitempty"`
	// StructuredDeclined explains an absent structured summary.
	StructuredDeclined string `json:"structured_declined,omitempty"`
}

func Decompile(filename string, opts DisassemblyOptions) (Decompilation, error) {
	if err := validateDisassemblyOptions(opts); err != nil {
		return Decompilation{}, err
	}
	opts.Flow = true
	var result Decompilation
	_, err := analyzeFile(filename, opts.Member, true, func(r io.ReaderAt, info OverviewResult) error {
		image, err := selectNativeImage(info.Images, opts.Arch)
		if err != nil {
			return err
		}
		address, err := resolveTarget(*image, opts.Target)
		if err != nil {
			return err
		}
		if opts.Bytes == 0 {
			opts.Bytes = functionWindow(*image, address)
		}
		decoded, err := disassembleImage(r, info, *image, address, opts)
		if err != nil {
			return err
		}
		result = liftDisassembly(decoded, true)
		name := opts.Target
		if strings.HasPrefix(name, "sys_callee_") {
			name = ""
		}
		// Report the function identity the same way the disassembly surface does,
		// so callers do not need the requested target to learn the name.
		if index, indexed := image.functions[address]; indexed && index.Name != "" {
			result.Name, result.NameSource = index.Name, index.Source
		} else if name != "" {
			result.Name = name
		}
		var calleeNotes []string
		resolver := newCalleeResolverWithNotes(r, info, *image, address, &calleeNotes)
		if executableSpan(*image, address) != 0 {
			structured, reason := analyzeStructuredWithReason(decoded.Format, decoded.Arch, name,
				decoded.Address, result.IR, result.Warnings, resolver)
			result.Structured = structured
			if result.Structured != nil {
				result.Structured.emitProgram()
			} else {
				// A decline is a normal outcome for unsupported code. Reporting the
				// reason keeps it distinguishable from an analysis that never ran.
				result.StructuredDeclined = reason
				if len(calleeNotes) > 0 {
					// The analyser only reports "call could not be summarised"; the
					// resolver knows which callee failed and why. Dropping that string is
					// what turned a one-line cause into six rounds of wrong hypotheses.
					result.Warnings = append(result.Warnings,
						"callee "+calleeNotes[0])
				}
			}
			if decoded.Arch == "arm" || decoded.Arch == "arm-thumb" {
				// ARM32 declines are reported with the architecture and the
				// actual reason: nothing lifted is different from an analyser
				// that examined typed instructions and stopped.
				if result.Coverage.Lifted == 0 {
					result.StructuredDeclined = decoded.Arch + ": every decoded ARM32/Thumb " +
						"instruction is opaque; no typed operation was produced"
				} else if result.Structured == nil {
					result.StructuredDeclined = decoded.Arch + ": " + result.StructuredDeclined
				}
			}
		}
		return nil
	})
	return result, err
}

func functionWindow(image Image, address uint64) int {
	span := executableSpan(image, address)
	if span == 0 {
		return 0
	}
	size := image.functions[address].Size
	if size == 0 {
		size = 256
	}
	for next := range image.functions {
		if next > address {
			size = min(size, next-address)
		}
	}
	return int(min(size, span, maxNativeWindow))
}

func newCalleeResolver(r io.ReaderAt, info OverviewResult, image Image, root uint64) func(uint64) *StructuredFunction {
	return newCalleeResolverWithNotes(r, info, image, root, nil)
}

func newCalleeResolverWithNotes(r io.ReaderAt, info OverviewResult, image Image, root uint64, notes *[]string) func(uint64) *StructuredFunction {
	const maxCallees, maxDepth = 24, 8
	answers := map[uint64]*StructuredFunction{root: nil}
	depth := 0
	var resolve func(uint64) *StructuredFunction
	resolve = func(address uint64) *StructuredFunction {
		if known, seen := answers[address]; seen {
			return known
		}
		if len(answers) > maxCallees || depth >= maxDepth {
			return nil
		}
		if _, indexed := image.functions[address]; !indexed {
			return nil
		}
		answers[address] = nil
		window := functionWindow(image, address)
		if window == 0 {
			return nil
		}
		decoded, err := disassembleImage(r, info, image, address, DisassemblyOptions{
			Flow: true, Bytes: window, Count: 200,
		})
		if err != nil {
			return nil
		}
		depth++
		lifted := liftDisassembly(decoded, false)
		answer, reason := analyzeStructuredWithReason(info.Format, image.Arch, calleeName(address), address, lifted.IR, lifted.Warnings, resolve)
		if answer == nil && notes != nil && len(*notes) < 4 {
			*notes = append(*notes, fmt.Sprintf("%#x: %s", address, reason))
		}
		depth--
		answers[address] = answer
		return answer
	}
	return resolve
}

func liftDisassembly(decoded Disassembly, render bool) Decompilation {
	result := Decompilation{
		OK: true, Engine: decoded.Engine, Path: decoded.Path, Format: decoded.Format,
		Member: decoded.Member, Arch: decoded.Arch, Address: decoded.Address,
		Warnings: decoded.Warnings, Coverage: LiftCoverage{Decoded: len(decoded.Instructions)},
	}
	var code strings.Builder
	next := 0
	for _, block := range decoded.Blocks {
		if render {
			fmt.Fprintf(&code, "L_%x:\n", block.Address)
		}
		ir := IRBlock{Address: block.Address, Edges: block.Edges}
		for next < len(decoded.Instructions) && decoded.Instructions[next].Address < block.End {
			op := liftInstruction(decoded.Arch, decoded.Instructions[next])
			ir.Operations = append(ir.Operations, op)
			if op.Opcode == "opaque" {
				result.Coverage.Opaque++
			} else {
				result.Coverage.Lifted++
			}
			if render {
				fmt.Fprintf(&code, "    %s\n", renderOperation(op))
			}
			next++
		}
		// Linear fallthroughs must remain explicit when blocks are printed
		// by address and the destination is absent from this window.
		if last := ir.Operations[len(ir.Operations)-1]; render && last.Opcode != "branch" && last.Opcode != "opaque" {
			for _, edge := range block.Edges {
				if edge.Kind == "fallthrough" {
					fmt.Fprintf(&code, "    goto %s;\n", label(edge.Target))
				}
			}
		}
		result.IR = append(result.IR, ir)
	}
	result.Pseudocode = code.String()
	return result
}

func liftInstruction(arch string, ins Instruction) Operation {
	opaque := Operation{Address: ins.Address, Opcode: "opaque", Raw: ins.Text}
	data, err := hex.DecodeString(ins.Bytes)
	if err != nil {
		return opaque
	}
	op := Operation{Address: ins.Address, Target: ins.Target}
	if arch == "arm" || arch == "arm-thumb" {
		if liftARM32(ins.Text, ins.Mnemonic, arm32OperandTokens(ins.Operands), &op) {
			// Only the decoder knows the instruction width; conditional branches
			// need it to name the instruction that runs when the condition fails.
			if op.Opcode == "branch" && op.Fallthrough == nil {
				op.Fallthrough = relativeAddress(ins.Address, int64(ins.Size))
			}
			return op
		}
		return opaque
	}
	if arch == "arm64" {
		inst, err := arm64asm.Decode(data)
		if err == nil && liftARM(inst, ins, &op) {
			return op
		}
		return opaque
	}
	mode := 32
	if arch == "x86_64" {
		mode = 64
	}
	// CET landing pads are no-ops to the IR as well. Without this they arrive as
	// opaque operations, which reads as a decode failure and inflates the opaque
	// count on every hardened binary. The shadow-stack forms are different: RDSSPQ
	// writes a register and INCSSPQ advances shadow-stack state from one, so
	// pretending they are no-ops would invent an effect. There is no honest IR
	// primitive for either, so keep them opaque with their decoded raw text and
	// let the coverage count report them.
	if text, _, isCET := x86CETInstruction(data); isCET {
		switch text {
		case "endbr64", "endbr32":
			return Operation{Address: ins.Address, Opcode: "nop", Raw: ins.Text}
		default:
			return opaque
		}
	}
	inst, err := safeX86Decode(data, mode)
	if err == nil && liftX86(inst, ins, &op) {
		return op
	}
	return opaque
}

func label(target *uint64) string {
	if target == nil {
		return "indirect_target()"
	}
	return fmt.Sprintf("L_%x", *target)
}

func renderOperation(op Operation) string {
	code := renderEffect(op)
	if op.Writeback != nil {
		base := op.Writeback.Register
		if op.Writeback.Base != "" {
			base = "pre(" + op.Writeback.Base + ")"
		}
		code += fmt.Sprintf(" %s = %s %+d;", op.Writeback.Register, base, op.Writeback.Delta)
	}
	return code
}

func renderEffect(op Operation) string {
	inputs := make([]string, 0, len(op.Inputs))
	for _, arg := range op.Inputs {
		inputs = append(inputs, renderOperand(arg, op.Opcode == "address"))
	}
	joined := strings.Join(inputs, ", ")
	switch op.Opcode {
	case "opaque":
		return fmt.Sprintf("opaque(%#x, %q);", op.Address, op.Raw)
	case "call", "jump":
		target := label(op.Target)
		if op.Target == nil && joined != "" {
			target = joined
		}
		if op.Opcode == "call" {
			return "call(" + target + ");"
		}
		return "goto " + target + ";"
	case "branch":
		return fmt.Sprintf("if (%s(%s)) goto %s; else goto %s;", op.Condition, joined, label(op.Target), label(op.Fallthrough))
	case "return":
		return "return_to_caller(" + joined + ");"
	case "trap":
		return "trap(" + joined + ");"
	case "nop":
		return "nop();"
	case "flags":
		return fmt.Sprintf("flags = %s(%s);", op.Flags, joined)
	}
	if op.Destination == nil {
		return fmt.Sprintf("opaque(%#x);", op.Address)
	}
	dest := renderOperand(*op.Destination, false)
	if op.Opcode == "select" {
		other := inputs[1]
		if op.SelectFalseOp != "" {
			other = fmt.Sprintf("%s%d(%s)", op.SelectFalseOp, op.Destination.Width, other)
		}
		return fmt.Sprintf("%s = %s() ? %s : %s;", dest, op.Condition, inputs[0], other)
	}
	if op.Opcode == "copy_pair" {
		return fmt.Sprintf("parallel_copy(%s, %s, %s);", dest, renderOperand(*op.SecondDestination, false), joined)
	}
	if op.Opcode == "copy" || op.Opcode == "address" {
		return dest + " = " + joined + ";"
	}
	primitive := op.Opcode
	if op.Flags != "" {
		primitive = op.Flags + "_with_flags"
	}
	return fmt.Sprintf("%s = %s%d(%s);", dest, primitive, op.Destination.Width, joined)
}

func renderOperand(arg Operand, addressOnly bool) string {
	switch arg.Kind {
	case "register":
		if arg.Scale != 0 {
			if arg.Shift == "asr" {
				return fmt.Sprintf("asr%d(%s, %d)", arg.Width, arg.Register, arg.Scale)
			}
			shift := "<<"
			if arg.Shift == "lsr" {
				shift = ">>"
			}
			return fmt.Sprintf("(%s %s %d)", arg.Register, shift, arg.Scale)
		}
		return arg.Register
	case "immediate":
		return arg.Immediate
	case "memory":
		m := arg.Memory
		var terms []string
		if m.Absolute != "" {
			terms = append(terms, m.Absolute)
		}
		if m.Base != "" {
			terms = append(terms, m.Base)
		}
		if m.Index != "" {
			terms = append(terms, fmt.Sprintf("%s * %d", m.Index, m.Scale))
		}
		if m.Displacement != 0 || len(terms) == 0 {
			terms = append(terms, fmt.Sprint(m.Displacement))
		}
		value := strings.Join(terms, " + ")
		if m.Segment != "" {
			value = "segment(" + m.Segment + ", " + value + ")"
		}
		if addressOnly {
			return value
		}
		return fmt.Sprintf("mem%d[%s]", arg.Width, value)
	default:
		return "unknown_value()"
	}
}

func register(name string, width int) Operand {
	return Operand{Kind: "register", Register: strings.ToLower(name), Width: width}
}

func immediate(value uint64, width int) Operand {
	if width > 0 && width < 64 {
		value &= (uint64(1) << width) - 1
	}
	return Operand{Kind: "immediate", Immediate: fmt.Sprintf("%#x", value), Width: width}
}
