package sysimage

import (
	"fmt"
	"sort"
	"strings"
)

type StructuredParameter struct {
	Index    int    `json:"index"`
	Register string `json:"register"`
	Width    int    `json:"width"`
}

type StructuredFunction struct {
	ABI          string                 `json:"abi"`
	Parameters   []StructuredParameter  `json:"parameters"`
	ReturnWidth  int                    `json:"return_width"`
	Pseudocode   string                 `json:"pseudocode"`
	Dependencies []StructuredDependency `json:"dependencies,omitempty"`
	definition   string
	calls        map[uint64]*StructuredFunction
}

type StructuredDependency struct {
	Address uint64 `json:"address"`
	Name    string `json:"name"`
}

type callingConvention struct {
	name, stack, result string
	parameters, saved   []string
	redZone, homeBytes  int64
}

// isARM32 covers the two names the disassembler uses for A32 and Thumb code.
func isARM32(arch string) bool {
	return arch == "arm" || arch == "arm-thumb"
}

func nativeABI(format, arch string) (callingConvention, bool) {
	switch {
	case arch == "x86_64" && format == "pe":
		return callingConvention{
			name: "windows_x64", stack: "rsp", result: "rax", homeBytes: 32,
			parameters: []string{"rcx", "rdx", "r8", "r9"},
			saved:      []string{"rbx", "rbp", "rdi", "rsi", "r12", "r13", "r14", "r15"},
		}, true
	case arch == "x86_64" && (format == "elf" || format == "macho"):
		return callingConvention{
			name: "sysv_amd64", stack: "rsp", result: "rax", redZone: 128,
			parameters: []string{"rdi", "rsi", "rdx", "rcx", "r8", "r9"},
			saved:      []string{"rbx", "rbp", "r12", "r13", "r14", "r15"},
		}, true
	case arch == "arm64" && (format == "elf" || format == "macho" || format == "ipa" || format == "pe"):
		return callingConvention{
			name: "aapcs64_integer", stack: "sp", result: "x0",
			parameters: []string{"x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"},
			saved:      []string{"x18", "x19", "x20", "x21", "x22", "x23", "x24", "x25", "x26", "x27", "x28", "x29", "x30"},
		}, true
	case (arch == "arm" || arch == "arm-thumb") && (format == "elf" || format == "pe"):
		// AAPCS32 keeps r4-r11 across calls. r12 (ip) is the intra-procedure
		// scratch, and lr is the link register; both occupy the same place in
		// this table as x18 and x30 do for AAPCS64.
		return callingConvention{
			name: "aapcs32_integer", stack: "sp", result: "r0",
			parameters: []string{"r0", "r1", "r2", "r3"},
			saved:      []string{"r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "r12", "lr"},
		}, true
	default:
		return callingConvention{}, false
	}
}

type summaryNode struct {
	result    symbolicValue
	predicate string
	yes, no   *summaryNode
}

type structuredAnalysis struct {
	abi          callingConvention
	arch         string
	blocks       map[uint64]IRBlock
	active       map[uint64]bool
	parameterUse []int
	promote      []bool
	remaining    int
	returnWidth  int
	resolve      func(uint64) *StructuredFunction
	callees      map[uint64]*StructuredFunction
	// decline records why a function could not be summarised, so callers get a
	// reason instead of an unexplained absence of structured output.
	decline string
}

func analyzeStructured(format, arch, name string, entry uint64, blocks []IRBlock, warnings []string,
	resolve func(uint64) *StructuredFunction) *StructuredFunction {
	fn, _ := analyzeStructuredWithReason(format, arch, name, entry, blocks, warnings, resolve)
	return fn
}

// structuredDecline explains, for the most recent analyzeStructured call in this
// request, why no structured summary was produced.
func analyzeStructuredWithReason(format, arch, name string, entry uint64, blocks []IRBlock,
	warnings []string, resolve func(uint64) *StructuredFunction) (*StructuredFunction, string) {
	return analyzeStructuredWithWidths(format, arch, name, entry, blocks, warnings, resolve, nil)
}

func analyzeStructuredWithWidths(format, arch, name string, entry uint64, blocks []IRBlock,
	warnings []string, resolve func(uint64) *StructuredFunction, widths []int) (*StructuredFunction, string) {
	abi, ok := nativeABI(format, arch)
	if !ok {
		return nil, "no calling convention is modelled for this format and architecture"
	}
	if len(warnings) != 0 {
		return nil, "disassembly reported warnings: " + strings.Join(warnings, "; ")
	}
	if len(blocks) == 0 {
		return nil, "no basic blocks were recovered"
	}
	a := structuredAnalysis{
		abi: abi, arch: arch, blocks: make(map[uint64]IRBlock, len(blocks)),
		active: make(map[uint64]bool), remaining: 256, parameterUse: make([]int, len(abi.parameters)),
		promote: make([]bool, len(abi.parameters)),
		resolve: resolve, callees: make(map[uint64]*StructuredFunction),
	}
	copy(a.parameterUse, widths)
	for _, block := range blocks {
		a.blocks[block.Address] = block
	}
	state := symbolicState{
		registers: map[string]symbolicValue{abi.stack: {width: 64, stack: true}},
		slots:     make(map[int64]symbolicValue),
	}
	var result *summaryNode
	var statements []statement
	if a.reachesCycle(entry) {
		// A loop cannot be expressed by the expression tree, so it is summarised
		// as statements instead.
		loopStatements, _ := a.summariseLoops(entry, state)
		statements = loopStatements
	} else {
		result = a.walk(entry, state, 0)
	}
	if result == nil && len(statements) == 0 {
		next := append([]int(nil), widths...)
		if len(next) == 0 {
			next = make([]int, len(abi.parameters))
		}
		for i, promote := range a.promote {
			if promote && next[i] != 64 {
				next[i] = 64
				return analyzeStructuredWithWidths(format, arch, name, entry, blocks, warnings, resolve, next)
			}
		}
		reason := a.decline
		if reason == "" {
			reason = "the function could not be summarised as a single expression"
		}
		return nil, reason
	}
	if !validCName(name) || name == "entry" {
		name = fmt.Sprintf("sub_%x", entry)
	}
	params := make([]StructuredParameter, 0)
	var declarations []string
	last := -1
	for i, width := range a.parameterUse {
		if width != 0 {
			last = i
		}
	}
	for i := 0; i <= last; i++ {
		width := a.parameterUse[i]
		params = append(params, StructuredParameter{i, abi.parameters[i], width})
		if width == 0 {
			declarations = append(declarations, fmt.Sprintf("uintptr_t arg%d", i))
		} else {
			declarations = append(declarations, fmt.Sprintf("uint%d_t arg%d", width, i))
		}
	}
	if len(declarations) == 0 {
		declarations = []string{"void"}
	}
	var code strings.Builder
	fmt.Fprintf(&code, "uint%d_t %s(%s) {\n", a.returnWidth, name, strings.Join(declarations, ", "))
	if len(statements) != 0 {
		renderStatements(&code, statements, "    ")
	} else {
		renderSummary(&code, result, "    ")
	}
	code.WriteString("}\n")
	return &StructuredFunction{
		ABI: abi.name, Parameters: params, ReturnWidth: a.returnWidth,
		Pseudocode: code.String(), definition: code.String(), calls: a.callees,
	}, ""
}

// declineHere records the first reason a function could not be summarised; a
// nested traversal can fail for several reasons but the first is the one the
// caller needs.
func (a *structuredAnalysis) declineHere(reason string) {
	if a.decline == "" {
		a.decline = reason
	}
}

// reachesCycle reports whether the block graph reachable from entry contains a
// cycle.
func (a *structuredAnalysis) reachesCycle(entry uint64) bool {
	const (
		unvisited = 0
		onStack   = 1
		finished  = 2
	)
	state := make(map[uint64]int, len(a.blocks))
	var visit func(address uint64) bool
	visit = func(address uint64) bool {
		switch state[address] {
		case onStack:
			return true
		case finished:
			return false
		}
		block, ok := a.blocks[address]
		if !ok {
			return false
		}
		state[address] = onStack
		for _, edge := range block.Edges {
			// A call edge is not a control-flow successor, so recursion must not
			// make an acyclic function look like a loop.
			if edge.Target != nil && edge.Kind != "call" && visit(*edge.Target) {
				return true
			}
		}
		state[address] = finished
		return false
	}
	return visit(entry)
}

func calleeName(address uint64) string {
	return fmt.Sprintf("sys_callee_%x", address)
}

func (fn *StructuredFunction) emitProgram() {
	if len(fn.calls) == 0 {
		return
	}
	var program strings.Builder
	seen := make(map[uint64]bool)
	var emit func(map[uint64]*StructuredFunction)
	emit = func(calls map[uint64]*StructuredFunction) {
		addresses := make([]uint64, 0, len(calls))
		for address := range calls {
			addresses = append(addresses, address)
		}
		sort.Slice(addresses, func(i, j int) bool { return addresses[i] < addresses[j] })
		for _, address := range addresses {
			if seen[address] {
				continue
			}
			seen[address] = true
			child := calls[address]
			emit(child.calls)
			program.WriteString("static " + child.definition + "\n")
			fn.Dependencies = append(fn.Dependencies, StructuredDependency{address, calleeName(address)})
		}
	}
	emit(fn.calls)
	program.WriteString(fn.definition)
	fn.Pseudocode = program.String()
}

func (a *structuredAnalysis) walk(address uint64, state symbolicState, depth int) *summaryNode {
	block, exists := a.blocks[address]
	if !exists || a.active[address] || depth >= 32 {
		// A block that is already being summarised is a back edge: the function
		// loops, and a single pass cannot state its effect.
		if exists && a.active[address] {
			a.declineHere("function contains a loop; loop summarisation is not implemented")
		}
		return nil
	}
	a.active[address] = true
	defer delete(a.active, address)
	for _, op := range block.Operations {
		if a.remaining == 0 {
			a.declineHere("analysis budget exhausted")
			return nil
		}
		a.remaining--
		if isARM32(a.arch) && op.Opcode != "branch" && op.Condition != "" && op.Condition != "arm.al" {
			// An ARM conditional instruction is not an unconditional operation
			// with the same mnemonic. Applying it would invent a result for the
			// path where the condition is false.
			a.declineHere(fmt.Sprintf("conditional instruction %q at %#x is not modelled", op.Condition, op.Address))
			return nil
		}
		switch op.Opcode {
		case "return":
			if !a.validReturn(state, op) {
				a.declineHere("returns through a stack frame the analysis cannot account for")
				return nil
			}
			return a.returnValue(state.registers[a.abi.result])
		case "trap":
			// A `svc` (or int3/ud2) call returns to the caller unless it is a known exit,
			// and the encoding does not say which. Ending the body here without claiming a
			// value makes a stub like `void trap(void){ svc }` summarise as a void callee,
			// so its callers stop declining. Claiming a return *value* would be a guess.
			if !a.validReturn(state, Operation{}) {
				a.declineHere("traps through a stack frame the analysis cannot account for")
				return nil
			}
			// No return value is claimed: the encoding does not say whether this
			// supervisor call returns or exits, and inventing one would be a guess.
			return &summaryNode{}
		case "branch":
			predicate := a.predicate(state, op)
			if predicate == "" || op.Target == nil || op.Fallthrough == nil {
				a.declineHere("branch condition is not a comparably known expression")
				return nil
			}
			yes := a.walk(*op.Target, state.clone(), depth+1)
			no := a.walk(*op.Fallthrough, state, depth+1)
			if yes == nil || no == nil {
				return nil
			}
			return &summaryNode{predicate: predicate, yes: yes, no: no}
		case "jump":
			if op.Target == nil {
				return nil
			}
			if _, local := a.blocks[*op.Target]; local {
				return a.walk(*op.Target, state, depth+1)
			}
			if !a.validReturn(state, Operation{}) {
				return nil
			}
			return a.returnValue(a.callValue(state, *op.Target))
		case "call":
			if !a.applyCall(&state, op) {
				a.declineHere("call could not be summarised under the calling convention")
				return nil
			}
		default:
			if isARM32(a.arch) && arm32ReturnsThroughPC(op) {
				// A32 and Thumb commonly return with `pop {r4, pc}` rather than
				// `bx lr`. The copy restores the frame and ends the function;
				// treating it as an ordinary register write loses the return.
				if !a.apply(&state, op) {
					a.declineHere(fmt.Sprintf("unsupported operation %q at %#x", op.Opcode, op.Address))
					return nil
				}
				if !a.validReturnWithoutLink(state) {
					a.declineHere("returns through a stack frame the analysis cannot account for")
					return nil
				}
				value := a.returnValue(state.registers[a.abi.result])
				if value == nil {
					a.declineHere("return value in r0 is not a recoverable expression")
				}
				return value
			}
			if !a.apply(&state, op) {
				a.declineHere(fmt.Sprintf("unsupported operation %q at %#x", op.Opcode, op.Address))
				return nil
			}
		}
	}
	if len(block.Edges) == 1 && block.Edges[0].Kind == "fallthrough" && block.Edges[0].Target != nil {
		return a.walk(*block.Edges[0].Target, state, depth+1)
	}
	return nil
}

func (a *structuredAnalysis) returnValue(value symbolicValue) *summaryNode {
	if value.text == "" || value.width < 32 || (a.returnWidth != 0 && a.returnWidth != value.width) {
		return nil
	}
	a.returnWidth = value.width
	return &summaryNode{result: value}
}

func (a *structuredAnalysis) validReturn(state symbolicState, op Operation) bool {
	return a.validReturnCheckingLink(state, op, true)
}

// validReturnWithoutLink checks a return through pc: the saved link value was
// loaded into pc from the frame, so lr itself need no longer hold it.
func (a *structuredAnalysis) validReturnWithoutLink(state symbolicState) bool {
	return a.validReturnCheckingLink(state, Operation{}, false)
}

func (a *structuredAnalysis) validReturnCheckingLink(state symbolicState, op Operation, checkLink bool) bool {
	sp := state.registers[a.abi.stack]
	if !sp.stack || sp.offset != 0 {
		return false
	}
	for _, saved := range a.abi.saved {
		key := canonicalRegister(saved)
		// A return through pc consumed the link value saved in the frame, so
		// lr itself need not still hold the incoming value on that path.
		if key == "x30" && !checkLink {
			continue
		}
		if value, written := state.registers[key]; written && value.origin != key {
			return false
		}
	}
	if a.arch == "arm64" || isARM32(a.arch) {
		return len(op.Inputs) == 0 ||
			(len(op.Inputs) == 1 && canonicalRegister(op.Inputs[0].Register) == "x30")
	}
	return len(op.Inputs) == 0
}

// arm32ReturnsThroughPC recognises the two A32/Thumb epilogues whose final
// write loads pc: `pop {r4, pc}` (also `pop {pc}`) is a copy from the stack
// with a positive sp writeback. An ordinary write to pc is a computed jump,
// not a return, and is left to the normal (declining) path.
func arm32ReturnsThroughPC(op Operation) bool {
	if op.Writeback == nil || canonicalRegister(op.Writeback.Register) != "sp" ||
		op.Writeback.Delta <= 0 {
		return false
	}
	dest := op.Destination
	if dest == nil || canonicalRegister(dest.Register) != "pc" {
		dest = op.SecondDestination
	}
	if dest == nil || canonicalRegister(dest.Register) != "pc" {
		return false
	}
	if len(op.Inputs) == 0 {
		return false
	}
	for _, input := range op.Inputs {
		if input.Kind != "memory" || input.Memory == nil ||
			canonicalRegister(input.Memory.Base) != "sp" {
			return false
		}
	}
	return true
}

func (a *structuredAnalysis) callValue(state symbolicState, target uint64) symbolicValue {
	if a.resolve == nil {
		return symbolicValue{}
	}
	callee := a.resolve(target)
	if callee == nil || callee.ABI != a.abi.name {
		return symbolicValue{}
	}
	args := make([]string, 0, len(callee.Parameters))
	for _, parameter := range callee.Parameters {
		if parameter.Width == 0 {
			args = append(args, "0")
			continue
		}
		value := a.read(state, register(parameter.Register, parameter.Width))
		if value.text == "" {
			return symbolicValue{}
		}
		args = append(args, typedTerm(value))
	}
	call := calleeName(target) + "(" + strings.Join(args, ", ") + ")"
	if len(call) > 480 {
		return symbolicValue{}
	}
	a.callees[target] = callee
	return symbolicValue{text: call, width: callee.ReturnWidth}
}

func (a *structuredAnalysis) applyCall(state *symbolicState, op Operation) bool {
	sp := state.registers[a.abi.stack]
	if op.Target == nil || !sp.stack ||
		(a.arch == "arm64" && sp.offset%16 != 0) ||
		(a.abi.homeBytes != 0 && (sp.offset+a.abi.homeBytes > 0 || (8+sp.offset)%16 != 0)) {
		return false
	}
	// Direct SysV callees may use compiler-relaxed alignment. The resolver
	// only accepts scalar operations and private stack access, so it cannot
	// hide a callee instruction that requires aligned memory.
	value := a.callValue(*state, *op.Target)
	if value.text == "" {
		return false
	}
	saved := map[string]bool{a.abi.stack: true}
	for _, reg := range a.abi.saved {
		key := canonicalRegister(reg)
		// AAPCS32 names the link register "lr", which canonicalises to x30
		// just like AAPCS64's link register. Both are volatile across calls.
		if key != "x30" {
			saved[key] = true
		}
	}
	for reg := range state.registers {
		if !saved[reg] {
			state.registers[reg] = symbolicValue{}
		}
	}
	for _, reg := range a.abi.parameters {
		state.registers[reg] = symbolicValue{}
	}
	if a.arch == "arm64" || isARM32(a.arch) {
		state.registers["x30"] = symbolicValue{}
	}
	for offset, slot := range state.slots {
		end := offset + int64(slot.width/8)
		if offset < sp.offset || (a.abi.homeBytes != 0 && end > sp.offset && offset < sp.offset+a.abi.homeBytes) {
			delete(state.slots, offset)
		}
	}
	state.flags = symbolicFlags{}
	state.registers[a.abi.result] = value
	return true
}

func renderSummary(out *strings.Builder, n *summaryNode, indent string) {
	if n.predicate == "" {
		fmt.Fprintf(out, "%sreturn %s;\n", indent, n.result.text)
		return
	}
	fmt.Fprintf(out, "%sif (%s) {\n", indent, n.predicate)
	renderSummary(out, n.yes, indent+"    ")
	fmt.Fprintf(out, "%s} else {\n", indent)
	renderSummary(out, n.no, indent+"    ")
	fmt.Fprintf(out, "%s}\n", indent)
}

func validCName(name string) bool {
	if name == "" {
		return false
	}
	for i, c := range name {
		if !(c == '_' || 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || i > 0 && '0' <= c && c <= '9') {
			return false
		}
	}
	switch name {
	case "auto", "break", "case", "char", "const", "continue", "default", "do", "double", "else",
		"enum", "extern", "float", "for", "goto", "if", "inline", "int", "long", "register",
		"restrict", "return", "short", "signed", "sizeof", "static", "struct", "switch", "typedef",
		"union", "unsigned", "void", "volatile", "while", "main", "uint32_t", "uint64_t", "int32_t", "int64_t",
		"_Alignas", "_Alignof", "_Atomic", "_Bool", "_Complex", "_Generic", "_Imaginary", "_Noreturn", "_Static_assert", "_Thread_local":
		return false
	}
	return true
}
