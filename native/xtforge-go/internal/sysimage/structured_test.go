package sysimage

import (
	"strings"
	"testing"
)

func TestX86ByteTestUsesCorrectRegisterBits(t *testing.T) {
	abi, _ := nativeABI("elf", "x86_64")
	a := structuredAnalysis{abi: abi, parameterUse: make([]int, 6)}
	state := symbolicState{registers: map[string]symbolicValue{
		"rsp": {width: 64, stack: true},
		"rax": {width: 32, text: "value"},
	}, slots: make(map[int64]symbolicValue)}
	ins, err := decodeInstruction("x86_64", 0x1000, []byte{0xf6, 0xc4, 0x80})
	if err != nil {
		t.Fatal(err)
	}
	op := liftInstruction("x86_64", ins)
	if !a.apply(&state, op) {
		t.Fatal("byte test was not applied")
	}
	predicate := a.predicate(state, Operation{Condition: "x86.jne"})
	if !strings.Contains(predicate, "value >> 8") || !strings.Contains(predicate, "0x80") {
		t.Fatalf("high-byte test lost its offset: %q", predicate)
	}
}

func TestLoopDoesNotAssumeUninitializedScratchIsZero(t *testing.T) {
	// add r10d, edi; sub edi, 1; jne loop; mov eax, r10d; ret
	data := []byte{0x41, 0x01, 0xfa, 0x83, 0xef, 0x01, 0x75, 0xf8, 0x44, 0x89, 0xd0, 0xc3}
	fn, reason := analyzeTestFunctionWithReason("elf", "x86_64", data)
	if fn != nil {
		t.Fatalf("unknown loop accumulator produced C: %s", fn.Pseudocode)
	}
	if reason == "" {
		t.Fatal("declined loop did not explain why")
	}
}

func TestLoopRejectsOverlappingStackWrites(t *testing.T) {
	abi, _ := nativeABI("elf", "x86_64")
	wide := Operand{Kind: "memory", Width: 64, Memory: &MemoryAddress{Base: "rsp", Displacement: -16}}
	narrow := Operand{Kind: "memory", Width: 32, Memory: &MemoryAddress{Base: "rsp", Displacement: -12}}
	a := structuredAnalysis{abi: abi, blocks: map[uint64]IRBlock{
		1: {Address: 1, Operations: []Operation{{Destination: &wide}, {Destination: &narrow}}},
	}}
	state := symbolicState{registers: map[string]symbolicValue{"rsp": {width: 64, stack: true}}, slots: make(map[int64]symbolicValue)}
	if _, ok := a.loopCarried(loopRegion{blocks: map[uint64]bool{1: true}}, state); ok {
		t.Fatal("overlapping stack slots were treated as independent loop variables")
	}
}

func TestLoopCarriedRegisterUsesWidestWrite(t *testing.T) {
	abi, _ := nativeABI("macho", "arm64")
	wide, narrow := register("x19", 64), register("w19", 32)
	a := structuredAnalysis{abi: abi, blocks: map[uint64]IRBlock{
		1: {Address: 1, Operations: []Operation{{Destination: &wide}, {Destination: &narrow}}},
	}}
	state := symbolicState{registers: map[string]symbolicValue{"sp": {width: 64, stack: true}}, slots: make(map[int64]symbolicValue)}
	variables, ok := a.loopCarried(loopRegion{blocks: map[uint64]bool{1: true}}, state)
	if !ok || len(variables) != 1 || variables[0].width != 64 {
		t.Fatalf("loop register lost wider writes: %#v", variables)
	}
}

func TestLoopAssignmentDoesNotInventCarryOrOverflowFlags(t *testing.T) {
	abi, _ := nativeABI("elf", "x86_64")
	a := &structuredAnalysis{abi: abi, parameterUse: make([]int, 6)}
	s := loopSummer{structuredAnalysis: a, variables: []loopVariable{
		{name: "v0", register: "rax", width: 32, argument: -1},
	}}
	state := symbolicState{registers: map[string]symbolicValue{
		"rax": {text: "(v0 - 0x1u)", width: 32},
	}, slots: make(map[int64]symbolicValue), flags: symbolicFlags{
		kind: "x86_sub", left: symbolicValue{text: "v0", width: 32},
		right:  symbolicValue{text: "0x1", width: 32},
		result: symbolicValue{text: "(v0 - 0x1u)", width: 32},
	}}
	dest := register("eax", 32)
	s.variableAssignment(&state, Operation{Destination: &dest})
	if s.predicate(state, Operation{Condition: "x86.jne"}) == "" {
		t.Fatal("zero comparison was lost")
	}
	if s.predicate(state, Operation{Condition: "x86.jb"}) != "" ||
		s.predicate(state, Operation{Condition: "x86.jl"}) != "" {
		t.Fatal("subtraction carry or overflow was replaced with a zero comparison")
	}
}

func TestNarrowReadOfFullWidthArgument(t *testing.T) {
	abi, _ := nativeABI("macho", "arm64")
	a := structuredAnalysis{abi: abi, parameterUse: make([]int, 8)}
	state := symbolicState{registers: make(map[string]symbolicValue), slots: make(map[int64]symbolicValue)}
	full := a.read(state, register("x0", 64))
	low := a.read(state, register("w0", 32))
	if full.text != "arg0" || low.text != "(uint32_t)(arg0)" || a.parameterUse[0] != 64 {
		t.Fatalf("64-bit argument lost its low view: full=%#v low=%#v", full, low)
	}
}

func TestReverseMixedWidthArgumentRecoversFullValue(t *testing.T) {
	// cmp w0, #0; mov x1, x0; add x0, x1, x0; ret
	data := []byte{0x1f, 0x00, 0x00, 0x71, 0xe1, 0x03, 0x00, 0xaa,
		0x20, 0x00, 0x00, 0x8b, 0xc0, 0x03, 0x5f, 0xd6}
	fn := analyzeTestFunction("macho", "arm64", data)
	if fn == nil || len(fn.Parameters) != 1 || fn.Parameters[0].Width != 64 {
		t.Fatalf("mixed-width argument was not recovered: %#v", fn)
	}
}

func TestMixedWidthArgumentDoesNotInventUpperBits(t *testing.T) {
	abi, _ := nativeABI("macho", "arm64")
	a := structuredAnalysis{abi: abi, parameterUse: make([]int, 8)}
	state := symbolicState{registers: make(map[string]symbolicValue), slots: make(map[int64]symbolicValue)}
	low := a.read(state, register("w0", 32))
	full := a.read(state, register("x0", 64))
	if low.text == "" || full.text != "" {
		t.Fatalf("32-bit argument was extended into unknown upper bits: low=%#v full=%#v", low, full)
	}
}

func TestLoopDoesNotRestoreClobberedArgument(t *testing.T) {
	abi, _ := nativeABI("elf", "x86_64")
	a := &structuredAnalysis{abi: abi, parameterUse: []int{32, 0, 0, 0, 0, 0}}
	s := loopSummer{
		structuredAnalysis: a,
		region:             loopRegion{header: 0x1000},
		variables:          []loopVariable{{name: "v0", register: "rdi", width: 32, argument: 0}},
	}
	state := symbolicState{registers: map[string]symbolicValue{
		"rsp": {width: 64, stack: true}, "rdi": {},
	}, slots: make(map[int64]symbolicValue)}
	if _, ok := s.translate(0x1000, state); ok || !strings.Contains(a.decline, "no known value") {
		t.Fatalf("clobbered register was treated as original argument: %q", a.decline)
	}
}

func TestLoopReachabilityExcludesCallEdges(t *testing.T) {
	header, body, callee := uint64(1), uint64(2), uint64(3)
	a := structuredAnalysis{blocks: map[uint64]IRBlock{
		header: {Address: header, Edges: []Edge{{Kind: "fallthrough", Target: &body}}},
		body: {Address: body, Edges: []Edge{
			{Kind: "jump", Target: &header}, {Kind: "call", Target: &callee},
		}},
		callee: {Address: callee, Edges: []Edge{{Kind: "jump", Target: &header}}},
	}}
	within := map[uint64]bool{header: true, body: true, callee: true}
	if a.reachesWithin(body, callee, within) {
		t.Fatal("call target was treated as a control-flow successor")
	}
	if a.reachableWithin(header, body)[callee] {
		t.Fatal("call target was included in the loop body")
	}
}

func analyzeTestFunction(format, arch string, data []byte) *StructuredFunction {
	return analyzeTestFunctionWithCalls(format, arch, "fixture", data, nil)
}

// analyzeTestFunctionWithReason returns the decline reason alongside the result.
func analyzeTestFunctionWithReason(format, arch string, data []byte) (*StructuredFunction, string) {
	instructions, blocks, warnings := recoverFlow(arch, 0x1000, data, 80)
	var lifted []IRBlock
	for _, block := range blocks {
		ir := IRBlock{Address: block.Address, Edges: block.Edges}
		for _, instruction := range instructions {
			if instruction.Address >= block.Address && instruction.Address < block.End {
				ir.Operations = append(ir.Operations, liftInstruction(arch, instruction))
			}
		}
		lifted = append(lifted, ir)
	}
	return analyzeStructuredWithReason(format, arch, "fixture", 0x1000, lifted, warnings, nil)
}

func analyzeTestFunctionWithCalls(format, arch, name string, data []byte,
	resolve func(uint64) *StructuredFunction) *StructuredFunction {
	instructions, blocks, warnings := recoverFlow(arch, 0x1000, data, 80)
	var lifted []IRBlock
	for _, block := range blocks {
		ir := IRBlock{Address: block.Address, Edges: block.Edges}
		for _, instruction := range instructions {
			if instruction.Address >= block.Address && instruction.Address < block.End {
				ir.Operations = append(ir.Operations, liftInstruction(arch, instruction))
			}
		}
		lifted = append(lifted, ir)
	}
	result := analyzeStructured(format, arch, name, 0x1000, lifted, warnings, resolve)
	if result != nil {
		result.emitProgram()
	}
	return result
}

func TestStructuredComposesCallsOnceAndClearsVolatileRegisters(t *testing.T) {
	callee := analyzeTestFunctionWithCalls("elf", "x86_64", calleeName(0x1100),
		[]byte{0x8d, 0x47, 0x01, 0xc3}, nil) // lea eax, [rdi+1]; ret
	if callee == nil {
		t.Fatal("callee must be proven")
	}
	resolve := func(address uint64) *StructuredFunction {
		if address == 0x1100 {
			return callee
		}
		return nil
	}
	parent := analyzeTestFunctionWithCalls("elf", "x86_64", "parent", []byte{
		0xe8, 0xfb, 0, 0, 0, // call 0x1100
		0x89, 0xc7, // mov edi, eax
		0xe8, 0xf4, 0, 0, 0, // call 0x1100
		0xc3,
	}, resolve)
	if parent == nil || len(parent.Dependencies) != 1 ||
		strings.Count(parent.Pseudocode, "static uint32_t sys_callee_1100(") != 1 ||
		!strings.Contains(parent.Pseudocode, "return sys_callee_1100(sys_callee_1100(arg0));") {
		t.Fatalf("incorrect call composition: %#v", parent)
	}
	clobbered := analyzeTestFunctionWithCalls("elf", "x86_64", "clobbered", []byte{
		0xe8, 0xfb, 0, 0, 0, // call 0x1100
		0x89, 0xf8, // mov eax, edi, an ABI-volatile register
		0xc3,
	}, resolve)
	if clobbered != nil {
		t.Fatalf("inferred an argument from a volatile register after a call: %#v", clobbered)
	}
	tail := analyzeTestFunctionWithCalls("elf", "x86_64", "tail",
		[]byte{0xe9, 0xfb, 0, 0, 0}, resolve)
	if tail == nil || len(tail.Dependencies) != 1 ||
		!strings.Contains(tail.Pseudocode, "return sys_callee_1100(arg0);") {
		t.Fatalf("failed to compose tail jump: %#v", tail)
	}
}

func TestStructuredUsesABIAndTracksStackSpills(t *testing.T) {
	linux := analyzeTestFunction("elf", "x86_64", []byte{
		0x55, 0x48, 0x89, 0xe5, // push rbp and copy rsp
		0x89, 0x7d, 0xfc, 0x8b, 0x45, 0xfc, // spill edi and reload to eax
		0x83, 0xc0, 0x01, 0x5d, 0xc3,
	})
	if linux == nil || linux.ABI != "sysv_amd64" || len(linux.Parameters) != 1 ||
		linux.Parameters[0].Register != "rdi" || linux.ReturnWidth != 32 ||
		!strings.Contains(linux.Pseudocode, "arg0 + 0x1") {
		t.Fatalf("unexpected SysV reconstruction: %#v", linux)
	}
	win := analyzeTestFunction("pe", "x86_64", []byte{0x89, 0xc8, 0x83, 0xc0, 1, 0xc3})
	if win == nil || win.ABI != "windows_x64" || len(win.Parameters) != 1 ||
		win.Parameters[0].Register != "rcx" || win.ReturnWidth != 32 {
		t.Fatalf("unexpected Windows reconstruction: %#v", win)
	}
}

func TestStructuredRecoversArm64ConditionalReturns(t *testing.T) {
	result := analyzeTestFunction("ipa", "arm64", []byte{
		0x60, 0, 0, 0x34, // cbz w0, +12
		0, 4, 0, 0x11, // add w0, w0, #1
		0xc0, 3, 0x5f, 0xd6,
		0xe0, 0, 0x80, 0x52, // mov w0, #7
		0xc0, 3, 0x5f, 0xd6,
	})
	if result == nil || len(result.Parameters) != 1 || result.Parameters[0].Register != "x0" ||
		!strings.Contains(result.Pseudocode, "if (arg0 == 0x0)") ||
		!strings.Contains(result.Pseudocode, "return 0x7;") ||
		!strings.Contains(result.Pseudocode, "arg0 + 0x1") {
		t.Fatalf("unexpected conditional reconstruction: %#v", result)
	}
}

func TestStructuredAbstainsOnUnmodelledEffects(t *testing.T) {
	for _, code := range [][]byte{
		{0x89, 0xf8, 0x0f, 0xc8, 0xc3}, // opaque register effect
		{0x89, 0x37, 0x89, 0xf0, 0xc3}, // external store
		{0x89, 0xf8, 0xeb, 0xfe},       // a loop without a recovered exit
		{0x89, 0xf8, 0xc2, 0x08, 0},    // stack adjustment on return
	} {
		if got := analyzeTestFunction("elf", "x86_64", code); got != nil {
			t.Fatalf("inferred a result in the presence of effects: %x %#v", code, got)
		}
	}
}

func TestStructuredZeroesAnUnknownRegister(t *testing.T) {
	result := analyzeTestFunction("elf", "x86_64", []byte{0x31, 0xc0, 0xc3})
	if result == nil || len(result.Parameters) != 0 || !strings.Contains(result.Pseudocode, "return 0x0;") {
		t.Fatalf("xor reg, reg did not recover an independent constant: %#v", result)
	}
}

func TestStructuredRecoversConditionalMovesAndSelects(t *testing.T) {
	x86 := analyzeTestFunction("elf", "x86_64", []byte{
		0x85, 0xff, // test edi, edi
		0xb8, 9, 0, 0, 0, // mov eax, 9
		0x8d, 0x57, 0x01, // lea edx, [rdi+1]
		0x0f, 0x45, 0xc2, // cmovne eax, edx
		0xc3,
	})
	if x86 == nil || !strings.Contains(x86.Pseudocode, "arg0 != 0x0 ?") ||
		!strings.Contains(x86.Pseudocode, "arg0 + 0x1") {
		t.Fatalf("conditional move: %#v", x86)
	}
	arm := analyzeTestFunction("ipa", "arm64", []byte{
		0x1f, 0, 0, 0x71, // cmp w0, #0
		0x20, 0x10, 0x82, 0x1a, // csel w0, w1, w2, ne
		0xc0, 3, 0x5f, 0xd6,
	})
	if arm == nil || !strings.Contains(arm.Pseudocode, "arg0 != 0x0 ? arg1 : arg2") {
		t.Fatalf("conditional select: %#v", arm)
	}
	increment := analyzeTestFunction("ipa", "arm64", []byte{
		0x1f, 0, 0, 0x71, // cmp w0, #0
		0xe8, 0, 0x80, 0x52, // mov w8, #7
		0, 5, 0x80, 0x1a, // csinc w0, w8, w0, eq
		0xc0, 3, 0x5f, 0xd6,
	})
	if increment == nil || !strings.Contains(increment.Pseudocode, "arg0 == 0x0 ? 0x7u : (arg0 + 0x1u)") {
		t.Fatalf("conditional increment: %#v", increment)
	}
}

func TestStructuredSummarisesACountedLoop(t *testing.T) {
	// test edi,edi; je exit; mov eax,0; add eax,edi; sub edi,1; jne back; ret
	// is the body GCC emits at -O1 for `while (value > 0) total += value--;`.
	function, reason := analyzeTestFunctionWithReason("elf", "x86_64", []byte{
		0x85, 0xff, // test edi, edi
		0x74, 0x0d, // je exit (0x1004 + 0x0d = 0x1011)
		0xb8, 0x00, 0x00, 0x00, 0x00, // mov eax, 0
		0x01, 0xf8, // add eax, edi
		0x83, 0xef, 0x01, // sub edi, 1
		0x75, 0xf9, // jne back
		0xc3,       // ret
		0x89, 0xf8, // exit: mov eax, edi
		0xc3, // ret
	})
	if function == nil {
		t.Fatalf("declined a supported counted loop: %s", reason)
	}
	if !strings.Contains(function.Pseudocode, "for (;;)") {
		t.Fatalf("loop was not reconstructed as a loop: %s", function.Pseudocode)
	}
	if !strings.Contains(function.Pseudocode, "break") {
		t.Fatalf("loop's exit test was dropped: %s", function.Pseudocode)
	}
}

func TestStructuredDeclinesLoopsItCannotModel(t *testing.T) {
	for name, code := range map[string][]byte{
		// Two sequential loops need statement ordering the summary does not model.
		"two loops": {
			0x31, 0xc0, // xor eax, eax
			0x85, 0xff, 0x74, 0x08, // test edi, edi; je fwd
			0x01, 0xf8, 0x83, 0xef, 0x01, 0x75, 0xfa, // add eax, edi; sub edi, 1; jne back
			0xc3,
		},
		// A call in the body is outside what a loop summary can claim.
		"call in body": {
			0x31, 0xc0,
			0x85, 0xff, 0x74, 0x0c,
			0xe8, 0x00, 0x00, 0x00, 0x00, // call rel32
			0x83, 0xef, 0x01, 0x75, 0xf7,
			0xc3,
		},
	} {
		if function, reason := analyzeTestFunctionWithReason("elf", "x86_64", code); function != nil {
			t.Fatalf("%s: summarised unsupported code: %#v", name, function)
		} else if reason == "" {
			t.Fatalf("%s: declined without a reason", name)
		}
	}
}

func TestStructuredDeclineIsEmptyForSupportedFunctions(t *testing.T) {
	function, reason := analyzeTestFunctionWithReason("elf", "x86_64", []byte{
		0x8d, 0x47, 0x01, // lea eax, [rdi+1]
		0xc3,
	})
	if function == nil || reason != "" {
		t.Fatalf("expected a summary and no decline reason, got %#v reason=%q", function, reason)
	}
}

func TestStructuredTreatsRecursionAsAcyclic(t *testing.T) {
	// cmp edi,2; jb exit; call self; ret; exit: mov eax,edi; ret
	// A recursive call is a call edge, not control flow, so this function has no
	// loop in it. The summary is still declined — a recursive callee has no
	// closed form here — but it must be declined as recursion, not mistaken for
	// a loop and sent down the loop path.
	code := []byte{
		0x83, 0xff, 0x02, // cmp edi, 2
		0x72, 0x08, // jb exit
		0xe8, 0xf6, 0xff, 0xff, 0xff, // call self
		0xc3,       // ret
		0x89, 0xf8, // exit: mov eax, edi
		0xc3, // ret
	}
	function, reason := analyzeTestFunctionWithReason("elf", "x86_64", code)
	if function != nil {
		t.Fatalf("summarised a recursive function: %#v", function)
	}
	if strings.Contains(reason, "loop") {
		t.Fatalf("recursion was reported as a loop: %q", reason)
	}
	if !strings.Contains(reason, "call") {
		t.Fatalf("decline reason does not name the call: %q", reason)
	}
}
