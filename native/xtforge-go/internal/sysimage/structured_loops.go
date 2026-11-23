package sysimage

// Loop summarisation.
//
// The acyclic path summarises a function as one expression tree (summaryNode),
// which cannot express a loop: a loop's effect depends on how many times its
// body ran, and its body assigns to values that outlive a single pass. This
// file adds the imperative half of the model. A function containing a loop is
// summarised as a statement list — a declaration per value the body changes,
// one `for (;;)`, and returns.
//
// The exit test is emitted where the compiler put it, as a `break`, instead of
// being rotated into a `while (cond)` head. That keeps the translation faithful
// without having to prove the rotation preserves the trip count, which for a
// test at the bottom of the body would mean proving the body always runs at
// least once.
//
// Scope: one loop with a linear body and a conditional back edge. Other control
// flow shapes are declined with a reason.

import (
	"fmt"
	"sort"
	"strings"
)

// statement is one line of a recovered body.
type statement struct {
	kind string // "declare", "assign", "if", "loop", "return", "break"

	variable loopVariable // declare
	// text is the assignment, the returned expression, or the exit test.
	text string
	then []statement // if: the taken arm; loop: the body
	// other is the else arm. It is nil when the test only guards what follows,
	// which is how a loop's exit test renders.
	other []statement
}

// loopVariable is a value a loop body changes across iterations.
type loopVariable struct {
	name     string
	width    int
	initial  string
	register string // canonical register, when inSlot is false
	slot     int64
	inSlot   bool
	// param is set when the value is already a C parameter, so it is assigned
	// but never re-declared.
	param bool
	// argument is the argument register the value lives in, or -1.
	argument      int
	uninitialized bool
}

// symbolic is the value a recovered variable reads as inside the body.
func (v loopVariable) symbolic() symbolicValue {
	return symbolicValue{text: v.name, width: v.width}
}

// loopRegion is one natural loop: its header and the blocks that repeat.
type loopRegion struct {
	header uint64
	blocks map[uint64]bool
}

// flow records how a walked path leaves the code it was given.
type flow int

const (
	flowContinue flow = iota // the path falls out of the walked block
	flowReturn               // the path returns from the function
	flowBreak                // the path leaves the loop it was walking
)

// findLoops returns the natural loops reachable from entry, in header order.
func (a *structuredAnalysis) findLoops(entry uint64) []loopRegion {
	visited := make(map[uint64]bool)
	active := make(map[uint64]bool)
	byHeader := make(map[uint64]int)
	var loops []loopRegion
	var visit func(uint64)
	visit = func(address uint64) {
		visited[address], active[address] = true, true
		for _, edge := range a.blocks[address].Edges {
			if edge.Target == nil || edge.Kind == "call" {
				continue
			}
			target := *edge.Target
			if _, local := a.blocks[target]; !local {
				continue
			}
			if active[target] {
				region := a.reachableWithin(target, address)
				if index, exists := byHeader[target]; exists {
					for block := range region {
						loops[index].blocks[block] = true
					}
				} else {
					byHeader[target] = len(loops)
					loops = append(loops, loopRegion{header: target, blocks: region})
				}
			} else if !visited[target] {
				visit(target)
			}
		}
		active[address] = false
	}
	if _, exists := a.blocks[entry]; exists {
		visit(entry)
	}
	return loops
}

// reachableWithin lists the header plus every block reachable from start that
// comes back to the header. Blocks that never return to it are loop exits and
// belong to the code after the loop.
func (a *structuredAnalysis) reachableWithin(header, start uint64) map[uint64]bool {
	seen := map[uint64]bool{start: true}
	queue := []uint64{start}
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		for _, edge := range a.blocks[current].Edges {
			if edge.Target == nil || edge.Kind == "call" {
				continue
			}
			next := *edge.Target
			if _, local := a.blocks[next]; !local || seen[next] {
				continue
			}
			seen[next] = true
			queue = append(queue, next)
		}
	}
	body := map[uint64]bool{header: true}
	for address := range seen {
		if a.reachesWithin(address, header, seen) {
			body[address] = true
		}
	}
	return body
}

// reachesWithin reports whether target is reachable from address staying inside
// within.
func (a *structuredAnalysis) reachesWithin(address, target uint64, within map[uint64]bool) bool {
	if address == target {
		return true
	}
	seen := make(map[uint64]bool, len(within))
	queue := []uint64{address}
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		if seen[current] {
			continue
		}
		seen[current] = true
		for _, edge := range a.blocks[current].Edges {
			if edge.Target == nil || edge.Kind == "call" || !within[*edge.Target] {
				continue
			}
			if *edge.Target == target {
				return true
			}
			queue = append(queue, *edge.Target)
		}
	}
	return false
}

// loopCarried finds the values a loop body changes, in a deterministic order.
func (a *structuredAnalysis) loopCarried(region loopRegion, entryState symbolicState) ([]loopVariable, bool) {
	addresses := make([]uint64, 0, len(region.blocks))
	for address := range region.blocks {
		addresses = append(addresses, address)
	}
	sort.Slice(addresses, func(i, j int) bool { return addresses[i] < addresses[j] })

	type key struct {
		slot int64
		name string
	}
	written := make(map[key]int)
	overlappingSlots := false

	note := func(op Operand) {
		switch op.Kind {
		case "register":
			name := canonicalRegister(op.Register)
			// The result register is deliberately included: an accumulator usually
			// lives there, and dropping it would leave the code after the loop
			// reading a stale expression.
			if name == a.abi.stack || name == "sp" || name == "flags" || name == "xzr" ||
				name == "x30" {
				return
			}
			k := key{name: name}
			written[k] = max(written[k], op.Width)
		case "memory":
			// A stack slot only has an address relative to the frame, so resolve
			// it against the state the walk started from.
			slot, ok := a.stackSlot(entryState, op, entryState.registers[a.abi.stack].offset)
			if !ok {
				return
			}
			for existing, value := range entryState.slots {
				end := slot + int64(op.Width/8)
				existingEnd := existing + int64(value.width/8)
				if slot < existingEnd && existing < end &&
					(slot != existing || op.Width != value.width) {
					overlappingSlots = true
				}
			}
			for existing, width := range written {
				if existing.name != "\x00slot" {
					continue
				}
				end := slot + int64(op.Width/8)
				existingEnd := existing.slot + int64(width/8)
				if slot < existingEnd && existing.slot < end &&
					(slot != existing.slot || op.Width != width) {
					overlappingSlots = true
				}
			}
			written[key{slot: slot, name: "\x00slot"}] = op.Width
		}
	}
	for _, address := range addresses {
		for _, op := range a.blocks[address].Operations {
			if op.Destination != nil {
				note(*op.Destination)
			}
			if op.SecondDestination != nil {
				note(*op.SecondDestination)
			}
		}
	}
	if overlappingSlots {
		a.declineHere("loop contains overlapping stack writes")
		return nil, false
	}
	if len(written) == 0 {
		a.declineHere("loop body changes no recoverable value")
		return nil, false
	}

	names := make([]key, 0, len(written))
	for entry := range written {
		names = append(names, entry)
	}
	sort.Slice(names, func(i, j int) bool {
		if names[i].name != names[j].name {
			return names[i].name < names[j].name
		}
		return names[i].slot < names[j].slot
	})

	variables := make([]loopVariable, 0, len(names))
	for index, entry := range names {
		width := written[entry]
		if width != 32 && width != 64 {
			a.declineHere(fmt.Sprintf("a value the loop changes is %d bits wide", width))
			return nil, false
		}
		variable := loopVariable{name: fmt.Sprintf("v%d", index), width: width, argument: -1}
		if entry.name == "\x00slot" {
			variable.slot, variable.inSlot = entry.slot, true
		} else {
			variable.register = entry.name
			variable.argument = a.argumentIndex(entry.name)
		}
		variables = append(variables, variable)
	}
	return variables, true
}

// loopSummer translates a function whose only loop has a single-block body.
type loopSummer struct {
	*structuredAnalysis
	region    loopRegion
	variables []loopVariable
	exitState symbolicState
	callTemps []loopVariable
	// declaredParameters records the parameters already named in the signature.
	declaredParameters map[string]bool
}

// argumentIndex reports which argument register name is, or -1.
func (a *structuredAnalysis) argumentIndex(name string) int {
	for i, parameter := range a.abi.parameters {
		if canonicalRegister(parameter) == name {
			return i
		}
	}
	return -1
}

// atAnalysisParameterUse reports the width recorded for a parameter, or zero.
func atAnalysisParameterUse(uses []int, index int) int {
	if index < 0 || index >= len(uses) {
		return 0
	}
	return uses[index]
}

// parameterDeclared reports whether name is already a parameter of the function.
func (s *loopSummer) parameterDeclared(name string) bool {
	for i := range s.structuredAnalysis.parameterUse {
		if fmt.Sprintf("arg%d", i) == name {
			return true
		}
	}
	return false
}

// summariseLoops returns the statement list for a function containing one loop.
func (a *structuredAnalysis) summariseLoops(entry uint64, state symbolicState) ([]statement, bool) {
	loops := a.findLoops(entry)
	if len(loops) == 0 {
		return nil, false
	}
	if len(loops) != 1 {
		a.declineHere(fmt.Sprintf("function has %d loops; only one loop is summarised", len(loops)))
		return nil, false
	}
	region := loops[0]
	summer := &loopSummer{structuredAnalysis: a, region: region,
		declaredParameters: make(map[string]bool)}
	before, atLoop, ok := summer.preamble(entry, state)
	if !ok {
		return nil, false
	}
	variables, ok := a.loopCarried(region, atLoop)
	if !ok {
		return nil, false
	}
	summer.variables = variables
	return summer.translateAt(before, atLoop)
}

// translate emits the code before the loop, the loop, and the code after it.
func (s *loopSummer) translate(entry uint64, state symbolicState) ([]statement, bool) {
	before, atLoop, ok := s.preamble(entry, state)
	if !ok {
		return nil, false
	}
	return s.translateAt(before, atLoop)
}

func (s *loopSummer) translateAt(before []statement, atLoop symbolicState) ([]statement, bool) {
	out := before
	for i := range s.variables {
		variable := &s.variables[i]
		var initial symbolicValue
		scratch := false
		if variable.inSlot {
			initial = atLoop.slots[variable.slot]
		} else {
			var present bool
			initial, present = atLoop.registers[variable.register]
			if !present {
				// A parameter that the loop only reads is never stored in the
				// symbolic state, because reading it does not change it. Its value
				// where the loop starts is still the argument itself.
				for i, parameter := range s.abi.parameters {
					if canonicalRegister(parameter) != variable.register {
						continue
					}
					if width := atAnalysisParameterUse(s.parameterUse, i); width != 0 {
						initial = symbolicValue{text: fmt.Sprintf("arg%d", i), width: width}
					} else if s.readsRegisterBeforeWrite(variable.register) {
						initial = s.read(atLoop, register(parameter, variable.width))
					} else {
						scratch = true
					}
					break
				}
			}
		}
		// A value in an argument register is only a parameter if it still holds the
		// argument where the loop starts. Compilers routinely reuse those registers
		// as scratch space, and naming such a value arg2 would claim it carries a
		// value the function never received.
		if variable.argument >= 0 && initial.width == variable.width &&
			initial.text == fmt.Sprintf("arg%d", variable.argument) {
			// It still holds the incoming argument, so it is that parameter and
			// needs no declaration.
			variable.name, variable.param = initial.text, true
			s.variables[i] = *variable
			continue
		}
		if !variable.inSlot && variable.width == 32 && initial.width == 64 && initial.text != "" {
			variable.width = 64
		}
		if !variable.inSlot && variable.width == 64 && initial.width == 32 && initial.text != "" {
			initial = symbolicValue{text: fmt.Sprintf("(uint64_t)(%s)", initial.text), width: 64}
		}
		if initial.text == "" && !variable.inSlot && (variable.argument < 0 || scratch) {
			variable.uninitialized = true
			variable.initial = "0"
			out = append(out, statement{kind: "declare", variable: *variable})
			continue
		}
		if initial.text == "" || initial.width != variable.width {
			s.declineHere(fmt.Sprintf("%s has no known value before the loop", variable.name))
			return nil, false
		}
		variable.initial = typedTerm(initial)
		out = append(out, statement{kind: "declare", variable: *variable})
	}

	body, exit, target, ok := s.emitBody(atLoop)
	if !ok {
		return nil, false
	}
	for _, temp := range s.callTemps {
		out = append(out, statement{kind: "declare", variable: temp})
	}
	if exit != "" {
		body = append(body, statement{kind: "break", text: exit})
	}
	out = append(out, statement{kind: "loop", then: body})

	after := s.afterLoop(s.exitState)
	rest, ok := s.renderFrom(target, after)
	if !ok {
		return nil, false
	}
	return append(out, rest...), true
}

// readsRegisterBeforeWrite checks paths through one iteration conservatively.
func (s *loopSummer) readsRegisterBeforeWrite(reg string) bool {
	seen := make(map[uint64]bool)
	var visit func(uint64) bool
	visit = func(address uint64) bool {
		if seen[address] || !s.region.blocks[address] {
			return false
		}
		seen[address] = true
		for _, op := range s.blocks[address].Operations {
			for _, input := range op.Inputs {
				if input.Kind == "register" && canonicalRegister(input.Register) == reg {
					return true
				}
				if input.Memory != nil && (canonicalRegister(input.Memory.Base) == reg ||
					canonicalRegister(input.Memory.Index) == reg) {
					return true
				}
			}
			if op.Destination != nil && op.Destination.Kind == "register" &&
				canonicalRegister(op.Destination.Register) == reg {
				return false
			}
		}
		for _, edge := range s.blocks[address].Edges {
			if edge.Kind != "call" && edge.Target != nil && visit(*edge.Target) {
				return true
			}
		}
		return false
	}
	return visit(s.region.header)
}

// afterLoop rewrites state so each variable reads as its own name, which is what
// the emitted C holds once the loop has finished.
func (s *loopSummer) afterLoop(state symbolicState) symbolicState {
	for _, variable := range s.variables {
		if variable.inSlot {
			if _, known := state.slots[variable.slot]; known {
				state.slots[variable.slot] = variable.symbolic()
			}
			continue
		}
		if state.registers[variable.register].text != "" {
			state.registers[variable.register] = variable.symbolic()
		}
	}
	return state
}

// preamble walks from entry to the loop header. A guard whose other arm leaves
// the function becomes an `if`, which is the shape of the `if (n == 0) return 0;`
// check compilers put in front of a counted loop.
func (s *loopSummer) preamble(entry uint64, state symbolicState) ([]statement, symbolicState, bool) {
	var out []statement
	current := entry
	for steps := 0; steps < 64; steps++ {
		if current == s.region.header {
			return out, state, true
		}
		block, exists := s.blocks[current]
		if !exists {
			s.declineHere("the code before the loop is not reachable")
			return nil, state, false
		}
		var descent []statement
		for _, op := range block.Operations {
			switch op.Opcode {
			case "return":
				s.declineHere("function returns before reaching the loop")
				return nil, state, false
			case "call":
				if !s.applyCall(&state, op) {
					s.declineHere("call before the loop could not be summarised")
					return nil, state, false
				}
			case "jump":
				if op.Target == nil {
					s.declineHere("jump before the loop has no known target")
					return nil, state, false
				}
				current = *op.Target
				out = append(out, descent...)
				descent = nil
				goto descend
			case "branch":
				predicate := s.predicate(state, op)
				if predicate == "" || op.Target == nil || op.Fallthrough == nil {
					s.declineHere("the path into the loop branches without a usable condition")
					return nil, state, false
				}
				into := s.reachesHeader(*op.Target)
				intoFallthrough := s.reachesHeader(*op.Fallthrough)
				if into == intoFallthrough {
					s.declineHere("the code before the loop does not have exactly one path into it")
					return nil, state, false
				}
				guard, guarded := *op.Target, predicate
				current = *op.Fallthrough
				if into {
					guard, guarded, current = *op.Fallthrough, "!("+predicate+")", *op.Target
				}
				elseStatements, ok := s.renderFrom(guard, state.clone())
				if !ok {
					return nil, state, false
				}
				out = append(out, descent...)
				descent = nil
				out = append(out, statement{kind: "if", text: guarded, then: elseStatements})
				goto descend
			default:
				if !s.apply(&state, op) {
					s.declineHere(fmt.Sprintf("unsupported operation %q at %#x", op.Opcode, op.Address))
					return nil, state, false
				}
				// A value the loop changes is declared with its value at that point,
				// so assigning it here would declare it twice.
				if s.writesLoopVariable(&state, op) {
					continue
				}
				if text := s.variableAssignment(&state, op); text != "" {
					descent = append(descent, statement{kind: "assign", text: text})
				}
			}
		}
		if len(block.Edges) != 1 || block.Edges[0].Target == nil {
			s.declineHere("the code before the loop does not fall through")
			return nil, state, false
		}
		current = *block.Edges[0].Target
		out = append(out, descent...)
	descend:
	}
	s.declineHere("could not reach the loop header")
	return nil, state, false
}

// reachesHeader reports whether address reaches the loop header.
func (s *loopSummer) reachesHeader(address uint64) bool {
	set := make(map[uint64]bool, len(s.blocks))
	for block := range s.blocks {
		set[block] = true
	}
	for block := range s.region.blocks {
		set[block] = true
	}
	return s.reachesWithin(address, s.region.header, set)
}

// emitBody translates the loop body and reports the test that leaves the loop
// and where control continues afterwards.
func (s *loopSummer) emitBody(state symbolicState) ([]statement, string, uint64, bool) {
	for _, variable := range s.variables {
		if variable.inSlot {
			state.slots[variable.slot] = variable.symbolic()
			continue
		}
		if variable.uninitialized {
			state.registers[variable.register] = symbolicValue{}
		} else {
			state.registers[variable.register] = variable.symbolic()
		}
	}
	var body []statement
	current := s.region.header
	seen := make(map[uint64]bool, len(s.region.blocks))
	var topExit *uint64
	for {
		if seen[current] {
			s.declineHere("loop contains an unsupported cycle")
			return nil, "", 0, false
		}
		seen[current] = true
		block := s.blocks[current]
		next := uint64(0)
		for _, op := range block.Operations {
			switch op.Opcode {
			case "branch":
				if topExit != nil {
					predicate := s.predicate(state, op)
					if predicate == "" || op.Target == nil || op.Fallthrough == nil {
						return nil, "", 0, false
					}
					yesAddress, yesPath := s.followLoopTrampolines(*op.Target)
					noAddress, noPath := s.followLoopTrampolines(*op.Fallthrough)
					yes, yesState, yesNext, yesOK := s.loopBranch(yesAddress, state.clone())
					no, noState, noNext, noOK := s.loopBranch(noAddress, state.clone())
					yesEmpty, noEmpty := false, false
					if yesOK && yesNext == noAddress {
						no, noState, noNext, noOK = nil, state.clone(), noAddress, true
						noEmpty = true
					} else if noOK && noNext == yesAddress {
						yes, yesState, yesNext, yesOK = nil, state.clone(), yesAddress, true
						yesEmpty = true
					}
					if !yesOK || !noOK || yesNext != noNext || seen[yesAddress] || seen[noAddress] {
						s.declineHere("loop branch does not have a supported common join")
						return nil, "", 0, false
					}
					for _, address := range append(yesPath, noPath...) {
						if seen[address] {
							s.declineHere("loop branch revisits an earlier block")
							return nil, "", 0, false
						}
						seen[address] = true
					}
					if !yesEmpty {
						seen[yesAddress] = true
					}
					if !noEmpty {
						seen[noAddress] = true
					}
					body = append(body, statement{kind: "if", text: predicate, then: yes, other: no})
					for reg, value := range yesState.registers {
						if value != noState.registers[reg] {
							yesState.registers[reg] = symbolicValue{}
						}
					}
					for reg := range noState.registers {
						if _, ok := yesState.registers[reg]; !ok {
							yesState.registers[reg] = symbolicValue{}
						}
					}
					for offset, value := range yesState.slots {
						if other, ok := noState.slots[offset]; !ok || value != other {
							delete(yesState.slots, offset)
						}
					}
					yesState.flags = symbolicFlags{}
					state, next = yesState, yesNext
					continue
				}
				predicate := s.predicate(state, op)
				if predicate == "" || op.Target == nil || op.Fallthrough == nil {
					s.declineHere("the loop's exit test is not a comparably known expression")
					return nil, "", 0, false
				}
				s.exitState = state.clone()
				switch {
				case *op.Target == s.region.header:
					// Jumping back to the header repeats the loop, so the predicate is
					// itself the repeat condition.
					return body, predicate, *op.Fallthrough, true
				case *op.Fallthrough == s.region.header:
					return body, "!(" + predicate + ")", *op.Target, true
				}
				targetInside := s.region.blocks[*op.Target]
				fallInside := s.region.blocks[*op.Fallthrough]
				if current == s.region.header && targetInside && fallInside {
					yes, yesExit, yesState, yesOK := s.loopAlternative(*op.Target, state.clone())
					no, noExit, noState, noOK := s.loopAlternative(*op.Fallthrough, state.clone())
					if yesOK && noOK && (yesExit == nil) != (noExit == nil) {
						body = append(body, statement{kind: "if", text: predicate, then: yes, other: no})
						if yesExit != nil {
							s.exitState = yesState
							return body, "", *yesExit, true
						}
						s.exitState = noState
						return body, "", *noExit, true
					}
				}
				if current == s.region.header && targetInside != fallInside {
					if targetInside {
						next, topExit = *op.Target, op.Fallthrough
						body = append(body, statement{kind: "break", text: predicate})
					} else {
						next, topExit = *op.Fallthrough, op.Target
						body = append(body, statement{kind: "break", text: "!(" + predicate + ")"})
					}
					continue
				}
				s.declineHere("the loop's exit branch does not return to the loop header")
				return nil, "", 0, false
			case "return":
				s.declineHere("the loop body returns instead of repeating")
				return nil, "", 0, false
			case "call":
				if !s.applyCall(&state, op) {
					s.declineHere("the loop body contains an unsupported call")
					return nil, "", 0, false
				}
				if topExit != nil {
					for reg := range s.exitState.registers {
						value := state.registers[reg]
						if reg == s.abi.result || value.text == "" && value.origin == "" && !value.stack {
							s.exitState.registers[reg] = symbolicValue{}
						}
					}
					for offset := range s.exitState.slots {
						if _, preserved := state.slots[offset]; !preserved {
							delete(s.exitState.slots, offset)
						}
					}
				}
				value := state.registers[s.abi.result]
				temp := loopVariable{name: fmt.Sprintf("call_result_%d", len(s.callTemps)),
					width: value.width, initial: "0"}
				s.callTemps = append(s.callTemps, temp)
				body = append(body, statement{kind: "assign", text: temp.name + " = " + value.text})
				state.registers[s.abi.result] = temp.symbolic()
			case "jump":
				if op.Target != nil && *op.Target == s.region.header && topExit != nil {
					return body, "", *topExit, true
				}
				if op.Target == nil || !s.region.blocks[*op.Target] || *op.Target == s.region.header {
					s.declineHere("loop jump does not lead to an unvisited body block")
					return nil, "", 0, false
				}
				next = *op.Target
			default:
				if !s.apply(&state, op) {
					s.declineHere(fmt.Sprintf("unsupported operation %q at %#x", op.Opcode, op.Address))
					return nil, "", 0, false
				}
				if text := s.variableAssignment(&state, op); text != "" {
					body = append(body, statement{kind: "assign", text: text})
				}
			}
		}
		if next == 0 && len(block.Edges) == 1 && block.Edges[0].Kind == "fallthrough" && block.Edges[0].Target != nil {
			next = *block.Edges[0].Target
		}
		if next == s.region.header && topExit != nil {
			return body, "", *topExit, true
		}
		if next == 0 || !s.region.blocks[next] {
			s.declineHere("the loop body has no supported path to its exit test")
			return nil, "", 0, false
		}
		current = next
	}
}

// loopAlternative handles a straight-line branch that returns to the header or exits.
func (s *loopSummer) loopAlternative(address uint64, state symbolicState) ([]statement, *uint64, symbolicState, bool) {
	var statements []statement
	seen := make(map[uint64]bool)
	for s.region.blocks[address] && !seen[address] {
		seen[address] = true
		block := s.blocks[address]
		var next *uint64
		for _, op := range block.Operations {
			switch op.Opcode {
			case "branch":
				if op.Target == nil || op.Fallthrough == nil {
					return nil, nil, state, false
				}
				predicate := s.predicate(state, op)
				if predicate == "" {
					return nil, nil, state, false
				}
				if *op.Target == s.region.header && !s.region.blocks[*op.Fallthrough] {
					return append(statements, statement{kind: "break", text: predicate}), op.Fallthrough, state, true
				}
				if *op.Fallthrough == s.region.header && !s.region.blocks[*op.Target] {
					return append(statements, statement{kind: "break", text: "!(" + predicate + ")"}), op.Target, state, true
				}
				return nil, nil, state, false
			case "jump":
				next = op.Target
			case "call", "return":
				return nil, nil, state, false
			default:
				if !s.apply(&state, op) {
					return nil, nil, state, false
				}
				if assignment := s.variableAssignment(&state, op); assignment != "" {
					statements = append(statements, statement{kind: "assign", text: assignment})
				}
			}
		}
		if next == nil && len(block.Edges) == 1 && block.Edges[0].Kind == "fallthrough" {
			next = block.Edges[0].Target
		}
		if next == nil {
			return nil, nil, state, false
		}
		if *next == s.region.header {
			return statements, nil, state, true
		}
		address = *next
	}
	return nil, nil, state, false
}

func (s *loopSummer) followLoopTrampolines(address uint64) (uint64, []uint64) {
	visited := make(map[uint64]bool)
	var path []uint64
	for !visited[address] && s.region.blocks[address] {
		block := s.blocks[address]
		if len(block.Operations) != 1 || block.Operations[0].Opcode != "jump" ||
			block.Operations[0].Target == nil {
			break
		}
		visited[address] = true
		path = append(path, address)
		address = *block.Operations[0].Target
	}
	return address, path
}

// loopBranch summarises one straight-line arm ending at a common join.
func (s *loopSummer) loopBranch(address uint64, state symbolicState) ([]statement, symbolicState, uint64, bool) {
	block, ok := s.blocks[address]
	if !ok || !s.region.blocks[address] {
		return nil, state, 0, false
	}
	var statements []statement
	for _, op := range block.Operations {
		if op.Opcode == "jump" {
			if op.Target == nil || !s.region.blocks[*op.Target] {
				return nil, state, 0, false
			}
			return statements, state, *op.Target, true
		}
		if op.Opcode == "branch" || op.Opcode == "return" || op.Opcode == "call" || !s.apply(&state, op) {
			return nil, state, 0, false
		}
		if assignment := s.variableAssignment(&state, op); assignment != "" {
			statements = append(statements, statement{kind: "assign", text: assignment})
		}
	}
	if len(block.Edges) != 1 || block.Edges[0].Kind != "fallthrough" || block.Edges[0].Target == nil {
		return nil, state, 0, false
	}
	return statements, state, *block.Edges[0].Target, s.region.blocks[*block.Edges[0].Target]
}

// writesLoopVariable reports whether op assigns to a value the loop changes.
func (s *loopSummer) writesLoopVariable(state *symbolicState, op Operation) bool {
	if op.Destination == nil {
		return false
	}
	if op.Destination.Kind == "register" {
		name := canonicalRegister(op.Destination.Register)
		for _, variable := range s.variables {
			if !variable.inSlot && variable.register == name {
				return true
			}
		}
		return false
	}
	slot, ok := s.stackSlot(*state, *op.Destination, state.registers[s.abi.stack].offset)
	if !ok {
		return false
	}
	for _, variable := range s.variables {
		if variable.inSlot && variable.slot == slot {
			return true
		}
	}
	return false
}

// variableAssignment reports the assignment op made to a recovered variable, and
// leaves that variable reading as its own name so later operations compose from
// the C local rather than repeating the expression.
func (s *loopSummer) variableAssignment(state *symbolicState, op Operation) string {
	if op.Destination == nil {
		return ""
	}
	for i := range s.variables {
		variable := &s.variables[i]
		var updated symbolicValue
		if variable.inSlot {
			if op.Destination.Kind != "memory" {
				continue
			}
			slot, ok := s.stackSlot(*state, *op.Destination, state.registers[s.abi.stack].offset)
			if !ok || slot != variable.slot {
				continue
			}
			updated = state.slots[slot]
		} else {
			if op.Destination.Kind != "register" ||
				canonicalRegister(op.Destination.Register) != variable.register {
				continue
			}
			updated = state.registers[variable.register]
		}
		flagResult := updated
		if !variable.inSlot && variable.width == 64 && updated.width == 32 && updated.text != "" {
			updated = symbolicValue{text: fmt.Sprintf("(uint32_t)(%s)", updated.text), width: 64}
		}
		if updated.text == "" || updated.width != variable.width ||
			updated.text == variable.name {
			return ""
		}
		// The comparison flags the operation just set describe the value before the
		// decrement, so a loop test such as `sub edi, 1; jne` would otherwise read
		// as `arg0 != 0x1`. Point the flags at the updated variable compared with
		// zero, which is what the subtraction's own result is tested against.
		if state.flags.left.text == flagResult.text || state.flags.result.text == flagResult.text {
			flagValue := variable.symbolic()
			if flagResult.width != variable.width {
				flagValue = symbolicValue{text: fmt.Sprintf("(uint%d_t)(%s)", flagResult.width, variable.name), width: flagResult.width}
			}
			state.flags.left = flagValue
			state.flags.right = symbolicValue{text: "0x0", width: flagResult.width}
			state.flags.result = flagValue
			state.flags.kind = "loop_result"
		}
		if variable.inSlot {
			state.slots[variable.slot] = variable.symbolic()
		} else {
			state.registers[variable.register] = variable.symbolic()
		}
		return fmt.Sprintf("%s = %s", variable.name, typedTerm(updated))
	}
	return ""
}

// renderFrom summarises the acyclic code at address using the existing walker.
func (s *loopSummer) renderFrom(address uint64, state symbolicState) ([]statement, bool) {
	tree := s.walk(address, state, 0)
	if tree == nil {
		reason := s.decline
		if reason == "" {
			reason = "code after the loop could not be summarised"
		}
		s.declineHere(reason)
		return nil, false
	}
	return summaryStatements(tree), true
}

// summaryStatements converts a summary tree into statements.
func summaryStatements(node *summaryNode) []statement {
	if node == nil {
		return nil
	}
	if node.predicate == "" {
		return []statement{{kind: "return", text: node.result.text}}
	}
	return []statement{{kind: "if", text: node.predicate,
		then: summaryStatements(node.yes), other: summaryStatements(node.no)}}
}

func renderStatements(out *strings.Builder, statements []statement, indent string) {
	for _, item := range statements {
		switch item.kind {
		case "declare":
			fmt.Fprintf(out, "%suint%d_t %s = %s;\n", indent, item.variable.width,
				item.variable.name, item.variable.initial)
		case "assign":
			fmt.Fprintf(out, "%s%s;\n", indent, item.text)
		case "return":
			fmt.Fprintf(out, "%sreturn %s;\n", indent, item.text)
		case "break":
			fmt.Fprintf(out, "%sif (!(%s)) break;\n", indent, item.text)
		case "if":
			if len(item.other) == 0 {
				fmt.Fprintf(out, "%sif (%s) {\n", indent, item.text)
				renderStatements(out, item.then, indent+"    ")
				fmt.Fprintf(out, "%s}\n", indent)
				continue
			}
			fmt.Fprintf(out, "%sif (%s) {\n", indent, item.text)
			renderStatements(out, item.then, indent+"    ")
			fmt.Fprintf(out, "%s} else {\n", indent)
			renderStatements(out, item.other, indent+"    ")
			fmt.Fprintf(out, "%s}\n", indent)
		case "loop":
			fmt.Fprintf(out, "%sfor (;;) {\n", indent)
			renderStatements(out, item.then, indent+"    ")
			fmt.Fprintf(out, "%s}\n", indent)
		}
	}
}
