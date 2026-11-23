package sysimage

import (
	"fmt"
	"strconv"
	"strings"
)

func (a *structuredAnalysis) predicate(state symbolicState, op Operation) string {
	switch op.Condition {
	case "arm64.cbz", "arm64.cbnz", "arm64.tbz", "arm64.tbnz",
		"arm.cbz", "arm.cbnz":
		if len(op.Inputs) == 0 {
			return ""
		}
		value := a.read(state, op.Inputs[0])
		if value.text == "" {
			return ""
		}
		operator := "=="
		if strings.HasSuffix(op.Condition, "nz") {
			operator = "!="
		}
		if strings.HasPrefix(op.Condition, "arm64.tb") {
			if len(op.Inputs) != 2 {
				return ""
			}
			bit, err := strconv.ParseUint(op.Inputs[1].Immediate, 0, 6)
			if err != nil || int(bit) >= value.width {
				return ""
			}
			return fmt.Sprintf("((%s >> %d) & 1u) %s 0x0", typedTerm(value), bit, operator)
		}
		return value.text + " " + operator + " 0x0"
	}
	f := state.flags
	if f.kind == "" {
		return ""
	}
	if strings.HasPrefix(f.kind, "x86_test") || strings.HasPrefix(f.kind, "arm64_tst") ||
		strings.HasPrefix(f.kind, "arm_tst") || strings.HasPrefix(f.kind, "arm_and") {
		f.result = binaryValue("and", f.left, f.right, f.left.width)
		if f.result.text == "" && (f.left.width == 8 || f.left.width == 16) &&
			f.left.width == f.right.width && f.left.text != "" && f.right.text != "" {
			f.result = symbolicValue{text: "(" + typedTerm(f.left) + " & " + typedTerm(f.right) + ")", width: f.left.width}
		}
		if f.left.text != "" && f.left.text == f.right.text {
			f.result = f.left
		}
	}
	if strings.HasPrefix(f.kind, "arm_teq") || strings.HasPrefix(f.kind, "arm_cmn") {
		operator := "xor"
		if strings.HasPrefix(f.kind, "arm_cmn") {
			operator = "add"
		}
		f.result = binaryValue(operator, f.left, f.right, f.left.width)
	}
	compares := strings.HasPrefix(f.kind, "x86_cmp") || strings.HasPrefix(f.kind, "arm64_cmp") ||
		strings.HasPrefix(f.kind, "arm_cmp") || f.kind == "x86_sub" || f.kind == "arm64_sub" ||
		f.kind == "arm_sub"
	switch op.Condition {
	case "x86.je", "x86.jne", "arm64.eq", "arm64.ne", "arm.eq", "arm.ne":
		operator := "=="
		if op.Condition == "x86.jne" || op.Condition == "arm64.ne" || op.Condition == "arm.ne" {
			operator = "!="
		}
		if compares && f.left.text != "" && f.right.text != "" && f.left.width == f.right.width {
			return f.left.text + " " + operator + " " + f.right.text
		}
		if f.result.text != "" {
			return f.result.text + " " + operator + " 0x0"
		}
	}
	if !compares || f.left.text == "" || f.right.text == "" || f.left.width != f.right.width ||
		(f.left.width != 32 && f.left.width != 64) {
		return ""
	}
	switch op.Condition {
	case "x86.jl", "arm64.lt", "arm.lt":
		return signedComparison(f.left, "<", f.right)
	case "x86.jle", "arm64.le", "arm.le":
		return signedComparison(f.left, "<=", f.right)
	case "x86.jg", "arm64.gt", "arm.gt":
		return signedComparison(f.left, ">", f.right)
	case "x86.jge", "arm64.ge", "arm.ge":
		return signedComparison(f.left, ">=", f.right)
	case "x86.jb", "arm64.cc", "arm.cc":
		return typedTerm(f.left) + " < " + typedTerm(f.right)
	case "x86.jbe", "arm64.ls", "arm.ls":
		return typedTerm(f.left) + " <= " + typedTerm(f.right)
	case "x86.ja", "arm64.hi", "arm.hi":
		return typedTerm(f.left) + " > " + typedTerm(f.right)
	case "x86.jae", "arm64.cs", "arm.cs":
		return typedTerm(f.left) + " >= " + typedTerm(f.right)
	}
	return ""
}

func signedComparison(left symbolicValue, operator string, right symbolicValue) string {
	// Flipping the sign bit orders two's-complement values as unsigned
	// integers without requiring an implementation-defined signed cast.
	mask := typedTerm(symbolicValue{
		text: fmt.Sprintf("%#x", uint64(1)<<(left.width-1)), width: left.width,
	})
	return fmt.Sprintf("(%s ^ %s) %s (%s ^ %s)", typedTerm(left), mask, operator, typedTerm(right), mask)
}
