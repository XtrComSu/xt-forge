package sysimage

import (
	"debug/elf"
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

func TestARM32HandEncoded(t *testing.T) {
	const base = 0x1000
	cases := []struct {
		name     string
		word     uint32
		mnemonic string
		operands string
		kind     string
		target   uint64
	}{
		{"add immediate", 0xe2800001, "add", "r0, r0, #1", "", 0},
		{"mov register", 0xe1a00001, "mov", "r0, r1", "", 0},
		{"cmp immediate", 0xe3500000, "cmp", "r0, #0", "", 0},
		{"bx lr", 0xe12fff1e, "bx", "lr", "return", 0},
		{"push", 0xe92d4010, "push", "{r4, lr}", "", 0},
		{"pop", 0xe8bd8010, "pop", "{r4, pc}", "return", 0},
		{"b .+8", 0xea000000, "b", "0x1008", "jump", base + 8},
		{"bl .+8", 0xeb000000, "bl", "0x1008", "call", base + 8},
		{"ldr immediate", 0xe5910004, "ldr", "r0, [r1, #0x4]", "", 0},
	}
	for _, tc := range cases {
		ins, ok := decodeARM32(tc.word, base)
		if !ok {
			t.Errorf("%s (%#08x): decoder returned ok=false", tc.name, tc.word)
			continue
		}
		if ins.Mnemonic != tc.mnemonic || ins.Operands != tc.operands || ins.Kind != tc.kind ||
			ins.Text != strings.TrimSpace(tc.mnemonic+" "+tc.operands) || ins.Size != 4 || ins.Address != base {
			t.Errorf("%s (%#08x): got %q / %q / %q / %q, want %q / %q / %q", tc.name, tc.word,
				ins.Text, ins.Mnemonic, ins.Operands, ins.Kind, tc.mnemonic, tc.operands, tc.kind)
		}
		if tc.target != 0 && (ins.Target == nil || *ins.Target != tc.target) {
			t.Errorf("%s (%#08x): target = %v, want %#x", tc.name, tc.word, ins.Target, tc.target)
		}
	}

	// A coprocessor instruction (MRC p15, ...) is deliberately out of scope.
	if _, ok := decodeARM32(0xee110f10, base); ok {
		t.Error("unimplemented coprocessor encoding was decoded")
	}
	// The dispatch path must expose the raw word in its error.
	_, err := decodeInstruction("arm", base, []byte{0x10, 0x0f, 0x11, 0xee})
	if err == nil || !strings.Contains(err.Error(), "ee110f10") {
		t.Errorf("expected raw ARM word in decode error, got %v", err)
	}
}

const arm32OracleSource = `
struct S { int a; int b; };
extern int helper(int);
int arr[16];
int compute(int n, struct S *s) {
    int total = 0;
    for (int i = 0; i < n; i++) total += arr[i] + s->a;
    switch (n) {
    case 0: total += helper(total); break;
    case 1: total -= 3; break;
    case 2: total ^= 0xff; break;
    default: total = ~total;
    }
    asm volatile("svc #0");
    return total;
}
`

func TestARM32OracleLLVM(t *testing.T) {
	clang, err := exec.LookPath("clang")
	if err != nil {
		t.Skip("clang is not installed")
	}
	objdump, err := exec.LookPath("llvm-objdump")
	if err != nil {
		t.Skip("llvm-objdump is not installed")
	}
	dir := t.TempDir()
	source := filepath.Join(dir, "oracle.c")
	object := filepath.Join(dir, "oracle.o")
	if err := os.WriteFile(source, []byte(arm32OracleSource), 0600); err != nil {
		t.Fatal(err)
	}
	compile := exec.Command(clang, "-target", "armv7-none-eabi", "-O1", "-fno-inline", "-c", source, "-o", object)
	if output, err := compile.CombinedOutput(); err != nil {
		t.Skipf("clang ARM object generation unavailable: %v\n%s", err, output)
	}
	disasm := exec.Command(objdump, "-d", "--triple=armv7-none-eabi", "--no-show-raw-insn", object)
	output, err := disasm.Output()
	if err != nil {
		t.Skipf("llvm-objdump ARM disassembly unavailable: %v", err)
	}

	words, err := arm32TextWords(object)
	if err != nil {
		t.Fatal(err)
	}
	oracle := parseARM32Objdump(string(output))
	if len(words) == 0 || len(oracle) == 0 {
		t.Fatalf("no .text instructions found: words=%d oracle=%d", len(words), len(oracle))
	}

	type mismatch struct {
		address uint64
		word    uint32
		ours    string
		llvm    string
	}
	var misses []mismatch
	matched := 0
	for address, word := range words {
		ours, ok := decodeARM32(word, address)
		ourText := "<undecoded>"
		if ok {
			ourText = ours.Mnemonic + " " + ours.Operands
		}
		llvmText, found := oracle[address]
		if !found {
			llvmText = "<missing>"
		}
		ourMnemonic, ourOperands := canonicalARM32Text(splitARM32Text(ourText))
		llvmMnemonic, llvmOperands := canonicalARM32Text(splitARM32Text(llvmText))
		if ourMnemonic != llvmMnemonic || normalizeARM32Operands(ourOperands) != normalizeARM32Operands(llvmOperands) {
			misses = append(misses, mismatch{address, word, strings.TrimSpace(ourText), llvmText})
			continue
		}
		matched++
	}
	for i, miss := range misses {
		if i >= 40 {
			break
		}
		t.Logf("ARM32 mismatch at %#x word %#08x: ours %q vs llvm %q", miss.address, miss.word, miss.ours, miss.llvm)
	}
	rate := float64(matched) / float64(len(words))
	t.Logf("ARM32 oracle match rate: %d/%d = %.3f (threshold 0.900)", matched, len(words), rate)
	if rate < 0.90 {
		t.Fatalf("ARM32 oracle match rate %.3f is below 0.900 (%d/%d matched)", rate, matched, len(words))
	}
}

func arm32TextWords(path string) (map[uint64]uint32, error) {
	file, err := elf.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	section := file.Section(".text")
	if section == nil {
		return nil, fmt.Errorf("object has no .text section")
	}
	data, err := section.Data()
	if err != nil {
		return nil, err
	}
	words := make(map[uint64]uint32)
	for offset := 0; offset+4 <= len(data); offset += 4 {
		words[section.Addr+uint64(offset)] = binary.LittleEndian.Uint32(data[offset:])
	}
	return words, nil
}

var (
	arm32ObjdumpLine  = regexp.MustCompile(`^\s*([0-9a-fA-F]+):\s+(?:[0-9a-fA-F]{8}\s+)?(\S+)(?:\s+(.*))?$`)
	arm32AngleSuffix  = regexp.MustCompile(`<[^>]*>`)
	arm32RegisterSpan = regexp.MustCompile(`\b(r\d+|sp|lr|pc)-(r\d+|sp|lr|pc)\b`)
	arm32Whitespace   = regexp.MustCompile(`\s+`)
)

func parseARM32Objdump(output string) map[uint64]string {
	result := make(map[uint64]string)
	for _, line := range strings.Split(output, "\n") {
		match := arm32ObjdumpLine.FindStringSubmatch(line)
		if match == nil {
			continue
		}
		address, err := strconv.ParseUint(match[1], 16, 64)
		if err != nil {
			continue
		}
		operands := match[3]
		if i := strings.IndexByte(operands, '@'); i >= 0 {
			operands = operands[:i]
		}
		operands = arm32AngleSuffix.ReplaceAllString(operands, " ")
		result[address] = strings.TrimSpace(match[2] + " " + arm32Whitespace.ReplaceAllString(operands, " "))
	}
	return result
}

func splitARM32Text(text string) (string, string) {
	fields := strings.Fields(strings.TrimSpace(text))
	if len(fields) == 0 {
		return "", ""
	}
	if len(fields) == 1 {
		return fields[0], ""
	}
	return fields[0], strings.Join(fields[1:], " ")
}

// canonicalARM32Text rewrites llvm-objdump's shift aliases (lsl r0, r1, #2)
// into the canonical "mov r0, r1, lsl #2" form used by our decoder.
func canonicalARM32Text(mnemonic, operands string) (string, string) {
	switch mnemonic {
	case "lsl", "lsr", "asr", "ror":
		if fields := strings.SplitN(operands, ", ", 3); len(fields) == 3 &&
			(strings.HasPrefix(fields[2], "#") || strings.HasPrefix(fields[2], "0x")) {
			return "mov", fields[0] + ", " + fields[1] + ", " + mnemonic + " " + strings.Replace(fields[2], "0x", "#0x", 1)
		}
	case "rrx":
		if fields := strings.SplitN(operands, ", ", 2); len(fields) == 2 {
			return "mov", fields[0] + ", " + fields[1] + ", rrx"
		}
	}
	return mnemonic, operands
}

// normalizeARM32Operands folds whitespace and the optional '#' immediate marker.
// Register ranges (r4-r7) are expanded because llvm-objdump prints each register
// separately while our decoder renders ranges as the ARM brief requests.
func normalizeARM32Operands(text string) string {
	text = arm32RegisterSpan.ReplaceAllStringFunc(text, func(span string) string {
		parts := strings.Split(span, "-")
		first, ok1 := arm32RegisterNumber(parts[0])
		last, ok2 := arm32RegisterNumber(parts[1])
		if !ok1 || !ok2 || last < first || last-first > 16 {
			return span
		}
		names := make([]string, 0, last-first+1)
		for n := first; n <= last; n++ {
			names = append(names, arm32RegisterName(n))
		}
		return strings.Join(names, ", ")
	})
	text = strings.ReplaceAll(text, "#", "")
	return arm32Whitespace.ReplaceAllString(strings.TrimSpace(text), " ")
}

func arm32RegisterNumber(name string) (int, bool) {
	switch name {
	case "sp":
		return 13, true
	case "lr":
		return 14, true
	case "pc":
		return 15, true
	}
	if !strings.HasPrefix(name, "r") {
		return 0, false
	}
	n, err := strconv.Atoi(name[1:])
	return n, err == nil && n >= 0 && n < 16
}

func arm32RegisterName(n int) string {
	switch n {
	case 13:
		return "sp"
	case 14:
		return "lr"
	case 15:
		return "pc"
	default:
		return "r" + strconv.Itoa(n)
	}
}
