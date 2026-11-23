package sysimage

import (
	"debug/elf"
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

func TestThumbHandEncoded(t *testing.T) {
	const base = 0x1001 // Thumb entry points may be odd; alignment must not be enforced.
	cases := []struct {
		name     string
		bytes    []byte
		mnemonic string
		operands string
		kind     string
		target   uint64
		wantSize int
	}{
		{"movs r0, #1", []byte{0x01, 0x20}, "movs", "r0, #0x1", "", 0, 2},
		{"cmp r0, #0", []byte{0x00, 0x28}, "cmp", "r0, #0x0", "", 0, 2},
		{"bx lr", []byte{0x70, 0x47}, "bx", "lr", "return", 0, 2},
		{"push {r4, lr}", []byte{0x10, 0xb5}, "push", "{r4, lr}", "", 0, 2},
		{"pop {r4, pc}", []byte{0x10, 0xbd}, "pop", "{r4, pc}", "return", 0, 2},
		{"b .+8", []byte{0x02, 0xe0}, "b", "0x1009", "jump", base + 8, 2},
		{"bl .+8", []byte{0x00, 0xf0, 0x02, 0xf8}, "bl", "0x1009", "call", base + 8, 4},
		{"b.w .+14", []byte{0x00, 0xf0, 0x07, 0xb8}, "b.w", "0x1013", "jump", base + 18, 4},
		{"bne.w .+6", []byte{0x40, 0xf0, 0x03, 0x80}, "bne.w", "0x100b", "jump", base + 10, 4},
		{"ldr r0, [pc, #4]", []byte{0x01, 0x48}, "ldr", "r0, [pc, #0x4]", "", 0, 2},
		{"strh r0, [r1, #2]", []byte{0x48, 0x80}, "strh", "r0, [r1, #0x2]", "", 0, 2},
		{"ldrh r0, [r1, #2]", []byte{0x48, 0x88}, "ldrh", "r0, [r1, #0x2]", "", 0, 2},
		{"svc #1", []byte{0x01, 0xdf}, "svc", "#0x1", "trap", 0, 2},
		{"udf #7", []byte{0x07, 0xde}, "udf", "#0x7", "trap", 0, 2},
		{"ldr.w r0, [r1, #0x10]", []byte{0xd1, 0xf8, 0x10, 0x00}, "ldr.w", "r0, [r1, #0x10]", "", 0, 4},
		{"str.w r2, [r1, #0x14]", []byte{0xc1, 0xf8, 0x14, 0x20}, "str.w", "r2, [r1, #0x14]", "", 0, 4},
		{"ldr r0, [r1, #-8]", []byte{0x51, 0xf8, 0x08, 0x0c}, "ldr", "r0, [r1, #-8]", "", 0, 4},
		{"str r0, [r1, #-4]", []byte{0x41, 0xf8, 0x04, 0x0c}, "str", "r0, [r1, #-4]", "", 0, 4},
		{"movw r1, #0x1634", []byte{0x41, 0xf2, 0x34, 0x61}, "movw", "r1, #0x1634", "", 0, 4},
		{"movt r2, #0x1234", []byte{0xc1, 0xf2, 0x34, 0x22}, "movt", "r2, #0x1234", "", 0, 4},
		{"add.w r0, r1, #0x40", []byte{0x01, 0xf1, 0x40, 0x00}, "add.w", "r0, r1, #0x40", "", 0, 4},
		{"sub.w r0, r2, #0x64", []byte{0xa2, 0xf1, 0x64, 0x00}, "sub.w", "r0, r2, #0x64", "", 0, 4},
		{"ldm.w r0!, {r4, r5, r6, r7}", []byte{0xb0, 0xe8, 0xf0, 0x00}, "ldm.w", "r0!, {r4, r5, r6, r7}", "", 0, 4},
		{"stm.w r1!, {r2, r3, r4, r5}", []byte{0xa1, 0xe8, 0x3c, 0x00}, "stm.w", "r1!, {r2, r3, r4, r5}", "", 0, 4},
		{"push.w {r4, r5, r6, r7, lr}", []byte{0x2d, 0xe9, 0xf0, 0x40}, "push.w", "{r4, r5, r6, r7, lr}", "", 0, 4},
		{"pop.w {r4, r5, r6, r7, pc}", []byte{0xbd, 0xe8, 0xf0, 0x80}, "pop.w", "{r4, r5, r6, r7, pc}", "return", 0, 4},
	}
	for _, tc := range cases {
		ins, length, ok := decodeThumb(tc.bytes, base)
		if !ok {
			t.Errorf("%s: decoder returned ok=false", tc.name)
			continue
		}
		if ins.Mnemonic != tc.mnemonic || ins.Operands != tc.operands || ins.Kind != tc.kind ||
			ins.Text != strings.TrimSpace(tc.mnemonic+" "+tc.operands) ||
			ins.Size != tc.wantSize || length != tc.wantSize || ins.Address != base {
			t.Errorf("%s: got %q / %q / %q / size %d (length %d), want %q / %q / %q / size %d", tc.name,
				ins.Text, ins.Mnemonic, ins.Operands, ins.Size, length,
				tc.mnemonic, tc.operands, tc.kind, tc.wantSize)
		}
		if tc.target != 0 && (ins.Target == nil || *ins.Target != tc.target) {
			t.Errorf("%s: target = %v, want %#x", tc.name, ins.Target, tc.target)
		}
	}

	// NOP hint: deliberately out of scope, so it must be refused instead of guessed.
	if _, length, ok := decodeThumb([]byte{0x00, 0xbf}, base); ok || length != 0 {
		t.Error("unimplemented 0xbf00 encoding was decoded")
	}
	// A 32-bit form with only a two-byte tail must fail without reading past the slice.
	if _, length, ok := decodeThumb([]byte{0x00, 0xf0}, base); ok || length != 0 {
		t.Error("truncated BL was decoded")
	}
	if _, length, ok := decodeThumb([]byte{0xd0, 0xf8}, base); ok || length != 0 {
		t.Error("truncated ldr.w was decoded")
	}
	// Writeback/unprivileged load-store forms and unknown MOVW tails stay refused.
	for name, bytes := range map[string][]byte{
		"ldr.w writeback": {0x51, 0xf8, 0x08, 0x0d},
		"movw bad tail":   {0x41, 0xf2, 0x34, 0xe1},
		"unknown e800":    {0x00, 0xe8, 0x00, 0x00},
	} {
		if _, length, ok := decodeThumb(bytes, base); ok || length != 0 {
			t.Errorf("unimplemented %s encoding was decoded", name)
		}
	}
	if _, _, ok := decodeThumb([]byte{0x01}, base); ok {
		t.Error("single byte was decoded")
	}

	for _, arch := range []string{"thumb", "arm-thumb"} {
		ins, err := decodeInstruction(arch, base, []byte{0x70, 0x47})
		if err != nil || ins.Mnemonic != "bx" || ins.Operands != "lr" || ins.Size != 2 {
			t.Errorf("decodeInstruction(%q) = %+v, %v", arch, ins, err)
		}
	}
}

const thumbOracleSource = `
struct Pair { volatile int x; int y; };
extern int helper(int);
int loop_switch(struct Pair *p, int n) {
    int total = 0;
    while (n > 0) {
        total += p->x;
        n--;
    }
    switch (n) {
    case -1: total += helper(total); break;
    case -2: total -= 3; break;
    case -3: total ^= p->y; break;
    default: total = ~total;
    }
    asm volatile("svc #0");
    return total;
}

/* Every Thumb-2 form under test, spelled out so the fixture cannot depend on
 * optimiser heuristics. The repeated groups also exercise wide register lists. */
__attribute__((naked)) void thumb2_forms(void) {
    asm volatile(
        ".rept 4\n"
        ".inst 0xf8d00010\n" // ldr.w r0, [r0, #0x10]
        ".inst 0xf8c12014\n" // str.w r2, [r1, #0x14]
        ".inst 0xf8510c08\n" // ldr r0, [r1, #-8]
        ".inst 0xf8410c04\n" // str r0, [r1, #-4]
        ".inst 0xf2416134\n" // movw r1, #0x1634
        ".inst 0xf2c22234\n" // movt r2, #0x1234
        ".inst 0xf1010040\n" // add.w r0, r1, #0x40
        ".inst 0xf1a20064\n" // sub.w r0, r2, #0x64
        ".inst 0xe8b000f0\n" // ldm.w r0!, {r4, r5, r6, r7}
        ".inst 0xe8a1003c\n" // stm.w r1!, {r2, r3, r4, r5}
        ".inst 0xe92d40f0\n" // push.w {r4, r5, r6, r7, lr}
        ".inst 0xe8bd80f0\n" // pop.w {r4, r5, r6, r7, pc}
        ".endr\n"
        ".inst 0x4770\n"     // bx lr
    );
}

int sum_pairs(struct Pair *p, int n) {
    int sum = 0;
    for (int i = 0; i < n; i++) {
        sum += p[i].x + p[i].y;
    }
    return sum;
}
`

func TestThumbOracleLLVM(t *testing.T) {
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
	if err := os.WriteFile(source, []byte(thumbOracleSource), 0600); err != nil {
		t.Fatal(err)
	}
	compile := exec.Command(clang, "-target", "thumbv7-none-eabi", "-mthumb", "-O1", "-fno-inline", "-c", source, "-o", object)
	if output, err := compile.CombinedOutput(); err != nil {
		t.Skipf("clang Thumb object generation unavailable: %v\n%s", err, output)
	}
	disasm := exec.Command(objdump, "-d", "--triple=thumbv7-none-eabi", "--no-show-raw-insn", object)
	output, err := disasm.Output()
	if err != nil {
		t.Skipf("llvm-objdump Thumb disassembly unavailable: %v", err)
	}

	data, sectionAddr, err := thumbTextData(object)
	if err != nil {
		t.Fatal(err)
	}
	oracle := parseThumbObjdump(string(output))
	if len(data) == 0 || len(oracle) == 0 {
		t.Fatalf("no .text instructions found: bytes=%d oracle=%d", len(data), len(oracle))
	}
	addresses := make([]uint64, 0, len(oracle))
	for address := range oracle {
		addresses = append(addresses, address)
	}
	sort.Slice(addresses, func(i, j int) bool { return addresses[i] < addresses[j] })

	type mismatch struct {
		address uint64
		bytes   string
		ours    string
		llvm    string
	}
	var misses []mismatch
	matched, seen := 0, 0
	for offset := 0; offset < len(data); {
		pc := sectionAddr + uint64(offset)
		ins, length, ok := decodeThumb(data[offset:], pc)
		if !ok || length < 2 || length > 4 || length > len(data)-offset {
			// Unknown encodings still have to be stepped over with the oracle's
			// instruction boundary so the rest of .text stays in sync.
			length = thumbBoundary(pc, addresses, len(data)-offset)
		}
		llvmText, found := oracle[pc]
		if found {
			seen++
			ourText := "<undecoded>"
			if ok {
				ourText = strings.TrimSpace(ins.Mnemonic + " " + ins.Operands)
			}
			ourMnemonic, ourOperands := splitThumbText(ourText)
			llvmMnemonic, llvmOperands := splitThumbText(llvmText)
			if ourMnemonic != llvmMnemonic || normalizeThumbOperands(ourOperands) != normalizeThumbOperands(llvmOperands) {
				misses = append(misses, mismatch{pc, fmt.Sprintf("%04x", binary.LittleEndian.Uint16(data[offset:])), ourText, llvmText})
			} else {
				matched++
			}
		}
		offset += length
	}
	for i, miss := range misses {
		if i >= 40 {
			break
		}
		t.Logf("Thumb mismatch at %#x (%s): ours %q vs llvm %q", miss.address, miss.bytes, miss.ours, miss.llvm)
	}
	rate := float64(matched) / float64(len(oracle))
	t.Logf("Thumb oracle match rate: %d/%d = %.3f (threshold 0.900)", matched, len(oracle), rate)
	if seen != len(oracle) {
		t.Errorf("walked %d of %d oracle instructions", seen, len(oracle))
	}
	if rate < 0.90 {
		t.Fatalf("Thumb oracle match rate %.3f is below 0.900 (%d/%d matched)", rate, matched, len(oracle))
	}
}

func thumbTextData(path string) ([]byte, uint64, error) {
	file, err := elf.Open(path)
	if err != nil {
		return nil, 0, err
	}
	defer file.Close()
	section := file.Section(".text")
	if section == nil {
		return nil, 0, fmt.Errorf("object has no .text section")
	}
	data, err := section.Data()
	if err != nil {
		return nil, 0, err
	}
	return data, section.Addr, nil
}

func thumbBoundary(address uint64, addresses []uint64, remaining int) int {
	for _, next := range addresses {
		if next > address {
			if size := int(next - address); size == 2 || size == 4 && size <= remaining {
				return size
			}
			return 2
		}
	}
	if remaining >= 4 {
		return 4
	}
	return 2
}

var (
	thumbObjdumpLine = regexp.MustCompile(`^\s*([0-9a-fA-F]+):\s+(?:[0-9a-fA-F]{4}\s+)?(\S+)(?:\s+(.*))?$`)
	thumbAngleSuffix = regexp.MustCompile(`<[^>]*>`)
	thumbWhitespace  = regexp.MustCompile(`\s+`)
)

func parseThumbObjdump(output string) map[uint64]string {
	result := make(map[uint64]string)
	for _, line := range strings.Split(output, "\n") {
		match := thumbObjdumpLine.FindStringSubmatch(line)
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
		operands = thumbAngleSuffix.ReplaceAllString(operands, " ")
		result[address] = strings.TrimSpace(match[2] + " " + thumbWhitespace.ReplaceAllString(operands, " "))
	}
	return result
}

func splitThumbText(text string) (string, string) {
	fields := strings.Fields(strings.TrimSpace(text))
	if len(fields) == 0 {
		return "", ""
	}
	if len(fields) == 1 {
		return fields[0], ""
	}
	return fields[0], strings.Join(fields[1:], " ")
}

// normalizeThumbOperands folds whitespace and the optional '#' immediate marker.
// Mnemonics are never normalised: movs must match movs, not mov.
func normalizeThumbOperands(text string) string {
	text = strings.ReplaceAll(text, "#", "")
	return thumbWhitespace.ReplaceAllString(strings.TrimSpace(text), " ")
}
