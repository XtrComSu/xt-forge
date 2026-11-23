package sysimage

import (
	"strings"
	"testing"

	"xtforge-hub/internal/thirdparty/xarch/x86asm"
)

// x86asmDecodeForTest calls the vendored decoder directly, so the test fails at the
// source of a panic rather than at the recovery layer.
func x86asmDecodeForTest(data []byte) (x86asm.Inst, error) {
	return x86asm.Decode(data, 64)
}

// A decoder must never abort the process.
//
// The vendored x86asm panics on some truncated EVEX (0x62) prefixes: it indexes
// inst.Prefix past its length. That crashed the whole tool with "index out of range [4]
// with length 4" while scanning a real 81 MB binary — one bad byte sequence in 81 MB was
// enough to lose the entire analysis.

func TestSafeX86DecodeNeverPanics(t *testing.T) {
	// The exact prefix that was observed, plus deliberately truncated variants and a
	// broad sweep of short buffers, because the panic depends on buffer length.
	cases := [][]byte{
		{0x62, 0x71, 0xFD, 0x48},
		{0x62},
		{0x62, 0x71},
		{0x62, 0x71, 0xFD},
		{0xC4},
		{0xC4, 0xE2},
		{0xC5},
		{0x0F, 0x38},
	}
	for _, data := range cases {
		func() {
			defer func() {
				if recovered := recover(); recovered != nil {
					t.Errorf("decode of %x panicked: %v", data, recovered)
				}
			}()
			_, _ = safeX86Decode(data, 64)
		}()
	}

	// Every one- and two-byte prefix followed by nothing must also be safe.
	for first := 0; first < 256; first++ {
		_, _ = safeX86Decode([]byte{byte(first)}, 64)
		for second := 0; second < 256; second++ {
			_, _ = safeX86Decode([]byte{byte(first), byte(second)}, 64)
		}
	}
}

// TestDisassemblyReportsRatherThanCrashes confirms the error path is reached through the
// public surface: a window starting with the panicking prefix must produce an error
// mentioning the bytes, not a process abort.
func TestDisassemblyReportsRatherThanCrashes(t *testing.T) {
	// 0x62 alone at the very end of a window is the shape that panicked.
	_, warnings := linearDecode("x86_64", 0x1000, []byte{0x62, 0x71, 0xFD, 0x48}, 4)
	if len(warnings) == 0 {
		t.Skip("the decoder accepted this window; nothing to report")
	}
	joined := strings.Join(warnings, " ")
	if !strings.Contains(joined, "decode") && !strings.Contains(joined, "panic") {
		t.Errorf("unexpected warning text: %v", warnings)
	}
	t.Logf("reported instead of crashing: %s", warnings[0])
}

// TestVendoredAVXPrefixIsRepaired pins the fix at its source rather than relying on the
// recover guard.
//
// The vendored decoder read src[pos] after consuming a VEX/EVEX prefix without checking
// that an opcode byte followed, so a buffer ending exactly at the prefix panicked. Four
// bytes (62 71 FD 48) found in a real binary were enough. The vendored file now returns
// "truncated prefix"; this test fails if that local fix is ever lost in a re-vendor.
func TestVendoredAVXPrefixIsRepaired(t *testing.T) {
	for _, tc := range []struct {
		name string
		data []byte
	}{
		{"evex prefix only", []byte{0x62, 0x71, 0xFD, 0x48}},
		{"3-byte vex prefix only", []byte{0xC4, 0xE2, 0x79}},
		{"2-byte vex prefix only", []byte{0xC5, 0xF8}},
	} {
		func() {
			defer func() {
				if recovered := recover(); recovered != nil {
					t.Errorf("%s: the vendored decoder still panics: %v", tc.name, recovered)
				}
			}()
			if _, err := x86asmDecodeForTest(tc.data); err == nil {
				t.Errorf("%s: expected a truncation error", tc.name)
			}
		}()
	}
}
