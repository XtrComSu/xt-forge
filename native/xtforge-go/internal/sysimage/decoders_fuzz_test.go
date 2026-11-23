package sysimage

import (
	"math/rand"
	"testing"
	"xtforge-hub/internal/thirdparty/xarch/arm64asm"
)

// TestFuzzDecoders asserts that no decoder aborts the process on arbitrary input.
//
// A vendored x86 decoder already panicked once on a real binary (VEX/EVEX prefix with no
// opcode byte), and that cost the whole run. 800,000 random inputs across the four
// decoders is the cheapest insurance available against the next one.
func TestFuzzDecoders(t *testing.T) {
	rng := rand.New(rand.NewSource(42))
	panics := map[string]string{}
	record := func(which string, err interface{}) {
		if _, seen := panics[which]; !seen {
			panics[which] = err.(error).Error()
		}
	}
	// x86 via the guard
	for i := 0; i < 200000; i++ {
		n := 1 + rng.Intn(15)
		buf := make([]byte, n)
		rng.Read(buf)
		func() {
			defer func() {
				if r := recover(); r != nil {
					record("safeX86Decode", r)
				}
			}()
			_, _ = safeX86Decode(buf, 64)
		}()
	}
	// arm64: fixed 4 bytes
	for i := 0; i < 200000; i++ {
		var buf [4]byte
		rng.Read(buf[:])
		func() {
			defer func() {
				if r := recover(); r != nil {
					record("arm64asm", r)
				}
			}()
			_, _ = arm64asm.Decode(buf[:])
		}()
	}
	// our A32
	for i := 0; i < 200000; i++ {
		word := rng.Uint32()
		func() {
			defer func() {
				if r := recover(); r != nil {
					record("decodeARM32", r)
				}
			}()
			_, _ = decodeARM32(word, 0x1000)
		}()
	}
	// our Thumb: 1..8 bytes
	for i := 0; i < 200000; i++ {
		n := 1 + rng.Intn(8)
		buf := make([]byte, n)
		rng.Read(buf)
		func() {
			defer func() {
				if r := recover(); r != nil {
					record("decodeThumb", r)
				}
			}()
			_, _, _ = decodeThumb(buf, 0x1000)
		}()
	}
	if len(panics) > 0 {
		for k, v := range panics {
			t.Errorf("%s panicked: %s", k, v)
		}
	}
}
