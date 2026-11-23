package sysimage

import (
	"encoding/binary"
	"testing"
)

func TestELFUnwindStartRelativeToHeader(t *testing.T) {
	data := []byte{1, 0x1b, 0x03, 0x3b, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	delta := int32(-0x500)
	binary.LittleEndian.PutUint32(data[12:], uint32(delta))
	binary.LittleEndian.PutUint32(data[16:], 0x100)
	starts, err := ehFrameStarts(data, binary.LittleEndian, 0x2000)
	if err != nil || len(starts) != 1 || starts[0] != 0x1b00 {
		t.Fatalf("starts: %v, error: %v", starts, err)
	}
	if _, err := ehFrameStarts(data[:len(data)-1], binary.LittleEndian, 0x2000); err == nil {
		t.Fatal("truncated pair was accepted")
	}
}
