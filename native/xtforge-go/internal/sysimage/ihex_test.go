package sysimage

import (
	"bytes"
	"fmt"
	"io"
	"strings"
	"testing"
)

// ihexLine builds one Intel HEX record and computes its checksum, so the tests
// do not hard-code checksums and quietly drift if a payload changes.
func ihexLine(count byte, addr uint16, typ byte, data []byte) string {
	var b strings.Builder
	fmt.Fprintf(&b, ":%02X%04X%02X", count, addr, typ)
	for _, value := range data {
		fmt.Fprintf(&b, "%02X", value)
	}
	sum := count + byte(addr>>8) + byte(addr) + typ
	for _, value := range data {
		sum += value
	}
	fmt.Fprintf(&b, "%02X", byte(0-sum))
	return b.String()
}

func TestIHEXSimpleRecords(t *testing.T) {
	first := make([]byte, 16)
	second := make([]byte, 16)
	for i := range first {
		first[i] = byte(i)
		second[i] = byte(0x10 + i)
	}
	source := strings.Join([]string{
		ihexLine(16, 0x0000, 0x00, first),
		ihexLine(16, 0x0010, 0x00, second),
		ihexLine(0, 0x0000, 0x01, nil),
	}, "\n") + "\n"

	img, err := ParseIHEX(strings.NewReader(source))
	if err != nil {
		t.Fatalf("ParseIHEX: %v", err)
	}
	if img.BadChecksums != 0 {
		t.Fatalf("BadChecksums = %d, want 0", img.BadChecksums)
	}
	if img.Records != 3 {
		t.Fatalf("Records = %d, want 3", img.Records)
	}
	if img.HasEntry {
		t.Fatal("HasEntry = true for a file without a start record")
	}
	if img.TotalSize != 32 {
		t.Fatalf("TotalSize = %d, want 32", img.TotalSize)
	}
	if len(img.Segments) != 1 {
		t.Fatalf("len(Segments) = %d, want 1 (adjacent records merge)", len(img.Segments))
	}
	segment := img.Segments[0]
	if segment.Start != 0 || segment.Size != 32 {
		t.Fatalf("segment = (start %#x, size %d), want (0, 32)", segment.Start, segment.Size)
	}
	want := append(append([]byte{}, first...), second...)
	if !bytes.Equal(segment.Bytes, want) {
		t.Fatalf("segment bytes = %x, want %x", segment.Bytes, want)
	}
}

func TestIHEXExtendedLinearAddress(t *testing.T) {
	data := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	source := strings.Join([]string{
		ihexLine(2, 0x0000, 0x04, []byte{0x08, 0x00}),
		ihexLine(4, 0x1234, 0x00, data),
		ihexLine(0, 0x0000, 0x01, nil),
	}, "\n")

	img, err := ParseIHEX(strings.NewReader(source))
	if err != nil {
		t.Fatalf("ParseIHEX: %v", err)
	}
	if len(img.Segments) != 1 {
		t.Fatalf("len(Segments) = %d, want 1", len(img.Segments))
	}
	if got := img.Segments[0].Start; got != 0x08001234 {
		t.Fatalf("Start = %#x, want 0x08001234", got)
	}
	if !bytes.Equal(img.Segments[0].Bytes, data) {
		t.Fatalf("Bytes = %x, want %x", img.Segments[0].Bytes, data)
	}
}

func TestIHEXExtendedSegmentAndWrap(t *testing.T) {
	source := strings.Join([]string{
		ihexLine(2, 0x0000, 0x02, []byte{0x00, 0x10}), // segment 0x10 -> base 0x100
		ihexLine(2, 0x0002, 0x00, []byte{0xAA, 0xBB}), // 0x102
		ihexLine(2, 0x0000, 0x00, []byte{0xCC, 0xDD}), // back to 0x100, out of order
		ihexLine(0, 0x0000, 0x01, nil),
	}, "\n")

	img, err := ParseIHEX(strings.NewReader(source))
	if err != nil {
		t.Fatalf("ParseIHEX: %v", err)
	}
	if len(img.Segments) != 1 {
		t.Fatalf("len(Segments) = %d, want 1 after sorting and merging", len(img.Segments))
	}
	if img.Segments[0].Start != 0x100 || img.Segments[0].Size != 4 {
		t.Fatalf("segment = (start %#x, size %d), want (0x100, 4)", img.Segments[0].Start, img.Segments[0].Size)
	}
	if got, want := img.Segments[0].Bytes, []byte{0xCC, 0xDD, 0xAA, 0xBB}; !bytes.Equal(got, want) {
		t.Fatalf("Bytes = %x, want %x", got, want)
	}

	// A record whose 16-bit address field wraps must not carry into the next
	// 64 KiB window: the tail starts again at the extended base.
	payload := bytes.Repeat([]byte{0x5A}, 16)
	wrapped := strings.Join([]string{
		ihexLine(16, 0xFFF8, 0x00, payload),
		ihexLine(0, 0x0000, 0x01, nil),
	}, "\n")
	img, err = ParseIHEX(strings.NewReader(wrapped))
	if err != nil {
		t.Fatalf("ParseIHEX (wrap): %v", err)
	}
	if len(img.Segments) != 2 {
		t.Fatalf("wrapped len(Segments) = %d, want 2", len(img.Segments))
	}
	if img.Segments[0].Start != 0 || img.Segments[0].Size != 8 {
		t.Fatalf("wrapped first segment = (%#x, %d), want (0, 8)", img.Segments[0].Start, img.Segments[0].Size)
	}
	if img.Segments[1].Start != 0xFFF8 || img.Segments[1].Size != 8 {
		t.Fatalf("wrapped second segment = (%#x, %d), want (0xfff8, 8)", img.Segments[1].Start, img.Segments[1].Size)
	}
}

func TestIHEXStartAddresses(t *testing.T) {
	tests := []struct {
		name string
		typ  byte
		data []byte
		want uint64
	}{
		{"start linear address", 0x05, []byte{0x12, 0x34, 0x56, 0x78}, 0x12345678},
		{"start segment address", 0x03, []byte{0x12, 0x34, 0x56, 0x78}, 0x1234<<4 + 0x5678},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			source := ihexLine(4, 0, test.typ, test.data) + "\n" + ihexLine(0, 0, 0x01, nil) + "\n"
			img, err := ParseIHEX(strings.NewReader(source))
			if err != nil {
				t.Fatalf("ParseIHEX: %v", err)
			}
			if !img.HasEntry || img.EntryPoint != test.want {
				t.Fatalf("HasEntry/EntryPoint = %v/%#x, want true/%#x", img.HasEntry, img.EntryPoint, test.want)
			}
			if len(img.Segments) != 0 || img.TotalSize != 0 {
				t.Fatalf("control records produced %d segments / %d bytes", len(img.Segments), img.TotalSize)
			}
		})
	}
}

func TestIHEXBadChecksum(t *testing.T) {
	good := ihexLine(2, 0x0000, 0x00, []byte{0x01, 0x02})
	bad := good[:len(good)-2]
	if good[len(good)-2:] == "00" {
		bad += "01"
	} else {
		bad += "00"
	}
	source := strings.Join([]string{
		good,
		bad,
		ihexLine(0, 0, 0x01, nil),
	}, "\n")

	img, err := ParseIHEX(strings.NewReader(source))
	if err != nil {
		t.Fatalf("ParseIHEX: %v", err)
	}
	if img.BadChecksums != 1 {
		t.Fatalf("BadChecksums = %d, want 1", img.BadChecksums)
	}
	if img.Records != 2 {
		t.Fatalf("Records = %d, want 2", img.Records)
	}
	if img.TotalSize != 2 || len(img.Segments) != 1 {
		t.Fatalf("bad record was not skipped: %d segments, %d bytes", len(img.Segments), img.TotalSize)
	}
	if !bytes.Equal(img.Segments[0].Bytes, []byte{0x01, 0x02}) {
		t.Fatalf("Bytes = %x, want 0102", img.Segments[0].Bytes)
	}
}

func TestIHEXTruncatedAndGarbage(t *testing.T) {
	good := ihexLine(2, 0x0010, 0x00, []byte{0xAB, 0xCD})
	source := strings.Join([]string{
		"garbage line with no colon",
		good,
		":10000000AABB", // declares 16 bytes but ends after two
		":0",            // odd-length payload
		"",
	}, "\n") // no trailing newline: the last line is truncated too

	img, err := ParseIHEX(strings.NewReader(source))
	if err != nil {
		t.Fatalf("ParseIHEX: %v", err)
	}
	if img.BadChecksums != 2 {
		t.Fatalf("BadChecksums = %d, want 2 (truncated and odd-length)", img.BadChecksums)
	}
	if img.Records != 1 {
		t.Fatalf("Records = %d, want 1", img.Records)
	}
	if len(img.Segments) != 1 || img.Segments[0].Start != 0x10 {
		t.Fatalf("segments = %+v, want one at 0x10", img.Segments)
	}
	if !bytes.Equal(img.Segments[0].Bytes, []byte{0xAB, 0xCD}) {
		t.Fatalf("Bytes = %x, want abcd", img.Segments[0].Bytes)
	}
}

func TestIsIHEX(t *testing.T) {
	record := ihexLine(0, 0, 0x01, nil)
	if !IsIHEX([]byte(record)) {
		t.Fatal("a valid record was not recognised as Intel HEX")
	}
	if !IsIHEX([]byte("garbage\n" + record + "\r\n")) {
		t.Fatal("a valid record after a junk line was not recognised")
	}
	for name, data := range map[string][]byte{
		"empty":     nil,
		"noise":     {0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE, 0x00, 0x11},
		"mach-o":    {0xCF, 0xFA, 0xED, 0xFE, 0x0C, 0x00, 0x00, 0x01},
		"lowercase": []byte(strings.ToLower(record)),
	} {
		if IsIHEX(data) {
			t.Fatalf("IsIHEX true for %s", name)
		}
	}
}

// repeatedIHEXLine streams one record many times without materialising a
// multi-megabyte test fixture in memory.
type repeatedIHEXLine struct {
	line []byte
	pos  int
	left int
}

func (r *repeatedIHEXLine) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	for r.pos >= len(r.line) {
		r.pos = 0
		r.left--
		if r.left == 0 {
			return 0, io.EOF
		}
	}
	n := copy(p, r.line[r.pos:])
	r.pos += n
	return n, nil
}

func TestParseIHEXOverLimit(t *testing.T) {
	payload := bytes.Repeat([]byte{0xA5}, 255)
	line := []byte(ihexLine(255, 0x0000, 0x00, payload) + "\n")
	reader := &repeatedIHEXLine{line: line, left: 66000} // > 16 MiB of declared data
	if _, err := ParseIHEX(reader); err == nil {
		t.Fatal("ParseIHEX accepted more than 16 MiB of decoded data")
	}
}
