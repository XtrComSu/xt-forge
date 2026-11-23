package sysimage

import (
	"fmt"
	"strings"
	"testing"
)

// srecTestLine builds an S-record with a computed checksum, so the expected
// bytes below are not copied from a fixture with an opaque checksum.
func srecTestLine(t *testing.T, typ byte, addr uint64, data []byte) string {
	t.Helper()
	var addrLen int
	switch typ {
	case '0', '1', '5', '9':
		addrLen = 2
	case '2', '6', '8':
		addrLen = 3
	case '3', '7':
		addrLen = 4
	default:
		t.Fatalf("unknown test record type S%c", typ)
	}
	if len(data)+addrLen+1 > 255 {
		t.Fatalf("test record too long: %d data bytes", len(data))
	}
	body := make([]byte, 1+addrLen+len(data))
	body[0] = byte(len(body)) // count: address + data + checksum
	for i := 0; i < addrLen; i++ {
		body[1+i] = byte(addr >> (8 * (addrLen - 1 - i)))
	}
	copy(body[1+addrLen:], data)
	var sum byte
	for _, b := range body {
		sum += b
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "S%c%02X", typ, body[0])
	for _, b := range body[1:] {
		fmt.Fprintf(&sb, "%02X", b)
	}
	fmt.Fprintf(&sb, "%02X", ^sum)
	return sb.String()
}

func TestSRECS1TwoRecords(t *testing.T) {
	input := srecTestLine(t, '1', 0x1000, []byte("Hello")) + "\n" +
		srecTestLine(t, '1', 0x1005, []byte(" world")) + "\n"
	img, err := ParseSREC(strings.NewReader(input))
	if err != nil {
		t.Fatalf("ParseSREC: %v", err)
	}
	if len(img.Segments) != 1 {
		t.Fatalf("segments = %d, want 1", len(img.Segments))
	}
	seg := img.Segments[0]
	if seg.Start != 0x1000 {
		t.Errorf("Start = %#x, want 0x1000", seg.Start)
	}
	if got := string(seg.Bytes); got != "Hello world" {
		t.Errorf("Bytes = %q, want %q", got, "Hello world")
	}
	if seg.Size != 11 || img.TotalSize != 11 {
		t.Errorf("sizes = (%d, %d), want (11, 11)", seg.Size, img.TotalSize)
	}
	if img.Records != 2 || img.BadRecords != 0 {
		t.Errorf("records/bad = %d/%d, want 2/0", img.Records, img.BadRecords)
	}
}

func TestSRECAddressWidths(t *testing.T) {
	cases := []struct {
		typ  byte
		addr uint64
	}{
		{'2', 0x010203},
		{'3', 0xDEADBEEF},
	}
	for _, tc := range cases {
		input := srecTestLine(t, tc.typ, tc.addr, []byte{0xAA, 0xBB}) + "\n"
		img, err := ParseSREC(strings.NewReader(input))
		if err != nil {
			t.Fatalf("type %c: ParseSREC: %v", tc.typ, err)
		}
		if len(img.Segments) != 1 {
			t.Fatalf("type %c: segments = %d, want 1", tc.typ, len(img.Segments))
		}
		if got := img.Segments[0].Start; got != tc.addr {
			t.Errorf("type %c: Start = %#x, want %#x", tc.typ, got, tc.addr)
		}
	}
}

func TestSRECEntryPoint(t *testing.T) {
	cases := []struct {
		typ  byte
		addr uint64
	}{
		{'7', 0xDEADBEEF},
		{'8', 0xABCDEF},
		{'9', 0x1234},
	}
	for _, tc := range cases {
		input := srecTestLine(t, '1', 0x2000, []byte{1, 2}) + "\n" +
			srecTestLine(t, tc.typ, tc.addr, nil) + "\n"
		img, err := ParseSREC(strings.NewReader(input))
		if err != nil {
			t.Fatalf("type %c: ParseSREC: %v", tc.typ, err)
		}
		if !img.HasEntry || img.EntryPoint != tc.addr {
			t.Errorf("type %c: entry = (%v, %#x), want (true, %#x)", tc.typ, img.HasEntry, img.EntryPoint, tc.addr)
		}
		if img.TotalSize != 2 {
			t.Errorf("type %c: TotalSize = %d, want 2", tc.typ, img.TotalSize)
		}
	}
}

func TestSRECHeaderCounted(t *testing.T) {
	input := srecTestLine(t, '0', 0, []byte("HDR\x00\x00")) + "\n" +
		srecTestLine(t, '1', 0x3000, []byte{0x11, 0x22}) + "\n"
	img, err := ParseSREC(strings.NewReader(input))
	if err != nil {
		t.Fatalf("ParseSREC: %v", err)
	}
	if img.Records != 2 || img.BadRecords != 0 {
		t.Errorf("records/bad = %d/%d, want 2/0", img.Records, img.BadRecords)
	}
	if len(img.Segments) != 1 || img.Segments[0].Start != 0x3000 {
		t.Fatalf("header produced data segments: %+v", img.Segments)
	}
	if img.TotalSize != 2 {
		t.Errorf("TotalSize = %d, want 2", img.TotalSize)
	}
}

func TestSRECBadChecksum(t *testing.T) {
	good1 := srecTestLine(t, '1', 0x4000, []byte("ab"))
	good2 := srecTestLine(t, '1', 0x4002, []byte("cd"))
	good3 := srecTestLine(t, '1', 0x4004, []byte("ef"))
	replacement := byte('0')
	if good2[len(good2)-1] == '0' {
		replacement = '1'
	}
	bad := good2[:len(good2)-1] + string(replacement)
	input := strings.Join([]string{good1, bad, good3}, "\n") + "\n"

	img, err := ParseSREC(strings.NewReader(input))
	if err != nil {
		t.Fatalf("ParseSREC: %v", err)
	}
	if img.BadRecords != 1 || img.Records != 2 {
		t.Errorf("records/bad = %d/%d, want 2/1", img.Records, img.BadRecords)
	}
	// The skipped record leaves a gap, so the good records stay separate.
	if img.TotalSize != 4 || len(img.Segments) != 2 {
		t.Fatalf("total/segments = %d/%d, want 4/2", img.TotalSize, len(img.Segments))
	}
	if got := string(img.Segments[0].Bytes); got != "ab" {
		t.Errorf("first Bytes = %q, want %q", got, "ab")
	}
	if got := string(img.Segments[1].Bytes); got != "ef" {
		t.Errorf("second Bytes = %q, want %q", got, "ef")
	}
}

func TestSRECTruncatedAndGarbage(t *testing.T) {
	input := "S1130ABC\n" + // declares a full payload that is not there
		"this is not an s-record\n" +
		"S1\n" + // no count field
		"\n" +
		srecTestLine(t, '1', 0x5000, []byte("ok")) + "\n" +
		"S11300" // truncated final line, no newline
	img, err := ParseSREC(strings.NewReader(input))
	if err != nil {
		t.Fatalf("ParseSREC: %v", err)
	}
	if img.BadRecords != 3 || img.Records != 1 {
		t.Errorf("records/bad = %d/%d, want 1/3", img.Records, img.BadRecords)
	}
	if len(img.Segments) != 1 || string(img.Segments[0].Bytes) != "ok" {
		t.Errorf("unexpected segments: %+v", img.Segments)
	}
}

func TestIsSREC(t *testing.T) {
	valid := srecTestLine(t, '1', 0x1000, []byte("hello")) + "\n" +
		srecTestLine(t, '9', 0x1000, nil) + "\n"
	if !IsSREC([]byte(valid)) {
		t.Error("valid S-record file not detected")
	}
	if !IsSREC([]byte(strings.ToLower(valid))) {
		t.Error("lowercase S-record file not detected")
	}
	if !IsSREC([]byte("S11300A1")) {
		t.Error("short valid prefix not detected")
	}
	for name, head := range map[string][]byte{
		"intel hex": []byte(":10010000214601360121470136007EFE09D2190140\n:00000001FF\n"),
		"binary":    {0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00, 0x00, 0x00},
		"empty":     {},
		"noise":     []byte("not a firmware format\njust some words\n"),
	} {
		if IsSREC(head) {
			t.Errorf("%s detected as S-record", name)
		}
	}
}

func TestParseSRECOverLimit(t *testing.T) {
	payload := make([]byte, 250) // maximum data bytes in an S3 record
	line := srecTestLine(t, '3', 0x1000, payload) + "\n"
	count := srecMaxBytes/len(payload) + 2
	img, err := ParseSREC(strings.NewReader(strings.Repeat(line, count)))
	if err == nil {
		t.Fatalf("ParseSREC accepted %d bytes (cap %d)", count*len(payload), srecMaxBytes)
	}
	if img.TotalSize > srecMaxBytes {
		t.Errorf("TotalSize = %d, cap %d", img.TotalSize, srecMaxBytes)
	}
}
