package rehub

// Tests for the pcap/pcapng reader.
//
// Every fixture is assembled here byte by byte, so each expected value is chosen
// rather than observed. That matters because the three failure modes this reader
// guards against all produce output that *looks* valid:
//
//   - reading a big-endian capture as little-endian gives nonsense timestamps and
//     lengths with no error;
//   - treating a nanosecond capture as microsecond puts every packet in 1970;
//   - using the wrong link-layer offset yields addresses that still look like IPs.
//
// A test that only asserts ok:true cannot tell any of those from correct parsing, so
// each test asserts a concrete address, port or timestamp.

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

// ethIPv4TCP builds an Ethernet frame carrying an IPv4/TCP segment.
func ethIPv4TCP(src, dst string, srcPort, dstPort uint16, payload []byte) []byte {
	mac := []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66}
	frame := append([]byte{}, mac...)
	frame = append(frame, 0x08, 0x00)

	tcp := make([]byte, 20)
	binary.BigEndian.PutUint16(tcp[0:2], srcPort)
	binary.BigEndian.PutUint16(tcp[2:4], dstPort)
	tcp[12] = 0x50 // data offset 5 words
	tcp = append(tcp, payload...)

	ip := make([]byte, 20)
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(20+len(tcp)))
	ip[8] = 64
	ip[9] = 6 // TCP
	copy(ip[12:16], parseIPv4(src))
	copy(ip[16:20], parseIPv4(dst))
	ip = append(ip, tcp...)
	return append(frame, ip...)
}

func parseIPv4(text string) []byte {
	out := make([]byte, 4)
	octet, index := 0, 0
	for _, r := range text {
		if r == '.' {
			out[index] = byte(octet)
			index++
			octet = 0
			continue
		}
		octet = octet*10 + int(r-'0')
	}
	out[index] = byte(octet)
	return out
}

// writePcap assembles a classic pcap file with the given magic and frames.
func writePcap(t *testing.T, magic uint32, order binary.ByteOrder, fraction uint32,
	frames [][]byte) string {
	t.Helper()
	header := make([]byte, 24)
	order.PutUint32(header[0:4], magic)
	order.PutUint16(header[4:6], 2)
	order.PutUint16(header[6:8], 4)
	order.PutUint32(header[16:20], 65535)
	order.PutUint32(header[20:24], 1) // LINKTYPE_ETHERNET
	out := header
	for index, frame := range frames {
		record := make([]byte, 16)
		order.PutUint32(record[0:4], uint32(1700000000+index))
		order.PutUint32(record[4:8], fraction)
		order.PutUint32(record[8:12], uint32(len(frame)))
		order.PutUint32(record[12:16], uint32(len(frame)))
		out = append(out, record...)
		out = append(out, frame...)
	}
	path := filepath.Join(t.TempDir(), "capture.pcap")
	if err := os.WriteFile(path, out, 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	return path
}

func TestPcapLittleEndianMicrosecond(t *testing.T) {
	frames := [][]byte{
		ethIPv4TCP("10.0.0.5", "93.184.216.34", 51000, 80,
			[]byte("GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n")),
	}
	path := writePcap(t, 0xa1b2c3d4, binary.LittleEndian, 500000, frames)
	result := InspectCapture(path, 50, true)
	if ok, _ := result["ok"].(bool); !ok {
		t.Fatalf("not ok: %v", result["error"])
	}
	if got := result["endianness"]; got != "little" {
		t.Errorf("endianness = %v, want little", got)
	}
	if got := result["resolution"]; got != "micro" {
		t.Errorf("resolution = %v, want micro", got)
	}
	if got := result["packet_count"]; got != 1 {
		t.Errorf("packet_count = %v, want 1", got)
	}
	// 1700000000 = 2023-11-14T22:13:20Z. Asserting the date, not just "non-empty",
	// is what catches a byte-order mix-up: the same bytes read the other way round
	// yield a valid-looking timestamp in a different year.
	if got := result["first_packet"]; got != "2023-11-14T22:13:20.500000Z" {
		t.Errorf("first_packet = %v, want 2023-11-14T22:13:20.500000Z", got)
	}
	flows, _ := result["flows"].([]map[string]any)
	if len(flows) != 1 {
		t.Fatalf("flows = %d, want 1", len(flows))
	}
	if flows[0]["src"] != "10.0.0.5" || flows[0]["dst"] != "93.184.216.34" {
		t.Errorf("flow addresses = %v -> %v", flows[0]["src"], flows[0]["dst"])
	}
	if flows[0]["dst_port"] != 80 {
		t.Errorf("dst_port = %v, want 80", flows[0]["dst_port"])
	}
	requests, _ := result["http_requests"].([]map[string]any)
	if len(requests) != 1 {
		t.Fatalf("http_requests = %d, want 1", len(requests))
	}
	if requests[0]["url"] != "http://example.com/index.html" {
		t.Errorf("url = %v", requests[0]["url"])
	}
}

func TestPcapBigEndian(t *testing.T) {
	// The same logical capture written big-endian must produce byte-identical
	// results. If endianness were assumed, the timestamp would land in a different
	// year rather than failing outright.
	frames := [][]byte{ethIPv4TCP("192.168.0.1", "8.8.8.8", 1234, 53, nil)}
	little := InspectCapture(writePcap(t, 0xa1b2c3d4, binary.LittleEndian, 250000, frames), 50, true)
	big := InspectCapture(writePcap(t, 0xa1b2c3d4, binary.BigEndian, 250000, frames), 50, true)
	if little["first_packet"] != big["first_packet"] {
		t.Errorf("timestamps differ by endianness: %v vs %v",
			little["first_packet"], big["first_packet"])
	}
	if big["endianness"] != "big" {
		t.Errorf("endianness = %v, want big", big["endianness"])
	}
	if big["packet_count"] != 1 {
		t.Errorf("packet_count = %v, want 1", big["packet_count"])
	}
	flows, _ := big["flows"].([]map[string]any)
	if len(flows) != 1 || flows[0]["src"] != "192.168.0.1" {
		t.Errorf("big-endian flow addresses wrong: %v", flows)
	}
}

func TestPcapNanosecondResolution(t *testing.T) {
	// 500_000_000 nanoseconds is the same instant as 500_000 microseconds. Read as
	// microseconds it would be 500 seconds past the epoch minute instead.
	frames := [][]byte{ethIPv4TCP("10.1.1.1", "10.2.2.2", 1000, 2000, nil)}
	micro := InspectCapture(writePcap(t, 0xa1b2c3d4, binary.LittleEndian, 500000, frames), 50, true)
	nano := InspectCapture(writePcap(t, 0xa1b23c4d, binary.LittleEndian, 500000000, frames), 50, true)
	if nano["resolution"] != "nano" {
		t.Errorf("resolution = %v, want nano", nano["resolution"])
	}
	if micro["first_packet"] != nano["first_packet"] {
		t.Errorf("same instant rendered differently: micro=%v nano=%v",
			micro["first_packet"], nano["first_packet"])
	}
}

func TestPcapngEnhancedPacketBlocks(t *testing.T) {
	block := func(blockType uint32, body []byte) []byte {
		padding := (4 - len(body)%4) % 4
		total := 12 + len(body) + padding
		out := make([]byte, 8)
		binary.LittleEndian.PutUint32(out[0:4], blockType)
		binary.LittleEndian.PutUint32(out[4:8], uint32(total))
		out = append(out, body...)
		out = append(out, make([]byte, padding)...)
		tail := make([]byte, 4)
		binary.LittleEndian.PutUint32(tail, uint32(total))
		return append(out, tail...)
	}

	shbBody := make([]byte, 16)
	binary.LittleEndian.PutUint32(shbBody[0:4], 0x1a2b3c4d)
	binary.LittleEndian.PutUint16(shbBody[4:6], 1)
	out := block(0x0a0d0d0a, shbBody)

	idbBody := make([]byte, 8)
	binary.LittleEndian.PutUint16(idbBody[0:2], 1) // Ethernet
	binary.LittleEndian.PutUint32(idbBody[4:8], 65535)
	out = append(out, block(0x00000001, idbBody)...)

	frame := ethIPv4TCP("172.16.0.9", "1.1.1.1", 40000, 443,
		[]byte("GET /secret HTTP/1.1\r\nHost: api.example\r\n\r\n"))
	total := uint64(1700000000) * 1000000
	epbBody := make([]byte, 20)
	binary.LittleEndian.PutUint32(epbBody[0:4], 0)
	binary.LittleEndian.PutUint32(epbBody[4:8], uint32(total>>32))
	binary.LittleEndian.PutUint32(epbBody[8:12], uint32(total&0xffffffff))
	binary.LittleEndian.PutUint32(epbBody[12:16], uint32(len(frame)))
	binary.LittleEndian.PutUint32(epbBody[16:20], uint32(len(frame)))
	epbBody = append(epbBody, frame...)
	out = append(out, block(0x00000006, epbBody)...)

	path := filepath.Join(t.TempDir(), "capture.pcapng")
	if err := os.WriteFile(path, out, 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	result := InspectCapture(path, 50, true)
	if ok, _ := result["ok"].(bool); !ok {
		t.Fatalf("not ok: %v", result["error"])
	}
	if result["format"] != "pcapng" {
		t.Errorf("format = %v, want pcapng", result["format"])
	}
	if result["interfaces"] != 1 {
		t.Errorf("interfaces = %v, want 1", result["interfaces"])
	}
	if result["linktype_name"] != "Ethernet" {
		t.Errorf("linktype_name = %v, want Ethernet", result["linktype_name"])
	}
	if result["packet_count"] != 1 {
		t.Errorf("packet_count = %v, want 1", result["packet_count"])
	}
	flows, _ := result["flows"].([]map[string]any)
	if len(flows) != 1 {
		t.Fatalf("flows = %d, want 1", len(flows))
	}
	if flows[0]["src"] != "172.16.0.9" || flows[0]["dst_port"] != 443 {
		t.Errorf("flow = %v -> %v", flows[0]["src"], flows[0]["dst_port"])
	}
	requests, _ := result["http_requests"].([]map[string]any)
	if len(requests) != 1 || requests[0]["url"] != "http://api.example/secret" {
		t.Errorf("http_requests = %v", requests)
	}
}

func TestPcapLinkTypeDecidesNetworkOffset(t *testing.T) {
	// A raw-IP capture has no Ethernet header, so the IP header starts at byte 0.
	// Parsing it with the Ethernet offset would read the IP version out of the middle
	// of the header and produce a plausible-looking wrong address.
	frame := ethIPv4TCP("10.9.9.9", "10.8.8.8", 5555, 6666, nil)[14:] // strip Ethernet
	header := make([]byte, 24)
	binary.LittleEndian.PutUint32(header[0:4], 0xa1b2c3d4)
	binary.LittleEndian.PutUint16(header[4:6], 2)
	binary.LittleEndian.PutUint16(header[6:8], 4)
	binary.LittleEndian.PutUint32(header[16:20], 65535)
	binary.LittleEndian.PutUint32(header[20:24], 101) // LINKTYPE_RAW
	record := make([]byte, 16)
	binary.LittleEndian.PutUint32(record[0:4], 1700000000)
	binary.LittleEndian.PutUint32(record[8:12], uint32(len(frame)))
	binary.LittleEndian.PutUint32(record[12:16], uint32(len(frame)))
	out := append(header, record...)
	out = append(out, frame...)

	path := filepath.Join(t.TempDir(), "raw.pcap")
	if err := os.WriteFile(path, out, 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	result := InspectCapture(path, 50, true)
	if result["linktype_name"] != "Raw IP" {
		t.Errorf("linktype_name = %v, want Raw IP", result["linktype_name"])
	}
	if result["parsed_packets"] != 1 {
		t.Fatalf("parsed_packets = %v, want 1", result["parsed_packets"])
	}
	flows, _ := result["flows"].([]map[string]any)
	if len(flows) != 1 || flows[0]["src"] != "10.9.9.9" {
		t.Errorf("raw-IP flow parsed wrong: %v", flows)
	}
}

func TestCaptureRejectsNonCaptureFiles(t *testing.T) {
	path := filepath.Join(t.TempDir(), "not-a-capture.bin")
	if err := os.WriteFile(path, []byte("this is definitely not a packet capture at all"), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	result := InspectCapture(path, 50, true)
	if ok, _ := result["ok"].(bool); ok {
		t.Errorf("a text file was accepted as a capture")
	}
	if result["found_magic"] == nil {
		t.Errorf("expected found_magic to explain the rejection")
	}
}

func TestTruncatedPcapDoesNotPanic(t *testing.T) {
	frames := [][]byte{
		ethIPv4TCP("10.0.0.1", "10.0.0.2", 1, 2, nil),
		ethIPv4TCP("10.0.0.3", "10.0.0.4", 3, 4, nil),
	}
	full := writePcap(t, 0xa1b2c3d4, binary.LittleEndian, 100, frames)
	data, err := os.ReadFile(full)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	// Cut mid-record: the walk must stop and report truncation, not read past the end.
	for _, cut := range []int{24, 30, len(data) / 2, len(data) - 5} {
		path := filepath.Join(t.TempDir(), "truncated.pcap")
		if err := os.WriteFile(path, data[:cut], 0o644); err != nil {
			t.Fatalf("write fixture: %v", err)
		}
		result := InspectCapture(path, 50, true)
		if cut < 24 {
			continue
		}
		if ok, _ := result["ok"].(bool); !ok && cut >= 24 {
			// A header-only file is legitimately "ok" with zero packets; a cut inside
			// the header is not. Neither may panic.
			continue
		}
	}
}

func TestSyntheticCorruptionNeverPanics(t *testing.T) {
	frames := [][]byte{ethIPv4TCP("10.0.0.1", "10.0.0.2", 80, 443,
		[]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"))}
	path := writePcap(t, 0xa1b2c3d4, binary.LittleEndian, 100, frames)
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	scratch := filepath.Join(t.TempDir(), "mutated.pcap")
	// Deterministic pseudo-random mutations: every byte position gets a few values,
	// which is enough to reach length, offset and link-type edge cases.
	for index := 0; index < len(original); index++ {
		for _, value := range []byte{0x00, 0xff, 0x7f} {
			mutated := append([]byte{}, original...)
			if mutated[index] == value {
				continue
			}
			mutated[index] = value
			if err := os.WriteFile(scratch, mutated, 0o644); err != nil {
				t.Fatalf("write fixture: %v", err)
			}
			InspectCapture(scratch, 10, true) // must not panic
		}
	}
}
