package rehub

// Packet capture readers for classic pcap and pcapng.
//
// WHY THIS IS NOT IN THE PYTHON MODULE ONLY: the native front end routes `re netcap`
// to this hub before Python ever sees it, so a Python-only implementation is dead
// code on every normal invocation. Adding a format here and not in Python means the
// format works; adding it in Python alone means it silently does nothing.
//
// The formats themselves have three traps that all produce plausible-looking wrong
// output rather than errors:
//
//   - Endianness is per-file, declared by the magic number. A big-endian capture read
//     as little-endian yields absurd timestamps and packet lengths, and every field
//     still looks like a number.
//   - Microsecond and nanosecond captures differ only in the magic's low bits.
//     Treating nanoseconds as microseconds puts every packet in 1970.
//   - The link-layer type decides where the IP header starts. Parsing an Ethernet
//     frame as raw IP reads the destination MAC's first byte as an IP version.

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"time"

	"xtforge-hub/internal/guard"
)

// pcapMagic describes how to read a capture: byte order plus timestamp resolution.
type pcapMagic struct {
	order binary.ByteOrder
	nano  bool
	name  string
}

var pcapMagics = map[string]pcapMagic{
	"d4c3b2a1": {binary.LittleEndian, false, "little"},
	"a1b2c3d4": {binary.BigEndian, false, "big"},
	"4d3cb2a1": {binary.LittleEndian, true, "little"},
	"a1b23c4d": {binary.BigEndian, true, "big"},
}

const pcapngSHB = "0a0d0d0a"

var linkTypeNames = map[uint32]string{
	0: "NULL", 1: "Ethernet", 101: "Raw IP", 105: "IEEE 802.11",
	113: "Linux SLL", 127: "IEEE 802.11 radiotap", 228: "Raw IPv4",
	229: "Raw IPv6", 276: "Linux SLL2",
}

var ipProtocolNames = map[uint8]string{
	1: "ICMP", 6: "TCP", 17: "UDP", 47: "GRE", 50: "ESP", 51: "AH", 58: "ICMPv6",
}

// captureFrame is one recorded packet plus the metadata from its record header.
type captureFrame struct {
	Timestamp   string
	Captured    uint32
	Original    uint32
	Data        []byte
	Seconds     uint32
	NoTimestamp bool
}

func linkTypeName(lt uint32) string {
	if name, ok := linkTypeNames[lt]; ok {
		return name
	}
	return fmt.Sprintf("unknown(%d)", lt)
}

func formatStamp(seconds int64, micros int64) string {
	if seconds < 0 || seconds > 1<<40 {
		return ""
	}
	return time.Unix(seconds, micros*1000).UTC().Format("2006-01-02T15:04:05.000000Z")
}

// readPcapFrames walks a classic pcap file.
func readPcapFrames(data []byte, magic pcapMagic, maxFrames int) ([]captureFrame, map[string]any, bool) {
	if len(data) < 24 {
		return nil, nil, false
	}
	header := map[string]any{
		"format":           "pcap",
		"endianness":       magic.name,
		"byte_order_magic": hex.EncodeToString(data[:4]),
	}
	if magic.nano {
		header["resolution"] = "nano"
	} else {
		header["resolution"] = "micro"
	}
	major := magic.order.Uint16(data[4:6])
	minor := magic.order.Uint16(data[6:8])
	snaplen := magic.order.Uint32(data[16:20])
	linktype := magic.order.Uint32(data[20:24])
	header["version"] = fmt.Sprintf("%d.%d", major, minor)
	header["snaplen"] = snaplen
	header["linktype"] = linktype
	header["linktype_name"] = linkTypeName(linktype)

	var frames []captureFrame
	truncated := false
	cursor := 24
	for cursor+16 <= len(data) && len(frames) < maxFrames {
		seconds := magic.order.Uint32(data[cursor : cursor+4])
		fraction := magic.order.Uint32(data[cursor+4 : cursor+8])
		captured := magic.order.Uint32(data[cursor+8 : cursor+12])
		original := magic.order.Uint32(data[cursor+12 : cursor+16])
		cursor += 16
		if int(captured) > len(data)-cursor {
			truncated = true
			break
		}
		// A nanosecond capture stores nanoseconds in this field; dividing by 1000 is
		// the entire difference between a correct timestamp and one in 1970.
		micros := int64(fraction)
		if magic.nano {
			micros = int64(fraction) / 1000
		}
		frames = append(frames, captureFrame{
			Timestamp: formatStamp(int64(seconds), micros),
			Captured:  captured,
			Original:  original,
			Seconds:   seconds,
			Data:      data[cursor : cursor+int(captured)],
		})
		cursor += int(captured)
	}
	return frames, header, truncated
}

// readPcapngFrames walks a pcapng file, which is a sequence of length-prefixed blocks.
func readPcapngFrames(data []byte, maxFrames int) ([]captureFrame, map[string]any, bool) {
	header := map[string]any{"format": "pcapng", "interfaces": 0}
	order := binary.ByteOrder(binary.LittleEndian)
	linktypeSet := false
	var frames []captureFrame
	truncated := false
	cursor := 0
	for cursor+12 <= len(data) && len(frames) < maxFrames {
		if hex.EncodeToString(data[cursor:cursor+4]) == pcapngSHB {
			// The byte-order magic inside the section header settles endianness for
			// every block that follows it, not just this one.
			if cursor+12 > len(data) {
				break
			}
			if hex.EncodeToString(data[cursor+8:cursor+12]) == "4d3c2b1a" {
				order = binary.LittleEndian
				header["endianness"] = "little"
			} else {
				order = binary.BigEndian
				header["endianness"] = "big"
			}
		}
		blockType := order.Uint32(data[cursor : cursor+4])
		blockLen := int(order.Uint32(data[cursor+4 : cursor+8]))
		if blockLen < 12 || cursor+blockLen > len(data) {
			truncated = true
			break
		}
		// The length is repeated at the end of the block; a mismatch means the walk
		// would otherwise silently misalign from here on.
		if trailing := order.Uint32(data[cursor+blockLen-4 : cursor+blockLen]); int(trailing) != blockLen {
			header["trailing_length_mismatch"] = true
		}
		switch blockType {
		case 0x00000001: // Interface Description Block
			if blockLen >= 20 {
				lt := uint32(order.Uint16(data[cursor+8 : cursor+10]))
				header["interfaces"] = header["interfaces"].(int) + 1
				if !linktypeSet {
					header["linktype"] = lt
					header["linktype_name"] = linkTypeName(lt)
					linktypeSet = true
				}
			}
		case 0x00000006: // Enhanced Packet Block
			if blockLen >= 32 {
				high := order.Uint32(data[cursor+12 : cursor+16])
				low := order.Uint32(data[cursor+16 : cursor+20])
				captured := order.Uint32(data[cursor+20 : cursor+24])
				original := order.Uint32(data[cursor+24 : cursor+28])
				bodyOffset := cursor + 28
				if bodyOffset+int(captured) <= cursor+blockLen {
					// Timestamp is a 64-bit count of interface units. The default
					// resolution is microseconds; the raw value is rendered at that
					// default rather than asserting a resolution not read.
					total := (uint64(high) << 32) | uint64(low)
					frames = append(frames, captureFrame{
						Timestamp: formatStamp(int64(total/1000000), int64(total%1000000)),
						Captured:  captured,
						Original:  original,
						Data:      data[bodyOffset : bodyOffset+int(captured)],
					})
				}
			}
		case 0x00000003: // Simple Packet Block
			if blockLen >= 16 {
				original := order.Uint32(data[cursor+8 : cursor+12])
				bodyOffset := cursor + 12
				captured := blockLen - 16
				frames = append(frames, captureFrame{
					Captured:    uint32(captured),
					Original:    original,
					NoTimestamp: true,
					Data:        data[bodyOffset : bodyOffset+captured],
				})
			}
		}
		cursor += blockLen
	}
	return frames, header, truncated
}

// networkOffset reports where the network header starts and the declared EtherType.
// The link layer is the only thing that says this; guessing misparses every frame.
func networkOffset(frame []byte, linktype uint32, haveLinktype bool) (int, int, bool) {
	if !haveLinktype {
		return 0, 0, false
	}
	switch linktype {
	case 1: // Ethernet
		if len(frame) < 14 {
			return 0, 0, false
		}
		etherType := int(binary.BigEndian.Uint16(frame[12:14]))
		offset := 14
		for (etherType == 0x8100 || etherType == 0x88a8) && len(frame) >= offset+4 {
			etherType = int(binary.BigEndian.Uint16(frame[offset+2 : offset+4]))
			offset += 4
		}
		return offset, etherType, true
	case 0, 101, 228, 229: // NULL / Raw IP: no link header
		return 0, -1, true
	case 113: // Linux SLL
		if len(frame) < 16 {
			return 0, 0, false
		}
		return 16, int(binary.BigEndian.Uint16(frame[14:16])), true
	case 276: // Linux SLL2
		if len(frame) < 20 {
			return 0, 0, false
		}
		return 20, int(binary.BigEndian.Uint16(frame[0:2])), true
	case 127: // radiotap
		if len(frame) < 4 {
			return 0, 0, false
		}
		return int(binary.LittleEndian.Uint16(frame[2:4])), -1, true
	}
	return 0, 0, false
}

// decodedIP is the subset of an IP header this reader needs.
type decodedIP struct {
	Version       int
	Src           string
	Dst           string
	Protocol      uint8
	Payload       []byte
	FirstFragment bool
}

func decodeIPv4(blob []byte) (decodedIP, bool) {
	if len(blob) < 20 || blob[0]>>4 != 4 {
		return decodedIP{}, false
	}
	headerLen := int(blob[0]&0x0f) * 4
	if headerLen < 20 || headerLen > len(blob) {
		return decodedIP{}, false
	}
	totalLen := int(binary.BigEndian.Uint16(blob[2:4]))
	end := totalLen
	if end > len(blob) || end < headerLen {
		end = len(blob)
	}
	fragmentOffset := binary.BigEndian.Uint16(blob[6:8]) & 0x1fff
	return decodedIP{
		Version:       4,
		Src:           net.IP(blob[12:16]).String(),
		Dst:           net.IP(blob[16:20]).String(),
		Protocol:      blob[9],
		Payload:       blob[headerLen:end],
		FirstFragment: fragmentOffset == 0,
	}, true
}

func decodeIPv6(blob []byte) (decodedIP, bool) {
	if len(blob) < 40 || blob[0]>>4 != 6 {
		return decodedIP{}, false
	}
	payloadLen := int(binary.BigEndian.Uint16(blob[4:6]))
	end := 40 + payloadLen
	if end > len(blob) {
		end = len(blob)
	}
	return decodedIP{
		Version:       6,
		Src:           net.IP(blob[8:24]).String(),
		Dst:           net.IP(blob[24:40]).String(),
		Protocol:      blob[6],
		Payload:       blob[40:end],
		FirstFragment: true,
	}, true
}

// captureTransport holds the port pair plus any decoded application payload.
type captureTransport struct {
	SrcPort  int
	DstPort  int
	Protocol string
	AppData  []byte
}

func decodeTransport(ip decodedIP) captureTransport {
	out := captureTransport{Protocol: ipProtocolNames[ip.Protocol]}
	if out.Protocol == "" {
		out.Protocol = fmt.Sprintf("IP(%d)", ip.Protocol)
	}
	out.SrcPort = -1
	out.DstPort = -1
	if !ip.FirstFragment {
		return out
	}
	payload := ip.Payload
	switch ip.Protocol {
	case 6: // TCP
		if len(payload) >= 20 {
			out.SrcPort = int(binary.BigEndian.Uint16(payload[0:2]))
			out.DstPort = int(binary.BigEndian.Uint16(payload[2:4]))
			offset := int(payload[12]>>4) * 4
			if offset >= 20 && offset <= len(payload) {
				out.AppData = payload[offset:]
			}
		}
	case 17: // UDP
		if len(payload) >= 8 {
			out.SrcPort = int(binary.BigEndian.Uint16(payload[0:2]))
			out.DstPort = int(binary.BigEndian.Uint16(payload[2:4]))
			out.AppData = payload[8:]
		}
	}
	return out
}

// httpFromPayload recognises a plaintext HTTP request line in a TCP payload.
func httpFromPayload(payload []byte) map[string]any {
	if len(payload) < 16 {
		return nil
	}
	if len(payload) > 400 {
		payload = payload[:400]
	}
	methods := []string{"GET", "POST", "PUT", "HEAD", "DELETE", "OPTIONS", "PATCH"}
	method := ""
	for _, candidate := range methods {
		if strings.HasPrefix(string(payload), candidate+" ") {
			method = candidate
			break
		}
	}
	if method == "" {
		return nil
	}
	lineEnd := strings.Index(string(payload), "\r\n")
	if lineEnd < 0 {
		lineEnd = len(payload)
	}
	parts := strings.SplitN(string(payload[:lineEnd]), " ", 3)
	if len(parts) < 2 {
		return nil
	}
	path := parts[1]
	host := ""
	lower := strings.ToLower(string(payload))
	if idx := strings.Index(lower, "\r\nhost:"); idx >= 0 {
		rest := string(payload[idx+7:])
		if stop := strings.Index(rest, "\r\n"); stop >= 0 {
			host = strings.TrimSpace(rest[:stop])
		}
	}
	url := path
	if host != "" {
		url = "http://" + host + path
	}
	return map[string]any{"method": method, "path": path, "host": host, "url": url}
}

// InspectCapture reads a pcap or pcapng file and summarises flows, endpoints and
// plaintext HTTP requests. Returns ok:false with a reason for any other format, so
// the caller can fall through to the next reader.
func InspectCapture(filePath string, limit int, extractHTTP bool) map[string]any {
	canon, err := guard.ReadGuard(filePath)
	if err != nil {
		return map[string]any{"ok": false, "error": err.Error()}
	}
	if limit <= 0 {
		limit = 200
	}
	data, err := os.ReadFile(canon)
	if err != nil {
		return map[string]any{"ok": false, "error": err.Error()}
	}
	if len(data) < 24 {
		return map[string]any{"ok": false,
			"error": fmt.Sprintf("file too small for a capture header (%d bytes)", len(data))}
	}

	magicHex := hex.EncodeToString(data[:4])
	var frames []captureFrame
	var header map[string]any
	var truncated bool
	if magicHex == pcapngSHB {
		frames, header, truncated = readPcapngFrames(data, 200000)
	} else if magic, ok := pcapMagics[magicHex]; ok {
		frames, header, truncated = readPcapFrames(data, magic, 200000)
	} else {
		return map[string]any{"ok": false, "error": "not a pcap or pcapng capture",
			"found_magic": magicHex}
	}
	if header == nil {
		return map[string]any{"ok": false, "error": "capture header is unreadable"}
	}

	linktype, haveLinktype := uint32(0), false
	if value, ok := header["linktype"].(uint32); ok {
		linktype, haveLinktype = value, true
	}

	type flowKey struct {
		Src, Dst         string
		SrcPort, DstPort int
		Protocol         string
	}
	flows := map[flowKey]*struct {
		Packets int
		Bytes   int
	}{}
	var flowOrder []flowKey
	protocols := map[string]int{}
	httpRequests := []map[string]any{}
	parsed, unparsed := 0, 0
	earliest, latest := "", ""

	for _, frame := range frames {
		offset, etherType, ok := networkOffset(frame.Data, linktype, haveLinktype)
		if !ok || offset < 0 || offset > len(frame.Data) {
			// A corrupt link-layer header (a radiotap length, say) can name an offset
			// past the end of the frame. Slicing there panics, so it is a parse
			// failure like any other.
			unparsed++
			continue
		}
		network := frame.Data[offset:]
		var ip decodedIP
		decoded := false
		switch etherType {
		case -1: // link type declares no EtherType: try IPv4 then IPv6
			if ip, decoded = decodeIPv4(network); !decoded {
				ip, decoded = decodeIPv6(network)
			}
		case 0x0800:
			ip, decoded = decodeIPv4(network)
		case 0x86dd:
			ip, decoded = decodeIPv6(network)
		}
		if !decoded {
			if etherType == 0x0806 {
				protocols["ARP"]++
			} else {
				unparsed++
			}
			continue
		}
		parsed++
		transport := decodeTransport(ip)
		protocols[transport.Protocol]++
		key := flowKey{Src: ip.Src, Dst: ip.Dst, SrcPort: transport.SrcPort,
			DstPort: transport.DstPort, Protocol: transport.Protocol}
		entry, exists := flows[key]
		if !exists {
			entry = &struct {
				Packets int
				Bytes   int
			}{}
			flows[key] = entry
			flowOrder = append(flowOrder, key)
		}
		entry.Packets++
		entry.Bytes += int(frame.Original)
		if frame.Timestamp != "" {
			if earliest == "" || frame.Timestamp < earliest {
				earliest = frame.Timestamp
			}
			if latest == "" || frame.Timestamp > latest {
				latest = frame.Timestamp
			}
		}
		if extractHTTP && len(httpRequests) < limit && ip.Protocol == 6 {
			if request := httpFromPayload(transport.AppData); request != nil {
				request["src"] = ip.Src
				request["dst"] = ip.Dst
				request["timestamp"] = frame.Timestamp
				httpRequests = append(httpRequests, request)
			}
		}
	}

	sort.SliceStable(flowOrder, func(i, j int) bool {
		return flows[flowOrder[i]].Bytes > flows[flowOrder[j]].Bytes
	})
	flowRows := []map[string]any{}
	for _, key := range flowOrder {
		if len(flowRows) >= limit {
			break
		}
		entry := flows[key]
		row := map[string]any{
			"src": key.Src, "dst": key.Dst, "protocol": key.Protocol,
			"packets": entry.Packets, "bytes": entry.Bytes,
		}
		if key.SrcPort >= 0 {
			row["src_port"] = key.SrcPort
		}
		if key.DstPort >= 0 {
			row["dst_port"] = key.DstPort
		}
		flowRows = append(flowRows, row)
	}

	result := map[string]any{
		"ok":                 true,
		"path":               canon,
		"packet_count":       len(frames),
		"parsed_packets":     parsed,
		"unparsed_packets":   unparsed,
		"flow_count":         len(flows),
		"flows":              flowRows,
		"protocols":          protocols,
		"http_requests":      httpRequests,
		"http_request_count": len(httpRequests),
		"first_packet":       earliest,
		"last_packet":        latest,
		"truncated":          truncated,
	}
	for key, value := range header {
		result[key] = value
	}
	return result
}
