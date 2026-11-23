package sysimage

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"sort"
	"strings"
)

// SRECSegment is one contiguous address range.
type SRECSegment struct {
	Start uint64 `json:"start"`
	Bytes []byte `json:"-"`
	Size  int    `json:"size"`
}

// SRECImage is a parsed S-record file.
type SRECImage struct {
	Segments   []SRECSegment `json:"segments"`
	TotalSize  int           `json:"total_size"`
	EntryPoint uint64        `json:"entry_point,omitempty"`
	HasEntry   bool          `json:"has_entry"`
	Records    int           `json:"records"`
	BadRecords int           `json:"bad_records"`
}

// srecMaxBytes bounds decoded payload: an S-record count is one byte, so a file
// can otherwise expand to an unbounded number of records.
const srecMaxBytes = 16 << 20

type srecRecord struct {
	typ  byte
	addr uint64
	data []byte
}

// srecAddressLen returns the address-field width of a defined record type, or
// zero for an unknown/reserved type.
func srecAddressLen(typ byte) int {
	switch typ {
	case '0', '1', '5', '9':
		return 2
	case '2', '6', '8':
		return 3
	case '3', '7':
		return 4
	}
	return 0
}

func srecHexNibble(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

func srecHexByte(hi, lo byte) (byte, bool) {
	h, ok1 := srecHexNibble(hi)
	l, ok2 := srecHexNibble(lo)
	if !ok1 || !ok2 {
		return 0, false
	}
	return h<<4 | l, true
}

// decodeSREC validates one line (already stripped of its line ending) and
// returns its type, address and payload. The checksum is the one's complement
// of the low byte of the sum of every byte after "S<type>", count included.
func decodeSREC(line string) (srecRecord, error) {
	var zero srecRecord
	if len(line) < 4 {
		return zero, fmt.Errorf("record is too short")
	}
	typ := line[1]
	if typ < '0' || typ > '9' {
		return zero, fmt.Errorf("bad record type %q", line[1])
	}
	addrLen := srecAddressLen(typ)
	if addrLen == 0 {
		return zero, fmt.Errorf("unsupported record type S%c", typ)
	}
	count, ok := srecHexByte(line[2], line[3])
	if !ok {
		return zero, fmt.Errorf("bad byte count")
	}
	if int(count) < addrLen+1 { // address plus checksum
		return zero, fmt.Errorf("byte count %d is too small", count)
	}
	// The count field itself occupies line[2:4]; line[4:] holds exactly
	// count more bytes (address, data and checksum).
	if len(line) != 4+2*int(count) {
		return zero, fmt.Errorf("truncated or overlong record")
	}
	raw := make([]byte, int(count)+1)
	raw[0] = count
	if _, err := hex.Decode(raw[1:], []byte(line[4:])); err != nil {
		return zero, fmt.Errorf("bad hex data: %w", err)
	}
	var sum byte
	for _, b := range raw[:len(raw)-1] {
		sum += b
	}
	if got := raw[len(raw)-1]; got != ^sum {
		return zero, fmt.Errorf("bad checksum: got %02X want %02X", got, ^sum)
	}
	var addr uint64
	for _, b := range raw[1 : 1+addrLen] {
		addr = addr<<8 | uint64(b)
	}
	return srecRecord{typ: typ, addr: addr, data: raw[1+addrLen : len(raw)-1]}, nil
}

// srecPrefix checks the part of a record that can be recognised even when a
// detector was handed only the leading bytes of a file.
func srecPrefix(line []byte) bool {
	if len(line) < 4 || (line[0] != 'S' && line[0] != 's') {
		return false
	}
	if line[1] < '0' || line[1] > '9' || srecAddressLen(line[1]) == 0 {
		return false
	}
	_, ok := srecHexByte(line[2], line[3])
	return ok
}

// IsSREC reports whether head looks like the start of a Motorola S-record
// file. At least one well-formed record (or an intact record prefix, when head
// is a short slice) must be present; text and binary noise are not records.
func IsSREC(head []byte) bool {
	rest := head
	for len(rest) > 0 {
		line := rest
		complete := false
		if nl := bytes.IndexByte(rest, '\n'); nl >= 0 {
			line, rest = rest[:nl], rest[nl+1:]
			complete = true
		} else {
			rest = nil
		}
		line = bytes.TrimRight(line, " \t\r")
		if len(line) == 0 {
			continue
		}
		if line[0] != 'S' && line[0] != 's' {
			// Non-record text is allowed (comments, build banners), but a
			// binary blob must not be waved through by a stray 'S' byte.
			if bytes.IndexFunc(line, func(r rune) bool { return r < 0x20 || r > 0x7e }) >= 0 {
				return false
			}
			continue
		}
		if _, err := decodeSREC(string(line)); err == nil {
			return true
		}
		if !complete && srecPrefix(line) {
			return true
		}
	}
	return false
}

// ParseSREC reads S1/S2/S3 data records into sorted, merged segments. S0, S5
// and S6 are counted but ignored; S7/S8/S9 carry an entry point. Bad lines are
// counted and skipped. Decoded payload is capped at 16 MiB.
func ParseSREC(r io.Reader) (SRECImage, error) {
	var img SRECImage
	if r == nil {
		return img, fmt.Errorf("srec: nil reader")
	}

	type chunk struct {
		start uint64
		data  []byte
	}
	var chunks []chunk
	total := 0
	br := bufio.NewReader(r)
	for {
		line, readErr := br.ReadString('\n')
		if len(line) > 0 {
			text := strings.TrimRight(line, " \t\r\n")
			if len(text) > 0 && (text[0] == 'S' || text[0] == 's') {
				rec, err := decodeSREC(text)
				if err != nil {
					img.BadRecords++
				} else {
					img.Records++
					switch rec.typ {
					case '1', '2', '3':
						if total+len(rec.data) > srecMaxBytes {
							img.TotalSize = total
							return img, fmt.Errorf("srec: decoded data exceeds %d bytes", srecMaxBytes)
						}
						if len(rec.data) > 0 {
							chunks = append(chunks, chunk{start: rec.addr, data: rec.data})
							total += len(rec.data)
						}
					case '7', '8', '9':
						img.EntryPoint = rec.addr
						img.HasEntry = true
					}
				}
			}
		}
		if readErr != nil {
			if readErr == io.EOF {
				break
			}
			img.TotalSize = total
			return img, fmt.Errorf("srec: read: %w", readErr)
		}
	}

	img.TotalSize = total
	sort.Slice(chunks, func(i, j int) bool { return chunks[i].start < chunks[j].start })
	for _, c := range chunks {
		if len(img.Segments) == 0 {
			img.Segments = append(img.Segments, SRECSegment{
				Start: c.start,
				Bytes: append([]byte(nil), c.data...),
				Size:  len(c.data),
			})
			continue
		}
		last := &img.Segments[len(img.Segments)-1]
		end := last.Start + uint64(len(last.Bytes))
		if last.Start > ^uint64(0)-uint64(len(last.Bytes)) {
			end = ^uint64(0)
		}
		if c.start <= end { // adjacent or overlapping
			last.Bytes = append(last.Bytes, c.data...)
			last.Size = len(last.Bytes)
		} else {
			img.Segments = append(img.Segments, SRECSegment{
				Start: c.start,
				Bytes: append([]byte(nil), c.data...),
				Size:  len(c.data),
			})
		}
	}
	return img, nil
}
