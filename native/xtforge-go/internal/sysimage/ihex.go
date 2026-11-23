package sysimage

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
)

// Intel HEX is a line-oriented ASCII encoding of bytes plus absolute addresses.
// Each line is ":LLAAAATT<data>CC": LL is the data length, AAAA a 16-bit address
// field, TT the record type and CC the checksum over every byte from LL onward.
// The 16-bit address is relative to a base installed by an extended-address
// record; only records carry data, so a file is recovered as a set of ranges.

// maxIHEXBytes bounds the decoded payload of a file. A text encoding is roughly
// 2.5x the size of its payload, so without a cap a small, hostile input could
// make us allocate far more memory than its on-disk size suggests.
const maxIHEXBytes = 16 << 20

const (
	ihexData             = 0x00
	ihexEndOfFile        = 0x01
	ihexExtendedSegment  = 0x02
	ihexStartSegment     = 0x03
	ihexExtendedLinear   = 0x04
	ihexStartLinear      = 0x05
	ihexHeaderBytes      = 4  // LL, AAAA (2 bytes), TT
	ihexMinRecordBytes   = 5  // the header plus a checksum
	ihexMinLineChars     = 10 // the header and checksum in hex digits
	ihexMaxLineBytes     = 1 << 20
	ihexInitialLineBytes = 64 << 10
)

// IHEXSegment is one contiguous address range recovered from an Intel HEX file.
type IHEXSegment struct {
	Start uint64 `json:"start"`
	Bytes []byte `json:"-"`
	Size  int    `json:"size"`
}

// IHEXImage is a parsed Intel HEX file.
type IHEXImage struct {
	Segments     []IHEXSegment `json:"segments"`
	TotalSize    int           `json:"total_size"`
	EntryPoint   uint64        `json:"entry_point,omitempty"`
	HasEntry     bool          `json:"has_entry"`
	Records      int           `json:"records"`
	BadChecksums int           `json:"bad_checksums"`
}

// ihexRun is a consecutive stretch of bytes from one data record. A single
// record can produce two runs when its 16-bit address field wraps, so runs are
// sorted and merged only after every line has been read.
type ihexRun struct {
	start uint64
	data  []byte
}

// IsIHEX reports whether the data looks like an Intel HEX file (a line starting
// with ':' followed by uppercase hex). Only a bounded head is needed, which is
// what the format dispatchers pass in. Binary formats such as Mach-O cannot
// satisfy this: their magic bytes are neither ':' nor ASCII hex.
func IsIHEX(head []byte) bool {
	for len(head) > 0 {
		line := head
		terminated := false
		if n := bytes.IndexByte(line, '\n'); n >= 0 {
			line, head = line[:n], line[n+1:]
			terminated = true
		} else {
			head = nil
		}
		line = bytes.TrimSpace(line)
		if len(line) < 1+ihexMinLineChars || line[0] != ':' {
			continue
		}
		payload := line[1:]
		// A head may end in the middle of a line; do not reject it merely
		// because the fragment holds an odd number of hex digits.
		if terminated && len(payload)%2 != 0 {
			continue
		}
		allHex := true
		for _, c := range payload {
			if !((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F')) {
				allHex = false
				break
			}
		}
		if allHex {
			return true
		}
	}
	return false
}

// ParseIHEX decodes an Intel HEX file. Unrecognised lines, malformed records and
// bad checksums are skipped and tallied in BadChecksums rather than failing the
// whole parse; exceeding the decoded-byte cap is the only data-dependent error.
func ParseIHEX(r io.Reader) (IHEXImage, error) {
	var img IHEXImage
	if r == nil {
		return img, fmt.Errorf("ihex: nil reader")
	}

	var runs []ihexRun
	var base uint64
	decoded := 0

	// finish is used on every exit path so the returned image always contains
	// the segments recovered so far, even when an error interrupts the parse.
	finish := func() IHEXImage {
		img.Segments, img.TotalSize = mergeIHEXRuns(runs)
		return img
	}

	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, ihexInitialLineBytes), ihexMaxLineBytes)
lines:
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if len(line) == 0 || line[0] != ':' {
			continue
		}

		record, ok := decodeIHEXRecord(line)
		if !ok {
			img.BadChecksums++
			continue
		}
		img.Records++

		count := int(record[0])
		addr := uint16(record[1])<<8 | uint16(record[2])
		typ := record[3]
		data := record[ihexHeaderBytes : ihexHeaderBytes+count]

		switch typ {
		case ihexData:
			if decoded+count > maxIHEXBytes {
				return finish(), fmt.Errorf("ihex: decoded data exceeds %d bytes", maxIHEXBytes)
			}
			decoded += count
			// The address field wraps inside the record only: each byte is
			// placed at base plus the wrapped 16-bit offset. A record that
			// straddles 0xFFFF therefore produces two runs starting at the
			// base again, never one run carried into the next 64 KiB window.
			var runStart uint64
			var runData []byte
			for i, value := range data {
				at := base + uint64(addr+uint16(i))
				if runData == nil || at != runStart+uint64(len(runData)) {
					if len(runData) > 0 {
						runs = append(runs, ihexRun{start: runStart, data: runData})
					}
					runStart, runData = at, make([]byte, 0, len(data)-i)
				}
				runData = append(runData, value)
			}
			if len(runData) > 0 {
				runs = append(runs, ihexRun{start: runStart, data: runData})
			}

		case ihexEndOfFile:
			// Nothing after EOF belongs to the image.
			break lines

		case ihexExtendedSegment:
			if len(data) == 2 {
				segment := uint16(data[0])<<8 | uint16(data[1])
				base = uint64(segment) << 4
			}

		case ihexStartSegment:
			if len(data) == 4 {
				cs := uint16(data[0])<<8 | uint16(data[1])
				ip := uint16(data[2])<<8 | uint16(data[3])
				img.EntryPoint = uint64(cs)<<4 + uint64(ip)
				img.HasEntry = true
			}

		case ihexExtendedLinear:
			if len(data) == 2 {
				upper := uint16(data[0])<<8 | uint16(data[1])
				base = uint64(upper) << 16
			}

		case ihexStartLinear:
			if len(data) == 4 {
				img.EntryPoint = uint64(data[0])<<24 | uint64(data[1])<<16 |
					uint64(data[2])<<8 | uint64(data[3])
				img.HasEntry = true
			}
		}
	}
	if err := scanner.Err(); err != nil && !errors.Is(err, bufio.ErrTooLong) {
		return finish(), fmt.Errorf("ihex: read: %w", err)
	}
	return finish(), nil
}

// decodeIHEXRecord validates one line and returns its decoded bytes, including
// the trailing checksum. An empty slice means the record must be tallied as bad.
func decodeIHEXRecord(line string) ([]byte, bool) {
	encoded := line[1:]
	if len(encoded) < ihexMinLineChars || len(encoded)%2 != 0 {
		return nil, false
	}
	record := make([]byte, len(encoded)/2)
	if _, err := hex.Decode(record, []byte(encoded)); err != nil {
		return nil, false
	}
	if len(record) < ihexMinRecordBytes {
		return nil, false
	}

	count := int(record[0])
	if len(record) != ihexHeaderBytes+count+1 {
		// A truncated or padded line cannot be trusted: the declared length
		// tells us where the data and checksum actually are.
		return nil, false
	}

	var sum byte
	for _, value := range record[:len(record)-1] {
		sum += value
	}
	if (byte)(0-sum) != record[len(record)-1] {
		return nil, false
	}
	return record, true
}

// mergeIHEXRuns sorts the recovered runs by address and joins touching ones.
// Overlaps are resolved in address order, keeping the first value seen at any
// address, so a malformed file still yields a well-formed set of segments.
func mergeIHEXRuns(runs []ihexRun) ([]IHEXSegment, int) {
	if len(runs) == 0 {
		return nil, 0
	}
	sort.SliceStable(runs, func(i, j int) bool { return runs[i].start < runs[j].start })

	segments := make([]IHEXSegment, 0, len(runs))
	total := 0
	for _, run := range runs {
		if len(run.data) == 0 {
			continue
		}
		if n := len(segments); n > 0 {
			last := &segments[n-1]
			lastEnd := last.Start + uint64(last.Size)
			if run.start <= lastEnd {
				skip := 0
				if run.start < lastEnd {
					skip = int(lastEnd - run.start)
					if skip >= len(run.data) {
						continue
					}
				}
				last.Bytes = append(last.Bytes, run.data[skip:]...)
				last.Size = len(last.Bytes)
				total += len(run.data) - skip
				continue
			}
		}
		data := make([]byte, len(run.data))
		copy(data, run.data)
		segments = append(segments, IHEXSegment{Start: run.start, Bytes: data, Size: len(data)})
		total += len(data)
	}
	return segments, total
}
