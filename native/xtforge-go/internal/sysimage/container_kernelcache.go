package sysimage

import (
	"bytes"
	"debug/macho"
	"encoding/binary"
	"fmt"
	"io"

	"xtforge-hub/internal/thirdparty/lzfse"
)

// machoTypeKextBundle is MH_KEXT_BUNDLE (0x0b), the filetype of a kext.
const machoTypeKextBundle macho.Type = 0x0b

// maxKernelCachePayload bounds how much kernel image this package will hold in
// memory. A production kernelcache is tens of megabytes; a firmware image with
// a payload above this needs streaming extraction, not a byte slice.
const maxKernelCachePayload = 512 << 20

// ASN.1 tags used by Apple's Image4 encoding. Image4 is DER-ish: a tag byte,
// a big-endian length, then the value, with IA5 strings for the magic and
// fourcc and an OCTET STRING for the payload.
const (
	kernelTagSequence      = 0x30
	kernelTagIA5String     = 0x16
	kernelTagOctetString   = 0x04
	kernelMaxTLVDepth      = 8
	kernelHeaderInspectLen = 8
)

// kernelTLV is one decoded tag-length-value record. value is a sub-slice of
// the container buffer, so it is only valid while that buffer is alive.
type kernelTLV struct {
	tag   byte
	value []byte
	end   int // offset just past this record in the original buffer
}

// readKernelTLV decodes one TLV at off. Every length is untrusted: the caller
// supplies a finite buffer, so each header byte and the declared value length
// are checked against the bytes actually present before anything is sliced.
// Long form is limited to the 0x81/0x82/0x83 prefixes used by Image4; a
// three-byte count still fits comfortably in an int, so it cannot wrap.
func readKernelTLV(buf []byte, off int) (kernelTLV, error) {
	// Tag plus at least one length byte. Comparing a difference (rather than
	// off+2) also rejects negative offsets and offsets past the end.
	if off < 0 || len(buf)-off < 2 {
		return kernelTLV{}, fmt.Errorf("TLV header at offset %d is truncated in a %d-byte file", off, len(buf))
	}
	tag := buf[off]
	lengthByte := buf[off+1]
	pos := off + 2
	var length int
	switch lengthByte {
	case 0x81: // one following length byte
		if len(buf)-pos < 1 {
			return kernelTLV{}, fmt.Errorf("TLV 0x81 length at offset %d is truncated", off+1)
		}
		length = int(buf[pos])
		pos++
	case 0x82: // two following length bytes
		if len(buf)-pos < 2 {
			return kernelTLV{}, fmt.Errorf("TLV 0x82 length at offset %d is truncated", off+1)
		}
		length = int(binary.BigEndian.Uint16(buf[pos : pos+2]))
		pos += 2
	case 0x83: // three following length bytes
		if len(buf)-pos < 3 {
			return kernelTLV{}, fmt.Errorf("TLV 0x83 length at offset %d is truncated", off+1)
		}
		length = int(buf[pos])<<16 | int(buf[pos+1])<<8 | int(buf[pos+2])
		pos += 3
	default:
		if lengthByte >= 0x80 {
			// Indefinite lengths and 4-byte counts are not emitted by Image4;
			// refusing them keeps this walker small and its cost predictable.
			return kernelTLV{}, fmt.Errorf("unsupported TLV length marker 0x%02x at offset %d", lengthByte, off+1)
		}
		length = int(lengthByte) // short form: 0..127
	}

	// A declared length larger than the whole file is the classic corrupt (or
	// hostile) container: reject it before slicing, and cap it independently
	// so a huge file cannot make us allocate a huge kernel image.
	if length > maxKernelCachePayload {
		return kernelTLV{}, fmt.Errorf("TLV at offset %d declares %d bytes, above the %d-byte kernelcache limit", off, length, maxKernelCachePayload)
	}
	if pos > len(buf) {
		return kernelTLV{}, fmt.Errorf("TLV length header at offset %d runs past the %d-byte file", off, len(buf))
	}
	if length > len(buf)-pos {
		return kernelTLV{}, fmt.Errorf("TLV at offset %d declares %d bytes but only %d remain", off, length, len(buf)-pos)
	}
	return kernelTLV{tag: tag, value: buf[pos : pos+length], end: pos + length}, nil
}

// findIM4P searches the constructed children of an Image4 sequence for the
// IM4P record. The depth limit matters because these tags come from the file:
// arbitrarily nested sequences must not turn into unbounded recursion.
func findIM4P(content []byte, depth int) ([]byte, error) {
	if depth > kernelMaxTLVDepth {
		return nil, fmt.Errorf("IMG4 TLV nesting exceeds %d levels", kernelMaxTLVDepth)
	}
	for off := 0; off < len(content); {
		child, err := readKernelTLV(content, off)
		if err != nil {
			return nil, fmt.Errorf("IMG4 TLV at offset %d: %w", off, err)
		}
		if child.tag == kernelTagSequence {
			first, err := readKernelTLV(child.value, 0)
			if err == nil && first.tag == kernelTagIA5String && string(first.value) == "IM4P" {
				return child.value, nil
			}
			// A manifest or property group can wrap other sequences. Skip
			// opaque children when they do not decode as an IM4P record.
			if nested, err := findIM4P(child.value, depth+1); err == nil {
				return nested, nil
			}
		}
		// end is greater than the header start for every valid TLV, so the
		// scan always advances even for tags we do not interpret.
		off = child.end
	}
	return nil, fmt.Errorf("IMG4 container has no IM4P payload sequence")
}

// im4pPayload reads the fourcc and the first OCTET STRING of an IM4P record.
// KBAG and property fields may follow the payload, so only the first OCTET
// STRING is the image data.
func im4pPayload(content []byte) ([]byte, error) {
	var fourcc string
	var payload []byte
	for off := 0; off < len(content); {
		field, err := readKernelTLV(content, off)
		if err != nil {
			return nil, fmt.Errorf("IM4P field at offset %d: %w", off, err)
		}
		switch {
		case field.tag == kernelTagIA5String && string(field.value) == "IM4P":
			// The record magic; the following IA5 string is the fourcc.
		case field.tag == kernelTagIA5String && fourcc == "":
			fourcc = string(field.value)
		case field.tag == kernelTagOctetString && payload == nil:
			payload = field.value
		}
		off = field.end
	}
	if fourcc != "krnl" {
		return nil, fmt.Errorf("IMG4 IM4P type is %q, want %q", fourcc, "krnl")
	}
	if payload == nil {
		return nil, fmt.Errorf("IMG4 IM4P has no OCTET STRING payload")
	}
	return payload, nil
}

// isLZFSE reports whether the payload starts with one of the block magics an
// IM4P LZFSE stream can begin with.
func isLZFSE(data []byte) bool {
	for _, magic := range [...]string{"bvx2", "bvx-", "bvxn", "bvx$"} {
		if bytes.HasPrefix(data, []byte(magic)) {
			return true
		}
	}
	return false
}

// inflateKernelCache decompresses an LZFSE payload with the vendored reader.
// The LimitReader stops a corrupt stream that claims an enormous expansion,
// and the recover guards against panics in the third-party decoder: malformed
// firmware must produce an error, never take down the analysis run.
func inflateKernelCache(data []byte) (out []byte, err error) {
	defer func() {
		if r := recover(); r != nil {
			out, err = nil, fmt.Errorf("LZFSE decoder panicked: %v", r)
		}
	}()
	reader := io.LimitReader(lzfse.NewReader(bytes.NewReader(data)), maxKernelCachePayload+1)
	out, err = io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("decompress LZFSE payload: %w", err)
	}
	if len(out) > maxKernelCachePayload {
		return nil, fmt.Errorf("LZFSE payload expands to %d bytes, above the %d-byte limit", len(out), maxKernelCachePayload)
	}
	return out, nil
}

// isMachOMagic accepts all four Mach-O magics (32/64-bit, either byte order),
// matching the raw bytes used by IsKernelCache.
func isMachOMagic(head []byte) bool {
	if len(head) < 4 {
		return false
	}
	switch binary.BigEndian.Uint32(head[:4]) {
	case 0xfeedface, 0xfeedfacf, 0xcefaedfe, 0xcffaedfe:
		return true
	}
	return false
}

// notKernelMachO names the bytes we saw: "not a Mach-O" alone would leave a
// caller unable to tell compressed, encrypted and mislabelled payloads apart.
func notKernelMachO(prefix []byte) error {
	n := min(len(prefix), kernelHeaderInspectLen)
	return fmt.Errorf("kernelcache payload is not a Mach-O; first %d bytes are %x", n, prefix[:n])
}

// openKernelCache extracts the Mach-O from an Apple kernelcache container.
// Returns the payload bytes, a human label, and an error.
func openKernelCache(r io.ReaderAt, size int64) ([]byte, string, error) {
	// The magic check needs four bytes. A larger file cannot contain an
	// in-limit kernel image: the Image4 wrapper is small compared with the
	// payload, so the same cap applies to the file we are about to buffer.
	if size < 4 {
		return nil, "", fmt.Errorf("kernelcache is %d bytes, too short to hold a magic", size)
	}
	if size > maxKernelCachePayload {
		return nil, "", fmt.Errorf("kernelcache is %d bytes, above the %d-byte inspection limit", size, maxKernelCachePayload)
	}
	data := make([]byte, int(size))
	if _, err := io.ReadFull(io.NewSectionReader(r, 0, size), data); err != nil {
		return nil, "", fmt.Errorf("read kernelcache: %w", err)
	}

	if !isMachOMagic(data[:4]) {
		if !bytes.Equal(data[:4], []byte("IMG4")) && data[0] != kernelTagSequence {
			return nil, "", fmt.Errorf("not an IMG4 container or Mach-O; first %d bytes are %x",
				min(len(data), kernelHeaderInspectLen), data[:min(len(data), kernelHeaderInspectLen)])
		}
		// An IMG4 file starts with the ASCII magic and then its top-level
		// DER sequence. Also accept the pure-DER spelling, where that same
		// "IMG4" IA5 string is the first child of the sequence at offset 0.
		off := 4
		if data[0] == kernelTagSequence {
			off = 0
		}
		outer, err := readKernelTLV(data, off)
		if err != nil {
			return nil, "", fmt.Errorf("IMG4 outer TLV: %w", err)
		}
		if outer.tag != kernelTagSequence {
			return nil, "", fmt.Errorf("IMG4 outer TLV has tag 0x%02x, want 0x%02x", outer.tag, kernelTagSequence)
		}
		record, err := findIM4P(outer.value, 0)
		if err != nil {
			return nil, "", err
		}
		payload, err := im4pPayload(record)
		if err != nil {
			return nil, "", err
		}
		if isLZFSE(payload) {
			payload, err = inflateKernelCache(payload)
			if err != nil {
				return nil, "", err
			}
		}
		if !isMachOMagic(payload) {
			return nil, "", notKernelMachO(payload)
		}
		return payload, "img4-kernel", nil
	}
	// A bare kext-collection Mach-O is already what the analyser needs; the
	// whole file is the image, so no container parsing is involved.
	return data, "kext-collection", nil
}

// kernelCacheHead reads the prefix IsKernelCache needs to classify a file.
// isKernelCacheHead is the container gate.
//
// It deliberately does NOT call IsKernelCache. That predicate accepts any Mach-O
// whose filetype is MH_EXECUTE (0x02), which is every ordinary executable — using
// it here would route every Mach-O on the system through the kernelcache loader.
// A container gate must be narrow: IMG4 wrappers, and bare Mach-O files that are
// genuinely MH_KEXT_BUNDLE (0x0B).
func isKernelCacheHead(head []byte) bool {
	if len(head) < 8 {
		return false
	}
	if string(head[:4]) == "IMG4" {
		ok, _ := IsKernelCache(head)
		return ok
	}
	if !isThinMachO([4]byte(head[:4])) && binary.BigEndian.Uint32(head[:4]) != macho.MagicFat {
		return false
	}
	var file *macho.File
	if isThinMachO([4]byte(head[:4])) {
		if parsed, err := macho.NewFile(bytes.NewReader(head)); err == nil {
			file = parsed
		}
	}
	if file == nil {
		return false
	}
	// debug/macho has no kext constant; MH_KEXT_BUNDLE is 0x0b in every SDK.
	return file.Type == machoTypeKextBundle
}

// kernelCacheHead reads the prefix the container gate inspects.
func kernelCacheHead(r io.ReaderAt, size int64) []byte {
	const limit = 4096
	if size <= 0 {
		return nil
	}
	n := int64(limit)
	if size < n {
		n = size
	}
	head := make([]byte, n)
	if _, err := r.ReadAt(head, 0); err != nil {
		return nil
	}
	return head
}
