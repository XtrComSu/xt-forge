package sysimage

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"
)

// kernelTLVBytes writes one DER-style tag-length-value record. Values of
// 128..255 bytes use the 0x81 long form and larger ones use 0x82, so the
// fixtures exercise the same length encodings as real Image4 containers.
func kernelTLVBytes(tag byte, value []byte) []byte {
	var header []byte
	switch n := len(value); {
	case n < 0x80:
		header = []byte{tag, byte(n)}
	case n <= 0xff:
		header = []byte{tag, 0x81, byte(n)}
	case n <= 0xffff:
		header = []byte{tag, 0x82, byte(n >> 8), byte(n)}
	default:
		header = []byte{tag, 0x83, byte(n >> 16), byte(n >> 8), byte(n)}
	}
	return append(header, value...)
}

// kernelIMG4Fixture wraps a payload in an IM4P record inside an IMG4 sequence.
func kernelIMG4Fixture(fourcc string, description string, payload []byte) []byte {
	im4p := kernelTLVBytes(kernelTagIA5String, []byte("IM4P"))
	im4p = append(im4p, kernelTLVBytes(kernelTagIA5String, []byte(fourcc))...)
	im4p = append(im4p, kernelTLVBytes(kernelTagIA5String, []byte(description))...)
	im4p = append(im4p, kernelTLVBytes(kernelTagOctetString, payload)...)

	body := kernelTLVBytes(kernelTagIA5String, []byte("IMG4"))
	body = append(body, kernelTLVBytes(kernelTagSequence, im4p)...)
	body = append(body, kernelTLVBytes(0xa0, []byte("opaque manifest"))...)
	return append([]byte("IMG4"), kernelTLVBytes(kernelTagSequence, body)...)
}

// kernelLZFSEStream builds an uncompressed LZFSE stream: an uncompressed
// block ("bvx-", raw length, raw bytes) followed by the end-of-stream block
// ("bvx$"). It is enough to exercise the vendored decompressor without an
// LZFSE encoder in the standard library.
func kernelLZFSEStream(raw []byte) []byte {
	stream := []byte("bvx-")
	var length [4]byte
	binary.LittleEndian.PutUint32(length[:], uint32(len(raw)))
	stream = append(stream, length[:]...)
	stream = append(stream, raw...)
	return append(stream, []byte("bvx$")...)
}

func TestOpenKernelCacheIMG4RawPayload(t *testing.T) {
	image := machFixture()
	for _, tc := range []struct {
		name        string
		description string
	}{
		{"short form lengths", "kernel fixture"},
		{"0x81 length form", strings.Repeat("d", 200)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			img4 := kernelIMG4Fixture("krnl", tc.description, image)
			data, label, err := openKernelCache(bytes.NewReader(img4), int64(len(img4)))
			if err != nil {
				t.Fatalf("openKernelCache: %v", err)
			}
			if !bytes.Equal(data, image) {
				t.Fatalf("extracted %d bytes, want the %d-byte Mach-O", len(data), len(image))
			}
			if label != "img4-kernel" {
				t.Errorf("label = %q, want %q", label, "img4-kernel")
			}
		})
	}
}

func TestOpenKernelCacheIMG4LZFSEPayload(t *testing.T) {
	image := machFixture()
	img4 := kernelIMG4Fixture("krnl", "LZFSE kernel", kernelLZFSEStream(image))
	data, label, err := openKernelCache(bytes.NewReader(img4), int64(len(img4)))
	if err != nil {
		t.Fatalf("openKernelCache: %v", err)
	}
	if !bytes.Equal(data, image) {
		t.Fatalf("decompressed %d bytes, want the %d-byte Mach-O", len(data), len(image))
	}
	if label != "img4-kernel" {
		t.Errorf("label = %q, want %q", label, "img4-kernel")
	}
}

func TestOpenKernelCacheBareMachO(t *testing.T) {
	for _, tc := range []struct {
		name  string
		order binary.ByteOrder
		magic uint32
	}{
		{"64-bit little endian", binary.LittleEndian, 0xfeedfacf},
		{"32-bit little endian", binary.LittleEndian, 0xfeedface},
		{"64-bit big endian", binary.BigEndian, 0xfeedfacf},
		{"32-bit big endian", binary.BigEndian, 0xfeedface},
	} {
		t.Run(tc.name, func(t *testing.T) {
			image := append(machoHeader(tc.order, tc.magic, 0x0100000c, 0x0b), []byte("kext body")...)
			data, label, err := openKernelCache(bytes.NewReader(image), int64(len(image)))
			if err != nil {
				t.Fatalf("openKernelCache: %v", err)
			}
			if !bytes.Equal(data, image) {
				t.Fatalf("bare Mach-O was changed: got %d bytes, want %d", len(data), len(image))
			}
			if label != "kext-collection" {
				t.Errorf("label = %q, want %q", label, "kext-collection")
			}
		})
	}
}

func TestOpenKernelCacheHugeTLVLength(t *testing.T) {
	// The outer sequence claims 0x7fffff bytes in an 8-byte file.
	huge := append([]byte("IMG4"), 0x30, 0x83, 0x7f, 0xff, 0xff)
	data, label, err := openKernelCache(bytes.NewReader(huge), int64(len(huge)))
	if err == nil {
		t.Fatalf("huge TLV length succeeded with %d bytes, label %q", len(data), label)
	}

	// A payload TLV nested inside a valid outer sequence must be rejected too.
	body := kernelTLVBytes(kernelTagIA5String, []byte("IMG4"))
	body = append(body, 0x30, 0x07, 0x16, 0x04, 'I', 'M', 0x04, 0x83)
	body = append(body, 0x7f, 0xff, 0xff)
	nested := append([]byte("IMG4"), kernelTLVBytes(kernelTagSequence, body)...)
	if _, _, err := openKernelCache(bytes.NewReader(nested), int64(len(nested))); err == nil {
		t.Fatal("nested huge TLV length succeeded, want an error")
	}

	// A bogus size must be rejected before any allocation happens.
	if _, _, err := openKernelCache(bytes.NewReader(huge), 1<<40); err == nil {
		t.Fatal("bogus file size succeeded, want an error")
	}
}

func TestOpenKernelCacheTruncatedTLV(t *testing.T) {
	cases := [][]byte{
		[]byte("IMG4"),                             // no TLV header
		[]byte("IMG4\x30"),                         // no length byte
		[]byte("IMG4\x30\x82\x01"),                 // partial long-form length
		[]byte("IMG4\x30\x08\x16\x04IM"),           // value shorter than declared
		[]byte("IMG4\x30\x04\x16\x04"),             // IA5 string without value
		[]byte("IMG4\x30\x06\x16\x04IMG4\x30\x82"), // sequence header at the end
	}
	for i, tc := range cases {
		data, label, err := openKernelCache(bytes.NewReader(tc), int64(len(tc)))
		if err == nil {
			t.Errorf("case %d: truncated TLV succeeded with %d bytes, label %q", i, len(data), label)
		}
	}
}

func TestOpenKernelCacheNonMachOPayload(t *testing.T) {
	payload := []byte("not-a-macho-payload")
	img4 := kernelIMG4Fixture("krnl", "not an image", payload)
	data, label, err := openKernelCache(bytes.NewReader(img4), int64(len(img4)))
	if err == nil {
		t.Fatalf("non-Mach-O payload succeeded with %d bytes, label %q", len(data), label)
	}
	if want := hex.EncodeToString(payload[:8]); !strings.Contains(err.Error(), want) {
		t.Errorf("error %q does not name the first 8 bytes (%s)", err, want)
	}

	// A different fourcc is not a kernel payload either.
	other := kernelIMG4Fixture("ibot", "bootloader", machFixture())
	if _, _, err := openKernelCache(bytes.NewReader(other), int64(len(other))); err == nil {
		t.Fatal("IM4P with a non-krnl fourcc succeeded, want an error")
	}
}
