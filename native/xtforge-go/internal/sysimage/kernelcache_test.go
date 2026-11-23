package sysimage

import (
	"encoding/binary"
	"testing"
)

// machoHeader builds a minimal Mach-O header with the given byte order,
// logical magic, cpu type and file type. The magic is written using the
// supplied order, so callers get the raw byte sequences found in real files
// (e.g. 0xfeedfacf little-endian becomes CF FA ED FE).
func machoHeader(order binary.ByteOrder, magic, cputype, filetype uint32) []byte {
	h := make([]byte, 32)
	order.PutUint32(h[0:4], magic)
	order.PutUint32(h[4:8], cputype)
	order.PutUint32(h[12:16], filetype)
	return h
}

func TestIsKernelCache(t *testing.T) {
	img4 := func(marker string, markerOffset int) []byte {
		h := make([]byte, 4096+64)
		copy(h, []byte("IMG4"))
		copy(h[markerOffset:], marker)
		return h
	}

	tests := []struct {
		name string
		head []byte
		want bool
		desc string
	}{
		{
			name: "img4 with KERNEL marker",
			head: img4("KERNEL", 64),
			want: true,
			desc: "img4-kernel",
		},
		{
			name: "img4 with krnl marker",
			head: img4("krnl", 128),
			want: true,
			desc: "img4-kernel",
		},
		{
			name: "img4 without kernel marker",
			head: img4("payload", 64),
			want: false,
			desc: "",
		},
		{
			name: "img4 marker beyond scan window",
			head: img4("KERNEL", 4096),
			want: false,
			desc: "",
		},
		{
			name: "MH_KEXT_BUNDLE arm64 big-endian",
			head: machoHeader(binary.BigEndian, 0xfeedfacf, 0x0100000c, 0x0b),
			want: true,
			desc: "kext-collection",
		},
		{
			name: "MH_EXECUTE x86 little-endian",
			head: machoHeader(binary.LittleEndian, 0xfeedface, 0x00000007, 0x02),
			want: true,
			desc: "kext-collection",
		},
		{
			name: "macho with wrong filetype",
			head: machoHeader(binary.LittleEndian, 0xfeedfacf, 0x0100000c, 0x01),
			want: false,
			desc: "",
		},
		{
			name: "macho with wrong cputype",
			head: machoHeader(binary.BigEndian, 0xfeedface, 0x0000000c, 0x0b),
			want: false,
			desc: "",
		},
		{
			name: "random bytes",
			head: []byte{0x00, 0x01, 0x02, 0x03, 0x10, 0x20, 0x30, 0x40, 0x55, 0xaa, 0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe},
			want: false,
			desc: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, desc := IsKernelCache(tc.head)
			if got != tc.want || desc != tc.desc {
				t.Fatalf("IsKernelCache() = (%v, %q), want (%v, %q)", got, desc, tc.want, tc.desc)
			}
		})
	}
}

func TestIsKernelCacheShortInputs(t *testing.T) {
	short := [][]byte{
		nil,
		{},
		{0x00},
		{0x49, 0x4d, 0x47, 0x34},       // 4 bytes: "IMG4"
		{0x49, 0x4d, 0x47, 0x34, 0x00}, // 5 bytes
		{0xcf, 0xfa, 0xed, 0xfe, 0x0c, 0x00, 0x00, 0x01}, // 7 bytes
	}
	for _, head := range short {
		got, desc := IsKernelCache(head)
		if got || desc != "" {
			t.Errorf("IsKernelCache(%v) = (%v, %q), want (false, \"\")", head, got, desc)
		}
	}
}
