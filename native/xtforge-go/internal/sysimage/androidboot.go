package sysimage

import (
	"compress/gzip"
	"encoding/binary"
	"fmt"
	"io"
)

// An Android boot image starts with the eight-byte magic "ANDROID!" followed by
// boot_img_hdr_v0, a little-endian header:
//
//	+8   kernel_size    u32    +12  kernel_addr    u32
//	+16  ramdisk_size   u32    +20  ramdisk_addr   u32
//	+24  second_size    u32    +28  second_addr    u32
//	+32  tags_addr      u32    +36  page_size      u32
//	+40  header_version u32    +44  os_version     u32
//	+48  name[16]              +64  cmdline[512]
//	+576 id[8]                 +584 extra_cmdline[1024]
//
// The header is followed by the kernel, ramdisk and second-stage payloads,
// padded out to page_size. Those payloads are compressed (usually gzip), so
// this reader stops at the header: it inventories what is present without
// pretending to have decoded an entry point or a function list.

const (
	androidBootMagic = "ANDROID!"

	// androidBootHeaderBytes covers every field this reader consumes, through
	// id[8] at +576. extra_cmdline starts at +584 and is deliberately ignored.
	androidBootHeaderBytes = 608

	// androidBootMaxImage is the package-wide cap for a payload we inventory.
	androidBootMaxImage = 512 << 20
)

// AndroidBoot is the read-only header inventory of an Android boot image.
// Version mirrors HeaderVersion as an int; both are zero for a v0 header.
type AndroidBoot struct {
	Version       int    `json:"version"`
	KernelSize    uint32 `json:"kernel_size"`
	KernelAddr    uint32 `json:"kernel_addr"`
	RamdiskSize   uint32 `json:"ramdisk_size"`
	PageSize      uint32 `json:"page_size"`
	Name          string `json:"name,omitempty"`
	Cmdline       string `json:"cmdline,omitempty"`
	OSVersion     string `json:"os_version,omitempty"`
	HeaderVersion uint32 `json:"header_version"`
	// KernelFormat names what the kernel payload is once gzip is peeled off: "elf",
	// "macho", "arm64-image", "gzip" (nested) or "unknown-<magic>". The payload is
	// described, not disassembled: a raw arm64 Image has no section table and needs an
	// explicit load address.
	KernelFormat string `json:"kernel_format,omitempty"`
	KernelMagic  string `json:"kernel_magic,omitempty"`
	KernelProbe  int    `json:"kernel_probe_bytes,omitempty"`
}

// IsAndroidBoot reports whether head begins with the eight-byte boot image
// magic. A head shorter than the magic, or a nil head, is not a boot image;
// this is safe to call on the short prefix a format dispatcher probes with.
func IsAndroidBoot(head []byte) bool {
	return len(head) >= len(androidBootMagic) && string(head[:len(androidBootMagic)]) == androidBootMagic
}

// ReadAndroidBoot parses the boot_img_hdr_v0 header at the start of r. size is
// the full file size and is used only to bound the input: a file shorter than
// 608 bytes, or larger than 512 MiB, is rejected before reading. Only the
// header is decoded; the compressed kernel and ramdisk are left untouched.
func ReadAndroidBoot(r io.ReaderAt, size int64) (AndroidBoot, error) {
	var boot AndroidBoot
	if r == nil {
		return boot, fmt.Errorf("android boot image requires a reader")
	}
	if size < androidBootHeaderBytes {
		return boot, fmt.Errorf("android boot image is only %d bytes; a header needs at least %d", size, androidBootHeaderBytes)
	}
	if size > androidBootMaxImage {
		return boot, fmt.Errorf("android boot image of %d bytes exceeds the %d MiB inspection limit", size, androidBootMaxImage>>20)
	}

	var head [androidBootHeaderBytes]byte
	if _, err := r.ReadAt(head[:], 0); err != nil {
		return boot, fmt.Errorf("read android boot header: %w", err)
	}
	if !IsAndroidBoot(head[:]) {
		return boot, fmt.Errorf("not an android boot image: bad magic %q", head[:len(androidBootMagic)])
	}

	boot.KernelSize = binary.LittleEndian.Uint32(head[8:12])
	boot.KernelAddr = binary.LittleEndian.Uint32(head[12:16])
	boot.RamdiskSize = binary.LittleEndian.Uint32(head[16:20])

	pageSize := binary.LittleEndian.Uint32(head[36:40])
	switch pageSize {
	case 2048, 4096, 8192, 16384:
		boot.PageSize = pageSize
	default:
		return AndroidBoot{}, fmt.Errorf("android boot image has invalid page size %d; expected one of 2048, 4096, 8192, 16384", pageSize)
	}

	// header_version and os_version are only meaningful from v1 onward. A v0
	// header reports Version 0, HeaderVersion 0 and an empty OSVersion even if
	// stray bytes happen to sit in the os_version slot.
	boot.HeaderVersion = binary.LittleEndian.Uint32(head[40:44])
	boot.Version = int(boot.HeaderVersion)
	if boot.HeaderVersion != 0 {
		boot.OSVersion = androidOSVersion(binary.LittleEndian.Uint32(head[44:48]))
	}

	boot.Name = androidNULString(head[48:64])
	boot.Cmdline = androidNULString(head[64:576])
	boot.KernelFormat, boot.KernelMagic, boot.KernelProbe = probeKernelPayload(r, boot)
	return boot, nil
}

// androidOSVersion renders a packed os_version word. The packing is:
//
//	bits 25..31 = a (major), 18..24 = b (minor), 11..17 = c (patch),
//	bits  4..10 = y (patch year minus 2000), 0..3 = m (patch month).
//
// A zero word is not a version and renders as "". The "/yyyy-mm" patch-date
// suffix is emitted only when a date was actually recorded; y is a 7-bit
// offset from 2000, so the year is rendered as 2000+y.
func androidOSVersion(v uint32) string {
	if v == 0 {
		return ""
	}
	a := (v >> 25) & 0x7f
	b := (v >> 18) & 0x7f
	c := (v >> 11) & 0x7f
	y := (v >> 4) & 0x7f
	m := v & 0xf

	version := fmt.Sprintf("%d.%d.%d", a, b, c)
	if y != 0 || m != 0 {
		version += fmt.Sprintf("/%04d-%02d", 2000+y, m)
	}
	return version
}

// androidNULString returns the printable prefix of a NUL-padded header field.
func androidNULString(field []byte) string {
	for i, b := range field {
		if b == 0 {
			return string(field[:i])
		}
	}
	return string(field)
}

// probeKernelPayload describes the kernel payload without extracting it.
//
// Every stock Android boot image stores a compressed kernel, so an inventory that stops
// at kernel_size tells an analyst almost nothing. Peeling the first layer and naming what
// is underneath ("gzip -> arm64-image") is the difference between "there is a payload"
// and "this is a Linux arm64 Image".
//
// Only a bounded prefix is decompressed: the goal is identification, not extraction.
func probeKernelPayload(r io.ReaderAt, boot AndroidBoot) (format, magic string, probe int) {
	if boot.KernelSize == 0 || boot.PageSize == 0 {
		return "", "", 0
	}
	const probeLimit = 64 << 10
	reader := io.NewSectionReader(r, int64(boot.PageSize), int64(boot.KernelSize))
	head := make([]byte, 1024)
	read, _ := io.ReadFull(reader, head)
	head = head[:read]
	if len(head) == 0 {
		return "", "", 0
	}
	magic = fmt.Sprintf("%x", head[:min(4, len(head))])

	payload := head
	if len(head) >= 2 && head[0] == 0x1f && head[1] == 0x8b {
		if _, err := reader.Seek(0, io.SeekStart); err == nil {
			if gz, err := gzip.NewReader(reader); err == nil {
				defer gz.Close()
				decompressed := make([]byte, probeLimit)
				count, _ := io.ReadFull(gz, decompressed)
				if count > 0 {
					payload = decompressed[:count]
					probe = count
				}
			}
		}
	}
	return classifyPayload(payload, magic), magic, probe
}

// classifyPayload names a payload from its leading bytes.
func classifyPayload(payload []byte, originalMagic string) string {
	switch {
	case len(payload) >= 4 && payload[0] == 0x7f && string(payload[1:4]) == "ELF":
		return "elf"
	case len(payload) >= 8 && (isThinMachO([4]byte(payload[:4])) ||
		binary.BigEndian.Uint32(payload[:4]) == 0xCAFEBABE):
		return "macho"
	case len(payload) >= 2 && payload[0] == 0x1f && payload[1] == 0x8b:
		return "gzip"
	case len(payload) >= 60 && string(payload[56:60]) == "ARMd":
		// The Linux arm64 Image magic sits at offset 56, after the branch and the
		// image header. It is the only reliable marker for a raw kernel image.
		return "arm64-image"
	case len(payload) >= 4 && string(payload[:4]) == "MZ\x00\x91":
		return "arm64-image"
	}
	return "unknown-" + originalMagic
}
