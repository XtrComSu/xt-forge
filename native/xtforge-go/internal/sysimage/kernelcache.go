package sysimage

import (
	"bytes"
	"encoding/binary"
)

// IsKernelCache reports whether the bytes look like an Apple kernelcache
// (a Mach-O wrapped in an IMG4/KERNEL container or a bare kext-collection
// Mach-O) and returns a short description of what was recognised.
func IsKernelCache(head []byte) (bool, string) {
	const scanLimit = 4096

	// IMG4 container: "IMG4" magic followed somewhere in the first 4 KiB
	// by a KERNEL/krnl marker.
	if len(head) >= 4 && bytes.Equal(head[:4], []byte("IMG4")) {
		end := len(head)
		if end > scanLimit {
			end = scanLimit
		}
		window := head[:end]
		if bytes.Contains(window, []byte("KERNEL")) || bytes.Contains(window, []byte("krnl")) {
			return true, "img4-kernel"
		}
		return false, ""
	}

	// Bare Mach-O kext collection. The mach_header fields we need are
	// cputype at offset 4 and filetype at offset 12, so require a full
	// 16-byte header before reading them.
	if len(head) < 16 {
		return false, ""
	}

	var order binary.ByteOrder
	switch binary.BigEndian.Uint32(head[0:4]) {
	case 0xfeedface, 0xfeedfacf:
		order = binary.BigEndian
	case 0xcefaedfe, 0xcffaedfe:
		order = binary.LittleEndian
	default:
		return false, ""
	}

	cputype := order.Uint32(head[4:8])
	filetype := order.Uint32(head[12:16])

	validCPU := cputype == 0x0100000c || cputype == 0x00000007 // arm64 or x86
	validFile := filetype == 0x0b || filetype == 0x02          // MH_KEXT_BUNDLE or MH_EXECUTE
	if validCPU && validFile {
		return true, "kext-collection"
	}

	return false, ""
}
