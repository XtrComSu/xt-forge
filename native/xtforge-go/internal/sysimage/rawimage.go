package sysimage

import (
	"fmt"
	"io"
	"math"
)

// maxRawImage mirrors the payload cap used by the other loaders in this package.
const maxRawImage = 512 << 20

// RawSpec describes how to interpret a file with no header.
type RawSpec struct {
	Arch         string `json:"arch"`
	Bits         int    `json:"bits"`
	Base         uint64 `json:"base"`
	Entry        uint64 `json:"entry,omitempty"`
	LittleEndian bool   `json:"little_endian"`
}

// rawBits maps an accepted raw architecture to its word size. Anything outside
// this table has no defined instruction decoder in this engine.
func rawBits(arch string) (int, bool) {
	switch arch {
	case "x86", "arm":
		return 32, true
	case "x86_64", "arm64":
		return 64, true
	}
	return 0, false
}

// ParseRawSpec validates a raw specification. arch must be one of x86, x86_64,
// arm, arm64; bits must be 16/32/64 and consistent with the arch; base may be 0.
//
// There is no bits argument to validate separately: the accepted architectures
// here are 32- or 64-bit only, so bits is derived from arch (16-bit raw input is
// therefore not accepted). All four accepted architectures are little-endian
// today, and that is recorded on both the spec and the resulting image.
func ParseRawSpec(arch string, base uint64) (RawSpec, error) {
	bits, ok := rawBits(arch)
	if !ok {
		return RawSpec{}, fmt.Errorf("unsupported raw architecture %q; accepted architectures: x86, x86_64, arm, arm64", arch)
	}
	return RawSpec{Arch: arch, Bits: bits, Base: base, LittleEndian: true}, nil
}

// RawImage builds an Image describing a headerless file at the given base.
// regions describe the executable extent (typically the whole file).
//
// A raw file has no metadata: the whole input becomes one file-backed executable
// section, dependencies and functions stay empty, and no entry point is invented
// unless the caller supplied one. A zero-length input is rejected — there is
// nothing to analyse — as is anything above the package's 512 MiB payload cap.
func RawImage(r io.ReaderAt, size int64, spec RawSpec) (Image, error) {
	if size <= 0 {
		return Image{}, fmt.Errorf("raw image is empty (%d bytes); nothing to analyse", size)
	}
	if size > maxRawImage {
		return Image{}, fmt.Errorf("raw image of %d bytes exceeds the %d MiB inspection limit", size, maxRawImage>>20)
	}
	bits, ok := rawBits(spec.Arch)
	if !ok {
		return Image{}, fmt.Errorf("unsupported raw architecture %q; accepted architectures: x86, x86_64, arm, arm64", spec.Arch)
	}
	if spec.Bits != 0 && spec.Bits != bits {
		return Image{}, fmt.Errorf("raw spec bits %d are inconsistent with architecture %q (%d bits)", spec.Bits, spec.Arch, bits)
	}
	length := uint64(size)
	if spec.Base > math.MaxUint64-length {
		return Image{}, fmt.Errorf("raw image at base %#x and size %d overflows the address space", spec.Base, size)
	}
	if r == nil {
		return Image{}, fmt.Errorf("raw image requires a reader")
	}

	region := Region{
		Name:     "raw",
		Address:  spec.Base,
		Size:     length,
		Offset:   0,
		FileSize: length,
	}
	image := Image{
		Arch:         spec.Arch,
		Bits:         bits,
		Sections:     []Region{region},
		Executable:   []Region{region},
		Dependencies: []string{},
		functions:    make(map[uint64]Function),
		fileSize:     length,
		littleEndian: true,
	}
	if spec.Entry != 0 {
		entry := spec.Entry
		image.EntryPoint = &entry
	}
	return image, nil
}
