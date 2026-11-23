package sysimage

import "encoding/binary"

// DyldCacheInfo describes an Apple dyld shared cache header.
type DyldCacheInfo struct {
	Magic        string `json:"magic"`
	Arch         string `json:"arch"`
	MappingCount uint32 `json:"mapping_count"`
	ImagesCount  uint32 `json:"images_count"`
	BaseAddress  uint64 `json:"base_address"`
}

const (
	dyldCacheMagic     = 0x646c7964 // "dyld" as little-endian chars d,y,l,d
	dyldCacheArchOff   = 36
	dyldCacheArchLen   = 16
	dyldCacheHeaderLen = 68 // through sharedRegionStart (offset 60, 8 bytes)
)

// ParseDyldCache parses the header of an Apple dyld shared cache.
// Returns ok=false when the bytes are not a dyld shared cache.
func ParseDyldCache(head []byte) (DyldCacheInfo, bool) {
	if len(head) < dyldCacheHeaderLen || binary.LittleEndian.Uint32(head[0:4]) != dyldCacheMagic {
		return DyldCacheInfo{}, false
	}

	arch := dyldCacheArch(head[dyldCacheArchOff : dyldCacheArchOff+dyldCacheArchLen])
	return DyldCacheInfo{
		Magic:        "dyld_v1 " + arch,
		Arch:         arch,
		MappingCount: binary.LittleEndian.Uint32(head[8:12]),  // mappingCount
		ImagesCount:  binary.LittleEndian.Uint32(head[16:20]), // imagesCountOld
		BaseAddress:  binary.LittleEndian.Uint64(head[60:68]), // sharedRegionStart
	}, true
}

// dyldCacheArch decodes the NUL-padded ASCII arch field. A non-ASCII byte
// invalidates the field, yielding an empty string.
func dyldCacheArch(raw []byte) string {
	var arch []byte
	for _, c := range raw {
		if c == 0 {
			break
		}
		if c >= 0x80 {
			return ""
		}
		arch = append(arch, c)
	}
	return string(arch)
}
