package sysimage

import (
	"encoding/binary"
	"math"
)

const (
	dyldMappingEntrySize = 32    // size of dyld_cache_mapping_info
	dyldMaxMappingCount  = 65536 // hard cap on the number of decoded mappings
)

// DyldMapping is one mapping in a dyld shared cache header.
type DyldMapping struct {
	Address    uint64 `json:"address"`
	Size       uint64 `json:"size"`
	FileOffset uint64 `json:"file_offset"`
}

// ParseDyldMappings decodes the mapping table.
// header is the first 68+ bytes, blob is the raw mapping-info data.
// Layout per entry (32 bytes, little endian): address u64, size u64,
// fileOffset u64, maxProt i32, initProt i32.
func ParseDyldMappings(blob []byte, count uint32) []DyldMapping {
	if count > dyldMaxMappingCount {
		count = dyldMaxMappingCount
	}
	if count == 0 || len(blob) < dyldMappingEntrySize {
		return []DyldMapping{}
	}
	// Stop cleanly when the blob holds fewer records than the header claims.
	if want := int(count) * dyldMappingEntrySize; len(blob) < want {
		count = uint32(len(blob) / dyldMappingEntrySize)
	}

	mappings := make([]DyldMapping, 0, count)
	for i := uint32(0); i < count; i++ {
		start := int(i) * dyldMappingEntrySize
		rec := blob[start : start+dyldMappingEntrySize]
		mappings = append(mappings, DyldMapping{
			Address:    binary.LittleEndian.Uint64(rec[0:8]),
			Size:       binary.LittleEndian.Uint64(rec[8:16]),
			FileOffset: binary.LittleEndian.Uint64(rec[16:24]),
		})
	}
	return mappings
}

// ExtractDyldImage returns the bytes of one image as laid out in the cache.
// image.Address is translated to a file offset through mappings, and
// size bytes are copied. Returns nil when the range is not mapped.
func ExtractDyldImage(cache []byte, mappings []DyldMapping, image DyldImage, size uint64) []byte {
	for _, m := range mappings {
		// Half-open range [Address, Address+Size). Subtract rather than add
		// so an overflowing Address+Size cannot wrap into a false match.
		if m.Size == 0 || image.Address < m.Address || image.Address-m.Address >= m.Size {
			continue
		}

		delta := image.Address - m.Address
		if m.FileOffset > math.MaxUint64-delta {
			return nil
		}
		off := m.FileOffset + delta
		if off > uint64(len(cache)) || size > uint64(len(cache))-off {
			return nil
		}

		out := make([]byte, int(size))
		copy(out, cache[int(off):int(off)+len(out)])
		return out
	}
	return nil
}
