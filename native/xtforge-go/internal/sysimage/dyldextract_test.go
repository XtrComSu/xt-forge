package sysimage

import (
	"bytes"
	"encoding/binary"
	"reflect"
	"testing"
)

// makeDyldMappingInfo builds one little-endian dyld_cache_mapping_info record.
func makeDyldMappingInfo(addr, size, fileOff uint64, maxProt, initProt int32) []byte {
	rec := make([]byte, dyldMappingEntrySize)
	binary.LittleEndian.PutUint64(rec[0:8], addr)
	binary.LittleEndian.PutUint64(rec[8:16], size)
	binary.LittleEndian.PutUint64(rec[16:24], fileOff)
	binary.LittleEndian.PutUint32(rec[24:28], uint32(maxProt))
	binary.LittleEndian.PutUint32(rec[28:32], uint32(initProt))
	return rec
}

func TestParseDyldMappings(t *testing.T) {
	t.Run("two entries", func(t *testing.T) {
		blob := append(
			makeDyldMappingInfo(0x180000000, 0x1000, 0x400, 5, 3),
			makeDyldMappingInfo(0x180001000, 0x1000, 0x1000, 5, 3)...,
		)
		want := []DyldMapping{
			{Address: 0x180000000, Size: 0x1000, FileOffset: 0x400},
			{Address: 0x180001000, Size: 0x1000, FileOffset: 0x1000},
		}
		if got := ParseDyldMappings(blob, 2); !reflect.DeepEqual(got, want) {
			t.Errorf("ParseDyldMappings() = %+v, want %+v", got, want)
		}
	})

	t.Run("nil blob", func(t *testing.T) {
		got := ParseDyldMappings(nil, 4)
		if got == nil || len(got) != 0 {
			t.Errorf("nil blob: got %+v, want a non-nil empty slice", got)
		}
	})

	t.Run("count larger than blob", func(t *testing.T) {
		blob := append(
			makeDyldMappingInfo(0x180000000, 0x1000, 0x400, 5, 3),
			makeDyldMappingInfo(0x180001000, 0x1000, 0x1000, 5, 3)...,
		)
		blob = append(blob, make([]byte, 7)...) // trailing partial record
		got := ParseDyldMappings(blob, 100)
		if len(got) != 2 {
			t.Fatalf("len(ParseDyldMappings()) = %d, want 2", len(got))
		}
		if got[1].Address != 0x180001000 || got[1].FileOffset != 0x1000 {
			t.Errorf("second mapping = %+v", got[1])
		}
	})

	t.Run("count cap", func(t *testing.T) {
		blob := make([]byte, (dyldMaxMappingCount+1)*dyldMappingEntrySize)
		got := ParseDyldMappings(blob, dyldMaxMappingCount+1)
		if len(got) != dyldMaxMappingCount {
			t.Errorf("len(ParseDyldMappings()) = %d, want %d", len(got), dyldMaxMappingCount)
		}
	})
}

func TestExtractDyldImage(t *testing.T) {
	cache := make([]byte, 0x2000)
	for i := range cache {
		cache[i] = byte(i)
	}
	mappings := []DyldMapping{
		{Address: 0x180000000, Size: 0x1000, FileOffset: 0x400},
		{Address: 0x180001000, Size: 0x1000, FileOffset: 0x1000},
	}

	t.Run("image in second mapping", func(t *testing.T) {
		image := DyldImage{Path: "/usr/lib/libfoo.dylib", Address: 0x180001100}
		want := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
		got := ExtractDyldImage(cache, mappings, image, uint64(len(want)))
		if !bytes.Equal(got, want) {
			t.Errorf("ExtractDyldImage() = %v, want %v", got, want)
		}
	})

	t.Run("image in first mapping", func(t *testing.T) {
		image := DyldImage{Address: 0x180000010}
		want := cache[0x410:0x414]
		if got := ExtractDyldImage(cache, mappings, image, 4); !bytes.Equal(got, want) {
			t.Errorf("ExtractDyldImage() = %v, want %v", got, want)
		}
	})

	t.Run("unmapped address", func(t *testing.T) {
		image := DyldImage{Address: 0x180004000}
		if got := ExtractDyldImage(cache, mappings, image, 4); got != nil {
			t.Errorf("unmapped address: got %v, want nil", got)
		}
	})

	t.Run("range overruns cache", func(t *testing.T) {
		image := DyldImage{Address: 0x180001ff8}
		if got := ExtractDyldImage(cache, mappings, image, 32); got != nil {
			t.Errorf("overrunning range: got %v, want nil", got)
		}
	})

	t.Run("zero size mapping matches nothing", func(t *testing.T) {
		zero := []DyldMapping{{Address: 0x1000, Size: 0, FileOffset: 0x200}}
		image := DyldImage{Address: 0x1000}
		if got := ExtractDyldImage(cache, zero, image, 1); got != nil {
			t.Errorf("zero-size mapping: got %v, want nil", got)
		}
	})

	t.Run("address just past mapping end", func(t *testing.T) {
		image := DyldImage{Address: 0x180002000} // end of second mapping
		if got := ExtractDyldImage(cache, mappings, image, 1); got != nil {
			t.Errorf("address at mapping end: got %v, want nil", got)
		}
	})

	t.Run("overflowing file offset", func(t *testing.T) {
		bad := []DyldMapping{{Address: 0x1000, Size: 0x100, FileOffset: ^uint64(0) - 1}}
		image := DyldImage{Address: 0x1010}
		if got := ExtractDyldImage(cache, bad, image, 1); got != nil {
			t.Errorf("overflowing file offset: got %v, want nil", got)
		}
	})

	t.Run("no mappings", func(t *testing.T) {
		if got := ExtractDyldImage(cache, nil, DyldImage{Address: 0x180000000}, 1); got != nil {
			t.Errorf("no mappings: got %v, want nil", got)
		}
	})
}
