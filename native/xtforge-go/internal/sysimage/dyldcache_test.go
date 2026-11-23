package sysimage

import (
	"encoding/binary"
	"testing"
)

// makeDyldCacheHeader builds a little-endian 64-bit dyld shared cache header.
func makeDyldCacheHeader(arch string, mappingCount, imagesCount uint32, base uint64) []byte {
	head := make([]byte, 72)
	binary.LittleEndian.PutUint32(head[0:], 0x646c7964) // magic "dyld"
	binary.LittleEndian.PutUint32(head[4:], 0x100)      // mappingOffset
	binary.LittleEndian.PutUint32(head[8:], mappingCount)
	binary.LittleEndian.PutUint32(head[12:], 0x200) // imagesOffsetOld
	binary.LittleEndian.PutUint32(head[16:], imagesCount)
	binary.LittleEndian.PutUint64(head[20:], 0x300) // dyldImageTextOffset
	binary.LittleEndian.PutUint64(head[28:], 1)     // dyldImageTextCount
	copy(head[36:52], arch)                         // arch[16]
	binary.LittleEndian.PutUint32(head[52:], 1)     // platform
	binary.LittleEndian.PutUint32(head[56:], 1)     // formatVersion
	binary.LittleEndian.PutUint64(head[60:], base)  // sharedRegionStart
	return head
}

func TestParseDyldCache(t *testing.T) {
	info, ok := ParseDyldCache(makeDyldCacheHeader("arm64e", 3, 1200, 0x180000000))
	if !ok {
		t.Fatal("valid dyld shared cache header was rejected")
	}
	if info.Magic != "dyld_v1 arm64e" {
		t.Errorf("Magic = %q, want %q", info.Magic, "dyld_v1 arm64e")
	}
	if info.Arch != "arm64e" {
		t.Errorf("Arch = %q, want %q", info.Arch, "arm64e")
	}
	if info.MappingCount != 3 {
		t.Errorf("MappingCount = %d, want 3", info.MappingCount)
	}
	if info.ImagesCount != 1200 {
		t.Errorf("ImagesCount = %d, want 1200", info.ImagesCount)
	}
	if info.BaseAddress != 0x180000000 {
		t.Errorf("BaseAddress = %#x, want %#x", info.BaseAddress, uint64(0x180000000))
	}
}

func TestParseDyldCacheShortInput(t *testing.T) {
	head := make([]byte, 32)
	binary.LittleEndian.PutUint32(head[0:], 0x646c7964)
	info, ok := ParseDyldCache(head)
	if ok || info != (DyldCacheInfo{}) {
		t.Fatalf("32-byte input: got (%+v, %v), want (zero, false)", info, ok)
	}
}

func TestParseDyldCacheNilInput(t *testing.T) {
	info, ok := ParseDyldCache(nil)
	if ok || info != (DyldCacheInfo{}) {
		t.Fatalf("nil input: got (%+v, %v), want (zero, false)", info, ok)
	}
}

func TestParseDyldCacheWrongMagic(t *testing.T) {
	head := makeDyldCacheHeader("arm64e", 3, 1200, 0x180000000)
	binary.LittleEndian.PutUint32(head[0:], 0xdeadbeef)
	info, ok := ParseDyldCache(head)
	if ok || info != (DyldCacheInfo{}) {
		t.Fatalf("wrong magic: got (%+v, %v), want (zero, false)", info, ok)
	}
}

func TestParseDyldCacheNonASCIIArch(t *testing.T) {
	head := makeDyldCacheHeader("arm64e", 3, 1200, 0x180000000)
	for i := 36; i < 52; i++ {
		head[i] = 0xff
	}
	info, ok := ParseDyldCache(head)
	if !ok {
		t.Fatal("header with non-ASCII arch was rejected")
	}
	if info.Arch != "" {
		t.Errorf("Arch = %q, want empty string", info.Arch)
	}
}
