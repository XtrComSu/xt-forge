package sysimage

import (
	"encoding/binary"
	"reflect"
	"testing"
)

// makeDyldImageInfo builds one little-endian dyld_cache_image_info record.
func makeDyldImageInfo(addr uint64, pathOffset int32) []byte {
	info := make([]byte, 32)
	binary.LittleEndian.PutUint64(info[0:8], addr)                 // address
	binary.LittleEndian.PutUint64(info[8:16], 0)                   // modTime
	binary.LittleEndian.PutUint64(info[16:24], 0)                  // inode
	binary.LittleEndian.PutUint32(info[24:28], uint32(pathOffset)) // pathFileOffset
	return info
}

func TestParseDyldImagesExactMatch(t *testing.T) {
	const p1 = "/usr/lib/libSystem.B.dylib"
	const p2 = "/usr/lib/libobjc.A.dylib"
	strings := []byte(p1 + "\x00" + p2 + "\x00")

	blob := append(makeDyldImageInfo(0x180000000, 0),
		makeDyldImageInfo(0x180200000, int32(len(p1)+1))...)

	got := ParseDyldImages(blob, strings, 2)
	want := []DyldImage{
		{Path: p1, Address: 0x180000000},
		{Path: p2, Address: 0x180200000},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ParseDyldImages() = %+v, want %+v", got, want)
	}
}

func TestParseDyldImagesCountExceedsBlob(t *testing.T) {
	const p = "/usr/lib/libSystem.B.dylib"
	strings := []byte(p + "\x00")
	blob := makeDyldImageInfo(0x180000000, 0)

	// Only one record fits, so the oversized count must not panic or over-read.
	got := ParseDyldImages(blob, strings, 100)
	want := []DyldImage{{Path: p, Address: 0x180000000}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ParseDyldImages() = %+v, want %+v", got, want)
	}
}

func TestParseDyldImagesOffsetBeyondPool(t *testing.T) {
	const p = "/usr/lib/libSystem.B.dylib"
	strings := []byte(p + "\x00")

	blob := make([]byte, 0, 96)
	blob = append(blob, makeDyldImageInfo(0x180000000, 0)...)
	blob = append(blob, makeDyldImageInfo(0x180200000, int32(len(strings)))...) // at end
	blob = append(blob, makeDyldImageInfo(0x180400000, -1)...)                  // negative

	got := ParseDyldImages(blob, strings, 3)
	want := []DyldImage{{Path: p, Address: 0x180000000}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ParseDyldImages() = %+v, want %+v", got, want)
	}
}

func TestParseDyldImagesEmptyStringPool(t *testing.T) {
	blob := makeDyldImageInfo(0x180000000, 0)
	if got := ParseDyldImages(blob, []byte{}, 1); got != nil {
		t.Errorf("empty string pool: got %+v, want nil", got)
	}
	if got := ParseDyldImages(blob, nil, 1); got != nil {
		t.Errorf("nil string pool: got %+v, want nil", got)
	}
}

func TestParseDyldImagesNilBlobs(t *testing.T) {
	strings := []byte("/usr/lib/libSystem.B.dylib\x00")
	if got := ParseDyldImages(nil, nil, 2); got != nil {
		t.Errorf("nil blobs: got %+v, want nil", got)
	}
	if got := ParseDyldImages(nil, strings, 2); got != nil {
		t.Errorf("nil imagesBlob: got %+v, want nil", got)
	}
}

func TestParseDyldImagesNoTerminatingNUL(t *testing.T) {
	const p = "/usr/lib/libfoo.dylib"
	strings := []byte(p) // no NUL anywhere
	blob := makeDyldImageInfo(0x180000000, 0)

	got := ParseDyldImages(blob, strings, 1)
	want := []DyldImage{{Path: p, Address: 0x180000000}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ParseDyldImages() = %+v, want %+v", got, want)
	}
}

func TestParseDyldImagesCountCap(t *testing.T) {
	strings := []byte("/x\x00")
	const total = 65537 // one over the cap
	blob := make([]byte, total*32)
	for i := 0; i < total; i++ {
		e := blob[i*32 : (i+1)*32]
		binary.LittleEndian.PutUint64(e[0:8], uint64(0x180000000+i))
	}
	got := ParseDyldImages(blob, strings, total)
	if len(got) != 65536 {
		t.Errorf("len(ParseDyldImages()) = %d, want 65536", len(got))
	}
}
