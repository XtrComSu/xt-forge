package sysimage

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

// The two GUIDs below are written into the synthetic FV byte by byte. Their
// expected strings are spelled out so the package's GUID byte order is checked
// rather than recomputed by the same formatter under test.
var (
	uefiGUIDA = [16]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10}
	uefiGUIDB = [16]byte{0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20}
)

const (
	uefiTestGUIDA = "04030201-0605-0807-090a-0b0c0d0e0f10"
	uefiTestGUIDB = "14131211-1615-1817-191a-1b1c1d1e1f20"
	uefiTestHdr   = 72 // 56 fixed bytes + one 8-byte block-map entry + terminator
)

type uefiTestFile struct {
	guid     [16]byte
	typeCode byte
	size     uint32
	large    bool
	extended uint64 // real size when size[3] is the 0xFFFFFF marker
}

// uefiTestVolume writes a firmware volume byte by byte: the header fields at
// the offsets documented in uefi.go, a block map, and 8-byte-aligned FFS file
// headers with their declared sizes.
func uefiTestVolume(files ...uefiTestFile) []byte {
	var total uint64 = uefiTestHdr
	for _, f := range files {
		size := uint64(f.size)
		if f.large {
			size = f.extended
		}
		total = (total + 7) &^ 7
		total += size
	}
	buf := make([]byte, (total+7)&^7)

	for i := 0; i < 16; i++ {
		buf[16+i] = byte(0xa0 + i) // FileSystemGuid
	}
	binary.LittleEndian.PutUint64(buf[32:40], uint64(len(buf))) // FvLength
	copy(buf[40:44], "_FVH")                                    // Signature == 0x4856465F LE
	binary.LittleEndian.PutUint16(buf[48:50], uefiTestHdr)      // HeaderLength
	binary.LittleEndian.PutUint32(buf[56:60], 1)                // block map: one entry
	binary.LittleEndian.PutUint32(buf[60:64], 8)
	// bytes 64:72 stay zero: the terminating block-map entry

	off := uint64(uefiTestHdr)
	for _, f := range files {
		copy(buf[off:off+16], f.guid[:]) // Name[16]
		buf[off+18] = f.typeCode         // Type
		buf[off+19] = 0                  // Attributes
		size := f.size
		if f.large {
			buf[off+20], buf[off+21], buf[off+22] = 0xff, 0xff, 0xff
			binary.LittleEndian.PutUint64(buf[off+24:off+32], f.extended)
			size = uint32(f.extended)
		} else {
			buf[off+20] = byte(size)
			buf[off+21] = byte(size >> 8)
			buf[off+22] = byte(size >> 16)
		}
		buf[off+23] = 0x01 // State
		off = (off + uint64(size) + 7) &^ 7
	}
	return buf
}

func TestIsUEFIVolume(t *testing.T) {
	buf := uefiTestVolume(uefiTestFile{guid: uefiGUIDA, size: 24})
	if !IsUEFIVolume(buf[:44]) || !IsUEFIVolume(buf) {
		t.Fatal("valid firmware volume signature was not recognized")
	}
	for _, head := range [][]byte{nil, make([]byte, 43), bytes.Repeat([]byte{0xcc}, 128), []byte("_FVH")} {
		if IsUEFIVolume(head) {
			t.Fatalf("random or short bytes %q were accepted", head)
		}
	}
}

func TestReadUEFIVolumeTwoFiles(t *testing.T) {
	buf := uefiTestVolume(
		uefiTestFile{guid: uefiGUIDA, typeCode: 0x02, size: 24},
		uefiTestFile{guid: uefiGUIDB, typeCode: 0xff, size: 32},
	)
	volume, err := ReadUEFIVolume(bytes.NewReader(buf), int64(len(buf)), 0)
	if err != nil {
		t.Fatalf("parse volume: %v", err)
	}
	if volume.Length != uint64(len(buf)) || volume.HeaderLength != uefiTestHdr {
		t.Fatalf("header fields: %+v", volume)
	}
	if volume.FileCount != 2 || len(volume.Files) != 2 {
		t.Fatalf("file count: %+v", volume)
	}
	want := []UEFIFile{
		{Name: uefiTestGUIDA, GUID: uefiTestGUIDA, Offset: 72, Size: 24, Type: 0x02},
		{Name: uefiTestGUIDB, GUID: uefiTestGUIDB, Offset: 96, Size: 32, Type: 0xff},
	}
	for i, expected := range want {
		if volume.Files[i] != expected {
			t.Fatalf("file %d: got %+v, want %+v", i, volume.Files[i], expected)
		}
	}
	if volume.Extracted {
		t.Fatal("read-only inventory must not claim the payload was extracted")
	}
}

func TestReadUEFIVolumeBadSignature(t *testing.T) {
	buf := uefiTestVolume(uefiTestFile{guid: uefiGUIDA, size: 24})
	buf[40] = 'X'
	_, err := ReadUEFIVolume(bytes.NewReader(buf), int64(len(buf)), 0)
	if err == nil || !strings.Contains(err.Error(), "signature") {
		t.Fatalf("bad signature should be named in the error, got %v", err)
	}
}

func TestReadUEFIVolumeLengthBeyondFile(t *testing.T) {
	buf := uefiTestVolume(uefiTestFile{guid: uefiGUIDA, size: 24})
	binary.LittleEndian.PutUint64(buf[32:40], uint64(len(buf))+8)
	_, err := ReadUEFIVolume(bytes.NewReader(buf), int64(len(buf)), 0)
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversized FvLength should be rejected, got %v", err)
	}
}

func TestReadUEFIVolumeZeroGUIDTerminates(t *testing.T) {
	buf := uefiTestVolume(
		uefiTestFile{guid: uefiGUIDA, typeCode: 0x02, size: 24},
		uefiTestFile{guid: [16]byte{}, typeCode: 0x07, size: 24}, // end marker
		uefiTestFile{guid: uefiGUIDB, typeCode: 0x07, size: 24},  // must be ignored
	)
	volume, err := ReadUEFIVolume(bytes.NewReader(buf), int64(len(buf)), 0)
	if err != nil {
		t.Fatalf("zero GUID should stop cleanly: %v", err)
	}
	if volume.FileCount != 1 || len(volume.Files) != 1 || volume.Files[0].Name != uefiTestGUIDA {
		t.Fatalf("files after the zero GUID were read: %+v", volume)
	}
}

func TestReadUEFIVolumeLargeFile(t *testing.T) {
	// Large-file entries are handled: Size[3] == 0xFFFFFF is resolved through
	// EFI_FFS_FILE_HEADER2.ExtendedSize at +24, capped at uint32 for reporting.
	buf := uefiTestVolume(uefiTestFile{guid: uefiGUIDA, typeCode: 0x07, large: true, extended: 32})
	volume, err := ReadUEFIVolume(bytes.NewReader(buf), int64(len(buf)), 0)
	if err != nil {
		t.Fatalf("parse large file: %v", err)
	}
	if volume.FileCount != 1 || len(volume.Files) != 1 || volume.Files[0].Size != 32 {
		t.Fatalf("large file size: %+v", volume)
	}

	// An implausible extended size fails with a clear message rather than a panic.
	binary.LittleEndian.PutUint64(buf[uefiTestHdr+24:uefiTestHdr+32], 1<<40)
	if _, err = ReadUEFIVolume(bytes.NewReader(buf), int64(len(buf)), 0); err == nil ||
		!strings.Contains(err.Error(), "large uefi file") {
		t.Fatalf("invalid extended size should be rejected clearly, got %v", err)
	}
}

func TestReadUEFIVolumeLimit(t *testing.T) {
	buf := uefiTestVolume(
		uefiTestFile{guid: uefiGUIDA, size: 24},
		uefiTestFile{guid: uefiGUIDB, size: 24},
	)
	volume, err := ReadUEFIVolume(bytes.NewReader(buf), int64(len(buf)), 1)
	if err != nil || volume.FileCount != 1 || len(volume.Files) != 1 {
		t.Fatalf("file limit: count=%d files=%d err=%v", volume.FileCount, len(volume.Files), err)
	}
}

func TestReadUEFIVolumeDetected(t *testing.T) {
	buf := uefiTestVolume(uefiTestFile{guid: uefiGUIDA, typeCode: 0x02, size: 24})
	format, images, err := inspect(bytes.NewReader(buf), uint64(len(buf)), false, "")
	if err != nil || format != "uefi" || len(images) != 1 || images[0].UEFI == nil {
		t.Fatalf("detection: format=%q images=%d uefi=%+v err=%v", format, len(images), images, err)
	}
	if images[0].UEFI.FileCount != 1 || images[0].UEFI.Files[0].Name != uefiTestGUIDA {
		t.Fatalf("detected volume: %+v", images[0].UEFI)
	}
}
