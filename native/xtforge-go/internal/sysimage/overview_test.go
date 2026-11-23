package sysimage

import (
	"archive/zip"
	"bytes"
	"debug/pe"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPEImportDescriptorsIncludeLibrariesWithoutNamedSymbols(t *testing.T) {
	data := make([]byte, 128)
	binary.LittleEndian.PutUint32(data[12:], 0x1040)
	binary.LittleEndian.PutUint32(data[16:], 0x1050)
	copy(data[64:], "fixture.dll\x00")
	image := Image{Sections: []Region{{Address: 0x401000, Size: 128, FileSize: 128}}}
	got, err := peDependencies(bytes.NewReader(data), image, 0x400000, pe.DataDirectory{VirtualAddress: 0x1000, Size: 40})
	if err != nil || len(got) != 1 || got[0] != "fixture.dll" {
		t.Fatalf("unexpected dependencies: %v, error: %v", got, err)
	}
}

func machFixture() []byte {
	data := make([]byte, 0x110)
	copy(data, []byte{0xcf, 0xfa, 0xed, 0xfe})
	put32 := func(offset int, value uint32) { binary.LittleEndian.PutUint32(data[offset:], value) }
	put64 := func(offset int, value uint64) { binary.LittleEndian.PutUint64(data[offset:], value) }
	put32(4, 0x0100000c)
	put32(12, 2)
	put32(16, 2)
	put32(20, 96)
	put32(32, 0x19)
	put32(36, 72)
	copy(data[40:], "__TEXT")
	put64(56, 0x100000000)
	put64(64, 0x1000)
	put64(80, uint64(len(data)))
	put32(88, 7)
	put32(92, 5)
	put32(104, 0x80000028)
	put32(108, 24)
	put64(112, 0x100)
	return data
}

func TestMachOverviewAndIPAMember(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XT_ROOTS", dir)
	image := machFixture()
	machPath := filepath.Join(dir, "Fixture")
	if err := os.WriteFile(machPath, image, 0600); err != nil {
		t.Fatal(err)
	}
	var archive bytes.Buffer
	writer := zip.NewWriter(&archive)
	member, err := writer.Create("Payload/Fixture.app/Fixture")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := member.Write(image); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	ipaPath := filepath.Join(dir, "fixture.ipa")
	if err := os.WriteFile(ipaPath, archive.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct{ path, format, member string }{
		{machPath, "macho", ""},
		{ipaPath, "ipa", "Payload/Fixture.app/Fixture"},
	} {
		got, err := Overview(tc.path, "")
		if err != nil {
			t.Fatal(err)
		}
		if got.Format != tc.format || got.Member != tc.member || len(got.Images) != 1 {
			t.Fatalf("unexpected overview: %#v", got)
		}
		i := got.Images[0]
		if i.Arch != "arm64" || i.EntryPoint == nil || *i.EntryPoint != 0x100000100 || len(i.Segments) != 1 {
			t.Fatalf("unexpected image: %#v", i)
		}
		if i.EntryFileOffset == nil || *i.EntryFileOffset != 0x100 {
			t.Fatalf("unexpected entry file offset: %#v", i.EntryFileOffset)
		}
	}
}

func TestMachFunctionStartsWithoutSymbols(t *testing.T) {
	data := machFixture()
	binary.LittleEndian.PutUint32(data[16:], 3)
	binary.LittleEndian.PutUint32(data[20:], 112)
	binary.LittleEndian.PutUint32(data[128:], 0x26)
	binary.LittleEndian.PutUint32(data[132:], 16)
	binary.LittleEndian.PutUint32(data[136:], 0x108)
	binary.LittleEndian.PutUint32(data[140:], 4)
	copy(data[0x108:], []byte{0x80, 0x02, 0x04, 0})
	file := filepath.Join(t.TempDir(), "Fixture")
	if err := os.WriteFile(file, data, 0600); err != nil {
		t.Fatal(err)
	}
	got, err := Functions(file, "", "arm64", 1)
	if err != nil || len(got.Images) != 1 {
		t.Fatalf("function index: %#v, %v", got, err)
	}
	index := got.Images[0]
	if index.Total != 2 || len(index.Functions) != 1 || index.Functions[0].Address != 0x100000100 ||
		index.Functions[0].Source != "macho_function_starts" || index.Functions[0].FileOffset != 0x100 {
		t.Fatalf("unexpected function entries: %#v", index)
	}
}

func TestUniversalMachOReportsSliceOffsets(t *testing.T) {
	arm := machFixture()
	intel := machFixture()
	binary.LittleEndian.PutUint32(intel[4:], 0x01000007)
	file := make([]byte, 0x3000)
	for i, v := range []uint32{
		0xcafebabe, 2,
		0x0100000c, 0, 0x1000, uint32(len(arm)), 12,
		0x01000007, 0, 0x2000, uint32(len(intel)), 12,
	} {
		binary.BigEndian.PutUint32(file[i*4:], v)
	}
	copy(file[0x1000:], arm)
	copy(file[0x2000:], intel)
	format, images, err := inspect(bytes.NewReader(file), uint64(len(file)), false, "")
	if err != nil || format != "macho" || len(images) != 2 {
		t.Fatalf("universal inspection: %s %#v %v", format, images, err)
	}
	if images[0].Arch != "arm64" || images[0].SliceOffset != 0x1000 ||
		images[1].Arch != "x86_64" || images[1].SliceOffset != 0x2000 {
		t.Fatalf("unexpected slices: %#v", images)
	}
}

func TestIPADuplicateMemberRejected(t *testing.T) {
	var archive bytes.Buffer
	writer := zip.NewWriter(&archive)
	name := "Payload/Fixture.app/Fixture"
	for range 2 {
		member, err := writer.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := member.Write(machFixture()); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := openIPA(bytes.NewReader(archive.Bytes()), int64(archive.Len()), name); err == nil {
		t.Fatal("ambiguous member must be rejected")
	}
}

func TestOversizedIPAMemberRejectedBeforeReading(t *testing.T) {
	var archive bytes.Buffer
	writer := zip.NewWriter(&archive)
	if _, err := writer.CreateRaw(&zip.FileHeader{
		Name:               "Payload/Fixture.app/Fixture",
		Method:             zip.Store,
		UncompressedSize64: maxIPAMember + 1,
	}); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	_, _, err := openIPA(bytes.NewReader(archive.Bytes()), int64(archive.Len()), "")
	if err == nil || !strings.Contains(err.Error(), "inspection limit") {
		t.Fatalf("expected inspection limit error, got %v", err)
	}
}

func TestFileOffsetRejectsZeroFillAndConflictingMappings(t *testing.T) {
	image := Image{Segments: []Region{{Address: 0x1000, Size: 0x40, Offset: 0x100, FileSize: 0x20}}}
	if offset, ok := image.fileOffset(0x101f); !ok || offset != 0x11f {
		t.Fatalf("unexpected backed offset: %#x (%v)", offset, ok)
	}
	if _, ok := image.fileOffset(0x1020); ok {
		t.Fatal("zero-fill bytes have no file offset")
	}
	image.Segments = append(image.Segments, Region{Address: 0x1000, Size: 0x20, Offset: 0x200, FileSize: 0x20})
	if _, ok := image.fileOffset(0x101f); ok {
		t.Fatal("conflicting mappings must remain unresolved")
	}
}

func TestMappedReadRejectsGapBetweenEndpoints(t *testing.T) {
	image := Image{Segments: []Region{
		{Address: 0x1000, Size: 4, FileSize: 4},
		{Address: 0x1008, Size: 4, Offset: 8, FileSize: 4},
	}}
	if _, err := image.readMapped(bytes.NewReader(make([]byte, 12)), 0x1000, 12); err == nil {
		t.Fatal("accepted a range that spans an unmapped gap")
	}
}

func TestFileOffsetRejectsOffsetsOutsideSlice(t *testing.T) {
	image := Image{fileSize: 8, Segments: []Region{{Address: 0x1000, Size: 16, FileSize: 16}}}
	if _, ok := image.fileOffset(0x1008); ok {
		t.Fatal("accepted an address outside the actual slice")
	}
}
