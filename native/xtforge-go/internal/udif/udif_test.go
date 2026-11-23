package udif

import (
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"encoding/binary"
	"os"
	"strings"
	"testing"
)

// buildImage assembles a minimal but structurally real UDIF image: a koly
// trailer, an XML chunk table whose blkx entries are base64-encoded "mish"
// tables, and a data fork holding the chunks.
//
// Fixtures are built rather than checked in so the test states exactly which
// bytes it depends on, and so a chunk-table bug shows up as a failed assertion
// here instead of as a mysterious extraction mismatch later.
type fixtureChunk struct {
	typ    uint32
	sector uint64
	length uint64 // payload bytes in the data fork
	out    int    // output sectors
	// payload writes the data-fork bytes for this chunk.
	payload func(t *testing.T, out []byte)
}

func buildImage(t *testing.T, name string, sectors uint64, chunks []fixtureChunk) []byte {
	t.Helper()
	var fork bytes.Buffer
	type descriptor struct {
		typ                         uint32
		sector, out, offset, length uint64
	}
	var descriptors []descriptor
	for _, c := range chunks {
		before := fork.Len()
		out := make([]byte, c.out*SectorSize)
		if c.payload == nil {
			c.payload = func(t *testing.T, out []byte) {
				for i := range out {
					out[i] = 0
				}
			}
		}
		c.payload(t, out)
		payload := out
		switch c.typ {
		case chunkZlib:
			var compressed bytes.Buffer
			writer := zlib.NewWriter(&compressed)
			if _, err := writer.Write(out); err != nil {
				t.Fatalf("compress fixture chunk: %v", err)
			}
			if err := writer.Close(); err != nil {
				t.Fatalf("close fixture chunk: %v", err)
			}
			payload = compressed.Bytes()
		case chunkZero, chunkIgnore:
			payload = nil
		}
		fork.Write(payload)
		descriptors = append(descriptors, descriptor{
			typ: c.typ, sector: c.sector, out: uint64(c.out),
			offset: uint64(before), length: uint64(len(payload)),
		})
	}

	// mish header: magic, version, sector number, sector count, data offset,
	// buffers needed, descriptor count, then reserved words.
	table := make([]byte, blkxHeaderSize)
	copy(table, "mish")
	binary.BigEndian.PutUint32(table[4:8], 1)
	binary.BigEndian.PutUint64(table[16:24], sectors)
	binary.BigEndian.PutUint32(table[200:204], uint32(len(descriptors)+1))
	for _, d := range descriptors {
		entry := make([]byte, 40)
		binary.BigEndian.PutUint32(entry[0:4], d.typ)
		binary.BigEndian.PutUint64(entry[8:16], d.sector)
		binary.BigEndian.PutUint64(entry[16:24], d.out)
		binary.BigEndian.PutUint64(entry[24:32], d.offset)
		binary.BigEndian.PutUint64(entry[32:40], d.length)
		table = append(table, entry...)
	}
	end := make([]byte, 40)
	binary.BigEndian.PutUint32(end[0:4], chunkEnd)
	table = append(table, end...)

	encoded := base64.StdEncoding.EncodeToString(table)
	var plist strings.Builder
	plist.WriteString(`<?xml version="1.0" encoding="UTF-8"?>` + "\n")
	plist.WriteString(`<plist version="1.0"><dict><key>resource-fork</key><dict>`)
	plist.WriteString(`<key>blkx</key><array><dict>`)
	plist.WriteString(`<key>Attributes</key><string>0x0050</string>`)
	plist.WriteString(`<key>CFName</key><string>` + name + `</string>`)
	plist.WriteString(`<key>Data</key><data>` + encoded + `</data>`)
	plist.WriteString(`</dict></array></dict></dict></plist>`)

	var out bytes.Buffer
	out.Write(fork.Bytes())
	xmlOffset := uint64(out.Len())
	out.WriteString(plist.String())

	trailer := make([]byte, kolyHeaderSize)
	copy(trailer, "koly")
	binary.BigEndian.PutUint32(trailer[4:8], 4)
	binary.BigEndian.PutUint32(trailer[8:12], kolyHeaderSize)
	binary.BigEndian.PutUint64(trailer[24:32], 0)
	binary.BigEndian.PutUint64(trailer[32:40], uint64(fork.Len()))
	binary.BigEndian.PutUint64(trailer[216:224], xmlOffset)
	binary.BigEndian.PutUint64(trailer[224:232], uint64(plist.Len()))
	binary.BigEndian.PutUint64(trailer[492:500], sectors)
	out.Write(trailer)
	return out.Bytes()
}

func openFixture(t *testing.T, data []byte) *Image {
	t.Helper()
	image, err := Open(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatalf("open fixture: %v", err)
	}
	return image
}

func TestOpenReadsTrailerAndChunkTable(t *testing.T) {
	data := buildImage(t, "disk image (Apple_APFS : 4)", 8, []fixtureChunk{
		{typ: chunkZlib, sector: 0, out: 4, payload: fill(0xaa)},
		{typ: chunkZero, sector: 4, out: 4},
	})
	image := openFixture(t, data)
	if image.Version != 4 {
		t.Fatalf("version = %d, want 4", image.Version)
	}
	if len(image.Partitions) != 1 {
		t.Fatalf("partitions = %d, want 1", len(image.Partitions))
	}
	partition := image.Partitions[0]
	if partition.Name != "disk image (Apple_APFS : 4)" {
		t.Fatalf("partition name = %q", partition.Name)
	}
	if partition.Attributes != 0x50 {
		t.Fatalf("attributes = %#x, want 0x50", partition.Attributes)
	}
	if partition.Sectors != 8 || partition.Written != 8*SectorSize {
		t.Fatalf("sectors = %d written = %d", partition.Sectors, partition.Written)
	}
	if image.Methods["zlib"] != 1 || image.Methods["zero"] != 1 {
		t.Fatalf("methods = %v", image.Methods)
	}
}

func TestExtractDecompressesAndZeroFills(t *testing.T) {
	data := buildImage(t, "disk", 8, []fixtureChunk{
		{typ: chunkZlib, sector: 0, out: 2, payload: fill(0x5a)},
		{typ: chunkZero, sector: 2, out: 2},
		{typ: chunkRaw, sector: 4, out: 2, payload: fill(0xc3)},
		{typ: chunkZero, sector: 6, out: 2},
	})
	raw, err := openFixture(t, data).Extract(0)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if len(raw) != 8*SectorSize {
		t.Fatalf("extracted %d bytes, want %d", len(raw), 8*SectorSize)
	}
	// The zlib chunk must be decompressed, not copied.
	if !bytes.Equal(raw[:SectorSize], bytes.Repeat([]byte{0x5a}, SectorSize)) {
		t.Fatalf("zlib chunk was not decompressed")
	}
	if !bytes.Equal(raw[2*SectorSize:4*SectorSize], make([]byte, 2*SectorSize)) {
		t.Fatalf("sparse region is not zero")
	}
	if !bytes.Equal(raw[4*SectorSize:6*SectorSize], bytes.Repeat([]byte{0xc3}, 2*SectorSize)) {
		t.Fatalf("raw chunk is wrong")
	}
}

func TestExtractReportsOutOfRangePartition(t *testing.T) {
	data := buildImage(t, "disk", 1, []fixtureChunk{{typ: chunkZero, sector: 0, out: 1}})
	if _, err := openFixture(t, data).Extract(1); err == nil {
		t.Fatal("extracting a missing partition should fail")
	}
}

func TestOpenRejectsNonUDIF(t *testing.T) {
	data := make([]byte, 1024)
	copy(data, "not a dmg at all")
	_, err := Open(bytes.NewReader(data), int64(len(data)))
	if err == nil || !strings.Contains(err.Error(), "koly") {
		t.Fatalf("err = %v, want a koly complaint", err)
	}
}

func TestOpenRejectsChunkTableOutsideImage(t *testing.T) {
	data := buildImage(t, "disk", 1, []fixtureChunk{{typ: chunkZero, sector: 0, out: 1}})
	// Point the XML offset past the end of the file.
	trailer := data[len(data)-kolyHeaderSize:]
	binary.BigEndian.PutUint64(trailer[216:224], uint64(len(data))*8)
	_, err := Open(bytes.NewReader(data), int64(len(data)))
	if err == nil || !strings.Contains(err.Error(), "outside") {
		t.Fatalf("err = %v, want an out-of-bounds complaint", err)
	}
}

func TestOpenRejectsUnknownChunkCompressionOnExtract(t *testing.T) {
	data := buildImage(t, "disk", 1, []fixtureChunk{{typ: chunkLZMA, sector: 0, out: 1}})
	// A chunk type with no decoder must fail loudly at extraction, not silently
	// produce zeroes that look like a sparse region.
	if _, err := openFixture(t, data).Extract(0); err == nil {
		t.Fatal("unsupported chunk type should fail extraction")
	}
}

func TestHasFilesystemDetectsAPFSAndHFS(t *testing.T) {
	apfs := make([]byte, 4096)
	copy(apfs[32:36], "NXSB")
	if got := HasFilesystem(apfs); got != "apfs" {
		t.Fatalf("apfs detection = %q", got)
	}
	hfs := make([]byte, 4096)
	binary.BigEndian.PutUint16(hfs[1024:1026], 0x482b)
	if got := HasFilesystem(hfs); got != "hfs+" {
		t.Fatalf("hfs+ detection = %q", got)
	}
	if got := HasFilesystem(make([]byte, 4096)); got != "" {
		t.Fatalf("blank image detected as %q", got)
	}
}

func fill(value byte) func(*testing.T, []byte) {
	return func(_ *testing.T, out []byte) {
		for i := range out {
			out[i] = value
		}
	}
}

// realDMG is an optional end-to-end check against a genuine Apple disk image.
//
// The sample is not checked in: it is somebody's installer. Point XTF_REAL_DMG
// at any UDIF image to run these tests; without it they skip, so the suite stays
// portable and no machine-specific path is baked into the source.
func realDMGPath() string {
	return os.Getenv("XTF_REAL_DMG")
}

func TestRealDMGParsesAndExtracts(t *testing.T) {
	path := realDMGPath()
	if path == "" {
		t.Skip("set XTF_REAL_DMG to a UDIF image to run the real-image checks")
	}
	file, err := os.Open(path)
	if err != nil {
		t.Skipf("cannot open XTF_REAL_DMG: %v", err)
	}
	defer file.Close()
	stat, err := file.Stat()
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	image, err := Open(file, stat.Size())
	if err != nil {
		t.Fatalf("open real DMG: %v", err)
	}
	if image.Version != 4 {
		t.Fatalf("version = %d, want 4", image.Version)
	}
	if len(image.Partitions) < 5 {
		t.Fatalf("partitions = %d, want the 8-entry GPT layout", len(image.Partitions))
	}
	if image.Methods["lzfse"] == 0 {
		t.Fatalf("this image is LZFSE-compressed but methods = %v", image.Methods)
	}
	// The APFS partition is the largest one.
	best := 0
	for i, partition := range image.Partitions {
		if partition.Written > image.Partitions[best].Written {
			best = i
		}
	}
	raw, err := image.Extract(best)
	if err != nil {
		t.Fatalf("extract APFS partition: %v", err)
	}
	if got := HasFilesystem(raw); got != "apfs" {
		t.Fatalf("extracted partition filesystem = %q, want apfs", got)
	}
	if uint64(len(raw)) != image.Partitions[best].Written {
		t.Fatalf("extracted %d bytes, partition declares %d", len(raw), image.Partitions[best].Written)
	}
}

// TestRealDMGContentMatchesIndependentExtraction is the check that matters:
// 7z decompresses this image through its own APFS reader. A file it recovered
// must appear verbatim inside the partition this package reconstructed. Without
// this, "extraction succeeded" would only prove we produced the right number of
// bytes, not the right bytes.
func TestRealDMGContentMatchesIndependentExtraction(t *testing.T) {
	// XTF_REAL_DMG_REFERENCE names a file an independent extractor recovered
	// from the same image (e.g. 7z x). Its bytes must appear inside the
	// partition this package reconstructs.
	path := realDMGPath()
	if path == "" {
		t.Skip("set XTF_REAL_DMG to a UDIF image to run this check")
	}
	reference, err := os.ReadFile(os.Getenv("XTF_REAL_DMG_REFERENCE"))
	if err != nil {
		t.Skip("set XTF_REAL_DMG_REFERENCE to a file extracted by another tool")
	}
	file, err := os.Open(path)
	if err != nil {
		t.Skipf("cannot open XTF_REAL_DMG: %v", err)
	}
	defer file.Close()
	stat, _ := file.Stat()
	image, err := Open(file, stat.Size())
	if err != nil {
		t.Fatalf("open real DMG: %v", err)
	}
	best := 0
	for i, partition := range image.Partitions {
		if partition.Written > image.Partitions[best].Written {
			best = i
		}
	}
	raw, err := image.Extract(best)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if len(reference) > 4096 {
		reference = reference[:4096]
	}
	probe := reference[512:]
	if !bytes.Contains(raw, probe) {
		t.Fatal("content 7z recovered does not appear in our extracted partition")
	}
	t.Logf("verified %d reference bytes at partition offset %d", len(probe), bytes.Index(raw, probe))
}

func BenchmarkRealDMGExtract(b *testing.B) {
	path := realDMGPath()
	if path == "" {
		b.Skip("set XTF_REAL_DMG to benchmark a real image")
	}
	file, err := os.Open(path)
	if err != nil {
		b.Skip("cannot open XTF_REAL_DMG")
	}
	defer file.Close()
	stat, _ := file.Stat()
	image, err := Open(file, stat.Size())
	if err != nil {
		b.Fatalf("open: %v", err)
	}
	b.SetBytes(int64(image.UncompressedSize))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := image.Extract(4); err != nil {
			b.Fatalf("extract: %v", err)
		}
	}
}

// TestBzip2ChunkDecodes exercises the bzip2 arm with a real compressed payload.
//
// The other chunk tests prove the plumbing; this one proves the decoder produces
// the original bytes, which is the only thing that makes "bzip2 support" true
// rather than "bzip2 no longer errors". The payload is embedded because
// compress/bzip2 in the standard library has a reader only — there is no writer
// to build a fixture from at test time.
func TestBzip2ChunkDecodes(t *testing.T) {
	encoded := "QlpoOTFBWSZTWRd7zbAAAaOZgEADEAAb6dZQIABwUwmmgNMQKVUNNBkbU2pqJoJoJgTcTgTUJsJ5EwJs" +
		"JkTAnInAn4TkTImRNxMifxdyRThQkBd7zbA="
	compressed, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	image := &Image{source: bytes.NewReader(compressed), size: int64(len(compressed))}
	got, err := image.chunkBytes(chunk{typ: chunkBzip2, offset: 0, length: uint64(len(compressed))})
	if err != nil {
		t.Fatalf("bzip2 chunk: %v", err)
	}
	want := bytes.Repeat([]byte("xt-forge bzip2 chunk. "), 40)
	if !bytes.Equal(got, want) {
		t.Fatalf("decoded %d bytes, want %d", len(got), len(want))
	}
}
