// Package udif reads Apple UDIF disk images (.dmg) without external tools.
//
// A UDIF image is a raw disk image split into chunks, with a trailer describing
// where each chunk lives and how it is compressed. The trailer is the last 512
// bytes of the file and starts with "koly". Everything needed to reconstruct the
// image is reachable from it: the chunk table lives either in the XML property
// list after the data fork, or in a binary "blkx" resource fork.
//
// What this package deliberately does not do: mount a filesystem. It returns the
// reconstructed raw image bytes, and the caller decides what to do with them
// (HFS+ and APFS both live at a known offset inside a partition, which is a
// separate problem from decompressing the container).
package udif

import (
	"bytes"
	"compress/bzip2"
	"compress/zlib"
	"encoding/base64"
	"encoding/binary"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"

	"xtforge-hub/internal/thirdparty/lzfse"
)

// SectorSize is the block size UDIF chunk offsets are expressed in.
const SectorSize = 512

// kolyHeaderSize is the fixed trailer size; the trailer is always the last 512
// bytes of the file regardless of the version recorded in it.
const kolyHeaderSize = 512

// blkxHeaderSize is the fixed part of a "mish" chunk table before its
// descriptors begin.
const blkxHeaderSize = 204

// Chunk types. Anything with the top bit set carries data; 0xffffffff is the
// terminator and 0x00000000 is a comment-only entry.
const (
	chunkZero    = 0x00000000
	chunkRaw     = 0x00000001
	chunkIgnore  = 0x00000002
	chunkADC     = 0x80000004
	chunkZlib    = 0x80000005
	chunkBzip2   = 0x80000006
	chunkLZFSE   = 0x80000007
	chunkLZMA    = 0x80000008
	chunkComment = 0x7ffffffe
	chunkEnd     = 0xffffffff
)

// maxChunkOutput bounds a single decompressed chunk. Real images use 1 MiB
// chunks; the limit keeps a hostile chunk table from asking for an
// unbounded allocation.
const maxChunkOutput = 64 << 20

// Partition is one entry of the image's chunk table.
type Partition struct {
	Name string `json:"name"`
	// Attributes is the raw attribute word from the plist.
	Attributes uint64 `json:"attributes"`
	// Sectors is the partition length in 512-byte sectors.
	Sectors uint64 `json:"sectors"`
	// Written is the number of output bytes the partition occupies.
	Written uint64 `json:"written"`
	chunks  []chunk
}

// Chunk is one decompression unit inside a partition.
type Chunk struct {
	Type   uint32 `json:"type"`
	Sector uint64 `json:"sector"`
	// Sectors is the chunk's length in the output, in 512-byte sectors.
	Sectors uint64 `json:"sectors"`
	// Offset is the compressed bytes' offset from the start of the data fork.
	Offset uint64 `json:"offset"`
	// Length is the compressed length in bytes.
	Length uint64 `json:"length"`
}

type chunk struct {
	typ     uint32
	sector  uint64
	sectors uint64
	offset  uint64
	length  uint64
}

// Image is a parsed disk image.
type Image struct {
	// Version is the UDIF format version from the trailer.
	Version uint32 `json:"version"`
	// DataForkOffset and DataForkLength describe where compressed bytes live.
	DataForkOffset uint64 `json:"data_fork_offset"`
	DataForkLength uint64 `json:"data_fork_length"`
	// Partitions lists every entry of the chunk table, in table order.
	Partitions []Partition `json:"partitions"`
	// CompressedSize and UncompressedSize are the data-fork byte count and the
	// total output size across all partitions.
	CompressedSize   uint64 `json:"compressed_size"`
	UncompressedSize uint64 `json:"uncompressed_size"`
	// Methods counts chunk compression kinds by name, so a caller can report
	// what a DMG actually uses without decompressing it.
	Methods map[string]int `json:"methods"`

	source io.ReaderAt
	size   int64
}

// koly is the fields this package needs from the 512-byte trailer.
type koly struct {
	version        uint32
	headerSize     uint32
	dataForkOffset uint64
	dataForkLength uint64
	xmlOffset      uint64
	xmlLength      uint64
	sectorCount    uint64
}

// Open parses the trailer and chunk table of a UDIF image.
func Open(r io.ReaderAt, size int64) (*Image, error) {
	if size < kolyHeaderSize {
		return nil, fmt.Errorf("UDIF image is %d bytes, smaller than its %d-byte trailer", size, kolyHeaderSize)
	}
	var trailer [kolyHeaderSize]byte
	if _, err := r.ReadAt(trailer[:], size-kolyHeaderSize); err != nil {
		return nil, fmt.Errorf("read UDIF trailer: %w", err)
	}
	header, err := parseKoly(trailer[:])
	if err != nil {
		return nil, err
	}
	image := &Image{
		Version:        header.version,
		DataForkOffset: header.dataForkOffset,
		DataForkLength: header.dataForkLength,
		Methods:        map[string]int{},
		source:         r,
		size:           size,
	}
	table, err := image.chunkTable(header)
	if err != nil {
		return nil, err
	}
	image.Partitions = table
	image.CompressedSize = header.dataForkLength
	for _, partition := range table {
		image.UncompressedSize += partition.Written
		for _, c := range partition.chunks {
			image.Methods[methodName(c.typ)]++
		}
	}
	return image, nil
}

func parseKoly(trailer []byte) (koly, error) {
	if string(trailer[:4]) != "koly" {
		return koly{}, errors.New("not a UDIF image: missing koly trailer")
	}
	header := koly{
		version: binary.BigEndian.Uint32(trailer[4:8]),
	}
	// The trailer layout is fixed, but the field offsets differ between the
	// documented v4 layout and older v1 images only in the fields this package
	// ignores, so a single read covers both.
	header.headerSize = binary.BigEndian.Uint32(trailer[8:12])
	header.dataForkOffset = binary.BigEndian.Uint64(trailer[24:32])
	header.dataForkLength = binary.BigEndian.Uint64(trailer[32:40])
	header.xmlOffset = binary.BigEndian.Uint64(trailer[216:224])
	header.xmlLength = binary.BigEndian.Uint64(trailer[224:232])
	header.sectorCount = binary.BigEndian.Uint64(trailer[492:500])
	if header.headerSize < kolyHeaderSize {
		return koly{}, fmt.Errorf("UDIF trailer declares a %d-byte header, smaller than %d", header.headerSize, kolyHeaderSize)
	}
	if header.xmlLength == 0 {
		// v1 images keep a binary resource fork rather than an XML plist. That
		// is rare enough (and old enough) that declining beats guessing.
		return koly{}, errors.New("UDIF image has no XML chunk table; v1 binary resource forks are not supported")
	}
	return header, nil
}

// blkxEntry is one partition description lifted out of the plist.
type blkxEntry struct {
	Attributes string
	Name       string
	Data       []byte
}

// parseBLKX walks the plist tokens and collects every dict inside the
// resource-fork's blkx array.
//
// A property list is key/value siblings rather than nested elements, so struct
// tags cannot describe it: <key>Attributes</key> and its <string> are separate
// children of the same <dict>. Walking tokens is the only honest way to read it.
func parseBLKX(raw []byte) ([]blkxEntry, error) {
	decoder := xml.NewDecoder(bytes.NewReader(raw))

	var entries []blkxEntry
	// stack of element names, so we know when we are inside blkx.
	var path []string
	var key string
	var inBLKX bool
	var current *blkxEntry
	// depth of the <dict> that starts a blkx entry.
	dictDepth := -1

	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("parse UDIF chunk table: %w", err)
		}
		switch element := token.(type) {
		case xml.StartElement:
			path = append(path, element.Name.Local)
			switch element.Name.Local {
			case "key":
				if err := decoder.DecodeElement(&key, &element); err != nil {
					return nil, fmt.Errorf("parse UDIF chunk table: %w", err)
				}
				path = path[:len(path)-1]
				// <key>blkx</key> is followed by <array>.
				if key == "blkx" {
					inBLKX = true
				}
			case "dict":
				if inBLKX && dictDepth < 0 {
					current = &blkxEntry{}
					dictDepth = len(path)
				}
			case "string":
				var value string
				if err := decoder.DecodeElement(&value, &element); err != nil {
					return nil, fmt.Errorf("parse UDIF chunk table: %w", err)
				}
				path = path[:len(path)-1]
				if current != nil {
					switch key {
					case "Attributes":
						current.Attributes = value
					case "CFName":
						current.Name = value
					}
					key = ""
				}
			case "data":
				// A plist <data> element carries base64 text, not raw bytes:
				// unmarshalling it straight into []byte keeps the literal
				// characters, which is why the decoded chunk table looked like
				// "bWlzaA==" instead of "mish".
				var encoded string
				if err := decoder.DecodeElement(&encoded, &element); err != nil {
					return nil, fmt.Errorf("parse UDIF chunk table: %w", err)
				}
				path = path[:len(path)-1]
				if current != nil && key == "Data" {
					decoded, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(encoded), ""))
					if err != nil {
						return nil, fmt.Errorf("partition %q has an unreadable chunk table: %w", current.Name, err)
					}
					current.Data = decoded
					key = ""
				}
			}
		case xml.EndElement:
			if len(path) > 0 {
				path = path[:len(path)-1]
			}
			switch element.Name.Local {
			case "dict":
				if current != nil && len(path)+1 == dictDepth {
					entries = append(entries, *current)
					current = nil
					dictDepth = -1
				}
			case "array":
				if inBLKX {
					inBLKX = false
				}
			}
		}
	}
	return entries, nil
}

func (image *Image) chunkTable(header koly) ([]Partition, error) {
	if header.xmlLength > maxChunkOutput<<5 {
		return nil, fmt.Errorf("UDIF chunk table claims %d bytes, refusing to read it", header.xmlLength)
	}
	if header.xmlOffset > uint64(image.size) || header.xmlLength > uint64(image.size)-header.xmlOffset {
		return nil, fmt.Errorf("UDIF chunk table at %d+%d lies outside the %d-byte image", header.xmlOffset, header.xmlLength, image.size)
	}
	raw := make([]byte, header.xmlLength)
	if _, err := image.source.ReadAt(raw, int64(header.xmlOffset)); err != nil {
		return nil, fmt.Errorf("read UDIF chunk table: %w", err)
	}
	entries, err := parseBLKX(raw)
	if err != nil {
		return nil, err
	}
	if len(entries) == 0 {
		return nil, errors.New("UDIF chunk table lists no partitions")
	}
	partitions := make([]Partition, 0, len(entries))
	for _, entry := range entries {
		partition, err := image.parsePartition(entry.Name, entry.Attributes, entry.Data)
		if err != nil {
			return nil, err
		}
		partitions = append(partitions, partition)
	}
	return partitions, nil
}

func (image *Image) parsePartition(name, attributes string, raw []byte) (Partition, error) {
	partition := Partition{Name: name}
	if attributes != "" {
		value, err := strconv.ParseUint(strings.TrimPrefix(attributes, "0x"), 16, 64)
		if err != nil {
			return Partition{}, fmt.Errorf("partition %q has an unreadable attribute word %q", name, attributes)
		}
		partition.Attributes = value
	}
	if len(raw) < blkxHeaderSize {
		return Partition{}, fmt.Errorf("partition %q has a %d-byte chunk table, smaller than its %d-byte header", name, len(raw), blkxHeaderSize)
	}
	if string(raw[:4]) != "mish" {
		return Partition{}, fmt.Errorf("partition %q chunk table does not start with mish", name)
	}
	partition.Sectors = binary.BigEndian.Uint64(raw[16:24])
	count := binary.BigEndian.Uint32(raw[200:204])
	if count == 0 {
		return partition, nil
	}
	// A descriptor is 40 bytes. Check the table against the declared count
	// rather than trusting it and reading past the end.
	if uint64(count)*40 > uint64(len(raw)-blkxHeaderSize) {
		return Partition{}, fmt.Errorf("partition %q declares %d chunks but only %d bytes remain", name, count, len(raw)-blkxHeaderSize)
	}
	partition.chunks = make([]chunk, 0, count)
	offset := blkxHeaderSize
	for i := uint32(0); i < count; i++ {
		entry := raw[offset : offset+40]
		offset += 40
		c := chunk{
			typ:     binary.BigEndian.Uint32(entry[0:4]),
			sector:  binary.BigEndian.Uint64(entry[8:16]),
			sectors: binary.BigEndian.Uint64(entry[16:24]),
			offset:  binary.BigEndian.Uint64(entry[24:32]),
			length:  binary.BigEndian.Uint64(entry[32:40]),
		}
		if c.typ == chunkEnd {
			break
		}
		partition.chunks = append(partition.chunks, c)
		partition.Written += c.sectors * SectorSize
	}
	return partition, nil
}

// Extract reconstructs one partition into its raw bytes.
//
// The caller picks a partition by index. Sparse chunks are written as zeroes, so
// the result is exactly partition.Written bytes long.
func (image *Image) Extract(index int) ([]byte, error) {
	if index < 0 || index >= len(image.Partitions) {
		return nil, fmt.Errorf("partition %d is out of range; the image has %d", index, len(image.Partitions))
	}
	partition := image.Partitions[index]
	if partition.Written == 0 {
		return nil, fmt.Errorf("partition %q is empty", partition.Name)
	}
	if partition.Written > maxChunkOutput<<7 {
		return nil, fmt.Errorf("partition %q expands to %d bytes, above the extraction limit", partition.Name, partition.Written)
	}
	out := make([]byte, partition.Written)
	for _, c := range partition.chunks {
		if c.sectors == 0 {
			continue
		}
		start := c.sector * SectorSize
		end := start + c.sectors*SectorSize
		if start > uint64(len(out)) || end > uint64(len(out)) {
			return nil, fmt.Errorf("partition %q chunk at sector %d runs past the partition end", partition.Name, c.sector)
		}
		switch c.typ {
		case chunkZero, chunkIgnore:
			// Leave the range zeroed.
			continue
		case chunkComment:
			continue
		}
		data, err := image.chunkBytes(c)
		if err != nil {
			return nil, fmt.Errorf("partition %q chunk at sector %d: %w", partition.Name, c.sector, err)
		}
		want := c.sectors * SectorSize
		if uint64(len(data)) < want {
			return nil, fmt.Errorf("partition %q chunk at sector %d decompressed to %d bytes, expected %d", partition.Name, c.sector, len(data), want)
		}
		copy(out[start:end], data[:want])
	}
	return out, nil
}

func (image *Image) chunkBytes(c chunk) ([]byte, error) {
	if c.length == 0 {
		return nil, nil
	}
	if c.length > maxChunkOutput {
		return nil, fmt.Errorf("compressed chunk claims %d bytes", c.length)
	}
	if c.offset > uint64(image.size) || c.length > uint64(image.size)-c.offset {
		return nil, fmt.Errorf("chunk at offset %d+%d lies outside the image", c.offset, c.length)
	}
	raw := make([]byte, c.length)
	if _, err := image.source.ReadAt(raw, int64(c.offset)); err != nil {
		return nil, err
	}
	switch c.typ {
	case chunkRaw:
		return raw, nil
	case chunkZlib, chunkADC:
		reader, err := zlib.NewReader(bytes.NewReader(raw))
		if err != nil {
			return nil, err
		}
		defer reader.Close()
		return io.ReadAll(io.LimitReader(reader, maxChunkOutput))
	case chunkLZFSE:
		return io.ReadAll(io.LimitReader(lzfse.NewReader(bytes.NewReader(raw)), maxChunkOutput))
	case chunkBzip2:
		data, err := io.ReadAll(io.LimitReader(bzip2.NewReader(bytes.NewReader(raw)), maxChunkOutput))
		if err != nil {
			return nil, fmt.Errorf("read bzip2 chunk: %w", err)
		}
		return data, nil
	case chunkLZMA:
		return nil, errors.New("LZMA chunks are not supported; the image needs an LZMA decoder")
	}
	return nil, fmt.Errorf("unknown chunk type 0x%08x", c.typ)
}

func methodName(typ uint32) string {
	switch typ {
	case chunkZero:
		return "zero"
	case chunkRaw:
		return "raw"
	case chunkIgnore:
		return "ignore"
	case chunkADC:
		return "adc"
	case chunkZlib:
		return "zlib"
	case chunkBzip2:
		return "bzip2"
	case chunkLZFSE:
		return "lzfse"
	case chunkLZMA:
		return "lzma"
	case chunkComment:
		return "comment"
	case chunkEnd:
		return "end"
	}
	return fmt.Sprintf("unknown-%08x", typ)
}

// Chunks returns the partition's chunk descriptors, ordered by output sector.
func (partition Partition) Chunks() []Chunk {
	out := make([]Chunk, 0, len(partition.chunks))
	for _, c := range partition.chunks {
		out = append(out, Chunk{Type: c.typ, Sector: c.sector, Sectors: c.sectors, Offset: c.offset, Length: c.length})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Sector < out[j].Sector })
	return out
}

// HasFilesystem reports whether the partition's first bytes look like a
// filesystem this package can describe. It is a cheap probe on already-extracted
// bytes, kept here so callers do not each reinvent the magic check.
func HasFilesystem(raw []byte) string {
	if len(raw) < 1024 {
		return ""
	}
	// HFS+ puts a signature at offset 1024.
	switch binary.BigEndian.Uint16(raw[1024:1026]) {
	case 0x482b:
		return "hfs+"
	case 0x4858:
		return "hfsx"
	}
	// APFS nests its container superblock behind an object header.
	if len(raw) >= 36 && bytes.Equal(raw[32:36], []byte("NXSB")) {
		return "apfs"
	}
	return ""
}
