package sysimage

import (
	"io"
	"math"
	"sort"
)

// EntropyProfile summarises byte entropy across a buffer.
type EntropyProfile struct {
	Overall   float64   `json:"overall"`
	Chunks    []float64 `json:"chunks"`
	ChunkSize int       `json:"chunk_size"`
	// Classification of the overall entropy.
	Class string `json:"class"`
}

// ProfileEntropy measures Shannon entropy in bits per byte over data,
// split into chunks of chunkSize bytes (the final chunk may be shorter).
// chunkSize <= 0 defaults to 4096.
func ProfileEntropy(data []byte, chunkSize int) EntropyProfile {
	if chunkSize <= 0 {
		chunkSize = 4096
	}
	chunkCap := 1
	if chunkSize < len(data) {
		chunkCap = (len(data)-1)/chunkSize + 1
	}
	p := EntropyProfile{
		ChunkSize: chunkSize,
		Chunks:    make([]float64, 0, chunkCap),
	}
	if len(data) == 0 {
		p.Class = "empty"
		return p
	}
	for start := 0; start < len(data); start += chunkSize {
		end := start + chunkSize
		if end > len(data) || end < start {
			end = len(data)
		}
		p.Chunks = append(p.Chunks, chunkEntropy(data[start:end]))
	}
	p.Overall = chunkEntropy(data)
	p.Class = classifyEntropy(p.Overall)
	return p
}

// chunkEntropy returns the Shannon entropy in bits per byte of b.
func chunkEntropy(b []byte) float64 {
	if len(b) == 0 {
		return 0
	}
	var counts [256]int
	for _, v := range b {
		counts[v]++
	}
	n := float64(len(b))
	var h float64
	for _, c := range counts {
		if c == 0 {
			continue
		}
		pr := float64(c) / n
		h -= pr * math.Log2(pr)
	}
	if h < 0 {
		return 0
	}
	return h
}

// classifyEntropy maps an overall entropy in bits per byte to a class.
func classifyEntropy(h float64) string {
	switch {
	case h < 1.0:
		return "low"
	case h < 6.0:
		return "structured"
	case h < 7.5:
		return "high"
	default:
		return "very-high"
	}
}

// maxSectionEntropyBytes caps the bytes profiled for one region so a single
// huge section cannot dominate the result.
const maxSectionEntropyBytes = 8 << 20

// SectionEntropy measures entropy for each named region that has file-backed
// bytes. Regions with no bytes are skipped.
type SectionEntropy struct {
	Name    string  `json:"name"`
	Entropy float64 `json:"entropy"`
	Class   string  `json:"class"`
	Bytes   uint64  `json:"bytes"`
}

// ProfileRegions reads the file-backed bytes of regions from r and profiles
// them with a 4096-byte chunk. Regions without bytes, with offsets that cannot
// be read, or that cannot be read at all are silently skipped. The result is
// sorted by region name for stable output.
func ProfileRegions(r io.ReaderAt, regions []Region) []SectionEntropy {
	out := make([]SectionEntropy, 0, len(regions))
	if r == nil || len(regions) == 0 {
		return out
	}
	for _, region := range regions {
		if region.FileSize == 0 || region.Offset > math.MaxInt64 {
			continue
		}
		length := region.FileSize
		if length > maxSectionEntropyBytes {
			length = maxSectionEntropyBytes
		}
		buf := make([]byte, int(length))
		n, err := r.ReadAt(buf, int64(region.Offset))
		if n == 0 || (err != nil && err != io.EOF) {
			continue
		}
		profile := ProfileEntropy(buf[:n], 4096)
		out = append(out, SectionEntropy{
			Name:    region.Name,
			Entropy: profile.Overall,
			Class:   profile.Class,
			Bytes:   uint64(n),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// profileImageRegions profiles an image's sections against the reader the
// image was decoded from. Fat Mach-O offsets are relative to the slice, so
// such images are profiled through a slice-relative reader.
func profileImageRegions(r io.ReaderAt, image *Image) {
	if r == nil || image == nil || len(image.Sections) == 0 {
		return
	}
	reader := r
	if image.SliceOffset > 0 {
		if image.SliceOffset > math.MaxInt64 || image.fileSize > math.MaxInt64 {
			return
		}
		reader = io.NewSectionReader(r, int64(image.SliceOffset), int64(image.fileSize))
	}
	image.SectionEntropy = ProfileRegions(reader, image.Sections)
}
