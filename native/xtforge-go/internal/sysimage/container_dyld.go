package sysimage

import (
	"bytes"
	"debug/macho"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"strconv"
	"strings"
)

// maxDyldCacheImage matches the DMG limit. A real shared cache is several
// gigabytes, so holding one in memory is only reasonable for small caches and
// firmware images; anything larger needs a mapped-cache reader.
const maxDyldCacheImage = maxDMGImage

// dyldMaxListedPaths keeps an error readable when a cache holds tens of
// thousands of images: a full listing would bury the failure.
const dyldMaxListedPaths = 10

// isDyldCache reports whether the first bytes begin a dyld shared cache.
func isDyldCache(head []byte) bool {
	_, ok := ParseDyldCache(head)
	return ok
}

// dyldCacheHead reads the fixed header prefix used for format detection.
// Short files and read failures are treated as "not a dyld cache" here; the
// open path reports the precise error once the format has been recognised.
func dyldCacheHead(r io.ReaderAt, size int64) []byte {
	if size < dyldCacheHeaderLen {
		return nil
	}
	head := make([]byte, dyldCacheHeaderLen)
	if _, err := r.ReadAt(head, 0); err != nil {
		return nil
	}
	return head
}

// dyldTableBounds checks a table declared by the header before it is sliced.
// Offsets and counts are untrusted: multiply in uint64 so an absurd count
// cannot wrap into a small one, and compare against the actual file size.
func dyldTableBounds(size int64, offset, count uint32, stride uint64) (uint64, uint64, error) {
	start := uint64(offset)
	length := uint64(count) * stride
	if length == 0 || start > uint64(size) || length > uint64(size)-start {
		return 0, 0, fmt.Errorf("table at offset %#x (%d bytes) lies outside the %d-byte file", start, length, size)
	}
	return start, length, nil
}

// openDyldCache extracts one Mach-O image from a shared cache into a byte slice.
// It returns the image bytes, a human label, and an error.
func openDyldCache(r io.ReaderAt, size int64, member string) ([]byte, string, error) {
	if size < dyldCacheHeaderLen {
		return nil, "", fmt.Errorf("truncated dyld shared cache: %d bytes, need at least %d", size, dyldCacheHeaderLen)
	}
	if size > maxDyldCacheImage {
		return nil, "", fmt.Errorf("dyld shared cache is %d MiB, above the %d MiB inspection limit; extract the image first",
			size>>20, maxDyldCacheImage>>20)
	}
	head := make([]byte, dyldCacheHeaderLen)
	if _, err := r.ReadAt(head, 0); err != nil {
		return nil, "", fmt.Errorf("read dyld shared cache header: %w", err)
	}
	info, ok := ParseDyldCache(head)
	if !ok {
		return nil, "", fmt.Errorf("not a dyld shared cache")
	}
	// The compact header stores the mapping and image tables at fixed offsets;
	// reuse the counts already decoded by ParseDyldCache.
	mapStart, mapLen, err := dyldTableBounds(size, binary.LittleEndian.Uint32(head[4:8]), info.MappingCount, dyldMappingEntrySize)
	if err != nil {
		return nil, "", fmt.Errorf("dyld mapping table: %w", err)
	}
	imgStart, imgLen, err := dyldTableBounds(size, binary.LittleEndian.Uint32(head[12:16]), info.ImagesCount, dyldImageInfoSize)
	if err != nil {
		return nil, "", fmt.Errorf("dyld image table: %w", err)
	}

	// Both tables index into the cache itself and image addresses are resolved
	// against it, so one bounded buffer serves all four dyld parsers.
	cache := make([]byte, int(size))
	if _, err := io.ReadFull(io.NewSectionReader(r, 0, size), cache); err != nil {
		return nil, "", fmt.Errorf("read dyld shared cache: %w", err)
	}
	mappings := ParseDyldMappings(cache[int(mapStart):int(mapStart+mapLen)], info.MappingCount)
	// pathFileOffset is an offset from the start of the cache file, so the whole
	// cache is the string pool the image table indexes into.
	images := ParseDyldImages(cache[int(imgStart):int(imgStart+imgLen)], cache, info.ImagesCount)
	if len(images) == 0 {
		return nil, "", fmt.Errorf("dyld shared cache contains no readable images")
	}
	if strings.EqualFold(member, "list") {
		// "list" is a discovery request, not a selectable image name: surface
		// the recorded paths in the error so an analyst knows what to choose.
		return nil, "", fmt.Errorf("dyld shared cache images (select by path or index); available paths:\n%s",
			describeDyldImages(images))
	}
	index, err := selectDyldImage(images, member)
	if err != nil {
		return nil, "", err
	}
	image := images[index]

	// Measure the image before copying it: a cache mapping also holds other
	// images, and the rest of the pipeline should see only the selected Mach-O.
	window := dyldImageWindow(cache, mappings, image)
	if window == 0 {
		return nil, "", fmt.Errorf("dyld image %q has no usable file mapping", image.Path)
	}
	probe := ExtractDyldImage(cache, mappings, image, window)
	if probe == nil {
		return nil, "", fmt.Errorf("dyld image %q could not be extracted", image.Path)
	}
	_, imageSize, err := machoExtent(probe)
	if err != nil {
		return nil, "", fmt.Errorf("dyld image %q is not a Mach-O: %w", image.Path, err)
	}
	data := ExtractDyldImage(cache, mappings, image, imageSize)
	if data == nil {
		return nil, "", fmt.Errorf("dyld image %q extends past its mapping", image.Path)
	}
	// machoExtent checks the header and load commands; NewFile also checks the
	// segments and sections that inspect() and later stages walk.
	if _, err := macho.NewFile(bytes.NewReader(data)); err != nil {
		return nil, "", fmt.Errorf("dyld image %q is not a Mach-O: %w", image.Path, err)
	}
	if image.Path == "" {
		return data, fmt.Sprintf("dyld image %d", index), nil
	}
	return data, image.Path, nil
}

// dyldImageWindow reports how many bytes are readable from an image's address
// to the end of its mapping. Clamping to the mapping keeps a neighbouring
// image's header from being mistaken for part of this image.
func dyldImageWindow(cache []byte, mappings []DyldMapping, image DyldImage) uint64 {
	for _, m := range mappings {
		// Subtract rather than add so an overflowing Address+Size cannot wrap
		// into a false match.
		if m.Size == 0 || image.Address < m.Address || image.Address-m.Address >= m.Size {
			continue
		}
		delta := image.Address - m.Address
		if m.FileOffset > math.MaxUint64-delta {
			return 0
		}
		off := m.FileOffset + delta
		if off >= uint64(len(cache)) {
			return 0
		}
		avail := uint64(len(cache)) - off
		if remaining := m.Size - delta; remaining < avail {
			avail = remaining
		}
		return avail
	}
	return 0
}

// selectDyldImage interprets member as a decimal index first, then as an exact
// path, then as a path substring. An empty member selects the first image.
func selectDyldImage(images []DyldImage, member string) (int, error) {
	if member == "" {
		return 0, nil
	}
	if index, err := strconv.Atoi(member); err == nil && index >= 0 && index < len(images) {
		return index, nil
	}
	// Prefer an exact path: a short substring must not be captured by an
	// unrelated image that happens to be listed earlier.
	for i, image := range images {
		if image.Path == member {
			return i, nil
		}
	}
	for i, image := range images {
		if strings.Contains(image.Path, member) {
			return i, nil
		}
	}
	return 0, fmt.Errorf("dyld shared cache has no image matching %q; available paths:\n%s",
		member, describeDyldImages(images))
}

func describeDyldImages(images []DyldImage) string {
	limit := min(len(images), dyldMaxListedPaths)
	lines := make([]string, 0, limit+1)
	for i := 0; i < limit; i++ {
		lines = append(lines, fmt.Sprintf("  [%d] %s", i, images[i].Path))
	}
	if len(images) > limit {
		lines = append(lines, fmt.Sprintf("  ... and %d more", len(images)-limit))
	}
	return strings.Join(lines, "\n")
}
