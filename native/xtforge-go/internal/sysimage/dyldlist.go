package sysimage

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const (
	dyldDefaultListLimit = 1000
	dyldMaxListPathBytes = 4096 // bounded read per image path
)

// ListDyldImages returns every image recorded in a shared cache, capped at limit
// (limit <= 0 means 1000). Paths are returned as recorded.
//
// Only the header, the mapping table, the first limit image-info records and
// their paths are read; a multi-gigabyte cache never has to be loaded whole.
func ListDyldImages(r io.ReaderAt, size int64, limit int) ([]DyldImage, error) {
	if limit <= 0 {
		limit = dyldDefaultListLimit
	}
	if limit > dyldMaxImageCount {
		limit = dyldMaxImageCount
	}
	if r == nil {
		return nil, errors.New("nil dyld shared cache reader")
	}
	if size < dyldCacheHeaderLen {
		return nil, fmt.Errorf("truncated dyld shared cache: %d bytes, need at least %d", size, dyldCacheHeaderLen)
	}
	head := make([]byte, dyldCacheHeaderLen)
	if _, err := r.ReadAt(head, 0); err != nil {
		return nil, fmt.Errorf("read dyld shared cache header: %w", err)
	}
	info, ok := ParseDyldCache(head)
	if !ok {
		return nil, errors.New("not a dyld shared cache")
	}

	// Read the mapping table through the same bounds check and parser as
	// openDyldCache. Listing does not need the decoded values, but a cache with
	// an invalid table must not be treated as listable.
	mapStart, mapLen, err := dyldTableBounds(size, binary.LittleEndian.Uint32(head[4:8]), info.MappingCount, dyldMappingEntrySize)
	if err != nil {
		return nil, fmt.Errorf("dyld mapping table: %w", err)
	}
	mapBlob := make([]byte, int(mapLen))
	if _, err := r.ReadAt(mapBlob, int64(mapStart)); err != nil {
		return nil, fmt.Errorf("read dyld mapping table: %w", err)
	}
	_ = ParseDyldMappings(mapBlob, info.MappingCount)

	count := uint32(limit)
	if info.ImagesCount < count {
		count = info.ImagesCount
	}
	if count == 0 {
		return []DyldImage{}, nil
	}
	imgStart, imgLen, err := dyldTableBounds(size, binary.LittleEndian.Uint32(head[12:16]), count, dyldImageInfoSize)
	if err != nil {
		return nil, fmt.Errorf("dyld image table: %w", err)
	}
	imgBlob := make([]byte, int(imgLen))
	if _, err := r.ReadAt(imgBlob, int64(imgStart)); err != nil {
		return nil, fmt.Errorf("read dyld image table: %w", err)
	}

	pool, err := dyldListPathPool(r, size, imgBlob, int(count))
	if err != nil {
		return nil, err
	}
	return ParseDyldImages(imgBlob, pool, count), nil
}

// dyldListPathPool gathers path strings into a compact, bounded pool so the
// shared ParseDyldImages decoder can be used without reading the whole cache.
// Each image record's pathFileOffset is rewritten to point into that pool.
func dyldListPathPool(r io.ReaderAt, size int64, imgBlob []byte, count int) ([]byte, error) {
	pool := make([]byte, 0, count*64)
	for i := 0; i < count; i++ {
		rec := imgBlob[i*dyldImageInfoSize : (i+1)*dyldImageInfoSize]
		off := int64(int32(binary.LittleEndian.Uint32(rec[dyldPathOffsetOff : dyldPathOffsetOff+4])))
		if off < 0 || off >= size {
			// Out-of-range offsets are skipped by ParseDyldImages.
			binary.LittleEndian.PutUint32(rec[dyldPathOffsetOff:], ^uint32(0))
			continue
		}
		want := int64(dyldMaxListPathBytes)
		if remain := size - off; remain < want {
			want = remain
		}
		buf := make([]byte, want)
		n, err := r.ReadAt(buf, off)
		if err != nil && (err != io.EOF || n == 0) {
			return nil, fmt.Errorf("read dyld image %d path at offset %#x: %w", i, off, err)
		}
		buf = buf[:n]
		if end := bytes.IndexByte(buf, 0); end >= 0 {
			buf = buf[:end]
		}
		if len(buf) == 0 {
			binary.LittleEndian.PutUint32(rec[dyldPathOffsetOff:], ^uint32(0))
			continue
		}
		binary.LittleEndian.PutUint32(rec[dyldPathOffsetOff:], uint32(len(pool)))
		pool = append(pool, buf...)
		pool = append(pool, 0)
	}
	if len(pool) == 0 {
		return nil, errors.New("dyld shared cache has no readable image paths")
	}
	return pool, nil
}
