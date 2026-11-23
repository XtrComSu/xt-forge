package sysimage

import (
	"bytes"
	"encoding/binary"
)

const (
	dyldImageInfoSize = 32    // size of dyld_cache_image_info
	dyldMaxImageCount = 65536 // hard cap on the number of decoded images
	dyldPathOffsetOff = 24    // byte offset of pathFileOffset within the record
)

// DyldImage is one image recorded in a dyld shared cache.
type DyldImage struct {
	Path    string `json:"path"`
	Address uint64 `json:"address"`
}

// ParseDyldImages decodes the image table of a dyld shared cache.
// imagesBlob is the cached image-info data; strings is the string pool the
// image paths index into. imagesCount is from the header.
// Returns nil when the inputs are unusable.
func ParseDyldImages(imagesBlob, strings []byte, imagesCount uint32) []DyldImage {
	if len(imagesBlob) == 0 || len(strings) == 0 || imagesCount == 0 {
		return nil
	}
	if imagesCount > dyldMaxImageCount {
		imagesCount = dyldMaxImageCount
	}
	// Stop cleanly when the blob holds fewer records than the header claims.
	if want := int(imagesCount) * dyldImageInfoSize; len(imagesBlob) < want {
		imagesCount = uint32(len(imagesBlob) / dyldImageInfoSize)
		if imagesCount == 0 {
			return nil
		}
	}

	var images []DyldImage
	for i := uint32(0); i < imagesCount; i++ {
		rec := imagesBlob[i*dyldImageInfoSize : (i+1)*dyldImageInfoSize]
		off := int32(binary.LittleEndian.Uint32(rec[dyldPathOffsetOff : dyldPathOffsetOff+4]))
		if off < 0 || int(off) >= len(strings) {
			continue
		}

		path := strings[off:]
		if end := bytes.IndexByte(path, 0); end >= 0 {
			path = path[:end]
		}
		if len(path) == 0 {
			continue
		}

		images = append(images, DyldImage{
			Path:    string(path),
			Address: binary.LittleEndian.Uint64(rec[0:8]),
		})
	}
	return images
}
