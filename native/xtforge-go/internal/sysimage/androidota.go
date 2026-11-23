package sysimage

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"path"
	"strings"
)

// An A/B OTA package is a ZIP holding payload.bin, a ChromeOS-style update
// payload, plus META-INF/com/android/metadata. payload.bin starts with:
//
//	+0  magic       "CrAU"
//	+4  version     u64
//	+12 manifest_sz u64
//	+20 protobuf manifest (opaque here)
//	... signature_sz u32
//
// Only the prefix is decoded: the manifest and the compressed partitions are
// deliberately left alone. This is an inventory, not an OTA installer.

const (
	androidOTALocalMagic   = "PK\x03\x04"
	androidOTACentralMagic = "PK\x01\x02"
	androidOTAPayloadMagic = "CrAU"

	// androidOTAMaxEntries bounds how many central-directory entries a report
	// considers at all; androidOTADefaultEntries is the listing cap for limit<=0.
	androidOTAMaxEntries     = 10000
	androidOTADefaultEntries = 64
	// androidOTAEntryCap bounds a single entry read, and androidOTAMetadataCap
	// bounds the metadata string returned in the report.
	androidOTAEntryCap    = 4096
	androidOTAMetadataCap = 2048
	// androidOTAProbeBytes is the bounded prefix used by format detection. An
	// OTA's defining entry names normally appear in a local header near the
	// start, even when the payload itself is huge.
	androidOTAProbeBytes = 8 << 20
)

// AndroidOTA is the read-only inventory of an Android OTA ZIP.
type AndroidOTA struct {
	Entries        []string `json:"entries"`     // zip entry names, capped
	EntryCount     int      `json:"entry_count"` // total entries, capped at 10000
	HasPayload     bool     `json:"has_payload"`
	PayloadVersion uint64   `json:"payload_version,omitempty"`
	ManifestSize   uint64   `json:"manifest_size,omitempty"`
	Metadata       string   `json:"metadata,omitempty"` // first lines of the OTA metadata
	TotalSize      int64    `json:"total_size"`
}

// androidOTAIsMarker reports whether a ZIP entry name makes the archive an OTA
// rather than an ordinary zip. path.Clean keeps a traversal such as
// "META-INF/com/android/../../x" from masquerading as an Android entry.
func androidOTAIsMarker(name string) bool {
	clean := path.Clean(name)
	if clean == "payload.bin" || strings.HasSuffix(clean, "/payload.bin") {
		return true
	}
	return clean == "META-INF/com/android/metadata" || strings.HasPrefix(clean, "META-INF/com/android/")
}

// androidOTAHasMarker scans a bounded byte slice for ZIP entry names. Both
// local-file headers and central-directory records are considered, so a head
// that stops before the end-of-central-directory still decides correctly.
func androidOTAHasMarker(data []byte) bool {
	// A complete central directory is authoritative when it is present.
	if zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data))); err == nil {
		for i, f := range zr.File {
			if i >= androidOTAMaxEntries {
				break
			}
			if androidOTAIsMarker(f.Name) {
				return true
			}
		}
	}
	if androidOTAScanNames(data, androidOTALocalMagic, 26, 28, 0, 30) {
		return true
	}
	return androidOTAScanNames(data, androidOTACentralMagic, 28, 30, 32, 46)
}

// androidOTAScanNames finds signature-tagged headers in data and checks the
// name that follows. nameOff/extraOff/commentOff are offsets within a record
// of fixed length; commentOff==0 means the record has no comment field.
func androidOTAScanNames(data []byte, sig string, nameOff, extraOff, commentOff, fixed int) bool {
	seen := 0
	for pos := 0; pos < len(data); {
		i := bytes.Index(data[pos:], []byte(sig))
		if i < 0 {
			return false
		}
		hdr := pos + i
		if hdr+fixed > len(data) {
			return false
		}
		nameLen := int(binary.LittleEndian.Uint16(data[hdr+nameOff : hdr+nameOff+2]))
		extraLen := int(binary.LittleEndian.Uint16(data[hdr+extraOff : hdr+extraOff+2]))
		commentLen := 0
		if commentOff != 0 {
			commentLen = int(binary.LittleEndian.Uint16(data[hdr+commentOff : hdr+commentOff+2]))
		}
		if nameLen == 0 || hdr+fixed+nameLen+extraLen+commentLen > len(data) {
			// A signature inside compressed data: resume just past it.
			pos = hdr + len(sig)
			continue
		}
		seen++
		if seen > androidOTAMaxEntries {
			return false
		}
		if androidOTAIsMarker(string(data[hdr+fixed : hdr+fixed+nameLen])) {
			return true
		}
		pos = hdr + fixed + nameLen + extraLen + commentLen
	}
	return false
}

// IsAndroidOTA reports whether head starts with a ZIP local-file header and
// contains payload.bin or an entry under META-INF/com/android/. A short head,
// an ordinary zip, and non-zip bytes all return false. When the head contains
// only part of the archive, the local and central headers inside that prefix
// are used to decide.
func IsAndroidOTA(head []byte) bool {
	if len(head) < len(androidOTALocalMagic) || string(head[:len(androidOTALocalMagic)]) != androidOTALocalMagic {
		return false
	}
	return androidOTAHasMarker(head)
}

// androidOTAReaderHasMarker checks the complete central directory of a file,
// so a large OTA whose Android entries sit beyond the detection prefix is
// still recognised. A broken or absent directory is not an error here: the
// caller falls back to scanning the local headers in the probe prefix.
func androidOTAReaderHasMarker(r io.ReaderAt, size uint64) bool {
	if r == nil || size > math.MaxInt64 {
		return false
	}
	zr, err := zip.NewReader(r, int64(size))
	if err != nil {
		return false
	}
	for i, f := range zr.File {
		if i >= androidOTAMaxEntries {
			break
		}
		if androidOTAIsMarker(f.Name) {
			return true
		}
	}
	return false
}

// androidOTAProbe reads a bounded prefix for IsAndroidOTA. A short read is
// treated as no probe: the caller can still fall back to its other readers.
func androidOTAProbe(r io.ReaderAt, size uint64) []byte {
	if size > uint64(^uint64(0)>>1) {
		return nil
	}
	n := int64(size)
	if n > androidOTAProbeBytes {
		n = androidOTAProbeBytes
	}
	if n < int64(len(androidOTALocalMagic)) {
		return nil
	}
	head := make([]byte, n)
	if _, err := r.ReadAt(head, 0); err != nil {
		return nil
	}
	return head
}

// ReadAndroidOTA inventories the ZIP at r. limit caps the number of entry
// names listed (a non-positive limit means 64); the total entry count is
// capped at 10000. Only the CrAU prefix of payload.bin and the first lines of
// the Android metadata file are read, each capped well below 4 KiB.
func ReadAndroidOTA(r io.ReaderAt, size int64, limit int) (AndroidOTA, error) {
	var ota AndroidOTA
	if r == nil {
		return ota, fmt.Errorf("android OTA requires a reader")
	}
	if size < int64(len(androidOTALocalMagic)) {
		return ota, fmt.Errorf("not an android OTA: %d bytes is too short for a zip", size)
	}
	var sig [4]byte
	if _, err := r.ReadAt(sig[:], 0); err != nil {
		return ota, fmt.Errorf("read OTA zip magic: %w", err)
	}
	if string(sig[:]) != androidOTALocalMagic {
		return ota, fmt.Errorf("not an android OTA: zip magic is %q", sig[:])
	}
	if limit <= 0 {
		limit = androidOTADefaultEntries
	}

	// The central directory is required: a truncated archive must fail rather
	// than be reported as an OTA with a partial inventory.
	zr, err := zip.NewReader(r, size)
	if err != nil {
		return AndroidOTA{}, fmt.Errorf("read OTA zip central directory: %w", err)
	}
	ota.TotalSize = size
	ota.EntryCount = len(zr.File)
	if ota.EntryCount > androidOTAMaxEntries {
		ota.EntryCount = androidOTAMaxEntries
	}
	if limit > ota.EntryCount {
		limit = ota.EntryCount
	}

	payloadIndex := -1
	metadataIndex := -1
	for i, f := range zr.File {
		if i >= androidOTAMaxEntries {
			break
		}
		if len(ota.Entries) < limit {
			ota.Entries = append(ota.Entries, f.Name)
		}
		switch {
		case path.Clean(f.Name) == "payload.bin" || strings.HasSuffix(path.Clean(f.Name), "/payload.bin"):
			if payloadIndex < 0 {
				payloadIndex = i
			}
		case path.Clean(f.Name) == "META-INF/com/android/metadata":
			if metadataIndex < 0 {
				metadataIndex = i
			}
		}
	}
	if payloadIndex >= 0 {
		ota.HasPayload = true
		version, manifestSize, err := androidOTAPayloadHeader(zr.File[payloadIndex])
		if err == nil {
			ota.PayloadVersion = version
			ota.ManifestSize = manifestSize
		}
	}
	if metadataIndex >= 0 {
		ota.Metadata = androidOTAMetadata(zr.File[metadataIndex])
	}
	return ota, nil
}

// androidOTAPayloadHeader reads only the fixed 20-byte CrAU prefix. The
// manifest after it is opaque and is not decoded or skipped through.
func androidOTAPayloadHeader(f *zip.File) (uint64, uint64, error) {
	rc, err := f.Open()
	if err != nil {
		return 0, 0, fmt.Errorf("open payload.bin: %w", err)
	}
	defer rc.Close()
	var head [20]byte
	if _, err := io.ReadFull(io.LimitReader(rc, int64(len(head))), head[:]); err != nil {
		return 0, 0, fmt.Errorf("read payload.bin header: %w", err)
	}
	if string(head[:4]) != androidOTAPayloadMagic {
		return 0, 0, fmt.Errorf("payload.bin magic is %q, want %q", head[:4], androidOTAPayloadMagic)
	}
	return binary.LittleEndian.Uint64(head[4:12]), binary.LittleEndian.Uint64(head[12:20]), nil
}

// androidOTAMetadata returns at most three lines and 2 KiB of the OTA
// metadata. The read itself stops after 4 KiB.
func androidOTAMetadata(f *zip.File) string {
	rc, err := f.Open()
	if err != nil {
		return ""
	}
	defer rc.Close()
	raw, err := io.ReadAll(io.LimitReader(rc, androidOTAEntryCap))
	if err != nil && len(raw) == 0 {
		return ""
	}
	if len(raw) > androidOTAMetadataCap {
		raw = raw[:androidOTAMetadataCap]
	}
	text := strings.ReplaceAll(string(raw), "\r\n", "\n")
	lines := strings.Split(strings.TrimSuffix(text, "\n"), "\n")
	if len(lines) > 3 {
		lines = lines[:3]
	}
	for i := range lines {
		lines[i] = strings.TrimSuffix(lines[i], "\r")
	}
	out := strings.Join(lines, "\n")
	if len(out) > androidOTAMetadataCap {
		out = out[:androidOTAMetadataCap]
	}
	return out
}
