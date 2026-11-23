package sysimage

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

type androidZipItem struct {
	name string
	data []byte
}

func androidTestZip(t *testing.T, items []androidZipItem) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, item := range items {
		w, err := zw.Create(item.name)
		if err != nil {
			t.Fatalf("create %q: %v", item.name, err)
		}
		if _, err := w.Write(item.data); err != nil {
			t.Fatalf("write %q: %v", item.name, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("close zip: %v", err)
	}
	return buf.Bytes()
}

// androidTestPayload builds a synthetic CrAU header: 4-byte magic, u64 version,
// u64 manifest size, 8 bytes of opaque manifest, then a u32 signature size.
func androidTestPayload(version, manifestSize uint64) []byte {
	payload := make([]byte, 32)
	copy(payload, androidOTAPayloadMagic)
	binary.LittleEndian.PutUint64(payload[4:12], version)
	binary.LittleEndian.PutUint64(payload[12:20], manifestSize)
	for i := 20; i < 28; i++ {
		payload[i] = byte(i)
	}
	binary.LittleEndian.PutUint32(payload[28:32], 7)
	return payload
}

func androidOTATestBlob(t *testing.T) []byte {
	t.Helper()
	return androidTestZip(t, []androidZipItem{
		{name: "payload.bin", data: androidTestPayload(3, 4096)},
		{name: "META-INF/com/android/metadata", data: []byte("ota-type=AB\npost-build=device/release:12/abc\npre-build=device/release:11/def\nfourth-line=ignored\n")},
		{name: "care_map.pb", data: []byte("x")},
	})
}

func TestIsAndroidOTA(t *testing.T) {
	ota := androidOTATestBlob(t)
	if !IsAndroidOTA(ota) {
		t.Fatal("an OTA zip was not recognized")
	}
	// Even a prefix that stops before the central directory must decide from
	// the local headers it does contain.
	if !IsAndroidOTA(ota[:512]) {
		t.Fatal("an OTA zip prefix with payload.bin was not recognized")
	}
	plain := androidTestZip(t, []androidZipItem{{name: "readme.txt", data: []byte("hello")}})
	if IsAndroidOTA(plain) {
		t.Fatal("an ordinary zip must not be claimed as an OTA")
	}
	for _, head := range [][]byte{nil, []byte("PK"), []byte("PK\x05\x06"), []byte("not a zip at all")} {
		if IsAndroidOTA(head) {
			t.Fatalf("non-zip head %q was accepted", head)
		}
	}
}

func TestReadAndroidOTA(t *testing.T) {
	blob := androidOTATestBlob(t)
	ota, err := ReadAndroidOTA(bytes.NewReader(blob), int64(len(blob)), 0)
	if err != nil {
		t.Fatalf("read OTA: %v", err)
	}
	if !ota.HasPayload || ota.PayloadVersion != 3 || ota.ManifestSize != 4096 {
		t.Fatalf("payload inventory: %+v", ota)
	}
	if ota.EntryCount != 3 || len(ota.Entries) != 3 || ota.TotalSize != int64(len(blob)) {
		t.Fatalf("entry inventory: %+v", ota)
	}
	wantMetadata := "ota-type=AB\npost-build=device/release:12/abc\npre-build=device/release:11/def"
	if ota.Metadata != wantMetadata {
		t.Fatalf("metadata: got %q, want %q", ota.Metadata, wantMetadata)
	}
}

func TestReadAndroidOTAEntryCap(t *testing.T) {
	items := []androidZipItem{{name: "payload.bin", data: androidTestPayload(1, 2)}}
	for i := 0; i < 9; i++ {
		items = append(items, androidZipItem{name: "file" + string(rune('a'+i)) + ".txt", data: []byte("x")})
	}
	blob := androidTestZip(t, items)
	ota, err := ReadAndroidOTA(bytes.NewReader(blob), int64(len(blob)), 3)
	if err != nil {
		t.Fatalf("read OTA: %v", err)
	}
	if ota.EntryCount != 10 || len(ota.Entries) != 3 {
		t.Fatalf("entry cap: count=%d entries=%v", ota.EntryCount, ota.Entries)
	}
	if !ota.HasPayload {
		t.Fatalf("payload was lost under the entry cap: %+v", ota)
	}
}

func TestReadAndroidOTAMetadataCap(t *testing.T) {
	long := strings.Repeat("x", 5000) + "\nsecond\nthird\nfourth\n"
	blob := androidTestZip(t, []androidZipItem{
		{name: "META-INF/com/android/metadata", data: []byte(long)},
		{name: "payload.bin", data: androidTestPayload(2, 99)},
	})
	ota, err := ReadAndroidOTA(bytes.NewReader(blob), int64(len(blob)), 0)
	if err != nil {
		t.Fatalf("read OTA: %v", err)
	}
	if len(ota.Metadata) != androidOTAMetadataCap || strings.Contains(ota.Metadata, "second") {
		t.Fatalf("metadata cap: len=%d value=%q", len(ota.Metadata), ota.Metadata)
	}
}

func TestReadAndroidOTATruncated(t *testing.T) {
	blob := androidOTATestBlob(t)
	for _, cut := range []int{len(blob) / 2, len(blob) - 10} {
		truncated := blob[:cut]
		if _, err := ReadAndroidOTA(bytes.NewReader(truncated), int64(len(truncated)), 0); err == nil {
			t.Fatalf("truncated zip at %d bytes should be rejected", cut)
		}
	}
}

func TestReadAndroidOTANonZip(t *testing.T) {
	data := []byte("this is not a zip archive")
	if IsAndroidOTA(data) {
		t.Fatal("non-zip bytes were detected as an OTA")
	}
	if _, err := ReadAndroidOTA(bytes.NewReader(data), int64(len(data)), 0); err == nil {
		t.Fatal("non-zip bytes should produce an error")
	}
	if _, err := ReadAndroidOTA(nil, 1024, 0); err == nil {
		t.Fatal("a nil reader should produce an error")
	}
}

func TestReadAndroidOTADetected(t *testing.T) {
	blob := androidOTATestBlob(t)
	format, images, err := inspect(bytes.NewReader(blob), uint64(len(blob)), false, "")
	if err != nil || format != "androidota" || len(images) != 1 || images[0].OTA == nil {
		t.Fatalf("detection: format=%q images=%d err=%v", format, len(images), err)
	}
	if !images[0].OTA.HasPayload || images[0].OTA.PayloadVersion != 3 {
		t.Fatalf("detected OTA: %+v", images[0].OTA)
	}
}
