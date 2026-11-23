package sysimage

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

// Fallback tests.
//
// The hash is the one field a user may compare against an external tool, so it is
// checked against crypto/sha256 computed here rather than against a value the
// implementation produced. The rest of the contract is boundedness: an unknown file
// must never cause an unbounded read or an unbounded preview.

func TestDescribeUnknownHashesWholeFile(t *testing.T) {
	payload := bytes.Repeat([]byte("fallback bytes "), 100)
	description := describeUnknown(bytes.NewReader(payload), int64(len(payload)))
	want := sha256.Sum256(payload)
	if description.SHA256 != hex.EncodeToString(want[:]) {
		t.Fatalf("sha256 = %q, want %q", description.SHA256, hex.EncodeToString(want[:]))
	}
	if description.Size != int64(len(payload)) {
		t.Fatalf("size = %d", description.Size)
	}
	if description.Truncated {
		t.Fatal("a small file was reported as truncated")
	}
	if description.Magic != hex.EncodeToString(payload[:8]) {
		t.Fatalf("magic = %q", description.Magic)
	}
}

func TestDescribeUnknownTruncatesPreviewNotHash(t *testing.T) {
	// Larger than the preview budget: the preview must shrink, the hash must not.
	payload := make([]byte, maxFallbackRead+4096)
	for index := range payload {
		payload[index] = byte(index * 7)
	}
	description := describeUnknown(bytes.NewReader(payload), int64(len(payload)))
	if !description.Truncated {
		t.Fatal("oversized file was not marked truncated")
	}
	if len(description.Hex) != fallbackPreviewBytes*2 {
		t.Fatalf("hex preview is %d chars, want %d", len(description.Hex), fallbackPreviewBytes*2)
	}
	want := sha256.Sum256(payload)
	if description.SHA256 != hex.EncodeToString(want[:]) {
		t.Fatal("hash was computed over the preview instead of the whole file")
	}
}

func TestDescribeUnknownClassifiesContent(t *testing.T) {
	zeros := make([]byte, 8192)
	zeroDescription := describeUnknown(bytes.NewReader(zeros), int64(len(zeros)))
	if zeroDescription.EntropyClass != "low" {
		t.Fatalf("zeros class = %q", zeroDescription.EntropyClass)
	}

	random := make([]byte, 8192)
	for index := range random {
		// A cheap full-range pattern: every byte value appears equally often.
		random[index] = byte(index)
	}
	randomDescription := describeUnknown(bytes.NewReader(random), int64(len(random)))
	if randomDescription.EntropyClass != "very-high" {
		t.Fatalf("uniform class = %q", randomDescription.EntropyClass)
	}
}

func TestDescribeUnknownExtractsRecognisableStrings(t *testing.T) {
	// A fake container: a magic, a version string, and binary noise.
	payload := []byte("SQLite format 3\x00")
	payload = append(payload, 0x00, 0x01, 0x02, 0x03)
	payload = append(payload, []byte("version 1.2.3 of something\x00")...)
	description := describeUnknown(bytes.NewReader(payload), int64(len(payload)))
	if len(description.Strings) < 2 {
		t.Fatalf("strings = %v", description.Strings)
	}
	if description.Strings[0] != "SQLite format 3" {
		t.Fatalf("first string = %q", description.Strings[0])
	}
	if len(description.Strings) > fallbackStringMax {
		t.Fatalf("string count %d exceeds the cap", len(description.Strings))
	}
}

func TestDescribeUnknownEmptyAndNil(t *testing.T) {
	empty := describeUnknown(bytes.NewReader(nil), 0)
	if empty.Size != 0 || empty.SHA256 != "" {
		t.Fatalf("empty = %+v", empty)
	}
	if empty.Summarise() == "" {
		t.Fatal("empty description produced no summary")
	}
	var missing *UnknownFile
	if missing.Summarise() != "" {
		t.Fatal("nil description produced a summary")
	}
}

func TestOverviewReportsUnknownFormat(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "blob.bin")
	payload := []byte("not any binary format, just text with a marker XT-MARKER-TEXT")
	if err := os.WriteFile(path, payload, 0600); err != nil {
		t.Fatal(err)
	}
	result, err := Overview(path, "")
	if err != nil {
		t.Fatalf("an unrecognised file should still be reported: %v", err)
	}
	if result.Format != "unknown" {
		t.Fatalf("format = %q, want unknown", result.Format)
	}
	if len(result.Images) != 1 || result.Images[0].Unknown == nil {
		t.Fatalf("images = %+v", result.Images)
	}
	unknown := result.Images[0].Unknown
	want := sha256.Sum256(payload)
	if unknown.SHA256 != hex.EncodeToString(want[:]) {
		t.Fatalf("hash mismatch through Overview")
	}
	found := false
	for _, run := range unknown.Strings {
		if bytes.Contains([]byte(run), []byte("XT-MARKER-TEXT")) {
			found = true
		}
	}
	if !found {
		t.Fatalf("marker string not recovered: %v", unknown.Strings)
	}
}

// TestUnknownNeverShadowsRealFormats is the guard that matters: the fallback must be
// the last resort, never a default that swallows binaries the loaders understand.
func TestUnknownNeverShadowsRealFormats(t *testing.T) {
	for _, tc := range []struct {
		name    string
		payload []byte
		format  string
	}{
		{"mach-o", machFixture(), "macho"},
		{"archive", archiveFixture(t), "archive"},
	} {
		dir := t.TempDir()
		path := filepath.Join(dir, tc.name)
		if err := os.WriteFile(path, tc.payload, 0600); err != nil {
			t.Fatal(err)
		}
		result, err := Overview(path, "")
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if result.Format != tc.format {
			t.Errorf("%s: format = %q, want %q", tc.name, result.Format, tc.format)
		}
		if len(result.Images) > 0 && result.Images[0].Unknown != nil {
			t.Errorf("%s: fell through to the unknown fallback", tc.name)
		}
	}
}
