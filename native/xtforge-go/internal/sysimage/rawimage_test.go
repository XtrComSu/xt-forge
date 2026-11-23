package sysimage

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestParseRawSpec(t *testing.T) {
	for _, tc := range []struct {
		arch string
		bits int
	}{
		{"x86", 32},
		{"x86_64", 64},
		{"arm", 32},
		{"arm64", 64},
	} {
		t.Run(tc.arch, func(t *testing.T) {
			spec, err := ParseRawSpec(tc.arch, 0x1000)
			if err != nil {
				t.Fatalf("ParseRawSpec(%q): %v", tc.arch, err)
			}
			if spec.Arch != tc.arch || spec.Bits != tc.bits {
				t.Fatalf("spec = %+v, want arch %q and %d bits", spec, tc.arch, tc.bits)
			}
			if spec.Base != 0x1000 || !spec.LittleEndian {
				t.Fatalf("spec = %+v, want base 0x1000 and little-endian", spec)
			}
			zero, err := ParseRawSpec(tc.arch, 0)
			if err != nil || zero.Base != 0 {
				t.Fatalf("ParseRawSpec(%q, 0) = %+v, %v", tc.arch, zero, err)
			}
		})
	}
	for _, arch := range []string{"", "mips", "X86_64"} {
		_, err := ParseRawSpec(arch, 0)
		if err == nil {
			t.Errorf("ParseRawSpec(%q) accepted an unsupported architecture", arch)
		}
	}
}

func TestRawImage(t *testing.T) {
	payload := bytes.Repeat([]byte{0x90}, 256)
	spec, err := ParseRawSpec("x86_64", 0x401000)
	if err != nil {
		t.Fatal(err)
	}
	image, err := RawImage(bytes.NewReader(payload), int64(len(payload)), spec)
	if err != nil {
		t.Fatalf("RawImage: %v", err)
	}
	if image.Arch != "x86_64" || image.Bits != 64 {
		t.Fatalf("arch/bits = %q/%d", image.Arch, image.Bits)
	}
	if !image.littleEndian {
		t.Fatal("raw image did not record little-endian byte order")
	}
	if len(image.Executable) != 1 {
		t.Fatalf("executable regions = %d, want 1", len(image.Executable))
	}
	region := image.Executable[0]
	if region.Name != "raw" || region.Address != 0x401000 || region.Size != 256 || region.Offset != 0 || region.FileSize != 256 {
		t.Fatalf("executable region = %+v", region)
	}
	if len(image.Sections) != 1 || image.Sections[0] != region {
		t.Fatalf("sections = %+v, want one raw section matching the executable region", image.Sections)
	}
	if len(image.Dependencies) != 0 || len(image.functions) != 0 {
		t.Fatalf("raw image invented metadata: dependencies %v, functions %v", image.Dependencies, image.functions)
	}
	if image.EntryPoint != nil {
		t.Fatalf("entry point = %#x, want nil without an explicit entry", *image.EntryPoint)
	}
	if offset, ok := image.fileOffset(0x401080); !ok || offset != 0x80 {
		t.Fatalf("fileOffset(base+0x80) = %#x, %v", offset, ok)
	}
}

func TestRawImageWithEntry(t *testing.T) {
	spec, err := ParseRawSpec("arm64", 0x8000)
	if err != nil {
		t.Fatal(err)
	}
	spec.Entry = 0x8100
	image, err := RawImage(bytes.NewReader(make([]byte, 256)), 256, spec)
	if err != nil {
		t.Fatal(err)
	}
	if image.EntryPoint == nil || *image.EntryPoint != spec.Entry {
		t.Fatalf("entry point = %v, want %#x", image.EntryPoint, spec.Entry)
	}
}

func TestRawImageOversize(t *testing.T) {
	spec, err := ParseRawSpec("arm", 0x1000)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := RawImage(bytes.NewReader(nil), maxRawImage+1, spec); err == nil {
		t.Fatal("raw image larger than 512 MiB was accepted")
	}
}

func TestRawImageEmpty(t *testing.T) {
	spec, err := ParseRawSpec("x86", 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := RawImage(bytes.NewReader(nil), 0, spec); err == nil {
		t.Fatal("zero-length raw image was accepted; this loader rejects empty input")
	}
	if _, err := RawImage(nil, 16, spec); err == nil {
		t.Fatal("nil reader was accepted")
	}
	if _, err := RawImage(bytes.NewReader(nil), 16, RawSpec{Arch: "sparc"}); err == nil {
		t.Fatal("unsupported architecture was accepted")
	}
}

// TestRawImageWiring checks the internal spec-aware inspect path: a headerless
// file becomes a raw image only when a spec is supplied, while a recognised
// format still wins.
func TestRawImageWiring(t *testing.T) {
	dir := t.TempDir()
	blob := filepath.Join(dir, "blob.bin")
	if err := os.WriteFile(blob, []byte("headerless payload, no magic here"), 0600); err != nil {
		t.Fatal(err)
	}
	spec, err := ParseRawSpec("arm", 0x20000)
	if err != nil {
		t.Fatal(err)
	}
	result, err := analyzeFileWithSpec(blob, "", false, nil, &spec)
	if err != nil {
		t.Fatalf("analyzeFileWithSpec: %v", err)
	}
	if result.Format != "raw" || len(result.Images) != 1 {
		t.Fatalf("format/images = %q/%d, want raw/1", result.Format, len(result.Images))
	}
	if result.Images[0].Arch != "arm" || result.Images[0].Bits != 32 {
		t.Fatalf("image = %+v", result.Images[0])
	}
	plain, err := analyzeFile(blob, "", false, nil)
	if err != nil || plain.Format != "unknown" || plain.Images[0].Unknown == nil {
		t.Fatalf("without a spec: format = %q, images = %+v, err = %v", plain.Format, plain.Images, err)
	}

	recognised := filepath.Join(dir, "macho")
	if err := os.WriteFile(recognised, machFixture(), 0600); err != nil {
		t.Fatal(err)
	}
	kept, err := analyzeFileWithSpec(recognised, "", false, nil, &spec)
	if err != nil {
		t.Fatal(err)
	}
	if kept.Format != "macho" {
		t.Fatalf("raw spec shadowed a recognised format: %q", kept.Format)
	}
}
