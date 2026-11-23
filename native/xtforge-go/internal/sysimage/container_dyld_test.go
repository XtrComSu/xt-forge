package sysimage

import (
	"bytes"
	"debug/macho"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// buildSyntheticDyldCache lays out the compact header used by the dyld
// parsers, a mapping covering all images, an image table, a path pool and one
// Mach-O fixture per image. No real cache is needed to exercise the pipeline.
func buildSyntheticDyldCache(t *testing.T, count int) ([]byte, []string) {
	t.Helper()
	if count < 1 {
		t.Fatalf("need at least one image, got %d", count)
	}
	const (
		base       = uint64(0x180000000)
		mappingOff = 0x100
		imagesOff  = 0x200
		dataOff    = 0x1000
		imageStep  = 0x200
	)
	stringsOff := imagesOff + count*dyldImageInfoSize + 32
	paths := make([]string, count)
	paths[0] = "/usr/lib/libSystem.B.dylib"
	for i := 1; i < count; i++ {
		paths[i] = fmt.Sprintf("/usr/lib/libFixture%d.dylib", i)
	}

	cache := make([]byte, dataOff+count*imageStep)
	copy(cache, makeDyldCacheHeader("arm64e", 1, uint32(count), base))
	copy(cache[mappingOff:], makeDyldMappingInfo(base, uint64(count*imageStep), dataOff, 5, 3))
	pool := stringsOff
	for i, p := range paths {
		copy(cache[imagesOff+i*dyldImageInfoSize:], makeDyldImageInfo(base+uint64(i*imageStep), int32(pool)))
		copy(cache[pool:], p+"\x00")
		pool += len(p) + 1
	}
	for i := range paths {
		copy(cache[dataOff+i*imageStep:], machFixture())
	}
	return cache, paths
}

func TestIsDyldCache(t *testing.T) {
	cache, _ := buildSyntheticDyldCache(t, 3)
	if !isDyldCache(cache[:dyldCacheHeaderLen]) {
		t.Fatal("synthetic dyld cache header was not recognised")
	}
	if isDyldCache(machFixture()) {
		t.Fatal("a Mach-O was misrecognised as a dyld cache")
	}
	random := make([]byte, 128)
	if _, err := rand.New(rand.NewSource(7)).Read(random); err != nil {
		t.Fatal(err)
	}
	if isDyldCache(random) {
		t.Fatal("random bytes were misrecognised as a dyld cache")
	}
}

func TestOpenDyldCacheSelectsImages(t *testing.T) {
	cache, paths := buildSyntheticDyldCache(t, 3)
	want := machFixture()
	for _, tc := range []struct{ member, path string }{
		{"", paths[0]},
		{"libSystem", paths[0]},
		{"1", paths[1]},
		{"2", paths[2]},
	} {
		data, name, err := openDyldCache(bytes.NewReader(cache), int64(len(cache)), tc.member)
		if err != nil {
			t.Fatalf("member %q: %v", tc.member, err)
		}
		if !bytes.Equal(data, want) {
			t.Errorf("member %q: extracted %d bytes, want the %d-byte Mach-O", tc.member, len(data), len(want))
		}
		if name != tc.path {
			t.Errorf("member %q: label = %q, want %q", tc.member, name, tc.path)
		}
		if _, err := macho.NewFile(bytes.NewReader(data)); err != nil {
			t.Errorf("member %q: extracted image is not a Mach-O: %v", tc.member, err)
		}
	}
}

func TestOpenDyldCacheUnknownMember(t *testing.T) {
	cache, _ := buildSyntheticDyldCache(t, 3)
	_, _, err := openDyldCache(bytes.NewReader(cache), int64(len(cache)), "not-present")
	if err == nil || !strings.Contains(err.Error(), "available paths") {
		t.Fatalf("expected a member error listing paths, got %v", err)
	}
	if !strings.Contains(err.Error(), "/usr/lib/libSystem.B.dylib") {
		t.Errorf("error does not list an available path: %v", err)
	}

	// A cache with more images than the listing cap must still be readable,
	// but its error may not dump every path.
	many, _ := buildSyntheticDyldCache(t, 12)
	_, _, err = openDyldCache(bytes.NewReader(many), int64(len(many)), "not-present")
	if err == nil {
		t.Fatal("expected an error for an unknown member")
	}
	if got := strings.Count(err.Error(), "/usr/lib/"); got != dyldMaxListedPaths {
		t.Errorf("error lists %d paths, want at most %d: %v", got, dyldMaxListedPaths, err)
	}
}

func TestOpenDyldCacheTruncated(t *testing.T) {
	cache, _ := buildSyntheticDyldCache(t, 3)
	for _, size := range []int{0, 40, dyldCacheHeaderLen, 0x180, 0x250, 0x1080} {
		_, _, err := openDyldCache(bytes.NewReader(cache[:size]), int64(size), "")
		if err == nil {
			t.Errorf("truncating to %#x bytes succeeded, want an error", size)
		}
	}
}

func TestOverviewOnDyldCache(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XT_ROOTS", dir)
	cache, paths := buildSyntheticDyldCache(t, 2)
	file := filepath.Join(dir, "dyld_shared_cache_arm64e")
	if err := os.WriteFile(file, cache, 0600); err != nil {
		t.Fatal(err)
	}
	got, err := Overview(file, "")
	if err != nil {
		t.Fatal(err)
	}
	if got.Format != "dyld" || got.Member != paths[0] || len(got.Images) != 1 {
		t.Fatalf("unexpected overview: %#v", got)
	}
	image := got.Images[0]
	if image.Arch != "arm64" || image.EntryPoint == nil || *image.EntryPoint != 0x100000100 {
		t.Fatalf("unexpected image: %#v", image)
	}
}
