package sysimage

import (
	"bytes"
	"reflect"
	"strings"
	"testing"
)

func TestListDyldImagesReturnsAllInOrder(t *testing.T) {
	cache, paths := buildSyntheticDyldCache(t, 3)
	got, err := ListDyldImages(bytes.NewReader(cache), int64(len(cache)), 0)
	if err != nil {
		t.Fatalf("ListDyldImages: %v", err)
	}
	want := []DyldImage{
		{Path: paths[0], Address: 0x180000000},
		{Path: paths[1], Address: 0x180000200},
		{Path: paths[2], Address: 0x180000400},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ListDyldImages() = %+v, want %+v", got, want)
	}
}

func TestListDyldImagesLimit(t *testing.T) {
	cache, paths := buildSyntheticDyldCache(t, 3)
	got, err := ListDyldImages(bytes.NewReader(cache), int64(len(cache)), 2)
	if err != nil {
		t.Fatalf("ListDyldImages: %v", err)
	}
	want := []DyldImage{
		{Path: paths[0], Address: 0x180000000},
		{Path: paths[1], Address: 0x180000200},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("limit 2: got %+v, want %+v", got, want)
	}
}

func TestListDyldImagesNonCache(t *testing.T) {
	for _, data := range [][]byte{nil, []byte("not a cache"), machFixture()} {
		if got, err := ListDyldImages(bytes.NewReader(data), int64(len(data)), 0); err == nil {
			t.Errorf("non-cache input %d bytes: got %+v, want an error", len(data), got)
		} else if !strings.Contains(err.Error(), "not a dyld shared cache") && !strings.Contains(err.Error(), "truncated") {
			t.Errorf("unexpected non-cache error: %v", err)
		}
	}
}

func TestListDyldImagesTruncated(t *testing.T) {
	cache, _ := buildSyntheticDyldCache(t, 3)
	for _, size := range []int{0, 40, dyldCacheHeaderLen, 0x118, 0x220} {
		got, err := ListDyldImages(bytes.NewReader(cache[:size]), int64(size), 0)
		if err == nil {
			t.Errorf("truncating to %#x bytes returned %+v, want an error", size, got)
		}
	}
}

func TestOpenDyldCacheList(t *testing.T) {
	cache, paths := buildSyntheticDyldCache(t, 3)
	for _, member := range []string{"list", "LIST", "LiSt"} {
		_, name, err := openDyldCache(bytes.NewReader(cache), int64(len(cache)), member)
		if err == nil {
			t.Fatalf("member %q: expected an error listing paths, got name %q", member, name)
		}
		for _, path := range paths {
			if !strings.Contains(err.Error(), path) {
				t.Errorf("member %q: error does not contain %q: %v", member, path, err)
			}
		}
	}

	// Listing must not break normal substring/index selection.
	for _, member := range []string{"libSystem", "1"} {
		data, name, err := openDyldCache(bytes.NewReader(cache), int64(len(cache)), member)
		if err != nil {
			t.Errorf("member %q: %v", member, err)
			continue
		}
		if !bytes.Equal(data, machFixture()) || name == "" {
			t.Errorf("member %q: unexpected extraction %q", member, name)
		}
	}
}
