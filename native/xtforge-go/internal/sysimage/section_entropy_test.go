package sysimage

import (
	"bytes"
	"math/rand"
	"os"
	"path/filepath"
	"testing"
)

func TestProfileRegionsClassifiesBackedBytes(t *testing.T) {
	data := make([]byte, 0x8000)
	rng := rand.New(rand.NewSource(1))
	if _, err := rng.Read(data[0x4000:]); err != nil {
		t.Fatal(err)
	}
	regions := []Region{
		{Name: "z_random", Offset: 0x4000, FileSize: 0x4000},
		{Name: "a_zero", Offset: 0, FileSize: 0x4000},
	}
	got := ProfileRegions(bytes.NewReader(data), regions)
	if len(got) != 2 {
		t.Fatalf("len(ProfileRegions) = %d, want 2: %+v", len(got), got)
	}
	if got[0].Name != "a_zero" || got[0].Class != "low" || got[0].Bytes != 0x4000 {
		t.Fatalf("zero region = %+v, want a_zero/low/%d bytes", got[0], 0x4000)
	}
	if got[1].Name != "z_random" || (got[1].Class != "high" && got[1].Class != "very-high") || got[1].Bytes != 0x4000 {
		t.Fatalf("random region = %+v, want z_random/high|very-high/%d bytes", got[1], 0x4000)
	}
}

func TestProfileRegionsSkipsUnbackedRegions(t *testing.T) {
	data := bytes.Repeat([]byte{0xab}, 16)
	got := ProfileRegions(bytes.NewReader(data), []Region{
		{Name: "no_bytes", Offset: 0, FileSize: 0},
		{Name: "past_end", Offset: 1024, FileSize: 4},
		{Name: "huge_offset", Offset: ^uint64(0), FileSize: 4},
		{Name: "backed", Offset: 4, FileSize: 4},
	})
	if len(got) != 1 || got[0].Name != "backed" || got[0].Bytes != 4 {
		t.Fatalf("unexpected regions: %+v", got)
	}
}

func TestProfileRegionsNilInputs(t *testing.T) {
	regions := []Region{{Name: "backed", Offset: 0, FileSize: 4}}
	for _, got := range [][]SectionEntropy{
		ProfileRegions(nil, nil),
		ProfileRegions(nil, regions),
		ProfileRegions(bytes.NewReader(make([]byte, 4)), nil),
	} {
		if len(got) != 0 {
			t.Fatalf("expected no entries, got %+v", got)
		}
	}
}

func TestProfileRegionsSortedByName(t *testing.T) {
	data := bytes.Repeat([]byte{0x5a}, 64)
	got := ProfileRegions(bytes.NewReader(data), []Region{
		{Name: "delta", Offset: 0, FileSize: 8},
		{Name: "alpha", Offset: 8, FileSize: 8},
		{Name: "charlie", Offset: 16, FileSize: 8},
		{Name: "bravo", Offset: 24, FileSize: 8},
	})
	want := []string{"alpha", "bravo", "charlie", "delta"}
	if len(got) != len(want) {
		t.Fatalf("len(result) = %d, want %d: %+v", len(got), len(want), got)
	}
	for i, name := range want {
		if got[i].Name != name {
			t.Fatalf("result[%d].Name = %q, want %q: %+v", i, got[i].Name, name, got)
		}
	}
}

func TestProfileRegionsCapsRegionAt8MiB(t *testing.T) {
	data := make([]byte, (8<<20)+4096)
	got := ProfileRegions(bytes.NewReader(data), []Region{
		{Name: "huge", Offset: 0, FileSize: uint64(len(data))},
	})
	if len(got) != 1 || got[0].Bytes != 8<<20 {
		t.Fatalf("capped region = %+v, want %d bytes", got, 8<<20)
	}
}

func TestSectionEntropyOverviewBinLS(t *testing.T) {
	if _, err := os.Stat("/bin/ls"); err != nil {
		t.Skipf("/bin/ls unavailable: %v", err)
	}
	t.Setenv("XT_ROOTS", "/bin,/usr/bin")
	result, err := Overview("/bin/ls", "")
	if err != nil {
		t.Fatalf("Overview(/bin/ls): %v", err)
	}
	if len(result.Images) != 1 {
		t.Fatalf("images = %d, want 1", len(result.Images))
	}
	sections := result.Images[0].SectionEntropy
	if len(sections) == 0 {
		t.Fatal("overview has no section entropy")
	}
	var text *SectionEntropy
	for i := range sections {
		if sections[i].Name == ".text" {
			text = &sections[i]
		}
		if i > 0 && sections[i-1].Name > sections[i].Name {
			t.Fatalf("section entropy is not sorted: %+v", sections)
		}
	}
	if text == nil || text.Bytes == 0 {
		t.Fatalf("no file-backed .text entry in %+v", sections)
	}
}

func TestSectionEntropyArchiveOmitted(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XT_ROOTS", dir)
	buf := []byte(testARMagic)
	buf = appendARMember(t, buf, "empty.o/", []byte{1, 2, 3, 4})
	path := filepath.Join(dir, "fixture.a")
	if err := os.WriteFile(path, buf, 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := Overview(path, "")
	if err != nil {
		t.Fatalf("Overview(archive): %v", err)
	}
	if result.Format != "archive" || len(result.Images) != 0 || len(result.Archive) != 1 {
		t.Fatalf("unexpected archive result: %+v", result)
	}
}
