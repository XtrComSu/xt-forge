package sysimage

import (
	"os"
	"path/filepath"
	"testing"
)

// Tests for the container and format branches added to analyzeFile.
//
// The gate test is the important one. IsKernelCache accepts any Mach-O whose
// filetype is MH_EXECUTE, and every ordinary executable is one, so using it as a
// container gate would route the entire Mach-O path through the kernelcache
// loader. isKernelCacheHead exists to be narrower, and this test is what keeps it
// that way.

func TestKernelCacheGateRejectsOrdinaryBinaries(t *testing.T) {
	for _, tc := range []struct {
		name string
		head []byte
	}{
		{"plain Mach-O executable", machFixture()},
		{"Mach-O with ObjC metadata", objcFixture(false)},
		{"ELF", func() []byte {
			return append([]byte{0x7f, 'E', 'L', 'F', 2, 1, 1, 0}, make([]byte, 128)...)
		}()},
		{"PE", append([]byte{'M', 'Z'}, make([]byte, 128)...)},
		{"random bytes", []byte("not a binary at all")},
		{"empty", nil},
		{"short", []byte{0xcf, 0xfa}},
	} {
		if isKernelCacheHead(tc.head) {
			t.Errorf("%s: gate accepted a non-kernelcache container", tc.name)
		}
	}
}

func TestKernelCacheGateAcceptsIMG4(t *testing.T) {
	head := append([]byte("IMG4"), []byte("\x00\x00\x00\x00KERNEL\x00\x00")...)
	head = append(head, make([]byte, 64)...)
	if !isKernelCacheHead(head) {
		t.Fatal("gate rejected an IMG4 kernel container")
	}
	// IMG4 without a kernel marker is not a kernelcache.
	plain := append([]byte("IMG4"), make([]byte, 64)...)
	if isKernelCacheHead(plain) {
		t.Fatal("gate accepted a bare IMG4 that is not a kernel")
	}
}

func TestOverviewOpensKernelCacheContainer(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "kernelcache.img4")
	container := kernelIMG4Fixture("krnl", "kernel", machFixture())
	if err := os.WriteFile(path, container, 0600); err != nil {
		t.Fatal(err)
	}
	result, err := Overview(path, "")
	if err != nil {
		t.Fatal(err)
	}
	if result.Format != "kernelcache" {
		t.Fatalf("format = %q, want kernelcache", result.Format)
	}
	if len(result.Images) == 0 {
		t.Fatal("no image recovered from the kernelcache payload")
	}
	// A malformed container must be rejected rather than treated as a Mach-O.
	broken := append([]byte("IMG4"), make([]byte, 128)...)
	brokenPath := filepath.Join(dir, "broken.img4")
	if err := os.WriteFile(brokenPath, broken, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Overview(brokenPath, ""); err == nil {
		t.Fatal("malformed IMG4 was accepted")
	}
}

func TestOverviewListsArchiveMembers(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "lib.a")
	if err := os.WriteFile(path, archiveFixture(t), 0600); err != nil {
		t.Fatal(err)
	}
	result, err := Overview(path, "")
	if err != nil {
		t.Fatal(err)
	}
	if result.Format != "archive" {
		t.Fatalf("format = %q, want archive", result.Format)
	}
	if len(result.Archive) != 2 {
		t.Fatalf("members = %d, want 2", len(result.Archive))
	}
	if result.Archive[0].Name != "first.o" || result.Archive[1].Name != "second.o" {
		t.Fatalf("member names = %q, %q", result.Archive[0].Name, result.Archive[1].Name)
	}
}

func TestOverviewAcceptsMemberFlagOnlyForContainers(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "plain.bin")
	if err := os.WriteFile(path, machFixture(), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Overview(path, "some-member"); err == nil {
		t.Fatal("--member on a bare Mach-O should be rejected")
	}
}

// archiveFixture builds a two-member archive using the helpers from archive_test.go.
func archiveFixture(t *testing.T) []byte {
	t.Helper()
	buf := []byte("!<arch>\n")
	buf = appendARMember(t, buf, "first.o", []byte("AAAA"))
	buf = appendARMember(t, buf, "second.o", []byte("BBBBBB"))
	return buf
}
