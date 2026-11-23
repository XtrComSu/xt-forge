package sysimage

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"testing"
)

const testARMagic = "!<arch>\n"

// arHeader builds one 60-byte ar header with decimal, space-padded fields.
func arHeader(t *testing.T, name, size, fmag string) []byte {
	t.Helper()
	h := make([]byte, archiveHeaderLen)
	padField := func(off, width int, value string) {
		for i := off; i < off+width; i++ {
			h[i] = ' '
		}
		copy(h[off:off+width], value)
	}
	padField(0, archiveNameLen, name)
	padField(16, 12, "0")
	padField(28, 6, "0")
	padField(34, 6, "0")
	padField(40, 8, "100644")
	padField(archiveSizeOff, archiveSizeLen, size)
	copy(h[58:60], fmag)
	return h
}

// appendARMember appends a header, its data, and the pad byte required after
// an odd-sized member so the next header starts at an even offset.
func appendARMember(t *testing.T, buf []byte, name string, data []byte) []byte {
	t.Helper()
	buf = append(buf, arHeader(t, name, strconv.Itoa(len(data)), "`\n")...)
	buf = append(buf, data...)
	if len(data)%2 != 0 {
		buf = append(buf, '\n')
	}
	return buf
}

func TestIsArchive(t *testing.T) {
	tests := []struct {
		name string
		head []byte
		want bool
	}{
		{"ar magic", []byte("!<arch>\nfirst.o/"), true},
		{"exact magic", []byte(testARMagic), true},
		{"elf", []byte("\x7fELF\x02\x01\x01\x00"), false},
		{"macho", []byte("\xcf\xfa\xed\xfe\x0c\x00\x00\x01"), false},
		{"random", []byte("not an archive at all"), false},
		{"short", []byte("!<arch>"), false},
		{"nil", nil, false},
	}
	for _, tc := range tests {
		if got := IsArchive(tc.head); got != tc.want {
			t.Errorf("IsArchive(%q) = %v, want %v", tc.head, got, tc.want)
		}
	}
}

func TestListArchiveMembers(t *testing.T) {
	t.Run("two members", func(t *testing.T) {
		buf := []byte(testARMagic)
		buf = appendARMember(t, buf, "first.o/", []byte("first body"))
		secondOff := int64(len(buf))
		buf = appendARMember(t, buf, "second.o/", []byte("second"))

		got, err := ListArchiveMembers(bytes.NewReader(buf), int64(len(buf)), 0)
		if err != nil {
			t.Fatalf("ListArchiveMembers: %v", err)
		}
		want := []ArchiveMember{
			{Name: "first.o", Offset: 8, Size: 10},
			{Name: "second.o", Offset: secondOff, Size: 6},
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("members = %+v, want %+v", got, want)
		}
	})

	t.Run("odd-sized member keeps the next header aligned", func(t *testing.T) {
		buf := []byte(testARMagic)
		buf = appendARMember(t, buf, "odd.o/", []byte("abc"))
		secondOff := int64(len(buf)) // 8 + 60 + 3 data bytes + 1 pad byte
		buf = appendARMember(t, buf, "even.o/", []byte("defg"))

		got, err := ListArchiveMembers(bytes.NewReader(buf), int64(len(buf)), 0)
		if err != nil {
			t.Fatalf("ListArchiveMembers: %v", err)
		}
		want := []ArchiveMember{
			{Name: "odd.o", Offset: 8, Size: 3},
			{Name: "even.o", Offset: secondOff, Size: 4},
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("members = %+v, want %+v", got, want)
		}
	})

	t.Run("symbol index is skipped", func(t *testing.T) {
		buf := []byte(testARMagic)
		buf = appendARMember(t, buf, "/", []byte("index"))
		realOff := int64(len(buf))
		buf = appendARMember(t, buf, "real.o/", []byte("ok"))

		got, err := ListArchiveMembers(bytes.NewReader(buf), int64(len(buf)), 0)
		if err != nil {
			t.Fatalf("ListArchiveMembers: %v", err)
		}
		want := []ArchiveMember{{Name: "real.o", Offset: realOff, Size: 2}}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("members = %+v, want %+v", got, want)
		}
	})

	t.Run("GNU long name is resolved", func(t *testing.T) {
		buf := []byte(testARMagic)
		// GNU terminates each table entry with "/\n", not NUL. A fixture using a
		// NUL terminator passes while every real `ar rcs` archive resolves to "",
		// which is exactly what happened before this case was corrected.
		buf = appendARMember(t, buf, "//", []byte("a_very_long_member_name.o/\n"))
		longOff := int64(len(buf))
		buf = appendARMember(t, buf, "/0", []byte("payload"))

		got, err := ListArchiveMembers(bytes.NewReader(buf), int64(len(buf)), 0)
		if err != nil {
			t.Fatalf("ListArchiveMembers: %v", err)
		}
		want := []ArchiveMember{{Name: "a_very_long_member_name.o", Offset: longOff, Size: 7}}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("members = %+v, want %+v", got, want)
		}
	})

	t.Run("bad header magic errors", func(t *testing.T) {
		buf := []byte(testARMagic)
		buf = append(buf, arHeader(t, "broken.o/", "3", "XX")...)
		buf = append(buf, "abc"...)
		got, err := ListArchiveMembers(bytes.NewReader(buf), int64(len(buf)), 0)
		if err == nil {
			t.Fatalf("ListArchiveMembers() = %+v, want an error", got)
		}
	})

	t.Run("limit caps members", func(t *testing.T) {
		buf := []byte(testARMagic)
		buf = appendARMember(t, buf, "one.o/", []byte("1"))
		buf = appendARMember(t, buf, "two.o/", []byte("2"))
		buf = appendARMember(t, buf, "three.o/", []byte("3"))

		got, err := ListArchiveMembers(bytes.NewReader(buf), int64(len(buf)), 2)
		if err != nil {
			t.Fatalf("ListArchiveMembers: %v", err)
		}
		if len(got) != 2 || got[0].Name != "one.o" || got[1].Name != "two.o" {
			t.Errorf("members = %+v, want the first two members only", got)
		}
	})

	t.Run("nil input", func(t *testing.T) {
		if _, err := ListArchiveMembers(nil, 0, 0); err == nil {
			t.Error("nil reader: want an error")
		}
		if _, err := ListArchiveMembers(bytes.NewReader(nil), 0, 0); err == nil {
			t.Error("empty reader: want an error")
		}
	})
}

// TestListArchiveMembersRealAr is the check that the in-memory fixtures missed.
//
// The synthetic case originally used a NUL-terminated long-name table and passed
// while every archive produced by real `ar rcs` resolved its long names to the
// empty string, because GNU terminates entries with "/\n". This test therefore
// drives the actual tool, and skips only when `ar` is absent.
func TestListArchiveMembersRealAr(t *testing.T) {
	arBinary, err := exec.LookPath("ar")
	if err != nil {
		t.Skip("ar not available")
	}
	dir := t.TempDir()
	longName := "a_very_long_member_name_that_exceeds_sixteen.o"
	for _, name := range []string{longName, "b.o"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("DATA"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	archivePath := filepath.Join(dir, "liblong.a")
	command := exec.Command(arBinary, "rcs", archivePath, longName, "b.o")
	command.Dir = dir
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("ar failed: %v: %s", err, output)
	}
	file, err := os.Open(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	stat, err := file.Stat()
	if err != nil {
		t.Fatal(err)
	}
	members, err := ListArchiveMembers(file, stat.Size(), 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(members) != 2 {
		t.Fatalf("members = %d, want 2: %+v", len(members), members)
	}
	if members[0].Name != longName {
		t.Fatalf("long name = %q, want %q", members[0].Name, longName)
	}
	if members[1].Name != "b.o" {
		t.Fatalf("second name = %q", members[1].Name)
	}
}
