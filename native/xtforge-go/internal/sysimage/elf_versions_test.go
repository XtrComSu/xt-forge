package sysimage

import (
	"encoding/binary"
	"reflect"
	"testing"
)

type testStrings struct{ data []byte }

func newTestStrings() *testStrings { return &testStrings{data: []byte{0}} }

func (s *testStrings) add(value string) uint32 {
	off := uint32(len(s.data))
	s.data = append(s.data, value...)
	s.data = append(s.data, 0)
	return off
}

type testVernaux struct {
	other uint16
	name  uint32
}

type testVerneed struct {
	file uint32
	aux  []testVernaux
}

// buildTestVerneed lays out each Verneed followed by its Vernaux records, so
// vn_aux/vna_next offsets are relative to the enclosing record as in an ELF.
func buildTestVerneed(records []testVerneed) []byte {
	starts := make([]int, len(records))
	size := 0
	for i, record := range records {
		starts[i] = size
		size += 16 + 16*len(record.aux)
	}
	out := make([]byte, size)
	for i, record := range records {
		base := starts[i]
		var next uint32
		if i+1 < len(records) {
			next = uint32(starts[i+1] - base)
		}
		binary.LittleEndian.PutUint16(out[base:], 1) // vn_version
		binary.LittleEndian.PutUint16(out[base+2:], uint16(len(record.aux)))
		binary.LittleEndian.PutUint32(out[base+4:], record.file)
		binary.LittleEndian.PutUint32(out[base+8:], 16) // vn_aux
		binary.LittleEndian.PutUint32(out[base+12:], next)
		for j, aux := range record.aux {
			at := base + 16 + 16*j
			binary.LittleEndian.PutUint32(out[at:], 0x1234) // vna_hash
			binary.LittleEndian.PutUint16(out[at+6:], aux.other)
			binary.LittleEndian.PutUint32(out[at+8:], aux.name)
			if j+1 < len(record.aux) {
				binary.LittleEndian.PutUint32(out[at+12:], 16) // vna_next
			}
		}
	}
	return out
}

func buildTestVersym(values ...uint16) []byte {
	out := make([]byte, 2*len(values))
	for i, value := range values {
		binary.LittleEndian.PutUint16(out[2*i:], value)
	}
	return out
}

func buildTestDynsym(bits int, names []uint32, shndx []uint16) []byte {
	stride, shndxAt := 16, 14
	if bits == 64 {
		stride, shndxAt = 24, 6
	}
	out := make([]byte, stride*len(names))
	for i := range names {
		binary.LittleEndian.PutUint32(out[i*stride:], names[i])
		binary.LittleEndian.PutUint16(out[i*stride+shndxAt:], shndx[i])
	}
	return out
}

func TestReadElfSymbolVersionsSingle(t *testing.T) {
	strs := newTestStrings()
	library := strs.add("libc.so.6")
	version := strs.add("GLIBC_2.34")
	symbol := strs.add("memcpy")
	verneed := buildTestVerneed([]testVerneed{{file: library, aux: []testVernaux{{other: 2, name: version}}}})
	versym := buildTestVersym(0, 1, 2)
	dynsym := buildTestDynsym(64, []uint32{0, 0, symbol}, []uint16{0, 0, 0})

	got := ReadElfSymbolVersions(verneed, versym, dynsym, strs.data, 64)
	want := []ElfSymbolVersion{{Name: "memcpy", Version: "GLIBC_2.34", Library: "libc.so.6"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v, want %#v", got, want)
	}
}

func TestReadElfSymbolVersionsTwoLibraries(t *testing.T) {
	strs := newTestStrings()
	libm := strs.add("libm.so.6")
	libc := strs.add("libc.so.6")
	cosVersion := strs.add("GLIBC_2.2.5")
	memcpyVersion := strs.add("GLIBC_2.34")
	cos := strs.add("cos")
	memcpy := strs.add("memcpy")
	verneed := buildTestVerneed([]testVerneed{
		{file: libm, aux: []testVernaux{{other: 2, name: cosVersion}}},
		{file: libc, aux: []testVernaux{{other: 3, name: memcpyVersion}}},
	})
	versym := buildTestVersym(2, 3)
	dynsym := buildTestDynsym(64, []uint32{cos, memcpy}, []uint16{0, 0})

	got := ReadElfSymbolVersions(verneed, versym, dynsym, strs.data, 64)
	want := []ElfSymbolVersion{
		{Name: "cos", Version: "GLIBC_2.2.5", Library: "libm.so.6"},
		{Name: "memcpy", Version: "GLIBC_2.34", Library: "libc.so.6"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v, want %#v", got, want)
	}
}

func TestReadElfSymbolVersionsHiddenBit(t *testing.T) {
	strs := newTestStrings()
	library := strs.add("libc.so.6")
	version := strs.add("GLIBC_2.34")
	symbol := strs.add("memcpy")
	verneed := buildTestVerneed([]testVerneed{{file: library, aux: []testVernaux{{other: 2, name: version}}}})
	versym := buildTestVersym(1, 0x8002) // hidden bit set on the versioned symbol
	dynsym := buildTestDynsym(64, []uint32{0, symbol}, []uint16{0, 0})

	got := ReadElfSymbolVersions(verneed, versym, dynsym, strs.data, 64)
	want := []ElfSymbolVersion{{Name: "memcpy", Version: "GLIBC_2.34", Library: "libc.so.6"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v, want %#v", got, want)
	}
}

func TestReadElfSymbolVersionsTruncated(t *testing.T) {
	strs := newTestStrings()
	libc := strs.add("libc.so.6")
	libm := strs.add("libm.so.6")
	firstVersion := strs.add("GLIBC_2.34")
	secondVersion := strs.add("GLIBC_2.2.5")
	memcpy := strs.add("memcpy")
	cos := strs.add("cos")
	verneed := buildTestVerneed([]testVerneed{
		{file: libc, aux: []testVernaux{{other: 2, name: firstVersion}}},
		{file: libm, aux: []testVernaux{{other: 3, name: secondVersion}}},
	})
	versym := buildTestVersym(2, 3)
	dynsym := buildTestDynsym(64, []uint32{memcpy, cos}, []uint16{0, 0})

	for _, tc := range []struct {
		name string
		data []byte
		want []ElfSymbolVersion
	}{
		{
			name: "second verneed header incomplete",
			data: verneed[:16+16+8], // first record complete, second one cut off
			want: []ElfSymbolVersion{{Name: "memcpy", Version: "GLIBC_2.34", Library: "libc.so.6"}},
		},
		{
			name: "vernaux record incomplete",
			data: verneed[:16+8], // header says one aux record, only half of it is present
			want: nil,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := ReadElfSymbolVersions(tc.data, versym, dynsym, strs.data, 64)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got %#v, want %#v", got, tc.want)
			}
		})
	}
}

func TestReadElfSymbolVersions32Bit(t *testing.T) {
	strs := newTestStrings()
	library := strs.add("libc.so.6")
	version := strs.add("GLIBC_2.34")
	symbol := strs.add("memcpy")
	verneed := buildTestVerneed([]testVerneed{{file: library, aux: []testVernaux{{other: 2, name: version}}}})
	versym := buildTestVersym(1, 1, 2)
	dynsym := buildTestDynsym(32, []uint32{0, 0, symbol}, []uint16{0, 0, 0})

	got := ReadElfSymbolVersions(verneed, versym, dynsym, strs.data, 32)
	want := []ElfSymbolVersion{{Name: "memcpy", Version: "GLIBC_2.34", Library: "libc.so.6"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v, want %#v", got, want)
	}
}

func TestReadElfSymbolVersionsEmpty(t *testing.T) {
	for _, tc := range []struct {
		name                         string
		verneed, versym, dynsym, str []byte
		bits                         int
	}{
		{name: "all empty"},
		{name: "no verneed", versym: []byte{1}, dynsym: make([]byte, 24), str: []byte{0}, bits: 64},
		{name: "no versym", verneed: make([]byte, 16), dynsym: make([]byte, 24), str: []byte{0}, bits: 64},
		{name: "no dynsym", verneed: make([]byte, 16), versym: []byte{1}, str: []byte{0}, bits: 64},
		{name: "no dynstr", verneed: make([]byte, 16), versym: []byte{1}, dynsym: make([]byte, 24), bits: 64},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := ReadElfSymbolVersions(tc.verneed, tc.versym, tc.dynsym, tc.str, tc.bits); got != nil {
				t.Fatalf("got %#v, want nil", got)
			}
		})
	}
}

func TestReadDebugLink(t *testing.T) {
	section := make([]byte, 20) // "libfoo.so.debug" is 15 bytes, NUL at 15, CRC at 16.
	copy(section, "libfoo.so.debug")
	binary.LittleEndian.PutUint32(section[16:], 0xdeadbeef)
	got, ok := ReadDebugLink(section)
	want := DebugLink{Name: "libfoo.so.debug", CRC: 0xdeadbeef}
	if !ok || got != want {
		t.Fatalf("got (%#v, %v), want (%#v, true)", got, ok, want)
	}
}

func TestReadDebugLinkShort(t *testing.T) {
	for _, section := range [][]byte{
		nil,
		{},
		[]byte("nonterminated"),
		append([]byte("libfoo.so.debug\x00"), 0xef, 0xbe), // shorter than name+4
	} {
		if got, ok := ReadDebugLink(section); ok {
			t.Fatalf("section %q: got (%#v, true), want false", section, got)
		}
	}
}

func TestReadDebugLinkPadding(t *testing.T) {
	section := make([]byte, 12) // 5-byte name + NUL = 6, padded to 8, then CRC.
	copy(section, "abcde")
	for i := 6; i < 8; i++ {
		section[i] = 0xff // padding must not leak into the name
	}
	binary.LittleEndian.PutUint32(section[8:], 0x0c0ffee0)
	got, ok := ReadDebugLink(section)
	want := DebugLink{Name: "abcde", CRC: 0x0c0ffee0}
	if !ok || got != want {
		t.Fatalf("got (%#v, %v), want (%#v, true)", got, ok, want)
	}
}
