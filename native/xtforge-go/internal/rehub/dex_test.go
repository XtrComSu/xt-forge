package rehub

import (
	"archive/zip"
	"bytes"
	"crypto/sha1"
	"encoding/binary"
	"hash/adler32"
	"os"
	"path/filepath"
	"testing"
)

// buildDex assembles a minimal but structurally valid DEX file with one class, one
// field and two methods, so every expected value is chosen by this test rather than
// observed from a fixture that might change.
//
// Hand-building it is the point: the header is not a packed array of 4-byte words
// (a 20-byte signature sits between the checksum and file_size), so a builder that
// gets the offsets right also documents them.
func buildDex(t *testing.T) []byte {
	t.Helper()
	const headerSize = 0x70
	// Sections, laid out after the header in the order DEX requires.
	stringData := []byte{}
	stringOffsets := []int{}
	addString := func(s string) int {
		stringOffsets = append(stringOffsets, len(stringData))
		// ULEB128 UTF-16 length, then MUTF-8 bytes, then a NUL.
		length := len([]rune(s))
		for {
			b := byte(length & 0x7F)
			length >>= 7
			if length != 0 {
				b |= 0x80
			}
			stringData = append(stringData, b)
			if length == 0 {
				break
			}
		}
		stringData = append(stringData, []byte(s)...)
		stringData = append(stringData, 0)
		return len(stringOffsets) - 1
	}
	// Index order matters only for readability here.
	idxTestClass := addString("Lcom/example/Test;")
	idxName := addString("value")
	idxMethod := addString("compute")
	idxObject := addString("Ljava/lang/Object;")
	idxInt := addString("I")
	idxVoid := addString("V")
	idxMethodB := addString("computeB")
	idxMethodC := addString("computeC")
	idxSource := addString("Test.java")
	idxShorty := addString("V")

	stringIDsOff := headerSize
	typeIDsOff := stringIDsOff + len(stringOffsets)*4
	protoIDsOff := typeIDsOff + 4*4
	fieldIDsOff := protoIDsOff + 12
	methodIDsOff := fieldIDsOff + 8
	classDefsOff := methodIDsOff + 4*8
	dataOff := classDefsOff + 32

	// class_data_item: 0 static, 1 instance field (delta 0), 1 direct, 1 virtual.
	classData := []byte{0x00, 0x01, 0x02, 0x00}
	classData = append(classData, 0x00, 0x02) // field 0, PRIVATE
	// Two *direct* methods with deltas 2 then 1, so accumulation lands on indices
	// 2 and 3 while reading the delta as an absolute index lands on 2 and 1. This
	// asymmetry is required: DEX restarts the accumulator at 0 for each kind, so a
	// single method per kind cannot distinguish the two readings at all, and a
	// fixture with all-zero deltas cannot either.
	classData = append(classData, 0x02, 0x01, 0x00) // direct: delta 2 -> method 2
	classData = append(classData, 0x01, 0x01, 0x00) // direct: delta 1 -> method 3
	classDataOff := dataOff

	total := dataOff + len(classData) + len(stringData)
	buf := make([]byte, total)

	copy(buf[0:], []byte{'d', 'e', 'x', '\n', '0', '3', '5', 0})
	put32 := func(off int, v uint32) { binary.LittleEndian.PutUint32(buf[off:], v) }
	put32(32, uint32(total)) // file_size
	put32(36, headerSize)    // header_size
	put32(40, 0x12345678)    // endian_tag
	put32(56, uint32(len(stringOffsets)))
	put32(60, uint32(stringIDsOff))
	put32(64, 4) // type_ids_size
	put32(68, uint32(typeIDsOff))
	put32(72, 1)
	put32(76, uint32(protoIDsOff))
	put32(80, 1)
	put32(84, uint32(fieldIDsOff))
	put32(88, 4)
	put32(92, uint32(methodIDsOff))
	put32(96, 1)
	put32(100, uint32(classDefsOff))
	put32(104, uint32(len(classData)+len(stringData)))
	put32(108, uint32(dataOff))

	// string_ids: absolute offsets into string_data.
	for i, rel := range stringOffsets {
		put32(stringIDsOff+i*4, uint32(dataOff+len(classData)+rel))
	}
	copy(buf[dataOff+len(classData):], stringData)

	// type_ids: descriptor string indices.
	put32(typeIDsOff+0, uint32(idxTestClass))
	put32(typeIDsOff+4, uint32(idxObject))
	put32(typeIDsOff+8, uint32(idxInt))
	put32(typeIDsOff+12, uint32(idxVoid))

	// proto_ids: shorty, return_type, parameters_off.
	put32(protoIDsOff, uint32(idxShorty))
	put32(protoIDsOff+4, 3) // void
	put32(protoIDsOff+8, 0)

	// field_ids: class_idx(u16), type_idx(u16), name_idx(u32).
	binary.LittleEndian.PutUint16(buf[fieldIDsOff:], 0)
	binary.LittleEndian.PutUint16(buf[fieldIDsOff+2:], 2) // int
	put32(fieldIDsOff+4, uint32(idxName))

	// method_ids: class_idx(u16), proto_idx(u16), name_idx(u32).
	// Methods 0 and 1 are decoys; the class_data directs at 2 and 3, which carry
	// distinct names so the delta bug becomes visible: treating delta as absolute
	// yields index 2 then index 1 (a decoy name) instead of 2 then 3.
	methodNames := []uint32{uint32(idxMethod), uint32(idxMethod),
		uint32(idxMethodB), uint32(idxMethodC)}
	for i, nameIdx := range methodNames {
		base := methodIDsOff + i*8
		binary.LittleEndian.PutUint16(buf[base:], 0)
		binary.LittleEndian.PutUint16(buf[base+2:], 0)
		put32(base+4, nameIdx)
	}

	copy(buf[classDataOff:], classData)

	// class_def: class_idx, access, superclass_idx, interfaces_off,
	//            source_file_idx, annotations_off, class_data_off, static_values_off
	put32(classDefsOff+0, 0)
	put32(classDefsOff+4, 0x0001|0x0010) // PUBLIC | FINAL
	put32(classDefsOff+8, 1)             // Ljava/lang/Object;
	put32(classDefsOff+12, 0)
	put32(classDefsOff+16, uint32(idxSource))
	put32(classDefsOff+20, 0)
	put32(classDefsOff+24, uint32(classDataOff))
	put32(classDefsOff+28, 0)

	// Signature and checksum last, since they cover the final bytes.
	sum := sha1Sum(buf[32:])
	copy(buf[12:32], sum)
	put32(8, adler32.Checksum(buf[12:]))
	return buf
}

func sha1Sum(data []byte) []byte {
	sum := sha1.Sum(data)
	return sum[:]
}

func TestInspectDexBytesHeaderAndCounts(t *testing.T) {
	report := InspectDexBytes(buildDex(t), 5)
	if ok, _ := report["ok"].(bool); !ok {
		t.Fatalf("not ok: %v", report["error"])
	}
	if got := report["version"]; got != "035" {
		t.Errorf("version = %v, want 035", got)
	}
	counts, _ := report["counts"].(map[string]any)
	want := map[string]uint32{"strings": 10, "types": 4, "prototypes": 1,
		"fields": 1, "methods": 4, "classes": 1}
	for key, value := range want {
		if got := counts[key]; got != value {
			t.Errorf("counts[%s] = %v, want %d", key, got, value)
		}
	}
}

func TestInspectDexBytesVerification(t *testing.T) {
	report := InspectDexBytes(buildDex(t), 5)
	verify, _ := report["verification"].(map[string]any)
	for _, key := range []string{"checksum_ok", "signature_ok", "file_size_ok"} {
		if ok, _ := verify[key].(bool); !ok {
			t.Errorf("%s = false, want true", key)
		}
	}
}

func TestInspectDexBytesRejectsCorruption(t *testing.T) {
	data := buildDex(t)
	data[len(data)-1] ^= 0xFF // flip a byte of the string data
	report := InspectDexBytes(data, 5)
	verify, _ := report["verification"].(map[string]any)
	if ok, _ := verify["checksum_ok"].(bool); ok {
		t.Error("checksum_ok = true after corrupting the file; the check is not load-bearing")
	}
}

func TestInspectDexBytesClassMembers(t *testing.T) {
	report := InspectDexBytes(buildDex(t), 5)
	classes, _ := report["classes"].([]map[string]any)
	if len(classes) != 1 {
		t.Fatalf("got %d classes, want 1", len(classes))
	}
	class := classes[0]
	if got := class["name"]; got != "Lcom/example/Test;" {
		t.Errorf("name = %v", got)
	}
	if got := class["superclass"]; got != "Ljava/lang/Object;" {
		t.Errorf("superclass = %v", got)
	}
	if got := class["source_file"]; got != "Test.java" {
		t.Errorf("source_file = %v", got)
	}
	if got := class["field_count"]; got != 1 {
		t.Errorf("field_count = %v, want 1", got)
	}
	if got := class["method_count"]; got != 2 {
		t.Errorf("method_count = %v, want 2", got)
	}
	fields, _ := class["fields"].([]map[string]any)
	if len(fields) != 1 || fields[0]["name"] != "value" {
		t.Errorf("fields = %v", fields)
	}
	methods, _ := class["methods"].([]map[string]any)
	if len(methods) != 2 {
		t.Fatalf("methods = %d, want 2", len(methods))
	}
	if got := methods[0]["name"]; got != "computeB" {
		t.Errorf("methods[0].name = %v, want computeB", got)
	}
	if got := methods[1]["name"]; got != "computeC" {
		t.Errorf("methods[1].name = %v, want computeC (delta was treated as absolute)", got)
	}
	proto, _ := methods[0]["proto"].(map[string]any)
	if got := proto["return_type"]; got != "V" {
		t.Errorf("return_type = %v, want V", got)
	}
}

func TestInspectDexBytesRejectsNonDex(t *testing.T) {
	for _, payload := range [][]byte{
		{},
		[]byte("not a dex file at all"),
		bytes.Repeat([]byte{0}, 200),
	} {
		report := InspectDexBytes(payload, 1)
		if ok, _ := report["ok"].(bool); ok {
			t.Errorf("accepted %d bytes of non-DEX input", len(payload))
		}
	}
}

func TestInspectDexBytesRandomInputNeverPanics(t *testing.T) {
	base := buildDex(t)
	for i := 0; i < 200; i++ {
		mutated := make([]byte, len(base))
		copy(mutated, base)
		// Mutate inside the structures the walker reads, not the magic.
		pos := 32 + (i*37)%(len(mutated)-32)
		mutated[pos] ^= byte(1 + i%255)
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panic on mutation at %d: %v", pos, r)
				}
			}()
			InspectDexBytes(mutated, 1)
		}()
	}
}

func TestInspectDexEntryFromArchive(t *testing.T) {
	dex := buildDex(t)
	dir := t.TempDir()
	apk := filepath.Join(dir, "sample.apk")
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create("classes.dex")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(dex); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(apk, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	report := InspectDexEntry(apk, "classes.dex")
	if ok, _ := report["ok"].(bool); !ok {
		t.Fatalf("not ok: %v", report["error"])
	}
	if got := report["entry"]; got != "classes.dex" {
		t.Errorf("entry = %v", got)
	}
	counts, _ := report["counts"].(map[string]any)
	if counts["classes"] != uint32(1) {
		t.Errorf("classes = %v, want 1", counts["classes"])
	}
}

func TestInspectDexEntryMissingArchive(t *testing.T) {
	report := InspectDexEntry("/nonexistent/file.apk", "classes.dex")
	if ok, _ := report["ok"].(bool); ok {
		t.Error("accepted a missing archive")
	}
}
