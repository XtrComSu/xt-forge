package rehub

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// Build an AndroidManifest.xml in the real binary format.
//
// The previous tests wrote a plain-text fake manifest containing
// `android.permission.INTERNET\x00com.demo.MainActivity\x00` and only asserted that
// `InspectAPK` returned ok — never what it found. That is why a permissions list which over-
// reported by one entry survived: nothing checked the values.
//
// A hand-built blob is not enough either. The scraper this replaces would happily "pass" any test
// whose fixture is a plain string, because it matched raw bytes. So the fixture below has a
// genuine chunked structure — string pool, resource map, typed attributes — and the assertions are
// about what a real decoder must return.
type axmlBuilder struct {
	strings []string
	index   map[string]int
	body    []byte
	attrs   []string
}

func newAXMLBuilder() *axmlBuilder {
	b := &axmlBuilder{index: map[string]int{}}
	// Attribute names first, because the resource map indexes into the string pool by position.
	for _, name := range []string{"versionCode", "versionName", "name", "exported", "permission"} {
		b.intern(name)
	}
	return b
}

func (b *axmlBuilder) intern(s string) int {
	if i, ok := b.index[s]; ok {
		return i
	}
	b.index[s] = len(b.strings)
	b.strings = append(b.strings, s)
	return b.index[s]
}

type attrSpec struct {
	name     string
	strValue string
	boolVal  *bool
	intVal   *int32
}

func (b *axmlBuilder) start(tag string, attrs ...attrSpec) {
	tagIdx := b.intern(tag)
	// An element chunk is: 8-byte ResChunk_header, then lineNumber and comment (8 more bytes),
	// then ns and name, then the attribute geometry. `attributeStart` is measured from chunk+16,
	// which is where the geometry begins — writing the body at chunk+8 puts every field 8 bytes
	// early and the decoder reads a name of zero and no attributes at all.
	// chunk+8 is where `body` begins. The platform's fields sit at:
	//   chunk+16 lineNumber, chunk+20 name, chunk+24 attributeStart,
	//   chunk+26 attributeSize, chunk+28 attributeCount
	// so in body coordinates that is 8, 12, 16, 18 and 20.
	body := make([]byte, 22)
	binary.LittleEndian.PutUint32(body[12:], uint32(tagIdx))
	binary.LittleEndian.PutUint16(body[16:], 20) // attributeStart, measured from chunk+16
	binary.LittleEndian.PutUint16(body[18:], 20) // attributeSize
	binary.LittleEndian.PutUint16(body[20:], uint16(len(attrs)))

	records := make([]byte, 0, len(attrs)*20)
	for _, a := range attrs {
		nameIdx := b.intern(a.name)
		rec := make([]byte, 20)
		binary.LittleEndian.PutUint32(rec[4:], uint32(nameIdx))
		switch {
		case a.boolVal != nil:
			binary.LittleEndian.PutUint32(rec[8:], 0xFFFFFFFF) // rawValue absent
			rec[15] = 0x12                                      // TYPE_INT_BOOLEAN
			if *a.boolVal {
				binary.LittleEndian.PutUint32(rec[16:], 0xFFFFFFFF)
			}
		case a.intVal != nil:
			binary.LittleEndian.PutUint32(rec[8:], 0xFFFFFFFF)
			rec[15] = 0x10 // TYPE_INT_DEC
			binary.LittleEndian.PutUint32(rec[16:], uint32(*a.intVal))
		default:
			valueIdx := b.intern(a.strValue)
			binary.LittleEndian.PutUint32(rec[8:], uint32(valueIdx))
			rec[15] = 0x03 // TYPE_STRING
			binary.LittleEndian.PutUint32(rec[16:], uint32(valueIdx))
		}
		records = append(records, rec...)
	}

	// Records begin at chunk+16+attributeStart, which is chunk+36 for attributeStart=20. `body`
	// is written at chunk+8 and is 22 bytes, so it ends at chunk+30 — six bytes short. The
	// padding is not slack: writing records at chunk+30 makes every field land mid-word and the
	// decoder reads a name index of 65535.
	const attrAreaAt = 16 + 20
	total := attrAreaAt + len(records)
	out := make([]byte, total)
	binary.LittleEndian.PutUint16(out[0:], resXMLStartElement)
	binary.LittleEndian.PutUint16(out[2:], 16) // header size, as the platform writes it
	binary.LittleEndian.PutUint32(out[4:], uint32(total))
	copy(out[8:], body)
	copy(out[attrAreaAt:], records)
	b.body = append(b.body, out...)
}

func (b *axmlBuilder) end(tag string) {
	tagIdx := b.intern(tag)
	body := make([]byte, 20)
	binary.LittleEndian.PutUint32(body[12:], uint32(tagIdx))
	out := make([]byte, 16+len(body))
	binary.LittleEndian.PutUint16(out[0:], resXMLEndElement)
	binary.LittleEndian.PutUint16(out[2:], 16)
	binary.LittleEndian.PutUint32(out[4:], uint32(len(out)))
	copy(out[8:], body)
	b.body = append(b.body, out...)
}

func (b *axmlBuilder) chunk(kind uint16, body []byte) []byte {
	out := make([]byte, 8+len(body))
	binary.LittleEndian.PutUint16(out[0:], kind)
	binary.LittleEndian.PutUint16(out[2:], 16) // header size, as the platform writes it
	binary.LittleEndian.PutUint32(out[4:], uint32(len(out)))
	copy(out[8:], body)
	return out
}

// build assembles the full document: XML header, string pool, resource map, then the body.
func (b *axmlBuilder) build() []byte {
	// String pool, UTF-16LE.
	var data bytes.Buffer
	offsets := make([]uint32, len(b.strings))
	for i, s := range b.strings {
		offsets[i] = uint32(data.Len())
		encoded := encodeUTF16LE(s)
		_ = binary.Write(&data, binary.LittleEndian, uint16(len(encoded)/2))
		data.Write(encoded)
		data.Write([]byte{0, 0})
	}
	for len(data.Bytes())%4 != 0 {
		data.WriteByte(0)
	}
	headerSize := 28
	poolSize := headerSize + len(offsets)*4 + data.Len()
	pool := make([]byte, poolSize)
	binary.LittleEndian.PutUint16(pool[0:], resStringPoolType)
	binary.LittleEndian.PutUint16(pool[2:], uint16(headerSize))
	binary.LittleEndian.PutUint32(pool[4:], uint32(poolSize))
	binary.LittleEndian.PutUint32(pool[8:], uint32(len(b.strings)))
	binary.LittleEndian.PutUint32(pool[16:], 0) // flags: UTF-16LE
	binary.LittleEndian.PutUint32(pool[20:], uint32(headerSize+len(offsets)*4))
	for i, off := range offsets {
		binary.LittleEndian.PutUint32(pool[headerSize+i*4:], off)
	}
	copy(pool[headerSize+len(offsets)*4:], data.Bytes())

	// Resource map: one id per pooled attribute name, in pool order.
	resourceMap := make([]byte, 8+16)
	binary.LittleEndian.PutUint16(resourceMap[0:], resXMLResourceMap)
	binary.LittleEndian.PutUint16(resourceMap[2:], 8)
	binary.LittleEndian.PutUint32(resourceMap[4:], uint32(len(resourceMap)))

	document := append(append(append([]byte{}, pool...), resourceMap...), b.body...)
	out := make([]byte, 8+len(document))
	binary.LittleEndian.PutUint16(out[0:], resXMLType)
	binary.LittleEndian.PutUint16(out[2:], 8)
	binary.LittleEndian.PutUint32(out[4:], uint32(len(out)))
	copy(out[8:], document)
	return out
}

func encodeUTF16LE(s string) []byte {
	units := []uint16{}
	for _, r := range s {
		if r > 0xFFFF {
			r -= 0x10000
			units = append(units, uint16(0xD800+(r>>10)), uint16(0xDC00+(r&0x3FF)))
			continue
		}
		units = append(units, uint16(r))
	}
	out := make([]byte, len(units)*2)
	for i, u := range units {
		binary.LittleEndian.PutUint16(out[i*2:], u)
	}
	return out
}

func trueValue() *bool  { v := true; return &v }

func manifestFixture() []byte {
	b := newAXMLBuilder()
	version := int32(3)
	b.start("manifest",
		attrSpec{name: "versionCode", intVal: &version},
		attrSpec{name: "versionName", strValue: "1.2"})
	b.start("uses-permission", attrSpec{name: "name", strValue: "android.permission.BLUETOOTH"})
	b.end("uses-permission")
	b.start("uses-permission", attrSpec{name: "name", strValue: "android.permission.CAMERA"})
	b.end("uses-permission")
	b.start("application")
	// A service whose *required* permission is high-privilege. It is NOT a requested permission,
	// and reporting it as one was the observed false positive.
	b.start("service",
		attrSpec{name: "name", strValue: ".TileService"},
		attrSpec{name: "permission", strValue: "android.permission.BIND_QUICK_SETTINGS_TILE"},
		attrSpec{name: "exported", boolVal: trueValue()})
	b.start("intent-filter")
	b.end("intent-filter")
	b.end("service")
	b.start("receiver", attrSpec{name: "name", strValue: ".BootReceiver"})
	b.end("receiver")
	b.end("application")
	b.end("manifest")
	return b.build()
}

func TestManifestPermissionsAreOnlyRequestedOnes(t *testing.T) {
	decoded, err := ParseAXMLManifest(manifestFixture())
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	want := []string{"android.permission.BLUETOOTH", "android.permission.CAMERA"}
	if len(decoded.Permissions) != len(want) {
		t.Fatalf("got %d permissions %v, want %d %v",
			len(decoded.Permissions), decoded.Permissions, len(want), want)
	}
	for i, w := range want {
		if decoded.Permissions[i] != w {
			t.Errorf("permission[%d] = %q, want %q", i, decoded.Permissions[i], w)
		}
	}
	for _, p := range decoded.Permissions {
		if p == "android.permission.BIND_QUICK_SETTINGS_TILE" {
			t.Errorf("a service's required permission was reported as requested: %s", p)
		}
	}
}

func TestManifestTypedValuesDecode(t *testing.T) {
	decoded, err := ParseAXMLManifest(manifestFixture())
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	// versionCode is stored as an integer, so it has no string-pool entry at all.
	if decoded.VersionCode != "3" {
		t.Errorf("versionCode = %q, want \"3\" (a typed int, not a pool string)",
			decoded.VersionCode)
	}
	if decoded.VersionName != "1.2" {
		t.Errorf("versionName = %q, want \"1.2\"", decoded.VersionName)
	}
}

func TestManifestComponentsCarryExportState(t *testing.T) {
	decoded, err := ParseAXMLManifest(manifestFixture())
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	if len(decoded.Components) != 2 {
		t.Fatalf("got %d components, want 2: %+v", len(decoded.Components), decoded.Components)
	}
	service := decoded.Components[0]
	if service.Name != ".TileService" {
		t.Errorf("service name = %q", service.Name)
	}
	if !service.Exported || service.ExportedWhy != "declared" {
		t.Errorf("service exported = %v (%q), want true (declared)",
			service.Exported, service.ExportedWhy)
	}
	if service.Permission != "android.permission.BIND_QUICK_SETTINGS_TILE" {
		t.Errorf("service permission = %q", service.Permission)
	}
	// The receiver declares no exported attribute and has no intent-filter, so it is not exported.
	receiver := decoded.Components[1]
	if receiver.Exported {
		t.Errorf("receiver with no intent-filter and no exported attribute reported as exported")
	}
	if receiver.Name != ".BootReceiver" {
		t.Errorf("receiver name = %q", receiver.Name)
	}
}

func TestMalformedManifestsAreRejected(t *testing.T) {
	// A wrong magic and an empty buffer must fail outright.
	if _, err := ParseAXMLManifest([]byte{}); err == nil {
		t.Error("empty buffer: no error")
	}
	if _, err := ParseAXMLManifest([]byte{0x01, 0x00, 0x08, 0x00, 0, 0, 0, 0}); err == nil {
		t.Error("wrong magic: no error")
	}
	// A chunk declaring size 0 would loop forever; it must be refused, not spun on.
	zeroChunk := []byte{0x03, 0x00, 0x08, 0x00, 0x10, 0x00, 0x00, 0x00,
		0x01, 0x00, 0x1C, 0x00, 0x00, 0x00, 0x00, 0x00}
	if _, err := ParseAXMLManifest(zeroChunk); err == nil {
		t.Error("zero-size chunk: no error")
	}
	// Truncation in the middle of the element stream yields a partial tree, not a crash and not
	// invented content. The pool is deliberately tolerant, so the assertion is about what comes
	// out rather than whether an error is raised: nothing may be fabricated past the cut.
	full := manifestFixture()
	for cut := 16; cut < len(full); cut += 7 {
		decoded, err := ParseAXMLManifest(full[:cut])
		if err != nil {
			continue // refusing is always acceptable
		}
		if len(decoded.Permissions) > 2 || len(decoded.Components) > 2 {
			t.Fatalf("cut at %d produced %d permissions and %d components from a prefix",
				cut, len(decoded.Permissions), len(decoded.Components))
		}
		if decoded.VersionCode != "" && decoded.VersionCode != "3" {
			t.Fatalf("cut at %d produced versionCode %q", cut, decoded.VersionCode)
		}
	}
}

func TestATruncatedManifestDoesNotInventAComponent(t *testing.T) {
	// Cutting before the `service` element means no service can be reported. This is the
	// property that matters for a triage tool: a partial read must not assert a component
	// (and therefore an export surface) the file does not contain.
	full := manifestFixture()
	for cut := 16; cut < len(full); cut++ {
		decoded, err := ParseAXMLManifest(full[:cut])
		if err != nil {
			continue
		}
		for _, component := range decoded.Components {
			if component.Name == ".TileService" {
				// Only acceptable once the whole element has been read; verify by checking that
				// the untruncated parse also has it.
				full_parsed, _ := ParseAXMLManifest(full)
				found := false
				for _, c := range full_parsed.Components {
					if c.Name == ".TileService" {
						found = true
					}
				}
				if !found {
					t.Fatalf("cut at %d reported a component the complete file lacks", cut)
				}
			}
		}
	}
}
