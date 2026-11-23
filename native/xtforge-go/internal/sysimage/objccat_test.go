package sysimage

import (
	"encoding/binary"
	"os"
	"testing"
)

// Category and protocol tests.
//
// The fixture is a minimal 64-bit Mach-O built in memory: a class, a category
// with an instance and a class method, a category whose class pointer is
// invalid, two protocol declarations, and a function-start table so naming can
// be checked end to end.

const (
	catTextAddr = 0x100000000
	catClassAt  = 0x100003000
	catRoAt     = 0x100003050
	catCatAt    = 0x100003100
	catBrokenAt = 0x100003140
	catProtoAt  = 0x100003400
)

// objcCategoryFixture builds the fixture; catlistSize is the declared section
// size, so a short size models a truncated __objc_catlist.
func objcCategoryFixture(catlistSize uint64) []byte {
	const (
		textAddr       = uint64(catTextAddr)
		classlistAt    = textAddr + 0x2000
		catlistAt      = textAddr + 0x2100
		protolistAt    = textAddr + 0x2200
		classNameAt    = textAddr + 0x500
		categoryAt     = textAddr + 0x540
		brokenNameAt   = textAddr + 0x560
		proto1NameAt   = textAddr + 0x600
		proto2NameAt   = textAddr + 0x620
		instanceSelAt  = textAddr + 0x700
		classSelAt     = textAddr + 0x720
		baseSelAt      = textAddr + 0x760
		typesAt        = textAddr + 0x780
		instanceImplAt = textAddr + 0x800
		classImplAt    = textAddr + 0x900
		baseMethodsAt  = textAddr + 0x3200
		instMethodsAt  = textAddr + 0x3300
		clsMethodsAt   = textAddr + 0x3280
		protoListAt    = textAddr + 0x3340
		proto2At       = textAddr + 0x3440
		startsAt       = 0x3600
	)
	data := make([]byte, 0x3800)
	put32 := func(offset int, value uint32) { binary.LittleEndian.PutUint32(data[offset:], value) }
	put64 := func(offset int, value uint64) { binary.LittleEndian.PutUint64(data[offset:], value) }
	fileOff := func(address uint64) int { return int(address - textAddr) }
	relative := func(from, to uint64) uint32 { return uint32(int32(int64(to) - int64(from))) }

	const (
		segmentCommandSize = 72
		sectionSize        = 80
		sectionCount       = 5
	)
	copy(data, []byte{0xcf, 0xfa, 0xed, 0xfe})
	put32(4, 0x0100000c) // CPU_TYPE_X86_64
	put32(12, 2)         // MH_EXECUTE
	put32(16, 2)         // segment + LC_FUNCTION_STARTS
	put32(20, segmentCommandSize+sectionCount*sectionSize+16)
	put32(24, 0)

	const segmentAt = 32
	put32(segmentAt, 0x19) // LC_SEGMENT_64
	put32(segmentAt+4, segmentCommandSize+sectionCount*sectionSize)
	copy(data[segmentAt+8:], "__TEXT")
	put64(segmentAt+24, textAddr)
	put64(segmentAt+32, uint64(len(data)))
	put64(segmentAt+40, 0)
	put64(segmentAt+48, uint64(len(data)))
	put32(segmentAt+64, sectionCount)

	type section struct {
		name    string
		address uint64
		size    uint64
	}
	sections := []section{
		{"__objc_classlist", classlistAt, 8},
		{"__objc_catlist", catlistAt, catlistSize},
		{"__objc_protolist", protolistAt, 16},
		{"__objc_data", textAddr + 0x3000, 40},
		{"__objc_const", textAddr + 0x3050, 64},
	}
	for index, entry := range sections {
		base := segmentAt + segmentCommandSize + index*sectionSize
		copy(data[base:], entry.name)
		copy(data[base+16:], "__TEXT")
		put64(base+32, entry.address)
		put64(base+40, entry.size)
		put32(base+48, uint32(entry.address-textAddr))
		put32(base+52, 2)
	}

	// Function starts so applyObjC has real function entries to name.
	startsAtCommand := segmentAt + segmentCommandSize + sectionCount*sectionSize
	put32(startsAtCommand, 0x26) // LC_FUNCTION_STARTS
	put32(startsAtCommand+4, 16)
	put32(startsAtCommand+8, startsAt)
	starts := []byte{0x80, 0x10, 0x80, 0x02, 0x00} // 0x800, 0x100, terminator
	put32(startsAtCommand+12, uint32(len(starts)))
	copy(data[startsAt:], starts)

	// Class and its base method list (unchanged by category recovery).
	put64(fileOff(classlistAt), catClassAt)
	put64(fileOff(catClassAt)+32, catRoAt|0x2)
	put64(fileOff(catRoAt)+24, classNameAt)
	put64(fileOff(catRoAt)+32, baseMethodsAt)
	copy(data[fileOff(classNameAt):], "FixtureClass\x00")
	put32(fileOff(baseMethodsAt), 0)
	put32(fileOff(baseMethodsAt)+4, 1)
	put64(fileOff(baseMethodsAt)+8, baseSelAt)
	copy(data[fileOff(baseSelAt):], "baseThing:\x00")

	// Category with an instance method (absolute list) and a class method
	// (relative list), exercising both method-list forms.
	put64(fileOff(catlistAt), catCatAt)
	put64(fileOff(catCatAt), categoryAt)
	put64(fileOff(catCatAt)+8, catClassAt)
	put64(fileOff(catCatAt)+16, instMethodsAt)
	put64(fileOff(catCatAt)+24, clsMethodsAt)
	put64(fileOff(catCatAt)+32, protoListAt)
	copy(data[fileOff(categoryAt):], "Utilities\x00")

	put32(fileOff(instMethodsAt), 0)
	put32(fileOff(instMethodsAt)+4, 1)
	put64(fileOff(instMethodsAt)+8, instanceSelAt)
	put64(fileOff(instMethodsAt)+16, typesAt)
	put64(fileOff(instMethodsAt)+24, instanceImplAt)
	copy(data[fileOff(instanceSelAt):], "instanceThing:\x00")
	copy(data[fileOff(typesAt):], "v16@0:8\x00")

	entry := clsMethodsAt + 8
	put32(fileOff(clsMethodsAt), 0x80000000)
	put32(fileOff(clsMethodsAt)+4, 1)
	put32(fileOff(entry), relative(entry, classSelAt))
	put32(fileOff(entry)+4, relative(entry+4, typesAt))
	put32(fileOff(entry)+8, relative(entry+8, classImplAt))
	copy(data[fileOff(classSelAt):], "classThing:\x00")

	// A second category with an unmapped class pointer must be skipped.
	put64(fileOff(catlistAt)+8, catBrokenAt)
	put64(fileOff(catBrokenAt), brokenNameAt)
	put64(fileOff(catBrokenAt)+8, 0xdeadbeefdeadbeef)
	put64(fileOff(catBrokenAt)+16, instMethodsAt)
	copy(data[fileOff(brokenNameAt):], "Broken\x00")

	// Protocol declarations: one via a category's protocol_list_t, one via
	// __objc_protolist.
	put64(fileOff(protoListAt), 1)
	put64(fileOff(protoListAt)+8, catProtoAt)
	put64(fileOff(catProtoAt)+8, proto1NameAt)
	put64(fileOff(proto2At)+8, proto2NameAt)
	put64(fileOff(protolistAt), catProtoAt)
	put64(fileOff(protolistAt)+8, proto2At)
	copy(data[fileOff(proto1NameAt):], "NSCopying\x00")
	copy(data[fileOff(proto2NameAt):], "FixtureDelegate\x00")
	return data
}

func writeObjCCategoryFixture(t *testing.T, catlistSize uint64) string {
	t.Helper()
	path := t.TempDir() + "/Categories"
	if err := os.WriteFile(path, objcCategoryFixture(catlistSize), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestObjCCategoriesAndProtocols(t *testing.T) {
	res, err := Functions(writeObjCCategoryFixture(t, 16), "", "", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Images) != 1 {
		t.Fatalf("images = %d", len(res.Images))
	}
	meta := res.Images[0].ObjC
	if meta == nil {
		t.Fatal("no Objective-C metadata recovered")
	}
	// Existing class output is unchanged.
	if len(meta.Classes) != 1 || meta.Classes[0].Name != "FixtureClass" {
		t.Fatalf("classes = %+v", meta.Classes)
	}
	if len(meta.Classes[0].Methods) != 1 || meta.Classes[0].Methods[0].Name != "baseThing:" {
		t.Fatalf("class methods = %+v", meta.Classes[0].Methods)
	}
	if len(meta.Categories) != 1 {
		t.Fatalf("categories = %d, want 1 (invalid class pointer must be skipped)", len(meta.Categories))
	}
	category := meta.Categories[0]
	if category.Name != "Utilities" || category.Class != "FixtureClass" {
		t.Fatalf("category = %+v", category)
	}
	if len(category.Methods) != 2 {
		t.Fatalf("category methods = %d, want 2", len(category.Methods))
	}
	if category.Methods[0].Name != "instanceThing:" || category.Methods[0].classMethod {
		t.Fatalf("instance method = %+v", category.Methods[0])
	}
	if category.Methods[1].Name != "classThing:" || !category.Methods[1].classMethod {
		t.Fatalf("class method = %+v", category.Methods[1])
	}
	wantProtocols := map[string]bool{"NSCopying": false, "FixtureDelegate": false}
	for _, name := range meta.Protocols {
		if _, known := wantProtocols[name]; known {
			wantProtocols[name] = true
		}
	}
	for name, found := range wantProtocols {
		if !found {
			t.Errorf("protocol %q not recovered from %v", name, meta.Protocols)
		}
	}

	names := map[uint64]string{}
	for _, fn := range res.Images[0].Functions {
		names[fn.Address] = fn.Name
	}
	want := map[uint64]string{
		catTextAddr + 0x800: "-[FixtureClass(Utilities) instanceThing:]",
		catTextAddr + 0x900: "+[FixtureClass(Utilities) classThing:]",
	}
	for address, name := range want {
		if names[address] != name {
			t.Errorf("function %#x named %q, want %q", address, names[address], name)
		}
	}
	if meta.Named != len(want) {
		t.Errorf("named = %d, want %d", meta.Named, len(want))
	}
}

func TestObjCTruncatedCatlistDoesNotPanic(t *testing.T) {
	for _, tc := range []struct {
		name string
		size uint64
	}{
		{"partial pointer", 4},
		{"one full entry plus trailing bytes", 12},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res, err := Functions(writeObjCCategoryFixture(t, tc.size), "", "", 0)
			if err != nil {
				t.Fatal(err)
			}
			meta := res.Images[0].ObjC
			if meta == nil {
				return
			}
			if len(meta.Categories) > 1 {
				t.Fatalf("categories = %d, want at most 1", len(meta.Categories))
			}
		})
	}
}
