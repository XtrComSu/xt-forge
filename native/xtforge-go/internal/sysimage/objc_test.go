package sysimage

import (
	"encoding/binary"
	"os"
	"testing"
)

// Objective-C metadata tests.
//
// The unit fixtures below are built in memory so the tests are exact and run
// everywhere. A real binary is also checked when one is available, because
// in-memory fixtures only prove the reader agrees with my own understanding of
// the format — the real sample is what proves it agrees with Apple's.

// objcFixture builds a minimal 64-bit Mach-O containing __objc_classlist,
// __objc_const, and __objc_methname, with one class and one method.
func objcFixture(relative bool) []byte {
	const (
		textAddr    = 0x100000000
		classlistAt = 0x100002000
		dataAt      = 0x100003000
		constAt     = 0x100003050
		nameAt      = 0x100000500
		methNameAt  = 0x100000720
	)
	// __objc_classlist lives at file offset 0x2000 and __objc_data at 0x3000, so
	// the file must span both; the __TEXT strings sit near the front.
	data := make([]byte, 0x3400)
	put32 := func(offset int, value uint32) { binary.LittleEndian.PutUint32(data[offset:], value) }
	put64 := func(offset int, value uint64) { binary.LittleEndian.PutUint64(data[offset:], value) }

	const (
		segmentCommandSize = 72
		sectionSize        = 80
		sectionCount       = 3
	)
	// Mach-O header.
	copy(data, []byte{0xcf, 0xfa, 0xed, 0xfe})
	put32(4, 0x0100000c) // CPU_TYPE_X86_64
	put32(12, 2)         // MH_EXECUTE
	put32(16, 1)         // one load command
	put32(20, segmentCommandSize+sectionCount*sectionSize)
	put32(24, 0) // no flags

	// One __TEXT segment carrying three sections.
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
		offset  uint64
	}
	sections := []section{
		{"__objc_classlist", classlistAt, 8, classlistAt - textAddr},
		{"__objc_data", dataAt, 40, dataAt - textAddr},
		{"__objc_const", constAt, 56, constAt - textAddr},
	}
	for index, entry := range sections {
		base := segmentAt + segmentCommandSize + index*sectionSize
		copy(data[base:], entry.name)
		copy(data[base+16:], "__TEXT")
		put64(base+32, entry.address)
		put64(base+40, entry.size)
		put32(base+48, uint32(entry.offset))
		put32(base+52, 2) // S_ZEROFILL-free: alignment 2
	}

	// classlist → class_t
	put64(int(classlistAt-textAddr), dataAt)
	// class_t.data → class_ro_t, with runtime flag bits set on purpose.
	put64(int(dataAt-textAddr)+32, constAt|0x2)
	// class_ro_t: name at +24, baseMethods at +32.
	put64(int(constAt-textAddr)+24, nameAt)
	put64(int(constAt-textAddr)+32, methNameAt)
	copy(data[int(nameAt-textAddr):], "FixtureClass\x00")

	flags := uint32(0)
	if relative {
		flags = 0x80000000
	}
	put32(int(methNameAt-textAddr), flags)
	put32(int(methNameAt-textAddr)+4, 1)
	entry := int(methNameAt-textAddr) + 8
	selectorAt := int(methNameAt-textAddr) + 0x40
	copy(data[selectorAt:], "doThing:\x00")
	if relative {
		// A relative entry is three 32-bit displacements, each measured from its
		// own field, and the selector field points at a selref slot rather than
		// at the string. Both quirks are reproduced here because both were bugs.
		selRef := selectorAt + 0x100
		put64(selRef, uint64(textAddr)+uint64(selectorAt))
		put32(entry, uint32(int32(selRef-entry)))
		put32(entry+4, uint32(int32(selectorAt+8-(entry+4))))
		put32(entry+8, 0)
	} else {
		put64(entry, uint64(textAddr)+uint64(selectorAt))
		put64(entry+8, uint64(textAddr)+uint64(selectorAt+8))
		put64(entry+16, 0)
	}
	return data
}

func TestObjCReadsClassAndMethod(t *testing.T) {
	for _, tc := range []struct {
		name     string
		relative bool
	}{
		{"absolute", false},
		{"relative", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := dir + "/Fixture"
			if err := os.WriteFile(path, objcFixture(tc.relative), 0600); err != nil {
				t.Fatal(err)
			}
			res, err := Functions(path, "", "", 0)
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
			if len(meta.Classes) != 1 {
				t.Fatalf("classes = %d, want 1", len(meta.Classes))
			}
			class := meta.Classes[0]
			if class.Name != "FixtureClass" {
				t.Fatalf("class name = %q", class.Name)
			}
			if len(class.Methods) != 1 {
				t.Fatalf("methods = %d, want 1", len(class.Methods))
			}
			if class.Methods[0].Name != "doThing:" {
				t.Fatalf("selector = %q", class.Methods[0].Name)
			}
		})
	}
}

func TestObjCRejectsGarbageWithoutPanicking(t *testing.T) {
	// A classlist whose pointers point nowhere must be skipped, not followed.
	data := objcFixture(false)
	for offset := 0; offset < 8; offset++ {
		data[0x2000+offset] = 0xff
	}
	dir := t.TempDir()
	path := dir + "/Broken"
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	res, err := Functions(path, "", "", 0)
	if err != nil {
		t.Fatalf("malformed metadata should not fail the analysis: %v", err)
	}
	if meta := res.Images[0].ObjC; meta != nil && len(meta.Classes) != 0 {
		t.Fatalf("recovered %d classes from garbage", len(meta.Classes))
	}
}

// TestObjCRealAppleBinary checks the reader against a real Apple binary. It is
// the only test that can catch a misreading of Apple's actual layout, since the
// fixtures above encode my understanding of the format.
func TestObjCRealAppleBinary(t *testing.T) {
	path := os.Getenv("XTF_REAL_MACHO")
	if path == "" {
		t.Skip("set XTF_REAL_MACHO to a real Mach-O to run this test")
	}
	res, err := Functions(path, "", "", 0)
	if err != nil {
		t.Fatal(err)
	}
	total, named := 0, 0
	for _, image := range res.Images {
		if image.ObjC == nil {
			continue
		}
		total += len(image.ObjC.Classes)
		named += image.ObjC.Named
		for _, class := range image.ObjC.Classes {
			if class.Name == "" {
				t.Errorf("%s: class with empty name", image.Arch)
			}
			for _, method := range class.Methods {
				if method.Name == "" {
					t.Errorf("%s: %s method with empty selector", image.Arch, class.Name)
				}
			}
		}
	}
	if total == 0 {
		t.Fatalf("no classes recovered from %s", path)
	}
	t.Logf("recovered %d classes, named %d functions", total, named)
}
