package sysimage

import (
	"debug/macho"
	"fmt"
	"io"
	"strings"
)

// Objective-C metadata recovery.
//
// A stripped Apple binary still names its methods: the class list, method lists,
// and selector strings survive because the runtime needs them. On a Swift app
// the Objective-C metadata is also the only place many method names exist at
// all, since Swift @objc thunks and protocol conformances are recorded there.
//
// This reads the metadata to do one thing: give recovered code addresses real
// names. It is not a class-dump; it recovers what naming needs, and reports the
// rest so the shapes are inspectable.

const (
	sectionObjCClassList    = "__objc_classlist"
	sectionObjCCategoryList = "__objc_catlist"
	sectionObjCProtocolList = "__objc_protolist"
	sectionObjCData         = "__objc_data"
	sectionMethodName       = "__objc_methname"
)

// objcClass is one recovered class.
type objcClass struct {
	Name    string       `json:"name"`
	Address uint64       `json:"address"`
	Methods []objcMethod `json:"methods,omitempty"`
}

// objcMethod is one recovered method.
type objcMethod struct {
	Name string `json:"name"`
	// Types is the Objective-C type encoding, e.g. "v40@0:8@16@24@32".
	Types string `json:"types,omitempty"`
	// Implementation is the method's code address, when the method list
	// carries one. Relative method lists store it as an offset.
	Implementation uint64 `json:"implementation,omitempty"`
	// classMethod distinguishes a category's class (+) methods from its
	// instance (-) methods. It is internal: the selector text is unchanged.
	classMethod bool
}

// objcCategory is one recovered category and the methods it adds to a class.
type objcCategory struct {
	Name    string       `json:"name"`
	Class   string       `json:"class"`
	Methods []objcMethod `json:"methods,omitempty"`
}

// objcMetadata is everything recovered from one image.
type objcMetadata struct {
	Classes    []objcClass    `json:"classes"`
	Categories []objcCategory `json:"categories,omitempty"`
	Protocols  []string       `json:"protocols,omitempty"`
	Selectors  []string       `json:"selectors,omitempty"`
	// Named counts how many code addresses the metadata named.
	Named int `json:"named"`
}

// readObjC recovers Objective-C metadata from a Mach-O image.
//
// Every read is bounds-checked through the image's own section map rather than
// by computing file offsets directly, so a malformed or hostile binary fails
// cleanly instead of reading out of bounds.
func readObjC(image *Image, r io.ReaderAt, file *macho.File) *objcMetadata {
	if file == nil || file.ByteOrder == nil || image.Bits/8 == 0 {
		return nil
	}
	classes := make([]objcClass, 0, 4096)
	classAddresses := map[uint64]string{}
	for _, entry := range machoSection(file, sectionObjCClassList) {
		for _, class := range readObjCClasses(image, r, file, entry) {
			classAddresses[class.Address] = class.Name
			classes = append(classes, class)
			if len(classes) >= 4096 {
				break
			}
		}
		if len(classes) >= 4096 {
			break
		}
	}
	var protocols []string
	protocols = append(protocols, readObjCProtocolSection(image, r, file, machoSection(file, sectionObjCProtocolList))...)
	readObjCClassProtocols(image, r, file, classes, &protocols)
	categories := readObjCCategories(image, r, file, machoSection(file, sectionObjCCategoryList), classAddresses, &protocols)
	if len(classes) == 0 && len(categories) == 0 && len(protocols) == 0 {
		return nil
	}
	meta := &objcMetadata{Classes: classes, Categories: categories, Protocols: dedupeStrings(protocols)}
	seen := map[string]bool{}
	for _, class := range classes {
		for _, method := range class.Methods {
			if method.Name != "" && !seen[method.Name] {
				seen[method.Name] = true
				meta.Selectors = append(meta.Selectors, method.Name)
			}
		}
	}
	for _, category := range categories {
		for _, method := range category.Methods {
			if method.Name != "" && !seen[method.Name] {
				seen[method.Name] = true
				meta.Selectors = append(meta.Selectors, method.Name)
			}
		}
	}
	return meta
}

// dedupeStrings keeps the first occurrence of each name, preserving order.
func dedupeStrings(names []string) []string {
	seen := make(map[string]bool, len(names))
	out := make([]string, 0, len(names))
	for _, name := range names {
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		out = append(out, name)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// machoSection returns the contents of every section with this name.
func machoSection(file *macho.File, name string) [][]byte {
	var contents [][]byte
	for _, section := range file.Sections {
		if section.Name != name {
			continue
		}
		data, err := section.Data()
		if err != nil || len(data) == 0 {
			continue
		}
		contents = append(contents, data)
	}
	return contents
}

// readObjCClasses follows classlist pointer → class_t → class_ro_t → methods.
//
// Layout (64-bit, as recorded in objc runtime sources):
//
//	class_t    { isa, superclass, cache, vtable, data }        // 40 bytes
//	class_ro_t { flags(4), instanceStart(4), instanceSize(4), reserved(4),
//	             ivarLayout, name, baseMethods, baseProtocols, ... }
//
// Two mistakes are easy to make here and both produce plausible garbage rather
// than an error. The low bits of a class_ro_t pointer carry runtime flags, so it
// must be masked before use. And because class_ro_t begins with four 32-bit
// words, name lands at byte 24 and baseMethods at byte 32 — not at the 40 and 48
// a naive "seven pointers" reading gives.
func readObjCClasses(image *Image, r io.ReaderAt, file *macho.File, data []byte) []objcClass {
	order := file.ByteOrder
	word := image.Bits / 8
	if word == 0 || len(data) < word {
		return nil
	}
	var classes []objcClass
	// __objc_classlist holds an array of *pointers* to class_t, not inline
	// structures. Reading the section itself as a class_t — which a first
	// version did — silently yields fields belonging to the wrong objects.
	for offset := 0; offset+word <= len(data); offset += word {
		classPointer, ok := readWord(data[offset:], order, image.Bits)
		if !ok || classPointer == 0 {
			continue
		}
		classStruct, ok := image.readAddress(r, classPointer, 5*word)
		if !ok {
			continue
		}
		roPointer, ok := readWord(classStruct[4*word:], order, image.Bits)
		if !ok {
			continue
		}
		roPointer &^= 0x7
		ro, ok := image.readAddress(r, roPointer, 5*word)
		if !ok {
			continue
		}
		nameAddress, ok := readWord(ro[3*word:], order, image.Bits)
		if !ok {
			continue
		}
		name, ok := image.readCString(r, nameAddress, 512)
		if !ok || !plausibleClassName(name) {
			continue
		}
		class := objcClass{Name: name, Address: classPointer}
		if methodsAddress, ok := readWord(ro[4*word:], order, image.Bits); ok && methodsAddress != 0 {
			class.Methods = image.readMethodEntry(r, methodsAddress, order)
		}
		classes = append(classes, class)
		if len(classes) >= 4096 {
			break
		}
	}
	return classes
}

// readMethodEntry reads what baseMethods points at.
//
// class_ro_t.baseMethods is a *single* method_list_t, not an array of list
// pointers. Treating it as an array — walking it as a null-terminated pointer
// table — produced a bogus address (0x500000018, the concatenation of the flags
// and count words) and zero methods. A list that does not decode is retried as a
// method_array_t, which is what categories and some newer builds use.
func (image *Image) readMethodEntry(r io.ReaderAt, address uint64, order interface {
	Uint64([]byte) uint64
	Uint32([]byte) uint32
}) []objcMethod {
	if methods := image.readMethodList(r, address, order); len(methods) > 0 {
		return methods
	}
	var methods []objcMethod
	entry := uint64(image.Bits / 8)
	for index := 0; index < 16; index++ {
		raw, ok := image.readAddress(r, address+uint64(index)*entry, image.Bits/8)
		if !ok {
			break
		}
		listAddress, ok := readWord(raw, order, image.Bits)
		if !ok || listAddress == 0 {
			break
		}
		methods = append(methods, image.readMethodList(r, listAddress, order)...)
		if len(methods) > 4096 {
			break
		}
	}
	return methods
}

// readMethodList decodes one method_list_t.
//
// The high bit of the flags word means the list uses *relative* offsets, a
// pointer-free form Apple introduced to save relocations. The entry size follows
// from that, not from the flags in general: a relative list is 12 bytes per
// entry (three 32-bit relative offsets), a classic list is 24 on 64-bit (three
// pointers). Getting this backwards reads plausible-looking garbage.
func (image *Image) readMethodList(r io.ReaderAt, address uint64, order interface {
	Uint64([]byte) uint64
	Uint32([]byte) uint32
}) []objcMethod {
	header, ok := image.readAddress(r, address, 8)
	if !ok {
		return nil
	}
	flags := order.Uint32(header[0:4])
	count := order.Uint32(header[4:8])
	if count > 4096 {
		return nil
	}
	relative := flags&0x80000000 != 0
	entrySize := uint64(24)
	if relative {
		entrySize = 12
	}
	base := address + 8
	var methods []objcMethod
	for i := uint32(0); i < count; i++ {
		entryAddress := base + uint64(i)*entrySize
		raw, ok := image.readAddress(r, entryAddress, int(entrySize))
		if !ok {
			break
		}
		var method objcMethod
		if relative {
			selDelta := int32(order.Uint32(raw[0:4]))
			typeDelta := int32(order.Uint32(raw[4:8]))
			implDelta := int32(order.Uint32(raw[8:12]))
			method.Name = image.readSelector(r, uint64(int64(entryAddress)+int64(selDelta)), order)
			method.Types, _ = image.readCString(r, uint64(int64(entryAddress+4)+int64(typeDelta)), 512)
			if implDelta != 0 {
				method.Implementation = uint64(int64(entryAddress+8) + int64(implDelta))
			}
		} else {
			selAddress, _ := readWord(raw[0:], order, image.Bits)
			typeAddress, _ := readWord(raw[8:], order, image.Bits)
			implAddress, _ := readWord(raw[16:], order, image.Bits)
			method.Name = image.readSelector(r, selAddress, order)
			method.Types, _ = image.readCString(r, typeAddress, 512)
			method.Implementation = implAddress
		}
		if method.Name == "" {
			continue
		}
		methods = append(methods, method)
	}
	return methods
}

// readSelector resolves a method's selector name.
//
// In a relative method list the name field is an offset to a *selector
// reference* — a pointer slot — rather than to the string itself, so resolving
// it needs one extra hop. Rather than guess which form a given build used,
// this tries the address as a string first and dereferences it as a pointer
// only when the bytes there are not a plausible selector. Both forms occur in
// shipped binaries.
func (image *Image) readSelector(r io.ReaderAt, address uint64, order interface {
	Uint64([]byte) uint64
	Uint32([]byte) uint32
}) string {
	if name, ok := image.readCString(r, address, 1024); ok && plausibleSelector(name) {
		return name
	}
	raw, ok := image.readAddress(r, address, image.Bits/8)
	if !ok {
		return ""
	}
	pointer, ok := readWord(raw, order, image.Bits)
	if !ok || pointer == 0 {
		return ""
	}
	if name, ok := image.readCString(r, pointer, 1024); ok && plausibleSelector(name) {
		return name
	}
	return ""
}

// plausibleSelector reports whether a string looks like an Objective-C selector:
// identifier characters plus the colons that separate arguments.
func plausibleSelector(name string) bool {
	if len(name) == 0 || len(name) > 1024 {
		return false
	}
	for _, char := range name {
		switch {
		case char >= 'a' && char <= 'z':
		case char >= 'A' && char <= 'Z':
		case char >= '0' && char <= '9':
		case char == '_' || char == ':' || char == '.':
		default:
			return false
		}
	}
	return true
}

// readAddress reads n bytes at a virtual address, using the image's section map
// so a bad pointer yields false instead of an out-of-bounds read.
func (image *Image) readAddress(r io.ReaderAt, address uint64, n int) ([]byte, bool) {
	offset, ok := image.fileRange(address, uint64(n))
	if !ok {
		return nil, false
	}
	buf := make([]byte, n)
	if _, err := r.ReadAt(buf, int64(offset)); err != nil {
		return nil, false
	}
	return buf, true
}

// readCString reads a NUL-terminated string, capped in length.
func (image *Image) readCString(r io.ReaderAt, address uint64, limit int) (string, bool) {
	if address == 0 {
		return "", false
	}
	const chunk = 64
	var out []byte
	for len(out) < limit {
		data, ok := image.readAddress(r, address+uint64(len(out)), chunk)
		if !ok {
			return "", false
		}
		if index := strings.IndexByte(string(data), 0); index >= 0 {
			out = append(out, data[:index]...)
			return string(out), true
		}
		out = append(out, data...)
	}
	return "", false
}

func readWord(data []byte, order interface {
	Uint64([]byte) uint64
	Uint32([]byte) uint32
}, bits int) (uint64, bool) {
	if bits == 64 {
		if len(data) < 8 {
			return 0, false
		}
		return order.Uint64(data), true
	}
	if len(data) < 4 {
		return 0, false
	}
	return uint64(order.Uint32(data)), true
}

// plausibleClassName rejects values that are structurally valid strings but
// cannot be class names, which is what a wrong pointer usually yields.
func plausibleClassName(name string) bool {
	if len(name) == 0 || len(name) > 512 {
		return false
	}
	for _, char := range name {
		switch {
		case char >= 'a' && char <= 'z':
		case char >= 'A' && char <= 'Z':
		case char >= '0' && char <= '9':
		case char == '_' || char == '.' || char == '$' || char == '-':
		default:
			return false
		}
	}
	return true
}

// applyObjC names code addresses from the recovered metadata.
//
// A method's implementation address is only used when a function already exists
// there. Inventing function starts from metadata would contradict the function
// index, which is derived from the binary's own tables.
func (image *Image) applyObjC(meta *objcMetadata, strip string) {
	if meta == nil {
		return
	}
	for _, class := range meta.Classes {
		for _, method := range class.Methods {
			if method.Implementation == 0 {
				continue
			}
			name := fmt.Sprintf("%s[%s %s]", strip, class.Name, method.Name)
			if _, exists := image.functions[method.Implementation]; !exists {
				continue
			}
			if image.nameFunction(method.Implementation, name, "objc_method") {
				meta.Named++
			}
		}
	}
	for _, category := range meta.Categories {
		qualifier := category.Class
		if qualifier == "" {
			qualifier = category.Name
		} else {
			qualifier += "(" + category.Name + ")"
		}
		for _, method := range category.Methods {
			if method.Implementation == 0 {
				continue
			}
			prefix := strip
			if method.classMethod {
				prefix = "+"
			}
			if prefix == "" {
				prefix = "-"
			}
			name := fmt.Sprintf("%s[%s %s]", prefix, qualifier, method.Name)
			if _, exists := image.functions[method.Implementation]; !exists {
				continue
			}
			if image.nameFunction(method.Implementation, name, "objc_method") {
				meta.Named++
			}
		}
	}
}
