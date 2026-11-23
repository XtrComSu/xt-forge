package sysimage

import (
	"debug/macho"
	"io"
	"math"
)

// Objective-C categories and protocol declarations.
//
// Categories are a second method-list source: a class's own class_ro_t lists
// only its base methods, while every category contributes instance and class
// methods of its own. Ignoring __objc_catlist therefore loses a large share of
// the method names in a typical Apple binary. Protocol declarations are read
// for reporting: their names are metadata, not function names.

const (
	maxCategories = 4096
	maxProtocols  = 4096
	// The 64-bit category_t fields used here: name, cls, instanceMethods,
	// classMethods, protocols, instanceProperties.
	categoryWords = 6
)

// byteOrder is the subset of binary.ByteOrder the metadata readers need.
type byteOrder interface {
	Uint64([]byte) uint64
	Uint32([]byte) uint32
}

// readObjCCategories follows catlist pointer → category_t → method lists.
//
// A category's class pointer is resolved against the classes recovered from
// __objc_classlist first, then by following the class_t to its name. A null
// class pointer leaves the category name as the qualifier. A non-null pointer
// that cannot be read at all is invalid metadata: that category is skipped
// rather than used to invent a class name.
func readObjCCategories(image *Image, r io.ReaderAt, file *macho.File, sections [][]byte, classNames map[uint64]string, protocols *[]string) []objcCategory {
	word := image.Bits / 8
	if word == 0 || file.ByteOrder == nil {
		return nil
	}
	order := file.ByteOrder
	var categories []objcCategory
	for _, data := range sections {
		for offset := 0; offset+word <= len(data); offset += word {
			pointer, ok := readWord(data[offset:], order, image.Bits)
			if !ok || pointer == 0 {
				continue
			}
			raw, ok := image.readAddress(r, pointer, categoryWords*word)
			if !ok {
				continue
			}
			nameAddress, ok := readWord(raw[0:], order, image.Bits)
			if !ok {
				continue
			}
			name, ok := image.readCString(r, nameAddress, 512)
			if !ok || !plausibleClassName(name) {
				continue
			}
			classPointer, ok := readWord(raw[word:], order, image.Bits)
			if !ok {
				continue
			}
			class, ok := categoryClassName(image, r, order, classPointer, classNames, name)
			if !ok {
				continue
			}
			category := objcCategory{Name: name, Class: class}
			addMethods := func(address uint64, isClassMethod bool) {
				for _, method := range image.readMethodEntry(r, address, order) {
					method.classMethod = isClassMethod
					category.Methods = append(category.Methods, method)
					if len(category.Methods) >= maxCategories {
						return
					}
				}
			}
			if address, ok := readWord(raw[2*word:], order, image.Bits); ok && address != 0 {
				addMethods(address, false)
			}
			if address, ok := readWord(raw[3*word:], order, image.Bits); ok && address != 0 {
				addMethods(address, true)
			}
			if address, ok := readWord(raw[4*word:], order, image.Bits); ok && address != 0 {
				image.readProtocolList(r, address, order, protocols)
			}
			categories = append(categories, category)
			if len(categories) >= maxCategories {
				return categories
			}
		}
	}
	return categories
}

// categoryClassName resolves a category's cls pointer to a class name.
// ok == false means the pointer itself is unusable and the category is skipped.
func categoryClassName(image *Image, r io.ReaderAt, order byteOrder, pointer uint64, classNames map[uint64]string, fallback string) (string, bool) {
	if pointer == 0 {
		return fallback, true
	}
	if name, known := classNames[pointer]; known && name != "" {
		return name, true
	}
	word := image.Bits / 8
	raw, ok := image.readAddress(r, pointer, 5*word)
	if !ok {
		return "", false
	}
	roPointer, ok := readWord(raw[4*word:], order, image.Bits)
	if !ok {
		return fallback, true
	}
	ro, ok := image.readAddress(r, roPointer&^uint64(0x7), 5*word)
	if !ok {
		return fallback, true
	}
	nameAddress, ok := readWord(ro[3*word:], order, image.Bits)
	if !ok {
		return fallback, true
	}
	name, ok := image.readCString(r, nameAddress, 512)
	if !ok || !plausibleClassName(name) {
		return fallback, true
	}
	return name, true
}

// readObjCProtocolSection reads __objc_protolist, an array of protocol_t
// pointers (not a protocol_list_t). Only protocol names are recovered.
func readObjCProtocolSection(image *Image, r io.ReaderAt, file *macho.File, sections [][]byte) []string {
	word := image.Bits / 8
	if word == 0 || file.ByteOrder == nil {
		return nil
	}
	var names []string
	for _, data := range sections {
		for offset := 0; offset+word <= len(data); offset += word {
			pointer, ok := readWord(data[offset:], file.ByteOrder, image.Bits)
			if !ok || pointer == 0 {
				continue
			}
			if name := image.readProtocolName(r, pointer, file.ByteOrder); name != "" {
				names = append(names, name)
				if len(names) >= maxProtocols {
					return names
				}
			}
		}
	}
	return names
}

// readObjCClassProtocols reads the baseProtocols protocol_list_t of each
// recovered class. Class fields are untouched; these names are additive.
func readObjCClassProtocols(image *Image, r io.ReaderAt, file *macho.File, classes []objcClass, protocols *[]string) {
	word := image.Bits / 8
	if word == 0 || file.ByteOrder == nil || protocols == nil {
		return
	}
	for _, class := range classes {
		raw, ok := image.readAddress(r, class.Address, 5*word)
		if !ok {
			continue
		}
		roPointer, ok := readWord(raw[4*word:], file.ByteOrder, image.Bits)
		if !ok {
			continue
		}
		ro, ok := image.readAddress(r, roPointer&^uint64(0x7), 5*word)
		if !ok {
			continue
		}
		base, ok := readWord(ro[4*word:], file.ByteOrder, image.Bits)
		if ok && base != 0 {
			image.readProtocolList(r, base, file.ByteOrder, protocols)
		}
	}
}

// readProtocolList reads { uintptr_t count; protocol_t *list[count]; }.
func (image *Image) readProtocolList(r io.ReaderAt, address uint64, order byteOrder, names *[]string) {
	word := uint64(image.Bits / 8)
	if word == 0 || address == 0 || names == nil {
		return
	}
	raw, ok := image.readAddress(r, address, int(word))
	if !ok {
		return
	}
	count, ok := readWord(raw, order, image.Bits)
	if !ok || count == 0 || count > maxProtocols {
		return
	}
	entry := address + word
	if entry < address {
		return
	}
	for index := uint64(0); index < count && index < maxProtocols; index++ {
		raw, ok := image.readAddress(r, entry, int(word))
		if !ok {
			break
		}
		pointer, ok := readWord(raw, order, image.Bits)
		if ok && pointer != 0 {
			if name := image.readProtocolName(r, pointer, order); name != "" {
				*names = append(*names, name)
			}
		}
		if entry > math.MaxUint64-word {
			break
		}
		entry += word
	}
}

// readProtocolName reads the name of a protocol_t, whose isa occupies the
// first word and whose name pointer the second on 64-bit images.
func (image *Image) readProtocolName(r io.ReaderAt, address uint64, order byteOrder) string {
	word := image.Bits / 8
	if word == 0 || address == 0 {
		return ""
	}
	raw, ok := image.readAddress(r, address, 2*word)
	if !ok {
		return ""
	}
	nameAddress, ok := readWord(raw[word:], order, image.Bits)
	if !ok {
		return ""
	}
	name, ok := image.readCString(r, nameAddress, 512)
	if !ok || !plausibleClassName(name) {
		return ""
	}
	return name
}
