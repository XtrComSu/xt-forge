// Android binary XML decoding.
//
// A manifest inside an APK is not text: it is a chunked binary format whose string pool is
// usually UTF-16LE and whose attribute values are *typed*. The previous implementation scraped
// the raw bytes for `android\.permission\.[A-Z0-9_]+` and reported every match.
//
// That over-reports. Measured on a real APK: the manifest declares four `uses-permission`
// elements, and the scraper returned five — because the string
// `android.permission.BIND_QUICK_SETTINGS_TILE` also appears as the value of a *service*
// attribute. A service's declared permission is a restriction the app imposes on callers; it is
// not a permission the app requests. Reporting it as requested is a false security claim.
//
// Decoding the format is the only way to answer "which permissions does this app request", and
// it is also the only way to get components, export flags, or any attribute typed as something
// other than a string.
package rehub

import (
	"encoding/binary"
	"fmt"
	"strings"
)

const (
	resStringPoolType   = 0x0001
	resXMLType          = 0x0003
	resXMLStartElement  = 0x0102
	resXMLEndElement    = 0x0103
	resXMLResourceMap   = 0x0180
	axmlNoIndex         = 0xFFFFFFFF
	axmlMaxBytes        = 32 * 1024 * 1024
	axmlMaxElements     = 100000
	axmlMaxDepth        = 256
)

// AXMLComponent is one declared component, with its resolved export state.
type AXMLComponent struct {
	Tag          string
	Name         string
	Exported     bool
	ExportedWhy  string
	Permission   string
	IntentFilter int
}

// AXMLManifest is the decoded summary of an AndroidManifest.xml.
type AXMLManifest struct {
	Package     string
	VersionCode string
	VersionName string
	Permissions []string
	Features    []string
	Components  []AXMLComponent
	MinSDK      string
	TargetSDK   string
	Elements    int
	Strings     int
}

type axmlReader struct {
	data []byte
}

func (r axmlReader) bounds(off, length int) error {
	if off < 0 || length < 0 || off+length > len(r.data) {
		return fmt.Errorf("read of %d byte(s) at %d runs past %d", length, off, len(r.data))
	}
	return nil
}

func (r axmlReader) u16(off int) (uint16, error) {
	if err := r.bounds(off, 2); err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint16(r.data[off:]), nil
}

func (r axmlReader) u32(off int) (uint32, error) {
	if err := r.bounds(off, 4); err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint32(r.data[off:]), nil
}

func (r axmlReader) u8(off int) (byte, error) {
	if err := r.bounds(off, 1); err != nil {
		return 0, err
	}
	return r.data[off], nil
}

type axmlAttr struct {
	Name   string
	Value  string
	Bool   bool
	IsBool bool
}

type axmlElement struct {
	Tag      string
	Attrs    []axmlAttr
	Children []*axmlElement
}

func (e *axmlElement) attr(name string) (axmlAttr, bool) {
	for _, a := range e.Attrs {
		if a.Name == name {
			return a, true
		}
	}
	return axmlAttr{}, false
}

// parseStringPool decodes a RES_STRING_POOL chunk. Both encodings occur in real APKs: UTF-16LE
// when flags bit 0x100 is clear, and a length-prefixed UTF-8 form when it is set.
func parseStringPool(r axmlReader, off int) ([]string, error) {
	headerSize, err := r.u16(off + 2)
	if err != nil {
		return nil, err
	}
	chunkSize, err := r.u32(off + 4)
	if err != nil {
		return nil, err
	}
	if headerSize < 28 || chunkSize < uint32(headerSize) {
		return nil, fmt.Errorf("string pool at %d has header %d chunk %d", off, headerSize, chunkSize)
	}
	count, err := r.u32(off + 8)
	if err != nil {
		return nil, err
	}
	flags, err := r.u32(off + 16)
	if err != nil {
		return nil, err
	}
	stringsStart, err := r.u32(off + 20)
	if err != nil {
		return nil, err
	}
	if count > 200000 {
		return nil, fmt.Errorf("string pool claims %d strings", count)
	}
	utf8 := flags&0x100 != 0
	base := off + int(stringsStart)
	offsetsAt := off + int(headerSize)

	out := make([]string, 0, count)
	for i := 0; i < int(count); i++ {
		rel, err := r.u32(offsetsAt + i*4)
		if err != nil {
			break
		}
		cursor := base + int(rel)
		var s string
		if utf8 {
			_, next, err := utf8Length(r, cursor)
			if err != nil {
				out = append(out, "")
				continue
			}
			byteLen, next2, err := utf8Length(r, next)
			if err != nil || r.bounds(next2, byteLen) != nil {
				out = append(out, "")
				continue
			}
			s = string(r.data[next2 : next2+byteLen])
		} else {
			chars, err := r.u16(cursor)
			if err != nil {
				out = append(out, "")
				continue
			}
			cursor += 2
			n := int(chars)
			if chars&0x8000 != 0 {
				low, err := r.u16(cursor)
				if err != nil {
					out = append(out, "")
					continue
				}
				cursor += 2
				n = int(chars&0x7FFF)<<16 | int(low)
			}
			if err := r.bounds(cursor, n*2); err != nil {
				out = append(out, "")
				continue
			}
			units := make([]uint16, n)
			for k := 0; k < n; k++ {
				units[k] = binary.LittleEndian.Uint16(r.data[cursor+k*2:])
			}
			s = decodeUTF16LE(units)
		}
		out = append(out, s)
	}
	return out, nil
}

func utf8Length(r axmlReader, at int) (int, int, error) {
	first, err := r.u8(at)
	if err != nil {
		return 0, at, err
	}
	if first&0x80 != 0 {
		second, err := r.u8(at + 1)
		if err != nil {
			return 0, at, err
		}
		return int(first&0x7F)<<8 | int(second), at + 2, nil
	}
	return int(first), at + 1, nil
}

// decodeUTF16LE converts UTF-16 code units to a Go string, pairing surrogates properly. Building
// the string byte-by-byte from ASCII would mangle any non-ASCII label, which manifests do carry.
func decodeUTF16LE(units []uint16) string {
	var sb strings.Builder
	for i := 0; i < len(units); i++ {
		u := units[i]
		if u >= 0xD800 && u <= 0xDBFF && i+1 < len(units) {
			low := units[i+1]
			if low >= 0xDC00 && low <= 0xDFFF {
				r := 0x10000 + (rune(u-0xD800) << 10) + rune(low-0xDC00)
				sb.WriteRune(r)
				i++
				continue
			}
		}
		sb.WriteRune(rune(u))
	}
	return sb.String()
}

// ParseAXMLManifest decodes a binary AndroidManifest.xml.
func ParseAXMLManifest(raw []byte) (*AXMLManifest, error) {
	if len(raw) > axmlMaxBytes {
		return nil, fmt.Errorf("manifest is %d bytes", len(raw))
	}
	r := axmlReader{data: raw}
	magic, err := r.u16(0)
	if err != nil {
		return nil, err
	}
	if magic != resXMLType {
		return nil, fmt.Errorf("not binary XML: first chunk type 0x%04x", magic)
	}
	headerSize, err := r.u16(2)
	if err != nil {
		return nil, err
	}

	var (
		strings    []string
		resourceID []uint32
		root       *axmlElement
		stack      []*axmlElement
		elements   int
	)

	off := int(headerSize)
	if off < 8 {
		off = 8
	}
	for off+8 <= len(raw) {
		chunkType, err := r.u16(off)
		if err != nil {
			break
		}
		chunkHeader, err := r.u16(off + 2)
		if err != nil {
			break
		}
		chunkSize, err := r.u32(off + 4)
		if err != nil {
			break
		}
		if chunkSize < 8 || chunkHeader < 8 || uint32(chunkHeader) > chunkSize {
			return nil, fmt.Errorf("chunk at %d has header %d chunk %d", off, chunkHeader, chunkSize)
		}
		switch chunkType {
		case resStringPoolType:
			if strings == nil {
				if pool, err := parseStringPool(r, off); err == nil {
					strings = pool
				}
			}
		case resXMLResourceMap:
			n := (int(chunkSize) - int(chunkHeader)) / 4
			for i := 0; i < n; i++ {
				v, err := r.u32(off + int(chunkHeader) + i*4)
				if err != nil {
					break
				}
				resourceID = append(resourceID, v)
			}
		case resXMLStartElement:
			elements++
			if elements > axmlMaxElements {
				return nil, fmt.Errorf("more than %d elements", axmlMaxElements)
			}
			if len(stack) >= axmlMaxDepth {
				return nil, fmt.Errorf("nesting deeper than %d", axmlMaxDepth)
			}
			element, err := parseStartElement(r, off, strings, resourceID)
			if err != nil {
				return nil, err
			}
			if len(stack) > 0 {
				parent := stack[len(stack)-1]
				parent.Children = append(parent.Children, element)
			} else if root == nil {
				root = element
			}
			stack = append(stack, element)
		case resXMLEndElement:
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
		}
		off += int(chunkSize)
	}

	manifest := &AXMLManifest{Elements: elements, Strings: len(strings)}
	if root == nil {
		return manifest, nil
	}
	if a, ok := root.attr("package"); ok {
		manifest.Package = a.Value
	}
	if a, ok := root.attr("versionCode"); ok {
		manifest.VersionCode = a.Value
	}
	if a, ok := root.attr("versionName"); ok {
		manifest.VersionName = a.Value
	}
	collectManifest(root, manifest)
	return manifest, nil
}

func parseStartElement(r axmlReader, off int, strings []string,
	resourceID []uint32) (*axmlElement, error) {
	nameIdx, err := r.u32(off + 20)
	if err != nil {
		return nil, err
	}
	attrStart, err := r.u16(off + 24)
	if err != nil {
		return nil, err
	}
	attrSize, err := r.u16(off + 26)
	if err != nil {
		return nil, err
	}
	attrCount, err := r.u16(off + 28)
	if err != nil {
		return nil, err
	}
	tag := ""
	if int(nameIdx) < len(strings) {
		tag = strings[nameIdx]
	}
	step := int(attrSize)
	if step < 20 {
		step = 20
	}

	element := &axmlElement{Tag: tag}
	for i := 0; i < int(attrCount); i++ {
		base := off + 16 + int(attrStart) + i*step
		nameIndex, err := r.u32(base + 4)
		if err != nil {
			break
		}
		rawValue, err := r.u32(base + 8)
		if err != nil {
			break
		}
		dataType, err := r.u8(base + 15)
		if err != nil {
			break
		}
		data, err := r.u32(base + 16)
		if err != nil {
			break
		}
		key := ""
		if int(nameIndex) < len(strings) {
			key = strings[nameIndex]
		}
		attr := axmlAttr{Name: key}
		if rawValue != axmlNoIndex && int(rawValue) < len(strings) {
			attr.Value = strings[rawValue]
		} else {
			attr.Value, attr.Bool, attr.IsBool = decodeTyped(dataType, data, strings)
		}
		element.Attrs = append(element.Attrs, attr)
	}
	return element, nil
}

// decodeTyped turns a typed Res_value into text, and reports booleans separately because
// `exported` must be a real bool: the payload is 0xFFFFFFFF for true and 0 for false, and reading
// it as an integer gives "4294967295" — which is neither true nor false to a caller.
func decodeTyped(dataType byte, data uint32, strings []string) (string, bool, bool) {
	switch dataType {
	case 0x03: // TYPE_STRING
		if int(data) < len(strings) {
			return strings[data], false, false
		}
		return "", false, false
	case 0x12: // TYPE_INT_BOOLEAN
		return "", data != 0, true
	case 0x10: // TYPE_INT_DEC
		return fmt.Sprintf("%d", int32(data)), false, false
	case 0x11: // TYPE_INT_HEX
		return fmt.Sprintf("0x%08x", data), false, false
	case 0x01, 0x07: // TYPE_REFERENCE, TYPE_DYNAMIC_REFERENCE
		return fmt.Sprintf("@0x%08x", data), false, false
	case 0x00: // TYPE_NULL
		return "", false, false
	}
	return fmt.Sprintf("type%02x:0x%08x", dataType, data), false, false
}

func collectManifest(root *axmlElement, manifest *AXMLManifest) {
	var walk func(e *axmlElement)
	walk = func(e *axmlElement) {
		switch e.Tag {
		case "uses-sdk":
			if a, ok := e.attr("minSdkVersion"); ok {
				manifest.MinSDK = a.Value
			}
			if a, ok := e.attr("targetSdkVersion"); ok {
				manifest.TargetSDK = a.Value
			}
		case "uses-permission":
			if a, ok := e.attr("name"); ok && a.Value != "" {
				manifest.Permissions = append(manifest.Permissions, a.Value)
			}
		case "uses-feature":
			if a, ok := e.attr("name"); ok && a.Value != "" {
				manifest.Features = append(manifest.Features, a.Value)
			}
		case "activity", "activity-alias", "service", "receiver", "provider":
			component := AXMLComponent{Tag: e.Tag}
			if a, ok := e.attr("name"); ok {
				component.Name = a.Value
			}
			if a, ok := e.attr("permission"); ok {
				component.Permission = a.Value
			}
			filters := 0
			for _, child := range e.Children {
				if child.Tag == "intent-filter" {
					filters++
				}
			}
			component.IntentFilter = filters
			if a, ok := e.attr("exported"); ok && a.IsBool {
				component.Exported = a.Bool
				component.ExportedWhy = "declared"
			} else if filters > 0 {
				component.Exported = true
				component.ExportedWhy = "implicit: intent-filter, no exported attribute"
			} else {
				component.Exported = false
				component.ExportedWhy = "implicit: no intent-filter, no exported attribute"
			}
			manifest.Components = append(manifest.Components, component)
		}
		for _, child := range e.Children {
			walk(child)
		}
	}
	walk(root)
}
