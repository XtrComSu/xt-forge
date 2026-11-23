package rehub

// Dalvik executable (.dex) reading, for the APK answer an analyst actually wants:
// which classes and methods are inside the package.
//
// Three details in DEX produce confidently wrong output when skipped, so each is
// handled explicitly here:
//
//   - Strings are MUTF-8, not UTF-8. NUL is encoded C0 80 and characters above the
//     BMP are two 3-byte surrogate halves. Decoding as UTF-8 either errors or
//     silently mangles every non-BMP string in the app.
//   - String data is a ULEB128 *UTF-16 length* followed by the bytes. Reading to the
//     first zero byte works until a string contains C0 80.
//   - encoded_field / encoded_method store an index *difference* from the previous
//     entry. Using the value as an absolute index returns a real method that belongs
//     to a different class — specific, plausible and wrong.
//
// The header is also not a packed array of 4-byte words: a 20-byte signature sits
// between the checksum and file_size, so every field is read at its absolute offset.
// Unpacking the header as a sequence of words misaligns everything after the
// signature, and the string table then reads from the wrong place.

import (
	"archive/zip"
	"bytes"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash/adler32"
	"io"
	"strings"
	"unicode/utf16"
)

const dexHeaderSize = 0x70

type dexFile struct {
	data []byte
	// Header fields, read at their absolute offsets.
	checksum      uint32
	fileSize      uint32
	endianTag     uint32
	mapOff        uint32
	stringIDsSize uint32
	stringIDsOff  uint32
	typeIDsSize   uint32
	typeIDsOff    uint32
	protoIDsSize  uint32
	protoIDsOff   uint32
	fieldIDsSize  uint32
	fieldIDsOff   uint32
	methodIDsSize uint32
	methodIDsOff  uint32
	classDefsSize uint32
	classDefsOff  uint32
}

func openDex(data []byte) (*dexFile, error) {
	if len(data) < dexHeaderSize {
		return nil, fmt.Errorf("file too small for a DEX header (%d bytes)", len(data))
	}
	if string(data[:4]) != "dex\n" || data[7] != 0 {
		return nil, fmt.Errorf("no DEX magic")
	}
	u32 := func(off int) uint32 { return binary.LittleEndian.Uint32(data[off:]) }
	d := &dexFile{data: data}
	d.checksum = u32(8)
	d.fileSize = u32(32)
	d.endianTag = u32(40)
	d.mapOff = u32(52)
	d.stringIDsSize, d.stringIDsOff = u32(56), u32(60)
	d.typeIDsSize, d.typeIDsOff = u32(64), u32(68)
	d.protoIDsSize, d.protoIDsOff = u32(72), u32(76)
	d.fieldIDsSize, d.fieldIDsOff = u32(80), u32(84)
	d.methodIDsSize, d.methodIDsOff = u32(88), u32(92)
	d.classDefsSize, d.classDefsOff = u32(96), u32(100)
	if d.endianTag != 0x12345678 && d.endianTag != 0x78563412 {
		return nil, fmt.Errorf("unexpected endian tag 0x%08x", d.endianTag)
	}
	if u32(36) != dexHeaderSize {
		return nil, fmt.Errorf("unexpected header size 0x%x", u32(36))
	}
	return d, nil
}

func dexUleb128(data []byte, off int) (uint32, int, error) {
	var value uint32
	for i := 0; i < 5; i++ {
		if off+i >= len(data) {
			return 0, 0, fmt.Errorf("truncated LEB128")
		}
		b := data[off+i]
		value |= uint32(b&0x7F) << (7 * uint(i))
		if b&0x80 == 0 {
			return value, off + i + 1, nil
		}
	}
	return 0, 0, fmt.Errorf("LEB128 longer than 5 bytes")
}

// dexMUTF8 decodes Modified UTF-8 up to the terminator.
func dexMUTF8(data []byte, off int) string {
	var units []uint16
	cursor := off
	for cursor < len(data) {
		b := data[cursor]
		if b == 0 {
			break
		}
		switch {
		case b < 0x80:
			units = append(units, uint16(b))
			cursor++
		case b&0xE0 == 0xC0:
			if cursor+1 >= len(data) {
				cursor = len(data)
				break
			}
			units = append(units, uint16(b&0x1F)<<6|uint16(data[cursor+1]&0x3F))
			cursor += 2
		case b&0xF0 == 0xE0:
			if cursor+2 >= len(data) {
				cursor = len(data)
				break
			}
			units = append(units, uint16(b&0x0F)<<12|
				uint16(data[cursor+1]&0x3F)<<6|uint16(data[cursor+2]&0x3F))
			cursor += 3
		default:
			units = append(units, 0xFFFD)
			cursor++
		}
	}
	return string(utf16.Decode(units))
}

func (d *dexFile) str(index uint32) string {
	if index >= d.stringIDsSize {
		return ""
	}
	entry := int(d.stringIDsOff) + int(index)*4
	if entry+4 > len(d.data) {
		return ""
	}
	dataOff := int(binary.LittleEndian.Uint32(d.data[entry:]))
	if dataOff >= len(d.data) {
		return ""
	}
	_, start, err := dexUleb128(d.data, dataOff)
	if err != nil {
		return ""
	}
	return dexMUTF8(d.data, start)
}

func (d *dexFile) typeName(index uint32) string {
	if index >= d.typeIDsSize {
		return ""
	}
	entry := int(d.typeIDsOff) + int(index)*4
	if entry+4 > len(d.data) {
		return ""
	}
	return d.str(binary.LittleEndian.Uint32(d.data[entry:]))
}

func (d *dexFile) proto(index uint32) map[string]any {
	if index >= d.protoIDsSize {
		return nil
	}
	entry := int(d.protoIDsOff) + int(index)*12
	if entry+12 > len(d.data) {
		return nil
	}
	shortyIdx := binary.LittleEndian.Uint32(d.data[entry:])
	returnIdx := binary.LittleEndian.Uint32(d.data[entry+4:])
	paramsOff := int(binary.LittleEndian.Uint32(d.data[entry+8:]))
	var params []string
	if paramsOff > 0 && paramsOff+4 <= len(d.data) {
		count := int(binary.LittleEndian.Uint32(d.data[paramsOff:]))
		if count > 64 {
			count = 64
		}
		for i := 0; i < count; i++ {
			cursor := paramsOff + 4 + i*2
			if cursor+2 > len(d.data) {
				break
			}
			params = append(params, d.typeName(uint32(binary.LittleEndian.Uint16(d.data[cursor:]))))
		}
	}
	return map[string]any{
		"shorty":      d.str(shortyIdx),
		"return_type": d.typeName(returnIdx),
		"parameters":  params,
	}
}

func (d *dexFile) methodID(index uint32) map[string]any {
	if index >= d.methodIDsSize {
		return nil
	}
	entry := int(d.methodIDsOff) + int(index)*8
	if entry+8 > len(d.data) {
		return nil
	}
	classIdx := uint32(binary.LittleEndian.Uint16(d.data[entry:]))
	protoIdx := uint32(binary.LittleEndian.Uint16(d.data[entry+2:]))
	nameIdx := binary.LittleEndian.Uint32(d.data[entry+4:])
	return map[string]any{
		"class": d.typeName(classIdx),
		"name":  d.str(nameIdx),
		"proto": d.proto(protoIdx),
	}
}

func (d *dexFile) fieldID(index uint32) map[string]any {
	if index >= d.fieldIDsSize {
		return nil
	}
	entry := int(d.fieldIDsOff) + int(index)*8
	if entry+8 > len(d.data) {
		return nil
	}
	classIdx := uint32(binary.LittleEndian.Uint16(d.data[entry:]))
	typeIdx := uint32(binary.LittleEndian.Uint16(d.data[entry+2:]))
	nameIdx := binary.LittleEndian.Uint32(d.data[entry+4:])
	return map[string]any{
		"class": d.typeName(classIdx),
		"type":  d.typeName(typeIdx),
		"name":  d.str(nameIdx),
	}
}

var dexClassFlags = [][2]any{
	{0x00001, "PUBLIC"}, {0x00002, "PRIVATE"}, {0x00004, "PROTECTED"},
	{0x00008, "STATIC"}, {0x00010, "FINAL"}, {0x00020, "SUPER"},
	{0x00200, "INTERFACE"}, {0x00400, "ABSTRACT"}, {0x01000, "SYNTHETIC"},
	{0x02000, "ANNOTATION"}, {0x04000, "ENUM"},
}

var dexMethodFlags = [][2]any{
	{0x00001, "PUBLIC"}, {0x00002, "PRIVATE"}, {0x00004, "PROTECTED"},
	{0x00008, "STATIC"}, {0x00010, "FINAL"}, {0x00020, "SYNCHRONIZED"},
	{0x00040, "BRIDGE"}, {0x00080, "VARARGS"}, {0x00100, "NATIVE"},
	{0x00400, "ABSTRACT"}, {0x00800, "STRICT"}, {0x01000, "SYNTHETIC"},
	{0x10000, "CONSTRUCTOR"}, {0x20000, "DECLARED_SYNCHRONIZED"},
}

var dexFieldFlags = [][2]any{
	{0x00001, "PUBLIC"}, {0x00002, "PRIVATE"}, {0x00004, "PROTECTED"},
	{0x00008, "STATIC"}, {0x00010, "FINAL"}, {0x00040, "VOLATILE"},
	{0x00080, "TRANSIENT"}, {0x01000, "SYNTHETIC"}, {0x04000, "ENUM"},
}

func dexFlagNames(mask uint32, table [][2]any) []string {
	var names []string
	for _, pair := range table {
		bit := uint32(pair[0].(int))
		if mask&bit != 0 {
			names = append(names, pair[1].(string))
		}
	}
	return names
}

// dexClassData decodes class_data_item. Deltas are accumulated, not used directly.
func (d *dexFile) classData(off uint32) ([]map[string]any, []map[string]any, error) {
	if off == 0 || int(off) >= len(d.data) {
		return nil, nil, nil
	}
	data := d.data
	cursor := int(off)
	read := func() (uint32, error) {
		value, next, err := dexUleb128(data, cursor)
		if err != nil {
			return 0, err
		}
		cursor = next
		return value, nil
	}
	staticCount, err := read()
	if err != nil {
		return nil, nil, err
	}
	instanceCount, err := read()
	if err != nil {
		return nil, nil, err
	}
	directCount, err := read()
	if err != nil {
		return nil, nil, err
	}
	virtualCount, err := read()
	if err != nil {
		return nil, nil, err
	}

	var fields, methods []map[string]any
	const maxItems = 20000

	var fieldIdx uint32
	for _, spec := range []struct {
		count  uint32
		static bool
	}{{staticCount, true}, {instanceCount, false}} {
		fieldIdx = 0
		count := spec.count
		if count > maxItems {
			count = maxItems
		}
		for i := uint32(0); i < count; i++ {
			delta, err := read()
			if err != nil {
				return fields, methods, err
			}
			access, err := read()
			if err != nil {
				return fields, methods, err
			}
			fieldIdx += delta
			info := d.fieldID(fieldIdx)
			if info == nil {
				continue
			}
			info["access"] = dexFlagNames(access, dexFieldFlags)
			info["static"] = spec.static
			fields = append(fields, info)
		}
	}

	for _, spec := range []struct {
		count uint32
		kind  string
	}{{directCount, "direct"}, {virtualCount, "virtual"}} {
		var methodIdx uint32
		count := spec.count
		if count > maxItems {
			count = maxItems
		}
		for i := uint32(0); i < count; i++ {
			delta, err := read()
			if err != nil {
				return fields, methods, err
			}
			access, err := read()
			if err != nil {
				return fields, methods, err
			}
			codeOff, err := read()
			if err != nil {
				return fields, methods, err
			}
			methodIdx += delta
			info := d.methodID(methodIdx)
			if info == nil {
				continue
			}
			info["access"] = dexFlagNames(access, dexMethodFlags)
			info["kind"] = spec.kind
			info["has_code"] = codeOff != 0
			info["native"] = access&0x00100 != 0
			if codeOff != 0 && int(codeOff)+16 <= len(d.data) {
				info["code"] = map[string]any{
					"registers":  binary.LittleEndian.Uint16(d.data[codeOff:]),
					"ins":        binary.LittleEndian.Uint16(d.data[codeOff+2:]),
					"tries":      binary.LittleEndian.Uint16(d.data[codeOff+6:]),
					"insns_size": binary.LittleEndian.Uint32(d.data[codeOff+12:]),
				}
			}
			methods = append(methods, info)
		}
	}
	return fields, methods, nil
}

// VerifyDex checks the embedded checksum (Adler-32 over everything after offset 12)
// and signature (SHA-1 over everything after offset 32). A mismatch means the file
// was modified after it was built.
func verifyDex(d *dexFile) map[string]any {
	out := map[string]any{
		"checksum_ok":  adler32.Checksum(d.data[12:]) == d.checksum,
		"file_size_ok": int(d.fileSize) == len(d.data),
	}
	sum := sha1.Sum(d.data[32:])
	// The stored signature is the raw 20 bytes at offset 12.
	out["signature_ok"] = hex.EncodeToString(sum[:]) == hex.EncodeToString(d.data[12:32])
	return out
}

func dexCounts(d *dexFile) map[string]any {
	return map[string]any{
		"strings":    d.stringIDsSize,
		"types":      d.typeIDsSize,
		"prototypes": d.protoIDsSize,
		"fields":     d.fieldIDsSize,
		"methods":    d.methodIDsSize,
		"classes":    d.classDefsSize,
	}
}

// InspectDexBytes inventories a DEX file already in memory.
func InspectDexBytes(data []byte, limit int) map[string]any {
	d, err := openDex(data)
	if err != nil {
		return map[string]any{"ok": false, "error": err.Error()}
	}
	if limit <= 0 {
		limit = 40
	}
	var classes []map[string]any
	var nativeMethods []string
	maxClasses := int(d.classDefsSize)
	if maxClasses > 5000 {
		maxClasses = 5000
	}
	for i := 0; i < maxClasses; i++ {
		entry := int(d.classDefsOff) + i*32
		if entry+32 > len(d.data) {
			break
		}
		classIdx := binary.LittleEndian.Uint32(d.data[entry:])
		access := binary.LittleEndian.Uint32(d.data[entry+4:])
		superIdx := binary.LittleEndian.Uint32(d.data[entry+8:])
		sourceIdx := binary.LittleEndian.Uint32(d.data[entry+16:])
		classDataOff := binary.LittleEndian.Uint32(d.data[entry+24:])

		record := map[string]any{
			"name":   d.typeName(classIdx),
			"access": dexFlagNames(access, dexClassFlags),
		}
		if superIdx != 0xFFFFFFFF {
			record["superclass"] = d.typeName(superIdx)
		}
		if sourceIdx != 0xFFFFFFFF {
			record["source_file"] = d.str(sourceIdx)
		}
		fields, methods, err := d.classData(classDataOff)
		if err != nil {
			record["error"] = err.Error()
		}
		record["field_count"] = len(fields)
		record["method_count"] = len(methods)
		if len(classes) < limit {
			record["fields"] = fields
			record["methods"] = methods
		}
		for _, m := range methods {
			if native, _ := m["native"].(bool); native {
				name, _ := record["name"].(string)
				mname, _ := m["name"].(string)
				nativeMethods = append(nativeMethods, name+"->"+mname)
			}
		}
		classes = append(classes, record)
	}

	return map[string]any{
		"ok":             true,
		"format":         "dex",
		"version":        string(data[4:7]),
		"counts":         dexCounts(d),
		"verification":   verifyDex(d),
		"class_count":    len(classes),
		"classes":        classes,
		"native_methods": nativeMethods,
	}
}

// InspectDexEntry reads one .dex entry out of an APK without unpacking it to disk.
func InspectDexEntry(apkPath, entryName string) map[string]any {
	zr, err := zip.OpenReader(apkPath)
	if err != nil {
		return map[string]any{"ok": false, "error": "cannot open archive: " + err.Error()}
	}
	defer zr.Close()
	if entryName == "" {
		entryName = "classes.dex"
	}
	var chosen *zip.File
	for _, f := range zr.File {
		if f.Name == entryName {
			chosen = f
			break
		}
		if chosen == nil && strings.HasSuffix(f.Name, ".dex") && !strings.Contains(f.Name, "/") {
			chosen = f
		}
	}
	if chosen == nil {
		return map[string]any{"ok": false, "error": "no " + entryName + " in the archive"}
	}
	rc, err := chosen.Open()
	if err != nil {
		return map[string]any{"ok": false, "error": err.Error()}
	}
	defer rc.Close()
	const maxDex = 256 * 1024 * 1024
	buf := make([]byte, 0, 1<<20)
	chunk := make([]byte, 1<<20)
	for {
		n, err := rc.Read(chunk)
		if n > 0 {
			buf = append(buf, chunk[:n]...)
			if len(buf) > maxDex {
				return map[string]any{"ok": false, "error": "dex entry too large"}
			}
		}
		if err != nil {
			break
		}
	}
	d, derr := openDex(buf)
	if derr != nil {
		return map[string]any{"ok": false, "error": derr.Error()}
	}
	return map[string]any{
		"ok":           true,
		"entry":        chosen.Name,
		"size":         len(buf),
		"version":      string(buf[4:7]),
		"counts":       dexCounts(d),
		"verification": verifyDex(d),
	}
}

// InspectDexEntryFull reads a .dex entry out of an archive and enumerates its
// classes. Separate from InspectDexEntry so the cheap counts-only path stays cheap:
// an APK inventory summarises every dex, while `apk dex` enumerates one.
func InspectDexEntryFull(apkPath, entryName string, limit int) map[string]any {
	data, name, err := readArchiveEntry(apkPath, entryName)
	if err != nil {
		return map[string]any{"ok": false, "error": err.Error()}
	}
	report := InspectDexBytes(data, limit)
	if ok, _ := report["ok"].(bool); ok {
		report["entry"] = name
		report["size"] = len(data)
		report["path"] = apkPath
	}
	return report
}

// readArchiveEntry returns the bytes of one entry, defaulting to the first top-level
// .dex when the requested name is absent.
func readArchiveEntry(apkPath, entryName string) ([]byte, string, error) {
	zr, err := zip.OpenReader(apkPath)
	if err != nil {
		return nil, "", fmt.Errorf("cannot open archive: %w", err)
	}
	defer zr.Close()
	if entryName == "" {
		entryName = "classes.dex"
	}
	var chosen *zip.File
	for _, f := range zr.File {
		if f.Name == entryName {
			chosen = f
			break
		}
		if chosen == nil && strings.HasSuffix(f.Name, ".dex") && !strings.Contains(f.Name, "/") {
			chosen = f
		}
	}
	if chosen == nil {
		return nil, "", fmt.Errorf("no %s in the archive", entryName)
	}
	rc, err := chosen.Open()
	if err != nil {
		return nil, "", err
	}
	defer rc.Close()
	const maxDex = 256 * 1024 * 1024
	var buf bytes.Buffer
	n, err := buf.ReadFrom(io.LimitReader(rc, maxDex+1))
	if err != nil {
		return nil, "", err
	}
	if n > maxDex {
		return nil, "", fmt.Errorf("dex entry too large")
	}
	return buf.Bytes(), chosen.Name, nil
}
