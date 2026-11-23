package sysimage

import (
	"encoding/binary"
	"fmt"
	"io"
	"strings"
)

// Enums and type modifiers from a PDB's TPI (type information) stream.
//
// The layouts below were checked byte-for-byte against PDBs built here with
// clang -target x86_64-pc-windows-msvc -O0 -g -gcodeview and lld-link /debug,
// and cross-checked with `llvm-pdbutil dump -types`:
//
//	LF_ENUM (0x1507): count u16, properties u16, underlyingType u32, fieldList u32, name
//	LF_MODIFIER (0x1001): modifiedType u32, modifiers u16
//	LF_ENUMERATE (0x1502, inside LF_FIELDLIST): attrs u16, NumericLeaf value, name
//
// For example the record for `enum Color { Red, Green = 5, Blue }` had the
// body `03 00 00 00 74 00 00 00 00 10 00 00 "Color\0"` (three members,
// int = 0x74, field list 0x1000), and its field list held
// `02 15 03 00 00 00 "Red\0"` followed by padded 0x1502 sub-records for
// Green (05 00) and Blue (06 00). A `const volatile int` record had the body
// `74 00 00 00 03 00`, confirming the u32 referent and u16 modifier mask.
// Large enumerator values use a four-byte NumericLeaf: 40000 was encoded as
// `02 80 40 9c` and 0x1234567 as `04 80 67 45 23 01` (u32 minus 0x8000).

const (
	pdbLeafEnum            = 0x1507
	pdbLeafModifier        = 0x1001
	pdbLeafEnumerate       = 0x1502
	pdbNumericLeafWideFlag = 0x8000

	pdbModifierConst     = 0x01
	pdbModifierVolatile  = 0x02
	pdbModifierUnaligned = 0x04
	pdbModifierUnmanaged = 0x08
)

// PDBEnum is one enum with its members.
type PDBEnum struct {
	Index      uint32          `json:"index"`
	Name       string          `json:"name"`
	Underlying string          `json:"underlying"`
	Members    []PDBEnumMember `json:"members"`
	Rendered   string          `json:"rendered"`
}

// PDBEnumMember is one named enumerator and its constant value.
type PDBEnumMember struct {
	Name  string `json:"name"`
	Value int64  `json:"value"`
}

// PDBModifier is a const/volatile/unmanaged wrapper around another type.
type PDBModifier struct {
	Index     uint32 `json:"index"`
	Modified  string `json:"modified"`
	Attribute string `json:"attribute"`
}

// pdbTypeStream is one pass over the TPI records, shared by both decoders in
// this file so the MSF and record-walk logic exists here only once.
type pdbTypeStream struct {
	records map[uint32]pdbTypeRecord
	order   []uint32
}

func pdbLoadTypeStream(r io.ReaderAt, size int64) (*pdbTypeStream, error) {
	if r == nil {
		return nil, fmt.Errorf("pdb: nil reader")
	}
	if size < pdbHeaderLen {
		return nil, fmt.Errorf("pdb: file is too short to hold an MSF 7.00 header")
	}
	blockSize, numBlocks, dir, sizes, err := pdbDirectory(r, size)
	if err != nil {
		return nil, err
	}
	if len(sizes) <= pdbTPIStreamIndex || sizes[pdbTPIStreamIndex] == 0 || sizes[pdbTPIStreamIndex] == 0xffffffff {
		return nil, fmt.Errorf("pdb: no type information stream")
	}
	stream, err := pdbStream(r, size, blockSize, numBlocks, dir, sizes, pdbTPIStreamIndex)
	if err != nil {
		return nil, err
	}
	if len(stream) < pdbTPIMinHeader {
		return nil, fmt.Errorf("pdb: type stream header is truncated")
	}
	headerSize := binary.LittleEndian.Uint32(stream[4:8])
	if headerSize < pdbTPIMinHeader || uint64(headerSize) >= uint64(len(stream)) {
		return nil, fmt.Errorf("pdb: implausible type header size %d", headerSize)
	}

	types := &pdbTypeStream{records: map[uint32]pdbTypeRecord{}}
	index := binary.LittleEndian.Uint32(stream[8:12])
	for offset := int(headerSize); offset+4 <= len(stream); {
		recordLen := int(binary.LittleEndian.Uint16(stream[offset:]))
		if recordLen == 0 || offset+2+recordLen > len(stream) {
			break
		}
		leaf := binary.LittleEndian.Uint16(stream[offset+2:])
		body := stream[offset+4 : offset+2+recordLen]
		types.records[index] = pdbTypeRecord{index: index, leaf: leaf, body: body}
		types.order = append(types.order, index)
		index++
		offset += 2 + recordLen
	}
	return types, nil
}

// pdbTypeIndices collects the indices of records of one leaf kind, in stream order.
func pdbTypeIndices(types *pdbTypeStream, leaf uint16) []uint32 {
	var indices []uint32
	for _, index := range types.order {
		if types.records[index].leaf == leaf {
			indices = append(indices, index)
		}
	}
	return indices
}

// ReadPDBEnums decodes every LF_ENUM record in a PDB's type stream.
func ReadPDBEnums(r io.ReaderAt, size int64, limit int) ([]PDBEnum, error) {
	types, err := pdbLoadTypeStream(r, size)
	if err != nil {
		return nil, err
	}
	indices := pdbTypeIndices(types, pdbLeafEnum)
	if limit <= 0 || limit > len(indices) {
		limit = len(indices)
	}
	enums := make([]PDBEnum, 0, limit)
	for _, index := range indices {
		if len(enums) >= limit {
			break
		}
		record := types.records[index]
		// count u16 + properties u16 + underlying u32 + fieldList u32 + NUL.
		if len(record.body) < 13 {
			continue
		}
		name := pdbCString(record.body[12:])
		if name == "" || name == "<unnamed-tag>" {
			continue
		}
		fieldList := binary.LittleEndian.Uint32(record.body[8:12])
		underlying := binary.LittleEndian.Uint32(record.body[4:8])
		enum := PDBEnum{
			Index:      index,
			Name:       name,
			Underlying: pdbEnumTypeName(underlying, types, 0),
			Members:    pdbEnumerators(fieldList, types),
		}
		enum.Rendered = pdbRenderEnum(enum)
		enums = append(enums, enum)
	}
	return enums, nil
}

// pdbEnumerators walks an LF_FIELDLIST and extracts its LF_ENUMERATE entries.
func pdbEnumerators(fieldListIndex uint32, types *pdbTypeStream) []PDBEnumMember {
	record, ok := types.records[fieldListIndex]
	if !ok || record.leaf != pdbLeafFieldList {
		return nil
	}
	var members []PDBEnumMember
	body := record.body
	for offset := 0; offset+6 <= len(body); {
		leaf := binary.LittleEndian.Uint16(body[offset:])
		if leaf == 0 {
			break
		}
		if leaf != pdbLeafEnumerate {
			// A field list can hold members and methods whose payload length is
			// not knowable here; stop instead of guessing where the next one is.
			break
		}
		value, width := pdbNumericLeaf(body[offset+4:])
		if width == 0 {
			break
		}
		nameAt := offset + 4 + width
		if nameAt >= len(body) {
			break
		}
		name := pdbCString(body[nameAt:])
		if name == "" {
			break
		}
		members = append(members, PDBEnumMember{Name: name, Value: value})
		// Sub-records are padded to a four-byte boundary relative to the start of
		// the field list body, as verified in the fixture's 0x1203 record.
		next := nameAt + len(name) + 1
		if pad := next % 4; pad != 0 {
			next += 4 - pad
		}
		if next <= offset {
			break
		}
		offset = next
	}
	return members
}

// pdbNumericLeaf decodes a CodeView NumericLeaf and returns its byte width.
// A high bit in the leading u16 means the whole u32 is the value with 0x8000
// subtracted; zero width means the input is truncated.
func pdbNumericLeaf(data []byte) (int64, int) {
	if len(data) < 2 {
		return 0, 0
	}
	first := binary.LittleEndian.Uint16(data)
	if first < pdbNumericLeafWideFlag {
		return int64(first), 2
	}
	if len(data) < 4 {
		return 0, 0
	}
	return int64(binary.LittleEndian.Uint32(data) - pdbNumericLeafWideFlag), 4
}

func pdbRenderEnum(enum PDBEnum) string {
	parts := make([]string, 0, len(enum.Members))
	for _, member := range enum.Members {
		parts = append(parts, fmt.Sprintf("%s = %d", member.Name, member.Value))
	}
	return fmt.Sprintf("enum %s { %s }", enum.Name, strings.Join(parts, ", "))
}

// ReadPDBModifiers decodes every LF_MODIFIER record in a PDB's type stream.
func ReadPDBModifiers(r io.ReaderAt, size int64, limit int) ([]PDBModifier, error) {
	types, err := pdbLoadTypeStream(r, size)
	if err != nil {
		return nil, err
	}
	indices := pdbTypeIndices(types, pdbLeafModifier)
	if limit <= 0 || limit > len(indices) {
		limit = len(indices)
	}
	modifiers := make([]PDBModifier, 0, limit)
	for _, index := range indices {
		if len(modifiers) >= limit {
			break
		}
		record := types.records[index]
		if len(record.body) < 6 {
			continue
		}
		modified := binary.LittleEndian.Uint32(record.body[0:4])
		attributes := binary.LittleEndian.Uint16(record.body[4:6])
		modifiers = append(modifiers, PDBModifier{
			Index:     index,
			Modified:  pdbEnumTypeName(modified, types, 0),
			Attribute: pdbModifierPrefix(attributes),
		})
	}
	return modifiers, nil
}

// pdbModifierPrefix renders a modifier mask as a C declaration prefix. Bits
// without a name are shown in hex rather than guessed.
func pdbModifierPrefix(attributes uint16) string {
	var prefix string
	if attributes&pdbModifierVolatile != 0 {
		prefix += "volatile "
	}
	if attributes&pdbModifierConst != 0 {
		prefix += "const "
	}
	if attributes&pdbModifierUnaligned != 0 {
		prefix += "unaligned "
	}
	if attributes&pdbModifierUnmanaged != 0 {
		prefix += "unmanaged "
	}
	known := uint16(pdbModifierConst | pdbModifierVolatile | pdbModifierUnaligned | pdbModifierUnmanaged)
	if unknown := attributes & ^known; unknown != 0 {
		prefix += fmt.Sprintf("modifier(0x%04x) ", unknown)
	}
	return prefix
}

// pdbEnumTypeName names an enum referent for modifier rendering, then falls
// back to the verified primitive/simple-type naming in pdbTypeName.
func pdbEnumTypeName(typeIndex uint32, types *pdbTypeStream, depth int) string {
	if typeIndex < pdbSimpleTypeLimit {
		return pdbTypeName(typeIndex, types.records, 0)
	}
	record, ok := types.records[typeIndex]
	if !ok || depth > 4 {
		return pdbTypeName(typeIndex, types.records, 0)
	}
	switch record.leaf {
	case pdbLeafEnum:
		if len(record.body) >= 13 {
			if name := pdbCString(record.body[12:]); name != "" {
				return "enum " + name
			}
		}
	case pdbLeafModifier:
		if len(record.body) >= 6 {
			modified := binary.LittleEndian.Uint32(record.body[0:4])
			attributes := binary.LittleEndian.Uint16(record.body[4:6])
			return pdbModifierPrefix(attributes) + pdbEnumTypeName(modified, types, depth+1)
		}
	}
	return pdbTypeName(typeIndex, types.records, 0)
}
