package sysimage

import (
	"encoding/binary"
	"fmt"
	"io"
	"strings"
)

// PDB procedure signatures.
//
// A PE has no symbol table and its PDB is the only place function signatures exist.
// This decodes the record kinds needed to recover them — LF_PROCEDURE, LF_ARGLIST,
// and the LF_POINTER / LF_ARRAY / LF_MODIFIER wrappers a parameter can be built
// from. It is deliberately not a general type decoder: a partial decoder that
// renders a wrong signature is worse than one that says it does not know, so every
// unrecognised type index renders as its number rather than a guess.
//
// The primitive table below was read off real llvm-pdbutil output for a fixture built
// here with clang -gcodeview + lld-link /debug, not from memory:
//
//	0x0003 void, 0x0011 short, 0x0013 __int64 (long long),
//	0x0070 char, 0x0074 int, 0x0075 unsigned
//
// Any simple type index not in the table renders as "type(0xNNNN)". That makes a gap
// visible instead of inventing a name.

const (
	pdbLeafProcedure32 = 0x1008
	pdbLeafArgList32   = 0x1201
	pdbSimpleTypeLimit = 0x1000
	// LF_ARRAY, verified against a clang -gcodeview / lld-link /debug fixture:
	// llvm-pdbutil printed "0x1004 | LF_ARRAY [size = 16], size: 16,
	// index type: 0x0023 (unsigned __int64), element type: 0x0074 (int)".
	pdbLeafArray = 0x1503
	// LF_MODIFIER (0x1001), its modifier bits and the NumericLeaf decoder are
	// already defined in pdb_enums.go, where their bytes were verified too.
)

// pdbSimpleTypes maps simple (non-record) type indices to names. Only entries verified
// against llvm-pdbutil are listed.
var pdbSimpleTypes = map[uint32]string{
	0x0003: "void",
	0x0010: "signed char",
	0x0011: "short",
	0x0012: "long",
	0x0013: "__int64",
	0x0020: "unsigned char",
	0x0021: "unsigned short",
	0x0022: "unsigned long",
	0x0023: "unsigned __int64",
	0x0030: "bool",
	0x0040: "float",
	0x0041: "double",
	0x0070: "char",
	0x0074: "int",
	0x0075: "unsigned",
}

// pdbSimpleTypeWidth is the byte width of the simple types with a known, fixed
// size. It is used only to turn an LF_ARRAY's byte size into an element count;
// a type not in this map still renders as an array, just without the count.
var pdbSimpleTypeWidth = map[uint32]int64{
	0x0010: 1, // signed char
	0x0011: 2, // short
	0x0012: 4, // long
	0x0013: 8, // __int64
	0x0020: 1, // unsigned char
	0x0021: 2, // unsigned short
	0x0022: 4, // unsigned long
	0x0023: 8, // unsigned __int64
	0x0030: 1, // bool
	0x0040: 4, // float
	0x0041: 8, // double
	0x0070: 1, // char
	0x0074: 4, // int
	0x0075: 4, // unsigned
}

// pdbCallingConventions maps the CodeView convention byte to a name.
var pdbCallingConventions = map[uint8]string{
	0x00: "cdecl",
	0x04: "fastcall",
	0x07: "thiscall",
	0x0b: "stdcall",
	0x16: "vectorcall",
}

// PDBSignature is one procedure recovered from a PDB type stream.
type PDBSignature struct {
	Index      uint32   `json:"index"`
	ReturnType string   `json:"return_type"`
	Arguments  []string `json:"arguments"`
	// Parameters names each argument, when the symbol stream supplies them. Types
	// alone leave the reader guessing which `int` is the buffer and which is the count.
	Parameters        []PDBParameter `json:"parameters,omitempty"`
	CallingConvention string         `json:"calling_convention,omitempty"`
	// Rendered is the signature in C form, e.g. "int (char, unsigned)".
	Rendered string `json:"rendered"`
}

// pdbTypeRecord is one record located in the type stream.
type pdbTypeRecord struct {
	index uint32
	leaf  uint16
	body  []byte
}

// ReadPDBSignatures decodes every LF_PROCEDURE record in a PDB's type stream.
//
// Records are indexed by their type index, which lets LF_PROCEDURE refer to an
// LF_ARGLIST that appears anywhere in the stream.
func ReadPDBSignatures(r io.ReaderAt, size int64, limit int) ([]PDBSignature, error) {
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
	typeIndexBegin := binary.LittleEndian.Uint32(stream[8:12])

	records := map[uint32]pdbTypeRecord{}
	var procedures []uint32
	index := typeIndexBegin
	for offset := int(headerSize); offset+4 <= len(stream); {
		recordLen := int(binary.LittleEndian.Uint16(stream[offset:]))
		if recordLen == 0 || offset+2+recordLen > len(stream) {
			break
		}
		leaf := binary.LittleEndian.Uint16(stream[offset+2:])
		body := stream[offset+4 : offset+2+recordLen]
		records[index] = pdbTypeRecord{index: index, leaf: leaf, body: body}
		if leaf == pdbLeafProcedure32 {
			procedures = append(procedures, index)
		}
		index++
		offset += 2 + recordLen
	}
	if limit <= 0 || limit > len(procedures) {
		limit = len(procedures)
	}
	signatures := make([]PDBSignature, 0, limit)
	for _, index := range procedures {
		if len(signatures) >= limit {
			break
		}
		record := records[index]
		if len(record.body) < 12 {
			continue
		}
		returnIndex := binary.LittleEndian.Uint32(record.body[0:4])
		convention := record.body[4]
		parameterCount := binary.LittleEndian.Uint16(record.body[6:8])
		argListIndex := binary.LittleEndian.Uint32(record.body[8:12])

		signature := PDBSignature{
			Index:             index,
			ReturnType:        pdbTypeName(returnIndex, records, 0),
			CallingConvention: pdbCallingConventions[convention],
		}
		arguments := pdbArgumentTypes(argListIndex, records, int(parameterCount))
		signature.Arguments = arguments
		signature.Rendered = fmt.Sprintf("%s (%s)", signature.ReturnType,
			joinOrVoid(arguments))
		signatures = append(signatures, signature)
	}
	return signatures, nil
}

// pdbArgumentTypes resolves an LF_ARGLIST into readable type names.
func pdbArgumentTypes(argListIndex uint32, records map[uint32]pdbTypeRecord, want int) []string {
	record, ok := records[argListIndex]
	if !ok || record.leaf != pdbLeafArgList32 || len(record.body) < 4 {
		return nil
	}
	count := int(binary.LittleEndian.Uint32(record.body[0:4]))
	if want > 0 && count > want {
		// The procedure's own count is authoritative; a list claiming more is
		// truncated by the record length anyway.
		count = want
	}
	if max := (len(record.body) - 4) / 4; count > max {
		count = max
	}
	arguments := make([]string, 0, count)
	for i := 0; i < count; i++ {
		typeIndex := binary.LittleEndian.Uint32(record.body[4+i*4:])
		arguments = append(arguments, pdbTypeName(typeIndex, records, 0))
	}
	return arguments
}

// pdbAggregateInfo reads the common parts of an LF_STRUCTURE or LF_UNION body.
//
// The two layouts differ, and treating a union as a struct was the original bug:
// `union Value` was rendered as `union lue /* 1633026048 bytes */` because the
// u32 size read at +8 swallowed the first two bytes of the name. Measured in the
// clang-cl -Z7 fixture against `llvm-pdbutil dump -types --type-data`:
//
//	LF_STRUCTURE 0x100D body: 03 00 00 00 0C 10 00 00 | 00 00 00 00 00 00 00 00 |
//	                          08 00 "Bits\0"     -> field list 0x100C, size 8, name at +18
//	LF_UNION     0x1004 body: 02 00 00 04 03 10 00 00 | 04 00 "Value\0"
//	                                             -> field list 0x1003, size 4, name at +10
//
// The size is a NumericLeaf in both cases (u16 for these records), which matches
// cvinfo.h's lfClass/lfUnion "data describing length ... and name".
func pdbAggregateInfo(body []byte, leaf uint16) (fieldList, size uint32, name string, ok bool) {
	const structNameAt, unionNameAt = 18, 10
	nameAt := 0
	switch leaf {
	case pdbLeafStructure:
		if len(body) < structNameAt+1 {
			return 0, 0, "", false
		}
		nameAt = structNameAt
	case pdbLeafUnion:
		if len(body) < unionNameAt+1 {
			return 0, 0, "", false
		}
		nameAt = unionNameAt
	default:
		return 0, 0, "", false
	}
	fieldList = binary.LittleEndian.Uint32(body[4:8])
	if value, width := pdbNumericLeaf(body[nameAt-2:]); width > 0 {
		size = uint32(value)
	}
	return fieldList, size, pdbCString(body[nameAt:]), true
}

// pdbIsUnion reports whether an aggregate record is a union. CodeView marks a
// union with the LF_UNION leaf rather than with a property bit, so the leaf is
// authoritative; callers pair it with the aggregate's union flag when rendering.
func pdbIsUnion(leaf uint16) bool { return leaf == pdbLeafUnion }

// pdbTypeWidth is the byte width of a type index, recursing through arrays, records,
// pointers and modifiers. It returns 0 when the width cannot be established, and callers
// then omit the array count rather than inventing one.
func pdbTypeWidth(typeIndex uint32, records map[uint32]pdbTypeRecord, depth int) int64 {
	if width, ok := pdbSimpleTypeWidth[typeIndex]; ok {
		return width
	}
	if mode := typeIndex & 0x0F00; mode >= 0x0100 && mode <= 0x0700 {
		// Near/far pointers: the 64-bit modes are 8 bytes, the 32-bit ones 4.
		if mode >= 0x0600 {
			return 8
		}
		return 4
	}
	record, ok := records[typeIndex]
	if !ok || depth > 4 {
		return 0
	}
	switch record.leaf {
	case pdbLeafArray:
		if len(record.body) < 10 {
			return 0
		}
		if size, n := pdbNumericLeaf(record.body[8:]); n > 0 {
			return size
		}
	case pdbLeafModifier:
		if len(record.body) < 4 {
			return 0
		}
		return pdbTypeWidth(binary.LittleEndian.Uint32(record.body[0:4]), records, depth+1)
	case pdbLeafStructure, pdbLeafUnion:
		// Struct and union sizes live at different offsets; pdbAggregateInfo owns
		// that difference (see the measured bytes there).
		_, size, name, ok := pdbAggregateInfo(record.body, record.leaf)
		if !ok {
			return 0
		}
		if size > 0 {
			return int64(size)
		}
		// A forward-reference record carries sizeof 0 and points at the real definition:
		// llvm-pdbutil shows `options: forward ref (-> 0x100C), sizeof 0` for the record
		// that `struct Rec list[2]` refers to. Without following it the array count was
		// unknowable. Match the definition by leaf and name, which is what the forward
		// ref names.
		if name == "" {
			return 0
		}
		for index, candidate := range records {
			if index == typeIndex || candidate.leaf != record.leaf {
				continue
			}
			if _, candidateSize, candidateName, candidateOK := pdbAggregateInfo(candidate.body, candidate.leaf); candidateOK &&
				candidateName == name && candidateSize > 0 {
				return int64(candidateSize)
			}
		}
	}
	return 0
}

// pdbTypeName renders a type index, recursing through pointer, array and modifier
// wrappers. Anything else reports its index so an unknown type is visible rather
// than guessed.
//
// The existing depth guard (4, below the required ceiling of 6) bounds every
// recursive path, including a corrupt self-referential record.
func pdbTypeName(typeIndex uint32, records map[uint32]pdbTypeRecord, depth int) string {
	if name, ok := pdbSimpleTypes[typeIndex]; ok {
		return name
	}
	// A pointer is encoded as a mode in bits 8-11 over a base type index: 0x0611 is a
	// 64-bit near pointer to 0x0011 (short), and llvm-pdbutil renders it "short*". Only
	// the near/far pointer modes are decoded; the base must resolve on its own, so an
	// unknown base still reports its index instead of inventing a name.
	if mode := typeIndex & 0x0F00; mode >= 0x0100 && mode <= 0x0700 {
		if base := typeIndex &^ 0x0F00; base != typeIndex {
			if _, simple := pdbSimpleTypes[base]; simple || base >= pdbSimpleTypeLimit {
				if depth <= 4 {
					inner := pdbTypeName(base, records, depth+1)
					if !strings.HasPrefix(inner, "type(") {
						return inner + "*"
					}
				}
			}
		}
	}
	if typeIndex < pdbSimpleTypeLimit {
		return fmt.Sprintf("type(0x%04x)", typeIndex)
	}
	record, ok := records[typeIndex]
	if !ok || depth > 4 {
		return fmt.Sprintf("type(0x%x)", typeIndex)
	}
	switch record.leaf {
	case pdbLeafPointer:
		// LF_POINTER: +0 underlying type u32, +4 attributes u32.
		if len(record.body) < 8 {
			return fmt.Sprintf("type(0x%x)", typeIndex)
		}
		underlying := binary.LittleEndian.Uint32(record.body[0:4])
		// Attribute bit 5 (0x20) distinguishes 32- from 64-bit pointers; the size
		// itself lives in bits 13..18. Render width when it is readable.
		attributes := binary.LittleEndian.Uint32(record.body[4:8])
		size := (attributes >> 13) & 0x3f
		if size == 0 {
			return pdbTypeName(underlying, records, depth+1) + " *"
		}
		return fmt.Sprintf("%s *", pdbTypeName(underlying, records, depth+1))
	case pdbLeafArray:
		// LF_ARRAY record body from the verified fixture (index 0x1004, for
		// `int a[4]` inside struct P), 12 bytes after the u16 length:
		//
		//   +0 74 00 00 00   elementType = 0x0074 (int)
		//   +4 23 00 00 00   indexType   = 0x0023 (unsigned __int64)
		//   +8 10 00         size NumericLeaf = 16 (u16 high bit clear)
		//   +10 00 F1        empty name NUL + CodeView alignment pad
		//
		// llvm-pdbutil reports "size: 16, index type: 0x0023 (unsigned __int64),
		// element type: 0x0074 (int)" for the same record, so 16 / 4 = 4.
		if len(record.body) < 4 {
			return fmt.Sprintf("type(0x%x)", typeIndex)
		}
		element := binary.LittleEndian.Uint32(record.body[0:4])
		// The element's width decides the count, and the element is often not a simple
		// type: a nested array, a struct or a pointer all have a width the simple table
		// does not know. Without that, `int grid[2][3]` rendered as `int[3][]` and
		// `struct Rec list[2]` as `struct Rec[]` — measured against llvm-pdbutil, which
		// reports sizes of 24/12, 32/16 and 32/8 for exactly those records.
		count := ""
		if width := pdbTypeWidth(element, records, depth+1); width > 0 && len(record.body) >= 10 {
			if size, n := pdbNumericLeaf(record.body[8:]); n > 0 && size > 0 {
				count = fmt.Sprintf("%d", size/width)
			}
		}
		// Dimensions are collected outermost-first so `int x[2][3]` comes out in C
		// order. Recursing into the element and appending there would reverse them.
		dimensions := "[" + count + "]"
		base := element
		for depth < 4 {
			inner, ok := records[base]
			if !ok || inner.leaf != pdbLeafArray || len(inner.body) < 10 {
				break
			}
			innerElement := binary.LittleEndian.Uint32(inner.body[0:4])
			innerCount := ""
			if width := pdbTypeWidth(innerElement, records, depth+1); width > 0 {
				if size, n := pdbNumericLeaf(inner.body[8:]); n > 0 && size > 0 {
					innerCount = fmt.Sprintf("%d", size/width)
				}
			}
			dimensions += "[" + innerCount + "]"
			base = innerElement
			depth++
		}
		return fmt.Sprintf("%s%s", pdbTypeName(base, records, depth+1), dimensions)

	case pdbLeafModifier:
		// LF_MODIFIER record bodies from the same fixture:
		//
		//   const int    0x1005: 74 00 00 00 01 00 F2 F1
		//   volatile short 0x1007: 11 00 00 00 02 00 F2 F1
		//
		// i.e. +0 modifiedType u32, +4 modifier mask u16, then alignment pad.
		// pdbModifierPrefix orders the bits outermost first ("volatile const ").
		if len(record.body) < 6 {
			return fmt.Sprintf("type(0x%x)", typeIndex)
		}
		modified := binary.LittleEndian.Uint32(record.body[0:4])
		attributes := binary.LittleEndian.Uint16(record.body[4:6])
		return pdbModifierPrefix(attributes) + pdbTypeName(modified, records, depth+1)

	case pdbLeafBitfield:
		// LF_BITFIELD 0x1008 in the fixture: underlying type 0x0075 (unsigned),
		// bit width 3, bit offset 0. The member that uses this record carries the
		// name; here the declaration is the underlying type and the width.
		if len(record.body) < 5 {
			return fmt.Sprintf("type(0x%x)", typeIndex)
		}
		underlying := binary.LittleEndian.Uint32(record.body[0:4])
		return fmt.Sprintf("%s : %d", pdbTypeName(underlying, records, depth+1), record.body[4])

	case pdbLeafEnum:
		// An enum referenced as a field type has no fields of its own here: name
		// it from its LF_ENUM record (body +12, verified against llvm-pdbutil).
		// A type index whose enum record is not in `records` still takes the
		// unknown-index path below, i.e. keeps its index.
		if len(record.body) >= 13 {
			if name := pdbCString(record.body[12:]); name != "" && name != "<unnamed-tag>" {
				return "enum " + name
			}
		}

	case pdbLeafStructure, pdbLeafUnion:
		// Name the aggregate so a parameter reads as "struct Point" / "union Value"
		// rather than an opaque index. The leaf decides the keyword; taking it
		// from a struct-only layout previously truncated a union's name to "lue".
		_, _, name, ok := pdbAggregateInfo(record.body, record.leaf)
		if ok && name != "" && name != "<unnamed-tag>" {
			kind := "struct"
			if pdbIsUnion(record.leaf) {
				kind = "union"
			}
			return kind + " " + name
		}
		return fmt.Sprintf("%s(0x%x)", pdbLeafLabel(record.leaf), typeIndex)
	case pdbLeafArgList32, pdbLeafFieldList, pdbLeafProcedure32:
		// Aggregates and other records are not decoded; name them by kind so a caller
		// can tell "a struct I cannot name" from "an index I could not resolve".
		return fmt.Sprintf("%s(0x%x)", pdbLeafLabel(record.leaf), typeIndex)
	}
	return fmt.Sprintf("type(0x%x)", typeIndex)
}

// pdbLeafLabel names a leaf for display, using the verified table where present.
func pdbLeafLabel(leaf uint16) string {
	if name, ok := pdbLeafNames[leaf]; ok {
		return name
	}
	return fmt.Sprintf("leaf(0x%04x)", leaf)
}

func joinOrVoid(arguments []string) string {
	if len(arguments) == 0 {
		return "void"
	}
	out := ""
	for index, argument := range arguments {
		if index > 0 {
			out += ", "
		}
		out += argument
	}
	return out
}

// PDBProcedure is one S_GPROC32 record: a function body with its type index.
//
// This is what turns a signature into something addressable. Public symbols give a
// name and a position but no type and no size; S_GPROC32 gives all four, which is why
// the naming path prefers it.
//
// Layout, verified byte-for-byte against a real PDB and cross-checked with
// `llvm-pdbutil dump -symbols` (which prints the same segment:offset and type index):
//
//	+0 parent u32, +4 end u32, +8 next u32, +12 codeSize u32,
//	+16 dbgStart u32, +20 dbgEnd u32, +24 typeIndex u32, +28 offset u32,
//	+32 segment u16, +34 flags u8, +35 name (NUL-terminated)
type PDBProcedure struct {
	Name string `json:"name"`
	// Parameters come from the S_LOCAL records inside this procedure's scope. The
	// signature stream knows the argument *types* but never their names, so a caller
	// reading `int*, unsigned long` cannot tell which is the buffer and which is the
	// count.
	Parameters []PDBParameter `json:"parameters,omitempty"`
	Segment    uint16         `json:"segment"`
	Offset     uint32         `json:"offset"`
	CodeSize   uint32         `json:"code_size"`
	TypeIndex  uint32         `json:"type_index"`
	Signature  string         `json:"signature,omitempty"`
}

// PDBParameter is one named parameter of a procedure.
type PDBParameter struct {
	Name      string `json:"name"`
	TypeIndex uint32 `json:"type_index"`
	Type      string `json:"type,omitempty"`
}

const (
	pdbSymGProc32 = 0x1110
	pdbSymLocal   = 0x113E
	// Offsets are relative to the record body, which already skips reclen and rectyp.
	// Record-absolute values (4/8/10) put the walk two bytes late and produced a
	// parameter named "t" with type index 0x6f630001. Verified against the raw bytes of
	// a real S_LOCAL: `... 3e 11 | 74 06 00 00 | 01 00 | values`.
	pdbLocalTypeAt      = 0
	pdbLocalFlagsAt     = 4
	pdbLocalNameAt      = 6
	pdbLocalFlagIsParam = 0x0001
	pdbGProc32NameAt    = 35
	pdbGProc32FixedLen  = 35
	pdbProcedureLimit   = 20000
)

// ReadPDBProcedures recovers S_GPROC32 records from every module symbol stream.
//
// The DBI header that indexes those streams is not parsed, so every stream outside the
// fixed metadata range is scanned. That is what ReadPDBPublicSymbols already does, for
// the same reason, and it costs one pass over a file that has already been read.
func ReadPDBProcedures(r io.ReaderAt, size int64, limit int) ([]PDBProcedure, error) {
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
	if limit <= 0 || limit > pdbProcedureLimit {
		limit = pdbProcedureLimit
	}
	// Signatures are resolved from the type stream when it is readable; a PDB with no
	// usable TPI still yields procedures, just without rendered signatures.
	signatures, _ := ReadPDBSignatures(r, size, 0)
	byIndex := make(map[uint32]string, len(signatures))
	for _, signature := range signatures {
		byIndex[signature.Index] = signature.Rendered
	}

	procedures := make([]PDBProcedure, 0)
	for index := range sizes {
		if len(procedures) >= limit {
			break
		}
		// Only the two streams whose layouts are known to be non-symbol data are
		// skipped: 1 is the PDB info header and 2 is the type stream. The DBI
		// header (3) and the global symbol stream are scanned, because a real PDB
		// keeps S_GPROC32 records there — skipping "everything up to 4", which is
		// what a first version did, recovered nothing at all.
		if index == 1 || index == 2 || sizes[index] == 0 || sizes[index] == 0xffffffff {
			continue
		}
		stream, err := pdbStream(r, size, blockSize, numBlocks, dir, sizes, index)
		if err != nil {
			continue
		}
		scanPDBProcedures(stream, byIndex, limit, &procedures)
	}
	if len(procedures) == 0 {
		return nil, nil
	}
	return procedures, nil
}

// scanPDBProcedures walks the CodeView records of one stream.
//
// A module symbol stream begins with a 4-byte signature (CV_SIGNATURE_C13, the value
// 4) rather than with a record. Reading it as a record header yields reclen=4,
// rectyp=0 and then a misaligned walk that stops almost immediately — which is why a
// first version recovered nothing from a stream that demonstrably contains the
// records.
func scanPDBProcedures(stream []byte, signatures map[uint32]string, limit int, out *[]PDBProcedure) {
	const cvSignatureC13 = 4
	start := 0
	if len(stream) >= 4 && binary.LittleEndian.Uint32(stream[:4]) == cvSignatureC13 {
		start = 4
	}
	current := -1
	for offset := start; offset+4 <= len(stream); {
		reclen := int(binary.LittleEndian.Uint16(stream[offset:]))
		if reclen == 0 || offset+2+reclen > len(stream) {
			return // a zero or overlong record invalidates the rest of the stream
		}
		rectyp := binary.LittleEndian.Uint16(stream[offset+2:])
		if rectyp == pdbSymGProc32 && reclen > pdbGProc32FixedLen {
			body := stream[offset+4 : offset+2+reclen]
			if len(body) >= pdbGProc32NameAt {
				procedure := PDBProcedure{
					CodeSize:  binary.LittleEndian.Uint32(body[12:16]),
					TypeIndex: binary.LittleEndian.Uint32(body[24:28]),
					Offset:    binary.LittleEndian.Uint32(body[28:32]),
					Segment:   binary.LittleEndian.Uint16(body[32:34]),
				}
				nameBytes := body[pdbGProc32NameAt:]
				if end := indexByteZero(nameBytes); end > 0 && pdbPrintableName(nameBytes[:end]) {
					procedure.Name = string(nameBytes[:end])
					procedure.Signature = signatures[procedure.TypeIndex]
					if procedure.Segment != 0 {
						*out = append(*out, procedure)
						current = len(*out) - 1
						if len(*out) >= limit {
							return
						}
					}
				}
			}
		} else if rectyp == pdbSymLocal && current >= 0 {
			// S_LOCAL: +0 typeIndex u32, +4 flags u16, +6 name. Only records flagged
			// as parameters are kept; locals with the same shape would otherwise be
			// presented as arguments.
			body := stream[offset+4 : offset+2+reclen]
			if len(body) > pdbLocalNameAt {
				flags := binary.LittleEndian.Uint16(body[pdbLocalFlagsAt : pdbLocalFlagsAt+2])
				if flags&pdbLocalFlagIsParam != 0 {
					nameBytes := body[pdbLocalNameAt:]
					if end := indexByteZero(nameBytes); end > 0 && pdbPrintableName(nameBytes[:end]) {
						parameter := PDBParameter{
							Name:      string(nameBytes[:end]),
							TypeIndex: binary.LittleEndian.Uint32(body[pdbLocalTypeAt : pdbLocalTypeAt+4]),
						}
						// Append in place: the procedure already sits at *out[current].
						(*out)[current].Parameters = append((*out)[current].Parameters, parameter)
					}
				}
			}
		}
		offset += 2 + reclen
	}
}

// indexByteZero is bytes.IndexByte for a NUL, kept local to avoid another import here.
func indexByteZero(data []byte) int {
	for index, value := range data {
		if value == 0 {
			return index
		}
	}
	return -1
}

// PDB aggregate layouts.
//
// LF_STRUCTURE / LF_UNION name a field list, and LF_FIELDLIST holds LF_MEMBER records
// that each carry a type index and a byte offset. Decoding those three is enough to
// print `struct Point { int x; int y; }` with real offsets, which is what a parameter
// of struct type needs in order to render as something other than type(0xNNNN).
//
// Layouts, per the CodeView specification as implemented by LLVM's
// CodeViewTypes.cpp:
//
//	LF_STRUCTURE: memberCount u16, properties u16, fieldList u32,
//	              derivedFrom u32, vshape u32, size NumericLeaf, name (NUL-terminated)
//	LF_UNION:     memberCount u16, properties u16, fieldList u32,
//	              size NumericLeaf, name (NUL-terminated)  <- size is NOT u32
//	LF_FIELDLIST: a concatenation of sub-records, each: leaf u16 then payload
//	LF_MEMBER:    attrs u16, type u32, offset (u16, or u32 when >= 0x8000),
//	              name (NUL-terminated)
//	LF_BITFIELD:  type u32, bit width u8, bit offset u8
const (
	pdbLeafUnion    = 0x1506
	pdbLeafMember   = 0x150d
	pdbMemberAttr   = 0x150d
	pdbLeafBitfield = 0x1205
)

// PDBField is one member of an aggregate.
type PDBField struct {
	Name   string `json:"name"`
	Type   string `json:"type"`
	Offset uint32 `json:"offset"`
	// BitWidth is nonzero when the member's type is an LF_BITFIELD record. In the
	// clang-cl fixture its LF_MEMBER attrs were 0x0003 (public) with no bitfield
	// bits set; the width came from the separate LF_BITFIELD type record.
	BitWidth int `json:"bit_width,omitempty"`
}

// PDBAggregate is one struct or union with its fields.
type PDBAggregate struct {
	Index  uint32     `json:"index"`
	Name   string     `json:"name"`
	Size   uint32     `json:"size"`
	Union  bool       `json:"union"`
	Fields []PDBField `json:"fields"`
	// Rendered is the C form, e.g. "struct Point { int x; int y; }".
	Rendered string `json:"rendered"`
}

// ReadPDBAggregates decodes struct and union layouts from a PDB's type stream.
func ReadPDBAggregates(r io.ReaderAt, size int64, limit int) ([]PDBAggregate, error) {
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
	records := map[uint32]pdbTypeRecord{}
	var aggregates []uint32
	index := binary.LittleEndian.Uint32(stream[8:12])
	for offset := int(headerSize); offset+4 <= len(stream); {
		recordLen := int(binary.LittleEndian.Uint16(stream[offset:]))
		if recordLen == 0 || offset+2+recordLen > len(stream) {
			break
		}
		leaf := binary.LittleEndian.Uint16(stream[offset+2:])
		records[index] = pdbTypeRecord{index: index, leaf: leaf, body: stream[offset+4 : offset+2+recordLen]}
		if leaf == pdbLeafStructure || leaf == pdbLeafUnion {
			aggregates = append(aggregates, index)
		}
		index++
		offset += 2 + recordLen
	}
	if limit <= 0 || limit > len(aggregates) {
		limit = len(aggregates)
	}
	out := make([]PDBAggregate, 0, limit)
	for _, index := range aggregates {
		if len(out) >= limit {
			break
		}
		record := records[index]
		aggregate := PDBAggregate{Index: index, Union: pdbIsUnion(record.leaf)}
		fieldList, size, name, ok := pdbAggregateInfo(record.body, record.leaf)
		if !ok {
			continue
		}
		aggregate.Size = size
		aggregate.Name = name
		aggregate.Fields = pdbFields(fieldList, records)
		// A name of "<unnamed-tag>" is what the compiler emits for anonymous
		// aggregates; it is not useful to print and would look like a real name.
		if aggregate.Name == "" || aggregate.Name == "<unnamed-tag>" {
			continue
		}
		if aggregate.Size == 0 && len(aggregate.Fields) == 0 {
			continue // a forward declaration, not a definition
		}
		aggregate.Rendered = pdbRenderAggregate(aggregate)
		out = append(out, aggregate)
	}
	return out, nil
}

// pdbFields walks an LF_FIELDLIST and extracts its LF_MEMBER entries.
func pdbFields(fieldListIndex uint32, records map[uint32]pdbTypeRecord) []PDBField {
	record, ok := records[fieldListIndex]
	if !ok || record.leaf != pdbLeafFieldList {
		return nil
	}
	var fields []PDBField
	body := record.body
	for offset := 0; offset+2 <= len(body); {
		leaf := binary.LittleEndian.Uint16(body[offset:])
		if leaf == 0 {
			break
		}
		if leaf != pdbLeafMember || offset+8 > len(body) {
			// Other sub-records (methods, static members, base classes) are not
			// decoded; skip them by their own length, which the walk cannot know
			// here, so stop rather than guess an offset.
			break
		}
		attrs := binary.LittleEndian.Uint16(body[offset+2:])
		typeIndex := binary.LittleEndian.Uint32(body[offset+4:])
		nameAt := offset + 8
		var field PDBField
		// A bitfield is encoded as a member whose type index points at an
		// LF_BITFIELD record. The high bits of LF_MEMBER.attrs are access/method
		// properties (CV_fldattr_t), not bit width: measured attrs for both a and
		// b in the fixture were 0x0003, with widths 3 and 5 in records 0x1008 and
		// 0x1009. Render the underlying type here and keep the width separate so
		// pdbRenderAggregate can place it after the member name (`unsigned a : 3`).
		if bitfield, ok := records[typeIndex]; ok && bitfield.leaf == pdbLeafBitfield && len(bitfield.body) >= 5 {
			underlying := binary.LittleEndian.Uint32(bitfield.body[0:4])
			field.Type = pdbTypeName(underlying, records, 0)
			field.BitWidth = int(bitfield.body[4])
		} else {
			field.Type = pdbTypeName(typeIndex, records, 0)
		}
		_ = attrs
		// The offset is a NumericLeaf: u16 below 0x8000, otherwise a u32 follows.
		raw := binary.LittleEndian.Uint16(body[nameAt:])
		if raw < 0x8000 {
			field.Offset = uint32(raw)
			nameAt += 2
		} else if nameAt+4 <= len(body) {
			field.Offset = binary.LittleEndian.Uint32(body[nameAt:])
			nameAt += 4
		}
		field.Name = pdbCString(body[nameAt:])
		if field.Name != "" {
			fields = append(fields, field)
		}
		// Advance past this member: its payload is fixed apart from the name, so the
		// next sub-record starts after the NUL-terminated name padded to 4 bytes.
		nameLen := len(field.Name) + 1
		next := nameAt + nameLen
		if pad := next % 4; pad != 0 {
			next += 4 - pad
		}
		if next <= offset {
			break
		}
		offset = next
	}
	return fields
}

func pdbCString(data []byte) string {
	end := indexByteZero(data)
	if end < 0 {
		return ""
	}
	return string(data[:end])
}

func pdbRenderAggregate(aggregate PDBAggregate) string {
	kind := "struct"
	if aggregate.Union {
		kind = "union"
	}
	rendered := fmt.Sprintf("%s %s", kind, aggregate.Name)
	if aggregate.Size > 0 {
		rendered += fmt.Sprintf(" /* %d bytes */", aggregate.Size)
	}
	if len(aggregate.Fields) == 0 {
		return rendered
	}
	rendered += " { "
	for position, field := range aggregate.Fields {
		if position > 0 {
			rendered += "; "
		}
		rendered += fmt.Sprintf("%s %s", field.Type, field.Name)
		if field.BitWidth > 0 {
			rendered += fmt.Sprintf(" : %d", field.BitWidth)
		}
	}
	return rendered + " }"
}
