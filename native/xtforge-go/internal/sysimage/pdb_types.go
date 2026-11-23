package sysimage

import (
	"encoding/binary"
	"fmt"
	"io"
)

// PDB type-stream census.
//
// This reads the TPI (type information) header and counts records by leaf kind. It
// deliberately decodes no types: a census is enough to tell an analyst whether a PDB
// carries type information at all, and it cannot be wrong in the way a half-finished
// type decoder can.
//
// The leaf-kind table below lists ONLY values verified against real PDBs produced
// here, because a wrong mapping is worse than none: it silently relabels records.
// Anything unlisted is reported as its hex value so it is visibly unclassified rather
// than confidently mislabelled.
//
// Verification method: build a PDB with clang -gcodeview + lld-link /debug, walk the
// TPI records here, and compare the per-kind counts with `llvm-pdbutil dump -types`
// for the same file. A fixture using structs, enums, pointers and a placed function
// produced 0x1002 Pointer, 0x1008 Procedure, 0x1201 ArgList, 0x1203 FieldList and
// 0x1505 Structure, and llvm-pdbutil reported exactly those five kinds in the same
// numbers. LF_MEMBER does not appear in the census because member records live inside
// a field list rather than as top-level records — which is also why a census must not
// be presented as a type count.
const (
	pdbLeafPointer   = 0x1002
	pdbLeafProcedure = 0x1008
	pdbLeafArgList   = 0x1201
	pdbLeafFieldList = 0x1203
	pdbLeafStructure = 0x1505
)

// pdbLeafNames maps verified leaf values to names. Add an entry only with a fixture
// that proves it.
var pdbLeafNames = map[uint16]string{
	pdbLeafPointer:   "Pointer",
	pdbLeafProcedure: "Procedure",
	pdbLeafArgList:   "ArgList",
	pdbLeafFieldList: "FieldList",
	pdbLeafStructure: "Structure",
}

// pdbTPIStreamIndex is the type-information stream in an MSF container.
const pdbTPIStreamIndex = 2

// PDBTypeCensus summarises a PDB's TPI stream without decoding type records.
type PDBTypeCensus struct {
	Version     uint32         `json:"version"`
	HeaderSize  uint32         `json:"header_size"`
	RecordCount uint32         `json:"record_count"`
	Kinds       map[string]int `json:"kinds"`
	Bytes       int            `json:"bytes"`
	Truncated   bool           `json:"truncated"`
}

const (
	pdbTPIMinHeader  = 56
	pdbTPIMaxRecords = 200000
)

// ReadPDBTypeCensus reads the TPI stream header and counts records by leaf kind.
func ReadPDBTypeCensus(r io.ReaderAt, size int64) (PDBTypeCensus, error) {
	if r == nil {
		return PDBTypeCensus{}, fmt.Errorf("pdb: nil reader")
	}
	if size < pdbHeaderLen {
		return PDBTypeCensus{}, fmt.Errorf("pdb: file is too short to hold an MSF 7.00 header")
	}
	blockSize, numBlocks, dir, sizes, err := pdbDirectory(r, size)
	if err != nil {
		return PDBTypeCensus{}, err
	}
	if len(sizes) <= pdbTPIStreamIndex || sizes[pdbTPIStreamIndex] == 0 || sizes[pdbTPIStreamIndex] == 0xffffffff {
		return PDBTypeCensus{}, fmt.Errorf("pdb: no type information stream")
	}
	stream, err := pdbStream(r, size, blockSize, numBlocks, dir, sizes, pdbTPIStreamIndex)
	if err != nil {
		return PDBTypeCensus{}, err
	}
	if len(stream) < pdbTPIMinHeader {
		return PDBTypeCensus{}, fmt.Errorf("pdb: type stream header is truncated")
	}
	census := PDBTypeCensus{
		Version:    binary.LittleEndian.Uint32(stream[0:4]),
		HeaderSize: binary.LittleEndian.Uint32(stream[4:8]),
		Kinds:      map[string]int{},
		Bytes:      len(stream),
	}
	if census.HeaderSize < pdbTPIMinHeader || uint64(census.HeaderSize) >= uint64(len(stream)) {
		return PDBTypeCensus{}, fmt.Errorf("pdb: implausible type header size %d", census.HeaderSize)
	}
	for offset := int(census.HeaderSize); offset+4 <= len(stream); {
		if census.RecordCount >= pdbTPIMaxRecords {
			census.Truncated = true
			break
		}
		recordLen := int(binary.LittleEndian.Uint16(stream[offset:]))
		if recordLen == 0 || offset+2+recordLen > len(stream) {
			break
		}
		leaf := binary.LittleEndian.Uint16(stream[offset+2:])
		name, known := pdbLeafNames[leaf]
		if !known {
			name = fmt.Sprintf("0x%04x", leaf)
		}
		census.Kinds[name]++
		census.RecordCount++
		offset += 2 + recordLen
	}
	return census, nil
}

// pdbStream reassembles one stream from its block list.
//
// The block list for stream N starts after the stream count, all stream sizes, and the
// block lists of every earlier stream — the same cursor pdbDirectory's callers walk.
func pdbStream(r io.ReaderAt, size int64, blockSize, numBlocks uint64, dir []byte, sizes []uint32, want int) ([]byte, error) {
	if want < 0 || want >= len(sizes) {
		return nil, fmt.Errorf("pdb: stream %d does not exist", want)
	}
	pos := uint64(4) + uint64(len(sizes))*4
	for index := 0; index < want; index++ {
		pos += ((uint64(sizes[index]) + blockSize - 1) / blockSize) * 4
	}
	need := ((uint64(sizes[want]) + blockSize - 1) / blockSize) * 4
	if pos+need > uint64(len(dir)) {
		return nil, fmt.Errorf("pdb: truncated block list for stream %d", want)
	}
	blockList := dir[int(pos):int(pos+need)]
	stream := make([]byte, int(sizes[want]))
	for blockIndex := uint64(0); blockIndex < need/4; blockIndex++ {
		start := blockIndex * blockSize
		chunk := blockSize
		if remain := uint64(sizes[want]) - start; remain < chunk {
			chunk = remain
		}
		block := binary.LittleEndian.Uint32(blockList[int(blockIndex)*4:])
		if err := pdbReadBlock(r, size, blockSize, uint32(numBlocks), block, stream[int(start):int(start+chunk)]); err != nil {
			return nil, fmt.Errorf("pdb: read stream %d block %d: %w", want, block, err)
		}
	}
	return stream, nil
}
