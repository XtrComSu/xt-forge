package sysimage

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
)

// PDBSymbol is one public symbol from a PDB.
type PDBSymbol struct {
	Name    string `json:"name"`
	Segment uint16 `json:"segment"` // 1-based section index
	Offset  uint32 `json:"offset"`  // offset within that section
}

const (
	// pdbMagic is the 32-byte MSF 7.00 superblock signature.
	pdbMagic = "Microsoft C/C++ MSF 7.00\r\n\x1aDS\x00\x00\x00"

	pdbHeaderLen      = 32 + 24 // magic followed by six u32 fields
	pdbPub32          = 0x110e  // S_PUB32 CodeView symbol record
	pdbPub32FixedLen  = 12      // bytes in a S_PUB32 record after Rectyp
	pdbDefaultLimit   = 20000
	pdbMaxBlockSize   = 1 << 24 // guard against absurd declared block sizes
	pdbMaxStreamBytes = 1 << 29 // 512 MiB per stream is already generous
	pdbMaxDirectory   = 1 << 28 // 256 MiB for the whole stream directory
	pdbMaxStreams     = 1 << 20 // and a bound on the stream count
)

// ReadPDBPublicSymbols parses a Microsoft PDB (MSF 7.0) container and returns
// its S_PUB32 public symbols. limit <= 0 means 20000 symbols.
//
// Only the MSF container and the CodeView symbol records are decoded. We scan
// all streams except 1-4 (PDB info, TPI, DBI and the name map) rather than
// parsing the DBI header to locate the global symbol stream: public records can
// appear in module streams as well, and scanning the remaining streams finds
// both without implementing the DBI header parse.
//
// Every offset and length is bounds-checked against size and the enclosing
// buffer; malformed records stop the scan of their stream instead of panicking.
func ReadPDBPublicSymbols(r io.ReaderAt, size int64, limit int) ([]PDBSymbol, error) {
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
	if limit <= 0 {
		limit = pdbDefaultLimit
	}
	// pos tracks the block-list cursor; it starts after the stream count and the
	// per-stream sizes.
	pos := uint64(4) + uint64(len(sizes))*4
	symbols := make([]PDBSymbol, 0)
	for i, streamSize := range sizes {
		// The DBI header parse is not implemented; skip the fixed metadata
		// streams and scan everything else for public symbols.
		// Block lists are walked even for skipped streams so the following
		// streams can still be located.
		blocks := (uint64(streamSize) + blockSize - 1) / blockSize
		need := blocks * 4
		if pos+need > uint64(len(dir)) {
			return nil, fmt.Errorf("pdb: truncated block list for stream %d", i)
		}
		blockList := dir[int(pos):int(pos+need)]
		pos += need

		if i >= 1 && i <= 4 || streamSize == 0 || streamSize == 0xffffffff || len(symbols) >= limit {
			continue
		}
		stream := make([]byte, int(streamSize))
		for b := range blocks {
			start := uint64(b) * blockSize
			want := blockSize
			if remain := uint64(streamSize) - start; remain < want {
				want = remain
			}
			block := binary.LittleEndian.Uint32(blockList[int(b)*4:])
			if err := pdbReadBlock(r, size, blockSize, uint32(numBlocks), block, stream[int(start):int(start+want)]); err != nil {
				return nil, fmt.Errorf("pdb: read stream %d block %d: %w", i, block, err)
			}
		}
		scanPDBPublicRecords(stream, limit-len(symbols), &symbols)
	}
	return symbols, nil
}

// scanPDBPublicRecords walks the CodeView records of one stream. Reclen counts
// the bytes after its own u16 field, so the next record starts at p+2+Reclen.
func scanPDBPublicRecords(stream []byte, room int, out *[]PDBSymbol) {
	for p := 0; room > 0 && p+2 <= len(stream); {
		reclen := int(binary.LittleEndian.Uint16(stream[p:]))
		if reclen == 0 || uint64(reclen)+2 > uint64(len(stream)-p) {
			return // a zero or overlong record invalidates the rest of the stream
		}
		next := p + 2 + reclen
		rectyp := binary.LittleEndian.Uint16(stream[p+2:])
		if rectyp == pdbPub32 && reclen >= pdbPub32FixedLen+1 {
			nameBytes := stream[p+2+pdbPub32FixedLen : next]
			if end := bytes.IndexByte(nameBytes, 0); end > 0 && pdbPrintableName(nameBytes[:end]) {
				name := string(nameBytes[:end])
				segment := binary.LittleEndian.Uint16(stream[p+2+10:])
				offset := binary.LittleEndian.Uint32(stream[p+2+6:])
				// "__imp_*" and other __ markers denote thunks or pragmas,
				// not function bodies.
				if segment != 0 && !bytes.HasPrefix(nameBytes, []byte("__")) {
					*out = append(*out, PDBSymbol{Name: name, Segment: segment, Offset: offset})
					room--
				}
			}
		}
		p = next
	}
}

func pdbPrintableName(name []byte) bool {
	for _, c := range name {
		if c < 0x20 || c > 0x7e {
			return false
		}
	}
	return len(name) > 0
}

// pdbReadAt reads exactly dst from an absolute file offset, refusing reads
// that extend beyond the declared file size.
func pdbReadAt(r io.ReaderAt, dst []byte, off uint64, size int64) error {
	if size < 0 || off > uint64(size) || uint64(len(dst)) > uint64(size)-off {
		return fmt.Errorf("read at %d exceeds file size %d", off, size)
	}
	if len(dst) == 0 {
		return nil
	}
	n, err := r.ReadAt(dst, int64(off))
	if n != len(dst) {
		if err == nil {
			err = io.ErrUnexpectedEOF
		}
		return fmt.Errorf("read at %d: %w", off, err)
	}
	return nil
}

// pdbReadBlock reads dst from one MSF block, validating the block number and
// the block's extent before touching the underlying reader.
func pdbReadBlock(r io.ReaderAt, size int64, blockSize uint64, numBlocks, block uint32, dst []byte) error {
	if numBlocks != 0 && block >= numBlocks {
		return fmt.Errorf("block %d is beyond block count %d", block, numBlocks)
	}
	off := uint64(block) * blockSize
	if off > uint64(size) || uint64(len(dst)) > uint64(size)-off {
		return fmt.Errorf("block %d exceeds file size %d", block, size)
	}
	return pdbReadAt(r, dst, off, size)
}

// pdbDirectory reads the MSF superblock and stream directory.
//
// Both the public-symbol reader and the info reader need this, and a second copy of
// the block-map arithmetic is exactly the kind of duplication that lets one copy rot
// silently, so it lives here once.
func pdbDirectory(r io.ReaderAt, size int64) (blockSize, numBlocks uint64, dir []byte, sizes []uint32, err error) {
	var header [pdbHeaderLen]byte
	if err := pdbReadAt(r, header[:], 0, size); err != nil {
		return 0, 0, nil, nil, fmt.Errorf("pdb: read superblock: %w", err)
	}
	if string(header[:len(pdbMagic)]) != pdbMagic {
		return 0, 0, nil, nil, fmt.Errorf("pdb: bad magic")
	}
	blockSize = uint64(binary.LittleEndian.Uint32(header[32:36]))
	blocks := uint64(binary.LittleEndian.Uint32(header[40:44]))
	dirBytes := binary.LittleEndian.Uint32(header[44:48])
	blockMapAddr := uint32(binary.LittleEndian.Uint32(header[52:56]))
	if blockSize < pdbHeaderLen || blockSize > pdbMaxBlockSize {
		return 0, 0, nil, nil, fmt.Errorf("pdb: invalid block size %d", blockSize)
	}
	if blocks != 0 && uint64(blockMapAddr) >= blocks {
		return 0, 0, nil, nil, fmt.Errorf("pdb: invalid block map address %d", blockMapAddr)
	}
	if uint64(dirBytes) > pdbMaxDirectory {
		return 0, 0, nil, nil, fmt.Errorf("pdb: directory is too large (%d bytes)", dirBytes)
	}
	dirBlocks := (uint64(dirBytes) + blockSize - 1) / blockSize
	if dirBlocks == 0 || dirBlocks*4 > blockSize {
		return 0, 0, nil, nil, fmt.Errorf("pdb: directory block map does not fit in one block")
	}
	blockMap := make([]byte, int(dirBlocks*4))
	if err := pdbReadBlock(r, size, blockSize, uint32(blocks), blockMapAddr, blockMap); err != nil {
		return 0, 0, nil, nil, fmt.Errorf("pdb: read directory block map: %w", err)
	}
	dir = make([]byte, int(dirBytes))
	for i := range dirBlocks {
		off := i * blockSize
		want := blockSize
		if remain := uint64(dirBytes) - off; remain < want {
			want = remain
		}
		block := binary.LittleEndian.Uint32(blockMap[int(i)*4:])
		if err := pdbReadBlock(r, size, blockSize, uint32(blocks), block, dir[int(off):int(off+want)]); err != nil {
			return 0, 0, nil, nil, fmt.Errorf("pdb: read directory block %d: %w", block, err)
		}
	}
	if len(dir) < 4 {
		return 0, 0, nil, nil, fmt.Errorf("pdb: truncated stream directory")
	}
	count := binary.LittleEndian.Uint32(dir[:4])
	if count > pdbMaxStreams || uint64(count)*4 > uint64(len(dir)-4) {
		return 0, 0, nil, nil, fmt.Errorf("pdb: invalid stream count %d", count)
	}
	sizes = make([]uint32, int(count))
	for i := range sizes {
		sizes[i] = binary.LittleEndian.Uint32(dir[4+int(i)*4:])
		if uint64(sizes[i]) > pdbMaxStreamBytes && sizes[i] != 0xffffffff {
			return 0, 0, nil, nil, fmt.Errorf("pdb: stream %d is too large (%d bytes)", i, sizes[i])
		}
	}
	return blockSize, blocks, dir, sizes, nil
}

// PDBInfo is the identity a PDB records about itself, used to prove that the file
// beside a binary is the one that binary was linked against.
type PDBInfo struct {
	GUID    string `json:"guid"`
	Age     uint32 `json:"age"`
	Version uint32 `json:"version"`
}

// ReadPDBInfo reads the identity from a PDB's info stream (stream 1).
func ReadPDBInfo(r io.ReaderAt, size int64) (PDBInfo, error) {
	if r == nil {
		return PDBInfo{}, fmt.Errorf("pdb: nil reader")
	}
	if size < pdbHeaderLen {
		return PDBInfo{}, fmt.Errorf("pdb: file is too short to hold an MSF 7.00 header")
	}
	blockSize, numBlocks, dir, sizes, err := pdbDirectory(r, size)
	if err != nil {
		return PDBInfo{}, err
	}
	if len(sizes) < 1 || sizes[1] == 0 || sizes[1] == 0xffffffff || sizes[1] < 28 {
		return PDBInfo{}, fmt.Errorf("pdb: no usable info stream")
	}
	// Walk past stream 0's block list to reach stream 1's.
	pos := uint64(4) + uint64(len(sizes))*4
	for i := 0; i < 1; i++ {
		pos += ((uint64(sizes[i]) + blockSize - 1) / blockSize) * 4
	}
	need := ((uint64(sizes[1]) + blockSize - 1) / blockSize) * 4
	if pos+need > uint64(len(dir)) {
		return PDBInfo{}, fmt.Errorf("pdb: truncated block list for the info stream")
	}
	blockList := dir[int(pos):int(pos+need)]
	stream := make([]byte, int(sizes[1]))
	for b := uint64(0); b < need/4; b++ {
		start := b * blockSize
		want := blockSize
		if remain := uint64(sizes[1]) - start; remain < want {
			want = remain
		}
		block := binary.LittleEndian.Uint32(blockList[int(b)*4:])
		if err := pdbReadBlock(r, size, blockSize, uint32(numBlocks), block, stream[int(start):int(start+want)]); err != nil {
			return PDBInfo{}, fmt.Errorf("pdb: read info stream: %w", err)
		}
	}
	return PDBInfo{
		Version: binary.LittleEndian.Uint32(stream[0:4]),
		Age:     binary.LittleEndian.Uint32(stream[8:12]),
		GUID:    formatGUIDBytes(stream[12:28]),
	}, nil
}
