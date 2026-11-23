package sysimage

import (
	"debug/elf"
	"encoding/binary"
	"fmt"
	"io"
	"math"
)

func indexELFUnwind(image *Image, r io.ReaderAt, file *elf.File) {
	var address, offset, size uint64
	if section := file.Section(".eh_frame_hdr"); section != nil {
		address, offset, size = section.Addr, section.Offset, section.FileSize
	} else {
		for _, program := range file.Progs {
			if program.Type == elf.PT_GNU_EH_FRAME {
				address, offset, size = program.Vaddr, program.Off, program.Filesz
				break
			}
		}
	}
	if size == 0 {
		return
	}
	if size > maxFunctionTable || offset > math.MaxInt64-size {
		image.warnings = append(image.warnings, "ELF unwind header exceeds inspection limits")
		return
	}
	data := make([]byte, size)
	if _, err := r.ReadAt(data, int64(offset)); err != nil {
		image.warnings = append(image.warnings, "read ELF unwind header: "+err.Error())
		return
	}
	starts, err := ehFrameStarts(data, file.ByteOrder, address)
	if err != nil {
		image.warnings = append(image.warnings, "ELF unwind header: "+err.Error())
		return
	}
	for _, start := range starts {
		for _, program := range file.Progs {
			if program.Type == elf.PT_LOAD && program.Flags&elf.PF_X != 0 &&
				start >= program.Vaddr && start-program.Vaddr < program.Filesz {
				image.addFunction(start, 0, "", "elf_eh_frame_hdr")
				break
			}
		}
	}
}

// ehFrameStarts accepts the fixed-width encodings used by GNU ld and LLD.
// The search table holds (initial PC, FDE address) pairs relative to the header.
func ehFrameStarts(data []byte, order binary.ByteOrder, address uint64) ([]uint64, error) {
	if len(data) < 4 || data[0] != 1 {
		return nil, fmt.Errorf("invalid version or size")
	}
	if data[2] == 0xff || data[3] == 0xff {
		return nil, nil
	}
	var pointerSize, valueSize int
	switch data[1] {
	case 0x1b:
		pointerSize = 4
	case 0x1c:
		pointerSize = 8
	}
	switch data[3] {
	case 0x3b:
		valueSize = 4
	case 0x3c:
		valueSize = 8
	}
	if pointerSize == 0 || valueSize == 0 || data[2] != 0x03 {
		return nil, fmt.Errorf("unsupported encodings %#x/%#x/%#x", data[1], data[2], data[3])
	}
	start := 4 + pointerSize
	if len(data)-start < 4 {
		return nil, fmt.Errorf("missing table count")
	}
	count := uint64(order.Uint32(data[start:]))
	table := data[start+4:]
	stride := valueSize * 2
	if count > uint64(len(table)/stride) {
		return nil, fmt.Errorf("truncated search table")
	}
	starts := make([]uint64, 0, int(count))
	for i := 0; i < int(count); i++ {
		pair := table[i*stride:]
		var delta int64
		if valueSize == 4 {
			delta = int64(int32(order.Uint32(pair)))
		} else {
			delta = int64(order.Uint64(pair))
		}
		if delta >= 0 && uint64(delta) <= math.MaxUint64-address {
			starts = append(starts, address+uint64(delta))
		} else if delta < 0 {
			distance := uint64(-(delta + 1)) + 1
			if distance <= address {
				starts = append(starts, address-distance)
			}
		}
	}
	return starts, nil
}
