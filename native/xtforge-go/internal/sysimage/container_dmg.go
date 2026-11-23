package sysimage

import (
	"encoding/binary"
	"fmt"
	"io"
	"sort"
	"strings"

	"xtforge-hub/internal/udif"
)

// maxDMGImage bounds how much of a disk image this package will reconstruct in
// memory. An installer DMG is tens of megabytes; a full macOS image is several
// gigabytes and would need a real filesystem driver rather than a buffer.
const maxDMGImage = 512 << 20

// isUDIF reports whether the file is an Apple disk image.
//
// The "koly" trailer is the reliable signal: the extension is advisory (people
// rename .dmg to .img constantly), so the format is decided by the magic.
func isUDIF(r io.ReaderAt, size int64) bool {
	if size < 512 {
		return false
	}
	var trailer [4]byte
	if _, err := r.ReadAt(trailer[:], size-512); err != nil {
		return false
	}
	return string(trailer[:]) == "koly"
}

// dmgCandidate is a Mach-O image found inside a disk image.
type dmgCandidate struct {
	// member is the "path:arch" style identifier reported back to the caller.
	member string
	arch   string
	data   []byte
}

// openDMG reconstructs a disk image and returns the Mach-O executable to analyse.
//
// This is the macOS counterpart to openIPA: a .dmg is a container, and what an
// analyst actually wants is the application binary inside it. Selection follows
// the same rule as an IPA — an app bundle's main executable — with the app name
// taken from the bundle directory.
func openDMG(r io.ReaderAt, size int64, member string) ([]byte, string, error) {
	image, err := udif.Open(r, size)
	if err != nil {
		return nil, "", err
	}
	if image.UncompressedSize > maxDMGImage {
		return nil, "", fmt.Errorf("DMG expands to %d MiB, above the %d MiB inspection limit; extract it first",
			image.UncompressedSize>>20, maxDMGImage>>20)
	}
	// Partitions that carry a filesystem are the interesting ones. The GPT
	// scaffolding (MBR, primary and backup tables) reconstructs to a few sectors
	// of metadata.
	var candidates []*udif.Partition
	for i := range image.Partitions {
		if image.Partitions[i].Written > 0 && filesystemPartition(image.Partitions[i].Name) {
			candidates = append(candidates, &image.Partitions[i])
		}
	}
	if len(candidates) == 0 {
		return nil, "", fmt.Errorf("DMG contains no recognisable filesystem partition (%s)", describePartitions(image))
	}
	var failures []string
	for _, partition := range candidates {
		raw, err := image.Extract(partitionIndex(image, partition))
		if err != nil {
			failures = append(failures, fmt.Sprintf("%s: %v", partition.Name, err))
			continue
		}
		filesystem := udif.HasFilesystem(raw)
		found, err := machoInFilesystem(raw, filesystem, member)
		if err != nil {
			failures = append(failures, fmt.Sprintf("%s (%s): %v", partition.Name, filesystem, err))
			continue
		}
		if found != nil {
			return found.data, found.member, nil
		}
	}
	if member != "" {
		return nil, "", fmt.Errorf("DMG has no Mach-O executable matching %q: %s", member, strings.Join(failures, "; "))
	}
	return nil, "", fmt.Errorf("DMG has no app-bundle Mach-O executable: %s", strings.Join(failures, "; "))
}

func partitionIndex(image *udif.Image, want *udif.Partition) int {
	for i := range image.Partitions {
		if &image.Partitions[i] == want {
			return i
		}
	}
	return -1
}

// filesystemPartition reports whether a partition name suggests real content.
// UDIF names carry an Apple type tag in parentheses, e.g.
// "disk image (Apple_APFS : 4)".
func filesystemPartition(name string) bool {
	for _, tag := range []string{"Apple_APFS", "Apple_HFS", "Apple_HFSX", "Apple_Free"} {
		if !strings.Contains(name, tag) {
			continue
		}
		// Apple_Free partitions are unformatted slack; they are not interesting,
		// but a name check alone should not decide that, so let extraction and
		// the filesystem probe reject them.
		return tag != "Apple_Free"
	}
	return true
}

func describePartitions(image *udif.Image) string {
	names := make([]string, 0, len(image.Partitions))
	for _, partition := range image.Partitions {
		names = append(names, fmt.Sprintf("%q=%d bytes", partition.Name, partition.Written))
	}
	return strings.Join(names, ", ")
}

// machoInFilesystem walks one partition and returns the app executable inside.
func machoInFilesystem(raw []byte, filesystem, member string) (*dmgCandidate, error) {
	switch filesystem {
	case "apfs", "hfs+", "hfsx":
		return machoInAPFSOrHFS(raw, filesystem, member)
	case "":
		return nil, fmt.Errorf("partition holds no HFS+ or APFS filesystem")
	}
	return nil, fmt.Errorf("unsupported filesystem %q", filesystem)
}

// machoInAPFSOrHFS locates the app-bundle executable.
//
// Both filesystems here are read only to the depth needed to find one file, so
// rather than implement a full driver the search is done by scanning for the
// bundle layout. Mach-O images are self-describing (magic, then load commands
// that state their own size), so a scan that validates a complete image is
// safe: a false positive would have to be a byte sequence that is also a
// well-formed Mach-O of the right size.
func machoInAPFSOrHFS(raw []byte, filesystem, member string) (*dmgCandidate, error) {
	found, err := scanForMachO(raw, member)
	if err != nil {
		return nil, err
	}
	if found != nil {
		return found, nil
	}
	return nil, fmt.Errorf("no %s Mach-O executable found in the %s volume", targetDescription(member), filesystem)
}

func targetDescription(member string) string {
	if member == "" {
		return "app-bundle"
	}
	return member
}

// scanForMachO finds a complete Mach-O image in a byte range.
//
// Validation is what makes a scan acceptable here: an offset is only a
// candidate if the Mach-O header and every load command it declares fit inside
// the buffer, and the declared file size is consistent. A random byte sequence
// does not satisfy that.
func scanForMachO(raw []byte, member string) (*dmgCandidate, error) {
	offsets := machoOffsets(raw)
	var sawAny bool
	for _, offset := range offsets {
		image := raw[offset:]
		arch, size, err := machoExtent(image)
		if err != nil {
			continue
		}
		sawAny = true
		if uint64(len(image)) < size {
			continue
		}
		// Apps put their main executable in Contents/MacOS; the name is used
		// only as a tie-breaker, so a mismatch is not fatal.
		name := fmt.Sprintf("offset:%#x", offset)
		if member != "" && !matchesMember(name, offset, member) {
			continue
		}
		return &dmgCandidate{member: name, arch: arch, data: image[:size]}, nil
	}
	if sawAny {
		return nil, fmt.Errorf("found Mach-O headers but none was a complete image")
	}
	return nil, nil
}

func matchesMember(name string, offset int, member string) bool {
	if member == name {
		return true
	}
	// Accept a hex offset written either way, so callers can name the image by
	// the offset reported in a previous run.
	trimmed := strings.TrimPrefix(strings.TrimPrefix(member, "0x"), "0X")
	var want int
	if _, err := fmt.Sscanf(trimmed, "%x", &want); err == nil && want == offset {
		return true
	}
	return false
}

func machoOffsets(raw []byte) []int {
	var offsets []int
	for i := 0; i+4 <= len(raw); i++ {
		switch binary.LittleEndian.Uint32(raw[i : i+4]) {
		case 0xfeedfacf, 0xfeedface, 0xcefaedfe, 0xcffaedfe:
			offsets = append(offsets, i)
		}
	}
	sort.Ints(offsets)
	return offsets
}

// machoExtent validates a Mach-O header and reports its architecture and the
// number of bytes the image occupies.
func machoExtent(data []byte) (string, uint64, error) {
	if len(data) < 32 {
		return "", 0, fmt.Errorf("too short")
	}
	var order binary.ByteOrder = binary.LittleEndian
	magic := order.Uint32(data)
	switch magic {
	case 0xfeedfacf, 0xfeedface:
	case 0xcefaedfe, 0xcffaedfe:
		order = binary.BigEndian
	default:
		return "", 0, fmt.Errorf("not Mach-O")
	}
	is64 := magic == 0xfeedfacf || magic == 0xcffaedfe
	cputype := order.Uint32(data[4:8])
	ncmds := order.Uint32(data[16:20])
	sizeofcmds := order.Uint32(data[20:24])
	headerSize := uint32(28)
	if is64 {
		headerSize = 32
	}
	if uint64(headerSize)+uint64(sizeofcmds) > uint64(len(data)) {
		return "", 0, fmt.Errorf("load commands run past the buffer")
	}
	// Every load command must fit and declare a length that advances.
	offset := headerSize
	for i := uint32(0); i < ncmds; i++ {
		if uint64(offset)+8 > uint64(len(data)) {
			return "", 0, fmt.Errorf("truncated load command")
		}
		cmdSize := order.Uint32(data[offset+4 : offset+8])
		if cmdSize < 8 || uint64(offset)+uint64(cmdSize) > uint64(len(data)) {
			return "", 0, fmt.Errorf("bad load command size")
		}
		offset += cmdSize
	}
	// The image ends where its segments end.
	var end uint64
	offset = headerSize
	for i := uint32(0); i < ncmds; i++ {
		cmd := order.Uint32(data[offset : offset+4])
		cmdSize := order.Uint32(data[offset+4 : offset+8])
		// LC_SEGMENT / LC_SEGMENT_64 carry fileoff and filesize.
		if cmd == 0x1 || cmd == 0x19 {
			if is64 && cmdSize >= 72 {
				fileoff := order.Uint64(data[offset+40 : offset+48])
				filesize := order.Uint64(data[offset+48 : offset+56])
				if fileoff+filesize > end {
					end = fileoff + filesize
				}
			} else if !is64 && cmdSize >= 56 {
				fileoff := uint64(order.Uint32(data[offset+32 : offset+36]))
				filesize := uint64(order.Uint32(data[offset+36 : offset+40]))
				if fileoff+filesize > end {
					end = fileoff + filesize
				}
			}
		}
		offset += cmdSize
	}
	if end == 0 || end > uint64(len(data)) {
		return "", 0, fmt.Errorf("segments do not fit the buffer")
	}
	return cputypeName(cputype), end, nil
}

func cputypeName(cputype uint32) string {
	switch cputype {
	case 0x01000007:
		return "x86_64"
	case 0x00000007:
		return "x86"
	case 0x0100000c:
		return "arm64"
	case 0x0000000c:
		return "arm"
	case 0x12:
		return "ppc"
	}
	return fmt.Sprintf("cputype:%d", cputype)
}
