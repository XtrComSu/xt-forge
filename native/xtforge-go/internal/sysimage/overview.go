// Package sysimage provides XT-Forge-SYS image inspection without external tools.
package sysimage

import (
	"archive/zip"
	"bytes"
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"xtforge-hub/internal/guard"
)

const maxIPAMember = 128 << 20

type OverviewResult struct {
	OK     bool    `json:"ok"`
	Engine string  `json:"engine"`
	Path   string  `json:"path"`
	Format string  `json:"format"`
	Member string  `json:"member,omitempty"`
	Images []Image `json:"images"`
	// Archive lists the members of a static archive, which has no single image.
	Archive []ArchiveMember `json:"archive,omitempty"`
}

// EntryPoint and address fields are preferred virtual addresses, before rebasing.
type Image struct {
	Arch            string   `json:"arch"`
	Bits            int      `json:"bits"`
	EntryPoint      *uint64  `json:"entry_point"`
	EntryFileOffset *uint64  `json:"entry_file_offset"`
	SliceOffset     uint64   `json:"slice_offset,omitempty"`
	Sections        []Region `json:"sections"`
	// SectionEntropy is populated for binary images only; archive and other
	// container-only results have no sections to profile.
	SectionEntropy []SectionEntropy `json:"section_entropy,omitempty"`
	Segments       []Region         `json:"segments"`
	Executable     []Region         `json:"executable_regions,omitempty"`
	Dependencies   []string         `json:"dependencies"`
	// Imports lists ELF symbols reached through GOT slots. It stays nil for
	// PE, Mach-O, and other formats, which have no ELF relocations.
	Imports []ELFImport `json:"imports,omitempty"`
	// Exports is the PE export list, decoded independently of the function
	// index: multiple exports can share one address, so a function-per-address
	// map cannot report the count honestly. ExportCount is its length.
	Exports     []PEExport `json:"exports,omitempty"`
	ExportCount int        `json:"export_count,omitempty"`
	// ObjC reports the Objective-C metadata recovered for naming, so the
	// structures behind a name are inspectable rather than implied.
	ObjC *objcMetadata `json:"objc,omitempty"`
	// DWARF reports debug-information symbols when the binary carries them.
	DWARF *dwarfMetadata `json:"dwarf,omitempty"`
	// Versions reports ELF symbol version requirements (GLIBC_2.34 and friends).
	Versions []ElfSymbolVersion `json:"versions,omitempty"`
	// DebugLink names a separate debug file, when the ELF records one.
	DebugLink *DebugLink `json:"debug_link,omitempty"`
	// Mode names the instruction set within an architecture, currently only for 32-bit
	// ARM: "arm" or "thumb". The two share bytes and cannot be told apart per
	// instruction, so the mode is decided once from the entry point.
	Mode string `json:"mode,omitempty"`
	// PDB records which symbol file supplied names for a PE, and whether it was
	// proven to match the binary rather than merely sitting beside it.
	PDB *PDBReference `json:"pdb,omitempty"`
	// IHEX holds a parsed Intel HEX file; SREC holds a parsed S-record file.
	// Both are text formats with no header, so they carry their own record.
	IHEX *IHEXImage `json:"ihex,omitempty"`
	SREC *SRECImage `json:"srec,omitempty"`
	// COFF holds a standalone COFF object. Such an object has no entry point and
	// no functions to index until it is linked, so those fields stay empty.
	COFF *COFFObject `json:"coff,omitempty"`
	// NE holds the header fields of a 16-bit New Executable. Its segment tables
	// are not parsed, so an NE image has no regions or functions to index.
	NE *NEImage `json:"ne,omitempty"`
	// AndroidBoot inventories a boot image header. There is deliberately no entry
	// point or function list: the kernel and ramdisk are compressed payloads this
	// reader does not decompress.
	AndroidBoot *AndroidBoot `json:"android_boot,omitempty"`
	// UEFI inventories a firmware volume. Section payloads are not decompressed, so
	// there is no entry point and no function list.
	UEFI *UEFIVolume `json:"uefi,omitempty"`
	// OTA inventories an Android OTA package: entries, the payload header fields and
	// the OTA metadata. The payload itself is not extracted.
	OTA *AndroidOTA `json:"android_ota,omitempty"`
	// Unknown is set only when no loader claimed the file. It carries the bounded
	// description from fallback.go instead of an error, so a caller always gets a
	// report for a regular file.
	Unknown *UnknownFile `json:"unknown,omitempty"`
	// path is the file the image came from, used to find sibling artefacts such as
	// a PDB. It is not serialized because it leaks local paths into reports.
	path      string
	functions map[uint64]Function
	// descentSeeds records .pdata begins so recursive descent can seed from the
	// exception directory even after a later pass changes the function index.
	descentSeeds []uint64
	warnings     []string
	fileSize     uint64
	littleEndian bool
	// exportsParsed distinguishes an image whose export table was examined and
	// found empty from one that has not been examined at all.
	exportsParsed bool
}

// Offset is relative to the beginning of the image slice.
type Region struct {
	Name     string `json:"name"`
	Address  uint64 `json:"address"`
	Size     uint64 `json:"size"`
	Offset   uint64 `json:"offset"`
	FileSize uint64 `json:"file_size"`
}

// OverviewWithRaw inspects a file, interpreting it as a headerless raw image when
// arch is non-empty. Raw mode exists because firmware dumps and extracted sections have
// no header at all, and "unknown format" is useless when the caller already knows the
// architecture and load address.
func OverviewWithRaw(filename, member, arch string, base uint64) (OverviewResult, error) {
	spec, err := ParseRawSpec(arch, base)
	if err != nil {
		return OverviewResult{}, err
	}
	return analyzeFileWithSpec(filename, member, false, nil, &spec)
}

func Overview(filename, member string) (OverviewResult, error) {
	return analyze(filename, member, false)
}

func analyze(filename, member string, indexFunctions bool) (OverviewResult, error) {
	return analyzeFile(filename, member, indexFunctions, nil)
}

func analyzeFile(filename, member string, indexFunctions bool, visit func(io.ReaderAt, OverviewResult) error) (OverviewResult, error) {
	return analyzeFileWithSpec(filename, member, indexFunctions, visit, nil)
}

// analyzeFileWithSpec is the internal inspection path. A non-nil spec means the
// caller supplied an explicit architecture and load address for a headerless
// file; it is used only where format detection gives up, never to shadow a
// format one of the loaders understands. The public Overview signature is
// unchanged: there is no --arch/--base plumbing on the overview command in the
// CLI, so only internal callers can supply a spec today.
func analyzeFileWithSpec(filename, member string, indexFunctions bool, visit func(io.ReaderAt, OverviewResult) error, spec *RawSpec) (OverviewResult, error) {
	canon, err := guard.ReadGuard(filename)
	if err != nil {
		return OverviewResult{}, err
	}
	stat, err := os.Stat(canon)
	if err != nil {
		return OverviewResult{}, err
	}
	if !stat.Mode().IsRegular() {
		return OverviewResult{}, fmt.Errorf("SYS analysis requires a regular file")
	}
	file, err := os.Open(canon)
	if err != nil {
		return OverviewResult{}, err
	}
	defer file.Close()

	result := OverviewResult{OK: true, Engine: "xt-forge-sys", Path: canon}
	var input io.ReaderAt = file
	inputSize := uint64(stat.Size())
	// container names the archive the payload came from; inspect() reports the
	// A static archive is a list of members, not one image, so it is answered
	// before any container or format detection.
	if archiveHead := kernelCacheHead(file, stat.Size()); IsArchive(archiveHead) {
		members, err := ListArchiveMembers(file, stat.Size(), 0)
		if err != nil {
			return OverviewResult{}, err
		}
		return OverviewResult{OK: true, Engine: "xt-forge-sys", Path: canon,
			Format: "archive", Images: []Image{}, Archive: members}, nil
	}
	// payload's own format, so the container label is reapplied afterwards.
	container := ""
	if strings.EqualFold(filepath.Ext(canon), ".ipa") {
		payload, name, err := openIPA(file, stat.Size(), member)
		if err != nil {
			return OverviewResult{}, err
		}
		result.Member = name
		container = "ipa"
		input = bytes.NewReader(payload)
		inputSize = uint64(len(payload))
	} else if isUDIF(file, stat.Size()) {
		payload, name, err := openDMG(file, stat.Size(), member)
		if err != nil {
			return OverviewResult{}, err
		}
		result.Member = name
		container = "dmg"
		input = bytes.NewReader(payload)
		inputSize = uint64(len(payload))
	} else if isDyldCache(dyldCacheHead(file, stat.Size())) {
		payload, name, err := openDyldCache(file, stat.Size(), member)
		if err != nil {
			return OverviewResult{}, err
		}
		result.Member = name
		container = "dyld"
		input = bytes.NewReader(payload)
		inputSize = uint64(len(payload))
	} else if isKernelCacheHead(kernelCacheHead(file, stat.Size())) {
		payload, name, err := openKernelCache(file, stat.Size())
		if err != nil {
			return OverviewResult{}, err
		}
		result.Member = name
		container = "kernelcache"
		input = bytes.NewReader(payload)
		inputSize = uint64(len(payload))
	} else if member != "" {
		return OverviewResult{}, fmt.Errorf("--member requires an IPA, DMG, dyld, or kernelcache container")
	}
	result.Format, result.Images, err = inspectWithSpec(input, inputSize, indexFunctions, canon, spec)
	if err != nil {
		return OverviewResult{}, err
	}
	// inspect() profiles sections on the indexFunctions path. The normal
	// overview path skips the heavy indexing but still reports section
	// entropy: reads are bounded to 8 MiB per section.
	if !indexFunctions && len(result.Images) > 0 {
		for i := range result.Images {
			profileImageRegions(input, &result.Images[i])
		}
	}
	for i := range result.Images {
		image := &result.Images[i]
		if image.EntryPoint == nil {
			continue
		}
		offset, ok := image.fileOffset(*image.EntryPoint)
		if !ok || image.SliceOffset > math.MaxInt64 || offset > math.MaxInt64-image.SliceOffset {
			continue
		}
		var probe [1]byte
		if _, err := input.ReadAt(probe[:], int64(offset+image.SliceOffset)); err == nil {
			image.EntryFileOffset = &offset
		}
	}
	if container != "" {
		if result.Format != "macho" {
			return OverviewResult{}, fmt.Errorf("%s member %q is not Mach-O", strings.ToUpper(container), result.Member)
		}
		// Keep the container's own name so a caller can tell an app bundle from a
		// bare Mach-O.
		result.Format = container
	}
	if visit != nil {
		if err := visit(input, result); err != nil {
			return OverviewResult{}, err
		}
	}
	return result, nil
}

func (image Image) fileOffset(address uint64) (uint64, bool) {
	return image.fileRange(address, 1)
}

func (image Image) fileRange(address, size uint64) (uint64, bool) {
	if size == 0 || size-1 > math.MaxUint64-address {
		return 0, false
	}
	end := address + (size - 1)
	regions := image.Segments
	if len(regions) == 0 {
		regions = image.Sections
	}
	var offset uint64
	var found, covered bool
	for _, region := range regions {
		start := max(address, region.Address)
		length := min(region.Size, region.FileSize)
		if start > end || start-region.Address >= length {
			continue
		}
		delta := start - region.Address
		if delta > math.MaxUint64-region.Offset || region.Offset+delta < start-address {
			return 0, false
		}
		candidate := region.Offset + delta - (start - address)
		if found && candidate != offset {
			return 0, false
		}
		offset, found = candidate, true
		covered = covered || (start == address && size <= length-delta)
	}
	if !covered || size-1 > math.MaxUint64-offset {
		return 0, false
	}
	if image.fileSize != 0 && (offset >= image.fileSize || size > image.fileSize-offset) {
		return 0, false
	}
	return offset, true
}

func openIPA(r io.ReaderAt, size int64, member string) ([]byte, string, error) {
	archive, err := zip.NewReader(r, size)
	if err != nil {
		return nil, "", fmt.Errorf("open IPA: %w", err)
	}
	var candidates []*zip.File
	for _, file := range archive.File {
		parts := strings.Split(file.Name, "/")
		if len(parts) < 3 || parts[0] != "Payload" || !strings.HasSuffix(parts[1], ".app") ||
			path.Clean(file.Name) != file.Name || strings.Contains(file.Name, "\\") || !file.Mode().IsRegular() {
			continue
		}
		if (member != "" && file.Name == member) ||
			(member == "" && len(parts) == 3 && parts[2] == strings.TrimSuffix(parts[1], ".app")) {
			candidates = append(candidates, file)
		}
	}
	if len(candidates) != 1 {
		return nil, "", fmt.Errorf("expected one IPA executable, found %d; specify its archive path with --member", len(candidates))
	}
	file := candidates[0]
	if file.UncompressedSize64 > maxIPAMember {
		return nil, "", fmt.Errorf("IPA member exceeds the %d MiB inspection limit", maxIPAMember>>20)
	}
	stream, err := file.Open()
	if err != nil {
		return nil, "", err
	}
	defer stream.Close()
	data, err := io.ReadAll(io.LimitReader(stream, maxIPAMember+1))
	if err != nil {
		return nil, "", err
	}
	if len(data) > maxIPAMember {
		return nil, "", fmt.Errorf("IPA member exceeds the %d MiB inspection limit", maxIPAMember>>20)
	}
	return data, file.Name, nil
}

// inspect resolves a file's format and images, and stamps each image with the path
// it came from so later stages can find sibling artefacts such as a PDB.
func inspect(r io.ReaderAt, size uint64, indexFunctions bool, sourcePath string) (string, []Image, error) {
	return inspectWithSpec(r, size, indexFunctions, sourcePath, nil)
}

// inspectWithSpec is inspect with an optional raw specification, which is used
// only when no known loader claims the input.
func inspectWithSpec(r io.ReaderAt, size uint64, indexFunctions bool, sourcePath string, spec *RawSpec) (string, []Image, error) {
	format, images, err := inspectFormat(r, size, indexFunctions, sourcePath, spec)
	for index := range images {
		images[index].path = sourcePath
	}
	return format, images, err
}

func inspectFormat(r io.ReaderAt, size uint64, indexFunctions bool, sourcePath string, spec *RawSpec) (format string, images []Image, err error) {
	var magic [4]byte
	if _, err := r.ReadAt(magic[:], 0); err != nil {
		// A headerless file can be shorter than the magic probe; an explicit
		// raw spec still gives the caller something analysable.
		if spec != nil {
			return rawImageFormat(r, size, sourcePath, *spec, indexFunctions)
		}
		return "", nil, fmt.Errorf("read binary magic: %w", err)
	}
	switch {
	case string(magic[:]) == "\x7fELF":
		file, err := elf.NewFile(r)
		if err != nil {
			return "", nil, err
		}
		image, err := elfImage(file)
		image.fileSize = size
		image.path = sourcePath
		if err == nil {
			populateELFMetadata(&image, file)
		}
		if err == nil && indexFunctions {
			profileImageRegions(r, &image)
			indexELF(&image, r, file)
			image.DWARF = readDWARF(r, "elf")
			image.applyDWARF(image.DWARF)
		}
		return "elf", []Image{image}, err
	case string(magic[:2]) == "MZ":
		// The DOS e_lfanew field points at the next signature. "NE" means a
		// 16-bit Windows New Executable, not a broken PE: report it as its own
		// format without trying to parse segments we do not need.
		if lfanew, ok := dosLfanew(r, size); ok && isNEAt(r, lfanew) {
			header, err := readNEImage(r, lfanew, size)
			if err != nil {
				return "", nil, err
			}
			image := Image{NE: header, fileSize: size, path: sourcePath}
			return "ne", []Image{image}, nil
		}
		file, note, err := openPE(r, size)
		if err != nil {
			return "", nil, err
		}
		image, err := peImage(r, file)
		image.fileSize = size
		image.path = sourcePath
		if note != "" {
			image.warnings = append(image.warnings, note)
		}
		if err == nil && indexFunctions {
			profileImageRegions(r, &image)
			indexPE(&image, r, file)
			image.DWARF = readDWARF(r, "pe")
			image.applyDWARF(image.DWARF)
		}
		return "pe", []Image{image}, err
	case binary.BigEndian.Uint32(magic[:]) == macho.MagicFat:
		file, err := macho.NewFatFile(r)
		if err != nil {
			return "", nil, err
		}
		images := make([]Image, 0, len(file.Arches))
		for _, arch := range file.Arches {
			image := machoImage(arch.File)
			image.SliceOffset = uint64(arch.Offset)
			if image.SliceOffset > size || uint64(arch.Size) > size-image.SliceOffset {
				return "", nil, fmt.Errorf("Mach-O slice exceeds image bounds")
			}
			image.fileSize = uint64(arch.Size)
			if indexFunctions {
				profileImageRegions(r, &image)
				slice := io.NewSectionReader(r, int64(arch.Offset), int64(arch.Size))
				indexMachO(&image, slice, arch.File)
				image.DWARF = readDWARF(slice, "macho")
				image.applyDWARF(image.DWARF)
			}
			images = append(images, image)
		}
		return "macho", images, nil
	case isThinMachO(magic):
		file, err := macho.NewFile(r)
		if err != nil {
			return "", nil, err
		}
		image := machoImage(file)
		image.fileSize = size
		image.path = sourcePath
		if indexFunctions {
			profileImageRegions(r, &image)
			indexMachO(&image, r, file)
			image.DWARF = readDWARF(r, "macho")
			image.applyDWARF(image.DWARF)
		}
		return "macho", []Image{image}, nil
	default:
		// A file that announces a format we claim to support, but that no loader
		// accepted, is a parse failure and must stay an error. Calling it "unknown"
		// would hide a broken container behind a generic report — the difference
		// between "I have never seen this" and "this is broken" matters.
		if claimed := claimedFormat(magic); claimed != "" {
			return "", nil, fmt.Errorf("%s: header is present but the file did not parse", claimed)
		}
		// A standalone COFF object has no MZ header, so the PE branch never sees it.
		// A zero SizeOfOptionalHeader marks the 20-byte header as an object rather
		// than an image: relocatable input with sections and symbols but no entry
		// point and no functions to index.
		var coffHead [18]byte
		if _, err := r.ReadAt(coffHead[:], 0); err == nil && IsCOFF(coffHead[:]) {
			if object, err := ReadCOFF(r, int64(size), 0); err == nil {
				return "coff", []Image{{COFF: &object}}, nil
			}
		}
		// A UEFI firmware volume carries "_FVH" at offset 0x28, past the zero vector
		// and filesystem GUID, so the four-byte probe cannot see it either.
		var uefiHead [64]byte
		if _, err := r.ReadAt(uefiHead[:], 0); err == nil && IsUEFIVolume(uefiHead[:]) {
			if volume, err := ReadUEFIVolume(r, int64(size), 0); err == nil {
				return "uefi", []Image{{UEFI: &volume}}, nil
			}
		}
		// An A/B OTA is a ZIP with payload.bin or META-INF/com/android metadata. An
		// ordinary ZIP is deliberately not claimed here.
		if IsAndroidOTA(uefiHead[:]) {
			if ota, err := ReadAndroidOTA(r, int64(size), 0); err == nil {
				return "androidota", []Image{{OTA: &ota}}, nil
			}
		}
		// An Android boot image announces itself with an eight-byte magic that the
		// four-byte format probe cannot see.
		var androidHead [8]byte
		if _, err := r.ReadAt(androidHead[:], 0); err == nil && IsAndroidBoot(androidHead[:]) {
			if boot, err := ReadAndroidBoot(r, int64(size)); err == nil {
				return "androidboot", []Image{{AndroidBoot: &boot}}, nil
			}
		}
		// Text-format firmware images. They begin with a character rather than a
		// magic, so they are recognised after the binary loaders have all declined.
		if text, err := readAllBounded(r, size, maxTextImage); err == nil {
			if IsIHEX(text) {
				if parsed, err := ParseIHEX(bytes.NewReader(text)); err == nil {
					return "ihex", []Image{{IHEX: &parsed}}, nil
				}
			}
			if IsSREC(text) {
				if parsed, err := ParseSREC(bytes.NewReader(text)); err == nil {
					return "srec", []Image{{SREC: &parsed}}, nil
				}
			}
		}
		// No loader claimed these bytes, but the caller told us how to read them:
		// an explicit architecture and base turn the blob into a raw image.
		if spec != nil {
			return rawImageFormat(r, size, sourcePath, *spec, indexFunctions)
		}
		// Anything else is described, not rejected. The caller decides whether an
		// unrecognised file is interesting; refusing to report anything forces a
		// trip to a hex dumper.
		return "unknown", []Image{fallbackImage(describeUnknown(r, int64(size)))}, nil
	}
}

// rawImageFormat loads an unclaimed input as a headerless image. It sits on the
// same path as the unknown-format report: a supplied spec changes what the
// fallback says, not which loader wins for recognised binaries.
func rawImageFormat(r io.ReaderAt, size uint64, sourcePath string, spec RawSpec, indexFunctions bool) (string, []Image, error) {
	if size > uint64(maxRawImage) {
		return "", nil, fmt.Errorf("raw image of %d bytes exceeds the %d MiB inspection limit", size, maxRawImage>>20)
	}
	image, err := RawImage(r, int64(size), spec)
	if err != nil {
		return "", nil, err
	}
	image.path = sourcePath
	if indexFunctions {
		profileImageRegions(r, &image)
	}
	return "raw", []Image{image}, nil
}

// claimedFormat names the container a file announces, when that container is one this
// engine claims to load. It exists so a malformed container is reported as broken
// rather than as an unrecognised format.
// maxTextImage bounds how much of a candidate text image is read for parsing.
// Intel HEX and S-record files expand several-fold, so 16 MiB of source is already a
// large firmware image; anything bigger is refused rather than buffered.
const maxTextImage = 16 << 20

// readAllBounded reads up to limit bytes, refusing anything larger.
func readAllBounded(r io.ReaderAt, size uint64, limit int64) ([]byte, error) {
	if int64(size) > limit {
		return nil, fmt.Errorf("file is larger than %d bytes", limit)
	}
	data := make([]byte, size)
	if _, err := r.ReadAt(data, 0); err != nil && len(data) != 0 {
		return nil, err
	}
	return data, nil
}

func claimedFormat(magic [4]byte) string {
	if string(magic[:]) == "IMG4" {
		return "IMG4 container"
	}
	if string(magic[:4]) == "dyld" {
		return "dyld shared cache"
	}
	if string(magic[:]) == "!<ar" {
		return "static archive"
	}
	return ""
}

func isThinMachO(magic [4]byte) bool {
	big := binary.BigEndian.Uint32(magic[:])
	little := binary.LittleEndian.Uint32(magic[:])
	return big == macho.Magic32 || big == macho.Magic64 || little == macho.Magic32 || little == macho.Magic64
}

func machoImage(file *macho.File) Image {
	image := Image{Arch: archName(file.Cpu.String()), Bits: 32, littleEndian: file.ByteOrder == binary.LittleEndian}
	if file.Magic == macho.Magic64 {
		image.Bits = 64
	}
	var text *macho.Segment
	var entryOffset *uint64
	var executableSections []Region
	for _, load := range file.Loads {
		if segment, ok := load.(*macho.Segment); ok {
			region := Region{segment.Name, segment.Addr, segment.Memsz, segment.Offset, segment.Filesz}
			image.Segments = append(image.Segments, region)
			if segment.Prot&4 != 0 {
				image.Executable = append(image.Executable, region)
			}
			if segment.Name == "__TEXT" {
				text = segment
			}
		}
		raw := load.Raw()
		const lcMain = 0x80000028
		if len(raw) >= 24 && file.ByteOrder.Uint32(raw) == lcMain {
			offset := file.ByteOrder.Uint64(raw[8:])
			entryOffset = &offset
		}
	}
	if text != nil && entryOffset != nil && *entryOffset < text.Filesz && *entryOffset <= math.MaxUint64-text.Addr {
		entry := text.Addr + *entryOffset
		image.EntryPoint = &entry
	}
	for _, section := range file.Sections {
		size := section.Size
		switch section.Flags & 0xff {
		case 0x1, 0xc, 0x12: // Zero-fill section types have no bytes in the file.
			size = 0
		}
		region := Region{section.Seg + "," + section.Name, section.Addr, section.Size, uint64(section.Offset), size}
		image.Sections = append(image.Sections, region)
		const instructionFlags = 0x80000400
		if size > 0 && section.Flags&instructionFlags != 0 {
			executableSections = append(executableSections, region)
		}
	}
	if len(executableSections) > 0 {
		image.Executable = executableSections
	}
	image.Dependencies, _ = file.ImportedLibraries()
	return image
}

// populateELFMetadata attaches symbol versions and a debug link to an ELF image.
// Both are optional: distro binaries usually carry versions, stripped ones rarely
// carry a debuglink.
func populateELFMetadata(image *Image, file *elf.File) {
	if image.Bits == 64 {
		image.Versions = ReadElfSymbolVersions(
			elfSectionBytes(file, ".gnu.version_r"), elfSectionBytes(file, ".gnu.version"),
			elfSectionBytes(file, ".dynsym"), elfSectionBytes(file, ".dynstr"), image.Bits)
	} else {
		image.Versions = ReadElfSymbolVersions(
			elfSectionBytes(file, ".gnu.version_r"), elfSectionBytes(file, ".gnu.version"),
			elfSectionBytes(file, ".dynsym"), elfSectionBytes(file, ".dynstr"), image.Bits)
	}
	if link, ok := ReadDebugLink(elfSectionBytes(file, ".gnu_debuglink")); ok {
		image.DebugLink = &link
	}
}

// elfSectionBytes returns a section's bytes, or nil when it is absent.
func elfSectionBytes(file *elf.File, name string) []byte {
	section := file.Section(name)
	if section == nil {
		return nil
	}
	data, err := section.Data()
	if err != nil {
		return nil
	}
	return data
}

func elfImage(file *elf.File) (Image, error) {
	image := Image{Arch: archName(file.Machine.String()), Bits: 32, littleEndian: file.ByteOrder == binary.LittleEndian}
	if file.Class == elf.ELFCLASS64 {
		image.Bits = 64
	}
	if file.Entry != 0 {
		entry := file.Entry
		// ARM marks Thumb code with bit 0 set on every code address, including the
		// entry point. The address itself is the even value.
		if file.Machine == elf.EM_ARM && entry&1 == 1 {
			image.Mode = "thumb"
			entry &^= 1
		}
		image.EntryPoint = &entry
	}
	for _, prog := range file.Progs {
		if prog.Type == elf.PT_LOAD {
			region := Region{prog.Type.String(), prog.Vaddr, prog.Memsz, prog.Off, prog.Filesz}
			image.Segments = append(image.Segments, region)
			if prog.Flags&elf.PF_X != 0 {
				image.Executable = append(image.Executable, region)
			}
		}
	}
	var executableSections []Region
	for _, section := range file.Sections {
		// A NOBITS section (.bss and friends) occupies memory but has no bytes in the
		// file, yet elf.Section.FileSize reports its size. Left alone, address-to-file
		// mapping treats .bss as file-backed and reads whatever happens to sit at that
		// offset — measured here, a reference into .bss resolved to a string out of
		// .comment.
		fileSize := section.FileSize
		if section.Type == elf.SHT_NOBITS {
			fileSize = 0
		}
		region := Region{section.Name, section.Addr, section.Size, section.Offset, fileSize}
		image.Sections = append(image.Sections, region)
		if section.FileSize > 0 && section.Type != elf.SHT_NOBITS &&
			section.Flags&(elf.SHF_EXECINSTR|elf.SHF_ALLOC) == elf.SHF_EXECINSTR|elf.SHF_ALLOC {
			executableSections = append(executableSections, region)
		}
	}
	if len(executableSections) > 0 {
		image.Executable = executableSections
	}
	libs, err := file.ImportedLibraries()
	image.Dependencies = libs
	image.Imports = ReadELFImports(file)
	return image, err
}

func peImage(r io.ReaderAt, file *pe.File) (Image, error) {
	// One table decides the PE architecture name, so ARM64EC and ARM64X are
	// distinguishable instead of collapsing into "arm64". A plain switch here
	// reported an x64-interop binary as ordinary arm64, which hides the mixed-ABI
	// calling convention from everything downstream.
	// The descriptive table uses Windows naming ("x86-64"), but everything
	// downstream switches on the engine's canonical names, so translate here.
	// Wiring the table's names straight through broke disasm on every x86-64 PE.
	machine := DescribePEMachine(file.Machine)
	image := Image{Arch: peCanonicalArch(machine), littleEndian: true}
	if machine.Emulated {
		image.warnings = append(image.warnings, "ARM64EC: arm64 code with x64 ABI interop")
	}
	if machine.Value == 0 {
		image.Arch = fmt.Sprintf("0x%x", file.Machine)
	}
	var base uint64
	var entry uint32
	var imports, exports pe.DataDirectory
	switch header := file.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		base, entry, image.Bits = uint64(header.ImageBase), header.AddressOfEntryPoint, 32
		if header.NumberOfRvaAndSizes > pe.IMAGE_DIRECTORY_ENTRY_IMPORT {
			imports = header.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_IMPORT]
		}
		if header.NumberOfRvaAndSizes > pe.IMAGE_DIRECTORY_ENTRY_EXPORT {
			exports = header.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_EXPORT]
		}
	case *pe.OptionalHeader64:
		base, entry, image.Bits = header.ImageBase, header.AddressOfEntryPoint, 64
		if header.NumberOfRvaAndSizes > pe.IMAGE_DIRECTORY_ENTRY_IMPORT {
			imports = header.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_IMPORT]
		}
		if header.NumberOfRvaAndSizes > pe.IMAGE_DIRECTORY_ENTRY_EXPORT {
			exports = header.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_EXPORT]
		}
	default:
		return image, fmt.Errorf("PE executable is missing its optional header")
	}
	if entry != 0 {
		if uint64(entry) > math.MaxUint64-base {
			return image, fmt.Errorf("PE entry point overflows its image base")
		}
		address := base + uint64(entry)
		image.EntryPoint = &address
	}
	for _, section := range file.Sections {
		if uint64(section.VirtualAddress) > math.MaxUint64-base {
			return image, fmt.Errorf("PE section address overflows its image base")
		}
		region := Region{section.Name, base + uint64(section.VirtualAddress), uint64(section.VirtualSize), uint64(section.Offset), uint64(section.Size)}
		image.Sections = append(image.Sections, region)
		if section.Characteristics&pe.IMAGE_SCN_MEM_EXECUTE != 0 {
			image.Executable = append(image.Executable, region)
		}
	}
	var err error
	image.Dependencies, err = peDependencies(r, image, base, imports)
	// Decode exports here so `re overview` reports the real count even though
	// it does not index functions. An unusable table is recorded as a reason,
	// not returned as an error.
	var exportReason string
	image.Exports, exportReason = parsePEExportsInFile(file, exports, base)
	image.ExportCount = len(image.Exports)
	image.exportsParsed = true
	if exportReason != "" {
		image.warnings = append(image.warnings, "exports unavailable, reason "+exportReason)
	}
	return image, err
}

func peDependencies(r io.ReaderAt, image Image, base uint64, directory pe.DataDirectory) ([]string, error) {
	if directory.VirtualAddress == 0 || directory.Size == 0 {
		return nil, nil
	}
	locate := func(rva uint64) (uint64, bool) {
		if rva > math.MaxUint64-base {
			return 0, false
		}
		return image.fileOffset(base + rva)
	}
	const descriptorSize, maxDescriptors = 20, 4096
	var dependencies []string
	seen := make(map[string]bool)
	for i := uint64(0); i < min(uint64(directory.Size)/descriptorSize, maxDescriptors); i++ {
		rva := uint64(directory.VirtualAddress) + i*descriptorSize
		offset, ok := locate(rva)
		end, endOK := locate(rva + descriptorSize - 1)
		if !ok || !endOK || end > math.MaxInt64 || end-offset != descriptorSize-1 {
			return nil, fmt.Errorf("PE import descriptor is not file-backed")
		}
		var descriptor [descriptorSize]byte
		if _, err := r.ReadAt(descriptor[:], int64(offset)); err != nil {
			return nil, fmt.Errorf("read PE import descriptor: %w", err)
		}
		if descriptor == [descriptorSize]byte{} {
			sort.Strings(dependencies)
			return dependencies, nil
		}
		nameRVA := uint64(binary.LittleEndian.Uint32(descriptor[12:16]))
		offset, ok = locate(nameRVA)
		if nameRVA == 0 || !ok || offset > math.MaxInt64 {
			return nil, fmt.Errorf("PE dependency name is not file-backed")
		}
		var name [1024]byte
		n, _ := r.ReadAt(name[:], int64(offset))
		length := bytes.IndexByte(name[:n], 0)
		if length <= 0 {
			return nil, fmt.Errorf("invalid PE dependency name")
		}
		end, endOK = locate(nameRVA + uint64(length))
		if !endOK || end-offset != uint64(length) {
			return nil, fmt.Errorf("PE dependency name is not contiguous")
		}
		value := string(name[:length])
		key := strings.ToLower(value)
		if !seen[key] {
			dependencies = append(dependencies, value)
			seen[key] = true
		}
	}
	return nil, fmt.Errorf("PE import directory is missing a terminator or exceeds %d descriptors", maxDescriptors)
}

// peCanonicalArch maps a described PE machine to the arch string the rest of the
// engine understands. Only the naming differs; the Emulated flag stays on the
// descriptor.
func peCanonicalArch(machine PEMachine) string {
	switch machine.Name {
	case "x86-64":
		return "x86_64"
	case "x86", "arm", "arm-thumb", "arm64", "ia64", "riscv32", "riscv64":
		return machine.Name
	case "arm64ec", "arm64x":
		// Both contain arm64 code; the variant is reported separately.
		return "arm64"
	}
	return machine.Name
}

func archName(name string) string {
	switch name {
	case "CpuAmd64", "EM_X86_64":
		return "x86_64"
	case "Cpu386", "EM_386":
		return "x86"
	case "CpuArm64", "EM_AARCH64":
		return "arm64"
	case "CpuArm", "EM_ARM":
		return "arm"
	default:
		return name
	}
}
