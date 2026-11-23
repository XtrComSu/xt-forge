package sysimage

import (
	"bytes"
	"encoding/binary"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"testing"
)

// syntheticNE is just enough MZ + NE header to identify the format. Segment
// tables are intentionally absent: identification must not depend on them.
func syntheticNE() []byte {
	buf := make([]byte, 0x100)
	copy(buf, "MZ")
	const lfanew = 0x60
	binary.LittleEndian.PutUint32(buf[eLfanewOffset:eLfanewOffset+4], lfanew)
	ne := buf[lfanew:]
	copy(ne, "NE")
	ne[2], ne[3] = 3, 10 // major, minor
	binary.LittleEndian.PutUint16(ne[neFlagsOffset:], 0x1234)
	ne[neTargetOSOffset] = 2 // Windows
	return buf
}

func TestPNESynthetic(t *testing.T) {
	buf := syntheticNE()
	format, images, err := inspect(bytes.NewReader(buf), uint64(len(buf)), false, "")
	if err != nil {
		t.Fatalf("inspect(synthetic NE): %v", err)
	}
	if format != "ne" || len(images) != 1 {
		t.Fatalf("inspect(synthetic NE) = (%q, %d images), want (\"ne\", 1)", format, len(images))
	}
	header := images[0].NE
	if header == nil {
		t.Fatal("synthetic NE image has no NE header record")
	}
	if header.ELfanew != 0x60 || header.TargetOS != 2 || header.Flags != 0x1234 {
		t.Fatalf("NE fields = (lfanew %#x, OS %d, flags %#x), want (0x60, 2, 0x1234)",
			header.ELfanew, header.TargetOS, header.Flags)
	}

	path := filepath.Join(t.TempDir(), "synthetic.exe")
	if err := os.WriteFile(path, buf, 0o600); err != nil {
		t.Fatal(err)
	}
	overview, err := Overview(path, "")
	if err != nil {
		t.Fatalf("Overview(synthetic NE): %v", err)
	}
	if !overview.OK || overview.Format != "ne" || len(overview.Images) != 1 || overview.Images[0].NE == nil {
		t.Fatalf("Overview(synthetic NE) = %+v, want ok/ne/one NE image", overview)
	}
}

// Paths are derived from the environment, never hardcoded: a committed test may not name a
// developer's home directory, and these Wine directories are only an example location.
func wineDir(elem ...string) string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(append([]string{home, ".wine", "drive_c", "windows"}, elem...)...)
}

var neFilenames = []string{
	"avifile.dll", "commdlg.dll", "compobj.dll", "ctl3d.dll", "ctl3dv2.dll",
	"dispdib.dll", "gdi.exe", "imm.dll", "krnl386.exe", "lzexpand.dll",
	"msacm.dll", "msvideo.dll",
}

func TestPNERealSysWOW64(t *testing.T) {
	stat, err := os.Stat(wineDir("syswow64"))
	if err != nil || !stat.IsDir() {
		t.Skipf("syswow64 directory %s is absent: %v", wineDir("syswow64"), err)
	}
	for _, name := range neFilenames {
		path := filepath.Join(wineDir("syswow64"), name)
		overview, err := Overview(path, "")
		if err != nil {
			t.Errorf("%s: Overview: %v", name, err)
			continue
		}
		if !overview.OK || overview.Format != "ne" || len(overview.Images) != 1 {
			t.Errorf("%s: Overview ok=%v format=%q images=%d, want ok/ne/1",
				name, overview.OK, overview.Format, len(overview.Images))
			continue
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		lfanew := binary.LittleEndian.Uint32(raw[eLfanewOffset:])
		header := overview.Images[0].NE
		if header == nil || header.ELfanew != lfanew ||
			header.TargetOS != raw[lfanew+neTargetOSOffset] ||
			header.Flags != binary.LittleEndian.Uint16(raw[lfanew+neFlagsOffset:]) {
			t.Errorf("%s: NE fields = %+v, want lfanew %#x from the file", name, header, lfanew)
		}
	}
}

func kernelbaseCandidates() []string {
	return []string{
		"/usr/lib/wine/x86_64-windows/kernelbase.dll",
		wineDir("system32", "kernelbase.dll"),
	}
}

func existingKernelbase(t *testing.T) []string {
	t.Helper()
	var paths []string
	for _, path := range kernelbaseCandidates() {
		if stat, err := os.Stat(path); err == nil && stat.Mode().IsRegular() {
			paths = append(paths, path)
		}
	}
	if len(paths) == 0 {
		t.Skip("no kernelbase.dll under Wine directories")
	}
	return paths
}

func TestPENEKernelBase(t *testing.T) {
	for _, path := range existingKernelbase(t) {
		overview, err := Overview(path, "")
		if err != nil {
			t.Errorf("%s: Overview: %v", path, err)
			continue
		}
		if !overview.OK || overview.Format != "pe" || len(overview.Images) != 1 {
			t.Errorf("%s: Overview ok=%v format=%q images=%d, want ok/pe/1",
				path, overview.OK, overview.Format, len(overview.Images))
			continue
		}
		if overview.Images[0].ExportCount == 0 {
			t.Errorf("%s: no exports decoded from the PE export directory", path)
		}
	}
}

// syntheticPEWithBrokenExports builds a small but valid PE whose export
// directory claims thousands of names while the mapped section holds only a
// few bytes. It exercises the image-level path, not just the array decoder.
func syntheticPEWithBrokenExports() []byte {
	const (
		lfanew    = 0x40
		optSize   = 0xe0
		sectionVA = 0x2000
	)
	buf := make([]byte, 0x400)
	copy(buf, "MZ")
	binary.LittleEndian.PutUint32(buf[eLfanewOffset:], lfanew)
	copy(buf[lfanew:], "PE\x00\x00")
	coff := buf[lfanew+4:]
	binary.LittleEndian.PutUint16(coff[0:], 0x014c)   // i386
	binary.LittleEndian.PutUint16(coff[2:], 1)        // one section
	binary.LittleEndian.PutUint16(coff[16:], optSize) // SizeOfOptionalHeader
	binary.LittleEndian.PutUint16(coff[18:], 0x0102)  // executable, 32-bit

	optional := buf[lfanew+24:]
	binary.LittleEndian.PutUint16(optional[0:], 0x10b) // PE32
	binary.LittleEndian.PutUint32(optional[28:], 0x400000)
	binary.LittleEndian.PutUint32(optional[32:], 0x1000) // SectionAlignment
	binary.LittleEndian.PutUint32(optional[36:], 0x200)  // FileAlignment
	binary.LittleEndian.PutUint32(optional[60:], 0x200)  // SizeOfHeaders
	binary.LittleEndian.PutUint16(optional[92:], 16)     // NumberOfRvaAndSizes
	binary.LittleEndian.PutUint32(optional[96:], sectionVA)
	binary.LittleEndian.PutUint32(optional[100:], 0x1000) // oversized export directory

	section := buf[lfanew+24+optSize:]
	copy(section, ".edata\x00\x00")
	binary.LittleEndian.PutUint32(section[8:], 0x200)
	binary.LittleEndian.PutUint32(section[12:], sectionVA)
	binary.LittleEndian.PutUint32(section[16:], 0x200)
	binary.LittleEndian.PutUint32(section[20:], 0x200)
	binary.LittleEndian.PutUint32(section[36:], 0x40000040)

	export := buf[0x200:]
	binary.LittleEndian.PutUint32(export[16:], 1)    // ordinal base
	binary.LittleEndian.PutUint32(export[20:], 2)    // NumberOfFunctions
	binary.LittleEndian.PutUint32(export[24:], 1000) // NumberOfNames, far too many
	binary.LittleEndian.PutUint32(export[28:], sectionVA+0x40)
	binary.LittleEndian.PutUint32(export[32:], sectionVA+0x80)
	binary.LittleEndian.PutUint32(export[36:], sectionVA+0xa0)
	return buf
}

func TestPEExportTruncatedDoesNotFailImage(t *testing.T) {
	buf := syntheticPEWithBrokenExports()
	format, images, err := inspect(bytes.NewReader(buf), uint64(len(buf)), false, "")
	if err != nil {
		t.Fatalf("inspect(PE with truncated exports): %v", err)
	}
	if format != "pe" || len(images) != 1 {
		t.Fatalf("inspect(PE with truncated exports) = (%q, %d images), want (\"pe\", 1)", format, len(images))
	}

	path := filepath.Join(t.TempDir(), "broken-exports.dll")
	if err := os.WriteFile(path, buf, 0o600); err != nil {
		t.Fatal(err)
	}
	overview, err := Overview(path, "")
	if err != nil || !overview.OK || overview.Format != "pe" {
		t.Fatalf("Overview(PE with truncated exports): ok=%v format=%q err=%v", overview.OK, overview.Format, err)
	}
	index, err := Functions(path, "", "", 100)
	if err != nil || !index.OK || len(index.Images) != 1 {
		t.Fatalf("Functions(PE with truncated exports): ok=%v images=%d err=%v", index.OK, len(index.Images), err)
	}
	if len(index.Images[0].Warnings) == 0 {
		t.Fatal("truncated export table produced no 'exports unavailable' reason")
	}
	joined := ""
	for _, warning := range index.Images[0].Warnings {
		joined += warning + " "
	}
	if !bytes.Contains([]byte(joined), []byte("exports unavailable, reason")) {
		t.Fatalf("warnings do not explain the missing exports: %q", joined)
	}
}

func TestPEExportCountMatchesReadobj(t *testing.T) {
	paths := existingKernelbase(t)
	readobj, err := exec.LookPath("llvm-readobj")
	if err != nil {
		t.Skipf("llvm-readobj is unavailable: %v", err)
	}
	namePattern := regexp.MustCompile(`(?m)^\s*Name:\s+(\S+)\s*$`)
	for _, path := range paths {
		out, err := exec.Command(readobj, "--coff-exports", path).Output()
		if err != nil {
			t.Fatalf("llvm-readobj --coff-exports %s: %v", path, err)
		}
		seen := map[string]bool{}
		for _, match := range namePattern.FindAllSubmatch(out, -1) {
			seen[string(match[1])] = true
		}
		overview, err := Overview(path, "")
		if err != nil {
			t.Fatalf("Overview(%s): %v", path, err)
		}
		got := overview.Images[0].ExportCount
		if got != len(seen) {
			t.Errorf("%s: export count %d, llvm-readobj reports %d", path, got, len(seen))
		} else {
			t.Logf("%s: export count %d agrees with llvm-readobj", path, got)
		}
	}
}
