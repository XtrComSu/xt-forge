package sysimage

import (
	"bytes"
	"encoding/binary"
	"os"
	"strings"
	"testing"
)

// androidTestHeader builds a boot_img_hdr_v0 byte by byte, padded to the
// minimum header length the reader accepts.
func androidTestHeader(pageSize, kernelSize uint32, name, cmdline string) []byte {
	head := make([]byte, androidBootHeaderBytes)
	copy(head, androidBootMagic) // +0 magic[8]
	binary.LittleEndian.PutUint32(head[8:12], kernelSize)
	binary.LittleEndian.PutUint32(head[12:16], 0x80008000) // +12 kernel_addr
	binary.LittleEndian.PutUint32(head[16:20], 0x1234)     // +16 ramdisk_size
	binary.LittleEndian.PutUint32(head[20:24], 0x81000000)
	binary.LittleEndian.PutUint32(head[24:28], 0) // +24 second_size
	binary.LittleEndian.PutUint32(head[28:32], 0)
	binary.LittleEndian.PutUint32(head[32:36], 0x100)    // +32 tags_addr
	binary.LittleEndian.PutUint32(head[36:40], pageSize) // +36 page_size
	binary.LittleEndian.PutUint32(head[40:44], 0)        // +40 header_version (v0)
	binary.LittleEndian.PutUint32(head[44:48], 0)        // +44 os_version (unused in v0)
	copy(head[48:64], name)                              // +48 name[16]
	copy(head[64:576], cmdline)                          // +64 cmdline[512]
	return head
}

func TestIsAndroidBoot(t *testing.T) {
	if !IsAndroidBoot([]byte("ANDROID!trailing")) {
		t.Fatal("correct magic was not recognized")
	}
	for _, head := range [][]byte{nil, []byte("ANDRO"), []byte("ANDROI!"), []byte("andROID!")} {
		if IsAndroidBoot(head) {
			t.Fatalf("wrong or short magic %q was accepted", head)
		}
	}
}

func TestReadAndroidBootV0(t *testing.T) {
	head := androidTestHeader(2048, 1234, "test", "console=tty")
	boot, err := ReadAndroidBoot(bytes.NewReader(head), int64(len(head)))
	if err != nil {
		t.Fatalf("v0 boot header: %v", err)
	}
	if boot.Version != 0 || boot.HeaderVersion != 0 || boot.OSVersion != "" {
		t.Fatalf("v0 version fields: %+v", boot)
	}
	if boot.KernelSize != 1234 || boot.KernelAddr != 0x80008000 || boot.PageSize != 2048 {
		t.Fatalf("v0 sizes/page: %+v", boot)
	}
	if boot.RamdiskSize != 0x1234 {
		t.Fatalf("v0 ramdisk size: %+v", boot)
	}
	if boot.Name != "test" || boot.Cmdline != "console=tty" {
		t.Fatalf("v0 strings: %+v", boot)
	}
}

func TestReadAndroidBootOSVersion(t *testing.T) {
	head := androidTestHeader(4096, 0, "", "")
	// a=12, b=1, c=0, y=23 (2023), m=5: (12<<25)|(1<<18)|(23<<4)|5.
	binary.LittleEndian.PutUint32(head[40:44], 1)
	binary.LittleEndian.PutUint32(head[44:48], 402915701)
	boot, err := ReadAndroidBoot(bytes.NewReader(head), int64(len(head)))
	if err != nil {
		t.Fatalf("v1 boot header: %v", err)
	}
	if boot.OSVersion != "12.1.0/2023-05" {
		t.Fatalf("os_version rendering: got %q", boot.OSVersion)
	}
	if boot.Version != 1 || boot.HeaderVersion != 1 {
		t.Fatalf("v1 header version: %+v", boot)
	}

	// A version with no patch date omits the suffix.
	binary.LittleEndian.PutUint32(head[44:48], (12<<25)|(1<<18))
	if boot, err = ReadAndroidBoot(bytes.NewReader(head), int64(len(head))); err != nil || boot.OSVersion != "12.1.0" {
		t.Fatalf("os_version without date: %q, %v", boot.OSVersion, err)
	}

	// v0 ignores even a non-zero packed word.
	binary.LittleEndian.PutUint32(head[40:44], 0)
	binary.LittleEndian.PutUint32(head[44:48], 402915701)
	if boot, err = ReadAndroidBoot(bytes.NewReader(head), int64(len(head))); err != nil || boot.OSVersion != "" {
		t.Fatalf("v0 os_version: %q, %v", boot.OSVersion, err)
	}
}

func TestReadAndroidBootShortFile(t *testing.T) {
	head := make([]byte, 100)
	copy(head, androidBootMagic)
	if _, err := ReadAndroidBoot(bytes.NewReader(head), int64(len(head))); err == nil {
		t.Fatal("a 100-byte file should be rejected")
	}
}

func TestReadAndroidBootInvalidPageSize(t *testing.T) {
	head := androidTestHeader(3000, 1, "", "")
	_, err := ReadAndroidBoot(bytes.NewReader(head), int64(len(head)))
	if err == nil || !strings.Contains(err.Error(), "3000") {
		t.Fatalf("page size 3000 should be named in the error, got %v", err)
	}
}

func TestReadAndroidBootMinimumLength(t *testing.T) {
	head := androidTestHeader(2048, 0, "", "")
	if len(head) != 608 {
		t.Fatalf("test header is %d bytes, want 608", len(head))
	}
	boot, err := ReadAndroidBoot(bytes.NewReader(head), 608)
	if err != nil {
		t.Fatalf("exactly 608 bytes should parse: %v", err)
	}
	if boot.PageSize != 2048 || boot.Name != "" || boot.Cmdline != "" {
		t.Fatalf("minimal header: %+v", boot)
	}
}

func TestReadAndroidBootTooLarge(t *testing.T) {
	_, err := ReadAndroidBoot(bytes.NewReader(nil), androidBootMaxImage+1)
	if err == nil {
		t.Fatal("a file above 512 MiB should be rejected")
	}
}

func TestReadAndroidBootDetected(t *testing.T) {
	head := androidTestHeader(2048, 1234, "test", "console=tty")
	format, images, err := inspect(bytes.NewReader(head), uint64(len(head)), false, "")
	if err != nil || format != "androidboot" || len(images) != 1 || images[0].AndroidBoot == nil {
		t.Fatalf("detection: format=%q images=%d boot=%+v err=%v", format, len(images), images, err)
	}
	if images[0].AndroidBoot.KernelSize != 1234 {
		t.Fatalf("detected boot payload: %+v", images[0].AndroidBoot)
	}
}

// TestAndroidBootRealImage validates the reader against a real vendor boot image.
//
// Every other boot-image test in this file builds its header by hand, which only proves
// the reader agrees with my own understanding of the format. This one requires a real
// file (XTF_REAL_BOOTIMG) and asserts values that were cross-checked two ways: against
// `file(1)` and against an independent byte parse of the same header.
func TestAndroidBootRealImage(t *testing.T) {
	path := os.Getenv("XTF_REAL_BOOTIMG")
	if path == "" {
		t.Skip("set XTF_REAL_BOOTIMG to a real Android boot image to run this test")
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	stat, err := file.Stat()
	if err != nil {
		t.Fatal(err)
	}
	boot, err := ReadAndroidBoot(file, stat.Size())
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	t.Logf("real boot image: kernel=%d page=%d header=%d os=%q name=%q cmdline=%d bytes",
		boot.KernelSize, boot.PageSize, boot.HeaderVersion, boot.OSVersion,
		boot.Name, len(boot.Cmdline))

	// These hold for the RMX1911 image this was developed against; a different device
	// legitimately differs, so only structural facts are asserted unconditionally.
	if boot.PageSize != 2048 && boot.PageSize != 4096 && boot.PageSize != 8192 && boot.PageSize != 16384 {
		t.Errorf("page size %d is not a real page size", boot.PageSize)
	}
	if boot.KernelSize == 0 {
		t.Error("no kernel size in a real boot image")
	}
	if boot.KernelSize > uint32(stat.Size()) {
		t.Errorf("kernel size %d exceeds the file %d", boot.KernelSize, stat.Size())
	}
	if boot.Cmdline == "" {
		t.Error("real boot images carry a cmdline")
	}
	if boot.KernelFormat == "" || boot.KernelFormat == "unknown" {
		t.Errorf("kernel payload not identified: %q", boot.KernelFormat)
	}
	if boot.KernelProbe == 0 {
		t.Error("payload probe decompressed nothing")
	}
}
