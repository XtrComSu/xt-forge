package sysimage

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
)

// Fallback inspection for files that are not a recognised binary format.
//
// An analyst pointing the tool at a firmware blob, a dump, an archive of unknown
// type or a random file should get a bounded, honest description rather than a bare
// "unsupported". The alternative — refusing to say anything — is what sends people
// back to `xxd`, and the point of this engine is to remove that trip.
//
// Everything here is deliberately bounded: a fixed preview budget, a capped read,
// and no attempt to interpret the bytes as code. Reporting size, hashes, entropy and
// a printable preview is enough to recognise a file and decide what to do next.

const (
	// maxFallbackRead bounds how much of an unknown file is read at all. The hash is
	// over the whole file through a streaming reader; only the preview needs bytes.
	maxFallbackRead = 1 << 20
	// fallbackPreviewBytes is how much goes into the hex and string previews.
	fallbackPreviewBytes = 256
	// fallbackStringRun is the shortest printable run worth reporting.
	fallbackStringRun = 6
	fallbackStringMax = 24
)

// UnknownFile describes a file that no loader claimed.
type UnknownFile struct {
	Size         int64   `json:"size"`
	SHA256       string  `json:"sha256"`
	Entropy      float64 `json:"entropy"`
	EntropyClass string  `json:"entropy_class"`
	// Magic is the first eight bytes in hex, which is what an analyst matches
	// against a format table by hand.
	Magic   string   `json:"magic"`
	Hex     string   `json:"hex_preview"`
	Strings []string `json:"strings,omitempty"`
	// Truncated reports that the preview covers less than the whole file.
	Truncated bool `json:"truncated"`
	// Note explains what this record is and is not.
	Note string `json:"note"`
}

// describeUnknown builds a bounded description of an unclaimed file.
//
// The hash covers the entire file even when the preview does not, because the hash is
// the one field a user may compare against an external source; a partial hash would be
// worse than no hash.
func describeUnknown(r io.ReaderAt, size int64) *UnknownFile {
	description := &UnknownFile{
		Size: size,
		Note: "unrecognised format: size, hash, entropy and a bounded preview only; " +
			"no disassembly or symbol recovery was attempted",
	}
	if size <= 0 {
		return description
	}

	hash := sha256.New()
	if copied, err := io.Copy(hash, io.NewSectionReader(r, 0, size)); err == nil && copied == size {
		description.SHA256 = hex.EncodeToString(hash.Sum(nil))
	}

	readLen := size
	if readLen > maxFallbackRead {
		readLen = maxFallbackRead
		description.Truncated = true
	}
	head := make([]byte, readLen)
	if _, err := r.ReadAt(head, 0); err != nil && len(head) == 0 {
		return description
	}

	profile := ProfileEntropy(head, 4096)
	description.Entropy = profile.Overall
	description.EntropyClass = profile.Class

	magicLen := 8
	if len(head) < magicLen {
		magicLen = len(head)
	}
	description.Magic = hex.EncodeToString(head[:magicLen])

	previewLen := fallbackPreviewBytes
	if len(head) < previewLen {
		previewLen = len(head)
	}
	description.Hex = hex.EncodeToString(head[:previewLen])
	description.Strings = printableRuns(head, fallbackStringMax, fallbackStringRun)
	return description
}

// printableRuns extracts short printable ASCII runs, which is usually enough to
// recognise a container ("PK", "SQLite format 3", a version string, a path).
//
// Runs are capped in both length and count: this is a recognition aid, not a strings
// dump, and an unbounded version would turn a 1 MiB preview into a large document.
func printableRuns(data []byte, maxRuns, minRun int) []string {
	var runs []string
	start := -1
	for index, value := range data {
		printable := value >= 0x20 && value < 0x7f
		if printable && start < 0 {
			start = index
		}
		if !printable && start >= 0 {
			if index-start >= minRun {
				runs = append(runs, string(data[start:index]))
				if len(runs) >= maxRuns {
					return runs
				}
			}
			start = -1
		}
	}
	if start >= 0 && len(data)-start >= minRun && len(runs) < maxRuns {
		runs = append(runs, string(data[start:]))
	}
	return runs
}

// fallbackImage wraps an unknown file in one Image so every caller keeps a uniform
// shape: a report always has images, and an unknown file is simply an image with no
// architecture and no sections.
func fallbackImage(description *UnknownFile) Image {
	return Image{
		Unknown: description,
		warnings: []string{fmt.Sprintf(
			"unrecognised format (%d bytes, entropy %s); reported without disassembly",
			description.Size, description.EntropyClass)},
	}
}

// Summarise renders the one-line form used by humans.
func (u *UnknownFile) Summarise() string {
	if u == nil {
		return ""
	}
	parts := []string{fmt.Sprintf("%d bytes", u.Size)}
	if u.SHA256 != "" {
		parts = append(parts, "sha256 "+u.SHA256[:16]+"...")
	}
	parts = append(parts, fmt.Sprintf("entropy %.2f (%s)", u.Entropy, u.EntropyClass))
	if len(u.Strings) > 0 {
		parts = append(parts, "first string "+strings.TrimSpace(u.Strings[0]))
	}
	return strings.Join(parts, ", ")
}
