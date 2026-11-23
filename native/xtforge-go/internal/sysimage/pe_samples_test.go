package sysimage

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Breadth harness for real PE files. XTF_PE_DIR points at a directory tree of
// samples; without it the test is a no-op so normal test runs stay hermetic.
// The walk and the whole inspection pass are bounded to 400 files / 60 s.
const (
	peSampleLimit   = 400
	peSampleTimeout = 60 * time.Second
)

// peSampleDefaults are consulted when XTF_PE_DIR is unset. They are the real Windows
// binaries that ship with Wine on this machine; the corpus claim ("1,600 files, 0
// failures") used to rest on a manual run with the variable set, which means nothing
// re-checked it. Running by default when the directories exist turns the claim into a test.
func peSampleDefaults() []string {
	home, err := os.UserHomeDir()
	if err != nil {
		home = ""
	}
	candidates := []string{
		"/usr/lib/wine/x86_64-windows",
		"/usr/lib/wine/i386-windows",
	}
	if home != "" {
		candidates = append(candidates,
			filepath.Join(home, ".wine", "drive_c", "windows", "system32"),
			filepath.Join(home, ".wine", "drive_c", "windows", "syswow64"))
	}
	present := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		if info, err := os.Stat(candidate); err == nil && info.IsDir() {
			present = append(present, candidate)
		}
	}
	return present
}

func TestPESamples(t *testing.T) {
	root := strings.TrimSpace(os.Getenv("XTF_PE_DIR"))
	explicit := root != ""
	if !explicit {
		defaults := peSampleDefaults()
		if len(defaults) == 0 {
			t.Skip("no PE sample directory found and XTF_PE_DIR is unset")
		}
		for _, directory := range defaults {
			t.Run(filepath.Base(directory), func(t *testing.T) {
				peSampleWalk(t, directory, false)
			})
		}
		return
	}
	info, err := os.Stat(root)
	if err != nil || !info.IsDir() {
		if explicit {
			t.Fatalf("XTF_PE_DIR %q is not a directory", root)
		}
		t.Skipf("%s is not a directory", root)
	}

	peSampleWalk(t, root, true)
}

func peSampleWalk(t *testing.T, root string, explicit bool) {
	t.Helper()
	start := time.Now()
	deadline := start.Add(peSampleTimeout)
	var samples []string
	err := filepath.WalkDir(root, func(p string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if !time.Now().Before(deadline) || len(samples) >= peSampleLimit {
			return filepath.SkipAll
		}
		if entry.IsDir() {
			return nil
		}
		switch strings.ToLower(filepath.Ext(entry.Name())) {
		case ".exe", ".dll", ".sys", ".efi":
		default:
			return nil
		}
		samples = append(samples, p)
		return nil
	})
	if err != nil {
		t.Fatalf("walk %q: %v", root, err)
	}
	if len(samples) == 0 {
		t.Fatalf("no .exe/.dll/.sys/.efi files found under %q", root)
	}
	t.Logf("PE_SAMPLES_START dir=%s candidates=%d limit=%d timeout=%s", root, len(samples), peSampleLimit, peSampleTimeout)

	failures := 0
	processed := 0
	for _, sample := range samples {
		if !time.Now().Before(deadline) {
			t.Logf("PE_SAMPLES_BOUND reached after %d of %d files in %s", processed, len(samples), time.Since(start))
			break
		}
		processed++
		result, overviewErr := Overview(sample, "")
		var reasons []string
		if overviewErr != nil {
			reasons = append(reasons, overviewErr.Error())
		}
		if !result.OK {
			reasons = append(reasons, "ok=false")
		}
		if len(result.Images) == 0 {
			reasons = append(reasons, "no images")
		}
		for i, image := range result.Images {
			// A 16-bit NE image is identified, not parsed: the engine reports its DOS/NE
			// header and nothing else, so it legitimately has no arch and no sections.
			// Demanding them here would mark correct behaviour as a failure.
			if result.Format == "ne" {
				continue
			}
			if image.Arch == "" {
				reasons = append(reasons, fmt.Sprintf("image %d: empty arch", i))
			}
			if len(image.Sections) < 1 {
				reasons = append(reasons, fmt.Sprintf("image %d: %d sections", i, len(image.Sections)))
			}
		}
		if len(reasons) != 0 {
			failures++
			t.Errorf("PE_SAMPLE_FAIL path=%s format=%q error=%q", sample, result.Format, strings.Join(reasons, "; "))
		}
	}
	t.Logf("PE_SAMPLES_DONE dir=%s processed=%d failures=%d elapsed=%s", root, processed, failures, time.Since(start))
	if failures != 0 {
		t.Fatalf("%d of %d PE samples failed to parse under %s", failures, processed, root)
	}
}
