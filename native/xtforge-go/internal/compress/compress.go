// Package compress implements error-preserving L1-L3 text compression and
// oversized MCP artifact spilling so tool outputs never flood model context.
package compress

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"xtforge-hub/internal/guard"
)

var errorLineRe = regexp.MustCompile(`(?i)(traceback \(most recent call last\)|\bfatal\b|\bsegfault\b|\bpanicked?\b|\berror\b|\bfailed\b|\bdenied\b|\brefused\b|\bexception\b|\bwarning\b)`)

// Squeeze compresses text to target level (L0=raw, L1=dedup/trim, L2=summary+errors, L3=errors+head/tail).
func Squeeze(text, level string) string {
	lvl := strings.ToUpper(strings.TrimSpace(level))
	if lvl == "" || lvl == "L0" {
		return text
	}
	lines := strings.Split(text, "\n")
	if len(lines) <= 25 {
		return text
	}

	var kept []string
	var errors []string
	seen := map[string]int{}
	for _, raw := range lines {
		line := strings.TrimRight(raw, " \t\r")
		if line == "" {
			continue
		}
		if errorLineRe.MatchString(line) {
			errors = append(errors, line)
		}
		seen[line]++
		if seen[line] == 1 {
			kept = append(kept, line)
		} else if seen[line] == 2 && lvl == "L1" {
			kept = append(kept, fmt.Sprintf("[repeated: %s]", trunc(line, 80)))
		}
	}

	switch lvl {
	case "L1":
		if len(kept) > 200 {
			head := kept[:120]
			tail := kept[len(kept)-60:]
			out := append([]string{}, head...)
			out = append(out, fmt.Sprintf("... [%d lines elided, %d error lines preserved] ...", len(kept)-180, len(errors)))
			out = append(out, errors...)
			out = append(out, tail...)
			return strings.Join(dedupPreserve(out), "\n")
		}
		return strings.Join(kept, "\n")
	case "L2":
		var out []string
		limit := min(40, len(kept))
		out = append(out, kept[:limit]...)
		if len(kept) > limit {
			out = append(out, fmt.Sprintf("... [%d additional lines compressed] ...", len(kept)-limit))
		}
		out = append(out, errors...)
		return strings.Join(dedupPreserve(out), "\n")
	default: // L3
		var out []string
		limit := min(15, len(kept))
		out = append(out, kept[:limit]...)
		if len(errors) > 0 {
			out = append(out, "--- preserved errors ---")
			out = append(out, errors...)
		}
		if len(kept) > limit+10 {
			out = append(out, "--- tail ---")
			out = append(out, kept[len(kept)-10:]...)
		}
		return strings.Join(dedupPreserve(out), "\n")
	}
}

// ClipOrSpill keeps text inline when <= maxBytes, otherwise compresses and spills
// the raw payload to ~/.xt-forge/cache/artifacts/<sha>.txt returning a compact handle.
func ClipOrSpill(text string, maxBytes int, prefix string) (string, string) {
	if maxBytes <= 0 {
		maxBytes = 16384
	}
	if len(text) <= maxBytes {
		return text, ""
	}
	sum := sha256.Sum256([]byte(text))
	id := hex.EncodeToString(sum[:])[:12]
	artDir := filepath.Join(guard.XTHome(), "cache", "artifacts")
	_ = os.MkdirAll(artDir, 0o755)
	artPath := filepath.Join(artDir, fmt.Sprintf("%s-%s.txt", prefix, id))
	_ = os.WriteFile(artPath, []byte(text), 0o600)

	squeezed := Squeeze(text, "L2")
	if len(squeezed) > maxBytes {
		squeezed = squeezed[:maxBytes-256] + "\n... [truncated; full output spilled]"
	}
	notice := fmt.Sprintf("[artifact spilled: %s (%d raw bytes -> %d compressed bytes)]\n\n%s",
		artPath, len(text), len(squeezed), squeezed)
	return notice, artPath
}

func dedupPreserve(lines []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(lines))
	for _, l := range lines {
		if !seen[l] {
			seen[l] = true
			out = append(out, l)
		}
	}
	return out
}

func trunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
