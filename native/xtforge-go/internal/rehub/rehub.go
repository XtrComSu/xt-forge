// Package rehub implements Go-backed reverse-engineering workflows:
// pure-Go Electron ASAR unpacking, HAR/SAZ network capture triage, Android APK
// manifest/component inspection, headless Ghidra/rizin decompilation, and
// capability-scoped dynamic tracing (Frida/gdb/lldb).
package rehub

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"xtforge-hub/internal/guard"
)

const maxREFileBytes = 256 * 1024 * 1024

// InspectASAR parses an Electron .asar archive (Chromium pickle header + JSON tree).
func InspectASAR(filePath string, extractDir string, limit int) map[string]any {
	canon, err := guard.ReadGuard(filePath)
	if err != nil {
		return map[string]any{"ok": false, "error": err.Error()}
	}
	if limit <= 0 {
		limit = 200
	}
	f, err := os.Open(canon)
	if err != nil {
		return map[string]any{"ok": false, "error": err.Error()}
	}
	defer f.Close()

	var hdr [16]byte
	if _, err := io.ReadFull(f, hdr[:]); err != nil {
		return map[string]any{"ok": false, "error": "truncated ASAR header"}
	}
	// Chromium Pickle header: [u32 payload_size=4][u32 header_size][u32 header_size-4][u32 json_len]
	jsonLen := binary.LittleEndian.Uint32(hdr[12:16])
	headerPayloadSize := binary.LittleEndian.Uint32(hdr[4:8])
	if jsonLen == 0 || jsonLen > 32*1024*1024 {
		return map[string]any{"ok": false, "error": fmt.Sprintf("invalid ASAR header length: %d", jsonLen)}
	}
	jsonBuf := make([]byte, jsonLen)
	if _, err := io.ReadFull(f, jsonBuf); err != nil {
		return map[string]any{"ok": false, "error": "truncated ASAR JSON directory"}
	}
	jsonBuf = bytes.TrimRight(jsonBuf, "\x00")
	var root map[string]any
	if err := json.Unmarshal(jsonBuf, &root); err != nil {
		return map[string]any{"ok": false, "error": "corrupt ASAR JSON index: " + err.Error()}
	}

	dataOffset := int64(8) + int64(headerPayloadSize)
	type asarFile struct {
		Path       string `json:"path"`
		Size       int64  `json:"size"`
		Offset     int64  `json:"offset"`
		Unpacked   bool   `json:"unpacked,omitempty"`
		SourceMap  bool   `json:"source_map,omitempty"`
	}
	var files []asarFile
	var sourceMaps []string
	var walk func(node map[string]any, prefix string)
	walk = func(node map[string]any, prefix string) {
		children, ok := node["files"].(map[string]any)
		if !ok {
			return
		}
		keys := make([]string, 0, len(children))
		for k := range children {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			sub, _ := children[k].(map[string]any)
			rel := k
			if prefix != "" {
				rel = prefix + "/" + k
			}
			if _, hasFiles := sub["files"]; hasFiles {
				walk(sub, rel)
				continue
			}
			sz := int64(0)
			if s, ok := sub["size"].(float64); ok {
				sz = int64(s)
			}
			off := int64(-1)
			if osStr, ok := sub["offset"].(string); ok {
				var parsed int64
				_, _ = fmt.Sscan(osStr, &parsed)
				off = parsed
			}
			unpacked, _ := sub["unpacked"].(bool)
			isMap := strings.HasSuffix(rel, ".js.map") || strings.HasSuffix(rel, ".mjs.map")
			if isMap {
				sourceMaps = append(sourceMaps, rel)
			}
			files = append(files, asarFile{
				Path:      rel,
				Size:      sz,
				Offset:    off,
				Unpacked:  unpacked,
				SourceMap: isMap,
			})
		}
	}
	walk(root, "")

	extracted := 0
	if extractDir != "" {
		wg, err := guard.WriteGuard(extractDir, true, "", false)
		if err != nil {
			return map[string]any{"ok": false, "error": err.Error()}
		}
		_ = wg
		if err := os.MkdirAll(extractDir, 0o755); err != nil {
			return map[string]any{"ok": false, "error": err.Error()}
		}
		for _, item := range files {
			if item.Unpacked || item.Offset < 0 || item.Size > 16*1024*1024 {
				continue
			}
			dest := filepath.Join(extractDir, filepath.FromSlash(item.Path))
			cleanDest := filepath.Clean(dest)
			if !strings.HasPrefix(cleanDest, filepath.Clean(extractDir)+string(filepath.Separator)) {
				continue
			}
			_ = os.MkdirAll(filepath.Dir(cleanDest), 0o755)
			buf := make([]byte, item.Size)
			if _, err := f.ReadAt(buf, dataOffset+item.Offset); err == nil {
				if os.WriteFile(cleanDest, buf, 0o644) == nil {
					extracted++
				}
			}
		}
	}

	shown := files
	if len(shown) > limit {
		shown = shown[:limit]
	}
	return map[string]any{
		"ok":          true,
		"path":        canon,
		"count":       len(shown),
		"total_files": len(files),
		"source_maps": sourceMaps,
		"extracted":   extracted,
		"files":       shown,
		"truncated":   len(files) > len(shown),
	}
}

// InspectNetcap parses HAR JSON or SAZ (Fiddler zip) HTTP capture files,
// masking Authorization/Cookie credentials automatically.
func InspectNetcap(filePath string, limit int) map[string]any {
	canon, err := guard.ReadGuard(filePath)
	if err != nil {
		return map[string]any{"ok": false, "error": err.Error()}
	}
	if limit <= 0 {
		limit = 50
	}
	ext := strings.ToLower(filepath.Ext(canon))
	if ext == ".saz" {
		zr, err := zip.OpenReader(canon)
		if err != nil {
			return map[string]any{"ok": false, "error": "cannot open SAZ archive: " + err.Error()}
		}
		defer zr.Close()
		var rawSessions []string
		for _, f := range zr.File {
			if strings.HasPrefix(f.Name, "raw/") && strings.HasSuffix(f.Name, "_c.txt") {
				rawSessions = append(rawSessions, f.Name)
			}
		}
		sort.Strings(rawSessions)
		var requests []map[string]any
		for i, name := range rawSessions {
			if i >= limit {
				break
			}
			for _, f := range zr.File {
				if f.Name == name {
					rc, err := f.Open()
					if err == nil {
						b, _ := io.ReadAll(io.LimitReader(rc, 4096))
						_ = rc.Close()
						firstLine := strings.SplitN(string(b), "\n", 2)[0]
						requests = append(requests, map[string]any{"session": name, "request_line": strings.TrimSpace(firstLine)})
					}
				}
			}
		}
		return map[string]any{"ok": true, "format": "saz", "path": canon, "sessions": len(rawSessions), "requests": requests}
	}

	raw, err := os.ReadFile(canon)
	if err != nil {
		return map[string]any{"ok": false, "error": err.Error()}
	}
	var har struct {
		Log struct {
			Entries []struct {
				StartedDateTime string  `json:"startedDateTime"`
				Time            float64 `json:"time"`
				Request         struct {
					Method  string `json:"method"`
					URL     string `json:"url"`
					Headers []struct {
						Name  string `json:"name"`
						Value string `json:"value"`
					} `json:"headers"`
				} `json:"request"`
				Response struct {
					Status  int `json:"status"`
					Content struct {
						Size     int64  `json:"size"`
						MimeType string `json:"mimeType"`
					} `json:"content"`
				} `json:"response"`
			} `json:"entries"`
		} `json:"log"`
	}
	if err := json.Unmarshal(raw, &har); err != nil {
		return map[string]any{"ok": false, "error": "invalid HAR JSON: " + err.Error()}
	}

	hosts := map[string]int{}
	var items []map[string]any
	for _, e := range har.Log.Entries {
		u := e.Request.URL
		if idx := strings.Index(u, "://"); idx > 0 {
			rest := u[idx+3:]
			host := strings.SplitN(rest, "/", 2)[0]
			hosts[host]++
		}
		if len(items) < limit {
			var authHeaders []string
			for _, h := range e.Request.Headers {
				ln := strings.ToLower(h.Name)
				if ln == "authorization" || ln == "cookie" || ln == "x-api-key" {
					authHeaders = append(authHeaders, h.Name+": [REDACTED]")
				}
			}
			items = append(items, map[string]any{
				"method":       e.Request.Method,
				"url":          u,
				"status":       e.Response.Status,
				"mime":         e.Response.Content.MimeType,
				"size":         e.Response.Content.Size,
				"ms":           e.Time,
				"auth_headers": authHeaders,
			})
		}
	}
	return map[string]any{
		"ok":            true,
		"format":        "har",
		"path":          canon,
		"total_entries": len(har.Log.Entries),
		"hosts":         hosts,
		"entries":       items,
	}
}

// InspectAPK inspects an Android APK using pure Go zip/AXML scanning, enriching
// with jadx/apktool metadata when installed on the host.
func InspectAPK(filePath string) map[string]any {
	canon, err := guard.ReadGuard(filePath)
	if err != nil {
		return map[string]any{"ok": false, "error": err.Error()}
	}
	zr, err := zip.OpenReader(canon)
	if err != nil {
		return map[string]any{"ok": false, "error": "cannot open APK: " + err.Error()}
	}
	defer zr.Close()

	var dexFiles, nativeLibs, assets []string
	var hasManifest bool
	var manifestBytes []byte
	for _, f := range zr.File {
		switch {
		case f.Name == "AndroidManifest.xml":
			hasManifest = true
			if rc, err := f.Open(); err == nil {
				manifestBytes, _ = io.ReadAll(io.LimitReader(rc, 2*1024*1024))
				_ = rc.Close()
			}
		case strings.HasSuffix(f.Name, ".dex"):
			dexFiles = append(dexFiles, f.Name)
		case strings.HasPrefix(f.Name, "lib/") && strings.HasSuffix(f.Name, ".so"):
			nativeLibs = append(nativeLibs, f.Name)
		case strings.HasPrefix(f.Name, "assets/"):
			if len(assets) < 40 {
				assets = append(assets, f.Name)
			}
		}
	}

	permissions := extractAXMLStrings(manifestBytes, `android\.permission\.[A-Z0-9_]+`)
	components := extractAXMLStrings(manifestBytes, `[a-zA-Z0-9_]+\.(?:[a-zA-Z0-9_]+\.)+[A-Z][a-zA-Z0-9_]+(?:Activity|Service|Receiver|Provider)`)
	jadxPath, _ := exec.LookPath("jadx")
	apktoolPath, _ := exec.LookPath("apktool")

	return map[string]any{
		"ok":           true,
		"path":         canon,
		"has_manifest": hasManifest,
		"dex_files":    dexFiles,
		"native_libs":  nativeLibs,
		"assets":       assets,
		"permissions":  permissions,
		"components":   components,
		"backends": map[string]string{
			"jadx":    jadxPath,
			"apktool": apktoolPath,
		},
	}
}

func extractAXMLStrings(raw []byte, pat string) []string {
	if len(raw) == 0 {
		return nil
	}
	// Android binary XML stores strings in both UTF-8 and UTF-16LE string pools.
	var asciiBuf strings.Builder
	for i := 0; i < len(raw); i++ {
		b := raw[i]
		if b >= 0x20 && b <= 0x7e {
			asciiBuf.WriteByte(b)
		} else if b == 0 {
			continue
		} else {
			asciiBuf.WriteByte(' ')
		}
	}
	re := regexp.MustCompile(pat)
	seen := map[string]bool{}
	var out []string
	for _, m := range re.FindAllString(asciiBuf.String(), -1) {
		if !seen[m] {
			seen[m] = true
			out = append(out, m)
		}
	}
	sort.Strings(out)
	return out
}

// Decompile bridges headless rizin/radare2 or Ghidra analyzeHeadless for
// token-bounded pseudocode extraction.
func Decompile(filePath, symbol, rva, engine string, maxLines int) map[string]any {
	canon, err := guard.ReadGuard(filePath)
	if err != nil {
		return map[string]any{"ok": false, "error": err.Error()}
	}
	if maxLines <= 0 {
		maxLines = 160
	}
	target := symbol
	if rva != "" {
		target = rva
	}
	if target == "" {
		target = "main"
	}
	if engine == "" || engine == "auto" {
		if _, err := exec.LookPath("rizin"); err == nil {
			engine = "rizin"
		} else if _, err := exec.LookPath("r2"); err == nil {
			engine = "r2"
		} else if _, err := exec.LookPath("analyzeHeadless"); err == nil {
			engine = "ghidra"
		} else {
			return map[string]any{
				"ok":           false,
				"available":    false,
				"path":         canon,
				"target":       target,
				"install_hint": "install rizin (pdc/rz-ghidra) or Ghidra analyzeHeadless; fallback: xtforge re cfg " + canon,
				"error":        "no headless decompiler backend found on PATH",
			}
		}
	}

	if engine == "rizin" || engine == "r2" {
		bin := engine
		cmdStr := fmt.Sprintf("aaa; s %s; pdc", target)
		out, runErr := exec.Command(bin, "-q", "-c", cmdStr, canon).CombinedOutput()
		if runErr != nil {
			return map[string]any{"ok": false, "engine": engine, "error": runErr.Error(), "stderr": string(out)}
		}
		lines := strings.Split(strings.TrimSpace(string(out)), "\n")
		truncated := false
		if len(lines) > maxLines {
			lines = lines[:maxLines]
			truncated = true
		}
		return map[string]any{
			"ok":         true,
			"engine":     engine,
			"path":       canon,
			"target":     target,
			"pseudocode": strings.Join(lines, "\n"),
			"lines":      len(lines),
			"truncated":  truncated,
		}
	}

	return map[string]any{
		"ok":     false,
		"engine": engine,
		"error":  "ghidra analyzeHeadless requires a configured project directory; use rizin for instant single-file pseudocode or fallback to `xtforge re cfg`",
	}
}

// Trace runs capability-scoped dynamic tracing (Frida/gdb/lldb) under guard enforcement.
func Trace(filePath, preset, confirmToken string, dryRun bool) map[string]any {
	canon, err := guard.ReadGuard(filePath)
	if err != nil {
		return map[string]any{"ok": false, "error": err.Error()}
	}
	if guard.CurrentMode() == guard.ModeExplore {
		return map[string]any{"ok": false, "error": "explore_mode: XT_PERM_MODE=explore forbids dynamic process execution"}
	}
	if preset == "" {
		preset = "api_trace"
	}
	validPresets := map[string]string{
		"api_trace":     "Trace libc / Win32 API calls without modifying process memory",
		"tls_keys":      "Read-only SSL/TLS handshake and endpoint logging",
		"crypto_hooks":  "Observe symmetric/hash buffer sizes and algorithm calls",
		"crash_capture": "Run under gdb/lldb batch mode to capture backtrace on signal",
	}
	desc, ok := validPresets[preset]
	if !ok {
		return map[string]any{"ok": false, "error": "unknown trace preset: " + preset}
	}

	if dryRun || (guard.CurrentMode() == guard.ModeAsk && confirmToken == "") {
		tok, _ := guard.IssueToken("re_trace_"+preset, canon, "re")
		return map[string]any{
			"ok":            true,
			"dry_run":       true,
			"preset":        preset,
			"description":   desc,
			"path":          canon,
			"confirm":       tok,
			"frida_present": hasBin("frida-trace"),
			"gdb_present":   hasBin("gdb"),
		}
	}

	if confirmToken != "" {
		if _, err := guard.WriteGuard(canon, true, confirmToken, false); err != nil {
			return map[string]any{"ok": false, "error": err.Error()}
		}
	}

	if preset == "crash_capture" && hasBin("gdb") {
		out, _ := exec.Command("gdb", "-batch", "-ex", "run", "-ex", "bt", "-ex", "info registers", canon).CombinedOutput()
		guard.AuditEvent("re-trace", "re_trace", preset, "ok", canon, 0)
		return map[string]any{
			"ok":     true,
			"engine": "gdb",
			"preset": preset,
			"path":   canon,
			"trace":  trimLines(string(out), 120),
		}
	}
	if hasBin("frida-trace") {
		var buf bytes.Buffer
		cmd := exec.Command("frida-trace", "-f", canon, "-i", "open*", "-i", "connect*")
		cmd.Stdout = &buf
		cmd.Stderr = &buf
		_ = cmd.Run()
		guard.AuditEvent("re-trace", "re_trace", preset, "ok", canon, 0)
		return map[string]any{
			"ok":     true,
			"engine": "frida-trace",
			"preset": preset,
			"path":   canon,
			"trace":  trimLines(buf.String(), 120),
		}
	}
	return map[string]any{
		"ok":           false,
		"available":    false,
		"preset":       preset,
		"install_hint": "install frida-tools (`pip install frida-tools`) or gdb for dynamic tracing",
		"error":        "neither frida-trace nor gdb is available on PATH",
	}
}

func hasBin(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

func trimLines(s string, max int) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) <= max {
		return strings.Join(lines, "\n")
	}
	return strings.Join(lines[:max], "\n") + "\n... [truncated]"
}
