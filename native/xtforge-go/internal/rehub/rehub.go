// Package rehub implements Go-backed reverse-engineering workflows:
// pure-Go Electron ASAR unpacking, HAR/SAZ network capture triage, Android APK
// manifest/component inspection, headless Ghidra/rizin decompilation, and
// capability-scoped dynamic tracing (Frida/gdb/lldb).
package rehub

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
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

func findBorerBinary() string {
	if p, err := exec.LookPath("borer"); err == nil {
		return p
	}
	home, _ := os.UserHomeDir()
	for _, cand := range []string{
		filepath.Join(home, ".local", "bin", "borer"),
		filepath.Join(home, ".cargo", "bin", "borer"),
	} {
		if st, err := os.Stat(cand); err == nil && !st.IsDir() {
			return cand
		}
	}
	return ""
}

// Decompile bridges Borer, headless rizin/radare2, Ghidra, or annotated objdump for
// token-bounded pseudocode extraction.
func Decompile(filePath, symbol, rva, engine string, maxLines int) map[string]any {
	canon, err := guard.ReadGuard(filePath)
	if err != nil {
		return map[string]any{"ok": false, "error": err.Error()}
	}
	if maxLines <= 0 {
		maxLines = 160
	}
	target := rva
	var targets []string
	if target == "" {
		for _, part := range strings.Split(symbol, ",") {
			if trimmed := strings.TrimSpace(part); trimmed != "" {
				targets = append(targets, trimmed)
				if len(targets) == 8 {
					break
				}
			}
		}
		if len(targets) > 0 {
			target = targets[0]
		}
	}
	if target == "" {
		target = "main"
	}
	borerBin := findBorerBinary()
	if engine == "" || engine == "auto" {
		if borerBin != "" {
			engine = "borer"
		} else if _, err := exec.LookPath("rizin"); err == nil {
			engine = "rizin"
		} else if _, err := exec.LookPath("r2"); err == nil {
			engine = "r2"
		} else if _, err := exec.LookPath("analyzeHeadless"); err == nil {
			engine = "ghidra"
		} else if _, err := exec.LookPath("objdump"); err == nil {
			engine = "objdump_annotated"
		} else {
			return map[string]any{
				"ok":           false,
				"available":    false,
				"path":         canon,
				"target":       target,
				"install_hint": "install borer, objdump, rizin, or Ghidra analyzeHeadless; fallback: xtforge re cfg " + canon,
				"error":        "no headless decompiler or objdump backend found on PATH",
			}
		}
	}

	if len(targets) > 1 {
		results := make(map[string]map[string]any, len(targets))
		ok := false
		for _, item := range targets {
			if _, exists := results[item]; exists {
				continue
			}
			result := decompileTarget(canon, item, engine, borerBin, maxLines)
			results[item] = result
			ok = ok || result["ok"] == true
		}
		return map[string]any{"ok": ok, "batch": true, "count": len(results), "results": results}
	}
	return decompileTarget(canon, target, engine, borerBin, maxLines)
}

func decompileTarget(canon, target, engine, borerBin string, maxLines int) map[string]any {
	if engine == "borer" && borerBin != "" {
		out, runErr := exec.Command(borerBin, "decompile", canon, target, "full", "0", strconv.Itoa(maxLines)).CombinedOutput()
		if runErr == nil && strings.TrimSpace(string(out)) != "" && !strings.HasPrefix(strings.TrimSpace(string(out)), "error:") {
			var notes []string
			if _, err := exec.LookPath("objdump"); err == nil {
				objOut, _ := exec.Command("objdump", "-d", "-M", "intel", "--no-show-raw-insn", "--disassemble="+target, canon).CombinedOutput()
				if len(objOut) > 0 {
					strMap := extractRodataStringMap(canon)
					annLines := annotateObjdumpLines(strings.Split(strings.TrimSpace(string(objOut)), "\n"), strMap)
					notes = annotateObjdumpReciprocalDivs(annLines)
				}
			}
			lines := strings.Split(strings.TrimSpace(string(out)), "\n")
			truncated := false
			if len(lines) > maxLines {
				lines = lines[:maxLines]
				truncated = true
			}
			pseudo := strings.Join(lines, "\n")
			if len(notes) > 0 {
				pseudo = "// [math-notes] " + strings.Join(notes, " | ") + "\n" + pseudo
			}
			return map[string]any{
				"ok":         true,
				"available":  true,
				"engine":     "borer",
				"path":       canon,
				"target":     target,
				"pseudocode": pseudo,
				"notes":      notes,
				"lines":      len(lines),
				"truncated":  truncated,
			}
		}
		// Fall through to objdump_annotated if symbol name requires objdump lookup
		engine = "objdump_annotated"
	}

	if engine == "objdump_annotated" || engine == "objdump" {
		args := []string{"-d", "-M", "intel", "--no-show-raw-insn", "--disassemble=" + target, canon}
		out, runErr := exec.Command("objdump", args...).CombinedOutput()
		if runErr != nil || !strings.Contains(string(out), "<"+target+">") {
			out, runErr = exec.Command("objdump", "-d", "--no-show-raw-insn", "--disassemble="+target, canon).CombinedOutput()
		}
		if runErr != nil || !strings.Contains(string(out), "<"+target+">") {
			out, runErr = exec.Command("objdump", "-d", "--disassemble="+target, canon).CombinedOutput()
		}
		if runErr != nil || strings.TrimSpace(string(out)) == "" {
			return map[string]any{
				"ok":     false,
				"engine": "objdump_annotated",
				"path":   canon,
				"target": target,
				"error":  fmt.Sprintf("symbol/target '%s' could not be disassembled: %v", target, runErr),
			}
		}
		strMap := extractRodataStringMap(canon)
		rawLines := annotateObjdumpLines(strings.Split(strings.TrimSpace(string(out)), "\n"), strMap)
		notes := annotateObjdumpReciprocalDivs(rawLines)
		truncated := false
		if len(rawLines) > maxLines {
			rawLines = rawLines[:maxLines]
			truncated = true
		}
		return map[string]any{
			"ok":         true,
			"available":  true,
			"engine":     "objdump_annotated",
			"path":       canon,
			"target":     target,
			"pseudocode": strings.Join(rawLines, "\n"),
			"notes":      notes,
			"lines":      len(rawLines),
			"truncated":  truncated,
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

var (
	reImulConst   = regexp.MustCompile(`\bimul\s+[^#\n]*\b0x([0-9a-fA-F]+)\b`)
	reShiftConst  = regexp.MustCompile(`\b(?:sar|shr)\s+[^,\n]+,\s*0x([0-9a-fA-F]+)|\b(?:sar|shr)\s+\$?0x([0-9a-fA-F]+)\b`)
	reRodataLine  = regexp.MustCompile(`^\s*([0-9a-fA-F]+)\s+((?:[0-9a-fA-F]{8}\s+){1,4})`)
	reAddrComment = regexp.MustCompile(`#\s*(?:0x)?([0-9a-fA-F]+)\b`)
)

func extractRodataStringMap(canon string) map[uint64]string {
	outMap := map[uint64]string{}
	out, err := exec.Command("objdump", "-s", "-j", ".rodata", canon).Output()
	if err != nil {
		return outMap
	}
	type chunk struct {
		addr uint64
		data []byte
	}
	var chunks []chunk
	for _, ln := range strings.Split(string(out), "\n") {
		m := reRodataLine.FindStringSubmatch(ln)
		if len(m) < 3 {
			continue
		}
		addr, err := strconv.ParseUint(m[1], 16, 64)
		if err != nil {
			continue
		}
		var b []byte
		for _, hx := range strings.Fields(m[2]) {
			dec, err := hex.DecodeString(hx)
			if err == nil {
				b = append(b, dec...)
			}
		}
		chunks = append(chunks, chunk{addr: addr, data: b})
	}
	if len(chunks) == 0 {
		return outMap
	}
	base := chunks[0].addr
	var buf []byte
	for _, ch := range chunks {
		if ch.addr > base+uint64(len(buf)) {
			gap := int(ch.addr - (base + uint64(len(buf))))
			buf = append(buf, make([]byte, gap)...)
		}
		buf = append(buf, ch.data...)
	}
	i := 0
	for i < len(buf) {
		if buf[i] >= 0x20 && buf[i] <= 0x7e {
			start := i
			for i < len(buf) && buf[i] >= 0x20 && buf[i] <= 0x7e {
				i++
			}
			if i < len(buf) && buf[i] == 0 && i-start >= 2 {
				outMap[base+uint64(start)] = string(buf[start:i])
			}
		}
		i++
	}
	return outMap
}

func annotateObjdumpLines(lines []string, strMap map[uint64]string) []string {
	var clean []string
	for _, raw := range lines {
		trim := strings.TrimSpace(raw)
		if trim == "" || strings.HasPrefix(trim, "Disassembly of section ") || strings.Contains(trim, ":     file format ") {
			continue
		}
		if m := reAddrComment.FindStringSubmatch(trim); len(m) >= 2 && len(strMap) > 0 {
			if addr, err := strconv.ParseUint(m[1], 16, 64); err == nil {
				if s, ok := strMap[addr]; ok {
					trim = fmt.Sprintf("%s ; str=%q", trim, s)
				}
			}
		}
		clean = append(clean, trim)
	}
	return clean
}

func annotateObjdumpReciprocalDivs(lines []string) []string {
	var notes []string
	seen := map[string]bool{}
	for i, ln := range lines {
		ms := reShiftConst.FindStringSubmatch(ln)
		if len(ms) == 0 {
			continue
		}
		hx := ms[1]
		if hx == "" {
			hx = ms[2]
		}
		shiftVal, err := strconv.ParseInt(hx, 16, 64)
		if err != nil || shiftVal < 0 || shiftVal > 16 {
			continue
		}
		start := i - 6
		if start < 0 {
			start = 0
		}
		for _, prev := range lines[start:i] {
			mm := reImulConst.FindStringSubmatch(prev)
			if len(mm) < 2 {
				continue
			}
			mVal, err := strconv.ParseUint(mm[1], 16, 64)
			if err != nil || mVal == 0 || mVal >= 0x80000000 {
				continue
			}
			ratio := float64(uint64(1)<<uint(32+shiftVal)) / float64(mVal)
			d := math.Round(ratio)
			if d >= 2 && math.Abs(ratio-d) < 0.02 {
				note := fmt.Sprintf("strength-reduced division near '%s': imul 0x%s + shift 0x%x == signed div by %.0f (%.4g%%)",
					strings.TrimSpace(ln), mm[1], shiftVal, d, 100.0/d)
				if !seen[note] {
					seen[note] = true
					notes = append(notes, note)
				}
				break
			}
		}
	}
	return notes
}
