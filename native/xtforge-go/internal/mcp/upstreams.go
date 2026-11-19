package mcp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"xtforge-hub/internal/guard"
)

// UpstreamConfig defines one persisted or preset external stdio MCP server.
type UpstreamConfig struct {
	Name    string            `json:"name"`
	Command []string          `json:"command"`
	Env     map[string]string `json:"env,omitempty"`
	Source  string            `json:"source,omitempty"`
}

type upstreamsFile struct {
	Version   int                       `json:"version"`
	Upstreams map[string]UpstreamConfig `json:"upstreams"`
}

type cachedCatalog struct {
	Server    string    `json:"server"`
	FetchedAt int64     `json:"fetched_at"`
	Tools     []ToolDef `json:"tools"`
}

// UpstreamsPath returns $XT_HOME/mcp_upstreams.json.
func UpstreamsPath() string {
	return filepath.Join(guard.XTHome(), "mcp_upstreams.json")
}

// CatalogCachePath returns $XT_HOME/cache/mcp-catalog-<server>.json.
func CatalogCachePath(server string) string {
	safe := strings.NewReplacer("/", "_", "\\", "_", ":", "_", " ", "_").Replace(server)
	return filepath.Join(guard.XTHome(), "cache", "mcp-catalog-"+safe+".json")
}

// LoadUpstreams reads user-configured external upstreams from $XT_HOME/mcp_upstreams.json.
func LoadUpstreams() map[string]UpstreamConfig {
	out := map[string]UpstreamConfig{}
	raw, err := os.ReadFile(UpstreamsPath())
	if err != nil {
		return out
	}
	var parsed upstreamsFile
	if json.Unmarshal(raw, &parsed) == nil && parsed.Upstreams != nil {
		for k, v := range parsed.Upstreams {
			if v.Name == "" {
				v.Name = k
			}
			out[k] = v
		}
	}
	return out
}

// SaveUpstream writes or updates an upstream server entry in $XT_HOME/mcp_upstreams.json.
func SaveUpstream(cfg UpstreamConfig) error {
	p := UpstreamsPath()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	cur := LoadUpstreams()
	cur[cfg.Name] = cfg
	payload := upstreamsFile{Version: 1, Upstreams: cur}
	b, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return err
	}
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

// SaveCachedCatalog stores a server's tools/list catalog under $XT_HOME/cache/.
func SaveCachedCatalog(server string, tools []ToolDef) error {
	p := CatalogCachePath(server)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	b, err := json.Marshal(cachedCatalog{
		Server:    server,
		FetchedAt: time.Now().Unix(),
		Tools:     tools,
	})
	if err != nil {
		return err
	}
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

// LoadCachedCatalog reads a previously probed tools/list snapshot for server.
func LoadCachedCatalog(server string) []ToolDef {
	raw, err := os.ReadFile(CatalogCachePath(server))
	if err != nil {
		return nil
	}
	var c cachedCatalog
	if json.Unmarshal(raw, &c) != nil {
		return nil
	}
	return c.Tools
}

// CanonicalUpstreamName normalizes common aliases for REA, Craft Anything, Borer, and Ghidra.
func CanonicalUpstreamName(name string) string {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "rea", "rea-agents", "re-mcp", "rea_mcp":
		return "rea"
	case "craft", "craft-anything", "craftanything", "craft-anything-cli", "craft_anything":
		return "craft-anything"
	case "borer", "borer-mcp", "borer-cli", "borer_mcp":
		return "borer"
	case "ghidra", "ghidra-mcp", "ghidramcp", "pyghidra", "pyghidra-mcp", "ghidra_mcp":
		return "ghidra"
	default:
		return strings.TrimSpace(name)
	}
}

// SplitCommand tokenizes a shell-like command string while preserving quoted
// arguments and Windows backslashes outside escape quotes.
func SplitCommand(cmdLine string) []string {
	var args []string
	var cur strings.Builder
	var quote rune
	inToken := false

	runes := []rune(cmdLine)
	for i := 0; i < len(runes); i++ {
		r := runes[i]
		if quote != 0 {
			if r == quote {
				quote = 0
				continue
			}
			if quote == '"' && r == '\\' && i+1 < len(runes) && (runes[i+1] == '"' || runes[i+1] == '\\') {
				i++
				cur.WriteRune(runes[i])
				continue
			}
			cur.WriteRune(r)
			continue
		}
		switch r {
		case '\'', '"':
			quote = r
			inToken = true
		case ' ', '\t', '\n', '\r':
			if inToken {
				args = append(args, cur.String())
				cur.Reset()
				inToken = false
			}
		default:
			cur.WriteRune(r)
			inToken = true
		}
	}
	if inToken {
		args = append(args, cur.String())
	}
	return args
}

func homeDir() string {
	if h := os.Getenv("HOME"); h != "" {
		return h
	}
	if h := os.Getenv("USERPROFILE"); h != "" {
		return h
	}
	h, _ := os.UserHomeDir()
	return h
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}

func firstExecutable(names ...string) string {
	for _, n := range names {
		if p, err := exec.LookPath(n); err == nil {
			return p
		}
	}
	return ""
}

func hasArg(args []string, targets ...string) bool {
	for _, a := range args {
		for _, t := range targets {
			if a == t {
				return true
			}
		}
	}
	return false
}

// ResolvePresetCommand returns the stdio command argv for a built-in preset
// ("rea", "craft-anything") or a saved entry in $XT_HOME/mcp_upstreams.json.
func ResolvePresetCommand(name string) (string, []string, error) {
	canon := CanonicalUpstreamName(name)
	saved := LoadUpstreams()
	if cfg, ok := saved[canon]; ok && len(cfg.Command) > 0 {
		return canon, cfg.Command, nil
	}
	if cfg, ok := saved[name]; ok && len(cfg.Command) > 0 {
		return name, cfg.Command, nil
	}

	home := homeDir()
	switch canon {
	case "rea":
		if os.Getenv("XT_REPLACE_REA") == "1" {
			if py := firstExecutable("python3", "python"); py != "" {
				return canon, []string{py, "-m", "xtforge.adapters.ghidra_mcp"}, nil
			}
		}
		if raw := strings.TrimSpace(os.Getenv("REA_CMD")); raw != "" {
			parts := SplitCommand(raw)
			if len(parts) > 0 {
				if extra := strings.TrimSpace(os.Getenv("REA_ARGS")); extra != "" {
					parts = append(parts, SplitCommand(extra)...)
				} else if !hasArg(parts, "mcp", "--mcp") {
					parts = append(parts, "mcp")
				}
				return canon, parts, nil
			}
		}
		if p := firstExecutable("rea-agents", "rea"); p != "" {
			return canon, []string{p, "mcp"}, nil
		}
		localCandidates := []string{
			filepath.Join(home, ".local", "share", "rea", "node_modules", ".bin", "rea-agents"),
			filepath.Join(home, ".local", "share", "rea", "node_modules", ".bin", "rea"),
		}
		if runtime.GOOS == "windows" {
			localCandidates = append([]string{
				filepath.Join(home, ".local", "share", "rea", "node_modules", ".bin", "rea-agents.cmd"),
				filepath.Join(home, "AppData", "Local", "rea", "node_modules", ".bin", "rea-agents.cmd"),
			}, localCandidates...)
		}
		for _, cand := range localCandidates {
			if fileExists(cand) {
				return canon, []string{cand, "mcp"}, nil
			}
		}
		if os.Getenv("XT_REA_NPX") == "1" {
			if npx := firstExecutable("npx", "npx.cmd"); npx != "" {
				return canon, []string{npx, "-y", "rea-agents@latest", "mcp"}, nil
			}
		}
		if py := firstExecutable("python3", "python"); py != "" {
			return canon, []string{py, "-m", "xtforge.adapters.ghidra_mcp"}, nil
		}
		return canon, nil, fmt.Errorf("rea executable not found (set REA_CMD or install rea-agents)")

	case "craft-anything":
		appendCraftFlags := func(base []string) []string {
			out := append([]string{}, base...)
			if !hasArg(out, "mcp") {
				out = append(out, "mcp")
			}
			// Expose all 300+ tools behind xt-forge's compact proxy unless explicitly opted out.
			if os.Getenv("XT_CRAFT_ALL_TOOLS") != "0" && !hasArg(out, "--all-tools") {
				out = append(out, "--all-tools")
			}
			if os.Getenv("XT_CRAFT_DEEP") == "1" && !hasArg(out, "--deep") {
				out = append(out, "--deep")
			}
			if os.Getenv("XT_CRAFT_ALLOW_RUN") == "1" && !hasArg(out, "--allow-run") {
				out = append(out, "--allow-run")
			}
			if proj := strings.TrimSpace(os.Getenv("XT_CRAFT_PROJECT")); proj != "" && !hasArg(out, "--project") {
				out = append(out, "--project", proj)
			}
			return out
		}
		if raw := strings.TrimSpace(os.Getenv("CRAFT_ANYTHING_CMD")); raw != "" {
			parts := SplitCommand(raw)
			if len(parts) > 0 {
				return canon, appendCraftFlags(parts), nil
			}
		}
		if p := firstExecutable("craft-anything-cli", "craft-anything"); p != "" {
			return canon, appendCraftFlags([]string{p}), nil
		}
		exe := ""
		if runtime.GOOS == "windows" {
			exe = ".exe"
		}
		candidates := []string{
			filepath.Join(home, ".cargo", "bin", "craft-anything-cli"+exe),
			filepath.Join(home, ".local", "bin", "craft-anything-cli"+exe),
		}
		for _, cand := range candidates {
			if fileExists(cand) {
				return canon, appendCraftFlags([]string{cand}), nil
			}
		}
		return canon, nil, fmt.Errorf("craft-anything-cli not found (set CRAFT_ANYTHING_CMD or install craft-anything-cli)")

	case "borer":
		appendBorerFlags := func(base []string) []string {
			out := append([]string{}, base...)
			if extra := strings.TrimSpace(os.Getenv("BORER_ARGS")); extra != "" {
				out = append(out, SplitCommand(extra)...)
			}
			return out
		}
		if raw := strings.TrimSpace(os.Getenv("BORER_CMD")); raw != "" {
			parts := SplitCommand(raw)
			if len(parts) > 0 {
				return canon, appendBorerFlags(parts), nil
			}
		}
		if p := firstExecutable("borer"); p != "" {
			return canon, appendBorerFlags([]string{p}), nil
		}
		exe := ""
		if runtime.GOOS == "windows" {
			exe = ".exe"
		}
		candidates := []string{
			filepath.Join(home, ".cargo", "bin", "borer"+exe),
			filepath.Join(home, ".local", "bin", "borer"+exe),
		}
		for _, cand := range candidates {
			if fileExists(cand) {
				return canon, appendBorerFlags([]string{cand}), nil
			}
		}
		return canon, nil, fmt.Errorf("borer executable not found (set BORER_CMD or install imjustprism/borer)")

	case "ghidra":
		if raw := strings.TrimSpace(os.Getenv("GHIDRA_MCP_CMD")); raw != "" {
			parts := SplitCommand(raw)
			if len(parts) > 0 {
				if extra := strings.TrimSpace(os.Getenv("GHIDRA_MCP_ARGS")); extra != "" {
					parts = append(parts, SplitCommand(extra)...)
				}
				return canon, parts, nil
			}
		}
		if p := firstExecutable("ghidra-mcp", "pyghidra-mcp"); p != "" {
			return canon, []string{p}, nil
		}
		if py := firstExecutable("python3", "python"); py != "" {
			return canon, []string{py, "-m", "xtforge.adapters.ghidra_mcp"}, nil
		}
		return canon, nil, fmt.Errorf("ghidra-mcp or python3 not found (set GHIDRA_MCP_CMD)")
	}

	return canon, nil, fmt.Errorf("unknown MCP server '%s' (pass --cmd or configure %s)", name, UpstreamsPath())
}

// KnownUpstreams returns every upstream server configured in $XT_HOME/mcp_upstreams.json,
// XT_MCP_UPSTREAMS, cached catalogs, or detected locally (rea / craft-anything / borer / ghidra).
func KnownUpstreams() []string {
	seen := map[string]bool{}
	var order []string
	add := func(n string) {
		c := CanonicalUpstreamName(n)
		if c != "" && !seen[c] {
			seen[c] = true
			order = append(order, c)
		}
	}
	for name := range LoadUpstreams() {
		add(name)
	}
	if envList := strings.TrimSpace(os.Getenv("XT_MCP_UPSTREAMS")); envList != "" {
		for _, item := range strings.Split(envList, ",") {
			add(item)
		}
	}
	// Include any cached catalog files already probed.
	cacheDir := filepath.Join(guard.XTHome(), "cache")
	if entries, err := os.ReadDir(cacheDir); err == nil {
		for _, e := range entries {
			n := e.Name()
			if strings.HasPrefix(n, "mcp-catalog-") && strings.HasSuffix(n, ".json") {
				srv := strings.TrimSuffix(strings.TrimPrefix(n, "mcp-catalog-"), ".json")
				add(srv)
			}
		}
	}
	// Also include locally installed rea / craft-anything / borer / ghidra presets without running npx downloads.
	for _, preset := range []string{"rea", "craft-anything", "borer", "ghidra"} {
		if !seen[preset] {
			if _, argv, err := ResolvePresetCommand(preset); err == nil && len(argv) > 0 {
				base := filepath.Base(argv[0])
				if base != "npx" && base != "npx.cmd" {
					add(preset)
				}
			}
		}
	}
	return order
}

func mcpCallTimeout() time.Duration {
	if raw := strings.TrimSpace(os.Getenv("XT_MCP_TIMEOUT")); raw != "" {
		if sec, err := strconv.Atoi(raw); err == nil && sec > 0 {
			return time.Duration(sec) * time.Second
		}
	}
	return 45 * time.Second
}

type upstreamLine struct {
	line []byte
	err  error
}

// UpstreamSession manages a persistent stdio JSON-RPC connection to one child MCP server.
type UpstreamSession struct {
	Name         string
	Cmd          []string
	proc         *exec.Cmd
	in           io.WriteCloser
	reader       *bufio.Reader
	lines        chan upstreamLine
	done         chan struct{}
	mu           sync.Mutex
	writeMu      sync.Mutex
	nextID       int
	tools        []ToolDef
	dirty        bool   // set when notifications/tools/list_changed arrives
	loadedBinary string // tracks active binary loaded into a borer session
}

// BorerSessionPath returns $XT_HOME/cache/borer-session.json.
func BorerSessionPath() string {
	return filepath.Join(guard.XTHome(), "cache", "borer-session.json")
}

func saveBorerSession(binPath string) {
	binPath = strings.TrimSpace(binPath)
	if binPath == "" {
		return
	}
	p := BorerSessionPath()
	_ = os.MkdirAll(filepath.Dir(p), 0o755)
	b, err := json.Marshal(map[string]any{"path": binPath, "updated_at": time.Now().Unix()})
	if err == nil {
		_ = os.WriteFile(p, b, 0o600)
	}
}

func loadBorerSession() string {
	raw, err := os.ReadFile(BorerSessionPath())
	if err != nil {
		return ""
	}
	var parsed struct {
		Path string `json:"path"`
	}
	if json.Unmarshal(raw, &parsed) == nil && fileExists(strings.TrimSpace(parsed.Path)) {
		return strings.TrimSpace(parsed.Path)
	}
	return ""
}

// StartUpstreamSession spawns an upstream stdio MCP server, completes initialize +
// notifications/initialized, and loads its initial tools/list snapshot.
func StartUpstreamSession(name string, argv []string) (*UpstreamSession, error) {
	if len(argv) == 0 {
		return nil, fmt.Errorf("empty upstream command for %s", name)
	}
	cmd := exec.Command(argv[0], argv[1:]...)
	savedUp := LoadUpstreams()
	var customEnv map[string]string
	if cfg, ok := savedUp[CanonicalUpstreamName(name)]; ok && len(cfg.Env) > 0 {
		customEnv = cfg.Env
	} else if cfg, ok := savedUp[name]; ok && len(cfg.Env) > 0 {
		customEnv = cfg.Env
	}
	if len(customEnv) > 0 {
		envMap := os.Environ()
		for k, v := range customEnv {
			envMap = append(envMap, k+"="+v)
		}
		cmd.Env = envMap
	}
	for _, a := range argv {
		if strings.HasPrefix(a, "xtforge.") {
			envMap := cmd.Env
			if len(envMap) == 0 {
				envMap = os.Environ()
			}
			if exePath, err := os.Executable(); err == nil {
				for _, rel := range []string{"..", filepath.Join("..", "..")} {
					cand := filepath.Clean(filepath.Join(filepath.Dir(exePath), rel))
					if fileExists(filepath.Join(cand, "xtforge", "__init__.py")) {
						curPy := os.Getenv("PYTHONPATH")
						if curPy != "" {
							envMap = append(envMap, "PYTHONPATH="+cand+string(os.PathListSeparator)+curPy)
						} else {
							envMap = append(envMap, "PYTHONPATH="+cand)
						}
						cmd.Env = envMap
						break
					}
				}
			}
			break
		}
	}
	upIn, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	upOut, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start %s (%s): %w", name, argv[0], err)
	}

	s := &UpstreamSession{
		Name:   CanonicalUpstreamName(name),
		Cmd:    append([]string{}, argv...),
		proc:   cmd,
		in:     upIn,
		reader: bufio.NewReaderSize(upOut, 1024*1024),
		lines:  make(chan upstreamLine, 32),
		done:   make(chan struct{}),
		nextID: 1,
	}
	go s.readLoop()

	if _, rpcErr := s.callLocked("initialize", map[string]any{
		"protocolVersion": ProtocolVersion,
		"capabilities":    map[string]any{},
		"clientInfo":      map[string]any{"name": "xtforge-hub", "version": "0.4.4"},
	}); rpcErr != nil {
		s.Close()
		return nil, fmt.Errorf("initialize %s: %s", s.Name, rpcErr.Message)
	}
	notif, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized"})
	if _, err := s.in.Write(append(notif, '\n')); err != nil {
		s.Close()
		return nil, fmt.Errorf("send initialized to %s: %w", s.Name, err)
	}
	if _, err := s.RefreshTools(); err != nil {
		s.Close()
		return nil, err
	}
	return s, nil
}

// Close shuts down stdin and terminates the child process cleanly.
func (s *UpstreamSession) Close() {
	if s == nil {
		return
	}
	if s.in != nil {
		_ = s.in.Close()
	}
	if s.proc != nil && s.proc.Process != nil {
		_ = s.proc.Process.Kill()
		_, _ = s.proc.Process.Wait()
	}
}

func (s *UpstreamSession) Tools() []ToolDef {
	s.mu.Lock()
	needRefresh := s.dirty
	out := append([]ToolDef{}, s.tools...)
	s.mu.Unlock()
	if needRefresh {
		if refreshed, err := s.RefreshTools(); err == nil {
			return refreshed
		}
	}
	return out
}

func (s *UpstreamSession) RefreshTools() ([]ToolDef, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	raw, rpcErr := s.callLocked("tools/list", map[string]any{})
	if rpcErr != nil {
		return nil, fmt.Errorf("tools/list %s: %s", s.Name, rpcErr.Message)
	}
	var parsed struct {
		Tools []ToolDef `json:"tools"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil, fmt.Errorf("decode tools/list %s: %w", s.Name, err)
	}
	s.tools = parsed.Tools
	s.dirty = false
	_ = SaveCachedCatalog(s.Name, s.tools)
	return append([]ToolDef{}, s.tools...), nil
}

// Alive reports whether the upstream child process and stdio reader are still running.
func (s *UpstreamSession) Alive() bool {
	if s == nil || s.done == nil {
		return false
	}
	select {
	case <-s.done:
		return false
	default:
		return true
	}
}

func (s *UpstreamSession) readLoop() {
	defer close(s.done)
	defer close(s.lines)
	for {
		b, err := s.reader.ReadBytes('\n')
		s.lines <- upstreamLine{line: b, err: err}
		if err != nil {
			return
		}
	}
}

// SendCancel emits an MCP notifications/cancelled message for requestID.
func (s *UpstreamSession) SendCancel(requestID int, reason string) bool {
	if s == nil || s.in == nil || requestID <= 0 {
		return false
	}
	params := map[string]any{"requestId": requestID}
	if strings.TrimSpace(reason) != "" {
		params["reason"] = reason
	}
	b, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"method":  "notifications/cancelled",
		"params":  params,
	})
	s.writeMu.Lock()
	_, err := s.in.Write(append(b, '\n'))
	s.writeMu.Unlock()
	return err == nil
}

func (s *UpstreamSession) CallTool(toolName string, args map[string]any) (json.RawMessage, *rpcError) {
	res, rpcErr, _, _, _ := s.CallToolContext(context.Background(), toolName, args)
	return res, rpcErr
}

// CallToolContext invokes toolName on the upstream session while respecting ctx cancellation
// and reporting whether the request was written to the wire (started) and whether
// notifications/cancelled was sent (cancelNotified).
func (s *UpstreamSession) CallToolContext(ctx context.Context, toolName string, args map[string]any) (json.RawMessage, *rpcError, int, bool, bool) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, &rpcError{Code: -32800, Message: "request cancelled before dispatch: " + err.Error()}, 0, false, false
	}
	callArgs := map[string]any{}
	for k, v := range args {
		callArgs[k] = v
	}

	s.mu.Lock()
	if s.Name == "borer" {
		if toolName == "query" {
			if rawURI, ok := callArgs["uri"].(string); ok {
				u := strings.TrimSpace(rawURI)
				if u != "" && !strings.Contains(u, "://") {
					callArgs["uri"] = "borer://" + strings.TrimPrefix(u, "/")
				}
			}
		}
		if toolName == "load_binary" {
			if p, _ := callArgs["path"].(string); strings.TrimSpace(p) == "" {
				if b, ok := callArgs["binary"].(string); ok && strings.TrimSpace(b) != "" {
					callArgs["path"] = strings.TrimSpace(b)
					delete(callArgs, "binary")
				}
			}
		} else if toolName != "load_project" && toolName != "save_project" && toolName != "reload" {
			var targetBin string
			if p, ok := callArgs["path"].(string); ok && strings.TrimSpace(p) != "" {
				targetBin = strings.TrimSpace(p)
				delete(callArgs, "path")
			}
			if b, ok := callArgs["binary"].(string); ok && strings.TrimSpace(b) != "" {
				if targetBin == "" {
					targetBin = strings.TrimSpace(b)
				}
				delete(callArgs, "binary")
			}
			if targetBin == "" && s.loadedBinary == "" {
				targetBin = loadBorerSession()
			}
			if targetBin != "" && targetBin != s.loadedBinary {
				if _, loadErr, _, _, _ := s.callLockedContext(ctx, "tools/call", map[string]any{
					"name":      "load_binary",
					"arguments": map[string]any{"path": targetBin},
				}); loadErr == nil {
					s.loadedBinary = targetBin
					saveBorerSession(targetBin)
				}
			}
		}
	}
	res, rpcErr, reqID, started, cancelNotified := s.callLockedContext(ctx, "tools/call", map[string]any{"name": toolName, "arguments": callArgs})
	if rpcErr == nil && s.Name == "borer" && toolName == "load_binary" {
		if p, ok := callArgs["path"].(string); ok && strings.TrimSpace(p) != "" {
			s.loadedBinary = strings.TrimSpace(p)
			saveBorerSession(s.loadedBinary)
		}
	}
	needRefresh := s.dirty || toolName == "enable_toolset" || toolName == "disable_toolset"
	s.mu.Unlock()

	if rpcErr == nil && needRefresh {
		_, _ = s.RefreshTools()
	}
	return res, rpcErr, reqID, started, cancelNotified
}

func (s *UpstreamSession) callLocked(method string, params any) (json.RawMessage, *rpcError) {
	res, rpcErr, _, _, _ := s.callLockedContext(context.Background(), method, params)
	return res, rpcErr
}

func (s *UpstreamSession) callLockedContext(ctx context.Context, method string, params any) (json.RawMessage, *rpcError, int, bool, bool) {
	if err := ctx.Err(); err != nil {
		return nil, &rpcError{Code: -32800, Message: "request cancelled before dispatch: " + err.Error()}, 0, false, false
	}

	id := s.nextID
	s.nextID++
	expectedID := strconv.Itoa(id)

	pBytes, _ := json.Marshal(params)
	req := rpcMessage{
		JSONRPC: "2.0",
		ID:      json.RawMessage(expectedID),
		Method:  method,
		Params:  pBytes,
	}
	line, _ := json.Marshal(req)
	s.writeMu.Lock()
	_, wErr := s.in.Write(append(line, '\n'))
	s.writeMu.Unlock()
	if wErr != nil {
		return nil, &rpcError{Code: -32000, Message: wErr.Error()}, id, false, false
	}

	timeout := mcpCallTimeout()
	timer := time.NewTimer(timeout)
	defer timer.Stop()

	for {
		var res upstreamLine
		var ok bool
		select {
		case res, ok = <-s.lines:
			if !ok {
				return nil, &rpcError{Code: -32000, Message: "upstream closed stdout waiting for " + method}, id, true, false
			}
		case <-ctx.Done():
			notified := s.SendCancel(id, "caller cancelled: "+ctx.Err().Error())
			return nil, &rpcError{Code: -32800, Message: "request cancelled waiting for " + method}, id, true, notified
		case <-timer.C:
			notified := s.SendCancel(id, "upstream timeout waiting for "+method)
			return nil, &rpcError{Code: -32001, Message: "upstream timeout waiting for " + method}, id, true, notified
		}

		trimmed := bytes.TrimSpace(res.line)
		if len(trimmed) > 0 {
			var msg rpcMessage
			if json.Unmarshal(trimmed, &msg) == nil {
				if len(msg.ID) == 0 || string(msg.ID) == "null" {
					if msg.Method == "notifications/tools/list_changed" {
						s.dirty = true
					}
					if res.err != nil {
						return nil, &rpcError{Code: -32000, Message: res.err.Error()}, id, true, false
					}
					continue
				}
				gotID := strings.Trim(strings.TrimSpace(string(msg.ID)), `"`)
				if gotID == expectedID {
					return msg.Result, msg.Error, id, true, false
				}
			}
		}
		if res.err != nil {
			return nil, &rpcError{Code: -32000, Message: res.err.Error()}, id, true, false
		}
	}
}

// ProbeUpstreamTools spawns cmdArgs, retrieves tools/list using a proper
// MCP handshake, caches the catalog if serverName != "", and kills the child cleanly.
func ProbeUpstreamTools(serverName string, cmdArgs []string) ([]ToolDef, error) {
	sess, err := StartUpstreamSession(serverName, cmdArgs)
	if err != nil {
		return nil, err
	}
	tools := sess.Tools()
	sess.Close()
	return tools, nil
}

// UpstreamPool holds lazy persistent stdio sessions keyed by canonical upstream name.
type UpstreamPool struct {
	mu       sync.Mutex
	sessions map[string]*UpstreamSession
}

func NewUpstreamPool() *UpstreamPool {
	return &UpstreamPool{sessions: map[string]*UpstreamSession{}}
}

func (p *UpstreamPool) GetOrStart(name string) (*UpstreamSession, error) {
	canon := CanonicalUpstreamName(name)
	p.mu.Lock()
	if s, ok := p.sessions[canon]; ok {
		if s.Alive() {
			p.mu.Unlock()
			return s, nil
		}
		delete(p.sessions, canon)
		go s.Close()
	}
	p.mu.Unlock()

	resolvedName, argv, err := ResolvePresetCommand(canon)
	if err != nil {
		return nil, err
	}
	sess, err := StartUpstreamSession(resolvedName, argv)
	if err != nil {
		return nil, err
	}

	p.mu.Lock()
	if existing, ok := p.sessions[resolvedName]; ok {
		p.mu.Unlock()
		sess.Close()
		return existing, nil
	}
	p.sessions[resolvedName] = sess
	p.mu.Unlock()
	return sess, nil
}

func (p *UpstreamPool) CloseAll() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for k, s := range p.sessions {
		s.Close()
		delete(p.sessions, k)
	}
}
