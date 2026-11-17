// Package lsp provides an on-demand Language Server Protocol client over stdio
// JSON-RPC (Content-Length framed) for compiler-grade definitions, references,
// hover info, diagnostics, and guarded symbol renames.
package lsp

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"xtforge-hub/internal/guard"
)

type ServerSpec struct {
	Lang    string
	Command string
	Args    []string
	Hint    string
}

var serverSpecs = map[string]ServerSpec{
	".py":   {Lang: "python", Command: "pyright-langserver", Args: []string{"--stdio"}, Hint: "npm i -g pyright"},
	".pyi":  {Lang: "python", Command: "pyright-langserver", Args: []string{"--stdio"}, Hint: "npm i -g pyright"},
	".rs":   {Lang: "rust", Command: "rust-analyzer", Args: nil, Hint: "rustup component add rust-analyzer"},
	".go":   {Lang: "go", Command: "gopls", Args: nil, Hint: "go install golang.org/x/tools/gopls@latest"},
	".c":    {Lang: "c", Command: "clangd", Args: nil, Hint: "install clang/clangd"},
	".h":    {Lang: "c", Command: "clangd", Args: nil, Hint: "install clang/clangd"},
	".cpp":  {Lang: "cpp", Command: "clangd", Args: nil, Hint: "install clang/clangd"},
	".hpp":  {Lang: "cpp", Command: "clangd", Args: nil, Hint: "install clang/clangd"},
	".ts":   {Lang: "typescript", Command: "typescript-language-server", Args: []string{"--stdio"}, Hint: "npm i -g typescript-language-server typescript"},
	".tsx":  {Lang: "typescript", Command: "typescript-language-server", Args: []string{"--stdio"}, Hint: "npm i -g typescript-language-server typescript"},
	".js":   {Lang: "javascript", Command: "typescript-language-server", Args: []string{"--stdio"}, Hint: "npm i -g typescript-language-server typescript"},
	".mjs":  {Lang: "javascript", Command: "typescript-language-server", Args: []string{"--stdio"}, Hint: "npm i -g typescript-language-server typescript"},
}

func DetectServer(filePath string) (ServerSpec, bool) {
	ext := strings.ToLower(filepath.Ext(filePath))
	spec, ok := serverSpecs[ext]
	return spec, ok
}

func writeLSPMessage(w io.Writer, msg any) error {
	b, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	header := fmt.Sprintf("Content-Length: %d\r\n\r\n", len(b))
	if _, err := io.WriteString(w, header); err != nil {
		return err
	}
	_, err = w.Write(b)
	return err
}

func readLSPMessage(r *bufio.Reader) (map[string]any, error) {
	contentLen := -1
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return nil, err
		}
		trimmed := strings.TrimRight(line, "\r\n")
		if trimmed == "" {
			break
		}
		if strings.HasPrefix(strings.ToLower(trimmed), "content-length:") {
			val := strings.TrimSpace(trimmed[len("content-length:"):])
			n, convErr := strconv.Atoi(val)
			if convErr == nil {
				contentLen = n
			}
		}
	}
	if contentLen <= 0 {
		return nil, fmt.Errorf("missing Content-Length")
	}
	buf := make([]byte, contentLen)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	var out map[string]any
	if err := json.Unmarshal(buf, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// Query executes a single on-demand LSP operation (def|refs|hover|symbols|diag|rename).
func Query(verb, filePath string, line, col int, newName string) map[string]any {
	canon, err := guard.ReadGuard(filePath)
	if err != nil {
		return map[string]any{"ok": false, "error": err.Error()}
	}
	spec, ok := DetectServer(canon)
	if !ok {
		return map[string]any{"ok": false, "error": "no LSP server mapping for extension: " + filepath.Ext(canon)}
	}
	binPath, lookErr := exec.LookPath(spec.Command)
	if lookErr != nil {
		return map[string]any{
			"ok":           false,
			"available":    false,
			"language":     spec.Lang,
			"server":       spec.Command,
			"install_hint": spec.Hint,
			"error":        fmt.Sprintf("LSP server '%s' not installed (%s)", spec.Command, spec.Hint),
		}
	}

	rootDir := findProjectRoot(filepath.Dir(canon))
	srcBytes, readErr := os.ReadFile(canon)
	if readErr != nil {
		return map[string]any{"ok": false, "error": readErr.Error()}
	}

	cmd := exec.Command(binPath, spec.Args...)
	inPipe, err := cmd.StdinPipe()
	if err != nil {
		return map[string]any{"ok": false, "error": err.Error()}
	}
	outPipe, err := cmd.StdoutPipe()
	if err != nil {
		return map[string]any{"ok": false, "error": err.Error()}
	}
	if err := cmd.Start(); err != nil {
		return map[string]any{"ok": false, "error": err.Error()}
	}
	defer func() {
		_ = inPipe.Close()
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	}()

	reader := bufio.NewReader(outPipe)
	rootURI := "file://" + rootDir
	docURI := "file://" + canon

	_ = writeLSPMessage(inPipe, map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "initialize",
		"params": map[string]any{
			"processId":    os.Getpid(),
			"rootUri":      rootURI,
			"capabilities": map[string]any{},
		},
	})
	if _, err := readUntilID(reader, 1, 8*time.Second); err != nil {
		return map[string]any{"ok": false, "error": "LSP initialize failed: " + err.Error()}
	}
	_ = writeLSPMessage(inPipe, map[string]any{
		"jsonrpc": "2.0",
		"method":  "initialized",
		"params":  map[string]any{},
	})
	_ = writeLSPMessage(inPipe, map[string]any{
		"jsonrpc": "2.0",
		"method":  "textDocument/didOpen",
		"params": map[string]any{
			"textDocument": map[string]any{
				"uri":        docURI,
				"languageId": spec.Lang,
				"version":    1,
				"text":       string(srcBytes),
			},
		},
	})

	// Zero-indexed LSP positions.
	zLine := max(0, line-1)
	zCol := max(0, col-1)

	var method string
	var params any
	switch verb {
	case "def":
		method = "textDocument/definition"
		params = posParams(docURI, zLine, zCol)
	case "refs":
		method = "textDocument/references"
		params = map[string]any{
			"textDocument": map[string]any{"uri": docURI},
			"position":     map[string]any{"line": zLine, "character": zCol},
			"context":      map[string]any{"includeDeclaration": true},
		}
	case "hover":
		method = "textDocument/hover"
		params = posParams(docURI, zLine, zCol)
	case "symbols":
		method = "textDocument/documentSymbol"
		params = map[string]any{"textDocument": map[string]any{"uri": docURI}}
	case "rename":
		if newName == "" {
			return map[string]any{"ok": false, "error": "rename requires --name"}
		}
		method = "textDocument/rename"
		params = map[string]any{
			"textDocument": map[string]any{"uri": docURI},
			"position":     map[string]any{"line": zLine, "character": zCol},
			"newName":      newName,
		}
	case "diag":
		diags := collectDiagnostics(reader, docURI, 2500*time.Millisecond)
		return map[string]any{
			"ok":          true,
			"language":    spec.Lang,
			"server":      spec.Command,
			"path":        canon,
			"diagnostics": diags,
			"count":       len(diags),
		}
	default:
		return map[string]any{"ok": false, "error": "unknown lsp verb: " + verb}
	}

	_ = writeLSPMessage(inPipe, map[string]any{
		"jsonrpc": "2.0",
		"id":      2,
		"method":  method,
		"params":  params,
	})
	resp, err := readUntilID(reader, 2, 10*time.Second)
	if err != nil {
		return map[string]any{"ok": false, "language": spec.Lang, "server": spec.Command, "error": err.Error()}
	}
	if errObj, hasErr := resp["error"]; hasErr {
		return map[string]any{"ok": false, "language": spec.Lang, "server": spec.Command, "error": errObj}
	}
	out := map[string]any{
		"ok":       true,
		"language": spec.Lang,
		"server":   spec.Command,
		"path":     canon,
		"verb":     verb,
		"result":   resp["result"],
	}
	if verb == "rename" {
		out["dry_run"] = true
		out["note"] = "workspace edit preview only; apply changes after review"
	}
	return out
}

func posParams(uri string, line, col int) map[string]any {
	return map[string]any{
		"textDocument": map[string]any{"uri": uri},
		"position":     map[string]any{"line": line, "character": col},
	}
}

func readUntilID(r *bufio.Reader, wantID float64, timeout time.Duration) (map[string]any, error) {
	type res struct {
		msg map[string]any
		err error
	}
	ch := make(chan res, 1)
	go func() {
		for {
			m, err := readLSPMessage(r)
			if err != nil {
				ch <- res{nil, err}
				return
			}
			if id, ok := m["id"].(float64); ok && id == wantID {
				ch <- res{m, nil}
				return
			}
		}
	}()
	select {
	case out := <-ch:
		return out.msg, out.err
	case <-time.After(timeout):
		return nil, fmt.Errorf("LSP timeout after %s", timeout)
	}
}

func collectDiagnostics(r *bufio.Reader, docURI string, wait time.Duration) []any {
	type res struct {
		m   map[string]any
		err error
	}
	ch := make(chan res, 16)
	done := make(chan struct{})
	go func() {
		for {
			select {
			case <-done:
				return
			default:
				m, err := readLSPMessage(r)
				if err != nil {
					return
				}
				ch <- res{m, nil}
			}
		}
	}()
	defer close(done)

	deadline := time.After(wait)
	var diags []any
	for {
		select {
		case item := <-ch:
			if item.m["method"] == "textDocument/publishDiagnostics" {
				if p, ok := item.m["params"].(map[string]any); ok {
					if p["uri"] == docURI {
						if arr, ok := p["diagnostics"].([]any); ok {
							diags = arr
							return diags
						}
					}
				}
			}
		case <-deadline:
			return diags
		}
	}
}

func findProjectRoot(dir string) string {
	cur := dir
	markers := []string{".git", "Cargo.toml", "go.mod", "pyproject.toml", "package.json"}
	for {
		for _, m := range markers {
			if _, err := os.Stat(filepath.Join(cur, m)); err == nil {
				return cur
			}
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return dir
		}
		cur = parent
	}
}
