// xtforge-hub: Go concurrency, MCP gateway, LSP multiplexer, RE runtime,
// research pipeline, and restart-safe loop daemon for xt-forge.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"xtforge-hub/internal/guard"
	"xtforge-hub/internal/loopd"
	"xtforge-hub/internal/lsp"
	"xtforge-hub/internal/mcp"
	"xtforge-hub/internal/rehub"
	"xtforge-hub/internal/research"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) == 0 {
		printJSON(map[string]any{
			"ok":      true,
			"service": "xtforge-hub",
			"version": "0.4.0",
			"nouns":   []string{"mcp", "code", "re", "research", "loop", "guard"},
		})
		return 0
	}
	// Strip global flags (--json, --db, --flash-base) anywhere so caller syntax is uniform.
	filtered := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--json" {
			continue
		}
		if (a == "--db" || a == "--flash-base") && i+1 < len(args) {
			i++
			continue
		}
		filtered = append(filtered, a)
	}
	if len(filtered) == 0 {
		return 0
	}

	noun := filtered[0]
	rest := filtered[1:]

	switch noun {
	case "mcp":
		return handleMCP(rest)
	case "code":
		return handleCode(rest)
	case "re":
		return handleRE(rest)
	case "research":
		return handleResearch(rest)
	case "loop":
		return handleLoop(rest)
	case "guard":
		return handleGuard(rest)
	default:
		return printError("unsupported hub noun: " + noun)
	}
}

func handleMCP(args []string) int {
	if len(args) == 0 {
		return printError("mcp requires a verb: serve|proxy|audit|trust")
	}
	verb := args[0]
	rest := args[1:]

	switch verb {
	case "serve":
		maxBytes := flagInt(rest, "--max-bytes", 16384)
		return mcp.ServeMeta(mcp.ResolveSelfBinary(), maxBytes)
	case "proxy":
		prefix := flagStr(rest, "--prefix", "proxy")
		cmdStr := flagStr(rest, "--cmd", "")
		maxBytes := flagInt(rest, "--max-bytes", 16384)
		trustFirst := hasFlag(rest, "--trust-on-first")
		if cmdStr == "" {
			return printError("mcp proxy requires --cmd '<upstream command>'")
		}
		parts := strings.Fields(cmdStr)
		return mcp.ServeProxy(prefix, parts, maxBytes, trustFirst)
	case "audit", "trust":
		serverName := flagStr(rest, "--server", "")
		cmdStr := flagStr(rest, "--cmd", "")
		trust := verb == "trust" || hasFlag(rest, "--pin")
		trustOnFirst := hasFlag(rest, "--trust-on-first")
		if serverName == "" && len(rest) > 0 && !strings.HasPrefix(rest[0], "-") {
			serverName = rest[0]
		}
		if cmdStr == "" {
			// Return trust DB overview when no live command is specified.
			db := mcp.LoadTrust()
			return printJSON(map[string]any{"ok": true, "trust_path": mcp.TrustPath(), "servers": db.Servers})
		}
		tools, err := probeToolsList(strings.Fields(cmdStr))
		if err != nil {
			return printError(err.Error())
		}
		if serverName == "" {
			serverName = filepathBase(strings.Fields(cmdStr)[0])
		}
		if trust {
			rec, err := mcp.PinTrust(serverName, cmdStr, tools)
			if err != nil {
				return printError(err.Error())
			}
			return printJSON(map[string]any{"ok": true, "action": "pinned", "record": rec})
		}
		res := mcp.EvaluateTools(serverName, cmdStr, tools, trustOnFirst)
		printJSON(map[string]any{
			"ok":         res.OK,
			"server":     res.Server,
			"status":     res.Status,
			"rug_pull":   res.Status == "rug_pull",
			"sha256":     res.SchemaSHA256,
			"tool_count": res.ToolCount,
			"findings":   res.Findings,
		})
		if !res.OK {
			return 1
		}
		return 0
	default:
		return printError("unknown mcp hub verb: " + verb)
	}
}

func probeToolsList(cmdArgs []string) ([]mcp.ToolDef, error) {
	if len(cmdArgs) == 0 {
		return nil, fmt.Errorf("empty command")
	}
	cmd := exec.Command(cmdArgs[0], cmdArgs[1:]...)
	in, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	defer func() {
		_ = in.Close()
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	}()

	reqs := []string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"xtforge-audit","version":"0.4.0"}}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}`,
	}
	for _, r := range reqs {
		_, _ = in.Write([]byte(r + "\n"))
	}
	_ = in.Close()

	raw, _ := ioReadAllLimit(out, 8*1024*1024)
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var resp struct {
			ID     any `json:"id"`
			Result struct {
				Tools []mcp.ToolDef `json:"tools"`
			} `json:"result"`
		}
		if json.Unmarshal([]byte(line), &resp) == nil && len(resp.Result.Tools) > 0 {
			return resp.Result.Tools, nil
		}
	}
	return nil, fmt.Errorf("no tools/list response received from upstream MCP server")
}

func ioReadAllLimit(r interface{ Read([]byte) (int, error) }, max int) ([]byte, error) {
	var out []byte
	buf := make([]byte, 4096)
	for len(out) < max {
		n, err := r.Read(buf)
		if n > 0 {
			out = append(out, buf[:n]...)
		}
		if err != nil {
			break
		}
	}
	return out, nil
}

func handleCode(args []string) int {
	if len(args) == 0 || args[0] != "lsp" {
		return printError("code hub expects: code lsp <def|refs|hover|symbols|diag|rename> <file>")
	}
	rest := args[1:]
	if len(rest) < 2 {
		return printError("usage: code lsp <def|refs|hover|symbols|diag|rename> <file> [--line N] [--col N] [--name NEW]")
	}
	verb := rest[0]
	filePath := rest[1]
	line := flagInt(rest[2:], "--line", 1)
	col := flagInt(rest[2:], "--col", 1)
	newName := flagStr(rest[2:], "--name", "")
	res := lsp.Query(verb, filePath, line, col, newName)
	return printJSONCode(res)
}

func handleRE(args []string) int {
	if len(args) < 2 {
		return printError("re hub expects: re <asar|netcap|apk|decompile|trace> <path>")
	}
	verb := args[0]
	filePath := args[1]
	rest := args[2:]

	switch verb {
	case "asar":
		extract := flagStr(rest, "--out", "")
		lim := flagInt(rest, "--limit", 200)
		return printJSONCode(rehub.InspectASAR(filePath, extract, lim))
	case "netcap":
		lim := flagInt(rest, "--limit", 50)
		return printJSONCode(rehub.InspectNetcap(filePath, lim))
	case "apk":
		return printJSONCode(rehub.InspectAPK(filePath))
	case "decompile":
		sym := flagStr(rest, "--symbol", "")
		rva := flagStr(rest, "--rva", "")
		eng := flagStr(rest, "--engine", "auto")
		maxL := flagInt(rest, "--max-lines", 160)
		return printJSONCode(rehub.Decompile(filePath, sym, rva, eng, maxL))
	case "trace":
		preset := flagStr(rest, "--preset", "api_trace")
		tok := flagStr(rest, "--confirm", "")
		dry := hasFlag(rest, "--dry-run")
		return printJSONCode(rehub.Trace(filePath, preset, tok, dry))
	default:
		return printError("unknown re hub verb: " + verb)
	}
}

func handleResearch(args []string) int {
	if len(args) == 0 {
		return printError("usage: research run <query> [--target NAME] [--web]")
	}
	rest := args
	if args[0] == "run" {
		rest = args[1:]
	}
	var queryParts []string
	for i := 0; i < len(rest); i++ {
		if strings.HasPrefix(rest[i], "--") {
			if rest[i] == "--target" && i+1 < len(rest) {
				i++
			}
			continue
		}
		queryParts = append(queryParts, rest[i])
	}
	query := strings.Join(queryParts, " ")
	target := flagStr(rest, "--target", "")
	includeWeb := hasFlag(rest, "--web")
	return printJSONCode(research.Run(mcp.ResolveSelfBinary(), query, target, includeWeb))
}

func handleLoop(args []string) int {
	if len(args) == 0 {
		return printError("usage: loop <schedule|list|stop> ...")
	}
	verb := args[0]
	rest := args[1:]
	switch verb {
	case "list":
		items, err := loopd.LoadAll()
		if err != nil {
			return printError(err.Error())
		}
		return printJSON(map[string]any{"ok": true, "disabled": loopd.Disabled(), "count": len(items), "schedules": items})
	case "schedule":
		task := ""
		if len(rest) > 0 && !strings.HasPrefix(rest[0], "-") {
			task = rest[0]
		}
		if t := flagStr(rest, "--cmd", ""); t != "" {
			if task != "" {
				// Positional interval + --cmd syntax (`loop schedule 5m --cmd "..."`).
				if sec, ok := parseDurationSeconds(task); ok {
					rest = append(rest, "--interval", strconv.Itoa(sec))
				}
			}
			task = t
		}
		if t := flagStr(rest, "--task", ""); t != "" {
			task = t
		}
		sess := flagStr(rest, "--session", "default")
		mode := flagStr(rest, "--mode", "fixed")
		interval := int64(flagInt(rest, "--interval", 300))
		res, err := loopd.Add(sess, task, mode, interval)
		if err != nil {
			return printError(err.Error())
		}
		res["task"] = map[string]any{"id": res["id"], "cmd": task, "interval": interval}
		return printJSONCode(res)
	case "stop":
		id := "all"
		if len(rest) > 0 && !strings.HasPrefix(rest[0], "-") {
			id = rest[0]
		}
		if f := flagStr(rest, "--id", ""); f != "" {
			id = f
		}
		res, err := loopd.Stop(id)
		if err != nil {
			return printError(err.Error())
		}
		return printJSONCode(res)
	default:
		return printError("unknown loop hub verb: " + verb)
	}
}

func parseDurationSeconds(s string) (int, bool) {
	s = strings.TrimSpace(strings.ToLower(s))
	if len(s) < 2 {
		return 0, false
	}
	unit := s[len(s)-1]
	n, err := strconv.Atoi(s[:len(s)-1])
	if err != nil || n <= 0 {
		return 0, false
	}
	switch unit {
	case 's':
		return n, true
	case 'm':
		return n * 60, true
	case 'h':
		return n * 3600, true
	default:
		return 0, false
	}
}

func handleGuard(args []string) int {
	if len(args) == 0 || args[0] == "status" {
		return printJSON(map[string]any{
			"ok":      true,
			"mode":    readPersistedGuardMode(),
			"xt_home": guard.XTHome(),
			"roots":   guard.Roots(),
		})
	}
	if args[0] == "mode" {
		if len(args) >= 2 && !strings.HasPrefix(args[1], "-") {
			m := strings.ToLower(strings.TrimSpace(args[1]))
			if m != "explore" && m != "ask" && m != "auto" {
				return printError("invalid guard mode: " + m + " (expected explore|ask|auto)")
			}
			_ = os.MkdirAll(guard.XTHome(), 0o755)
			if err := os.WriteFile(guard.XTHome()+"/guard_mode.txt", []byte(m+"\n"), 0o644); err != nil {
				return printError(err.Error())
			}
			guard.AuditEvent("cli", "user", "guard.mode", m, map[string]any{"mode": m}, 0)
			return printJSON(map[string]any{"ok": true, "mode": m, "engine": "go"})
		}
		return printJSON(map[string]any{"ok": true, "mode": readPersistedGuardMode(), "engine": "go"})
	}
	return printError("unknown guard verb: " + args[0])
}

func readPersistedGuardMode() string {
	if env := strings.TrimSpace(os.Getenv("XT_PERM_MODE")); env != "" {
		return string(guard.CurrentMode())
	}
	if raw, err := os.ReadFile(guard.XTHome() + "/guard_mode.txt"); err == nil {
		m := strings.ToLower(strings.TrimSpace(string(raw)))
		if m == "explore" || m == "ask" || m == "auto" {
			return m
		}
	}
	return string(guard.CurrentMode())
}

func flagStr(args []string, flag, def string) string {
	for i := 0; i < len(args); i++ {
		if args[i] == flag && i+1 < len(args) {
			return args[i+1]
		}
		if strings.HasPrefix(args[i], flag+"=") {
			return strings.SplitN(args[i], "=", 2)[1]
		}
	}
	return def
}

func flagInt(args []string, flag string, def int) int {
	raw := flagStr(args, flag, "")
	if raw == "" {
		return def
	}
	v, err := strconv.Atoi(raw)
	if err != nil {
		return def
	}
	return v
}

func hasFlag(args []string, flag string) bool {
	for _, a := range args {
		if a == flag {
			return true
		}
	}
	return false
}

func filepathBase(p string) string {
	parts := strings.Split(strings.ReplaceAll(p, "\\", "/"), "/")
	return parts[len(parts)-1]
}

func printJSON(v any) int {
	b, _ := json.MarshalIndent(v, "", "  ")
	fmt.Println(string(b))
	return 0
}

func printJSONCode(v map[string]any) int {
	b, _ := json.MarshalIndent(v, "", "  ")
	fmt.Println(string(b))
	if ok, exists := v["ok"].(bool); exists && !ok {
		return 1
	}
	return 0
}

func printError(msg string) int {
	b, _ := json.MarshalIndent(map[string]any{"ok": false, "error": msg}, "", "  ")
	fmt.Println(string(b))
	return 1
}
