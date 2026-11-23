// xtforge-hub: Go concurrency, MCP gateway, LSP multiplexer, RE runtime,
// research pipeline, and restart-safe loop daemon for xt-forge.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"

	"xtforge-hub/internal/guard"
	"xtforge-hub/internal/intel"
	"xtforge-hub/internal/loopd"
	"xtforge-hub/internal/lsp"
	"xtforge-hub/internal/mcp"
	"xtforge-hub/internal/rehub"
	"xtforge-hub/internal/research"
	"xtforge-hub/internal/sysimage"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) == 0 {
		printJSON(map[string]any{
			"ok":      true,
			"service": "xtforge-hub",
			"version": "0.4.4",
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

	if noun == "--meta" {
		maxBytes := flagInt(rest, "--max-bytes", 16384)
		return mcp.ServeMeta(mcp.ResolveSelfBinary(), maxBytes)
	}

	switch noun {
	case "mcp":
		return handleMCP(rest)
	case "code":
		return handleCode(rest)
	case "re":
		return handleRE(rest)
	case "intel":
		return handleIntel(rest)
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

func resolveHubUpstream(serverName, cmdStr string) (string, []string, error) {
	if cmdStr != "" {
		parts := mcp.SplitCommand(cmdStr)
		if len(parts) == 0 {
			return "", nil, fmt.Errorf("empty upstream command")
		}
		srv := serverName
		if srv == "" {
			srv = filepathBase(parts[0])
		}
		return mcp.CanonicalUpstreamName(srv), parts, nil
	}
	if serverName == "" {
		return "", nil, fmt.Errorf("--server or --cmd required")
	}
	return mcp.ResolvePresetCommand(serverName)
}

func handleMCP(args []string) int {
	if len(args) == 0 {
		return printError("mcp requires a verb: serve|proxy|audit|trust|connect|journal")
	}
	verb := args[0]
	rest := args[1:]

	switch verb {
	case "serve":
		maxBytes := flagInt(rest, "--max-bytes", 16384)
		return mcp.ServeMeta(mcp.ResolveSelfBinary(), maxBytes)
	case "proxy":
		serverName := flagStr(rest, "--server", "")
		if serverName == "" && len(rest) > 0 && !strings.HasPrefix(rest[0], "-") {
			serverName = rest[0]
		}
		prefix := flagStr(rest, "--prefix", "")
		cmdStr := flagStr(rest, "--cmd", "")
		maxBytes := flagInt(rest, "--max-bytes", 16384)
		trustFirst := hasFlag(rest, "--trust-on-first")
		resolvedName, parts, err := resolveHubUpstream(serverName, cmdStr)
		if err != nil && prefix != "" && cmdStr == "" && serverName == "" {
			resolvedName, parts, err = resolveHubUpstream(prefix, "")
		}
		if err != nil {
			return printError("mcp proxy: " + err.Error())
		}
		if prefix == "" {
			if resolvedName != "" {
				prefix = strings.ReplaceAll(resolvedName, "-", "_")
			} else {
				prefix = "proxy"
			}
		}
		return mcp.ServeProxy(prefix, parts, maxBytes, trustFirst)
	case "connect":
		serverName := flagStr(rest, "--server", "")
		if serverName == "" && len(rest) > 0 && !strings.HasPrefix(rest[0], "-") {
			serverName = rest[0]
		}
		cmdStr := flagStr(rest, "--cmd", "")
		resolvedName, parts, err := resolveHubUpstream(serverName, cmdStr)
		if err != nil {
			return printError("mcp connect: " + err.Error())
		}
		tools, err := mcp.ProbeUpstreamTools(resolvedName, parts)
		if err != nil {
			return printError("mcp connect probe failed: " + err.Error())
		}
		joinedCmd := strings.Join(parts, " ")
		auditRes := mcp.EvaluateTools(resolvedName, joinedCmd, tools, true)
		if !auditRes.OK {
			printJSON(map[string]any{
				"ok":         false,
				"server":     resolvedName,
				"status":     auditRes.Status,
				"tool_count": auditRes.ToolCount,
				"findings":   auditRes.Findings,
			})
			return 1
		}
		if err := mcp.SaveUpstream(mcp.UpstreamConfig{
			Name:    resolvedName,
			Command: parts,
			Source:  "connect",
		}); err != nil {
			return printError("mcp connect save failed: " + err.Error())
		}
		return printJSON(map[string]any{
			"ok":             true,
			"server":         resolvedName,
			"command":        parts,
			"status":         auditRes.Status,
			"sha256":         auditRes.SchemaSHA256,
			"tool_count":     auditRes.ToolCount,
			"upstreams_path": mcp.UpstreamsPath(),
			"catalog_cache":  mcp.CatalogCachePath(resolvedName),
			"usage":          fmt.Sprintf(`xt-forge --meta -> xt_discover(upstream=%q) / xt_call(name=%q)`, resolvedName, resolvedName+":<tool>"),
		})
	case "audit", "trust":
		serverName := flagStr(rest, "--server", "")
		cmdStr := flagStr(rest, "--cmd", "")
		trust := verb == "trust" || hasFlag(rest, "--pin")
		trustOnFirst := hasFlag(rest, "--trust-on-first")
		if serverName == "" && len(rest) > 0 && !strings.HasPrefix(rest[0], "-") {
			serverName = rest[0]
		}
		if cmdStr == "" && serverName == "" {
			db := mcp.LoadTrust()
			return printJSON(map[string]any{
				"ok":         true,
				"trust_path": mcp.TrustPath(),
				"servers":    db.Servers,
				"upstreams":  mcp.LoadUpstreams(),
			})
		}
		resolvedName, parts, err := resolveHubUpstream(serverName, cmdStr)
		if err != nil {
			return printError(err.Error())
		}
		tools, err := mcp.ProbeUpstreamTools(resolvedName, parts)
		if err != nil {
			return printError(err.Error())
		}
		joinedCmd := strings.Join(parts, " ")
		if trust {
			rec, err := mcp.PinTrust(resolvedName, joinedCmd, tools)
			if err != nil {
				return printError(err.Error())
			}
			return printJSON(map[string]any{"ok": true, "action": "pinned", "record": rec})
		}
		res := mcp.EvaluateTools(resolvedName, joinedCmd, tools, trustOnFirst)
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
	case "journal":
		state := flagStr(rest, "--state", "")
		key := flagStr(rest, "--key", "")
		if key != "" {
			if e, ok := mcp.FindJournalByKey(key); ok {
				return printJSON(map[string]any{
					"ok":           true,
					"journal_path": mcp.JournalPath(),
					"found":        true,
					"entry":        e,
				})
			}
			return printJSON(map[string]any{
				"ok":           true,
				"journal_path": mcp.JournalPath(),
				"found":        false,
			})
		}
		entries := mcp.ListJournalEntries(state)
		return printJSON(map[string]any{
			"ok":           true,
			"journal_path": mcp.JournalPath(),
			"count":        len(entries),
			"entries":      entries,
		})
	default:
		return printError("unknown mcp hub verb: " + verb)
	}
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
	// demangle takes symbols rather than a path, so it is the one verb that is
	// valid with a single argument. Its missing-argument error is handled below.
	if len(args) == 0 || (len(args) < 2 && args[0] != "demangle") {
		return printError("re hub expects: re <overview|functions|callgraph|demangle|pdb-types|xrefs-native|dispatch-native|disasm-native|decompile-native|asar|netcap|apk|decompile|trace> <path>")
	}
	verb := args[0]
	filePath := ""
	if len(args) > 1 {
		filePath = args[1]
	}
	var rest []string
	if len(args) > 2 {
		rest = args[2:]
	}

	switch verb {
	case "callgraph":
		filePath = flagStr(args[1:], "--path", filePath)
		result, err := sysimage.CallGraph(filePath, flagStr(rest, "--member", ""),
			flagStr(rest, "--arch", ""), flagInt(rest, "--limit", 0))
		if err != nil {
			return printError(err.Error())
		}
		return printJSON(result)
	case "pdb-types":
		filePath = flagStr(args[1:], "--path", filePath)
		file, err := os.Open(filePath)
		if err != nil {
			return printError(err.Error())
		}
		defer file.Close()
		stat, err := file.Stat()
		if err != nil {
			return printError(err.Error())
		}
		census, err := sysimage.ReadPDBTypeCensus(file, stat.Size())
		if err != nil {
			return printError(err.Error())
		}
		signatures, err := sysimage.ReadPDBSignatures(file, stat.Size(), flagInt(rest, "--limit", 0))
		if err != nil {
			return printError(err.Error())
		}
		// Parameter names live in the symbol stream, not the type stream: the signature
		// knows `int*, unsigned long` and the S_LOCAL records know `values`, `count`.
		// They are joined on the procedure's type index.
		if procedures, procErr := sysimage.ReadPDBProcedures(file, stat.Size(), 0); procErr == nil {
			byType := make(map[uint32][]sysimage.PDBParameter)
			for _, procedure := range procedures {
				if len(procedure.Parameters) > 0 {
					byType[procedure.TypeIndex] = procedure.Parameters
				}
			}
			for index := range signatures {
				parameters, ok := byType[signatures[index].Index]
				if !ok {
					continue
				}
				// The argument list and the parameter records are in the same order, so
				// each name can be given the type the signature already resolved.
				for position := range parameters {
					if position < len(signatures[index].Arguments) {
						parameters[position].Type = signatures[index].Arguments[position]
					}
				}
				signatures[index].Parameters = parameters
			}
		}
		aggregates, aggErr := sysimage.ReadPDBAggregates(file, stat.Size(), flagInt(rest, "--limit", 0))
		if aggErr != nil {
			return printError(aggErr.Error())
		}
		return printJSON(map[string]any{"ok": true, "engine": "xt-forge-sys",
			"path": filePath, "census": census, "signatures": signatures,
			"aggregates": aggregates})
	case "overview":
		filePath = flagStr(args[1:], "--path", filePath)
		arch := flagStr(rest, "--arch", "")
		base := flagUint(rest, "--base", 0)
		var result sysimage.OverviewResult
		var err error
		if arch != "" {
			result, err = sysimage.OverviewWithRaw(filePath, flagStr(args[1:], "--member", ""), arch, base)
		} else {
			result, err = sysimage.Overview(filePath, flagStr(args[1:], "--member", ""))
		}
		if err != nil {
			return printError(err.Error())
		}
		return printJSON(result)
	case "functions":
		filePath = flagStr(args[1:], "--path", filePath)
		result, err := sysimage.Functions(filePath, flagStr(args[1:], "--member", ""),
			flagStr(args[1:], "--arch", ""), flagInt(args[1:], "--limit", 200))
		if err != nil {
			return printError(err.Error())
		}
		return printJSON(result)
	case "demangle":
		symbols := args[1:]
		if len(symbols) == 0 {
			return printError("usage: re demangle <symbol> [more symbols...]")
		}
		demangled := sysimage.DemangleSymbols(symbols)
		results := make([]map[string]string, len(symbols))
		for i, symbol := range symbols {
			results[i] = map[string]string{"symbol": symbol, "demangled": demangled[i]}
		}
		return printJSON(map[string]any{"ok": true, "results": results})
	case "xrefs-native":
		filePath = flagStr(args[1:], "--path", filePath)
		result, err := sysimage.References(filePath, sysimage.ReferenceOptions{
			Member:       flagStr(rest, "--member", ""),
			Arch:         flagStr(rest, "--arch", ""),
			Target:       flagStr(rest, "--target", ""),
			MaxFunctions: flagInt(rest, "--max-functions", 0),
			Limit:        flagInt(rest, "--limit", 0),
		})
		if err != nil {
			return printError(err.Error())
		}
		return printJSON(result)
	case "dispatch-native":
		filePath = flagStr(args[1:], "--path", filePath)
		result, err := sysimage.RecoverDispatch(filePath, sysimage.DispatchOptions{
			Member: flagStr(rest, "--member", ""),
			Arch:   flagStr(rest, "--arch", ""),
			Target: flagStr(rest, "--target", ""),
		})
		if err != nil {
			return printError(err.Error())
		}
		return printJSON(result)
	case "disasm-native", "decompile-native":
		filePath = flagStr(args[1:], "--path", filePath)
		options := sysimage.DisassemblyOptions{
			Member: flagStr(rest, "--member", ""),
			Arch:   flagStr(rest, "--arch", ""),
			Target: flagStr(rest, "--target", ""),
			Bytes:  flagInt(rest, "--bytes", 0),
			Count:  flagInt(rest, "--max-instructions", 0),
			Flow:   hasFlag(rest, "--flow"),
		}
		if verb == "decompile-native" {
			result, err := sysimage.Decompile(filePath, options)
			if err != nil {
				return printError(err.Error())
			}
			return printJSON(result)
		}
		result, err := sysimage.Disassemble(filePath, options)
		if err != nil {
			return printError(err.Error())
		}
		return printJSON(result)
	case "asar":
		extract := flagStr(rest, "--out", "")
		lim := flagInt(rest, "--limit", 200)
		return printJSONCode(rehub.InspectASAR(filePath, extract, lim))
	case "netcap":
		lim := flagInt(rest, "--limit", 50)
		return printJSONCode(rehub.InspectNetcap(filePath, lim))
	case "dex":
		// A loose .dex file, or a .dex inside an APK when it is given as an archive.
		lim := flagInt(rest, "limit", 40)
		if strings.HasSuffix(filePath, ".apk") || strings.HasSuffix(filePath, ".zip") {
			entry := flagStr(rest, "entry", "classes.dex")
			return printJSONCode(rehub.InspectDexEntryFull(filePath, entry, lim))
		}
		data, err := os.ReadFile(filePath)
		if err != nil {
			return printJSONCode(map[string]any{"ok": false, "error": "cannot read file: " + err.Error()})
		}
		return printJSONCode(rehub.InspectDexBytes(data, lim))
	case "apk":
		// `apk dex` enumerates classes and methods; plain `apk` is the inventory.
		if hasToken(rest, "dex") {
			entry := flagStr(rest, "entry", "classes.dex")
			lim := flagInt(rest, "limit", 40)
			return printJSONCode(rehub.InspectDexEntryFull(filePath, entry, lim))
		}
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
	case "checksec":
		return printJSONCode(rehub.Checksec(filePath))
	case "capa":
		return printJSONCode(rehub.Capa(filePath))
	default:
		return printError("unknown re hub verb: " + verb)
	}
}

func handleIntel(args []string) int {
	if len(args) == 0 {
		return printError("usage: intel <sources|ip|cve|kev|search|hash|domain> [value]")
	}
	verb := args[0]
	rest := args[1:]
	val := ""
	for i := 0; i < len(rest); i++ {
		if strings.HasPrefix(rest[i], "--") {
			if (rest[i] == "--query" || rest[i] == "--since" || rest[i] == "--limit") && i+1 < len(rest) {
				i++
			}
			continue
		}
		if val == "" {
			val = rest[i]
		}
	}
	switch verb {
	case "sources":
		return printJSONCode(intel.Sources())
	case "ip":
		return printJSONCode(intel.IP(val))
	case "cve":
		return printJSONCode(intel.CVE(val))
	case "kev":
		q := flagStr(rest, "--query", val)
		lim := flagInt(rest, "--limit", 20)
		return printJSONCode(intel.KEV(q, lim))
	case "search":
		q := flagStr(rest, "--query", val)
		lim := flagInt(rest, "--limit", 10)
		since := flagInt(rest, "--since", 0)
		return printJSONCode(intel.Search(q, lim, since))
	case "hash":
		return printJSONCode(intel.Hash(val))
	case "domain":
		return printJSONCode(intel.Domain(val))
	default:
		return printError("unknown intel hub verb: " + verb)
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

// hasToken reports whether a bare word appears in the argument list, for
// subcommand-style dispatch (`apk dex`).
func hasToken(args []string, want string) bool {
	for _, a := range args {
		if a == want {
			return true
		}
	}
	return false
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

// flagUint reads an unsigned value, accepting decimal or 0x-prefixed hex. A base
// address is naturally written in hex, so decimal-only parsing would silently ignore the
// flag and load the image at 0.
func flagUint(args []string, flag string, def uint64) uint64 {
	raw := flagStr(args, flag, "")
	if raw == "" {
		return def
	}
	base := 10
	if strings.HasPrefix(raw, "0x") || strings.HasPrefix(raw, "0X") {
		base = 0
	}
	v, err := strconv.ParseUint(raw, base, 64)
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
