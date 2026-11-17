package mcp

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"xtforge-hub/internal/compress"
	"xtforge-hub/internal/guard"
)

const ProtocolVersion = "2025-06-18"

type rpcMessage struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// CatalogEntry describes one CLI tool exposed through xt-forge meta mode.
type CatalogEntry struct {
	Name        string   `json:"name"`
	Noun        string   `json:"noun"`
	Verb        string   `json:"verb,omitempty"`
	Category    string   `json:"category"`
	Description string   `json:"description"`
	ArgsHint    string   `json:"args_hint"`
	Mutating    bool     `json:"mutating"`
	Tags        []string `json:"tags"`
}

// FullCatalog returns xt-forge's complete CLI surface for meta-tool discovery.
func FullCatalog() []CatalogEntry {
	return []CatalogEntry{
		// Reverse Engineering
		{Name: "re_info", Noun: "re", Verb: "info", Category: "re", Description: "Inspect ELF, PE, or Mach-O binary headers, arch, and entry point.", ArgsHint: `{"argv":["info","/path/to/bin"]}`, Tags: []string{"binary", "elf", "pe", "macho"}},
		{Name: "re_sections", Noun: "re", Verb: "sections", Category: "re", Description: "List binary sections with virtual size, raw size, and Shannon entropy.", ArgsHint: `{"argv":["sections","/path/to/bin"]}`, Tags: []string{"entropy", "sections"}},
		{Name: "re_symbols", Noun: "re", Verb: "symbols", Category: "re", Description: "List symbols, imports, or exports.", ArgsHint: `{"argv":["symbols","/path/to/bin","--limit","50"]}`, Tags: []string{"symbols", "imports", "exports"}},
		{Name: "re_strings", Noun: "re", Verb: "strings", Category: "re", Description: "Extract ASCII, stack-constructed, or single-byte XOR strings.", ArgsHint: `{"argv":["strings","/path/to/bin","--xor"]}`, Tags: []string{"strings", "xor", "stack"}},
		{Name: "re_pack", Noun: "re", Verb: "pack", Category: "re", Description: "Detect packed or encrypted binaries using entropy and string density.", ArgsHint: `{"argv":["pack","/path/to/bin"]}`, Tags: []string{"packer", "entropy"}},
		{Name: "re_ioc", Noun: "re", Verb: "ioc", Category: "re", Description: "Extract URLs, IPs, domains, hashes, registry keys, and CVEs.", ArgsHint: `{"argv":["ioc","/path/to/bin"]}`, Tags: []string{"ioc", "malware"}},
		{Name: "re_checksec", Noun: "re", Verb: "checksec", Category: "re", Description: "Inspect exploit mitigations (NX, PIE, Canary, RELRO, ASLR, CFG).", ArgsHint: `{"argv":["checksec","/path/to/bin"]}`, Tags: []string{"checksec", "mitigations"}},
		{Name: "re_capa", Noun: "re", Verb: "capa", Category: "re", Description: "Detect behavioral capabilities (anti-debug, injection, persistence).", ArgsHint: `{"argv":["capa","/path/to/bin"]}`, Tags: []string{"capa", "behavior"}},
		{Name: "re_cfg", Noun: "re", Verb: "cfg", Category: "re", Description: "Reconstruct function basic block CFG and cross-references.", ArgsHint: `{"argv":["cfg","/path/to/bin","--symbol","main"]}`, Tags: []string{"cfg", "disasm", "rizin"}},
		{Name: "re_rtti", Noun: "re", Verb: "rtti", Category: "re", Description: "Extract C++ RTTI classes and vtable pointers.", ArgsHint: `{"argv":["rtti","/path/to/bin"]}`, Tags: []string{"rtti", "cpp", "vtable"}},
		{Name: "re_diff", Noun: "re", Verb: "diff", Category: "re", Description: "Compare two binaries for added, removed, or modified functions.", ArgsHint: `{"argv":["diff","/bin/v1","/bin/v2"]}`, Tags: []string{"diff", "patch"}},
		{Name: "re_crash", Noun: "re", Verb: "crash", Category: "re", Description: "Analyze Windows MiniDump or Linux ELF core crash dumps.", ArgsHint: `{"argv":["crash","/path/to/core"]}`, Tags: []string{"crash", "dump", "minidump"}},
		{Name: "re_hooks", Noun: "re", Verb: "hooks", Category: "re", Description: "Scan disassembly for inline hooks and direct syscall stubs.", ArgsHint: `{"argv":["hooks","/path/to/bin"]}`, Tags: []string{"hooks", "syscalls"}},
		{Name: "re_patch", Noun: "re", Verb: "patch", Category: "re", Description: "Apply guarded atomic byte patch to a binary copy.", ArgsHint: `{"argv":["patch","/path/to/bin","--offset","0x100","--patch-bytes","9090"]}`, Mutating: true, Tags: []string{"patch", "binary"}},
		{Name: "re_annotate", Noun: "re", Verb: "annotate", Category: "re", Description: "Read or write persistent per-binary symbol renames, types, and comments.", ArgsHint: `{"argv":["annotate","rename","/path/to/bin","--rva","0x1000","--name","decrypt_cfg"]}`, Mutating: true, Tags: []string{"annotate", "rename", "overlay"}},
		{Name: "re_decompile", Noun: "re", Verb: "decompile", Category: "re", Description: "Decompile function pseudocode via rizin or headless Ghidra when installed.", ArgsHint: `{"argv":["decompile","/path/to/bin","--symbol","main"]}`, Tags: []string{"decompile", "pseudocode", "ghidra", "rizin"}},
		{Name: "re_apk", Noun: "re", Verb: "apk", Category: "re", Description: "Inspect Android APK manifest, permissions, components, and native libs.", ArgsHint: `{"argv":["apk","/path/to/app.apk"]}`, Tags: []string{"apk", "android", "jadx"}},
		{Name: "re_asar", Noun: "re", Verb: "asar", Category: "re", Description: "List or extract Electron ASAR archives and JS source maps.", ArgsHint: `{"argv":["asar","/path/to/app.asar"]}`, Tags: []string{"asar", "electron", "js"}},
		{Name: "re_netcap", Noun: "re", Verb: "netcap", Category: "re", Description: "Summarize endpoints and masked auth headers from HAR/SAZ captures.", ArgsHint: `{"argv":["netcap","/path/to/capture.har"]}`, Tags: []string{"har", "saz", "network"}},
		{Name: "re_trace", Noun: "re", Verb: "trace", Category: "re", Description: "Run capability-scoped dynamic tracing via Frida, gdb, or lldb.", ArgsHint: `{"argv":["trace","/path/to/bin","--preset","api_trace"]}`, Mutating: true, Tags: []string{"frida", "trace", "dynamic"}},

		// Code Intelligence & LSP
		{Name: "code_symbols", Noun: "code", Verb: "symbols", Category: "code", Description: "Extract symbols and signatures from source files.", ArgsHint: `{"argv":["symbols","/path/to/file.py"]}`, Tags: []string{"ast", "symbols"}},
		{Name: "code_refs", Noun: "code", Verb: "refs", Category: "code", Description: "Find symbol references across a workspace.", ArgsHint: `{"argv":["refs","MyFunc","."]}`, Tags: []string{"refs", "callers"}},
		{Name: "code_index", Noun: "code", Verb: "index", Category: "code", Description: "Index workspace symbols and call/import edges into code_graph.db.", ArgsHint: `{"argv":["index","."]}`, Mutating: true, Tags: []string{"graph", "index"}},
		{Name: "code_graph", Noun: "code", Verb: "graph", Category: "code", Description: "Query callers, callees, and imports for a symbol up to depth N.", ArgsHint: `{"argv":["graph","Store",".","--depth","2"]}`, Tags: []string{"graph", "callgraph"}},
		{Name: "code_lsp", Noun: "code", Verb: "lsp", Category: "code", Description: "Query on-demand LSP servers for definition, references, hover, or diagnostics.", ArgsHint: `{"argv":["lsp","diag","main.go"]}`, Tags: []string{"lsp", "serena", "diagnostics"}},

		// Memory, Knowledge & Recall
		{Name: "mem_search", Noun: "mem", Verb: "search", Category: "memory", Description: "BM25 + hybrid search across durable memory.", ArgsHint: `{"argv":["search","auth bug","--k","5"]}`, Tags: []string{"memory", "search"}},
		{Name: "mem_put", Noun: "mem", Verb: "put", Category: "memory", Description: "Store a durable memory record (including failed_attempt or anti_pattern).", ArgsHint: `{"argv":["put","--kind","fact","--title","...","--body","..."]}`, Mutating: true, Tags: []string{"memory", "write"}},
		{Name: "mem_consolidate", Noun: "mem", Verb: "consolidate", Category: "memory", Description: "Merge near-duplicate memory records while preserving provenance links.", ArgsHint: `{"argv":["consolidate","--dry-run"]}`, Mutating: true, Tags: []string{"memory", "dedupe"}},
		{Name: "mem_record_failure", Noun: "mem", Verb: "record-failure", Category: "memory", Description: "Record a failed attempt with error signature to prevent repeating mistakes.", ArgsHint: `{"argv":["record-failure","--title","...","--error-sig","...","--body","..."]}`, Mutating: true, Tags: []string{"negative_memory", "failure"}},
		{Name: "recall", Noun: "recall", Category: "memory", Description: "Unified cross-store recall across mem, recon, flash, errors, and artifacts.", ArgsHint: `{"argv":["query text"]}`, Tags: []string{"recall", "cross-store"}},
		{Name: "knowledge", Noun: "knowledge", Category: "memory", Description: "Lifecycle-tracked knowledge (put, get, search, verify, revise, link, deprecate).", ArgsHint: `{"argv":["search","query"]}`, Tags: []string{"knowledge", "verify"}},

		// Steering, Guardrails & Loops
		{Name: "goal_check", Noun: "goal", Verb: "check", Category: "steering", Description: "Vibe-check and anti-loop gate: checks criteria drift, diff bloat, stuck state, and prior failures.", ArgsHint: `{"argv":["check","--criteria","tests pass","--workdir","."]}`, Tags: []string{"vibe_check", "steering", "anti_loop"}},
		{Name: "goal_verify", Noun: "goal", Verb: "verify", Category: "steering", Description: "Independently verify completion claims and replay approved checks.", ArgsHint: `{"argv":["verify","--body","<goal-done>...</goal-done>","--verify","pytest"]}`, Tags: []string{"verify", "goal"}},
		{Name: "loop_policy", Noun: "loop", Verb: "policy", Category: "steering", Description: "Manage or inspect loop scheduler policy, schedules, and safety caps.", ArgsHint: `{"argv":["policy"]}`, Tags: []string{"loop", "schedule"}},
		{Name: "taste_learn", Noun: "taste", Verb: "learn", Category: "steering", Description: "Record deterministic preference evidence without overwriting conflicts.", ArgsHint: `{"argv":["search"]}`, Tags: []string{"taste", "preferences"}},

		// Research, Recon, Intel & Security
		{Name: "research_run", Noun: "research", Verb: "run", Category: "research", Description: "Run parallel multi-source research across code, mem, CVE intel, docs, and web.", ArgsHint: `{"argv":["run","CVE-2024-3094"]}`, Tags: []string{"research", "dossier", "cve"}},
		{Name: "intel", Noun: "intel", Category: "research", Description: "Keyless threat intel lookup for IP, CVE, CISA KEV, domain, or file hash.", ArgsHint: `{"argv":["cve","CVE-2024-3094"]}`, Tags: []string{"cve", "kev", "ip", "hash"}},
		{Name: "docs", Noun: "docs", Category: "research", Description: "Fetch live library documentation via Context7.", ArgsHint: `{"argv":["search","tokio"]}`, Tags: []string{"docs", "context7"}},
		{Name: "recon", Noun: "recon", Category: "security", Description: "Scoped findings ledger and deterministic markdown recon report generator.", ArgsHint: `{"argv":["list","target"]}`, Tags: []string{"recon", "findings"}},
		{Name: "scan", Noun: "scan", Category: "security", Description: "Read-only scan for secrets, risky patterns, dependency drift, injection, or MCP schemas.", ArgsHint: `{"argv":["secrets","."]}`, Tags: []string{"secrets", "injection", "mcp"}},
		{Name: "codec", Noun: "codec", Category: "security", Description: "Hash, encode, decode, entropy, and structured JWT/PEM/UUID inspection.", ArgsHint: `{"argv":["inspect","eyJ..."]}`, Tags: []string{"codec", "jwt", "hash"}},
		{Name: "mcp_audit", Noun: "mcp", Verb: "audit", Category: "security", Description: "Audit mounted MCP servers for schema rug-pulls and hidden prompt injections.", ArgsHint: `{"argv":["audit"]}`, Tags: []string{"mcp", "audit", "rug_pull"}},
		{Name: "swarm", Noun: "swarm", Category: "re", Description: "High-concurrency CFG map-reduce, speculative solver, and binary audit swarm.", ArgsHint: `{"argv":["audit","/path/to/bin"]}`, Tags: []string{"swarm", "audit"}},
		{Name: "route_context", Noun: "route", Verb: "context", Category: "code", Description: "Token-budgeted query and symbol-graph context packer.", ArgsHint: `{"argv":["context",".","--query","Store","--symbols"]}`, Tags: []string{"context", "symbols"}},
		{Name: "compress", Noun: "compress", Category: "ops", Description: "Error-preserving L0-L3 output compressor.", ArgsHint: `{"argv":["L1","--text","..."]}`, Tags: []string{"compress", "tokens"}},
		{Name: "session", Noun: "session", Category: "ops", Description: "Fork, rewind, list, or delete state checkpoints.", ArgsHint: `{"argv":["list"]}`, Tags: []string{"session", "checkpoint"}},
	}
}

func searchCatalog(query string, category string, limit int) []CatalogEntry {
	if limit <= 0 {
		limit = 10
	}
	q := strings.ToLower(strings.TrimSpace(query))
	cat := strings.ToLower(strings.TrimSpace(category))
	words := strings.Fields(q)

	type scored struct {
		entry CatalogEntry
		score int
	}
	var hits []scored
	for _, e := range FullCatalog() {
		if cat != "" && strings.ToLower(e.Category) != cat {
			continue
		}
		if len(words) == 0 {
			hits = append(hits, scored{e, 1})
			continue
		}
		hay := strings.ToLower(e.Name + " " + e.Noun + " " + e.Verb + " " + e.Category + " " + e.Description + " " + strings.Join(e.Tags, " "))
		s := 0
		for _, w := range words {
			if strings.Contains(hay, w) {
				s += 2
			}
			if e.Name == w || e.Noun == w || e.Verb == w {
				s += 3
			}
		}
		if s > 0 {
			hits = append(hits, scored{e, s})
		}
	}
	sort.Slice(hits, func(i, j int) bool {
		if hits[i].score != hits[j].score {
			return hits[i].score > hits[j].score
		}
		return hits[i].entry.Name < hits[j].entry.Name
	})
	out := make([]CatalogEntry, 0, min(limit, len(hits)))
	for i := 0; i < len(hits) && i < limit; i++ {
		out = append(out, hits[i].entry)
	}
	return out
}

func runLocalCommand(selfBin string, argv []string, maxBytes int) (string, bool) {
	if len(argv) == 0 {
		return "error: empty argv", true
	}
	if guard.CurrentMode() == guard.ModeExplore {
		// Block obvious mutating verbs in explore mode before invoking child.
		noun := argv[0]
		verb := ""
		if len(argv) > 1 {
			verb = argv[1]
		}
		mutating := map[string]map[string]bool{
			"mem":  {"put": true, "forget": true, "import": true, "sync": true, "purge": true, "consolidate": true, "record-failure": true, "link": true, "unlink": true},
			"re":   {"patch": true, "trace": true},
			"code": {"index": true},
			"mcp":  {"trust": true},
		}
		if mutating[noun][verb] {
			guard.AuditEvent("mcp", "xt_call", strings.Join(argv, " "), "denied_explore", argv, 1)
			return "denied: XT_PERM_MODE=explore forbids mutating verb " + noun + " " + verb, true
		}
	}

	fullArgs := append([]string{}, argv...)
	hasJSON := false
	for _, a := range fullArgs {
		if a == "--json" {
			hasJSON = true
			break
		}
	}
	if !hasJSON {
		fullArgs = append(fullArgs, "--json")
	}

	cmd := exec.Command(selfBin, fullArgs...)
	outBytes, err := cmd.CombinedOutput()
	exitCode := 0
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			exitCode = ee.ExitCode()
		} else {
			exitCode = 1
		}
	}
	guard.AuditEvent("mcp", "xt_call", argv[0], map[bool]string{true: "ok", false: "error"}[exitCode == 0], argv, exitCode)
	clipped, _ := compress.ClipOrSpill(string(outBytes), maxBytes, "xt-"+argv[0])
	return clipped, exitCode != 0
}

// ServeMeta runs xt-forge's built-in 4-tool meta MCP server over stdio.
func ServeMeta(selfBin string, maxBytes int) int {
	if maxBytes <= 0 {
		maxBytes = 16384
	}
	metaTools := []ToolDef{
		{
			Name:        "xt_discover",
			Description: "Search xt-forge's 40+ CLI tools across RE, code graph, LSP, memory, steering, research, and security.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"query":    map[string]any{"type": "string", "description": "Keywords or capability to find"},
					"category": map[string]any{"type": "string", "description": "Optional filter: re|code|memory|steering|research|security|ops"},
					"limit":    map[string]any{"type": "integer", "description": "Max results (default 10)"},
				},
				"additionalProperties": false,
			},
		},
		{
			Name:        "xt_schema",
			Description: "Return exact usage hints and flags for an xt-forge tool discovered via xt_discover.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"name": map[string]any{"type": "string"},
				},
				"required":             []string{"name"},
				"additionalProperties": false,
			},
		},
		{
			Name:        "xt_call",
			Description: "Execute any xt-forge command with automatic L1-L3 compression and artifact spilling for large outputs.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"argv":      map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
					"max_bytes": map[string]any{"type": "integer"},
				},
				"required":             []string{"argv"},
				"additionalProperties": false,
			},
		},
		{
			Name:        "xt_batch",
			Description: "Run multiple read-only xt-forge commands concurrently in one turn.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"calls": map[string]any{
						"type": "array",
						"items": map[string]any{
							"type": "object",
							"properties": map[string]any{
								"argv": map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
							},
							"required": []string{"argv"},
						},
					},
				},
				"required":             []string{"calls"},
				"additionalProperties": false,
			},
		},
	}

	return serveLoop(metaTools, func(name string, args map[string]any) (string, bool) {
		switch name {
		case "xt_discover":
			q, _ := args["query"].(string)
			cat, _ := args["category"].(string)
			lim := 10
			if f, ok := args["limit"].(float64); ok && f > 0 {
				lim = int(f)
			}
			b, _ := json.MarshalIndent(map[string]any{
				"ok":      true,
				"matches": searchCatalog(q, cat, lim),
			}, "", "  ")
			return string(b), false
		case "xt_schema":
			target, _ := args["name"].(string)
			for _, e := range FullCatalog() {
				if e.Name == target {
					b, _ := json.MarshalIndent(e, "", "  ")
					return string(b), false
				}
			}
			return fmt.Sprintf("unknown xt-forge catalog tool: %s", target), true
		case "xt_call":
			rawArgv, _ := args["argv"].([]any)
			argv := make([]string, 0, len(rawArgv))
			for _, item := range rawArgv {
				if s, ok := item.(string); ok {
					argv = append(argv, s)
				}
			}
			mb := maxBytes
			if f, ok := args["max_bytes"].(float64); ok && f > 0 {
				mb = int(f)
			}
			return runLocalCommand(selfBin, argv, mb)
		case "xt_batch":
			rawCalls, _ := args["calls"].([]any)
			if len(rawCalls) > 16 {
				return "batch limited to 16 calls", true
			}
			results := make([]map[string]any, len(rawCalls))
			var wg sync.WaitGroup
			for i, rc := range rawCalls {
				wg.Add(1)
				go func(idx int, item any) {
					defer wg.Done()
					m, _ := item.(map[string]any)
					rawArgv, _ := m["argv"].([]any)
					argv := make([]string, 0, len(rawArgv))
					for _, a := range rawArgv {
						if s, ok := a.(string); ok {
							argv = append(argv, s)
						}
					}
					txt, isErr := runLocalCommand(selfBin, argv, maxBytes/2)
					results[idx] = map[string]any{"argv": argv, "isError": isErr, "output": txt}
				}(i, rc)
			}
			wg.Wait()
			b, _ := json.MarshalIndent(map[string]any{"ok": true, "results": results}, "", "  ")
			return string(b), false
		default:
			return "unknown tool: " + name, true
		}
	})
}

// ServeProxy wraps any upstream stdio MCP server behind a 3-tool lite facade
// (<prefix>_search, <prefix>_list, <prefix>_call) with inline compression,
// artifact spilling, and schema rug-pull verification.
func ServeProxy(prefix string, upstreamCmd []string, maxBytes int, trustOnFirst bool) int {
	if prefix == "" {
		prefix = "proxy"
	}
	if maxBytes <= 0 {
		maxBytes = 16384
	}
	if len(upstreamCmd) == 0 {
		fmt.Fprintln(os.Stderr, "xtforge mcp proxy: upstream command required")
		return 2
	}

	cmd := exec.Command(upstreamCmd[0], upstreamCmd[1:]...)
	upIn, err := cmd.StdinPipe()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	upOut, err := cmd.StdoutPipe()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "xtforge mcp proxy: start failed: %v\n", err)
		return 1
	}
	defer func() {
		_ = upIn.Close()
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	}()

	reader := bufio.NewReader(upOut)
	var upMu sync.Mutex
	nextID := 1
	callUpstream := func(method string, params any) (json.RawMessage, *rpcError) {
		upMu.Lock()
		defer upMu.Unlock()
		id := nextID
		nextID++
		pBytes, _ := json.Marshal(params)
		req := rpcMessage{
			JSONRPC: "2.0",
			ID:      json.RawMessage(fmt.Sprintf("%d", id)),
			Method:  method,
			Params:  pBytes,
		}
		line, _ := json.Marshal(req)
		if _, err := upIn.Write(append(line, '\n')); err != nil {
			return nil, &rpcError{Code: -32000, Message: err.Error()}
		}
		deadline := time.Now().Add(30 * time.Second)
		for time.Now().Before(deadline) {
			rawLine, err := reader.ReadString('\n')
			if err != nil {
				return nil, &rpcError{Code: -32000, Message: err.Error()}
			}
			rawLine = strings.TrimSpace(rawLine)
			if rawLine == "" {
				continue
			}
			var resp rpcMessage
			if json.Unmarshal([]byte(rawLine), &resp) != nil {
				continue
			}
			if len(resp.ID) == 0 {
				continue // skip notifications
			}
			return resp.Result, resp.Error
		}
		return nil, &rpcError{Code: -32001, Message: "upstream timeout"}
	}

	// Initialize upstream & inspect tools/list.
	_, initErr := callUpstream("initialize", map[string]any{
		"protocolVersion": ProtocolVersion,
		"capabilities":    map[string]any{},
		"clientInfo":      map[string]any{"name": "xtforge-hub-proxy", "version": "0.4.0"},
	})
	if initErr != nil {
		fmt.Fprintf(os.Stderr, "xtforge mcp proxy: initialize failed: %s\n", initErr.Message)
		return 1
	}
	upMu.Lock()
	notif, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized"})
	_, _ = upIn.Write(append(notif, '\n'))
	upMu.Unlock()

	listRaw, listErr := callUpstream("tools/list", map[string]any{})
	var upstreamTools []ToolDef
	if listErr == nil && len(listRaw) > 0 {
		var parsed struct {
			Tools []ToolDef `json:"tools"`
		}
		if json.Unmarshal(listRaw, &parsed) == nil {
			upstreamTools = parsed.Tools
		}
	}

	auditRes := EvaluateTools(prefix, strings.Join(upstreamCmd, " "), upstreamTools, trustOnFirst)
	if auditRes.Status == "rug_pull" || auditRes.Status == "injection_risk" {
		fmt.Fprintf(os.Stderr, "xtforge mcp proxy warning: %s flagged (%s)\n", prefix, auditRes.Status)
	}

	proxyTools := []ToolDef{
		{
			Name:        prefix + "_search",
			Description: fmt.Sprintf("Search %d tools on proxied MCP server '%s' by keyword.", len(upstreamTools), prefix),
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"query": map[string]any{"type": "string"},
					"limit": map[string]any{"type": "integer"},
				},
				"required": []string{"query"},
			},
		},
		{
			Name:        prefix + "_list",
			Description: fmt.Sprintf("List tool names and summaries on proxied MCP server '%s'.", prefix),
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"offset": map[string]any{"type": "integer"},
					"limit":  map[string]any{"type": "integer"},
				},
			},
		},
		{
			Name:        prefix + "_call",
			Description: fmt.Sprintf("Execute a tool on '%s' with automatic compression and artifact spilling.", prefix),
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"tool":      map[string]any{"type": "string"},
					"arguments": map[string]any{"type": "object"},
				},
				"required": []string{"tool"},
			},
		},
	}

	return serveLoop(proxyTools, func(name string, args map[string]any) (string, bool) {
		switch name {
		case prefix + "_search":
			q := strings.ToLower(fmt.Sprint(args["query"]))
			lim := 10
			if f, ok := args["limit"].(float64); ok && f > 0 {
				lim = int(f)
			}
			var hits []map[string]any
			for _, t := range upstreamTools {
				hay := strings.ToLower(t.Name + " " + t.Description)
				if strings.Contains(hay, q) {
					hits = append(hits, map[string]any{
						"name":        t.Name,
						"description": SummarizeDescription(t.Description, 140),
						"inputSchema": t.InputSchema,
					})
				}
				if len(hits) >= lim {
					break
				}
			}
			b, _ := json.MarshalIndent(map[string]any{"server": prefix, "audit": auditRes.Status, "matches": hits}, "", "  ")
			return string(b), false
		case prefix + "_list":
			off, lim := 0, 30
			if f, ok := args["offset"].(float64); ok && f >= 0 {
				off = int(f)
			}
			if f, ok := args["limit"].(float64); ok && f > 0 {
				lim = int(f)
			}
			var rows []map[string]string
			for i := off; i < len(upstreamTools) && len(rows) < lim; i++ {
				rows = append(rows, map[string]string{
					"name":        upstreamTools[i].Name,
					"description": SummarizeDescription(upstreamTools[i].Description, 100),
				})
			}
			b, _ := json.MarshalIndent(map[string]any{"server": prefix, "total": len(upstreamTools), "tools": rows}, "", "  ")
			return string(b), false
		case prefix + "_call":
			tName, _ := args["tool"].(string)
			tArgs, _ := args["arguments"].(map[string]any)
			if tArgs == nil {
				tArgs = map[string]any{}
			}
			if guard.CurrentMode() == guard.ModeExplore && (strings.Contains(tName, "write") || strings.Contains(tName, "delete") || strings.Contains(tName, "patch")) {
				guard.AuditEvent("mcp-proxy", prefix, tName, "denied_explore", tArgs, 1)
				return "denied: XT_PERM_MODE=explore forbids mutating proxied call " + tName, true
			}
			resRaw, callErr := callUpstream("tools/call", map[string]any{"name": tName, "arguments": tArgs})
			if callErr != nil {
				guard.AuditEvent("mcp-proxy", prefix, tName, "error", tArgs, 1)
				return callErr.Message, true
			}
			guard.AuditEvent("mcp-proxy", prefix, tName, "ok", tArgs, 0)
			clipped, _ := compress.ClipOrSpill(string(resRaw), maxBytes, prefix+"-"+tName)
			return clipped, false
		default:
			return "unknown proxy tool: " + name, true
		}
	})
}

func serveLoop(tools []ToolDef, handler func(string, map[string]any) (string, bool)) int {
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 64*1024), 16*1024*1024)
	writeResp := func(v any) {
		b, _ := json.Marshal(v)
		_, _ = os.Stdout.Write(append(b, '\n'))
	}

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var msg rpcMessage
		if err := json.Unmarshal([]byte(line), &msg); err != nil {
			writeResp(map[string]any{"jsonrpc": "2.0", "id": nil, "error": rpcError{Code: -32700, Message: "parse error"}})
			continue
		}
		if msg.Method == "exit" {
			break
		}
		if len(msg.ID) == 0 || string(msg.ID) == "null" {
			continue
		}
		switch msg.Method {
		case "initialize":
			var params struct {
				ProtocolVersion string `json:"protocolVersion"`
			}
			_ = json.Unmarshal(msg.Params, &params)
			pv := params.ProtocolVersion
			if pv == "" {
				pv = ProtocolVersion
			}
			writeResp(map[string]any{
				"jsonrpc": "2.0",
				"id":      msg.ID,
				"result": map[string]any{
					"protocolVersion": pv,
					"capabilities":    map[string]any{"tools": map[string]any{"listChanged": false}},
					"serverInfo":      map[string]any{"name": "xt-forge-hub", "version": "0.4.0"},
				},
			})
		case "ping":
			writeResp(map[string]any{"jsonrpc": "2.0", "id": msg.ID, "result": map[string]any{}})
		case "tools/list":
			writeResp(map[string]any{"jsonrpc": "2.0", "id": msg.ID, "result": map[string]any{"tools": tools}})
		case "tools/call":
			var params struct {
				Name      string         `json:"name"`
				Arguments map[string]any `json:"arguments"`
			}
			_ = json.Unmarshal(msg.Params, &params)
			if params.Arguments == nil {
				params.Arguments = map[string]any{}
			}
			text, isErr := handler(params.Name, params.Arguments)
			writeResp(map[string]any{
				"jsonrpc": "2.0",
				"id":      msg.ID,
				"result": map[string]any{
					"content": []map[string]any{{"type": "text", "text": text}},
					"isError": isErr,
				},
			})
		case "shutdown":
			writeResp(map[string]any{"jsonrpc": "2.0", "id": msg.ID, "result": nil})
		default:
			writeResp(map[string]any{"jsonrpc": "2.0", "id": msg.ID, "error": rpcError{Code: -32601, Message: "method not found: " + msg.Method}})
		}
	}
	return 0
}

// ResolveSelfBinary locates the xtforge launcher or python fallback.
func ResolveSelfBinary() string {
	exe, err := os.Executable()
	if err == nil {
		// native/xtforge-go/xtforge-hub -> repo root -> bin/xtforge
		cand := filepath.Join(filepath.Dir(exe), "..", "..", "bin", "xtforge")
		if _, err := os.Stat(cand); err == nil {
			return cand
		}
	}
	return "xtforge"
}
