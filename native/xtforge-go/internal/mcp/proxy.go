package mcp

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"

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
		{Name: "re_info", Noun: "re", Verb: "info", Category: "re", Description: "Inspect ELF, PE, or Mach-O binary headers, arch, and entry point.", ArgsHint: `{"argv":["re","info","/path/to/bin"]}`, Tags: []string{"binary", "elf", "pe", "macho"}},
		{Name: "re_sections", Noun: "re", Verb: "sections", Category: "re", Description: "List binary sections with virtual size, raw size, and Shannon entropy.", ArgsHint: `{"argv":["re","sections","/path/to/bin"]}`, Tags: []string{"entropy", "sections"}},
		{Name: "re_symbols", Noun: "re", Verb: "symbols", Category: "re", Description: "List symbols, imports, or exports.", ArgsHint: `{"argv":["re","symbols","/path/to/bin","--limit","50"]}`, Tags: []string{"symbols", "imports", "exports"}},
		{Name: "re_disasm", Noun: "re", Verb: "disasm", Category: "re", Description: "Disassemble a binary function or section with instruction mnemonic summary.", ArgsHint: `{"argv":["re","disasm","/path/to/bin","--symbol","main"]}`, Tags: []string{"disasm", "disassemble", "assembly", "instructions", "objdump"}},
		{Name: "re_strings", Noun: "re", Verb: "strings", Category: "re", Description: "Extract ASCII, stack-constructed, or single-byte XOR strings.", ArgsHint: `{"argv":["re","strings","/path/to/bin","--xor"]}`, Tags: []string{"strings", "xor", "stack"}},
		{Name: "re_pack", Noun: "re", Verb: "pack", Category: "re", Description: "Detect packed or encrypted binaries using entropy and string density.", ArgsHint: `{"argv":["re","pack","/path/to/bin"]}`, Tags: []string{"packer", "entropy"}},
		{Name: "re_ioc", Noun: "re", Verb: "ioc", Category: "re", Description: "Extract URLs, IPs, domains, hashes, registry keys, and CVEs.", ArgsHint: `{"argv":["re","ioc","/path/to/bin"]}`, Tags: []string{"ioc", "malware"}},
		{Name: "re_checksec", Noun: "re", Verb: "checksec", Category: "re", Description: "Inspect exploit mitigations (NX, PIE, Canary, RELRO, ASLR, CFG).", ArgsHint: `{"argv":["re","checksec","/path/to/bin"]}`, Tags: []string{"checksec", "mitigations"}},
		{Name: "re_capa", Noun: "re", Verb: "capa", Category: "re", Description: "Detect behavioral capabilities (anti-debug, injection, persistence).", ArgsHint: `{"argv":["re","capa","/path/to/bin"]}`, Tags: []string{"capa", "behavior"}},
		{Name: "re_cfg", Noun: "re", Verb: "cfg", Category: "re", Description: "Reconstruct function basic block CFG and cross-references.", ArgsHint: `{"argv":["re","cfg","/path/to/bin","--symbol","main"]}`, Tags: []string{"cfg", "disasm", "rizin"}},
		{Name: "re_rtti", Noun: "re", Verb: "rtti", Category: "re", Description: "Extract C++ RTTI classes and vtable pointers.", ArgsHint: `{"argv":["re","rtti","/path/to/bin"]}`, Tags: []string{"rtti", "cpp", "vtable"}},
		{Name: "re_diff", Noun: "re", Verb: "diff", Category: "re", Description: "Compare two binaries for modified functions, normalized disassembly instruction diffs, strength-reduced division/constant notes, and strings diffs.", ArgsHint: `{"argv":["re","diff","/bin/v1","/bin/v2"]}`, Tags: []string{"diff", "patch", "binary", "regression", "disasm"}},
		{Name: "re_crash", Noun: "re", Verb: "crash", Category: "re", Description: "Analyze Windows MiniDump or Linux ELF core crash dumps.", ArgsHint: `{"argv":["re","crash","/path/to/core"]}`, Tags: []string{"crash", "dump", "minidump"}},
		{Name: "re_hooks", Noun: "re", Verb: "hooks", Category: "re", Description: "Scan disassembly for inline hooks and direct syscall stubs.", ArgsHint: `{"argv":["re","hooks","/path/to/bin"]}`, Tags: []string{"hooks", "syscalls"}},
		{Name: "re_patch", Noun: "re", Verb: "patch", Category: "re", Description: "Apply guarded atomic byte patch to a binary copy.", ArgsHint: `{"argv":["re","patch","/path/to/bin","--offset","0x100","--patch-bytes","9090"]}`, Mutating: true, Tags: []string{"patch", "binary"}},
		{Name: "re_annotate", Noun: "re", Verb: "annotate", Category: "re", Description: "Read or write persistent per-binary symbol renames, types, and comments.", ArgsHint: `{"argv":["re","annotate","rename","/path/to/bin","--rva","0x1000","--name","decrypt_cfg"]}`, Mutating: true, Tags: []string{"annotate", "rename", "overlay"}},
		{Name: "re_decompile", Noun: "re", Verb: "decompile", Category: "re", Description: "Decompile function pseudocode via rizin/Ghidra or annotated objdump disassembly fallback with reciprocal constant notes.", ArgsHint: `{"argv":["re","decompile","/path/to/bin","--symbol","main"]}`, Tags: []string{"decompile", "pseudocode", "ghidra", "rizin", "disasm"}},
		{Name: "re_apk", Noun: "re", Verb: "apk", Category: "re", Description: "Inspect Android APK manifest, permissions, components, and native libs.", ArgsHint: `{"argv":["re","apk","/path/to/app.apk"]}`, Tags: []string{"apk", "android", "jadx"}},
		{Name: "re_asar", Noun: "re", Verb: "asar", Category: "re", Description: "List or extract Electron ASAR archives and JS source maps.", ArgsHint: `{"argv":["re","asar","/path/to/app.asar"]}`, Tags: []string{"asar", "electron", "js"}},
		{Name: "re_netcap", Noun: "re", Verb: "netcap", Category: "re", Description: "Summarize endpoints and masked auth headers from HAR/SAZ captures.", ArgsHint: `{"argv":["re","netcap","/path/to/capture.har"]}`, Tags: []string{"har", "saz", "network"}},
		{Name: "re_trace", Noun: "re", Verb: "trace", Category: "re", Description: "Run capability-scoped dynamic tracing via Frida, gdb, or lldb.", ArgsHint: `{"argv":["re","trace","/path/to/bin","--preset","api_trace"]}`, Mutating: true, Tags: []string{"frida", "trace", "dynamic"}},

		// Code Intelligence & LSP
		{Name: "code_symbols", Noun: "code", Verb: "symbols", Category: "code", Description: "Extract AST symbols and signatures from a source file or directory.", ArgsHint: `{"argv":["code","symbols","."]}`, Tags: []string{"ast", "symbols", "outline"}},
		{Name: "code_refs", Noun: "code", Verb: "refs", Category: "code", Description: "Text regex references across a workspace (prefer code_callers or code_graph for import-resolved callers).", ArgsHint: `{"argv":["code","refs","MyFunc","."]}`, Tags: []string{"refs", "grep"}},
		{Name: "code_index", Noun: "code", Verb: "index", Category: "code", Description: "Index workspace symbols and call/import edges into code_graph.db.", ArgsHint: `{"argv":["code","index","."]}`, Mutating: true, Tags: []string{"graph", "index"}},
		{Name: "code_graph", Noun: "code", Verb: "graph", Category: "code", Description: "Query definition, import-resolved production callers, excerpts, staleness, and callees for a symbol.", ArgsHint: `{"argv":["code","graph","MyFunc",".","--depth","2"]}`, Tags: []string{"graph", "callgraph", "callers", "definition"}},
		{Name: "code_callers", Noun: "code", Verb: "callers", Category: "code", Description: "Evidence-backed caller lookup returning definition, import-resolved production callers, excerpts, and ambiguity.", ArgsHint: `{"argv":["code","callers","MyFunc",".","--depth","2"]}`, Tags: []string{"callers", "graph", "evidence", "usage"}},
		{Name: "code_audit", Noun: "code", Verb: "audit", Category: "code", Description: "Fast AST correctness audit across source files (duplicate aggregation, date/range boundary bugs, stale cache, truncation, mutable defaults).", ArgsHint: `{"argv":["code","audit","."]}`, Tags: []string{"audit", "bugs", "defects", "correctness", "static", "review", "issues"}},
		{Name: "code_trace", Noun: "code", Verb: "trace", Category: "code", Description: "Trace an entry symbol across imports, package __init__ re-exports, shadowed handlers, and runtime config dispatch.", ArgsHint: `{"argv":["code","trace","dispatch_request","."]}`, Tags: []string{"trace", "reexport", "config", "dispatch", "handler", "flow", "routing"}},
		{Name: "code_lsp", Noun: "code", Verb: "lsp", Category: "code", Description: "Query on-demand LSP servers for definition, references, hover, or diagnostics.", ArgsHint: `{"argv":["code","lsp","diag","main.go"]}`, Tags: []string{"lsp", "serena", "diagnostics"}},

		// Memory, Knowledge & Recall
		{Name: "mem_search", Noun: "mem", Verb: "search", Category: "memory", Description: "BM25 + hybrid search across durable memory.", ArgsHint: `{"argv":["mem","search","auth bug","--k","5"]}`, Tags: []string{"memory", "search"}},
		{Name: "mem_put", Noun: "mem", Verb: "put", Category: "memory", Description: "Store a durable memory record (including failed_attempt or anti_pattern).", ArgsHint: `{"argv":["mem","put","--kind","fact","--title","...","--body","..."]}`, Mutating: true, Tags: []string{"memory", "write"}},
		{Name: "mem_consolidate", Noun: "mem", Verb: "consolidate", Category: "memory", Description: "Merge near-duplicate memory records while preserving provenance links.", ArgsHint: `{"argv":["mem","consolidate","--dry-run"]}`, Mutating: true, Tags: []string{"memory", "dedupe"}},
		{Name: "mem_record_failure", Noun: "mem", Verb: "record-failure", Category: "memory", Description: "Record a failed attempt with error signature to prevent repeating mistakes.", ArgsHint: `{"argv":["mem","record-failure","--title","...","--error-sig","...","--body","..."]}`, Mutating: true, Tags: []string{"negative_memory", "failure"}},
		{Name: "recall", Noun: "recall", Category: "memory", Description: "Unified cross-store recall across mem, recon, flash, errors, and artifacts.", ArgsHint: `{"argv":["recall","query text"]}`, Tags: []string{"recall", "cross-store"}},
		{Name: "knowledge", Noun: "knowledge", Category: "memory", Description: "Lifecycle-tracked knowledge (put, get, search, verify, revise, link, deprecate).", ArgsHint: `{"argv":["knowledge","search","query"]}`, Tags: []string{"knowledge", "verify"}},

		// Steering, Guardrails & Loops
		{Name: "goal_check", Noun: "goal", Verb: "check", Category: "steering", Description: "Vibe-check and anti-loop gate: checks criteria drift, diff bloat, stuck state, and prior failures.", ArgsHint: `{"argv":["goal","check","--criteria","tests pass","--workdir","."]}`, Tags: []string{"vibe_check", "steering", "anti_loop"}},
		{Name: "goal_verify", Noun: "goal", Verb: "verify", Category: "steering", Description: "Independently verify completion claims and replay approved checks.", ArgsHint: `{"argv":["goal","verify","--body","<goal-done>...</goal-done>","--verify","pytest"]}`, Tags: []string{"verify", "goal"}},
		{Name: "loop_policy", Noun: "loop", Verb: "policy", Category: "steering", Description: "Manage or inspect loop scheduler policy, schedules, and safety caps.", ArgsHint: `{"argv":["loop","policy"]}`, Tags: []string{"loop", "schedule"}},
		{Name: "taste_learn", Noun: "taste", Verb: "learn", Category: "steering", Description: "Record deterministic preference evidence without overwriting conflicts.", ArgsHint: `{"argv":["taste","search"]}`, Tags: []string{"taste", "preferences"}},

		// Research, Recon, Intel & Security
		{Name: "research_run", Noun: "research", Verb: "run", Category: "research", Description: "Run parallel multi-source research across code, mem, CVE intel, docs, and web.", ArgsHint: `{"argv":["research","run","CVE-2024-3094"]}`, Tags: []string{"research", "dossier", "cve"}},
		{Name: "intel", Noun: "intel", Category: "research", Description: "Keyless threat intel lookup for IP, CVE, CISA KEV, domain, or file hash.", ArgsHint: `{"argv":["intel","cve","CVE-2024-3094"]}`, Tags: []string{"cve", "kev", "ip", "hash"}},
		{Name: "docs", Noun: "docs", Category: "research", Description: "Fetch live library documentation via Context7.", ArgsHint: `{"argv":["docs","search","tokio"]}`, Tags: []string{"docs", "context7"}},
		{Name: "recon", Noun: "recon", Category: "security", Description: "Scoped findings ledger and deterministic markdown recon report generator.", ArgsHint: `{"argv":["recon","list","target"]}`, Tags: []string{"recon", "findings"}},
		{Name: "scan", Noun: "scan", Category: "security", Description: "Read-only scan for secrets, risky patterns, dependency drift, injection, or MCP schemas.", ArgsHint: `{"argv":["scan","secrets","."]}`, Tags: []string{"secrets", "injection", "mcp"}},
		{Name: "scan_secrets", Noun: "scan", Verb: "secrets", Category: "security", Description: "Scan workspace files for hardcoded credentials and API tokens (masked by default).", ArgsHint: `{"argv":["scan","secrets","."]}`, Tags: []string{"secrets", "scan", "tokens"}},
		{Name: "scan_mcp", Noun: "scan", Verb: "mcp", Category: "security", Description: "Scan MCP config/manifest files for hidden prompt-injection instructions.", ArgsHint: `{"argv":["scan","mcp","/path/to/mcp.json"]}`, Tags: []string{"mcp", "injection", "scan"}},
		{Name: "scan_injection", Noun: "scan", Verb: "injection", Category: "security", Description: "Scan text or config files for prompt-injection payloads.", ArgsHint: `{"argv":["scan","injection","/path/to/file"]}`, Tags: []string{"injection", "scan"}},
		{Name: "codec", Noun: "codec", Category: "security", Description: "Hash, encode, decode, entropy, and structured JWT/PEM/UUID inspection.", ArgsHint: `{"argv":["codec","inspect","eyJ..."]}`, Tags: []string{"codec", "jwt", "hash"}},
		{Name: "mcp_audit", Noun: "mcp", Verb: "audit", Category: "security", Description: "Audit mounted MCP servers for schema rug-pulls and hidden prompt injections.", ArgsHint: `{"argv":["mcp","audit"]}`, Tags: []string{"mcp", "audit", "rug_pull"}},
		{Name: "swarm", Noun: "swarm", Category: "re", Description: "High-concurrency CFG map-reduce, speculative solver, and binary audit swarm.", ArgsHint: `{"argv":["swarm","audit","/path/to/bin"]}`, Tags: []string{"swarm", "audit"}},
		{Name: "route_context", Noun: "route", Verb: "context", Category: "code", Description: "Token-budgeted query and symbol-graph context packer.", ArgsHint: `{"argv":["route","context",".","--query","MyFunc","--symbols"]}`, Tags: []string{"context", "symbols"}},
		{Name: "route_grep", Noun: "route", Verb: "grep", Category: "code", Description: "Ranked identifier-aware code grep across definitions and references.", ArgsHint: `{"argv":["route","grep",".","--pattern","MyFunc","--rank"]}`, Tags: []string{"grep", "search", "definitions"}},
		{Name: "route_errors", Noun: "route", Verb: "errors", Category: "code", Description: "Extract error-bearing lines from a log file or directory.", ArgsHint: `{"argv":["route","errors","/path/to/log"]}`, Tags: []string{"errors", "logs", "traceback"}},
		{Name: "compress", Noun: "compress", Category: "ops", Description: "Error-preserving L0-L3 output compressor.", ArgsHint: `{"argv":["compress","L1","--path","/path/to/log"]}`, Tags: []string{"compress", "tokens"}},
		{Name: "compress_l1", Noun: "compress", Verb: "L1", Category: "ops", Description: "Error-preserving L1 log/output compressor for large files.", ArgsHint: `{"argv":["compress","L1","--path","/path/to/log"]}`, Tags: []string{"compress", "logs", "errors"}},
		{Name: "session", Noun: "session", Category: "ops", Description: "Fork, rewind, list, or delete state checkpoints.", ArgsHint: `{"argv":["session","list"]}`, Tags: []string{"session", "checkpoint"}},
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

func runLocalCommand(selfBin string, argv []string, maxBytes int, workDir string) (string, bool) {
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
	if workDir != "" {
		cmd.Dir = workDir
	}
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
	outStr := string(outBytes)
	trimmed := bytes.TrimSpace(outBytes)
	if len(trimmed) > 0 && (trimmed[0] == '{' || trimmed[0] == '[') && json.Valid(trimmed) {
		var comp bytes.Buffer
		if json.Compact(&comp, trimmed) == nil {
			outStr = comp.String()
		}
	}
	clipped, _ := compress.ClipOrSpill(outStr, maxBytes, "xt-"+argv[0])
	return clipped, exitCode != 0
}

// ServeMeta runs xt-forge's built-in 4-tool meta MCP server over stdio.
func splitUpstreamToolRef(raw string) (string, string, bool) {
	idx := strings.IndexByte(raw, ':')
	if idx <= 0 || idx+1 >= len(raw) {
		return "", "", false
	}
	srv := CanonicalUpstreamName(raw[:idx])
	tool := strings.TrimSpace(raw[idx+1:])
	if srv == "" || tool == "" {
		return "", "", false
	}
	return srv, tool, true
}

func isMutatingToolName(name string) bool {
	l := strings.ToLower(name)
	for _, kw := range []string{"write", "delete", "remove", "patch", "modify", "update_", "install", "uninstall", "run_command", "exec", "sign_in", "sign_out", "rebuild"} {
		if strings.Contains(l, kw) {
			return true
		}
	}
	return false
}

func resolveUpstreamTools(pool *UpstreamPool, server string) ([]ToolDef, error) {
	canon := CanonicalUpstreamName(server)
	if cached := LoadCachedCatalog(canon); len(cached) > 0 {
		return cached, nil
	}
	sess, err := pool.GetOrStart(canon)
	if err != nil {
		return nil, err
	}
	return sess.Tools(), nil
}

type callRecoveryOpts struct {
	IdempotencyKey string
	VerifyTool     string
	VerifyArgs     map[string]any
}

func extractRecoveryOpts(args map[string]any) callRecoveryOpts {
	var opts callRecoveryOpts
	if args == nil {
		return opts
	}
	if s, ok := args["idempotency_key"].(string); ok {
		opts.IdempotencyKey = strings.TrimSpace(s)
	}
	if s, ok := args["verify_tool"].(string); ok {
		opts.VerifyTool = strings.TrimSpace(s)
	}
	if va, ok := args["verify_args"].(map[string]any); ok {
		opts.VerifyArgs = va
	}
	return opts
}

func firstNonEmptyStr(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func digestResult(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])[:20]
}

func parseVerificationCommitted(raw json.RawMessage) bool {
	var envelope map[string]any
	if json.Unmarshal(raw, &envelope) != nil {
		return false
	}
	if isErr, ok := envelope["isError"].(bool); ok && isErr {
		return false
	}
	inspectMap := func(m map[string]any) (decided bool, val bool) {
		for _, k := range []string{"committed", "found", "exists"} {
			if b, ok := m[k].(bool); ok {
				return true, b
			}
		}
		if st, ok := m["status"].(string); ok {
			switch strings.ToLower(strings.TrimSpace(st)) {
			case "not_found", "missing", "absent", "unknown", "never_started":
				return true, false
			case "committed", "completed", "ok", "succeeded", "success":
				return true, true
			}
		}
		if rec, ok := m["receipt"]; ok && rec != nil {
			return true, true
		}
		return false, false
	}
	if d, v := inspectMap(envelope); d {
		return v
	}
	if content, ok := envelope["content"].([]any); ok {
		for _, item := range content {
			cm, ok := item.(map[string]any)
			if !ok {
				continue
			}
			txt, _ := cm["text"].(string)
			var inner map[string]any
			if txt != "" && json.Unmarshal([]byte(txt), &inner) == nil {
				if d, v := inspectMap(inner); d {
					return v
				}
			}
		}
	}
	return true
}

func runRecoverableUpstreamCall(
	ctx context.Context,
	sess *UpstreamSession,
	auditKind, server, toolName string,
	args map[string]any,
	opts callRecoveryOpts,
	maxBytes int,
) (string, bool) {
	if ctx == nil {
		ctx = context.Background()
	}
	if args == nil {
		args = map[string]any{}
	}
	canon := CanonicalUpstreamName(server)
	if canon == "" && sess != nil {
		canon = sess.Name
	}
	if guard.CurrentMode() == guard.ModeExplore && isMutatingToolName(toolName) {
		guard.AuditEvent(auditKind, canon, toolName, "denied_explore", args, 1)
		return fmt.Sprintf("denied: XT_PERM_MODE=explore forbids mutating upstream call %s:%s", canon, toolName), true
	}

	key := strings.TrimSpace(opts.IdempotencyKey)
	digest := argsDigest(canon, toolName, args)
	var entry JournalEntry

	if key != "" {
		if existing, found := FindJournalByKey(key); found {
			state := NormalizeJournalState(existing.State)
			if existing.ArgsSHA256 != "" && existing.ArgsSHA256 != digest {
				return fmt.Sprintf("idempotency conflict for key %q: args mismatch existing call %s (%s:%s)", key, existing.CallID, existing.Server, existing.Tool), true
			}
			switch state {
			case CallCompleted:
				if !existing.IsError {
					guard.AuditEvent(auditKind, canon, toolName, "replayed", args, 0)
					clipped, _ := compress.ClipOrSpill(existing.Result, maxBytes, canon+"-"+toolName)
					return clipped, false
				}
				entry = existing
			case CallUnknownOutcome:
				verifyTool := firstNonEmptyStr(opts.VerifyTool, existing.VerifyTool)
				verifyArgs := opts.VerifyArgs
				if verifyArgs == nil {
					verifyArgs = existing.VerifyArgs
				}
				if verifyArgs == nil {
					verifyArgs = map[string]any{"idempotency_key": key}
				}
				if verifyTool == "" {
					guard.AuditEvent(auditKind, canon, toolName, "blocked_unknown_outcome", args, 1)
					payload, _ := json.Marshal(map[string]any{
						"ok":                  false,
						"state":               CallUnknownOutcome,
						"call_id":             existing.CallID,
						"idempotency_key":     key,
						"attempts":            existing.Attempts,
						"cancel_notified":     existing.CancelNotified,
						"duplicate_prevented": true,
						"message":             fmt.Sprintf("call %s (%s:%s) interrupted with unknown outcome; verify via read-only tool or pass verify_tool before retrying", existing.CallID, canon, toolName),
					})
					return string(payload), true
				}
				vRaw, vErr, _, _, _ := sess.CallToolContext(ctx, verifyTool, verifyArgs)
				if vErr != nil {
					guard.AuditEvent(auditKind, canon, toolName, "verify_error", args, 1)
					return fmt.Sprintf("unknown_outcome verification %s:%s failed (%s); duplicate write blocked", canon, verifyTool, vErr.Message), true
				}
				if parseVerificationCommitted(vRaw) {
					existing.State = CallCompleted
					existing.IsError = false
					existing.Error = ""
					existing.Result = string(vRaw)
					existing.ResultSHA256 = digestResult(string(vRaw))
					_, _ = UpsertJournalEntry(existing)
					guard.AuditEvent(auditKind, canon, toolName, "recovered", args, 0)
					var parsedReceipt any
					_ = json.Unmarshal(vRaw, &parsedReceipt)
					recPayload, _ := json.Marshal(map[string]any{
						"ok":                  true,
						"recovered":           true,
						"duplicate_prevented": true,
						"state":               CallCompleted,
						"call_id":             existing.CallID,
						"idempotency_key":     key,
						"attempts":            existing.Attempts,
						"verify_tool":         verifyTool,
						"receipt":             parsedReceipt,
					})
					clipped, _ := compress.ClipOrSpill(string(recPayload), maxBytes, canon+"-"+toolName+"-recovered")
					return clipped, false
				}
				entry = existing
			case CallNeverStarted:
				entry = existing
			default:
				entry = existing
			}
		}
	}

	if err := ctx.Err(); err != nil {
		if entry.CallID == "" {
			entry = JournalEntry{
				IdempotencyKey: key,
				Server:         canon,
				Tool:           toolName,
				ArgsSHA256:     digest,
				VerifyTool:     opts.VerifyTool,
				VerifyArgs:     opts.VerifyArgs,
			}
		}
		entry.State = CallNeverStarted
		entry.Cancelled = true
		entry.IsError = true
		entry.Error = err.Error()
		entry, _ = UpsertJournalEntry(entry)
		guard.AuditEvent(auditKind, canon, toolName, "cancelled_before_start", args, 1)
		return fmt.Sprintf("cancelled before start (%s): %v", CallNeverStarted, err), true
	}

	trackJournal := key != "" || isMutatingToolName(toolName)
	if trackJournal {
		if entry.CallID == "" {
			entry = JournalEntry{
				IdempotencyKey: key,
				Server:         canon,
				Tool:           toolName,
				ArgsSHA256:     digest,
				VerifyTool:     opts.VerifyTool,
				VerifyArgs:     opts.VerifyArgs,
			}
		}
		entry.State = CallInFlight
		entry.Attempts++
		entry.IsError = false
		entry.Error = ""
		if opts.VerifyTool != "" {
			entry.VerifyTool = opts.VerifyTool
		}
		if opts.VerifyArgs != nil {
			entry.VerifyArgs = opts.VerifyArgs
		}
		entry, _ = UpsertJournalEntry(entry)
	}

	resRaw, rpcErr, reqID, started, cancelNotified := sess.CallToolContext(ctx, toolName, args)
	if rpcErr != nil {
		isInterrupt := !started || rpcErr.Code == -32000 || rpcErr.Code == -32001 || rpcErr.Code == -32800
		if trackJournal || isInterrupt {
			if entry.CallID == "" {
				entry = JournalEntry{
					IdempotencyKey: key,
					Server:         canon,
					Tool:           toolName,
					ArgsSHA256:     digest,
					Attempts:       1,
					VerifyTool:     opts.VerifyTool,
					VerifyArgs:     opts.VerifyArgs,
				}
			}
			entry.RequestID = reqID
			entry.CancelNotified = entry.CancelNotified || cancelNotified
			entry.IsError = true
			entry.Error = rpcErr.Message
			if !started {
				entry.State = CallNeverStarted
				entry.Cancelled = true
			} else if isInterrupt {
				entry.State = CallUnknownOutcome
				if rpcErr.Code == -32800 {
					entry.Cancelled = true
				}
			} else {
				entry.State = CallCompleted
			}
			entry, _ = UpsertJournalEntry(entry)
		}
		guard.AuditEvent(auditKind, canon, toolName, "error", args, 1)
		if !started {
			return fmt.Sprintf("call cancelled before dispatch (state=%s, call_id=%s): %s", CallNeverStarted, entry.CallID, rpcErr.Message), true
		}
		if isInterrupt {
			return fmt.Sprintf("interrupted call with unknown outcome (state=%s, call_id=%s, cancel_notified=%v): %s — verify effect with a read-only check before retrying", CallUnknownOutcome, entry.CallID, cancelNotified, rpcErr.Message), true
		}
		return rpcErr.Message, true
	}

	if trackJournal {
		entry.RequestID = reqID
		entry.State = CallCompleted
		entry.IsError = false
		entry.Error = ""
		entry.Result = string(resRaw)
		entry.ResultSHA256 = digestResult(string(resRaw))
		_, _ = UpsertJournalEntry(entry)
	}
	guard.AuditEvent(auditKind, canon, toolName, "ok", args, 0)
	clipped, _ := compress.ClipOrSpill(string(resRaw), maxBytes, canon+"-"+toolName)
	return clipped, false
}

func callUpstreamTool(pool *UpstreamPool, server, toolName string, args map[string]any, maxBytes int) (string, bool) {
	return callUpstreamToolContext(context.Background(), pool, server, toolName, args, callRecoveryOpts{}, maxBytes)
}

func callUpstreamToolContext(ctx context.Context, pool *UpstreamPool, server, toolName string, args map[string]any, opts callRecoveryOpts, maxBytes int) (string, bool) {
	canon := CanonicalUpstreamName(server)
	if args == nil {
		args = map[string]any{}
	}
	if guard.CurrentMode() == guard.ModeExplore && isMutatingToolName(toolName) {
		guard.AuditEvent("mcp", canon, toolName, "denied_explore", args, 1)
		return fmt.Sprintf("denied: XT_PERM_MODE=explore forbids mutating upstream call %s:%s", canon, toolName), true
	}
	if ctx != nil && ctx.Err() != nil {
		if opts.IdempotencyKey != "" || isMutatingToolName(toolName) {
			_, _ = UpsertJournalEntry(JournalEntry{
				IdempotencyKey: opts.IdempotencyKey,
				Server:         canon,
				Tool:           toolName,
				ArgsSHA256:     argsDigest(canon, toolName, args),
				State:          CallNeverStarted,
				Cancelled:      true,
				IsError:        true,
				Error:          ctx.Err().Error(),
				VerifyTool:     opts.VerifyTool,
				VerifyArgs:     opts.VerifyArgs,
			})
		}
		return fmt.Sprintf("cancelled before start (state=%s): %v", CallNeverStarted, ctx.Err()), true
	}
	sess, err := pool.GetOrStart(canon)
	if err != nil {
		guard.AuditEvent("mcp", canon, toolName, "start_error", args, 1)
		return err.Error(), true
	}
	return runRecoverableUpstreamCall(ctx, sess, "mcp", canon, toolName, args, opts, maxBytes)
}

func searchUpstreamCatalogs(pool *UpstreamPool, upstreamFilter, query string, limit int) ([]map[string]any, map[string]map[string]any) {
	q := strings.ToLower(strings.TrimSpace(query))
	words := strings.Fields(q)
	filter := CanonicalUpstreamName(strings.TrimSpace(upstreamFilter))

	known := KnownUpstreams()
	statusMap := make(map[string]map[string]any, len(known))
	var targets []string
	if filter != "" && filter != "all" && filter != "xt-forge" {
		targets = []string{filter}
	} else if filter != "xt-forge" {
		targets = known
	}

	type hit struct {
		row   map[string]any
		score int
	}
	var hits []hit
	for _, srv := range known {
		inScope := false
		for _, t := range targets {
			if t == srv {
				inScope = true
				break
			}
		}
		var tools []ToolDef
		var probeErr error
		probed := false
		if inScope && filter != "" && filter != "all" {
			tools, probeErr = resolveUpstreamTools(pool, srv)
			probed = true
		} else {
			tools = LoadCachedCatalog(srv)
			if inScope && len(tools) == 0 && (strings.Contains(q, srv) || (srv == "craft-anything" && strings.Contains(q, "craft"))) {
				tools, probeErr = resolveUpstreamTools(pool, srv)
				probed = true
			}
		}
		if probeErr != nil {
			statusMap[srv] = map[string]any{
				"status":    "unavailable",
				"reachable": false,
				"tools":     0,
				"error":     probeErr.Error(),
			}
		} else if len(tools) > 0 {
			statusMap[srv] = map[string]any{
				"status":    "ready",
				"reachable": true,
				"tools":     len(tools),
			}
		} else if probed {
			statusMap[srv] = map[string]any{
				"status":    "ready",
				"reachable": true,
				"tools":     0,
			}
		} else {
			statusMap[srv] = map[string]any{
				"status":    "cold_cache",
				"reachable": nil,
				"tools":     0,
			}
		}
		if !inScope {
			continue
		}
		for _, t := range tools {
			hay := strings.ToLower(srv + " " + t.Name + " " + t.Description)
			if srv == "borer" && t.Name == "query" {
				hay += " triage taint emulate solve grep unpack devirt stackstrings capabilities antianalysis dynimports checks yara sig why layout patch flat vm hidden decoded"
			}
			score := 0
			if len(words) == 0 {
				score = 1
			} else {
				for _, w := range words {
					if w == srv || (w == "craft" && srv == "craft-anything") {
						score += 2
					}
					if strings.Contains(hay, w) {
						score += 2
					}
					if strings.ToLower(t.Name) == w {
						score += 4
					}
				}
			}
			if score > 0 {
				prefixed := srv + ":" + t.Name
				argsHint := fmt.Sprintf(`{"name":%q,"arguments":{}}`, prefixed)
				if srv == "borer" {
					switch t.Name {
					case "load_binary":
						argsHint = fmt.Sprintf(`{"name":%q,"arguments":{"path":"/abs/path/to/bin"}}`, prefixed)
					case "decompile", "function_summary", "function", "disassemble_function", "cfg", "callgraph", "xrefs":
						argsHint = fmt.Sprintf(`{"name":%q,"arguments":{"path":"/abs/path/to/bin","address":"0x1000"}}`, prefixed)
					case "query":
						argsHint = fmt.Sprintf(`{"name":%q,"arguments":{"path":"/abs/path/to/bin","uri":"borer://triage"}}`, prefixed)
					case "binary_info", "strings", "symbols", "functions", "find_crypto_constants", "entropy":
						argsHint = fmt.Sprintf(`{"name":%q,"arguments":{"path":"/abs/path/to/bin"}}`, prefixed)
					}
				}
				hits = append(hits, hit{
					score: score,
					row: map[string]any{
						"name":        prefixed,
						"upstream":    srv,
						"tool":        t.Name,
						"description": SummarizeDescription(t.Description, 140),
						"args_hint":   argsHint,
					},
				})
			}
		}
	}
	sort.Slice(hits, func(i, j int) bool {
		if hits[i].score != hits[j].score {
			return hits[i].score > hits[j].score
		}
		return fmt.Sprint(hits[i].row["name"]) < fmt.Sprint(hits[j].row["name"])
	})
	if limit <= 0 {
		limit = 10
	}
	if len(hits) > limit {
		hits = hits[:limit]
	}
	out := make([]map[string]any, 0, len(hits))
	for _, h := range hits {
		out = append(out, h.row)
	}
	return out, statusMap
}

func buildLocalArgv(entry CatalogEntry, rawArgv []string, toolArgs map[string]any) []string {
	if len(rawArgv) > 0 {
		// Auto-prepend noun (and verb when missing) if caller followed a shorthand hint.
		if rawArgv[0] == entry.Noun {
			return append([]string{}, rawArgv...)
		}
		if entry.Verb != "" && rawArgv[0] == entry.Verb {
			return append([]string{entry.Noun}, rawArgv...)
		}
		out := []string{entry.Noun}
		if entry.Verb != "" {
			out = append(out, entry.Verb)
		}
		return append(out, rawArgv...)
	}

	out := []string{entry.Noun}
	if entry.Verb != "" {
		out = append(out, entry.Verb)
	}
	if len(toolArgs) == 0 {
		return out
	}

	used := map[string]bool{"cwd": true}
	popStr := func(keys ...string) string {
		for _, k := range keys {
			if v, ok := toolArgs[k]; ok && v != nil {
				used[k] = true
				s := strings.TrimSpace(fmt.Sprint(v))
				if s != "" && s != "<nil>" {
					return s
				}
			}
		}
		return ""
	}

	switch {
	case entry.Name == "route_context" || entry.Name == "route_grep" || entry.Name == "route_errors":
		pathVal := popStr("path", "root", "dir", "workspace", "file")
		if pathVal == "" {
			pathVal = "."
		}
		out = append(out, pathVal)
	case entry.Name == "code_graph" || entry.Name == "code_callers" || entry.Name == "code_refs" || entry.Name == "code_trace":
		sym := popStr("symbol", "name", "target")
		pathVal := popStr("path", "root", "dir", "workspace")
		if pathVal == "" {
			pathVal = "."
		}
		if sym != "" {
			out = append(out, "--symbol", sym, "--path", pathVal)
		} else {
			out = append(out, pathVal)
		}
	case entry.Name == "code_symbols" || entry.Name == "code_index" || entry.Name == "code_audit":
		pathVal := popStr("path", "root", "dir", "workspace", "file", "target", "repo")
		if pathVal == "" {
			pathVal = "."
		}
		out = append(out, pathVal)
	case entry.Name == "code_lsp":
		if act := popStr("action", "op"); act != "" {
			out = append(out, act)
		}
		if pathVal := popStr("path", "file"); pathVal != "" {
			out = append(out, pathVal)
		}
	case entry.Name == "mem_search":
		if q := popStr("query", "text"); q != "" {
			out = append(out, q)
		}
	case entry.Name == "recall":
		if q := popStr("query", "text"); q != "" {
			out = append(out, q)
		}
	case entry.Name == "compress" || strings.HasPrefix(entry.Name, "compress_"):
		if entry.Verb == "" {
			level := popStr("level")
			if level == "" {
				level = "L1"
			}
			out = append(out, level)
		} else {
			used["level"] = true
		}
	case entry.Name == "scan":
		if kind := popStr("kind", "subcommand", "mode"); kind != "" {
			out = append(out, kind)
		} else {
			out = append(out, "secrets")
		}
		if pathVal := popStr("path", "root", "dir", "file", "value"); pathVal != "" {
			out = append(out, pathVal)
		}
	case strings.HasPrefix(entry.Name, "scan_"):
		if pathVal := popStr("path", "root", "dir", "file", "value"); pathVal != "" {
			out = append(out, pathVal)
		}
	case entry.Name == "re_diff":
		if b1 := popStr("bin1", "v1", "path1", "file1", "old", "a", "left", "first", "path", "value"); b1 != "" {
			out = append(out, b1)
		}
		if b2 := popStr("bin2", "v2", "path2", "file2", "new", "b", "right", "second", "other"); b2 != "" {
			out = append(out, b2)
		}
	default:
		if strings.HasPrefix(entry.Name, "re_") {
			if act := popStr("action"); act != "" {
				out = append(out, act)
			}
			if pathVal := popStr("path", "file", "binary", "bin", "target_file"); pathVal != "" {
				out = append(out, pathVal)
			}
			if entry.Name == "re_cfg" || entry.Name == "re_decompile" || entry.Name == "re_disasm" {
				if sym := popStr("symbol", "func", "function", "name"); sym != "" {
					out = append(out, "--symbol", sym)
				}
			} else if sym := popStr("symbol", "func", "function"); sym != "" {
				out = append(out, "--symbol", sym)
			}
		} else if q := popStr("value"); q != "" {
			out = append(out, q)
		}
	}

	keys := make([]string, 0, len(toolArgs))
	for k := range toolArgs {
		if !used[k] {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	for _, k := range keys {
		v := toolArgs[k]
		if v == nil {
			continue
		}
		flag := "--" + strings.ReplaceAll(k, "_", "-")
		switch val := v.(type) {
		case bool:
			if val {
				out = append(out, flag)
			}
		case float64:
			if val == float64(int64(val)) {
				out = append(out, flag, fmt.Sprintf("%d", int64(val)))
			} else {
				out = append(out, flag, fmt.Sprint(val))
			}
		default:
			s := fmt.Sprint(val)
			if s != "" && s != "<nil>" {
				if strings.HasPrefix(s, "-") {
					out = append(out, flag+"="+s)
				} else {
					out = append(out, flag, s)
				}
			}
		}
	}
	return out
}

// ServeMeta runs xt-forge's built-in 4-tool meta MCP server over stdio, routing
// both xt-forge CLI tools and connected upstream MCP servers (e.g. rea, craft-anything).
func ServeMeta(selfBin string, maxBytes int) int {
	if maxBytes <= 0 {
		maxBytes = 16384
	}
	pool := NewUpstreamPool()
	defer pool.CloseAll()

	metaTools := []ToolDef{
		{
			Name:        "xt_discover",
			Description: "Discover xt-forge tools (code_callers, code_graph, code_audit, code_trace, re_diff, re_cfg, route_context, scan_secrets) and upstream MCP tools.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"query":    map[string]any{"type": "string"},
					"category": map[string]any{"type": "string"},
					"upstream": map[string]any{"type": "string"},
					"limit":    map[string]any{"type": "integer"},
				},
				"additionalProperties": false,
			},
		},
		{
			Name:        "xt_schema",
			Description: "Get schema/usage for an xt-forge or <server>:<tool> name.",
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
			Description: "Execute xt-forge tool directly: name='code_callers'|'code_graph'|'code_audit'|'code_trace'|'re_diff'|'re_decompile'|'re_disasm'|'route_context' or <server>:<tool> with recovery.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"argv":            map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "Explicit CLI argv, e.g. ['re','diff','bin/v1','bin/v2'] or ['code','audit','.']"},
					"name":            map[string]any{"type": "string", "description": "xt-forge tool name (e.g. 'code_callers', 'code_audit', 'code_trace', 're_diff', 're_decompile') or '<server>:<tool>'"},
					"server":          map[string]any{"type": "string"},
					"tool":            map[string]any{"type": "string"},
					"arguments":       map[string]any{"type": "object", "description": "Args object: {'symbol':...,'path':'.'} for code_*, {'path':'.'} for code_audit, {'bin1':...,'bin2':...} for re_diff, {'path':...,'symbol':...} for re_decompile"},
					"cwd":             map[string]any{"type": "string"},
					"idempotency_key": map[string]any{"type": "string"},
					"verify_tool":     map[string]any{"type": "string"},
					"verify_args":     map[string]any{"type": "object"},
					"max_bytes":       map[string]any{"type": "integer"},
				},
				"additionalProperties": false,
			},
		},
		{
			Name:        "xt_batch",
			Description: "Run multiple read-only calls concurrently.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"calls": map[string]any{
						"type": "array",
						"items": map[string]any{
							"type": "object",
							"properties": map[string]any{
								"argv":      map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
								"name":      map[string]any{"type": "string"},
								"server":    map[string]any{"type": "string"},
								"tool":      map[string]any{"type": "string"},
								"arguments": map[string]any{"type": "object"},
							},
						},
					},
				},
				"required":             []string{"calls"},
				"additionalProperties": false,
			},
		},
	}

	dispatchCall := func(ctx context.Context, args map[string]any, budget int) (string, bool) {
		rawName, _ := args["name"].(string)
		srv, _ := args["server"].(string)
		tool, _ := args["tool"].(string)
		toolArgs, _ := args["arguments"].(map[string]any)
		opts := extractRecoveryOpts(args)
		if srv != "" && tool != "" {
			return callUpstreamToolContext(ctx, pool, srv, tool, toolArgs, opts, budget)
		}
		if uSrv, uTool, ok := splitUpstreamToolRef(rawName); ok {
			return callUpstreamToolContext(ctx, pool, uSrv, uTool, toolArgs, opts, budget)
		}
		workDir, _ := args["cwd"].(string)
		if workDir == "" && toolArgs != nil {
			if c, ok := toolArgs["cwd"].(string); ok {
				workDir = c
			}
		}
		rawArgv, _ := args["argv"].([]any)
		argv := make([]string, 0, len(rawArgv))
		for _, item := range rawArgv {
			if s, ok := item.(string); ok {
				argv = append(argv, s)
			}
		}
		if rawName != "" {
			norm := strings.ReplaceAll(strings.TrimSpace(rawName), "-", "_")
			matched := false
			var matchedEntry CatalogEntry
			for _, e := range FullCatalog() {
				if e.Name == rawName || e.Name == norm {
					matchedEntry = e
					argv = buildLocalArgv(e, argv, toolArgs)
					matched = true
					break
				}
			}
			if !matched {
				if strings.HasPrefix(norm, "scan_") {
					verb := strings.TrimPrefix(norm, "scan_")
					matchedEntry = CatalogEntry{Name: norm, Noun: "scan", Verb: verb}
					argv = buildLocalArgv(matchedEntry, argv, toolArgs)
					matched = true
				} else if strings.HasPrefix(norm, "compress_l") && len(norm) == len("compress_l1") {
					lvl := strings.ToUpper(strings.TrimPrefix(norm, "compress_"))
					matchedEntry = CatalogEntry{Name: norm, Noun: "compress", Verb: lvl}
					argv = buildLocalArgv(matchedEntry, argv, toolArgs)
					matched = true
				}
			}
			if !matched && len(argv) == 0 {
				return fmt.Sprintf("unknown xt-forge tool '%s'; call xt_discover or pass explicit argv", rawName), true
			}
			if matched && len(rawArgv) == 0 {
				if matchedEntry.Name == "code_graph" || matchedEntry.Name == "code_callers" || matchedEntry.Name == "code_refs" || matchedEntry.Name == "code_trace" {
					hasSym := false
					for _, k := range []string{"symbol", "name", "target"} {
						if v, ok := toolArgs[k]; ok && strings.TrimSpace(fmt.Sprint(v)) != "" && fmt.Sprint(v) != "<nil>" {
							hasSym = true
							break
						}
					}
					if !hasSym {
						return fmt.Sprintf("missing required field 'symbol' for %s; example: {\"name\":%q,\"arguments\":{\"symbol\":\"MyFunc\",\"path\":\".\"}}", matchedEntry.Name, matchedEntry.Name), true
					}
				} else if matchedEntry.Name == "route_grep" {
					hasPat := false
					for _, k := range []string{"pattern", "regex"} {
						if v, ok := toolArgs[k]; ok && strings.TrimSpace(fmt.Sprint(v)) != "" && fmt.Sprint(v) != "<nil>" {
							hasPat = true
							break
						}
					}
					if !hasPat {
						return "missing required field 'pattern' for route_grep; example: {\"name\":\"route_grep\",\"arguments\":{\"pattern\":\"MyFunc\",\"path\":\".\"}}", true
					}
				}
			}
		}
		return runLocalCommand(selfBin, argv, budget, workDir)
	}

	return serveLoop(metaTools, func(ctx context.Context, name string, args map[string]any) (string, bool) {
		switch name {
		case "xt_discover":
			q, _ := args["query"].(string)
			cat, _ := args["category"].(string)
			up, _ := args["upstream"].(string)
			lim := 10
			if f, ok := args["limit"].(float64); ok && f > 0 {
				lim = int(f)
			}
			local := []CatalogEntry{}
			upNorm := strings.ToLower(strings.TrimSpace(up))
			if upNorm == "" || upNorm == "all" || upNorm == "xt-forge" {
				local = searchCatalog(q, cat, lim)
			}
			ext, upStatus := searchUpstreamCatalogs(pool, up, q, lim)
			if cat != "" {
				ext = []map[string]any{}
			}
			payload := map[string]any{
				"ok":               true,
				"matches":          local,
				"upstream_matches": ext,
				"upstream_status":  upStatus,
				"known_upstreams":  KnownUpstreams(),
			}
			b, _ := json.MarshalIndent(payload, "", "  ")
			return string(b), false
		case "xt_schema":
			target, _ := args["name"].(string)
			if srv, toolName, ok := splitUpstreamToolRef(target); ok {
				tools, err := resolveUpstreamTools(pool, srv)
				if err != nil {
					return err.Error(), true
				}
				for _, t := range tools {
					if t.Name == toolName {
						b, _ := json.MarshalIndent(map[string]any{
							"ok":          true,
							"upstream":    srv,
							"name":        srv + ":" + t.Name,
							"tool":        t.Name,
							"description": t.Description,
							"inputSchema": t.InputSchema,
						}, "", "  ")
						return string(b), false
					}
				}
				return fmt.Sprintf("unknown tool '%s' on upstream '%s'", toolName, srv), true
			}
			for _, mt := range metaTools {
				if mt.Name == target {
					b, _ := json.MarshalIndent(mt, "", "  ")
					return string(b), false
				}
			}
			for _, e := range FullCatalog() {
				if e.Name == target {
					b, _ := json.MarshalIndent(e, "", "  ")
					return string(b), false
				}
			}
			return fmt.Sprintf("unknown xt-forge catalog tool: %s", target), true
		case "xt_call":
			mb := maxBytes
			if f, ok := args["max_bytes"].(float64); ok && f > 0 {
				mb = int(f)
			}
			return dispatchCall(ctx, args, mb)
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
					txt, isErr := dispatchCall(ctx, m, maxBytes/2)
					results[idx] = map[string]any{
						"target":  m["name"],
						"argv":    m["argv"],
						"isError": isErr,
						"output":  txt,
					}
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
// artifact spilling, dynamic tools/list refresh, and schema rug-pull verification.
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

	sess, err := StartUpstreamSession(prefix, upstreamCmd)
	if err != nil {
		fmt.Fprintf(os.Stderr, "xtforge mcp proxy: %v\n", err)
		return 1
	}
	defer sess.Close()

	upstreamTools := sess.Tools()
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
			Description: fmt.Sprintf("Execute a tool on '%s' with compression, spill, and journal recovery.", prefix),
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"tool":            map[string]any{"type": "string"},
					"arguments":       map[string]any{"type": "object"},
					"idempotency_key": map[string]any{"type": "string"},
					"verify_tool":     map[string]any{"type": "string"},
					"verify_args":     map[string]any{"type": "object"},
				},
				"required": []string{"tool"},
			},
		},
	}

	return serveLoop(proxyTools, func(ctx context.Context, name string, args map[string]any) (string, bool) {
		currentTools := sess.Tools()
		switch name {
		case prefix + "_search":
			q := strings.ToLower(fmt.Sprint(args["query"]))
			lim := 10
			if f, ok := args["limit"].(float64); ok && f > 0 {
				lim = int(f)
			}
			var hits []map[string]any
			for _, t := range currentTools {
				hay := strings.ToLower(t.Name + " " + t.Description)
				if q == "" || strings.Contains(hay, q) {
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
			b, _ := json.MarshalIndent(map[string]any{"server": prefix, "total_tools": len(currentTools), "audit": auditRes.Status, "matches": hits}, "", "  ")
			clipped, _ := compress.ClipOrSpill(string(b), maxBytes, prefix+"-search")
			return clipped, false
		case prefix + "_list":
			off, lim := 0, 30
			if f, ok := args["offset"].(float64); ok && f >= 0 {
				off = int(f)
			}
			if f, ok := args["limit"].(float64); ok && f > 0 {
				lim = int(f)
			}
			var rows []map[string]string
			for i := off; i < len(currentTools) && len(rows) < lim; i++ {
				rows = append(rows, map[string]string{
					"name":        currentTools[i].Name,
					"description": SummarizeDescription(currentTools[i].Description, 100),
				})
			}
			b, _ := json.MarshalIndent(map[string]any{"server": prefix, "total": len(currentTools), "tools": rows}, "", "  ")
			return string(b), false
		case prefix + "_call":
			tName, _ := args["tool"].(string)
			if tName == "" {
				tName, _ = args["name"].(string)
			}
			tArgs, _ := args["arguments"].(map[string]any)
			if tArgs == nil {
				tArgs = map[string]any{}
			}
			opts := extractRecoveryOpts(args)
			return runRecoverableUpstreamCall(ctx, sess, "mcp-proxy", prefix, tName, tArgs, opts, maxBytes)
		default:
			return "unknown proxy tool: " + name, true
		}
	})
}

func normalizeRPCID(raw json.RawMessage) string {
	return strings.Trim(strings.TrimSpace(string(raw)), `"`)
}

func serveLoop(tools []ToolDef, handler func(context.Context, string, map[string]any) (string, bool)) int {
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 64*1024), 16*1024*1024)

	var outMu sync.Mutex
	writeResp := func(v any) {
		b, _ := json.Marshal(v)
		outMu.Lock()
		_, _ = os.Stdout.Write(append(b, '\n'))
		outMu.Unlock()
	}

	var activeMu sync.Mutex
	active := map[string]context.CancelFunc{}
	var wg sync.WaitGroup

	cancelAll := func() {
		activeMu.Lock()
		for id, cancel := range active {
			cancel()
			delete(active, id)
		}
		activeMu.Unlock()
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
			cancelAll()
			break
		}
		if len(msg.ID) == 0 || string(msg.ID) == "null" {
			if msg.Method == "notifications/cancelled" {
				var params struct {
					RequestID json.RawMessage `json:"requestId"`
				}
				if json.Unmarshal(msg.Params, &params) == nil {
					key := normalizeRPCID(params.RequestID)
					activeMu.Lock()
					if cancel, ok := active[key]; ok {
						cancel()
						delete(active, key)
					}
					activeMu.Unlock()
				}
			}
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
					"serverInfo":      map[string]any{"name": "xt-forge-hub", "version": "0.4.4"},
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
			reqID := append(json.RawMessage(nil), msg.ID...)
			reqKey := normalizeRPCID(reqID)
			ctx, cancel := context.WithCancel(context.Background())
			activeMu.Lock()
			active[reqKey] = cancel
			activeMu.Unlock()
			wg.Add(1)
			go func(id json.RawMessage, key string, ctx context.Context, cancel context.CancelFunc, name string, args map[string]any) {
				defer wg.Done()
				defer func() {
					activeMu.Lock()
					delete(active, key)
					activeMu.Unlock()
					cancel()
				}()
				text, isErr := handler(ctx, name, args)
				if ctx.Err() == context.Canceled {
					return
				}
				writeResp(map[string]any{
					"jsonrpc": "2.0",
					"id":      id,
					"result": map[string]any{
						"content": []map[string]any{{"type": "text", "text": text}},
						"isError": isErr,
					},
				})
			}(reqID, reqKey, ctx, cancel, params.Name, params.Arguments)
		case "shutdown":
			cancelAll()
			writeResp(map[string]any{"jsonrpc": "2.0", "id": msg.ID, "result": nil})
		default:
			writeResp(map[string]any{"jsonrpc": "2.0", "id": msg.ID, "error": rpcError{Code: -32601, Message: "method not found: " + msg.Method}})
		}
	}
	wg.Wait()
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
