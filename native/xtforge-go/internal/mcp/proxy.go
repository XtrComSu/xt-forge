package mcp

import (
	"bufio"
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

func searchUpstreamCatalogs(pool *UpstreamPool, upstreamFilter, query string, limit int) []map[string]any {
	q := strings.ToLower(strings.TrimSpace(query))
	words := strings.Fields(q)
	filter := CanonicalUpstreamName(strings.TrimSpace(upstreamFilter))

	var targets []string
	if filter != "" && filter != "all" && filter != "xt-forge" {
		targets = []string{filter}
	} else if filter != "xt-forge" {
		targets = KnownUpstreams()
	}

	type hit struct {
		row   map[string]any
		score int
	}
	var hits []hit
	for _, srv := range targets {
		var tools []ToolDef
		if filter != "" && filter != "all" {
			tools, _ = resolveUpstreamTools(pool, srv)
		} else {
			tools = LoadCachedCatalog(srv)
			// If query explicitly names rea or craft-anything and no cache exists yet, live-probe once.
			if len(tools) == 0 && (strings.Contains(q, srv) || (srv == "craft-anything" && strings.Contains(q, "craft"))) {
				tools, _ = resolveUpstreamTools(pool, srv)
			}
		}
		for _, t := range tools {
			hay := strings.ToLower(srv + " " + t.Name + " " + t.Description)
			score := 0
			if len(words) == 0 {
				score = 1
			} else {
				for _, w := range words {
					if w == srv || w == "craft" && srv == "craft-anything" {
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
				hits = append(hits, hit{
					score: score,
					row: map[string]any{
						"name":        prefixed,
						"upstream":    srv,
						"tool":        t.Name,
						"description": SummarizeDescription(t.Description, 140),
						"args_hint":   fmt.Sprintf(`{"name":%q,"arguments":{}}`, prefixed),
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
			Description: "Search xt-forge and upstream MCP tools (rea, craft-anything, ...).",
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
			Description: "Run xt-forge argv or upstream <server>:<tool> safely with journal recovery.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"argv":            map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
					"name":            map[string]any{"type": "string"},
					"server":          map[string]any{"type": "string"},
					"tool":            map[string]any{"type": "string"},
					"arguments":       map[string]any{"type": "object"},
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
		rawArgv, _ := args["argv"].([]any)
		argv := make([]string, 0, len(rawArgv))
		for _, item := range rawArgv {
			if s, ok := item.(string); ok {
				argv = append(argv, s)
			}
		}
		if len(argv) == 0 && rawName != "" {
			for _, e := range FullCatalog() {
				if e.Name == rawName {
					argv = []string{e.Noun}
					if e.Verb != "" {
						argv = append(argv, e.Verb)
					}
					break
				}
			}
		}
		return runLocalCommand(selfBin, argv, budget)
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
			ext := []map[string]any{}
			if cat == "" {
				ext = searchUpstreamCatalogs(pool, up, q, lim)
			}
			payload := map[string]any{
				"ok":               true,
				"matches":          local,
				"upstream_matches": ext,
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
					"serverInfo":      map[string]any{"name": "xt-forge-hub", "version": "0.4.2"},
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
