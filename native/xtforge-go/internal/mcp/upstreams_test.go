package mcp

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeMockMCPServer(t *testing.T, script string) []string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "mock_mcp.py")
	if err := os.WriteFile(p, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return []string{"python3", p}
}

func TestSplitCommandAndPresetResolution(t *testing.T) {
	t.Setenv("XT_HOME", t.TempDir())

	parts := SplitCommand(`"/opt/Craft Anything/craft-anything-cli" mcp --project "my proj"`)
	if len(parts) != 4 || parts[0] != "/opt/Craft Anything/craft-anything-cli" || parts[3] != "my proj" {
		t.Fatalf("unexpected SplitCommand: %#v", parts)
	}

	t.Setenv("REA_CMD", "/tmp/fake/rea-agents")
	name, reaCmd, err := ResolvePresetCommand("rea-agents")
	if err != nil || name != "rea" || len(reaCmd) != 2 || reaCmd[1] != "mcp" {
		t.Fatalf("unexpected rea preset resolution: name=%s cmd=%v err=%v", name, reaCmd, err)
	}

	t.Setenv("CRAFT_ANYTHING_CMD", "/tmp/fake/craft-anything-cli")
	t.Setenv("XT_CRAFT_DEEP", "1")
	t.Setenv("XT_CRAFT_ALL_TOOLS", "1")
	cname, craftCmd, err := ResolvePresetCommand("craft")
	if err != nil || cname != "craft-anything" {
		t.Fatalf("unexpected craft preset: name=%s err=%v", cname, err)
	}
	joined := strings.Join(craftCmd, " ")
	if !strings.Contains(joined, "mcp") || !strings.Contains(joined, "--all-tools") || !strings.Contains(joined, "--deep") {
		t.Fatalf("expected craft flags, got: %s", joined)
	}
}

func TestUpstreamSessionStatePersistenceAndDynamicRefresh(t *testing.T) {
	t.Setenv("XT_HOME", t.TempDir())

	mock := writeMockMCPServer(t, `
import json, sys

initialized = False
opened_target = None
enabled_native = False

for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    msg = json.loads(line)
    mid = msg.get("id")
    method = msg.get("method")
    if method == "initialize":
        print(json.dumps({"jsonrpc": "2.0", "id": mid, "result": {
            "protocolVersion": "2025-06-18",
            "capabilities": {"tools": {"listChanged": True}},
            "serverInfo": {"name": "mock-craft-rea", "version": "1.0"}
        }}), flush=True)
    elif method == "notifications/initialized":
        initialized = True
    elif method == "tools/list":
        if not initialized:
            print(json.dumps({"jsonrpc": "2.0", "id": mid, "error": {"code": -32002, "message": "not initialized"}}), flush=True)
            continue
        tools = [
            {"name": "open_binary", "description": "Open target file persistently.", "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}}},
            {"name": "enable_toolset", "description": "Enable additional toolset.", "inputSchema": {"type": "object", "properties": {"name": {"type": "string"}}}},
            {"name": "get_state", "description": "Inspect current opened target.", "inputSchema": {"type": "object"}},
        ]
        if enabled_native:
            tools.append({"name": "native_disasm", "description": "Disassemble function.", "inputSchema": {"type": "object"}})
        print(json.dumps({"jsonrpc": "2.0", "id": mid, "result": {"tools": tools}}), flush=True)
    elif method == "tools/call":
        p = msg.get("params") or {}
        tname = p.get("name")
        args = p.get("arguments") or {}
        if tname == "open_binary":
            opened_target = args.get("path")
            res = {"content": [{"type": "text", "text": f"opened:{opened_target}"}]}
        elif tname == "get_state":
            res = {"content": [{"type": "text", "text": f"state:{opened_target}|native={enabled_native}"}]}
        elif tname == "enable_toolset":
            enabled_native = True
            print(json.dumps({"jsonrpc": "2.0", "method": "notifications/tools/list_changed"}), flush=True)
            res = {"content": [{"type": "text", "text": "enabled:native"}]}
        elif tname == "native_disasm":
            res = {"content": [{"type": "text", "text": "disasm:ret"}]}
        else:
            res = {"content": [{"type": "text", "text": "unknown"}], "isError": True}
        print(json.dumps({"jsonrpc": "2.0", "id": mid, "result": res}), flush=True)
`)

	sess, err := StartUpstreamSession("craft-anything", mock)
	if err != nil {
		t.Fatalf("StartUpstreamSession failed: %v", err)
	}
	defer sess.Close()

	if len(sess.Tools()) != 3 {
		t.Fatalf("expected 3 initial tools, got %d", len(sess.Tools()))
	}

	if _, rpcErr := sess.CallTool("open_binary", map[string]any{"path": "/bin/ls"}); rpcErr != nil {
		t.Fatalf("open_binary failed: %v", rpcErr.Message)
	}
	if _, rpcErr := sess.CallTool("enable_toolset", map[string]any{"name": "native"}); rpcErr != nil {
		t.Fatalf("enable_toolset failed: %v", rpcErr.Message)
	}
	// Catalog should have refreshed automatically after notifications/tools/list_changed.
	if len(sess.Tools()) != 4 {
		t.Fatalf("expected 4 tools after enable_toolset refresh, got %d", len(sess.Tools()))
	}

	stateRaw, rpcErr := sess.CallTool("get_state", map[string]any{})
	if rpcErr != nil {
		t.Fatalf("get_state failed: %v", rpcErr.Message)
	}
	var parsed map[string]any
	if err := json.Unmarshal(stateRaw, &parsed); err != nil {
		t.Fatal(err)
	}
	content := parsed["content"].([]any)[0].(map[string]any)["text"].(string)
	if content != "state:/bin/ls|native=True" {
		t.Fatalf("expected persistent state across calls, got %q", content)
	}

	// Verify saved upstream + catalog cache populate searchUpstreamCatalogs.
	if err := SaveUpstream(UpstreamConfig{Name: "craft-anything", Command: mock, Source: "test"}); err != nil {
		t.Fatal(err)
	}
	pool := NewUpstreamPool()
	defer pool.CloseAll()
	hits := searchUpstreamCatalogs(pool, "craft-anything", "disasm", 5)
	if len(hits) == 0 || hits[0]["name"] != "craft-anything:native_disasm" {
		t.Fatalf("expected craft-anything:native_disasm search hit, got %#v", hits)
	}
}
