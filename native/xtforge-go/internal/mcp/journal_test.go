package mcp

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCallRecoveryDropReplyAndVerifyReceipt(t *testing.T) {
	xtHome := t.TempDir()
	t.Setenv("XT_HOME", xtHome)
	t.Setenv("XT_PERM_MODE", "full")

	statePath := filepath.Join(t.TempDir(), "server_state.json")
	mock := writeMockMCPServer(t, `
import json, os, sys

state_path = sys.argv[1]

def load_state():
    if os.path.exists(state_path):
        with open(state_path, "r") as f:
            return json.load(f)
    return {"commits": 0, "attempts": 0, "receipts": {}}

def save_state(st):
    with open(state_path, "w") as f:
        json.dump(st, f)

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
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": "mock-job-srv", "version": "1.0"},
        }}), flush=True)
    elif method == "tools/list":
        print(json.dumps({"jsonrpc": "2.0", "id": mid, "result": {"tools": [
            {"name": "submit_job", "description": "Commit one job once", "inputSchema": {"type": "object"}},
            {"name": "get_receipt", "description": "Read-only receipt lookup", "inputSchema": {"type": "object"}},
        ]}}), flush=True)
    elif method == "tools/call":
        p = msg.get("params") or {}
        tname = p.get("name")
        args = p.get("arguments") or {}
        st = load_state()
        if tname == "submit_job":
            st["attempts"] += 1
            key = args.get("job_id") or "default"
            if key not in st["receipts"]:
                st["commits"] += 1
                st["receipts"][key] = {"receipt_id": f"rcpt-{st['commits']}", "job_id": key}
            save_state(st)
            if st["attempts"] == 1:
                # Commit ONCE then drop the first reply by exiting abruptly.
                sys.exit(0)
            res = {"content": [{"type": "text", "text": json.dumps({"committed": True, "receipt": st["receipts"][key]})}]}
            print(json.dumps({"jsonrpc": "2.0", "id": mid, "result": res}), flush=True)
        elif tname == "get_receipt":
            key = args.get("job_id") or "default"
            rec = st["receipts"].get(key)
            payload = {"found": rec is not None, "receipt": rec}
            res = {"content": [{"type": "text", "text": json.dumps(payload)}]}
            print(json.dumps({"jsonrpc": "2.0", "id": mid, "result": res}), flush=True)
`)
	cmd := append(mock, statePath)
	pool := NewUpstreamPool()
	defer pool.CloseAll()

	if err := SaveUpstream(UpstreamConfig{Name: "jobs", Command: cmd, Source: "test"}); err != nil {
		t.Fatal(err)
	}

	// 1) Pre-cancelled context records never_started and makes zero server attempts.
	cancelledCtx, cancelNow := context.WithCancel(context.Background())
	cancelNow()
	txt0, isErr0 := callUpstreamToolContext(cancelledCtx, pool, "jobs", "submit_job", map[string]any{"job_id": "j0"}, callRecoveryOpts{
		IdempotencyKey: "job-j0",
	}, 8192)
	if !isErr0 || !strings.Contains(txt0, CallNeverStarted) {
		t.Fatalf("expected never_started on pre-cancelled call, got isErr=%v txt=%s", isErr0, txt0)
	}
	entry0, ok := FindJournalByKey("job-j0")
	if !ok || entry0.State != CallNeverStarted {
		t.Fatalf("expected journal state=%s, got ok=%v entry=%+v", CallNeverStarted, ok, entry0)
	}

	// 2) Execute call without verify_tool: server commits ONCE, then drops reply -> unknown_outcome.
	txt1, isErr1 := callUpstreamToolContext(context.Background(), pool, "jobs", "submit_job", map[string]any{"job_id": "j1"}, callRecoveryOpts{
		IdempotencyKey: "job-j1",
	}, 8192)
	if !isErr1 || !strings.Contains(txt1, CallUnknownOutcome) {
		t.Fatalf("expected unknown_outcome when reply drops, got isErr=%v txt=%s", isErr1, txt1)
	}
	entry1, ok := FindJournalByKey("job-j1")
	if !ok || entry1.State != CallUnknownOutcome {
		t.Fatalf("expected unknown_outcome in journal, got %+v", entry1)
	}

	// 3) Retry WITHOUT verify_tool must refuse duplicate execution.
	pool.CloseAll()
	txtBlocked, isErrBlocked := callUpstreamToolContext(context.Background(), pool, "jobs", "submit_job", map[string]any{"job_id": "j1"}, callRecoveryOpts{
		IdempotencyKey: "job-j1",
	}, 8192)
	if !isErrBlocked || !strings.Contains(txtBlocked, "unknown_outcome") || !strings.Contains(txtBlocked, "duplicate_prevented") {
		t.Fatalf("expected blind retry to be blocked, got isErr=%v txt=%s", isErrBlocked, txtBlocked)
	}

	// 4) Retry WITH verify_tool recovers receipt via read-only lookup, avoids duplicate write, marks completed.
	txt2, isErr2 := callUpstreamToolContext(context.Background(), pool, "jobs", "submit_job", map[string]any{"job_id": "j1"}, callRecoveryOpts{
		IdempotencyKey: "job-j1",
		VerifyTool:     "get_receipt",
		VerifyArgs:     map[string]any{"job_id": "j1"},
	}, 8192)
	if isErr2 {
		t.Fatalf("expected recovery to succeed, got error: %s", txt2)
	}
	if !strings.Contains(txt2, `"recovered":true`) || !strings.Contains(txt2, `"duplicate_prevented":true`) || !strings.Contains(txt2, `rcpt-1`) {
		t.Fatalf("expected recovered receipt output, got: %s", txt2)
	}

	rawState, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	var st struct {
		Commits  int `json:"commits"`
		Attempts int `json:"attempts"`
	}
	if err := json.Unmarshal(rawState, &st); err != nil {
		t.Fatal(err)
	}
	if st.Commits != 1 || st.Attempts != 1 {
		t.Fatalf("expected exactly 1 commit and 1 submit_job attempt, got commits=%d attempts=%d", st.Commits, st.Attempts)
	}

	// 5) Subsequent call replays completed result with zero extra upstream calls.
	txt3, isErr3 := callUpstreamToolContext(context.Background(), pool, "jobs", "submit_job", map[string]any{"job_id": "j1"}, callRecoveryOpts{
		IdempotencyKey: "job-j1",
	}, 8192)
	if isErr3 || !strings.Contains(txt3, "rcpt-1") {
		t.Fatalf("expected replay of completed entry, got isErr=%v txt=%s", isErr3, txt3)
	}
}

func TestCancelPropagatesNotificationToUpstream(t *testing.T) {
	t.Setenv("XT_HOME", t.TempDir())
	t.Setenv("XT_PERM_MODE", "full")

	cancelLog := filepath.Join(t.TempDir(), "cancellations.jsonl")
	mock := writeMockMCPServer(t, `
import json, sys, threading, time

cancel_log = sys.argv[1]
cancel_ev = threading.Event()

def handle_call(mid):
    # Hold open briefly waiting for cancellation notification
    cancel_ev.wait(timeout=2.0)

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
            "capabilities": {},
            "serverInfo": {"name": "mock-slow", "version": "1.0"},
        }}), flush=True)
    elif method == "tools/list":
        print(json.dumps({"jsonrpc": "2.0", "id": mid, "result": {"tools": [
            {"name": "slow_write", "description": "Slow write", "inputSchema": {"type": "object"}},
        ]}}), flush=True)
    elif method == "notifications/cancelled":
        with open(cancel_log, "a") as f:
            f.write(json.dumps(msg) + "\n")
            f.flush()
        cancel_ev.set()
    elif method == "tools/call":
        threading.Thread(target=handle_call, args=(mid,), daemon=True).start()
`)
	sess, err := StartUpstreamSession("slow", append(mock, cancelLog))
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Millisecond)
	defer cancel()

	txt, isErr := runRecoverableUpstreamCall(ctx, sess, "mcp", "slow", "slow_write", map[string]any{"x": 1}, callRecoveryOpts{
		IdempotencyKey: "slow-1",
	}, 8192)
	if !isErr || !strings.Contains(txt, CallUnknownOutcome) || !strings.Contains(txt, "cancel_notified=true") {
		t.Fatalf("expected unknown_outcome with cancel_notified=true, got isErr=%v txt=%s", isErr, txt)
	}

	// Allow mock subprocess a moment to flush cancellation log before assertion.
	deadline := time.Now().Add(1 * time.Second)
	var logBytes []byte
	for time.Now().Before(deadline) {
		logBytes, err = os.ReadFile(cancelLog)
		if err == nil && len(logBytes) > 0 {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if !strings.Contains(string(logBytes), "notifications/cancelled") || !strings.Contains(string(logBytes), `"requestId"`) {
		t.Fatalf("expected upstream to receive notifications/cancelled, got log=%q err=%v", string(logBytes), err)
	}
}

func TestNormalizeInFlightJournalOnLoad(t *testing.T) {
	t.Setenv("XT_HOME", t.TempDir())
	p := JournalPath()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	raw := `{"version":1,"entries":{"c1":{"call_id":"c1","idempotency_key":"k1","server":"s","tool":"t","state":"in_flight","attempts":1}}}`
	if err := os.WriteFile(p, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	entry, ok := FindJournalByKey("k1")
	if !ok || entry.State != CallUnknownOutcome {
		t.Fatalf("expected interrupted in_flight to normalize to unknown_outcome, got ok=%v entry=%+v", ok, entry)
	}
}
