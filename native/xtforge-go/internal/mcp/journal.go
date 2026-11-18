package mcp

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"xtforge-hub/internal/guard"
)

const (
	CallNeverStarted   = "never_started"
	CallInFlight       = "in_flight"
	CallUnknownOutcome = "unknown_outcome"
	CallCompleted      = "completed"
)

// JournalEntry tracks one recoverable or idempotent tool invocation.
type JournalEntry struct {
	CallID         string         `json:"call_id"`
	IdempotencyKey string         `json:"idempotency_key"`
	Server         string         `json:"server"`
	Tool           string         `json:"tool"`
	ArgsSHA256     string         `json:"args_sha256"`
	State          string         `json:"state"` // never_started | unknown_outcome | completed
	RequestID      int            `json:"request_id,omitempty"`
	Attempts       int            `json:"attempts"`
	Cancelled      bool           `json:"cancelled,omitempty"`
	CancelNotified bool           `json:"cancel_notified,omitempty"`
	VerifyTool     string         `json:"verify_tool,omitempty"`
	VerifyArgs     map[string]any `json:"verify_args,omitempty"`
	IsError        bool           `json:"is_error,omitempty"`
	Result         string         `json:"result,omitempty"`
	ResultSHA256   string         `json:"result_sha256,omitempty"`
	Error          string         `json:"error,omitempty"`
	CreatedAt      int64          `json:"created_at"`
	UpdatedAt      int64          `json:"updated_at"`
}

type journalFile struct {
	Version int                     `json:"version"`
	Entries map[string]JournalEntry `json:"entries"`
}

var journalMu sync.Mutex

// JournalPath returns $XT_HOME/checkpoints/call_journal.json.
func JournalPath() string {
	return filepath.Join(guard.XTHome(), "checkpoints", "call_journal.json")
}

// NormalizeJournalState maps interrupted in_flight rows to unknown_outcome on load.
func NormalizeJournalState(state string) string {
	if state == CallInFlight {
		return CallUnknownOutcome
	}
	return state
}

func argsDigest(server, tool string, args map[string]any) string {
	if args == nil {
		args = map[string]any{}
	}
	b, _ := json.Marshal(args)
	h := sha256.Sum256([]byte(server + ":" + tool + ":" + string(b)))
	return hex.EncodeToString(h[:])[:20]
}

func loadJournalLocked() journalFile {
	jf := journalFile{Version: 1, Entries: map[string]JournalEntry{}}
	raw, err := os.ReadFile(JournalPath())
	if err != nil {
		return jf
	}
	if json.Unmarshal(raw, &jf) != nil || jf.Entries == nil {
		return journalFile{Version: 1, Entries: map[string]JournalEntry{}}
	}
	for k, e := range jf.Entries {
		e.State = NormalizeJournalState(e.State)
		jf.Entries[k] = e
	}
	return jf
}

func saveJournalLocked(jf journalFile) error {
	p := JournalPath()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(jf, "", "  ")
	if err != nil {
		return err
	}
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

// FindJournalByKey returns the latest entry for idempotencyKey (or derived key).
func FindJournalByKey(key string) (JournalEntry, bool) {
	journalMu.Lock()
	defer journalMu.Unlock()
	jf := loadJournalLocked()
	var best JournalEntry
	var found bool
	for _, e := range jf.Entries {
		if e.IdempotencyKey == key {
			if !found || e.UpdatedAt >= best.UpdatedAt {
				best = e
				found = true
			}
		}
	}
	return best, found
}

// UpsertJournalEntry inserts or updates one call journal record atomically.
func UpsertJournalEntry(e JournalEntry) (JournalEntry, error) {
	journalMu.Lock()
	defer journalMu.Unlock()
	now := time.Now().Unix()
	if e.CallID == "" {
		e.CallID = fmt.Sprintf("call_%d_%s", now, argsDigest(e.Server, e.Tool, map[string]any{"ts": time.Now().UnixNano()})[:8])
	}
	if e.CreatedAt == 0 {
		e.CreatedAt = now
	}
	e.UpdatedAt = now
	jf := loadJournalLocked()
	jf.Entries[e.CallID] = e
	if err := saveJournalLocked(jf); err != nil {
		return e, err
	}
	return e, nil
}

// ListJournalEntries returns journal entries sorted newest-first, optionally filtered by state.
func ListJournalEntries(stateFilter string) []JournalEntry {
	journalMu.Lock()
	defer journalMu.Unlock()
	jf := loadJournalLocked()
	f := strings.TrimSpace(strings.ToLower(stateFilter))
	out := make([]JournalEntry, 0, len(jf.Entries))
	for _, e := range jf.Entries {
		if f != "" && e.State != f {
			continue
		}
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].UpdatedAt != out[j].UpdatedAt {
			return out[i].UpdatedAt > out[j].UpdatedAt
		}
		return out[i].CallID > out[j].CallID
	})
	return out
}
