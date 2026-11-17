// Package loopd manages persistent, restart-safe loop schedules under
// ~/.xt-forge/loops/ enforcing MAX_TASKS=50, 7-day lifetime cap, and the
// XT_NATIVE_LOOP=0 kill switch.
package loopd

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"xtforge-hub/internal/guard"
)

const (
	MaxTasks        = 50
	LifetimeSeconds = 7 * 86400
)

type Schedule struct {
	ID        string `json:"id"`
	SessionID string `json:"session_id"`
	Task      string `json:"task"`
	Mode      string `json:"mode"`
	Interval  int64  `json:"interval,omitempty"`
	Created   int64  `json:"created"`
	Expires   int64  `json:"expires"`
	Paused    bool   `json:"paused"`
}

func storePath() string {
	return filepath.Join(guard.XTHome(), "loops", "schedules.json")
}

func Disabled() bool {
	return os.Getenv("XT_NATIVE_LOOP") == "0"
}

func LoadAll() ([]Schedule, error) {
	raw, err := os.ReadFile(storePath())
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var items []Schedule
	if err := json.Unmarshal(raw, &items); err != nil {
		return nil, err
	}
	now := time.Now().Unix()
	var alive []Schedule
	for _, s := range items {
		if s.Expires > now {
			alive = append(alive, s)
		}
	}
	return alive, nil
}

func SaveAll(items []Schedule) error {
	p := storePath()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(items, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(p, append(b, '\n'), 0o600)
}

func Add(sessionID, task, mode string, interval int64) (map[string]any, error) {
	if Disabled() {
		return map[string]any{"ok": false, "error": "loops disabled by XT_NATIVE_LOOP=0"}, nil
	}
	if sessionID == "" {
		sessionID = "default"
	}
	if strings.TrimSpace(task) == "" {
		return map[string]any{"ok": false, "error": "task text required"}, nil
	}
	if mode == "" {
		mode = "fixed"
	}
	items, err := LoadAll()
	if err != nil {
		return nil, err
	}
	now := time.Now().Unix()
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s|%s|%d", sessionID, task, now)))
	id := "loop-" + hex.EncodeToString(sum[:])[:10]
	items = append(items, Schedule{
		ID:        id,
		SessionID: sessionID,
		Task:      task,
		Mode:      mode,
		Interval:  interval,
		Created:   now,
		Expires:   now + LifetimeSeconds,
	})

	// Enforce per-session MAX_TASKS cap (evict oldest first).
	var mine, others []Schedule
	for _, s := range items {
		if s.SessionID == sessionID {
			mine = append(mine, s)
		} else {
			others = append(others, s)
		}
	}
	sort.Slice(mine, func(i, j int) bool { return mine[i].Created < mine[j].Created })
	if len(mine) > MaxTasks {
		mine = mine[len(mine)-MaxTasks:]
	}
	final := append(others, mine...)
	if err := SaveAll(final); err != nil {
		return nil, err
	}
	return map[string]any{"ok": true, "id": id, "active": len(mine), "max_tasks": MaxTasks}, nil
}

func Stop(id string) (map[string]any, error) {
	items, err := LoadAll()
	if err != nil {
		return nil, err
	}
	var kept []Schedule
	removed := 0
	for _, s := range items {
		if id == "all" || s.ID == id {
			removed++
			continue
		}
		kept = append(kept, s)
	}
	if err := SaveAll(kept); err != nil {
		return nil, err
	}
	return map[string]any{"ok": true, "removed": removed, "remaining": len(kept)}, nil
}
