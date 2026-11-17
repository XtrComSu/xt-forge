// Package research runs parallel multi-source evidence gathering across
// local memory/knowledge, code graph, threat intel (CVE/KEV), Context7 docs,
// and writes structured findings to a recon ledger.
package research

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"time"
)

type SourceHit struct {
	Source string `json:"source"`
	OK     bool   `json:"ok"`
	Data   any    `json:"data,omitempty"`
	Error  string `json:"error,omitempty"`
}

// Run executes a parallel multi-source research pass using the xtforge CLI.
func Run(selfBin, query, target string, includeWeb bool) map[string]any {
	query = strings.TrimSpace(query)
	if query == "" {
		return map[string]any{"ok": false, "error": "research query required"}
	}
	if target == "" {
		target = sanitizeTarget(query)
	}

	type job struct {
		name string
		argv []string
	}
	jobs := []job{
		{name: "recall", argv: []string{"recall", query, "--json"}},
		{name: "knowledge", argv: []string{"knowledge", "search", query, "--json"}},
		{name: "code_grep", argv: []string{"route", "grep", ".", "--pattern", firstToken(query), "--limit", "10", "--json"}},
	}
	upper := strings.ToUpper(query)
	if strings.HasPrefix(upper, "CVE-") {
		jobs = append(jobs, job{name: "intel_cve", argv: []string{"intel", "cve", upper, "--json"}})
	} else {
		jobs = append(jobs, job{name: "intel_search", argv: []string{"intel", "search", query, "--limit", "5", "--json"}})
	}
	if includeWeb {
		jobs = append(jobs, job{name: "web_search", argv: []string{"search", query, "--web", "--limit", "5", "--json"}})
	}

	results := make([]SourceHit, len(jobs))
	var wg sync.WaitGroup
	for i, jb := range jobs {
		wg.Add(1)
		go func(idx int, j job) {
			defer wg.Done()
			cmd := exec.Command(selfBin, j.argv...)
			out, err := cmd.CombinedOutput()
			if err != nil && len(out) == 0 {
				results[idx] = SourceHit{Source: j.name, OK: false, Error: err.Error()}
				return
			}
			var parsed any
			if json.Unmarshal(out, &parsed) == nil {
				results[idx] = SourceHit{Source: j.name, OK: true, Data: parsed}
			} else {
				results[idx] = SourceHit{Source: j.name, OK: err == nil, Data: strings.TrimSpace(string(out))}
			}
		}(i, jb)
	}
	wg.Wait()

	// Record a concise recon note under target for traceability.
	noteBody := fmt.Sprintf("Research pass at %s for %q across %d sources.",
		time.Now().UTC().Format(time.RFC3339), query, len(results))
	_ = exec.Command(selfBin, "recon", "new", target).Run()
	_ = exec.Command(selfBin, "recon", "note", target, "--text", noteBody).Run()

	okCount := 0
	for _, r := range results {
		if r.OK {
			okCount++
		}
	}
	return map[string]any{
		"ok":           true,
		"query":        query,
		"recon_target": target,
		"sources_ok":   okCount,
		"sources_all":  len(results),
		"hits":         results,
	}
}

func firstToken(s string) string {
	fields := strings.Fields(s)
	if len(fields) == 0 {
		return s
	}
	return fields[0]
}

func sanitizeTarget(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			b.WriteRune(r)
		} else if r == ' ' {
			b.WriteRune('-')
		}
		if b.Len() >= 32 {
			break
		}
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		return "research"
	}
	return "research-" + out
}
