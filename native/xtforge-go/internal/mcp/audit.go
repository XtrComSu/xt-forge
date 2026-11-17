// Package mcp provides the built-in lite MCP meta-proxy, full xt-forge meta
// server, and MCP supply-chain rug-pull / prompt-injection auditor.
package mcp

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"xtforge-hub/internal/guard"
)

// ToolDef matches the JSON-RPC MCP tools/list item shape.
type ToolDef struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"inputSchema"`
}

// TrustRecord stores pinned schema hashes for one MCP server.
type TrustRecord struct {
	Server       string            `json:"server"`
	Command      string            `json:"command,omitempty"`
	SchemaSHA256 string            `json:"schema_sha256"`
	ToolHashes   map[string]string `json:"tool_hashes"`
	ToolCount    int               `json:"tool_count"`
	FirstSeen    int64             `json:"first_seen"`
	LastVerified int64             `json:"last_verified"`
}

type TrustDB struct {
	Version int                    `json:"version"`
	Servers map[string]TrustRecord `json:"servers"`
}

var injectionRules = []struct {
	id       string
	severity string
	re       *regexp.Regexp
	desc     string
}{
	{"ignore_prior", "critical", regexp.MustCompile(`(?i)\bignore\s+(all\s+)?(previous|prior|above)\s+(instructions|prompts|rules)`), "instruction override directive"},
	{"hidden_system", "critical", regexp.MustCompile(`(?i)(<\s*system\s*>|<\s*/?\s*important\s*>|\[SYSTEM\]|IMPORTANT:\s*before\s+calling)`), "hidden prompt tag or imperative override"},
	{"secret_exfil", "critical", regexp.MustCompile(`(?i)(\.ssh/id_rsa|\.aws/credentials|\.env\b|read\s+~/.ssh|pass\s+contents?\s+to)`), "credential exfiltration instruction"},
	{"stealth_directive", "high", regexp.MustCompile(`(?i)(do\s+not\s+(tell|inform|mention\s+to)\s+the\s+user|hide\s+this\s+from\s+the\s+user)`), "stealth concealment instruction"},
	{"shell_pipe", "critical", regexp.MustCompile(`(?i)(curl|wget)[^|]*\|\s*(ba)?sh`), "remote shell execution directive"},
	{"zero_width", "high", regexp.MustCompile("[\u200b\u200c\u200d\u2060\ufeff]"), "zero-width invisible characters in schema"},
}

// TrustPath returns the path to mcp_trust.json inside XT_HOME.
func TrustPath() string {
	return filepath.Join(guard.XTHome(), "mcp_trust.json")
}

// LoadTrust reads mcp_trust.json, returning an empty DB if absent.
func LoadTrust() TrustDB {
	db := TrustDB{Version: 1, Servers: map[string]TrustRecord{}}
	raw, err := os.ReadFile(TrustPath())
	if err != nil {
		return db
	}
	if err := json.Unmarshal(raw, &db); err != nil || db.Servers == nil {
		return TrustDB{Version: 1, Servers: map[string]TrustRecord{}}
	}
	return db
}

// SaveTrust atomically writes mcp_trust.json.
func SaveTrust(db TrustDB) error {
	p := TrustPath()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(db, "", "  ")
	if err != nil {
		return err
	}
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

func toolHash(t ToolDef) string {
	canon, _ := json.Marshal(map[string]any{
		"name":        t.Name,
		"description": t.Description,
		"inputSchema": t.InputSchema,
	})
	sum := sha256.Sum256(canon)
	return hex.EncodeToString(sum[:])
}

func catalogHash(toolHashes map[string]string) string {
	names := make([]string, 0, len(toolHashes))
	for k := range toolHashes {
		names = append(names, k)
	}
	sort.Strings(names)
	h := sha256.New()
	for _, n := range names {
		h.Write([]byte(n))
		h.Write([]byte("="))
		h.Write([]byte(toolHashes[n]))
		h.Write([]byte("\n"))
	}
	return hex.EncodeToString(h.Sum(nil))
}

// AuditFinding describes a schema mutation or injection risk.
type AuditFinding struct {
	Severity string `json:"severity"`
	Rule     string `json:"rule"`
	Tool     string `json:"tool,omitempty"`
	Detail   string `json:"detail"`
}

// AuditResult holds the full trust & security evaluation for one MCP server.
type AuditResult struct {
	OK           bool           `json:"ok"`
	Server       string         `json:"server"`
	Status       string         `json:"status"` // trusted | untrusted | rug_pull | injection_risk
	ToolCount    int            `json:"tool_count"`
	SchemaSHA256 string         `json:"schema_sha256"`
	Findings     []AuditFinding `json:"findings"`
}

// EvaluateTools checks tool schemas for prompt injection and rug-pull drift against mcp_trust.json.
func EvaluateTools(server, command string, tools []ToolDef, trustOnFirst bool) AuditResult {
	hashes := make(map[string]string, len(tools))
	findings := make([]AuditFinding, 0)

	for _, t := range tools {
		hashes[t.Name] = toolHash(t)
		schemaBytes, _ := json.Marshal(t.InputSchema)
		inspectText := t.Description + "\n" + string(schemaBytes)
		for _, rule := range injectionRules {
			if rule.re.MatchString(inspectText) {
				findings = append(findings, AuditFinding{
					Severity: rule.severity,
					Rule:     "schema_" + rule.id,
					Tool:     t.Name,
					Detail:   rule.desc,
				})
			}
		}
	}

	overall := catalogHash(hashes)
	db := LoadTrust()
	pinned, exists := db.Servers[server]
	status := "trusted"

	if !exists {
		if trustOnFirst && len(findings) == 0 {
			now := time.Now().Unix()
			db.Servers[server] = TrustRecord{
				Server:       server,
				Command:      command,
				SchemaSHA256: overall,
				ToolHashes:   hashes,
				ToolCount:    len(tools),
				FirstSeen:    now,
				LastVerified: now,
			}
			_ = SaveTrust(db)
			status = "trusted"
		} else if len(findings) > 0 {
			status = "injection_risk"
		} else {
			status = "untrusted"
		}
	} else {
		if pinned.SchemaSHA256 != overall {
			status = "rug_pull"
			for name, h := range hashes {
				oldH, ok := pinned.ToolHashes[name]
				if !ok {
					findings = append(findings, AuditFinding{
						Severity: "high",
						Rule:     "tool_added",
						Tool:     name,
						Detail:   "tool added since pinned trust snapshot",
					})
				} else if oldH != h {
					findings = append(findings, AuditFinding{
						Severity: "critical",
						Rule:     "schema_mutated",
						Tool:     name,
						Detail:   "tool description or inputSchema changed since pinned snapshot",
					})
				}
			}
			for name := range pinned.ToolHashes {
				if _, ok := hashes[name]; !ok {
					findings = append(findings, AuditFinding{
						Severity: "medium",
						Rule:     "tool_removed",
						Tool:     name,
						Detail:   "tool removed since pinned trust snapshot",
					})
				}
			}
		}
		if len(findings) > 0 && status == "trusted" {
			status = "injection_risk"
		}
	}

	hasCritical := false
	for _, f := range findings {
		if f.Severity == "critical" || f.Severity == "high" {
			hasCritical = true
			break
		}
	}

	return AuditResult{
		OK:           !hasCritical && status != "rug_pull" && status != "injection_risk",
		Server:       server,
		Status:       status,
		ToolCount:    len(tools),
		SchemaSHA256: overall,
		Findings:     findings,
	}
}

// PinTrust saves or updates the trusted schema snapshot for server.
func PinTrust(server, command string, tools []ToolDef) (TrustRecord, error) {
	hashes := make(map[string]string, len(tools))
	for _, t := range tools {
		hashes[t.Name] = toolHash(t)
	}
	db := LoadTrust()
	now := time.Now().Unix()
	first := now
	if prev, ok := db.Servers[server]; ok && prev.FirstSeen > 0 {
		first = prev.FirstSeen
	}
	rec := TrustRecord{
		Server:       server,
		Command:      command,
		SchemaSHA256: catalogHash(hashes),
		ToolHashes:   hashes,
		ToolCount:    len(tools),
		FirstSeen:    first,
		LastVerified: now,
	}
	db.Servers[server] = rec
	if err := SaveTrust(db); err != nil {
		return rec, err
	}
	return rec, nil
}

// SummarizeDescription trims multi-line descriptions cleanly for compact listings.
func SummarizeDescription(s string, max int) string {
	line := strings.Join(strings.Fields(s), " ")
	if len(line) <= max {
		return line
	}
	return line[:max-3] + "..."
}
