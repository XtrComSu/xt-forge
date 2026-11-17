// Package guard implements xt-forge's read-only-by-default path safety,
// 3-tier session permission modes (explore, ask, auto), confirm tokens,
// and append-only JSONL audit logging.
package guard

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// PermMode controls session write/exec behavior (inspired by Craft Agents / Assay).
type PermMode string

const (
	ModeExplore PermMode = "explore"
	ModeAsk     PermMode = "ask"
	ModeAuto    PermMode = "auto"
)

var DenyGlobs = []string{
	"*/.ssh/*", "*/.gnupg/*", "*.key", "*.pem", "*.pfx", "*.p12",
	"*/.env", "*/.env.*", "*/.aws/credentials", "*/.netrc", "*.keystore",
	"*/id_rsa*", "*/shadow", "*/.git-credentials",
}

var defaultRoots = []string{
	"$HOME", "$HOME/storage/shared", "$HOME/sample-app",
	"/tmp", "/var/tmp",
	"/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/lib", "/usr/lib64",
	"/lib", "/lib64", "/opt",
	"${PREFIX}/bin", "${PREFIX}/sbin", "${PREFIX}/lib", "${PREFIX}/share",
}

var forbiddenCommands = []struct {
	re     *regexp.Regexp
	reason string
}{
	{regexp.MustCompile(`(?i)\brm\s+(-[a-zA-Z]*\s+)*-[a-zA-Z]*r`), "recursive delete"},
	{regexp.MustCompile(`(?i)\brm\s+-[a-zA-Z]*f\b\s+[/~]`), "forced root or home wipe"},
	{regexp.MustCompile(`(?i)\bsudo\b|\bsu\b`), "privilege escalation"},
	{regexp.MustCompile(`(?i)\bcurl\b[^|]*\|\s*(ba)?sh`), "remote code execution"},
	{regexp.MustCompile(`(?i)\bwget\b[^|]*\|\s*(ba)?sh`), "remote code execution"},
	{regexp.MustCompile(`>\s*/(etc|usr|bin|sbin|system|boot)/`), "write to system path"},
	{regexp.MustCompile(`(?i)\bchmod\s+(?:-R\s+)?777\b`), "world-writable permissions"},
	{regexp.MustCompile(`(?i)\bdd\s+.*of=/dev/`), "raw device write"},
	{regexp.MustCompile(`(?i)\bmkfs\b|\bfdisk\b`), "filesystem destruction"},
	{regexp.MustCompile(`(?i)\bshred\b`), "destructive file shredding"},
	{regexp.MustCompile(`>\s*/dev/(?:sda|nvme|hda|vda)`), "raw disk write redirection"},
	{regexp.MustCompile(`(?i)\b(?:base64\s+-d|xxd\s+-r)[^|]*\|\s*(?:ba)?sh`), "encoded payload pipe to shell"},
}

// DeniedError represents a guard policy rejection.
type DeniedError struct {
	Code   string `json:"code"`
	Reason string `json:"reason"`
}

func (e *DeniedError) Error() string {
	return fmt.Sprintf("%s: %s", e.Code, e.Reason)
}

type tokenRec struct {
	Action  string `json:"action"`
	Path    string `json:"path"`
	Scope   string `json:"scope"`
	Expires int64  `json:"expires"`
}

var (
	tokenMu sync.Mutex
	tokens  = map[string]tokenRec{}
)

// CurrentMode returns the active session permission mode from XT_PERM_MODE.
// Defaults to "ask" so read-only operations work seamlessly while mutations
// require explicit opt-in or confirm tokens.
func CurrentMode() PermMode {
	raw := strings.ToLower(strings.TrimSpace(os.Getenv("XT_PERM_MODE")))
	switch PermMode(raw) {
	case ModeExplore, ModeAsk, ModeAuto:
		return PermMode(raw)
	default:
		return ModeAsk
	}
}

// Home returns the current home directory.
func Home() string {
	if h, err := os.UserHomeDir(); err == nil && h != "" {
		return h
	}
	if h := os.Getenv("HOME"); h != "" {
		return h
	}
	return "/tmp"
}

// UserHome discovers the true user home when running under .dsh/agy-accounts/*.
func UserHome() string {
	h := Home()
	cur := h
	for {
		parent := filepath.Dir(cur)
		if parent == cur {
			break
		}
		if filepath.Base(cur) == ".dsh" {
			return parent
		}
		cur = parent
	}
	return h
}

// XTHome returns the xt-forge runtime state directory.
func XTHome() string {
	if v := strings.TrimSpace(os.Getenv("XT_HOME")); v != "" {
		return v
	}
	return filepath.Join(Home(), ".xt-forge")
}

func expandVars(p string) string {
	if p == "~" {
		return Home()
	}
	if strings.HasPrefix(p, "~/") {
		p = filepath.Join(Home(), p[2:])
	}
	return os.Expand(p, func(key string) string {
		if v, ok := os.LookupEnv(key); ok {
			return v
		}
		return "$" + key
	})
}

// Roots returns allowlisted root directories.
func Roots() []string {
	var raw []string
	if env := strings.TrimSpace(os.Getenv("XT_ROOTS")); env != "" {
		raw = strings.Split(env, ",")
	} else {
		raw = append(raw, defaultRoots...)
	}
	var out []string
	seen := map[string]bool{}
	add := func(p string) {
		if p == "" || seen[p] {
			return
		}
		seen[p] = true
		out = append(out, p)
	}
	if uh := UserHome(); uh != Home() {
		add(uh)
	}
	for _, entry := range raw {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		exp := expandVars(entry)
		if strings.Contains(exp, "$") || exp == "/" || exp == "" || exp == "." {
			continue
		}
		if real, err := filepath.EvalSymlinks(exp); err == nil {
			exp = real
		}
		add(exp)
	}
	return out
}

// Canonical resolves symlinks and .. as far as the path exists on disk.
func Canonical(p string) string {
	exp := expandVars(p)
	abs, err := filepath.Abs(exp)
	if err == nil {
		exp = abs
	}
	if real, err := filepath.EvalSymlinks(exp); err == nil {
		return real
	}
	var tail []string
	cur := exp
	for {
		if real, err := filepath.EvalSymlinks(cur); err == nil {
			parts := append([]string{real}, tail...)
			return filepath.Join(parts...)
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return exp
		}
		tail = append([]string{filepath.Base(cur)}, tail...)
		cur = parent
	}
}

// IsDeniedName checks whether path or its basename matches any DenyGlobs entry.
func IsDeniedName(p string) string {
	slashPath := filepath.ToSlash(p)
	base := path.Base(slashPath)
	for _, g := range DenyGlobs {
		if matched, _ := path.Match(g, slashPath); matched {
			return g
		}
		if matched, _ := path.Match(g, base); matched {
			return g
		}
		// Handle leading */ prefix against full path suffixes.
		if strings.HasPrefix(g, "*/") {
			sub := g[1:]
			if strings.Contains(slashPath, strings.TrimSuffix(sub, "*")) && matchStar(g, slashPath) {
				return g
			}
		}
	}
	return ""
}

func matchStar(pattern, text string) bool {
	// Simple wildcard matcher matching fnmatch semantics without path boundary restrictions.
	pi, ti := 0, 0
	starIdx, matchIdx := -1, 0
	for ti < len(text) {
		if pi < len(pattern) && (pattern[pi] == '?' || pattern[pi] == text[ti]) {
			pi++
			ti++
		} else if pi < len(pattern) && pattern[pi] == '*' {
			starIdx = pi
			matchIdx = ti
			pi++
		} else if starIdx != -1 {
			pi = starIdx + 1
			matchIdx++
			ti = matchIdx
		} else {
			return false
		}
	}
	for pi < len(pattern) && pattern[pi] == '*' {
		pi++
	}
	return pi == len(pattern)
}

func isWithinRoot(canon, root string) bool {
	rel, err := filepath.Rel(root, canon)
	if err != nil {
		return false
	}
	return rel == "." || (!strings.HasPrefix(rel, ".."+string(filepath.Separator)) && rel != "..")
}

// CheckAllowed validates path against allowlisted roots and DENY_GLOBS.
func CheckAllowed(p string, write bool) (string, error) {
	canon := Canonical(p)
	allowed := false
	for _, root := range Roots() {
		if isWithinRoot(canon, root) {
			allowed = true
			break
		}
	}
	if !allowed {
		return "", &DeniedError{Code: "root_denied", Reason: fmt.Sprintf("path outside allowlisted roots: %s", canon)}
	}
	if g := IsDeniedName(canon); g != "" {
		if write {
			return "", &DeniedError{Code: "deny_listed", Reason: fmt.Sprintf("writing to deny-listed path (%s) is refused", g)}
		}
		return "", &DeniedError{Code: "deny_listed", Reason: fmt.Sprintf("deny-listed path (%s): contents never exposed", g)}
	}
	return canon, nil
}

// ReadGuard enforces read-only allowlist + deny rules.
func ReadGuard(p string) (string, error) {
	return CheckAllowed(p, false)
}

// IssueToken creates a short-lived single-use confirm token for path.
func IssueToken(action, p, scope string) (map[string]any, error) {
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		return nil, err
	}
	tok := hex.EncodeToString(b[:])
	canon := Canonical(p)
	tokenMu.Lock()
	tokens[tok] = tokenRec{
		Action:  action,
		Path:    canon,
		Scope:   scope,
		Expires: time.Now().Unix() + 300,
	}
	tokenMu.Unlock()
	return map[string]any{
		"confirm_token": tok,
		"action":        action,
		"path":          canon,
		"expires_in":    300,
		"note":          fmt.Sprintf("re-run with --confirm %s to execute %s", tok, action),
	}, nil
}

// WriteGuard enforces permission mode + confirm token validation for mutations.
func WriteGuard(p string, write bool, confirmToken string, dryRun bool) (map[string]any, error) {
	canon, err := CheckAllowed(p, write)
	if err != nil {
		return nil, err
	}
	if !write {
		return map[string]any{"path": canon, "write": false}, nil
	}
	mode := CurrentMode()
	if mode == ModeExplore {
		return nil, &DeniedError{Code: "explore_mode", Reason: "XT_PERM_MODE=explore forbids write/exec actions"}
	}
	if dryRun {
		return map[string]any{"path": canon, "write": true, "dry_run": true, "mode": string(mode)}, nil
	}
	if confirmToken != "" {
		tokenMu.Lock()
		rec, ok := tokens[confirmToken]
		if !ok || rec.Expires < time.Now().Unix() {
			tokenMu.Unlock()
			return nil, &DeniedError{Code: "token_invalid", Reason: "confirm_token missing, expired, or already used"}
		}
		if rec.Path != canon {
			tokenMu.Unlock()
			return nil, &DeniedError{Code: "token_mismatch", Reason: "confirm_token does not match this path"}
		}
		delete(tokens, confirmToken)
		tokenMu.Unlock()
		return map[string]any{"path": canon, "write": true, "dry_run": false, "confirmed": true, "mode": string(mode)}, nil
	}
	if mode == ModeAuto {
		return map[string]any{"path": canon, "write": true, "dry_run": false, "auto": true, "mode": string(mode)}, nil
	}
	return map[string]any{"path": canon, "write": true, "dry_run": true, "mode": string(mode)}, nil
}

// CheckCommand validates a shell command against forbidden patterns.
func CheckCommand(cmd string) string {
	for _, rule := range forbiddenCommands {
		if rule.re.MatchString(cmd) {
			return rule.reason
		}
	}
	return ""
}

// AuditEvent writes a replayable JSONL audit record to ~/.xt-forge/audit/.
func AuditEvent(session, actor, tool, verdict string, args any, exitCode int) {
	if session == "" {
		session = "default"
	}
	auditDir := filepath.Join(XTHome(), "audit")
	if err := os.MkdirAll(auditDir, 0o755); err != nil {
		return
	}
	safeSession := regexp.MustCompile(`[^a-zA-Z0-9_.-]`).ReplaceAllString(session, "_")
	rec := map[string]any{
		"ts":        time.Now().UTC().Format(time.RFC3339Nano),
		"session":   session,
		"mode":      string(CurrentMode()),
		"actor":     actor,
		"tool":      tool,
		"verdict":   verdict,
		"exit_code": exitCode,
		"args":      args,
	}
	b, err := json.Marshal(rec)
	if err != nil {
		return
	}
	f, err := os.OpenFile(filepath.Join(auditDir, safeSession+".jsonl"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = f.Write(append(b, '\n'))
}

// IsDeniedError checks if err is a *DeniedError.
func IsDeniedError(err error) (*DeniedError, bool) {
	var de *DeniedError
	if errors.As(err, &de) {
		return de, true
	}
	return nil, false
}
