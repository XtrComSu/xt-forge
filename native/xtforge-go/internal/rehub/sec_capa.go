package rehub

import (
	"bytes"
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"os"
	"strings"

	"xtforge-hub/internal/guard"
)

type capaRule struct {
	Name        string
	Category    string
	Severity    string
	Description string
	Imports     []string
	Strings     []string
}

var capabilityRules = []capaRule{
	{
		Name:        "anti_debugging",
		Category:    "evasion",
		Severity:    "HIGH",
		Description: "Checks for debugger presence or interacts with debug subsystems",
		Imports:     []string{"IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess", "ZwQueryInformationProcess", "OutputDebugStringA", "OutputDebugStringW", "DbgBreakPoint", "DbgUserBreakPoint", "ptrace"},
		Strings:     []string{"beingdebugged", "debuggerdetected"},
	},
	{
		Name:        "process_injection",
		Category:    "execution",
		Severity:    "CRITICAL",
		Description: "Allocates memory or creates execution threads in remote processes",
		Imports:     []string{"VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "CreateRemoteThreadEx", "NtMapViewOfSection", "ZwMapViewOfSection", "QueueUserAPC", "SetThreadContext", "process_vm_writev"},
	},
	{
		Name:        "privilege_manipulation",
		Category:    "privilege_escalation",
		Severity:    "HIGH",
		Description: "Inspects or adjusts process token privileges or user IDs",
		Imports:     []string{"OpenProcessToken", "AdjustTokenPrivileges", "LookupPrivilegeValueA", "LookupPrivilegeValueW", "DuplicateTokenEx", "setuid", "setgid", "cap_set_proc"},
		Strings:     []string{"sedebugprivilege", "setcbprivilege"},
	},
	{
		Name:        "memory_evasion",
		Category:    "defense_evasion",
		Severity:    "MEDIUM",
		Description: "Changes page protection (RWX) or suppresses OS error dialogs",
		Imports:     []string{"VirtualProtect", "VirtualProtectEx", "NtProtectVirtualMemory", "ZwProtectVirtualMemory", "SetErrorMode", "mprotect"},
	},
	{
		Name:        "network_communications",
		Category:    "network",
		Severity:    "MEDIUM",
		Description: "Establishes raw sockets or HTTP client connections",
		Imports:     []string{"WSAStartup", "connect", "send", "recv", "InternetOpenA", "InternetOpenW", "HttpSendRequestA", "WinHttpOpen", "URLDownloadToFileA", "getaddrinfo"},
	},
	{
		Name:        "crypto_operations",
		Category:    "cryptography",
		Severity:    "LOW",
		Description: "Invokes native cryptographic primitives or entropy sources",
		Imports:     []string{"CryptEncrypt", "CryptDecrypt", "BCryptEncrypt", "BCryptDecrypt", "CryptGenRandom", "EVP_EncryptInit", "EVP_DecryptInit", "RAND_bytes"},
	},
}

// Checksec inspects binary security hardening mitigations natively using Go stdlib parsers.
func Checksec(filePath string) map[string]any {
	canon, err := guard.ReadGuard(filePath)
	if err != nil {
		return map[string]any{"ok": false, "error": err.Error()}
	}
	raw, err := os.ReadFile(canon)
	if err != nil {
		return map[string]any{"ok": false, "error": err.Error(), "path": canon}
	}

	if len(raw) >= 4 && bytes.Equal(raw[:4], []byte{0x7f, 'E', 'L', 'F'}) {
		f, err := elf.NewFile(bytes.NewReader(raw))
		if err != nil {
			return map[string]any{"ok": false, "error": err.Error(), "path": canon}
		}
		hasRelro := false
		nx := true
		for _, p := range f.Progs {
			if uint32(p.Type) == 0x6474e552 { // PT_GNU_RELRO
				hasRelro = true
			}
			if uint32(p.Type) == 0x6474e551 && (uint32(p.Flags)&1) != 0 { // PT_GNU_STACK + PF_X
				nx = false
			}
		}
		relro := "No"
		if hasRelro {
			relro = "Partial"
			if dynSyms, err := f.DynamicSymbols(); err == nil {
				_ = dynSyms
			}
			if vals, err := f.DynValue(elf.DT_BIND_NOW); err == nil && len(vals) > 0 {
				relro = "Full"
			}
		}
		canary := false
		checkSyms := func(syms []elf.Symbol) {
			for _, s := range syms {
				if strings.Contains(s.Name, "stack_chk") || strings.Contains(s.Name, "security_cookie") {
					canary = true
					break
				}
			}
		}
		if syms, err := f.DynamicSymbols(); err == nil {
			checkSyms(syms)
		}
		if !canary {
			if syms, err := f.Symbols(); err == nil {
				checkSyms(syms)
			}
		}
		rpaths, _ := f.DynString(elf.DT_RPATH)
		runpaths, _ := f.DynString(elf.DT_RUNPATH)
		return map[string]any{
			"ok":     true,
			"path":   canon,
			"format": "elf",
			"engine": "go",
			"mitigations": map[string]any{
				"relro":   relro,
				"canary":  canary,
				"nx":      nx,
				"pie":     f.Type == elf.ET_DYN,
				"rpath":   len(rpaths) > 0,
				"runpath": len(runpaths) > 0,
			},
		}
	}

	if len(raw) >= 2 && raw[0] == 'M' && raw[1] == 'Z' {
		f, err := pe.NewFile(bytes.NewReader(raw))
		if err != nil {
			return map[string]any{"ok": false, "error": err.Error(), "path": canon}
		}
		var chars uint16
		var is64, hasCert bool
		switch hdr := f.OptionalHeader.(type) {
		case *pe.OptionalHeader32:
			chars = hdr.DllCharacteristics
			if len(hdr.DataDirectory) > 4 {
				hasCert = hdr.DataDirectory[4].Size > 0
			}
		case *pe.OptionalHeader64:
			chars = hdr.DllCharacteristics
			is64 = true
			if len(hdr.DataDirectory) > 4 {
				hasCert = hdr.DataDirectory[4].Size > 0
			}
		}
		return map[string]any{
			"ok":     true,
			"path":   canon,
			"format": "pe",
			"engine": "go",
			"mitigations": map[string]any{
				"aslr":            (chars & 0x0040) != 0,
				"high_entropy_va": is64 && (chars&0x0020) != 0,
				"dep_nx":          (chars & 0x0100) != 0,
				"cfg":             (chars & 0x4000) != 0,
				"force_integrity": (chars & 0x0080) != 0,
				"no_seh":          (chars & 0x0400) != 0,
				"authenticode":    hasCert,
			},
		}
	}

	if mf, err := macho.NewFile(bytes.NewReader(raw)); err == nil {
		return map[string]any{
			"ok":     true,
			"path":   canon,
			"format": "macho",
			"engine": "go",
			"mitigations": map[string]any{
				"pie": (mf.Flags & macho.FlagPIE) != 0,
				"nx":  (mf.Flags & macho.FlagNoHeapExecution) != 0,
			},
		}
	}

	return map[string]any{"ok": false, "err": "unrecognized binary format", "path": canon}
}

// Capa performs static behavioral capability detection across ELF, PE, and Mach-O imports and byte signatures.
func Capa(filePath string) map[string]any {
	canon, err := guard.ReadGuard(filePath)
	if err != nil {
		return map[string]any{"ok": false, "err": err.Error()}
	}
	raw, err := os.ReadFile(canon)
	if err != nil {
		return map[string]any{"ok": false, "err": err.Error(), "path": canon}
	}

	fmtName := "raw"
	impSet := map[string]bool{}
	if len(raw) >= 4 && bytes.Equal(raw[:4], []byte{0x7f, 'E', 'L', 'F'}) {
		fmtName = "elf"
		if f, err := elf.NewFile(bytes.NewReader(raw)); err == nil {
			if syms, err := f.DynamicSymbols(); err == nil {
				for _, s := range syms {
					impSet[s.Name] = true
				}
			}
			if syms, err := f.Symbols(); err == nil {
				for _, s := range syms {
					impSet[s.Name] = true
				}
			}
		}
	} else if len(raw) >= 2 && raw[0] == 'M' && raw[1] == 'Z' {
		fmtName = "pe"
		if f, err := pe.NewFile(bytes.NewReader(raw)); err == nil {
			if imps, err := f.ImportedSymbols(); err == nil {
				for _, entry := range imps {
					fn := strings.SplitN(entry, ":", 2)[0]
					impSet[fn] = true
				}
			}
		}
	} else if mf, err := macho.NewFile(bytes.NewReader(raw)); err == nil {
		fmtName = "macho"
		if mf.Symtab != nil {
			for _, s := range mf.Symtab.Syms {
				impSet[strings.TrimPrefix(s.Name, "_")] = true
			}
		}
	}

	detected := make([]map[string]any, 0)
	for _, rule := range capabilityRules {
		matches := make([]map[string]string, 0)
		for _, imp := range rule.Imports {
			if impSet[imp] {
				matches = append(matches, map[string]string{"type": "import", "indicator": imp})
			}
		}
		for _, s := range rule.Strings {
			if containsASCIIFold(raw, s) {
				matches = append(matches, map[string]string{"type": "string", "indicator": s})
			}
		}
		if len(matches) > 0 {
			detected = append(detected, map[string]any{
				"name":        rule.Name,
				"category":    rule.Category,
				"severity":    rule.Severity,
				"description": rule.Description,
				"matches":     matches,
				"count":       len(matches),
			})
		}
	}

	return map[string]any{
		"ok":           true,
		"path":         canon,
		"format":       fmtName,
		"capabilities": detected,
		"count":        len(detected),
		"engine":       "go",
	}
}

func containsASCIIFold(haystack []byte, lowerNeedle string) bool {
	if len(lowerNeedle) == 0 || len(haystack) < len(lowerNeedle) {
		return false
	}
	// Fast pivot scan on first lowercase/uppercase byte using bytes.IndexByte or direct loop.
	firstLo := lowerNeedle[0]
	firstHi := firstLo
	if firstLo >= 'a' && firstLo <= 'z' {
		firstHi = firstLo - 32
	}
	limit := len(haystack) - len(lowerNeedle)
	for i := 0; i <= limit; i++ {
		b := haystack[i]
		if b != firstLo && b != firstHi {
			continue
		}
		matched := true
		for j := 1; j < len(lowerNeedle); j++ {
			c := haystack[i+j]
			if c >= 'A' && c <= 'Z' {
				c += 32
			}
			if c != lowerNeedle[j] {
				matched = false
				break
			}
		}
		if matched {
			return true
		}
	}
	return false
}
