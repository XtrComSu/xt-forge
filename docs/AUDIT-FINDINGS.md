# Recon report: XT-Bridge-DemonEdition

- findings: 5
- notes: 0
- severity: critical 2, high 2, medium 1

## Findings

### [critical] Both agents silently ignored a mistyped/unparsed --pin and ran in plaintext

BOTH agents silently accepted a trust anchor that was never applied. agent-go/cmd/xt-agent/main.go: the stdlib flag package stops at the first non-flag token, so `xt-agent 127.0.0.1 9099 --pin <hash>` left --pin unparsed in fs.Args() and the call proceeded in PLAINTEXT. Proven before the fix: $ xt-agent-go 127.0.0.1 9999 --pin DEADBEEF --once [!] WARNING: plaintext transport — node key and commands are unencrypted. agent-rs/src/main.rs: the `_ =>` arm pushed any unknown token into the positional list, so a typo became the host: $ xt-agent 127.0.0.1 9999 --pinn ABCD --once [*] XT-Agent 1.0-rust -> http://127.0.0.1:9999 [!] WARNING: plaintext transport In both cases the operator believed the channel was pinned. Fixed: - go: trailing tokens after the positionals are re-parsed through the same FlagSet; a third positional is a usage error - rust: any token starting with '-' that is not a known flag exits 2 with the valid flag list; a flag missing its value exits 2 Regression tests added on both sides (3 Go, 4 Rust).

    evidence: agent-go/cmd/xt-agent/main.go; agent-rs/src/main.rs; before/after probes

### [critical] CLI --pin disabled all TLS verification and the pin was never compared

cli/api.ts buildTLS returned rejectUnauthorized: !insecure && (pin ? false : !!pem) so passing --pin turned certificate verification OFF, and the pin itself was stored as dead data (`_pin`) that nothing ever compared. Proven before the fix: with a deliberately wrong pin (sha256:000...0) against the live TLS host the CLI still received HTTP 200. Fixed by making a pin a TRUST ANCHOR: - resolveTLS() opens a node:tls connection, reads the peer DER certificate, computes sha256, compares against the pin with a constant-time compare, and only then promotes that certificate to `ca` with rejectUnauthorized:true - buildTLS throws on a malformed pin instead of degrading to "no pin" - --insecure remains the only way to disable verification, and it no longer pretends to honour a pin Measured after the fix: - correct pin -> reaches the host (HTTP layer answers) - wrong pin -> "TLS pin mismatch — expected sha256:000..., peer presented sha256:f999..." exit 1 8 regression tests in cli/tls.test.ts lock the contract.

    evidence: cli/api.ts buildTLS/resolveTLS; wrong-pin returned 200 before, mismatch after

### [high] VT: Microsoft Wacatac!ml fires on any Go binary importing os/exec

Microsoft `Trojan:Script/Wacatac.*!ml` fires on the Go agent and on every Go binary that imports `os/exec`. Isolated by ablation against the live VT API: abl-a net/http only 62/62 0 detections abl-b http + exec("/bin/sh",-c) 63/64 1 Wacatac.C!ml abl-c http + exec(shell, no literal) 58/59 1 Wacatac.B!ml abl-d http + exec("id") no shell 63/64 1 Wacatac.C!ml The Rust agent (same fleet capability, different stdlib) is 64/64 clean, so the capability is not the trigger: the `os/exec` import surface in a Go binary is. abl-c proves the literal "/bin/sh" is not required (the tag only changes letter, B vs C). Consequence: `!ml` is an opaque Microsoft-internal model score with no published contract. It cannot be "optimised away" from this side without removing process execution, which is the product. The honest remedies are: - ship signed (Authenticode) — reputation, per docs/AV-HARDENING.md §1 - file the false positive with Microsoft using the signed build - keep the Rust agent as the 0-detection option Removing os/exec from the Go agent to chase the score would delete the `system_shell_spawn` capability that is in the shipped destructive set.

    evidence: VT API ablation: abl-a 62/62 clean, abl-b 63/64, abl-c 58/59, abl-d 63/64; rust agent 64/64 clean (sha256 5ab76d597f6f5b94a84bb6093f20f21f1697b125e29dd3c59346f2ff1b983931)

### [high] host-go: zero-value http.Server left the listener open to slowloris

cmd/xt-host/main.go used http.ListenAndServe / ListenAndServeTLS with the zero-value server, which sets ReadHeaderTimeout, ReadTimeout, WriteTimeout and IdleTimeout to "no limit". Any client could hold goroutines and connection slots by dribbling a request (slowloris). Fixed with an explicit http.Server{ReadHeaderTimeout:15s, ReadTimeout:60s, WriteTimeout:120s, IdleTimeout:120s, MaxHeaderBytes:1MB}. Measured: 5 connections sending headers without the terminating blank line were closed by the server at t=15.0s (ReadHeaderTimeout), while concurrent normal requests still returned 200 in 0.01s.

    evidence: cmd/xt-host/main.go; 5 stalled conns closed at t=15.0s after fix

### [medium] host-go: requireNodeKey read the whole body unbounded and discarded the error

`requireNodeKey` (host-go/internal/api/api.go) peeks the request body to read `node_id`, then restores it for the handler. It did so with b, _ := io.ReadAll(r.Body) // no LimitReader, error discarded Two defects in one line: 1. unbounded buffer — nothing capped the read below the route's MaxBytesReader 2. the discarded error means an over-limit body silently became a TRUNCATED body; the handler then saw well-formed but incomplete JSON Fixed with io.LimitReader(r.Body, maxNodeBodyPeek) and an explicit 400 on a read error. Measured after the fix: 900 KB node result reaches auth (401), 2 MB is refused with 400.

    evidence: internal/api/api.go requireNodeKey; live probe 900KB->401, 2MB->400
