# Integrations: plugins and MCP servers

Status: **survey + decisions, 2026-10-20** · installed in
`~/.config/opencode/opencode.json`

## The decision rule

An MCP server costs context **on every model step**, exactly like a skill:
each tool contributes a name and a schema. So the question is never "is this
good?" — it is "does this earn its schema?".

| cost | verdict |
|---|---|
| 1-3 tools, fills a real gap | install |
| 10-30 tools, strong capability | consider, or fold into xt-forge |
| 100+ tools | never — the schema costs more than it returns |

The same rule killed a security-skill library of 818 entries. It applies
double here, because tool schemas are longer than skill descriptions.

## Installed

| server | tools | why |
|---|---:|---|
| **xt-forge** | 50 | the toolkit: memory, taste, goal, repos, scan, codec, eval |
| **github** | 39 | repos, issues, PRs — the workflow's outer loop |
| **context7** | 2 | **up-to-date library docs**, remote HTTP, 63k★, MIT |

`context7` is the highest value-per-token integration available: two tools,
and it answers "how does this API work *now*" for any library. Training data
goes stale; this does not. It also removes a class of bug where the agent
writes against an API version that no longer exists.

```sh
opencode mcp add context7 --global --url https://mcp.context7.com/mcp
```

## Blocked on this host (but unblockable)

| server | needs | note |
|---|---|---|
| `microsoft/playwright-mcp` | Node (`npx`) | browser automation, 38k★ — the one thing Node would add |
| `bethington/ghidra-mcp` | Java + Ghidra | replaced by native `re` verbs |
| most npm-based servers | Node | this host has `uv`/Python only |

Node and Java are installable here (sudo + curl on Arch). What that buys:

- **playwright-mcp** — browser automation for recon and web testing. Cost:
  ~25 tool schemas every step. Worth it only if browser work is frequent.
- **ghidra-mcp** — see below; installing Java does not make 200 tools cheap.

## Rejected on budget

**`ghidra-mcp`** (5.8k★, Apache-2.0) is the best packaged RE tooling found —
200+ tools for Ghidra. It is also the single most context-destroying thing on
the list: 200 schemas is more than every other tool in this setup combined,
and the cost is paid on every step whether or not RE is the task.

The right integration is the capability, not the server. That is now built:
`xtforge re ioc|disasm|graph|pack|entropy|sections|symbols|strings|info|needed`.
What is still genuinely missing versus Ghidra is **decompilation**, and that
cannot be replicated cheaply — it is the one thing worth adding Java for, if
the need is frequent.

## Integrated into xt-forge instead of installed

| source | idea | where it lands |
|---|---|---|
| **context7** | live library docs | **`xtforge docs search/resolve/show`** — one verb, zero schemas |
| **ghidra-mcp** | reverse engineering | **`xtforge re ioc/disasm/graph`** — native, on top of binutils |
| **Shodan / GreyNoise / NVD / EPSS / CISA KEV / CIRCL** | threat intel | **`xtforge intel`** — six keyless sources, one verb |
| **HuggingFace Hub** | model & dataset discovery | **`xtforge hub`** — quants, sizes, base models |
| `inth3shadows/terse` | lossless MCP output compression | `compress` family (backlog B7) |
| `DeusData/codebase-memory-mcp` | code intelligence as a graph | `mem link` + `code parse` |
| memory servers generally | cross-session memory | `xtforge mem` — already the single store |

Two of those are now built rather than installed:

**`xtforge docs`** calls Context7's HTTP API directly (search + fetch). Two MCP
tools would cost two schemas on every model step; a verb costs nothing until
called. It is the same capability with a smaller footprint.

**`xtforge re ioc|disasm|graph`** is the Ghidra alternative. The binutils on
the box (objdump, nm, readelf, strings) already do the heavy lifting; this
turns their output into structured results behind three verbs:

```sh
xtforge re ioc <binary>       # IPs, domains, URLs, hashes, CVEs, paths, keys
xtforge re disasm <binary> --symbol main --count 40
xtforge re graph <binary>     # imports, exports, call sites, hot targets
```

On `/bin/ls` that yields 112 imports, 15 exports and 200 call sites with
resolved symbol names — the map you need before reading a binary. It is not a
decompiler, but it is native, instant, and free of 200 schemas.

An IOC report masks credentials (`admin:***@host`) and suppresses the
password-as-email artefact: a scanner must not become a secret store.

**`xtforge intel`** is the other half of `re ioc`: extract indicators, then
enrich them. Six sources, all keyless — no signup, no key, no schema:

| verb | source | answers |
|---|---|---|
| `intel ip <addr>` | Shodan InternetDB + GreyNoise | ports, hostnames, CVEs, scanning noise |
| `intel domain <name>` | native DNS + CIRCL/VT | records, mail posture (SPF/DMARC), spoofability |
| `intel cve <id>` | NVD + EPSS + CISA KEV | CVSS, exploit probability, known exploitation |
| `intel kev [--query]` | CISA KEV | what is being exploited right now |
| `intel search <kw> [--since N]` | NVD | recent CVEs by keyword |
| `intel hash <digest>` | CIRCL hashlookup | is this file known, and what is it |

`intel domain` speaks DNS itself (`xtforge/core/dns.py`): the box has no
`dig`, `host` or `nslookup`, and a dependency for six record types is a bad
trade. It uses EDNS0 and retries over TCP on truncation — without that, a
domain with several TXT records (github.com) comes back with none, which
looks exactly like "no SPF record". It reports mail posture instead of just
records: `SPF soft-fails (~all)`, `DMARC reject`.

Key-gated sources join automatically when the env var exists — no code
change: `XT_VT_KEY` adds VirusTotal to `intel ip` and `intel hash`,
`XT_ABUSECH_KEY` adds MalwareBazaar family attribution. Without keys the
verbs still work; `intel sources` shows which are live.

**`xtforge hub`** answers the operational questions for local models:
`models <q> --gguf` (what exists), `files <repo>` (how big is each quant),
`show <repo>` (base model, license, training data), `datasets <q>`.

Both are cached on disk (`$XT_HOME/cache/net`) and honour
`XT_NET_OFFLINE=1`, so tests never touch the network.

`terse` deserves a note: it shrinks MCP tool output before the model sees it,
**losslessly**, asserting a round-trip inverse. That is exactly the property
xt-forge's compress family promises ("never drop error lines"), and it is the
same problem — tool output is the largest recurring context cost. It is 2★,
so we do not install it; the design is worth absorbing.

## Watch list

| candidate | trigger to install |
|---|---|
| `playwright-mcp` | Node becomes available |
| `ghidra-mcp` | Java/Ghidra becomes available **and** we decide the tools earn their schema |
| Sentry / OTLP MCPs | an observability backend exists to talk to |
| filesystem MCP | never — `xtforge route` covers it without a network hop |

## Adding one

```sh
# remote HTTP (no runtime needed)
opencode mcp add <name> --global --url https://...

# local, if the runtime exists
opencode mcp add <name> --global npx -y <package>
opencode mcp list        # must show ✓ connected before you rely on it
```

Then check the tool count it adds (`opencode mcp list` shows the server; the
tool schemas arrive in the model's context). If it adds more than a handful,
ask what to remove instead.

## Rules

- no server without a named caller: if nothing in the workflow needs it, it
  is noise with a schema
- tool count is a budget; adding 20 tools means justifying 20 schemas
- prefer folding a capability into xt-forge when the server brings a runtime
  dependency or a hundred tools
- a server that is `pending` is not installed; make it `connected` first
