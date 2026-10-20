# xt-native — the OpenCode taste plugin

Source for the OpenCode plugin that carries xt-forge's taste, goal and loop
mechanics into a session.

This directory is the **canon**. `xtforge plugin install` copies it into
`~/.config/opencode/plugins/xt-native/`, stamps the paths the plugin needs
(`installed.json`) and registers it in the OpenCode config.
`xtforge plugin status` reports whether the installed copy still matches this
source; the test suite fails when it does not.

## What it is

| Surface | Behaviour |
|---|---|
| `/taste` | `show`, `review`, `stats`, `learn <statement>`, `why <id>`, `forget <id>`, `on`, `off` |
| `/goal` | `record`, `status`, `check <cmd>`, `done <marker>`, `stop` — `done` verifies a `<goal-done>` claim independently against the approved check |
| `/loop`, `/loops`, `/loop-stop` | fixed and self-paced scheduling, restart-safe, cancellable |
| prompt hook | explicit preferences in a prompt become taste signals |
| context hook | enforced taste rules ride along as a system block; a completion claim is verified in the same request |

## One prompt, one signal

OpenCode loads this plugin once per location, so the prompt hook is
registered more than once and fires more than once for the same prompt.
Each firing used to ingest the prompt again, and each copy counted as
another piece of evidence: a rule the user stated **once** reached
`enforced` and was injected into every session, with an evidence log that
showed the same quote over and over.

The prompt carries an id that is unique per admitted prompt, so that id is
the deduplication key. The same id is ingested once; a different id is a
different prompt and is ingested again. The set lives at module level
because every load of the plugin shares one module instance.

If a profile was already inflated this way, `xtforge taste repair` collapses
the duplicated evidence and recomputes the counters.

## What it never does

- no model call — the learner is arithmetic inside xt-forge
- no session breakage — every xt-forge call is time-boxed and degrades to a
  no-op when the CLI is missing
- no permission widening, no file reads, no writes outside the taste store

## Why the block is rendered by xt-forge

The `<taste>` block is produced by `xtforge taste inject`, not by this file.
One format, one implementation: the CLI, the MCP server and the plugin can
never disagree about what the model sees. The same applies to the
`<goal-done>` verdict (`xtforge goal verify`).

The plugin is **one file** on purpose: a plugin that imports its own modules
can be reloaded against a stale copy of one of them, which is exactly how this
plugin once failed to load.

## Install

```sh
xtforge plugin install     # copy the source, stamp it, register it
xtforge plugin status      # installed? registered? still current?
xtforge plugin uninstall   # unregister (add --purge to delete the files)
```

`xtforge sync` installs it too, alongside the launcher, the command
templates and the harness wiring.

Registration in `opencode.json`:

```json
{ "plugins": ["/home/you/.config/opencode/plugins/xt-native"] }
```

## Test it

```sh
node --test plugins/xt-native/test/            # the plugin alone
python3 -m unittest discover -s tests -v        # the whole suite
```

Two suites cover this plugin:

- `test/plugin.test.mjs` drives the plugin with a mock OpenCode context:
  commands, hooks, the injected block, loop scheduling, and a fabricated
  completion claim.
- `test/taste.sessions.test.mjs` is the D2 acceptance — **ten scripted
  sessions** through this exact file against the **real** xt-forge CLI: the
  expected learnings appear, no key is invented, and only enforced rules
  reach the block.
