# xt-forge for OpenCode

![OpenCode Plugin Preview](opencode-setup.gif)

Watch the full walkthrough: [opencode-setup.mp4](opencode-setup.mp4)

OpenCode gets native slash commands (`/taste`, `/goal`, `/loop`) via the single-file [`plugins/xt-native`](../../plugins/xt-native/) plugin alongside the 4-tool `--meta` MCP server.

## Quick Setup

1. Install and register the OpenCode plugin (copies into `~/.config/opencode/plugins/xt-native` and records drift state):

```sh
./bin/xtforge plugin install
./bin/xtforge plugin status
```

2. Merge [`opencode.json`](opencode.json) into `~/.config/opencode/opencode.json` (update `/path/to/xt-forge` to your checkout path).

3. Use the slash commands directly inside OpenCode:

- `/taste show | learn <rule> | why <id> | review`: deterministic preference memory (no LLM tokens used)
- `/goal record | status | check <cmd> | done`: rejects unverified `<goal-done>` claims
- `/loop | /loops | /loop-stop`: restart-safe bounded background schedules

## Included Files

- [`opencode.json`](opencode.json): OpenCode plugin + `--meta` MCP server configuration
- [`opencode-setup.mp4`](opencode-setup.mp4) and [`opencode-setup.gif`](opencode-setup.gif): setup and hook walkthrough
- Source plugin: [`plugins/xt-native/`](../../plugins/xt-native/)
