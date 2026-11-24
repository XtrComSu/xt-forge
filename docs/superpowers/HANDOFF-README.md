# xt-forge README handoff

The [README](../../README.md) on [xt-forge-dev](https://github.com/XtrComSu/xt-forge-dev#readme) was last updated in commit `5535b56`. Use the [original xt-forge README](https://github.com/XtrComSu/xt-forge#readme) and its terminal GIFs as the visual reference.

## Copy and visual style

- Lead with what xt-forge does and how to run it. Use headings that name the subject, such as “Binary inspection” or “Dependency and advisory checks.” Keep writing instructions, work-in-progress notes, and repository access details out of reader-facing copy.
- Keep the original XT logo, dark terminal pane, thin red accent, numbered tabs, red prompt, and XT-OSS footer. Match the original four-card banner layout and use current, supportable facts in the cards.
- Make figures in code. Capture real CLI output from a reproducible fixture, retain the transcript, and use it to drive the visual. Keep illustration, animation, and benchmark data distinct.
- Keep capability claims tied to the engine and format actually exercised. Retain the distinction between the 0.4.7 ELF/PE checks and the 0.4.6 agent benchmark. Use the [changelog](../../CHANGELOG.md) to check what was available in each version.

## Figures in use

| File | What it shows |
| --- | --- |
| [features.svg](../assets/release-review/features.svg) | The four feature cards at the top of the README |
| [navigator.svg](../assets/release-review/navigator.svg) | The 4-column visual Workflow Navigator directing users across tasks |
| [binary-walkthrough.gif](../assets/release-review/binary-walkthrough.gif) | ELF identification, disassembly of `main`, and the call site for `increment` |
| [dependency-walkthrough.gif](../assets/release-review/dependency-walkthrough.gif) | Manifest reading, resolved package identity, and OSV advisory remediation |
| [source-walkthrough.gif](../assets/release-review/source-walkthrough.gif) | Budgeted context search, AST callers hierarchy, and execution dispatch tracing |
| [mcp-walkthrough.gif](../assets/release-review/mcp-walkthrough.gif) | Stdio MCP initialization, on-demand tool discovery, and agentic invocation |
| [disassembly.svg](../assets/release-review/disassembly.svg), [dependencies.svg](../assets/release-review/dependencies.svg), [source-navigation.svg](../assets/release-review/source-navigation.svg), [mcp-gateway.svg](../assets/release-review/mcp-gateway.svg) | Static versions for readers who prefer stills |
| [workflow.svg](../assets/release-review/workflow.svg) | How inputs reach CLI, MCP, and saved evidence |
| [bench_9tier_charts.png](../bench_9tier_charts.png) | Historical 0.4.6 agent evaluation, under a collapsible heading |

## Updating an example

1. Run `python3 scripts/capture_readme_demo.py` from the repository root with a C compiler and the Go hub available. The [capture script](../../scripts/capture_readme_demo.py) compiles a small ELF and writes the example manifest, then records five files under `docs/assets/release-review/`. Skip recapture for layout-only edits.
2. Run `python3 scripts/render_readme_diagrams.py` with Pillow installed. The [renderer](../../scripts/render_readme_diagrams.py) reads the captured output and creates the SVGs and GIFs. It uses the committed logo and selects local fonts through `fc-match` when available.
3. Review the GIFs through a full loop and inspect the summary frame in each tab. Compare names, addresses, counts, and versions with the linked transcripts. Check the banner at narrow width, static figures, alt text, and relative links. Run `git diff --check` and inspect the rendered README on the branch that contains the assets.

The last review checked both GIFs and the banner locally and confirmed that GitHub held the same file hashes on `main`. A later change should repeat that check for the files it touches.
