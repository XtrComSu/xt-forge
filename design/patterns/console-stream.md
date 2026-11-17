---
id: console-stream
name: Streaming console / log timeline
purpose: Watch long-running work and find the one line that explains a failure.
when: The task emits ordered events over time and the user needs both the trend and a specific line.
not_when: There are under ~20 events (a static list) or the user only needs a summary.
stack: html+css, react
dependencies: none
license: MIT
provenance: authored for XT-Forge, 2026-11-03
states: [loading, empty, partial, error, permission, offline]
---

# Streaming console

Hierarchy: status strip (running / failed / done + elapsed) above the stream.
The stream is dense, monospaced, and never reflows on each event.

## Required behaviour
- Follow-tail that pauses the moment the user scrolls up, with a "jump to live" pill.
- Errors visually distinct and listed in a summary strip, not only inline.
- Timestamps relative by default, absolute on hover.
- Copy and export act on the visible selection.

## States
| state | what the user sees |
|---|---|
| loading | "connecting…" with a cancel action |
| empty | the command that produced nothing, plus its exit status |
| partial | "stream truncated; full log at <path>" — never a silent cut |
| error | the failing event pinned, exit status shown |
| permission | the stream is scoped; state what was withheld |
| offline | disconnected badge + automatic reconnect attempt count |
