---
id: editor
name: Split editor with live preview
purpose: Edit structured or rendered content while seeing the result.
when: The user writes source that renders (markdown, templates, config).
not_when: The output is not visually meaningful, or editing is single-field.
stack: html+css, react
dependencies: none
license: MIT
provenance: authored for XT-Forge, 2026-11-03
states: [loading, empty, partial, error, permission, offline]
---

# Split editor

Hierarchy: the editor is the primary surface; the preview is secondary and can
collapse on narrow screens. Toolbar is sparse — only actions used every session.

## Required behaviour
- Keyboard-first: save, toggle preview, jump to error.
- Errors appear inline at the offending line, and in a summary list.
- Unsaved state is visible and blocks navigation with a clear choice.
- Preview failure must not lose edits; show the compile error beside the preview.

## States
| state | what the user sees |
|---|---|
| loading | editor disabled with "opening…", never a spinner over content |
| empty | one sentence on what to write, plus a paste/import affordance |
| partial | preview shows the last good render, labelled stale |
| error | inline marker + summary; save still allowed |
| permission | read-only banner stating why, edit controls removed |
| offline | local draft notice; queued save with explicit status |
