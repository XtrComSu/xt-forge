---
id: search-results
name: Dense search results
purpose: Let a user scan many matches and refine quickly.
when: |
  The primary task is finding one item among many. Result count is high and the
  user iterates on the query rather than reading one record.
not_when: |
  The user reads one item at a time (use a reader/detail layout), or the set is
  under ~10 items (a plain list needs no filters).
stack: html+css, react
dependencies: none
license: MIT
provenance: authored for XT-Forge, 2026-11-03
states: [loading, empty, partial, error, permission, offline]
---

# Dense search results

Hierarchy: query and result count first, then filters, then results. The filter
column is narrow and scannable; results carry one strong line and at most two
supporting lines.

## Structure
1. Sticky query bar with the current query editable in place.
2. Result count + active filters as removable chips.
3. Result rows: title (link), one-line excerpt, source + date.
4. Pagination or incremental load — never infinite scroll for a task the user
   resumes later.

## Required states
| state | what the user sees |
|---|---|
| loading | skeleton rows, count placeholder, filters still usable |
| empty | the query echoed back, one suggestion to broaden, no fake results |
| partial | "showing 20 of ~400" with an explicit continue action |
| error | the failing part named, retry for that part only |
| permission | which results are hidden and why, not a blank page |
| offline | last results dimmed + "refreshing when back online" |

## Anti-pattern
Do not put each result in a card with a gradient, a shadow and a large avatar.
Density is the point of this screen; decoration costs scans.
