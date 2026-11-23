#!/usr/bin/env bash
# Dispatch one isolated task to a free model, then let the caller verify.
#
# Deliberately narrow: one task, one file, one verifiable check. A free model
# given freedom to restructure a 7000-line engine produces plausible nonsense;
# given a single function with a test to satisfy, it is genuinely useful.
#
# Usage: dispatch.sh <model> <worktree> <prompt-file> <log-file>
set -uo pipefail

model="${1:?model}"
worktree="${2:?worktree}"
prompt="${3:?prompt file}"
log="${4:?log file}"

[ -d "$worktree" ] || { echo "no such worktree: $worktree" >&2; exit 2; }
[ -f "$prompt" ] || { echo "no such prompt: $prompt" >&2; exit 2; }

cd "$worktree" || exit 2

timeout 900 opencode run -m "$model" "$(cat "$prompt")" >"$log" 2>&1
status=$?

echo "exit=$status log=$log" >&2
exit "$status"
