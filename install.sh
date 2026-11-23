#!/usr/bin/env bash
# Universal Linux & macOS installer for xt-forge.
# Local checkout:  ./install.sh
# Piped install :  curl -fsSL https://raw.githubusercontent.com/XtrComSu/xt-forge/main/install.sh | bash
set -euo pipefail

REPO_URL="${XT_REPO_URL:-https://github.com/XtrComSu/xt-forge.git}"
BRANCH="${XT_BRANCH:-main}"

resolve_root() {
  local src="${BASH_SOURCE[0]:-}"
  if [ -n "$src" ] && [ -f "$src" ]; then
    local candidate
    candidate="$(cd "$(dirname "$src")" && pwd)"
    if [ -f "${candidate}/VERSION" ] && [ -f "${candidate}/bin/xtforge" ]; then
      echo "$candidate"
      return 0
    fi
  fi
  if [ -f "./VERSION" ] && [ -f "./bin/xtforge" ]; then
    pwd
    return 0
  fi
  local dst="${HOME}/.xt-forge-src"
  if [ -d "${dst}/.git" ]; then
    echo "[xt-forge] Updating existing checkout at ${dst}..." >&2
    # A failed fetch used to be swallowed with `|| true` and followed by an
    # unconditional `reset --hard`, which meant a network failure silently
    # reinstalled whatever `origin/${BRANCH}` already pointed at — an old build
    # reported as a fresh install. Fail loudly instead: installing a stale tree
    # while the user believes they upgraded is worse than not installing.
    if ! git -C "${dst}" fetch --depth 1 origin "${BRANCH}"; then
      echo "[xt-forge] ERROR: could not fetch ${BRANCH} from ${REPO_URL}." >&2
      echo "[xt-forge] The checkout at ${dst} was left untouched." >&2
      echo "[xt-forge] Re-run when the network is available, or set XT_SKIP_FETCH=1" >&2
      echo "[xt-forge] to build from the existing checkout as-is." >&2
      if [ "${XT_SKIP_FETCH:-0}" != "1" ]; then
        return 1
      fi
      echo "${dst}"
      return 0
    fi
    # `reset --hard` discards uncommitted work. That is destructive and this is an
    # installer, not a checkout manager: someone who edited files under
    # ${dst} must not lose them to a convenience update. Refuse unless they say
    # otherwise, and tell them exactly how to say otherwise.
    if [ -n "$(git -C "${dst}" status --porcelain 2>/dev/null)" ]; then
      if [ "${XT_FORCE_RESET:-0}" = "1" ]; then
        echo "[xt-forge] XT_FORCE_RESET=1: discarding local changes in ${dst}." >&2
      else
        echo "[xt-forge] ERROR: ${dst} has local changes; refusing to discard them." >&2
        git -C "${dst}" status --short >&2 || true
        echo "[xt-forge] Commit or stash them, or re-run with XT_FORCE_RESET=1 to discard." >&2
        return 1
      fi
    fi
    git -C "${dst}" checkout "${BRANCH}" >/dev/null 2>&1 || true
    # stdout is the function's return value, captured by the caller as
    # ROOT="$(resolve_root)". `git reset` writes "HEAD is now at <sha>" to stdout,
    # so an unredirected reset makes ROOT the literal string
    # "HEAD is now at 7f1a2f6 init\n/home/.../.xt-forge-src" and every later path
    # built from ROOT is nonsense. Send progress to stderr; keep the real errors.
    git -C "${dst}" reset --hard "origin/${BRANCH}" >&2
  else
    echo "[xt-forge] Cloning xt-forge (${BRANCH}) to ${dst}..." >&2
    git clone --depth 1 --branch "${BRANCH}" "${REPO_URL}" "${dst}"
  fi
  echo "${dst}"
}

ROOT="$(resolve_root)"
LOCAL_BIN="${HOME}/.local/bin"
OS_NAME="$(uname -s 2>/dev/null || echo unknown)"

# Ensure Apple Silicon Homebrew paths are visible if running non-interactively
if [ "$OS_NAME" = "Darwin" ]; then
  export PATH="/opt/homebrew/bin:/usr/local/bin:${PATH}"
fi

echo "[xt-forge] Installing from ${ROOT} (${OS_NAME})"

# Rebuild only when the shipped native artifact is missing or older than its sources,
# so re-running the installer is cheap. Set XT_FORCE_REBUILD=1 to always rebuild.
# A build from scratch costs ~2 minutes (the Rust dependency set includes bundled SQLite).
xtf_stale() {
  local artifact="$1"
  shift
  if [ "${XT_FORCE_REBUILD:-0}" = "1" ]; then return 0; fi
  if [ ! -f "${artifact}" ]; then return 0; fi
  [ -n "$(find "$@" -newer "${artifact}" -print -quit 2>/dev/null)" ]
}

# Build native Rust and Go engines automatically when toolchains exist.
if command -v cargo >/dev/null 2>&1 && [ -f "${ROOT}/native/xtforge-rs/Cargo.toml" ]; then
  if xtf_stale "${ROOT}/native/xtforge-rs/target/release/xtforge-native" \
      "${ROOT}/native/xtforge-rs/src" "${ROOT}/native/xtforge-rs/Cargo.toml" \
      "${ROOT}/native/xtforge-rs/Cargo.lock"; then
    echo "[xt-forge] Building Rust core (native/xtforge-rs)..."
    (cd "${ROOT}/native/xtforge-rs" && cargo build --release --quiet)
  else
    echo "[xt-forge] Rust core is up to date (set XT_FORCE_REBUILD=1 to rebuild)."
  fi
fi

if command -v go >/dev/null 2>&1 && [ -f "${ROOT}/native/xtforge-go/go.mod" ]; then
  if xtf_stale "${ROOT}/native/xtforge-go/xtforge-hub" \
      "${ROOT}/native/xtforge-go/cmd" "${ROOT}/native/xtforge-go/internal" \
      "${ROOT}/native/xtforge-go/go.mod"; then
    echo "[xt-forge] Building Go service hub (native/xtforge-go)..."
    (cd "${ROOT}/native/xtforge-go" && go build -ldflags="-s -w" -o xtforge-hub ./cmd/xtforge-hub)
  else
    echo "[xt-forge] Go service hub is up to date (set XT_FORCE_REBUILD=1 to rebuild)."
  fi
fi

chmod +x "${ROOT}/bin/xtforge" "${ROOT}/bin/xtforge-termux" "${ROOT}/bin/npx-xtforge.mjs"

if command -v node >/dev/null 2>&1; then
  node "${ROOT}/bin/npx-xtforge.mjs" init --quiet
else
  mkdir -p "${LOCAL_BIN}"
  ln -sf "${ROOT}/bin/xtforge" "${LOCAL_BIN}/xt-forge"
  ln -sf "${ROOT}/bin/xtforge" "${LOCAL_BIN}/xtforge"
  ln -sf "${ROOT}/bin/xtforge" "${LOCAL_BIN}/xtf"
  echo "[xt-forge] Linked ${LOCAL_BIN}/{xt-forge,xtforge,xtf}"
  SKILL_TARGETS=("${HOME}/.agents/skills" "${HOME}/.dsh/skills" "${HOME}/.config/opencode/skills" "${HOME}/.claude/skills" "${HOME}/.kimi-code/skills")
  for extra_h in .qoder .gemini .codex .cursor; do
    [ -d "${HOME}/${extra_h}" ] && SKILL_TARGETS+=("${HOME}/${extra_h}/skills")
  done
  for dst in "${SKILL_TARGETS[@]}"; do
    mkdir -p "${dst}"
    for legacy in XTF-Pulse XTF-Compass XTF-Spark XTF-Shield XTF-Lumen XTF-Gage \
                  XTF-Vise XTF-Trace XTF-Beacon XTF-Anvil XTF-Sliver XTF-Chisel \
                  XTF-Wraith XTF-Cipher XTF-Cartographer XTF-Scalpel XTF-Sentinel XTF-Crucible; do
      rm -rf "${dst}/${legacy}"
    done
    for tier in simple complex advanced; do
      if [ -d "${ROOT}/skills/${tier}" ]; then
        for s in "${ROOT}/skills/${tier}"/XTF-*; do
          [ -d "${s}" ] && cp -r "${s}" "${dst}/"
        done
      fi
    done
  done
  mkdir -p "${HOME}/.dsh/commands" "${HOME}/.claude/commands"
  printf '%s\n' "---" "description: Run xt-forge natively (/xtf --meta, /xtf re checksec, /xtf intel cve, /xtf code graph)" "---" 'Execute `xt-forge $ARGUMENTS` cleanly. If `$ARGUMENTS` is `--meta`, inspect or run `xt-forge --meta`.' > "${HOME}/.dsh/commands/xtf.md"
  printf '%s\n' "---" "description: Run xt-forge natively (/xtf --meta, /xtf re checksec, /xtf intel cve)" "---" 'Run `xt-forge $ARGUMENTS` and present crisp findings.' > "${HOME}/.claude/commands/xtf.md"
fi

# Also link into Homebrew/local bin on macOS or /usr/local/bin on Linux when already user-writable.
for sysbin in /opt/homebrew/bin /usr/local/bin; do
  if [ -d "$sysbin" ] && [ -w "$sysbin" ]; then
    ln -sf "${ROOT}/bin/xtforge" "${sysbin}/xt-forge"
    ln -sf "${ROOT}/bin/xtforge" "${sysbin}/xtforge"
    ln -sf "${ROOT}/bin/xtforge" "${sysbin}/xtf"
  fi
done

case ":${PATH}:" in
  *":${LOCAL_BIN}:"*) ;;
  *)
    if [ "$OS_NAME" = "Darwin" ]; then
      echo "[xt-forge] Add ${LOCAL_BIN} to PATH in ~/.zshrc:"
      echo "  echo 'export PATH=\"\$HOME/.local/bin:\$PATH\"' >> ~/.zshrc && source ~/.zshrc"
    else
      echo "[xt-forge] Add ${LOCAL_BIN} to PATH in ~/.bashrc (or ~/.profile):"
      echo "  echo 'export PATH=\"\$HOME/.local/bin:\$PATH\"' >> ~/.bashrc && source ~/.bashrc"
    fi
    ;;
esac

"${LOCAL_BIN}/xt-forge" version --json

# Register the MCP server and lay down the skill/command templates. Without this
# a fresh install leaves `doctor` reporting `mcp: not registered`, so every agent
# sees zero xt-forge tools until the user runs a second command they were never
# told about — the install looks complete and is not. sync is idempotent and
# never deletes entries it did not create, so re-running the installer is safe.
if [ "${XT_SKIP_SYNC:-0}" != "1" ]; then
  echo "[xt-forge] Registering MCP server and templates..."
  if "${LOCAL_BIN}/xt-forge" sync >/dev/null 2>&1; then
    echo "[xt-forge] MCP server registered."
  else
    echo "[xt-forge] WARNING: sync did not complete; run 'xt-forge sync' to finish." >&2
    echo "[xt-forge] Until it does, agents will not see xt-forge tools." >&2
  fi
fi

echo "[xt-forge] Done! Try: xt-forge doctor  |  xt-forge --meta"
