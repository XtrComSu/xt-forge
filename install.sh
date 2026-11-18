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
    git -C "${dst}" fetch --depth 1 origin "${BRANCH}" >/dev/null 2>&1 || true
    git -C "${dst}" checkout "${BRANCH}" >/dev/null 2>&1 || true
    git -C "${dst}" reset --hard "origin/${BRANCH}" >/dev/null 2>&1 || true
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

# Build native Rust and Go engines automatically when toolchains exist.
if command -v cargo >/dev/null 2>&1 && [ -f "${ROOT}/native/xtforge-rs/Cargo.toml" ]; then
  echo "[xt-forge] Building Rust core (native/xtforge-rs)..."
  (cd "${ROOT}/native/xtforge-rs" && cargo build --release --quiet)
fi

if command -v go >/dev/null 2>&1 && [ -f "${ROOT}/native/xtforge-go/go.mod" ]; then
  echo "[xt-forge] Building Go service hub (native/xtforge-go)..."
  (cd "${ROOT}/native/xtforge-go" && go build -ldflags="-s -w" -o xtforge-hub ./cmd/xtforge-hub)
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
  for dst in "${HOME}/.agents/skills" "${HOME}/.dsh/skills" "${HOME}/.config/opencode/skills" "${HOME}/.claude/skills"; do
    mkdir -p "${dst}"
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
echo "[xt-forge] Done! Try: xt-forge doctor  |  xt-forge --meta"
