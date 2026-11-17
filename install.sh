#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOCAL_BIN="${HOME}/.local/bin"

echo "[xt-forge] Installing from ${ROOT}"

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
fi

echo "[xt-forge] Done! Try: xt-forge doctor  |  xt-forge --meta"
