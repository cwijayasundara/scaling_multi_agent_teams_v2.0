#!/bin/sh
# One-time local setup: Python env, dashboard deps, OpenShell VM gateway, qualification.
# Idempotent: each step is skipped when already done. Never touches .env.
#   scripts/setup.sh                 # everything
#   scripts/setup.sh --no-openshell  # Python + dashboard only (offline workflows)
set -eu

OPENSHELL_VERSION=0.1.8
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"
WITH_OPENSHELL=1
for arg in "$@"; do
  case "$arg" in
    --no-openshell) WITH_OPENSHELL=0 ;;
    -h|--help) sed -n '2,6p' "$0"; exit 0 ;;
    *) echo "unknown option: $arg" >&2; exit 2 ;;
  esac
done

step() { printf '\n==> %s\n' "$*"; }
have() { command -v "$1" >/dev/null 2>&1; }

step "Python environment (.venv)"
if [ -x .venv/bin/python ] && PYTHONPATH=src .venv/bin/python -c 'import teamlab.cli, teamlab.agents, pytest' 2>/dev/null; then
  echo "already installed: $(.venv/bin/python --version)"
elif have uv; then
  [ -x .venv/bin/python ] || uv venv --python 3.12
  uv pip install --python .venv/bin/python -r requirements.lock
  uv pip install --python .venv/bin/python --no-deps -e .
else
  [ -x .venv/bin/python ] || python3.12 -m venv .venv
  .venv/bin/python -m pip install -e '.[test]'
fi

step "Dashboard dependencies"
if [ -d dashboard/node_modules/next ]; then
  echo "already installed"
elif have npm; then
  npm ci --prefix dashboard
else
  echo "npm not found; install Node.js, then rerun (the dashboard is optional)" >&2
fi

[ -f .env ] || echo "note: no .env yet. Live runs need OPENAI_API_KEY: cp .env.example .env && chmod 600 .env"

if [ "$WITH_OPENSHELL" = 0 ]; then
  step "Skipping OpenShell (--no-openshell)"; exit 0
fi

OS=$(uname -s)
step "OpenShell $OPENSHELL_VERSION"
if have openshell && openshell --version 2>/dev/null | grep -qx "openshell $OPENSHELL_VERSION"; then
  echo "already installed"
else
  have openshell && echo "found $(openshell --version); installing pinned $OPENSHELL_VERSION"
  TMP=$(mktemp -d)
  trap 'rm -rf "$TMP"' EXIT
  # Pinned installer; it verifies release checksums before installing.
  curl -fsSL "https://raw.githubusercontent.com/NVIDIA/OpenShell/v$OPENSHELL_VERSION/install.sh" -o "$TMP/install.sh"
  OPENSHELL_VERSION="v$OPENSHELL_VERSION" sh "$TMP/install.sh"
fi

if [ "$OS" = Darwin ]; then
  step "e2fsprogs (needed by the VM driver on macOS)"
  if brew list e2fsprogs >/dev/null 2>&1; then echo "already installed"; else brew install e2fsprogs; fi
fi

step "Gateway: vm compute driver"
if [ "$OS" = Darwin ] && [ ! -f "$HOME/.config/openshell/gateway.toml" ]; then
  CONFIG="$(brew --prefix)/var/openshell/gateway.toml"   # Homebrew service config
else
  CONFIG="$HOME/.config/openshell/gateway.toml"           # takes precedence when present
fi
if [ -f "$CONFIG" ] && grep -Eq '^[[:space:]]*compute_driver[[:space:]]*=[[:space:]]*"vm"' "$CONFIG"; then
  echo "already configured: $CONFIG"
  RESTART=0
else
  mkdir -p "$(dirname "$CONFIG")"
  if [ -f "$CONFIG" ]; then
    BACKUP="$CONFIG.bak.$(date +%Y%m%d%H%M%S)"
    cp "$CONFIG" "$BACKUP"; echo "backed up previous config to $BACKUP"
  fi
  cat > "$CONFIG" <<'EOF'
[openshell]
version = 2

[openshell.gateway]
compute_driver = "vm"

[openshell.drivers.vm]
vcpus = 1
mem_mib = 1024
EOF
  echo "wrote $CONFIG"
  RESTART=1
fi

if [ "$RESTART" = 1 ] || ! openshell status >/dev/null 2>&1; then
  step "Restarting gateway"
  if [ "$OS" = Darwin ]; then brew services restart openshell; else systemctl --user restart openshell-gateway; fi
fi
i=0
until openshell status 2>/dev/null | grep -q Connected; do
  i=$((i+1)); [ $i -ge 60 ] && { echo "gateway did not connect; see 'openshell status'" >&2; exit 1; }
  sleep 1
done
echo "gateway connected"

step "Qualifying the execution boundary (real guests, ~30s, no model calls)"
if PYTHONPATH=src .venv/bin/python -m teamlab qualify-host >/dev/null; then
  echo "qualified: reports/host-qualification.json"
else
  echo "qualification FAILED: inspect reports/host-qualification.json" >&2; exit 1
fi

printf '\nSetup complete.\n  make dashboard ROOT=runs/openshell\n  make authored BUDGET=... INPUT_PRICE=... OUTPUT_PRICE=...\n'
