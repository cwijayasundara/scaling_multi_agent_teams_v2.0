#!/bin/sh
# Start a small live authored run whose calculations execute in OpenShell microVMs.
# Bills the model provider. Spend settings are required; nothing is assumed.
#   scripts/run-authored.sh --budget-usd 1 --input-usd-per-million P --output-usd-per-million Q [teamlab run options]
# Extra options override the defaults below (later flags win), e.g. --workers 2 --rows 1000.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"

case " $* " in *" --budget-usd "*) ;; *) MISSING=1 ;; esac
case " $* " in *" --input-usd-per-million "*) ;; *) MISSING=1 ;; esac
case " $* " in *" --output-usd-per-million "*) ;; *) MISSING=1 ;; esac
if [ "${MISSING:-0}" = 1 ]; then
  sed -n '2,5p' "$0" >&2
  echo "error: pass --budget-usd, --input-usd-per-million and --output-usd-per-million (use your verified provider prices)" >&2
  exit 2
fi

[ -f .env ] || [ -n "${OPENAI_API_KEY:-}" ] || { echo "error: OPENAI_API_KEY not set (.env or environment)" >&2; exit 2; }
openshell status 2>/dev/null | grep -q Connected || { echo "error: OpenShell gateway not connected; run scripts/setup.sh" >&2; exit 2; }
if ! .venv/bin/python -c 'import json,sys; sys.exit(0 if json.load(open("reports/host-qualification.json")).get("qualified") else 1)' 2>/dev/null; then
  echo "error: no passing qualification; run: PYTHONPATH=src .venv/bin/python -m teamlab qualify-host" >&2
  exit 2
fi

export PYTHONPATH=src
exec .venv/bin/python -m teamlab run \
  --root runs/openshell \
  --workflow authored --mode live \
  --execution-profile openshell \
  --workers 1 --rows 200 \
  --max-requests 40 --model-call-limit 40 \
  "$@"
