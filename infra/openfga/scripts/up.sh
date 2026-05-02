#!/usr/bin/env bash
#
# OpenFGA boot wrapper — start the docker-compose stack idempotently.
#
# - Idempotent: `docker compose up -d` is a no-op if services are already running.
# - Reads secrets from infra/openfga/.env (must exist; see .env.example).
# - Intended to be called by launchd / systemd / manual invocation.
#
# Manual invocation:
#   ./infra/openfga/scripts/up.sh
#
# Override the OpenFGA dir (default = parent of this script's dir):
#   OPENFGA_DIR=/path/to/infra/openfga ./infra/openfga/scripts/up.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OPENFGA_DIR="${OPENFGA_DIR:-$(cd "$SCRIPT_DIR/.." && pwd)}"
COMPOSE_FILE="$OPENFGA_DIR/docker-compose.yml"
ENV_FILE="$OPENFGA_DIR/.env"
LOG_DIR="${OPENFGA_LOG_DIR:-$OPENFGA_DIR/logs}"

mkdir -p "$LOG_DIR"

ts() { date '+%Y-%m-%d %H:%M:%S'; }

if [ ! -f "$COMPOSE_FILE" ]; then
  echo "$(ts) [openfga-up] FATAL: $COMPOSE_FILE missing" >&2
  exit 1
fi

if [ ! -f "$ENV_FILE" ]; then
  echo "$(ts) [openfga-up] FATAL: $ENV_FILE missing — copy .env.example and fill secrets" >&2
  exit 1
fi

# launchd PATH may not include /opt/homebrew/bin; ensure docker is reachable.
export PATH="/opt/homebrew/bin:/usr/local/bin:$PATH"

if ! command -v docker >/dev/null 2>&1; then
  echo "$(ts) [openfga-up] FATAL: docker CLI not in PATH" >&2
  exit 1
fi

echo "$(ts) [openfga-up] Starting OpenFGA stack"
docker compose -f "$COMPOSE_FILE" --env-file "$ENV_FILE" up -d

echo "$(ts) [openfga-up] up -d returned 0; current state:"
docker compose -f "$COMPOSE_FILE" --env-file "$ENV_FILE" ps
