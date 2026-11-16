#!/usr/bin/env bash
# Restore a VENOMSCAN database backup into the production stack.
# Usage: scripts/restore.sh backups/venomscan-YYYYmmddTHHMMSSZ.dump.gz
# Stop api and worker first so nothing writes while the database is replaced:
#   docker compose --env-file infra/compose/.env.prod \
#     -f infra/compose/docker-compose.prod.yml stop api worker
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 <backup.dump.gz>" >&2
  exit 2
fi

BACKUP="$1"
[[ -f "$BACKUP" ]] || { echo "backup not found: $BACKUP" >&2; exit 2; }

if [[ -f "$BACKUP.sha256" ]]; then
  echo "verifying integrity…"
  (cd "$(dirname "$BACKUP")" && sha256sum -c "$(basename "$BACKUP").sha256")
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE_FILE="${COMPOSE_FILE:-$ROOT/infra/compose/docker-compose.prod.yml}"
ENV_FILE="${ENV_FILE:-$ROOT/infra/compose/.env.prod}"
POSTGRES_USER="${POSTGRES_USER:-venom}"
POSTGRES_DB="${POSTGRES_DB:-venomscan}"

compose() { docker compose --env-file "$ENV_FILE" -f "$COMPOSE_FILE" "$@"; }

echo "restoring $BACKUP into $POSTGRES_DB…"
gunzip -c "$BACKUP" | compose exec -T postgres \
  pg_restore -U "$POSTGRES_USER" -d "$POSTGRES_DB" --clean --if-exists --no-owner

echo "restore complete. Start the stack again:"
echo "  docker compose --env-file $ENV_FILE -f $COMPOSE_FILE start api worker"
echo "Then verify GET /healthz and open a report to confirm its SHA-256 still matches."
