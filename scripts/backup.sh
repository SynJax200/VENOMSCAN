#!/usr/bin/env bash
# Back up the VENOMSCAN PostgreSQL database (reports and audit trail included).
# Usage: scripts/backup.sh            (run from anywhere)
# Env:   COMPOSE_FILE, BACKUP_DIR, POSTGRES_USER, POSTGRES_DB
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE_FILE="${COMPOSE_FILE:-$ROOT/infra/compose/docker-compose.prod.yml}"
ENV_FILE="${ENV_FILE:-$ROOT/infra/compose/.env.prod}"
BACKUP_DIR="${BACKUP_DIR:-$ROOT/backups}"
POSTGRES_USER="${POSTGRES_USER:-venom}"
POSTGRES_DB="${POSTGRES_DB:-venomscan}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
TARGET="$BACKUP_DIR/venomscan-$STAMP.dump.gz"

mkdir -p "$BACKUP_DIR"
umask 077

docker compose --env-file "$ENV_FILE" -f "$COMPOSE_FILE" exec -T postgres \
  pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" --format=custom --no-owner \
  | gzip -9 > "$TARGET"

sha256sum "$TARGET" > "$TARGET.sha256"
# Persist Redis AOF state too; scans in flight are resumable only from their last event.
docker compose --env-file "$ENV_FILE" -f "$COMPOSE_FILE" exec -T redis redis-cli SAVE >/dev/null

echo "backup written: $TARGET"
echo "integrity:      $TARGET.sha256"
echo "Restore with:   scripts/restore.sh $TARGET (stop api + worker first)"
