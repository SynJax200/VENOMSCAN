#!/usr/bin/env bash
# Codespaces demo runner: builds and starts the VENOMSCAN stack on the
# forwarded port, then seeds a verified self-scan so the UI is populated.
#
#   bash scripts/codespace-demo.sh prepare   # downloads Nuclei, builds images
#   bash scripts/codespace-demo.sh start     # starts services + seeds demo data
#
# Set LLM_API_KEY as a Codespaces secret to enable the AI features.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

MODE="${1:-start}"
COMPOSE_FILE=infra/compose/docker-compose.prod.yml
OVERLAY=infra/compose/docker-compose.codespace.yml
ENV_FILE=infra/compose/.env.prod
PAGE_PORT=3000
NUCLEI_VERSION=v3.11.1
HOST="${CODESPACE_NAME:-venomscan}-${PAGE_PORT}.${GITHUB_CODESPACES_PORT_FORWARDING_DOMAIN:-app.github.dev}"
URL="https://${HOST}"
DEMO_EMAIL="${DEMO_EMAIL:-demo@venomscan.local}"
DEMO_PASSWORD="${DEMO_PASSWORD:-Venom-demo-codespace-123}"
COMPOSE=(docker compose --env-file "$ENV_FILE" -f "$COMPOSE_FILE" -f "$OVERLAY")
SERVICES=(postgres redis api worker web)

say() { printf '\n==> %s\n' "$*"; }
warn() { printf 'WARNING: %s\n' "$*" >&2; }
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

require_docker() {
  command -v docker >/dev/null 2>&1 || die "docker is missing; recreate the Codespace from the devcontainer"
  for _ in $(seq 1 12); do
    docker info >/dev/null 2>&1 && return 0
    sleep 5
  done
  die "docker daemon is not ready; wait a minute and rerun"
}

random_hex() { openssl rand -hex "$1"; }

retry() {
  local attempts=$1
  shift
  local n=0
  until "$@"; do
    n=$((n + 1))
    [[ $n -ge $attempts ]] && return 1
    warn "command failed; retrying (${n}/${attempts})"
    sleep 15
  done
}

write_env() {
  [[ -f "$ENV_FILE" ]] && return
  say "writing ${ENV_FILE}"
  cat > "$ENV_FILE" <<EOF
DOMAIN=${HOST}
ACME_EMAIL=demo@example.com
API_BASE=${URL}
WEB_BASE=${URL}
CORS_ORIGINS=${URL}
SEED_TARGET_URL=${URL}
DEMO_ENABLED=false
SECRET_KEY=$(random_hex 32)
POSTGRES_USER=venom
POSTGRES_PASSWORD=$(random_hex 24)
POSTGRES_DB=venomscan
ALLOW_PRIVATE_TARGETS=false
ALLOW_REGISTRATION=true
SCAN_DEFAULT_PROFILE=safe
SCAN_MAX_REQUESTS=120
SCAN_MAX_SECONDS=90
SCAN_RPS=4
SCAN_OSINT_ENABLED=true
SCAN_HISTORY_ENABLED=true
SCAN_SPA_ENABLED=true
SCAN_DIRS_ENABLED=true
OOB_ENABLED=false
LLM_PROVIDER=openai_compat
LLM_MODEL=${LLM_MODEL:-gemini-2.5-flash}
LLM_BASE_URL=${LLM_BASE_URL:-https://generativelanguage.googleapis.com/v1beta/openai/}
LLM_API_KEY=${LLM_API_KEY:-}
AI_ALLOWED_HOSTS=generativelanguage.googleapis.com
AI_CACHE_TTL_SECONDS=900
AI_AUTO_TRIAGE=true
AI_REPORT_AUTOFILL=true
REPORT_LINK_HOURS=24
NUCLEI_ENABLED=true
NUCLEI_BINARY=/opt/nuclei/nuclei
NUCLEI_TEMPLATES=/nuclei-templates
NUCLEI_SEVERITIES=info,low,medium
NUCLEI_RATE_LIMIT=10
NUCLEI_TIMEOUT=60
PLUGIN_DIRS=/plugins
PLUGIN_DIRS_HOST=../../examples/plugins
NUCLEI_TEMPLATES_HOST=../../nuclei-templates
NUCLEI_BIN_DIR=../../.nuclei-bin
LOGIN_STATE_BACKEND=redis
TRUSTED_PROXIES=
EOF
  chmod 600 "$ENV_FILE"
  [[ -n "${LLM_API_KEY:-}" ]] || warn "LLM_API_KEY is not set; AI features stay in deterministic mode"
}

install_nuclei() {
  [[ -x .nuclei-bin/nuclei ]] && return
  say "downloading Nuclei ${NUCLEI_VERSION}"
  mkdir -p .nuclei-bin
  curl -fsSL -o /tmp/venomscan-nuclei.zip \
    "https://github.com/projectdiscovery/nuclei/releases/download/${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION#v}_linux_amd64.zip"
  if command -v unzip >/dev/null 2>&1; then
    unzip -oq /tmp/venomscan-nuclei.zip -d .nuclei-bin
  else
    python3 -m zipfile -e /tmp/venomscan-nuclei.zip .nuclei-bin
  fi
  chmod 755 .nuclei-bin/nuclei
  rm -f /tmp/venomscan-nuclei.zip
}

wait_for_web() {
  for _ in $(seq 1 60); do
    code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "http://127.0.0.1:${PAGE_PORT}/" || true)
    [[ "$code" == "200" ]] && return 0
    sleep 5
  done
  "${COMPOSE[@]}" ps || true
  die "web did not answer on port ${PAGE_PORT}; inspect: ${COMPOSE[*]} logs web api"
}

seed_demo() {
  grep -q '^SEED_DONE=1' "$ENV_FILE" && { say "demo data already seeded"; return; }
  say "seeding demo account, verified target and self-scan (about a minute)"
  if "${COMPOSE[@]}" exec -T \
      -e VG_URL="$URL" -e VG_EMAIL="$DEMO_EMAIL" -e VG_PASSWORD="$DEMO_PASSWORD" \
      api .venv/bin/python - < scripts/codespace_seed.py; then
    printf 'SEED_DONE=1\n' >> "$ENV_FILE"
    sed -i 's/^ALLOW_REGISTRATION=.*/ALLOW_REGISTRATION=false/' "$ENV_FILE"
    say "closing public sign-up and restarting the API"
    "${COMPOSE[@]}" up -d api
  else
    warn "demo seeding failed; the UI still works, register manually to explore"
  fi
}

start() {
  require_docker
  write_env
  install_nuclei
  say "starting postgres, redis, api, worker and web"
  retry 3 "${COMPOSE[@]}" up -d --remove-orphans "${SERVICES[@]}" \
    || die "compose up kept failing; rerun the script (layer cache makes retries fast)"
  wait_for_web
  seed_demo
  cat <<EOF

==> VENOMSCAN demo
    URL:      ${URL}
    Login:    ${DEMO_EMAIL}
    Password: ${DEMO_PASSWORD}
    AI:       $([[ -n "${LLM_API_KEY:-}" ]] && echo enabled || echo "deterministic mode (set LLM_API_KEY secret)")
    Stop:     docker compose --env-file ${ENV_FILE} -f ${COMPOSE_FILE} -f ${OVERLAY} down

EOF
}

prepare() {
  require_docker
  write_env
  install_nuclei
  say "building images (first build takes roughly 10-15 minutes)"
  retry 3 "${COMPOSE[@]}" build api worker web \
    || die "image build kept failing; rerun the script to resume from cached layers"
  say "prepare complete; run: bash scripts/codespace-demo.sh start"
}

case "$MODE" in
  prepare) prepare ;;
  start) start ;;
  *) die "usage: $0 [prepare|start]" ;;
esac
