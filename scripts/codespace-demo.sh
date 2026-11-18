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
SEED_TARGET_URL=http://api:8000/demo
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
LLM_MODEL=${LLM_MODEL:-gemini-3-flash-preview}
LLM_BASE_URL=${LLM_BASE_URL:-https://generativelanguage.googleapis.com/v1beta/openai/}
LLM_API_KEY=${LLM_API_KEY:-}
LLM_TIMEOUT=120
LLM_MAX_TOKENS=4096
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

set_env() {
  local key=$1 value=$2
  if grep -q "^${key}=" "$ENV_FILE"; then
    sed -i "s|^${key}=.*|${key}=${value}|" "$ENV_FILE"
  else
    printf '%s=%s\n' "$key" "$value" >> "$ENV_FILE"
  fi
}

migrate_ai_env() {
  # Existing workspaces keep their old .env.prod: 2.5-flash now 404s for new API
  # keys, and reasoning models need more output tokens than the old 30 s/900 cap.
  [[ -f "$ENV_FILE" ]] || return
  if grep -q '^LLM_MODEL=gemini-2.5-flash' "$ENV_FILE"; then
    set_env LLM_MODEL gemini-3-flash-preview
    warn "LLM_MODEL switched to gemini-3-flash-preview (gemini-2.5-flash is closed to new keys)"
  fi
  grep -q '^LLM_TIMEOUT=' "$ENV_FILE" || set_env LLM_TIMEOUT 120
  grep -q '^LLM_MAX_TOKENS=' "$ENV_FILE" || set_env LLM_MAX_TOKENS 4096
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
  # "/" redirects to the login page, so any 2xx/3xx answer means Next is serving.
  for _ in $(seq 1 60); do
    code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "http://127.0.0.1:${PAGE_PORT}/" || true)
    [[ "$code" =~ ^[23] ]] && return 0
    sleep 5
  done
  "${COMPOSE[@]}" ps || true
  "${COMPOSE[@]}" logs --tail 40 web api || true
  die "web did not answer on port ${PAGE_PORT}; inspect: ${COMPOSE[*]} logs web api"
}

seed_demo() {
  # The seed is idempotent: it skips the scan when one exists and only fills the
  # gaps (missing target, attestation or PDF/JSON reports), so always run it.
  say "seeding demo account, verified target, self-scan and PDF/JSON reports (about two minutes on the first run)"
  if "${COMPOSE[@]}" exec -T -e DEMO_PASSWORD="$DEMO_PASSWORD" \
      api .venv/bin/python -m venomscan_api.seed; then
    if ! grep -q '^SEED_DONE=1' "$ENV_FILE"; then
      printf 'SEED_DONE=1\n' >> "$ENV_FILE"
    fi
    if grep -q '^ALLOW_REGISTRATION=true' "$ENV_FILE"; then
      sed -i 's/^ALLOW_REGISTRATION=.*/ALLOW_REGISTRATION=false/' "$ENV_FILE"
      say "closing public sign-up and restarting the API"
      "${COMPOSE[@]}" up -d api
    fi
  else
    warn "demo seeding failed; the UI still works, register manually to explore"
  fi
}

start() {
  require_docker
  write_env
  migrate_ai_env
  install_nuclei
  say "building api, worker and web (cached layers keep reruns quick)"
  retry 3 "${COMPOSE[@]}" build api worker web \
    || die "image build kept failing; rerun the script to resume from cached layers"
  say "starting postgres, redis, api, worker and web"
  retry 3 "${COMPOSE[@]}" up -d --remove-orphans "${SERVICES[@]}" \
    || die "compose up kept failing; rerun the script (layer cache makes retries fast)"
  wait_for_web
  seed_demo
  if grep -qE '^LLM_API_KEY=.+' "$ENV_FILE"; then ai_state=enabled; else ai_state="deterministic mode (set LLM_API_KEY)"; fi
  cat <<EOF

==> VENOMSCAN demo
    URL:      ${URL}
    Login:    ${DEMO_EMAIL}
    Password: ${DEMO_PASSWORD} (an account registered earlier keeps its own password)
    AI:       ${ai_state}
    Stop:     docker compose --env-file ${ENV_FILE} -f ${COMPOSE_FILE} -f ${OVERLAY} down

EOF
}

prepare() {
  require_docker
  write_env
  migrate_ai_env
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
