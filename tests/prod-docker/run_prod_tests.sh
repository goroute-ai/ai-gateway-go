#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
COMPOSE_FILE="$ROOT_DIR/deployments/prod-test/docker-compose.prod-test.yml"
CERT_DIR="$ROOT_DIR/.tmp/prod-test-certs"
CLI_HOME=""

cleanup() {
  local rc=$?
  if [[ "$rc" -ne 0 ]]; then
    echo "--- Prod-Test Compose Status ---" >&2
    docker compose -f "$COMPOSE_FILE" ps -a >&2 || true
    echo "--- gateway-migrate logs ---" >&2
    docker compose -f "$COMPOSE_FILE" logs --tail=40 gateway-migrate >&2 || true
    echo "--- ai-gateway-1 logs (tail 60) ---" >&2
    docker compose -f "$COMPOSE_FILE" logs --tail=60 ai-gateway-1 >&2 || true
    echo "--- ai-gateway-2 logs (tail 60) ---" >&2
    docker compose -f "$COMPOSE_FILE" logs --tail=60 ai-gateway-2 >&2 || true
    echo "--- keycloak logs (tail 40) ---" >&2
    docker compose -f "$COMPOSE_FILE" logs --tail=40 keycloak >&2 || true
    echo "--- prod-test-fixtures logs (tail 40) ---" >&2
    docker compose -f "$COMPOSE_FILE" logs --tail=40 prod-test-fixtures >&2 || true
  fi
  echo "==> Tearing down prod-test Docker stack, CLI temp home, and ephemeral certs..."
  docker compose -f "$COMPOSE_FILE" down -v --remove-orphans >/dev/null 2>&1 || true
  rm -rf "$CERT_DIR"
  if [[ -n "$CLI_HOME" && -d "$CLI_HOME" ]]; then
    rm -rf "$CLI_HOME"
  fi
  exit "$rc"
}
trap cleanup EXIT INT TERM

echo "==> Step 1: Generating ephemeral TLS Root CA, SAN certs, and Mozilla+CA bundle..."
bash "$ROOT_DIR/deployments/prod-test/gen-certs.sh" "$CERT_DIR"

echo "==> Step 2: Building production distroless gateway & fixtures images..."
docker compose -f "$COMPOSE_FILE" build gateway-migrate prod-test-fixtures

echo "==> Step 3 (Suite 1a): Verifying fail-closed production startup gates in container..."
assert_startup_fails() {
  local desc="$1"
  shift
  local cid
  cid="$(docker run -d "$@" goroute-ai-gateway:prod-test -config /app/configs/config.yaml)"
  local rc="running"
  for _ in $(seq 1 25); do
    local state
    state="$(docker inspect -f '{{.State.Status}}' "$cid" 2>/dev/null || echo "exited")"
    if [[ "$state" == "exited" ]]; then
      rc="$(docker inspect -f '{{.State.ExitCode}}' "$cid" 2>/dev/null || echo "1")"
      break
    fi
    sleep 0.2
  done
  docker rm -f "$cid" >/dev/null 2>&1 || true
  if [[ "$rc" == "running" || "$rc" == "0" ]]; then
    echo "FAIL: container unexpectedly started/exited-0 ($rc) for negative case: $desc" >&2
    exit 1
  fi
  echo "  PASS (rejected with exit $rc): $desc"
}

BASE_PROD_ENV=(
  -e GATEWAY_ENV=production
  -e GATEWAY_STORAGE_MODE=memory
  -e GATEWAY_MASTER_ADMIN_KEY=sk-gw-prod-neg-test-master-key-123456
  -e GATEWAY_MASTER_ENCRYPTION_KEY=a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90
  -e GATEWAY_SESSION_SECRET=prod-neg-session-secret-0123456789abcdef0123456789abcdef
)

assert_startup_fails "short session_secret in production" \
  -e GATEWAY_ENV=production \
  -e GATEWAY_STORAGE_MODE=memory \
  -e GATEWAY_MASTER_ADMIN_KEY=sk-gw-prod-neg-test-master-key-123456 \
  -e GATEWAY_MASTER_ENCRYPTION_KEY=a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90 \
  -e GATEWAY_SESSION_SECRET=too-short

assert_startup_fails "allow_loopback_http=true in production" \
  "${BASE_PROD_ENV[@]}" \
  -e GATEWAY_ALLOW_LOOPBACK_HTTP=true

assert_startup_fails "allow_private_networks=true in production" \
  "${BASE_PROD_ENV[@]}" \
  -e GATEWAY_SECURITY_SSRF_ALLOW_PRIVATE=true

assert_startup_fails "allow_insecure_http=true in production" \
  "${BASE_PROD_ENV[@]}" \
  -e GATEWAY_SECURITY_SSRF_ALLOW_INSECURE_HTTP=true

assert_startup_fails "unresolved os.environ reference in master_admin_key" \
  -e GATEWAY_ENV=production \
  -e GATEWAY_STORAGE_MODE=memory \
  -e GATEWAY_MASTER_ADMIN_KEY=os.environ/MISSING_TEST_VAR \
  -e GATEWAY_MASTER_ENCRYPTION_KEY=a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90 \
  -e GATEWAY_SESSION_SECRET=prod-neg-session-secret-0123456789abcdef0123456789abcdef

assert_startup_fails "overly broad allowed_private_cidrs=0.0.0.0/0 in production" \
  "${BASE_PROD_ENV[@]}" \
  -e GATEWAY_SECURITY_SSRF_ALLOWED_PRIVATE_CIDRS=0.0.0.0/0

assert_startup_fails "wildcard cors_allowed_origins=* in production" \
  "${BASE_PROD_ENV[@]}" \
  -e GATEWAY_CORS_ALLOWED_ORIGINS='*'

echo "==> Step 4: Starting 2-replica production-topology Docker Compose stack (Keycloak 26 + Postgres 16 TLS + Redis 7 + Fixtures + Caddy TLS)..."
docker compose -f "$COMPOSE_FILE" up -d

echo "==> Waiting for both GoRoute replicas & fixtures (/readyz via verified TLS)..."
READY=0
for _ in $(seq 1 90); do
  if curl -fsS --cacert "$CERT_DIR/ca.crt" --resolve "gateway.prod.test:18444:127.0.0.1" "https://gateway.prod.test:18444/readyz" >/dev/null 2>&1 \
     && curl -fsS --cacert "$CERT_DIR/ca.crt" --resolve "gateway.prod.test:18445:127.0.0.1" "https://gateway.prod.test:18445/readyz" >/dev/null 2>&1 \
     && curl -fsS --cacert "$CERT_DIR/ca.crt" --resolve "fixtures.prod.test:18443:127.0.0.1" "https://fixtures.prod.test:18443/healthz" >/dev/null 2>&1; then
    READY=1
    break
  fi
  sleep 2
done
if [[ "$READY" != "1" ]]; then
  echo "FAIL: prod-test gateway replicas or fixtures did not become ready in time" >&2
  exit 1
fi
echo "==> Both replicas and HTTPS fixtures are ready over TLS 1.3!"

echo "==> Step 5 (Suite 2): Running Playwright browser E2E against live Keycloak 26 & Operator UI Parity..."
if [[ ! -d "$ROOT_DIR/tests/ui-e2e/node_modules/playwright" ]]; then
  (cd "$ROOT_DIR/tests/ui-e2e" && npm install && npx playwright install chromium)
fi
NODE_PATH="$ROOT_DIR/tests/ui-e2e/node_modules" \
  PROD_BASE_URL="https://gateway.prod.test:18443" \
  PROD_AUTH_URL="https://auth.prod.test:18443" \
  PROD_MASTER_ADMIN_KEY="sk-gw-prod-test-master-admin-key-2026-secure" \
  node "$SCRIPT_DIR/prod_ui_keycloak.spec.mjs"

echo "==> Step 6 (Suite 9): Running cmd/goroute Developer CLI E2E over TLS..."
(cd "$ROOT_DIR" && make build-cli >/dev/null)
CLI_HOME="$(mktemp -d)"
CLI_LOGIN_LOG="$(mktemp -t goroute-cli-login.XXXXXX)"
(
  GOROUTE_CONFIG_DIR="$CLI_HOME" \
  SSL_CERT_FILE="$CERT_DIR/ca-bundle.crt" \
  "$ROOT_DIR/bin/goroute" login --gateway "https://127.0.0.1:18443" --provider keycloak --no-open >"$CLI_LOGIN_LOG" 2>&1
) &
CLI_PID=$!

VERIF_URL=""
for _ in $(seq 1 40); do
  if grep -q "https://gateway.prod.test:18443/ui/cli?" "$CLI_LOGIN_LOG" 2>/dev/null; then
    VERIF_URL="$(grep -oE 'https://gateway\.prod\.test:18443/ui/cli\?[^[:space:]]+' "$CLI_LOGIN_LOG" | head -n1)"
    break
  fi
  sleep 0.25
done
if [[ -z "$VERIF_URL" ]]; then
  echo "FAIL: goroute CLI login did not emit verification_url; log:" >&2
  cat "$CLI_LOGIN_LOG" >&2 || true
  rm -f "$CLI_LOGIN_LOG"
  kill "$CLI_PID" >/dev/null 2>&1 || true
  exit 1
fi

NODE_PATH="$ROOT_DIR/tests/ui-e2e/node_modules" \
  PROD_BASE_URL="https://gateway.prod.test:18443" \
  PROD_AUTH_URL="https://auth.prod.test:18443" \
  PROD_CLI_APPROVE_URL="$VERIF_URL" \
  node "$SCRIPT_DIR/prod_ui_keycloak.spec.mjs"

wait "$CLI_PID"
rm -f "$CLI_LOGIN_LOG"

CREDS_FILE="$CLI_HOME/credentials.json"
if [[ ! -f "$CREDS_FILE" ]]; then
  echo "FAIL: expected CLI credentials file at $CREDS_FILE" >&2
  exit 1
fi
CREDS_MODE="$(stat -f '%Lp' "$CREDS_FILE" 2>/dev/null || stat -c '%a' "$CREDS_FILE")"
if [[ "$CREDS_MODE" != "600" ]]; then
  echo "FAIL: expected credentials.json mode 600, got $CREDS_MODE" >&2
  exit 1
fi

GOROUTE_CONFIG_DIR="$CLI_HOME" SSL_CERT_FILE="$CERT_DIR/ca-bundle.crt" "$ROOT_DIR/bin/goroute" whoami | grep -q "llm_api"
GOROUTE_CONFIG_DIR="$CLI_HOME" SSL_CERT_FILE="$CERT_DIR/ca-bundle.crt" "$ROOT_DIR/bin/goroute" models list
if GOROUTE_CONFIG_DIR="$CLI_HOME" SSL_CERT_FILE="$CERT_DIR/ca-bundle.crt" "$ROOT_DIR/bin/goroute" keys list >/dev/null 2>&1; then
  echo "FAIL: least-privilege CLI llm_api key unexpectedly allowed /admin/v1/keys!" >&2
  exit 1
fi
CLI_KEY_ID="$(node -e "const fs=require('fs'); console.log(JSON.parse(fs.readFileSync(process.argv[1],'utf8')).key_id);" "$CREDS_FILE")"
MINTED_CLI_KEY="$(node -e "const fs=require('fs'); console.log(JSON.parse(fs.readFileSync(process.argv[1],'utf8')).api_key);" "$CREDS_FILE")"
GOROUTE_CONFIG_DIR="$CLI_HOME" SSL_CERT_FILE="$CERT_DIR/ca-bundle.crt" GOROUTE_API_KEY="sk-gw-prod-test-master-admin-key-2026-secure" "$ROOT_DIR/bin/goroute" keys list | grep -q "$CLI_KEY_ID"
GOROUTE_CONFIG_DIR="$CLI_HOME" SSL_CERT_FILE="$CERT_DIR/ca-bundle.crt" GOROUTE_API_KEY="sk-gw-prod-test-master-admin-key-2026-secure" "$ROOT_DIR/bin/goroute" projects list | grep -q "prod-ui-project"
GOROUTE_CONFIG_DIR="$CLI_HOME" SSL_CERT_FILE="$CERT_DIR/ca-bundle.crt" GOROUTE_API_KEY="sk-gw-prod-test-master-admin-key-2026-secure" "$ROOT_DIR/bin/goroute" logout --revoke
rm -rf "$CLI_HOME"
REVOKED_CODE="$(curl -s -o /dev/null -w '%{http_code}' --cacert "$CERT_DIR/ca.crt" --resolve "gateway.prod.test:18443:127.0.0.1" -H "Authorization: Bearer $MINTED_CLI_KEY" "https://gateway.prod.test:18443/v1/models")"
if [[ "$REVOKED_CODE" != "401" ]]; then
  echo "FAIL: expected revoked CLI key to return 401, got $REVOKED_CODE" >&2
  exit 1
fi
echo "  PASS (Suite 9): goroute CLI login, 0600 creds, whoami, models, keys, projects, logout --revoke verified!"

echo "==> Step 7 (Suites 1, 3, 4, 5, 6, 7, 8, 10, 99): Running Go production E2E verification..."
(cd "$ROOT_DIR" && go test -tags=proddocker -v -count=1 ./tests/prod-docker/)

echo "==> Step 8 (Suite 4d): Scanning container logs for secret leakage (internal + live provider keys)..."
GW_LOGS="$(docker compose -f "$COMPOSE_FILE" logs ai-gateway-1 ai-gateway-2 2>&1)"
SECRETS_TO_SCAN=(
  "sk-gw-prod-test-master-admin-key-2026-secure"
  "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90"
  "prod-test-hmac-session-secret-0123456789abcdef"
  "goroute-prod-oidc-secret-2026"
  "prod-test-redis-pass-2026"
  "prod-test-pg-password-2026"
  "prod-test-authz-hmac-secret-2026"
  "prod-test-siem-hmac-secret-2026"
)
for env_name in PROD_LIVE_OPENAI_API_KEY PROD_LIVE_ANTHROPIC_API_KEY PROD_LIVE_GROQ_API_KEY PROD_LIVE_OPENROUTER_API_KEY PROD_LIVE_GEMINI_API_KEY; do
  val="${!env_name:-}"
  if [[ -n "$val" ]]; then
    SECRETS_TO_SCAN+=("$val")
  fi
done
for secret in "${SECRETS_TO_SCAN[@]}"; do
  if echo "$GW_LOGS" | grep -qF "$secret"; then
    echo "FAIL: secret leaked in gateway container logs!" >&2
    exit 1
  fi
done
echo "  PASS: Zero internal or live provider secrets found in gateway container logs."
echo "==> ALL PRODUCTION DOCKER AUTHORIZATION SUITES (1-10 + 99) PASSED!"
