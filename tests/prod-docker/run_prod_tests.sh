#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
COMPOSE_FILE="$ROOT_DIR/deployments/prod-test/docker-compose.prod-test.yml"
CERT_DIR="$ROOT_DIR/.tmp/prod-test-certs"

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
  fi
  echo "==> Tearing down prod-test Docker stack and ephemeral certs..."
  docker compose -f "$COMPOSE_FILE" down -v --remove-orphans >/dev/null 2>&1 || true
  rm -rf "$CERT_DIR"
  exit "$rc"
}
trap cleanup EXIT INT TERM

echo "==> Step 1: Generating ephemeral TLS Root CA & SAN certs..."
bash "$ROOT_DIR/deployments/prod-test/gen-certs.sh" "$CERT_DIR"

echo "==> Step 2: Building production distroless gateway image..."
docker compose -f "$COMPOSE_FILE" build gateway-migrate

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

echo "==> Step 4: Starting 2-replica production-topology Docker Compose stack (Keycloak 26 + Postgres 16 TLS + Redis 7 + Caddy TLS)..."
docker compose -f "$COMPOSE_FILE" up -d

echo "==> Waiting for both GoRoute replicas (/readyz via verified TLS)..."
READY=0
for _ in $(seq 1 90); do
  if curl -fsS --cacert "$CERT_DIR/ca.crt" --resolve "gateway.prod.test:18444:127.0.0.1" "https://gateway.prod.test:18444/readyz" >/dev/null 2>&1 \
     && curl -fsS --cacert "$CERT_DIR/ca.crt" --resolve "gateway.prod.test:18445:127.0.0.1" "https://gateway.prod.test:18445/readyz" >/dev/null 2>&1; then
    READY=1
    break
  fi
  sleep 2
done
if [[ "$READY" != "1" ]]; then
  echo "FAIL: prod-test gateway replicas did not become ready in time" >&2
  exit 1
fi
echo "==> Both replicas are ready over TLS 1.3!"

echo "==> Step 5 (Suite 2): Running Playwright browser E2E against live Keycloak 26..."
if [[ ! -d "$ROOT_DIR/tests/ui-e2e/node_modules/playwright" ]]; then
  (cd "$ROOT_DIR/tests/ui-e2e" && npm install && npx playwright install chromium)
fi
NODE_PATH="$ROOT_DIR/tests/ui-e2e/node_modules" \
  PROD_BASE_URL="https://gateway.prod.test:18443" \
  PROD_AUTH_URL="https://auth.prod.test:18443" \
  PROD_MASTER_ADMIN_KEY="sk-gw-prod-test-master-admin-key-2026-secure" \
  node "$SCRIPT_DIR/prod_ui_keycloak.spec.mjs"

echo "==> Step 6 (Suites 1, 3, 4, 5, 6): Running Go production E2E verification..."
(cd "$ROOT_DIR" && go test -tags=proddocker -v -count=1 ./tests/prod-docker/...)

echo "==> Step 7 (Suite 4d): Scanning container logs for secret leakage..."
GW_LOGS="$(docker compose -f "$COMPOSE_FILE" logs ai-gateway-1 ai-gateway-2 2>&1)"
for secret in \
  "sk-gw-prod-test-master-admin-key-2026-secure" \
  "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90" \
  "prod-test-hmac-session-secret-0123456789abcdef" \
  "goroute-prod-oidc-secret-2026" \
  "prod-test-redis-pass-2026" \
  "prod-test-pg-password-2026"; do
  if echo "$GW_LOGS" | grep -qF "$secret"; then
    echo "FAIL: secret leaked in gateway container logs!" >&2
    exit 1
  fi
done
echo "  PASS: Zero secrets found in gateway container logs."
echo "==> ALL PRODUCTION DOCKER OIDC SUITES (1-6) PASSED!"
