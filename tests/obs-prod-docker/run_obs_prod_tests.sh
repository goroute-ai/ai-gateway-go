#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
COMPOSE_FILE="$ROOT_DIR/deployments/obs-prod-test/docker-compose.obs-prod.yml"
CERT_DIR="$ROOT_DIR/.tmp/obs-prod-certs"
OTEL_DIR="$ROOT_DIR/.tmp/obs-prod-otel"
KEEP_STACK="${KEEP_STACK:-0}"

cleanup() {
  local rc=$?
  if [[ "$rc" -ne 0 ]]; then
    echo "--- Obs-Prod Compose Status ---" >&2
    docker compose -f "$COMPOSE_FILE" ps -a >&2 || true
    echo "--- gateway-migrate logs ---" >&2
    docker compose -f "$COMPOSE_FILE" logs --tail=40 gateway-migrate >&2 || true
    echo "--- otel-collector logs (tail 50) ---" >&2
    docker compose -f "$COMPOSE_FILE" logs --tail=50 otel-collector >&2 || true
    echo "--- ai-gateway-1 logs (tail 60) ---" >&2
    docker compose -f "$COMPOSE_FILE" logs --tail=60 ai-gateway-1 >&2 || true
    echo "--- ai-gateway-2 logs (tail 60) ---" >&2
    docker compose -f "$COMPOSE_FILE" logs --tail=60 ai-gateway-2 >&2 || true
  fi
  if [[ "$KEEP_STACK" == "1" ]]; then
    echo "==> KEEP_STACK=1 set: leaving Docker stack running on https://gateway.prod.test:20443"
  else
    echo "==> Tearing down obs-prod-test Docker stack and ephemeral artifacts..."
    docker compose -f "$COMPOSE_FILE" down -v --remove-orphans >/dev/null 2>&1 || true
    rm -rf "$CERT_DIR" "$OTEL_DIR"
  fi
  exit "$rc"
}
trap cleanup EXIT INT TERM

wait_replicas_ready() {
  echo "==> Waiting for both hardened GoRoute replicas (/readyz via verified TLS 1.3)..."
  for _ in $(seq 1 60); do
    if curl -fsS --cacert "$CERT_DIR/ca.crt" --resolve "gateway.prod.test:20444:127.0.0.1" "https://gateway.prod.test:20444/readyz" >/dev/null 2>&1 \
       && curl -fsS --cacert "$CERT_DIR/ca.crt" --resolve "gateway.prod.test:20445:127.0.0.1" "https://gateway.prod.test:20445/readyz" >/dev/null 2>&1; then
      echo "==> Both replicas are ready over TLS 1.3!"
      return 0
    fi
    sleep 1
  done
  echo "FAIL: obs-prod-test gateway replicas did not become ready in time" >&2
  return 1
}

echo "==> Step 1: Generating ephemeral TLS Root CA, SAN certs, and Mozilla+CA bundle..."
bash "$ROOT_DIR/deployments/obs-prod-test/gen-certs.sh" "$CERT_DIR"

echo "==> Step 2: Preparing writable OTLP JSONL output directory..."
rm -rf "$OTEL_DIR"
mkdir -p "$OTEL_DIR"
touch "$OTEL_DIR/traces.jsonl" "$OTEL_DIR/metrics.jsonl" "$OTEL_DIR/logs.jsonl"
chmod 777 "$OTEL_DIR"
chmod 666 "$OTEL_DIR/traces.jsonl" "$OTEL_DIR/metrics.jsonl" "$OTEL_DIR/logs.jsonl"

echo "==> Step 3: Building production distroless gateway & fixtures images..."
docker compose -f "$COMPOSE_FILE" build gateway-migrate obs-test-fixtures

echo "==> Step 4 (Suite O0): Verifying fail-closed OTLP startup gates in production container..."
assert_startup_fails() {
  local desc="$1"
  local cfg_path="$2"
  shift 2
  local cid
  cid="$(docker run -d "$@" goroute-ai-gateway:obs-prod-test -config "$cfg_path")"
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
  -e GATEWAY_MASTER_ADMIN_KEY=sk-gw-obs-neg-test-master-key-123456
  -e GATEWAY_MASTER_ENCRYPTION_KEY=c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2
  -e GATEWAY_SESSION_SECRET=obs-prod-neg-session-secret-0123456789abcdef0123456789abcdef
)

cat >"$CERT_DIR/unresolved-otel-header.yaml" <<'EOF'
storage:
  mode: "memory"
otel:
  enabled: true
  endpoint: "https://otel.prod.test:20443"
  headers:
    Authorization: "os.environ/MISSING_OTEL_SECRET_VAR"
EOF
assert_startup_fails "unresolved os.environ/ in otel.headers" "/etc/goroute/bad.yaml" \
  -v "$CERT_DIR/unresolved-otel-header.yaml:/etc/goroute/bad.yaml:ro" \
  "${BASE_PROD_ENV[@]}"

assert_startup_fails "invalid otel.traces.sampler=bogus" "" \
  "${BASE_PROD_ENV[@]}" \
  -e GATEWAY_OTEL_ENABLED=true \
  -e OTEL_TRACES_SAMPLER=bogus

echo "==> Step 5 (Suite O0b): Verifying otel.enabled=false emits ZERO OTLP traffic..."
GATEWAY_OTEL_ENABLED=false docker compose -f "$COMPOSE_FILE" up -d
wait_replicas_ready
curl -fsS --cacert "$CERT_DIR/ca.crt" --resolve "gateway.prod.test:20443:127.0.0.1" \
  -H "Authorization: Bearer sk-gw-obs-prod-master-admin-key-2026-secure" \
  "https://gateway.prod.test:20443/admin/v1/observability/metrics" >/dev/null
sleep 2
if [[ -s "$OTEL_DIR/traces.jsonl" || -s "$OTEL_DIR/metrics.jsonl" || -s "$OTEL_DIR/logs.jsonl" ]]; then
  echo "FAIL: otel.enabled=false emitted unexpected OTLP telemetry!" >&2
  ls -la "$OTEL_DIR" >&2
  exit 1
fi
echo "  PASS: Zero OTLP traces/metrics/logs emitted when otel.enabled=false."

echo "==> Step 6 (Suites O1–O6): Enabling 3-signal OTLP/HTTP export across both replicas..."
GATEWAY_OTEL_ENABLED=true docker compose -f "$COMPOSE_FILE" up -d --force-recreate --no-deps ai-gateway-1 ai-gateway-2
wait_replicas_ready

(cd "$ROOT_DIR" && go test -tags=obsproddocker -v -count=1 ./tests/obs-prod-docker/)

echo "==> Step 7 (Suite O3b Log Scan): Scanning all container stdout logs for secret leakage & correlation..."
ALL_LOGS="$(docker compose -f "$COMPOSE_FILE" logs ai-gateway-1 ai-gateway-2 gateway-migrate caddy 2>&1)"
SECRETS_TO_SCAN=(
  "sk-gw-obs-prod-master-admin-key-2026-secure"
  "c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2"
  "obs-prod-hmac-session-secret-0123456789abcdef0123456789abcdef"
  "obs-prod-otel-collector-token-2026"
  "obs-prod-siem-hmac-secret-2026"
  "obs-prod-redis-pass-2026"
  "obs-prod-pg-password-2026"
  "private.user.canary@secret-corp.example"
)
for secret in "${SECRETS_TO_SCAN[@]}"; do
  if echo "$ALL_LOGS" | grep -qF "$secret"; then
    echo "FAIL: secret/PII leaked in container stdout logs!" >&2
    exit 1
  fi
done
if ! echo "$ALL_LOGS" | grep -q '"trace_id"' || ! echo "$ALL_LOGS" | grep -q '"org_id"'; then
  echo "FAIL: expected correlated trace_id and org_id fields in gateway JSON stdout logs!" >&2
  exit 1
fi
echo "  PASS: Zero secrets/PII leaked across container stdout logs and trace_id/org_id correlation verified."
echo "==========================================================================="
echo "  ALL PRODUCTION DOCKER OTLP OBSERVABILITY SUITES (O0–O6) PASSED!          "
echo "==========================================================================="
