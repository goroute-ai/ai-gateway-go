#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
COMPOSE_FILE="$ROOT_DIR/deployments/cache-prod-test/docker-compose.cache-prod.yml"
CERT_DIR="$ROOT_DIR/.tmp/cache-prod-certs"
KEEP_STACK="${KEEP_STACK:-0}"

if [[ -z "${GATEWAY_TEST_GEMINI_API_KEY:-}" ]]; then
  echo "ERROR: GATEWAY_TEST_GEMINI_API_KEY must be set in your shell environment (never committed)." >&2
  echo "Usage: GATEWAY_TEST_GEMINI_API_KEY=\"<key>\" make test-cache-prod-docker" >&2
  exit 1
fi

cleanup() {
  local rc=$?
  if [[ "$rc" -ne 0 ]]; then
    echo "--- Cache-Prod Compose Status ---" >&2
    docker compose -f "$COMPOSE_FILE" ps -a >&2 || true
    echo "--- gateway-migrate logs ---" >&2
    docker compose -f "$COMPOSE_FILE" logs --tail=40 gateway-migrate >&2 || true
    echo "--- ai-gateway-1 logs (tail 60) ---" >&2
    docker compose -f "$COMPOSE_FILE" logs --tail=60 ai-gateway-1 >&2 || true
    echo "--- ai-gateway-2 logs (tail 60) ---" >&2
    docker compose -f "$COMPOSE_FILE" logs --tail=60 ai-gateway-2 >&2 || true
  fi
  if [[ "$KEEP_STACK" == "1" ]]; then
    echo "==> KEEP_STACK=1 set: leaving Docker stack running on https://gateway.prod.test:19443"
  else
    echo "==> Tearing down cache-prod-test Docker stack and ephemeral TLS certs..."
    docker compose -f "$COMPOSE_FILE" down -v --remove-orphans >/dev/null 2>&1 || true
    rm -rf "$CERT_DIR"
  fi
  exit "$rc"
}
trap cleanup EXIT INT TERM

wait_replicas_ready() {
  echo "==> Waiting for both hardened GoRoute replicas (/readyz via verified TLS 1.3)..."
  for _ in $(seq 1 60); do
    if curl -fsS --cacert "$CERT_DIR/ca.crt" --resolve "gateway.prod.test:19444:127.0.0.1" "https://gateway.prod.test:19444/readyz" >/dev/null 2>&1 \
       && curl -fsS --cacert "$CERT_DIR/ca.crt" --resolve "gateway.prod.test:19445:127.0.0.1" "https://gateway.prod.test:19445/readyz" >/dev/null 2>&1; then
      echo "==> Both replicas are ready over TLS 1.3!"
      return 0
    fi
    sleep 1
  done
  echo "FAIL: cache-prod-test gateway replicas did not become ready in time" >&2
  return 1
}

echo "==> Step 1: Generating ephemeral TLS Root CA, SAN certs, and Mozilla+CA bundle..."
bash "$ROOT_DIR/deployments/prod-test/gen-certs.sh" "$CERT_DIR"

echo "==> Step 2: Building production distroless gateway image..."
docker compose -f "$COMPOSE_FILE" build gateway-migrate

echo "==> Step 3 (Suite C0): Verifying fail-closed cache startup gates in production container..."
assert_startup_fails() {
  local desc="$1"
  local cfg_path="$2"
  shift 2
  local cid
  cid="$(docker run -d "$@" goroute-ai-gateway:cache-prod-test -config "$cfg_path")"
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
  -e GATEWAY_MASTER_ADMIN_KEY=sk-gw-cache-neg-test-master-key-123456
  -e GATEWAY_MASTER_ENCRYPTION_KEY=b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90a1
  -e GATEWAY_SESSION_SECRET=prod-cache-neg-session-secret-0123456789abcdef0123456789abcdef
  -e GATEWAY_CACHE_ENABLED=true
)

assert_startup_fails "unknown cache.type=memcached" "" \
  "${BASE_PROD_ENV[@]}" \
  -e GATEWAY_CACHE_TYPE=memcached

assert_startup_fails "cache.type=redis-semantic without embedding_model" "" \
  "${BASE_PROD_ENV[@]}" \
  -e GATEWAY_CACHE_TYPE=redis-semantic \
  -e GATEWAY_CACHE_REDIS_ADDR=redis-cache:6379

assert_startup_fails "cache.type=redis-semantic with invalid similarity_threshold=1.5" "" \
  "${BASE_PROD_ENV[@]}" \
  -e GATEWAY_CACHE_TYPE=redis-semantic \
  -e GATEWAY_CACHE_REDIS_ADDR=redis-cache:6379 \
  -e GATEWAY_CACHE_SEMANTIC_EMBEDDING_MODEL=gemini-embedding-001 \
  -e GATEWAY_CACHE_SEMANTIC_SIMILARITY_THRESHOLD=1.5

assert_startup_fails "cache.type=redis-semantic with invalid vector_algorithm=IVF" "" \
  "${BASE_PROD_ENV[@]}" \
  -e GATEWAY_CACHE_TYPE=redis-semantic \
  -e GATEWAY_CACHE_REDIS_ADDR=redis-cache:6379 \
  -e GATEWAY_CACHE_SEMANTIC_EMBEDDING_MODEL=gemini-embedding-001 \
  -e GATEWAY_CACHE_SEMANTIC_VECTOR_ALGORITHM=IVF

cat >"$CERT_DIR/no-redis.yaml" <<'EOF'
storage:
  mode: "memory"
  redis_addr: ""
cache:
  enabled: true
  type: "redis"
EOF
assert_startup_fails "cache.type=redis without any redis_addr" "/etc/goroute/no-redis.yaml" \
  -v "$CERT_DIR/no-redis.yaml:/etc/goroute/no-redis.yaml:ro" \
  "${BASE_PROD_ENV[@]}" \
  -e GATEWAY_CACHE_TYPE=redis

echo "==> Step 4 (Phase 1 — Suite C1): Booting stack with cache.type=local (max_entries=4)..."
GATEWAY_CACHE_TYPE=local \
GATEWAY_CACHE_MAX_ENTRIES=4 \
GATEWAY_CACHE_EXCLUDED_CALL_TYPES=embedding \
  docker compose -f "$COMPOSE_FILE" up -d
wait_replicas_ready
(cd "$ROOT_DIR" && go test -tags=cacheproddocker -v -count=1 -run "^TestCacheProd_SuiteC1_LocalMode$" ./tests/cache-prod-docker/)

echo "==> Step 5 (Phase 2 — Suite C2): Switching replicas to cache.type=redis (dedicated redis-cache)..."
GATEWAY_CACHE_TYPE=redis \
GATEWAY_CACHE_EXCLUDED_CALL_TYPES=embedding \
  docker compose -f "$COMPOSE_FILE" up -d --force-recreate --no-deps ai-gateway-1 ai-gateway-2
wait_replicas_ready
(cd "$ROOT_DIR" && go test -tags=cacheproddocker -v -count=1 -run "^TestCacheProd_SuiteC2_RedisKV_HA$" ./tests/cache-prod-docker/)

echo "==> Step 5b (Phase 2b — Suite C2b): Opt-in embeddings caching (excluded_call_types=[])..."
GATEWAY_CACHE_TYPE=redis \
GATEWAY_CACHE_EXCLUDED_CALL_TYPES="" \
  docker compose -f "$COMPOSE_FILE" up -d --force-recreate --no-deps ai-gateway-1 ai-gateway-2
wait_replicas_ready
(cd "$ROOT_DIR" && go test -tags=cacheproddocker -v -count=1 -run "^TestCacheProd_SuiteC2b_RedisKV_EmbeddingsOptIn$" ./tests/cache-prod-docker/)

echo "==> Step 6 (Phase 3 — Suites C3, C4, C5, C6): Switching replicas to cache.type=redis-semantic (HNSW)..."
GATEWAY_CACHE_TYPE=redis-semantic \
GATEWAY_CACHE_EXCLUDED_CALL_TYPES=embedding \
GATEWAY_CACHE_SEMANTIC_EMBEDDING_MODEL=gemini-embedding-001 \
GATEWAY_CACHE_SEMANTIC_SIMILARITY_THRESHOLD=0.85 \
GATEWAY_CACHE_SEMANTIC_INDEX_NAME=gw_semantic_cache_idx \
GATEWAY_CACHE_SEMANTIC_VECTOR_ALGORITHM=HNSW \
GATEWAY_CACHE_SEMANTIC_MAX_MESSAGES=4 \
  docker compose -f "$COMPOSE_FILE" up -d --force-recreate --no-deps ai-gateway-1 ai-gateway-2
wait_replicas_ready
(cd "$ROOT_DIR" && go test -tags=cacheproddocker -v -count=1 -run "^TestCacheProd_SuiteC(3_RedisSemantic_HNSW_LiveGemini|4_ChaosFailOpenAndRecovery|5_ConcurrencyFinOpsAndMetrics|6_ConfigRedactionAndCORS)$" ./tests/cache-prod-docker/)

echo "==> Step 7 (Phase 4): Verifying cache.type=redis-semantic with vector_algorithm=FLAT..."
GATEWAY_CACHE_TYPE=redis-semantic \
GATEWAY_CACHE_EXCLUDED_CALL_TYPES=embedding \
GATEWAY_CACHE_SEMANTIC_EMBEDDING_MODEL=gemini-embedding-001 \
GATEWAY_CACHE_SEMANTIC_SIMILARITY_THRESHOLD=0.85 \
GATEWAY_CACHE_SEMANTIC_INDEX_NAME=gw_semantic_flat_idx \
GATEWAY_CACHE_SEMANTIC_VECTOR_ALGORITHM=FLAT \
GATEWAY_CACHE_SEMANTIC_MAX_MESSAGES=4 \
  docker compose -f "$COMPOSE_FILE" up -d --force-recreate --no-deps ai-gateway-1 ai-gateway-2
wait_replicas_ready
(cd "$ROOT_DIR" && go test -tags=cacheproddocker -v -count=1 -run "^TestCacheProd_Phase4_RedisSemantic_FLAT$" ./tests/cache-prod-docker/)

echo "==> Step 8 (Suite C6 Log Scan): Scanning all container logs for secret leakage..."
ALL_LOGS="$(docker compose -f "$COMPOSE_FILE" logs ai-gateway-1 ai-gateway-2 gateway-migrate caddy 2>&1)"
SECRETS_TO_SCAN=(
  "sk-gw-cache-prod-master-admin-key-2026-secure"
  "b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90a1"
  "prod-cache-hmac-session-secret-0123456789abcdef0123456789abcdef"
  "prod-cache-primary-pass-2026"
  "prod-cache-dedicated-pass-2026"
  "prod-cache-pg-password-2026"
  "$GATEWAY_TEST_GEMINI_API_KEY"
)
for secret in "${SECRETS_TO_SCAN[@]}"; do
  if echo "$ALL_LOGS" | grep -qF "$secret"; then
    echo "FAIL: secret leaked in container logs!" >&2
    exit 1
  fi
done
echo "  PASS: Zero internal or live Gemini secrets found across all container logs."
echo "==========================================================================="
echo "  ALL PRODUCTION DOCKER CACHING SUITES (C0–C6 + FLAT) PASSED!              "
echo "==========================================================================="
