#!/usr/bin/env bash
set -euo pipefail

UI_E2E_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$UI_E2E_DIR/../.." && pwd)"

POSTGRES_DSN="${GATEWAY_POSTGRES_DSN:-postgres://gateway:gateway@localhost:15432/aigateway_test?sslmode=disable}"
REDIS_ADDR="${GATEWAY_REDIS_ADDR:-localhost:16379}"

pick_free_port() {
  node -e 'const net=require("node:net"); const s=net.createServer(); s.listen(0,"127.0.0.1",()=>{console.log(s.address().port); s.close();});'
}

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/goroute-ui-e2e.XXXXXX")"
GW_PID=""
IDP_PID=""

cleanup() {
  local rc=$?
  if [[ -n "$GW_PID" ]]; then
    kill "$GW_PID" >/dev/null 2>&1 || true
    wait "$GW_PID" >/dev/null 2>&1 || true
  fi
  if [[ -n "$IDP_PID" ]]; then
    kill "$IDP_PID" >/dev/null 2>&1 || true
    wait "$IDP_PID" >/dev/null 2>&1 || true
  fi
  if [[ "$rc" -ne 0 ]]; then
    echo "--- Gateway log tail ---" >&2
    tail -n 60 "$TMP_DIR/gateway.log" >&2 || true
    echo "--- Mock IdP log tail ---" >&2
    tail -n 40 "$TMP_DIR/mock_idp.log" >&2 || true
  fi
  rm -rf "$TMP_DIR"
  exit "$rc"
}
trap cleanup EXIT INT TERM

if [[ ! -d "$UI_E2E_DIR/node_modules/playwright" ]]; then
  echo "==> Installing Playwright dependencies in $UI_E2E_DIR..."
  (cd "$UI_E2E_DIR" && npm install && npx playwright install chromium)
fi

MOCK_IDP_PORT="$(pick_free_port)"
GW_PORT="$(pick_free_port)"

ADMIN_KEY="sk-gw-uie2e-$(openssl rand -hex 20)"
ENC_KEY="$(openssl rand -hex 32)"
JWT_SECRET="$(openssl rand -hex 32)"
SESSION_SECRET="$(openssl rand -hex 32)"
UI_USERNAME="ui-admin"
UI_PASSWORD="UiE2eStrong!Pass-$(openssl rand -hex 8)"

echo "==> Starting Mock OIDC/HIBP server on 127.0.0.1:${MOCK_IDP_PORT}..."
MOCK_IDP_PORT="$MOCK_IDP_PORT" node "$UI_E2E_DIR/mock_idp.mjs" >"$TMP_DIR/mock_idp.log" 2>&1 &
IDP_PID=$!

for _ in $(seq 1 30); do
  if curl -fsS "http://127.0.0.1:${MOCK_IDP_PORT}/healthz" >/dev/null 2>&1; then
    break
  fi
  sleep 0.2
done
curl -fsS "http://127.0.0.1:${MOCK_IDP_PORT}/healthz" >/dev/null

cat >"$TMP_DIR/config.yaml" <<EOF
server:
  environment: "development"
  host: "127.0.0.1"
  port: ${GW_PORT}
  grpc_port: 0

logging:
  level: "info"
  format: "json"

storage:
  mode: "postgres"
  postgres_dsn: "${POSTGRES_DSN}"
  redis_addr: "${REDIS_ADDR}"
  redis_db: 0

auth:
  master_admin_key: "${ADMIN_KEY}"
  master_encryption_key: "${ENC_KEY}"
  allow_master_key_data_plane: false
  enable_data_plane_jwt: true
  jwt_secret: "${JWT_SECRET}"
  jwt_issuer: "http://127.0.0.1:${MOCK_IDP_PORT}/oidc"
  jwt_audience: "goroute-ui-client"
  ui_username: "${UI_USERNAME}"
  ui_password: "${UI_PASSWORD}"
  session_secret: "${SESSION_SECRET}"
  enable_hibp_check: true
  hibp_base_url: "http://127.0.0.1:${MOCK_IDP_PORT}/hibp/range"
  sso_providers:
    - id: "corp-oidc"
      display_name: "Corporate OIDC"
      type: "oidc"
      client_id: "goroute-ui-client"
      client_secret: "mock-ui-client-secret"
      issuer: "http://127.0.0.1:${MOCK_IDP_PORT}/oidc"
      discovery_url: "http://127.0.0.1:${MOCK_IDP_PORT}/oidc/.well-known/openid-configuration"
      redirect_url: "http://localhost:${GW_PORT}/auth/sso/corp-oidc/callback"

rate_limit:
  enabled: true
  fallback_to_local_on_outage: false

security:
  network:
    outbound_ssrf:
      allow_private_networks: true
      allow_insecure_http: true
      allowed_schemes:
        - "http"
        - "https"
EOF

echo "==> Building gateway binary for headless UI E2E..."
(cd "$ROOT_DIR" && go build -o "$TMP_DIR/ai-gateway" ./cmd/gateway)

echo "==> Running PostgreSQL migrations..."
"$TMP_DIR/ai-gateway" -config "$TMP_DIR/config.yaml" -migrate-only >/dev/null

echo "==> Starting GoRoute gateway on http://localhost:${GW_PORT}..."
"$TMP_DIR/ai-gateway" -config "$TMP_DIR/config.yaml" >"$TMP_DIR/gateway.log" 2>&1 &
GW_PID=$!

READY=0
for _ in $(seq 1 60); do
  if curl -fsS "http://127.0.0.1:${GW_PORT}/readyz" >/dev/null 2>&1; then
    READY=1
    break
  fi
  sleep 0.5
done
if [[ "$READY" != "1" ]]; then
  echo "FAIL: gateway did not become ready on :${GW_PORT}" >&2
  exit 1
fi

echo "==> Executing Playwright Chromium Operator Web UI suite..."
(
  cd "$UI_E2E_DIR"
  UI_E2E_BASE_URL="http://localhost:${GW_PORT}" \
  UI_E2E_ADMIN_KEY="$ADMIN_KEY" \
  UI_E2E_USERNAME="$UI_USERNAME" \
  UI_E2E_PASSWORD="$UI_PASSWORD" \
  UI_E2E_MOCK_IDP_URL="http://127.0.0.1:${MOCK_IDP_PORT}" \
  node operator_ui.spec.mjs
)
