#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PROD_COMPOSE="$ROOT_DIR/deployments/docker-compose.prod-test.yml"
TEST_COMPOSE="$ROOT_DIR/deployments/docker-compose.test.yml"
RUN_DIR="${GOROUTE_PROD_RUN_DIR:-/tmp/goroute-prod-test}"
BASE_HTTPS="https://localhost:28443"
BASE_HTTP="http://localhost:28080"
PROM_URL="http://localhost:19090"

PHASE_FILTER="all"
KEEP_STACK=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --phase)
      PHASE_FILTER="${2:-all}"
      shift 2
      ;;
    --keep-stack)
      KEEP_STACK=1
      shift
      ;;
    *)
      echo "Unknown argument: $1" >&2
      exit 2
      ;;
  esac
done

cd "$ROOT_DIR"

should_run_phase() {
  local p="$1"
  [[ "$PHASE_FILTER" == "all" || "$PHASE_FILTER" == "$p" ]]
}

ensure_runtime_env() {
  mkdir -p "$RUN_DIR/tls"
  chmod 0700 "$RUN_DIR" || true

  if [[ ! -f "$RUN_DIR/.env" ]]; then
    local pg_pass redis_pass admin_key enc_key jwt_sec
    pg_pass="$(openssl rand -hex 20)"
    redis_pass="$(openssl rand -hex 20)"
    admin_key="sk-gw-prodtest-$(openssl rand -hex 24)"
    enc_key="$(openssl rand -hex 32)"
    jwt_sec="$(openssl rand -hex 32)"
    cat >"$RUN_DIR/.env" <<EOF
POSTGRES_PASSWORD=$pg_pass
REDIS_PASSWORD=$redis_pass
GATEWAY_MASTER_ADMIN_KEY=$admin_key
GATEWAY_MASTER_ENCRYPTION_KEY=$enc_key
GATEWAY_JWT_SECRET=$jwt_sec
EOF
    chmod 0600 "$RUN_DIR/.env"
    printf '%s' "$admin_key" >"$RUN_DIR/prom_token"
    chmod 0644 "$RUN_DIR/prom_token"
  fi

  set -a
  # shellcheck disable=SC1090
  source "$RUN_DIR/.env"
  set +a
  export GOROUTE_PROD_RUN_DIR="$RUN_DIR"

  if [[ ! -f "$RUN_DIR/tls/.tls-ready" ]]; then
    echo "==> Generating ephemeral PKI CA and TLS SAN certificates in $RUN_DIR/tls..."
    rm -f "$RUN_DIR/tls/"*
    openssl req -x509 -newkey rsa:2048 -nodes -days 7 \
      -keyout "$RUN_DIR/tls/ca.key" \
      -out "$RUN_DIR/tls/ca.crt" \
      -subj "/CN=GoRoute-ProdTest-CA" >/dev/null 2>&1

    gen_leaf_cert() {
      local name="$1"
      local san="$2"
      openssl req -newkey rsa:2048 -nodes \
        -keyout "$RUN_DIR/tls/${name}.key" \
        -out "$RUN_DIR/tls/${name}.csr" \
        -subj "/CN=${name}" >/dev/null 2>&1
      cat >"$RUN_DIR/tls/${name}.ext" <<EOF
subjectAltName=${san}
extendedKeyUsage=serverAuth
EOF
      openssl x509 -req -in "$RUN_DIR/tls/${name}.csr" \
        -CA "$RUN_DIR/tls/ca.crt" -CAkey "$RUN_DIR/tls/ca.key" -CAcreateserial \
        -out "$RUN_DIR/tls/${name}.crt" -days 7 \
        -extfile "$RUN_DIR/tls/${name}.ext" >/dev/null 2>&1
    }

    gen_leaf_cert "mock-upstream" "DNS:mock-upstream,IP:172.29.10.20,IP:127.0.0.1"
    gen_leaf_cert "otel-collector" "DNS:otel-collector,IP:172.29.10.30,IP:127.0.0.1"
    gen_leaf_cert "nginx-lb" "DNS:localhost,DNS:nginx-lb,IP:127.0.0.1"

    # Combine Distroless system CAs (if image exists) + ephemeral CA so both public and test TLS work.
    if docker image inspect goroute/ai-gateway:prod-test >/dev/null 2>&1; then
      local tmp_cid
      tmp_cid="$(docker create goroute/ai-gateway:prod-test)"
      docker cp "$tmp_cid:/etc/ssl/certs/ca-certificates.crt" "$RUN_DIR/tls/ca-bundle.crt" >/dev/null 2>&1 || true
      docker rm "$tmp_cid" >/dev/null 2>&1 || true
      chmod 0644 "$RUN_DIR/tls/ca-bundle.crt" 2>/dev/null || true
    fi
    cat "$RUN_DIR/tls/ca.crt" >>"$RUN_DIR/tls/ca-bundle.crt"
    chmod 0644 "$RUN_DIR/tls/"*
    touch "$RUN_DIR/tls/.tls-ready"
  fi
}

cleanup() {
  if [[ "$KEEP_STACK" == "1" ]]; then
    echo "==> --keep-stack set; leaving goroute-prod-test running."
    return 0
  fi
  echo "==> Cleaning up prod-test and ephemeral test stacks..."
  POSTGRES_PASSWORD="${POSTGRES_PASSWORD:-down}" \
  REDIS_PASSWORD="${REDIS_PASSWORD:-down}" \
  GATEWAY_MASTER_ADMIN_KEY="${GATEWAY_MASTER_ADMIN_KEY:-down-placeholder}" \
  GATEWAY_MASTER_ENCRYPTION_KEY="${GATEWAY_MASTER_ENCRYPTION_KEY:-down-placeholder-down-placeholder}" \
  GATEWAY_JWT_SECRET="${GATEWAY_JWT_SECRET:-down-placeholder}" \
  docker compose -f "$PROD_COMPOSE" down -v --remove-orphans >/dev/null 2>&1 || true
  docker compose -f "$TEST_COMPOSE" --profile fullstack down -v --remove-orphans >/dev/null 2>&1 || true
  if [[ -f "$RUN_DIR/state.env" ]]; then
    rm -f "$RUN_DIR/state.env"
  fi
}
trap cleanup EXIT

curl_tls() {
  curl --cacert "$RUN_DIR/tls/ca.crt" "$@"
}

assert_eq() {
  local got="$1" want="$2" msg="$3"
  if [[ "$got" != "$want" ]]; then
    echo "FAIL: $msg (got='$got', want='$want')" >&2
    exit 1
  fi
}

load_state() {
  if [[ -f "$RUN_DIR/state.env" ]]; then
    # shellcheck disable=SC1090
    source "$RUN_DIR/state.env"
  fi
}

provision_fixture_tenant() {
  ensure_runtime_env
  load_state
  if [[ -n "${VIRTUAL_KEY:-}" && -n "${ORG_ID:-}" ]]; then
    return 0
  fi

  local ts
  ts="$(date +%s)"
  local hdr_auth="Authorization: Bearer ${GATEWAY_MASTER_ADMIN_KEY}"
  local hdr_json="Content-Type: application/json"

  echo "==> Seeding fixture organization, tenant, credentials, model groups, MCP, A2A..."
  ORG_ID="$(curl_tls -fsS -X POST "$BASE_HTTPS/admin/v1/organizations" -H "$hdr_auth" -H "$hdr_json" \
    -d "{\"name\":\"ProdTestOrg\",\"slug\":\"prod-test-${ts}\",\"max_budget_micros\":1000000000}" | jq -r '.id')"
  [[ -n "$ORG_ID" && "$ORG_ID" != "null" ]]

  TEAM_ID="$(curl_tls -fsS -X POST "$BASE_HTTPS/admin/v1/teams" -H "$hdr_auth" -H "$hdr_json" \
    -d "{\"org_id\":\"$ORG_ID\",\"name\":\"CorePlatform\"}" | jq -r '.id')"
  USER_ID="$(curl_tls -fsS -X POST "$BASE_HTTPS/admin/v1/users" -H "$hdr_auth" -H "$hdr_json" \
    -d "{\"org_id\":\"$ORG_ID\",\"team_id\":\"$TEAM_ID\",\"email\":\"prod-runner-${ts}@goroute.local\",\"role\":\"developer\"}" | jq -r '.id')"

  for prov in openai anthropic ollama; do
    curl_tls -fsS -X POST "$BASE_HTTPS/admin/v1/organizations/$ORG_ID/subscriptions" -H "$hdr_auth" -H "$hdr_json" \
      -d "{\"provider\":\"$prov\",\"is_enabled\":true}" >/dev/null
  done

  curl_tls -fsS -X POST "$BASE_HTTPS/admin/v1/catalogue/import" -H "$hdr_auth" >/dev/null

  CRED_OPENAI="$(curl_tls -fsS -X POST "$BASE_HTTPS/admin/v1/credentials" -H "$hdr_auth" -H "$hdr_json" \
    -d "{\"org_id\":\"$ORG_ID\",\"provider\":\"openai\",\"name\":\"mock-openai\",\"base_url\":\"https://mock-upstream:8443/v1\",\"api_key\":\"sk-mock-openai\"}" | jq -r '.id')"
  CRED_ANT="$(curl_tls -fsS -X POST "$BASE_HTTPS/admin/v1/credentials" -H "$hdr_auth" -H "$hdr_json" \
    -d "{\"org_id\":\"$ORG_ID\",\"provider\":\"anthropic\",\"name\":\"mock-ant\",\"base_url\":\"https://mock-upstream:8443\",\"api_key\":\"sk-mock-ant\"}" | jq -r '.id')"
  CRED_OLLAMA="$(curl_tls -fsS -X POST "$BASE_HTTPS/admin/v1/credentials" -H "$hdr_auth" -H "$hdr_json" \
    -d "{\"org_id\":\"$ORG_ID\",\"provider\":\"ollama\",\"name\":\"mock-ollama\",\"base_url\":\"https://mock-upstream:8443\",\"api_key\":\"ollama-local\"}" | jq -r '.id')"

  # Sync models from mock-upstream (/v1/models, /api/tags) so mock IDs exist in global_models
  curl_tls -fsS -X POST "$BASE_HTTPS/admin/v1/catalogue/sync" -H "$hdr_auth" >/dev/null

  # Ensure verified pricing on key test models so FinOps cost_micros > 0
  for mid in "openai/gpt-4o-mini" "openai/text-embedding-3-small" "openai/gpt-image-1.5" "openai/tts-1" "anthropic/claude-sonnet-4-20250514" "ollama/llama3.2:1b"; do
    curl_tls -s -o /dev/null -X POST "$BASE_HTTPS/admin/v1/catalogue/pricing" -H "$hdr_auth" -H "$hdr_json" \
      -d "{\"global_model_id\":\"$mid\",\"input_cost_micros_per_1m\":150000,\"output_cost_micros_per_1m\":600000,\"pricing_status\":\"verified\"}" || true
  done

  create_routed_model() {
    local alias="$1" gid="$2" cid="$3" depname="$4"
    local mgid
    mgid="$(curl_tls -fsS -X POST "$BASE_HTTPS/admin/v1/model-groups" -H "$hdr_auth" -H "$hdr_json" \
      -d "{\"org_id\":\"$ORG_ID\",\"alias\":\"$alias\",\"routing_strategy\":\"weighted-shuffle\"}" | jq -r '.id')"
    curl_tls -fsS -X POST "$BASE_HTTPS/admin/v1/deployments" -H "$hdr_auth" -H "$hdr_json" \
      -d "{\"model_group_id\":\"$mgid\",\"global_model_id\":\"$gid\",\"credential_id\":\"$cid\",\"deployment_name\":\"$depname\",\"weight\":100}" >/dev/null
  }

  create_routed_model "prod-chat" "openai/gpt-4o-mini" "$CRED_OPENAI" "gpt-4o-mini"
  create_routed_model "prod-embed" "openai/text-embedding-3-small" "$CRED_OPENAI" "text-embedding-3-small"
  create_routed_model "prod-image" "openai/gpt-image-1.5" "$CRED_OPENAI" "gpt-image-1.5"
  create_routed_model "prod-tts" "openai/tts-1" "$CRED_OPENAI" "tts-1"
  create_routed_model "prod-anthropic" "anthropic/claude-sonnet-4-20250514" "$CRED_ANT" "claude-sonnet-4-20250514"
  create_routed_model "prod-ollama" "ollama/llama3.2:1b" "$CRED_OLLAMA" "llama3.2:1b"

  # Register mock MCP server & sync tools
  local mcp_id
  mcp_id="$(curl_tls -fsS -X POST "$BASE_HTTPS/admin/v1/mcp/servers" -H "$hdr_auth" -H "$hdr_json" \
    -d "{\"org_id\":\"$ORG_ID\",\"name\":\"MockMCP\",\"slug\":\"mock-mcp\",\"transport_type\":\"streamable_http\",\"endpoint_url\":\"https://mock-upstream:8443/mcp\",\"auth_type\":\"none\"}" | jq -r '.server.id // .id')"
  curl_tls -fsS -X POST "$BASE_HTTPS/admin/v1/mcp/servers/$mcp_id/sync" -H "$hdr_auth" >/dev/null

  # Register mock A2A agent
  local card_json
  card_json='{"name":"mock-a2a","url":"https://mock-upstream:8443/a2a","version":"1.0.0","protocolVersions":["1.0"],"skills":[{"id":"echo","name":"Echo"}]}'
  curl_tls -fsS -X POST "$BASE_HTTPS/admin/v1/a2a/agents" -H "$hdr_auth" -H "$hdr_json" \
    -d "$(jq -nc --arg oid "$ORG_ID" --arg card "$card_json" '{org_id:$oid,name:"MockA2AAgent",slug:"mock-a2a",endpoint_url:"https://mock-upstream:8443/a2a",agent_card_json:$card,task_visibility_mode:"org_admin"}')" >/dev/null

  local vk_json burst_json rotate_json unbudgeted_json
  vk_json="$(curl_tls -fsS -X POST "$BASE_HTTPS/admin/v1/keys" -H "$hdr_auth" -H "$hdr_json" \
    -d "{\"org_id\":\"$ORG_ID\",\"team_id\":\"$TEAM_ID\",\"user_id\":\"$USER_ID\",\"name\":\"prod-main-key\",\"role\":\"developer\",\"allowed_mcp_servers\":[\"*\"],\"allowed_a2a_agents\":[\"*\"],\"rpm_limit\":500000,\"tpm_limit\":100000000,\"max_budget_micros\":500000000}")"
  VIRTUAL_KEY="$(echo "$vk_json" | jq -r '.raw_key')"
  VIRTUAL_KEY_ID="$(echo "$vk_json" | jq -r '.id')"

  burst_json="$(curl_tls -fsS -X POST "$BASE_HTTPS/admin/v1/keys" -H "$hdr_auth" -H "$hdr_json" \
    -d "{\"org_id\":\"$ORG_ID\",\"name\":\"prod-burst-key\",\"role\":\"developer\",\"rpm_limit\":4,\"tpm_limit\":100000,\"max_budget_micros\":50000000}")"
  BURST_KEY="$(echo "$burst_json" | jq -r '.raw_key')"

  rotate_json="$(curl_tls -fsS -X POST "$BASE_HTTPS/admin/v1/keys" -H "$hdr_auth" -H "$hdr_json" \
    -d "{\"org_id\":\"$ORG_ID\",\"name\":\"prod-rotate-key\",\"role\":\"developer\",\"rpm_limit\":100,\"tpm_limit\":100000,\"max_budget_micros\":50000000}")"
  ROTATE_KEY="$(echo "$rotate_json" | jq -r '.raw_key')"
  ROTATE_KEY_ID="$(echo "$rotate_json" | jq -r '.id')"

  local unbudgeted_org_id
  unbudgeted_org_id="$(curl_tls -fsS -X POST "$BASE_HTTPS/admin/v1/organizations" -H "$hdr_auth" -H "$hdr_json" \
    -d "{\"name\":\"ProdUnbudgetedOrg\",\"slug\":\"prod-unbudgeted-${ts}\",\"max_budget_micros\":0}" | jq -r '.id')"
  curl_tls -fsS -X POST "$BASE_HTTPS/admin/v1/organizations/$unbudgeted_org_id/subscriptions" -H "$hdr_auth" -H "$hdr_json" \
    -d '{"provider":"openai","is_enabled":true}' >/dev/null
  unbudgeted_json="$(curl_tls -fsS -X POST "$BASE_HTTPS/admin/v1/keys" -H "$hdr_auth" -H "$hdr_json" \
    -d "{\"org_id\":\"$unbudgeted_org_id\",\"name\":\"prod-unbudgeted-key\",\"role\":\"developer\",\"rpm_limit\":100,\"tpm_limit\":100000,\"max_budget_micros\":0}")"
  UNBUDGETED_KEY="$(echo "$unbudgeted_json" | jq -r '.raw_key')"

  cat >"$RUN_DIR/state.env" <<EOF
ORG_ID=$ORG_ID
TEAM_ID=$TEAM_ID
USER_ID=$USER_ID
CRED_OPENAI=$CRED_OPENAI
VIRTUAL_KEY=$VIRTUAL_KEY
VIRTUAL_KEY_ID=$VIRTUAL_KEY_ID
BURST_KEY=$BURST_KEY
ROTATE_KEY=$ROTATE_KEY
ROTATE_KEY_ID=$ROTATE_KEY_ID
UNBUDGETED_KEY=$UNBUDGETED_KEY
EOF
}

phase_1() {
  echo "======================================================================"
  echo "  PHASE 1: Static Checks, UI Parity, Docker Builds & Supply-Chain"
  echo "======================================================================"
  test -z "$(gofmt -l .)"
  go vet ./...
  go run ./cmd/specgen -root .
  diff -rq web/dist internal/ui/dist
  node web/scripts/check-budget.mjs

  echo "==> Running Gitleaks secret scan (--no-git)..."
  gitleaks detect --source=. --config=.gitleaks.toml --no-git

  echo "==> Building hardened Distroless images (ai-gateway & mock-upstream)..."
  docker build -t goroute/ai-gateway:prod-test -f deployments/Dockerfile .
  docker build -t goroute/mock-upstream:prod-test -f tests/fixtures/mock-upstream/Dockerfile .

  echo "==> Running containerized govulncheck..."
  docker run --rm -v "$ROOT_DIR:/src:ro" -w /src golang:alpine \
    sh -c 'apk add --no-cache git >/dev/null && go install golang.org/x/vuln/cmd/govulncheck@latest && govulncheck ./...'

  echo "==> Running containerized Trivy image + deployment IaC scans..."
  docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
    aquasec/trivy:latest image --severity HIGH,CRITICAL --ignore-unfixed --exit-code 1 --scanners vuln goroute/ai-gateway:prod-test || {
      echo "WARN: fixable HIGH found; enforcing strict CRITICAL exit gate..."
      docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
        aquasec/trivy:latest image --severity CRITICAL --exit-code 1 --scanners vuln goroute/ai-gateway:prod-test
    }
  docker run --rm -v "$ROOT_DIR:/repo:ro" \
    aquasec/trivy:latest config --severity CRITICAL --exit-code 1 /repo/deployments
  echo "==> Phase 1 PASSED."
}

phase_2() {
  echo "======================================================================"
  echo "  PHASE 2: Strict Production Boot, Negative Key Check & Hardening"
  echo "======================================================================"
  if ! docker image inspect goroute/ai-gateway:prod-test >/dev/null 2>&1; then
    docker build -t goroute/ai-gateway:prod-test -f deployments/Dockerfile .
  fi
  if ! docker image inspect goroute/mock-upstream:prod-test >/dev/null 2>&1; then
    docker build -t goroute/mock-upstream:prod-test -f tests/fixtures/mock-upstream/Dockerfile .
  fi

  ensure_runtime_env

  echo "==> Negative test: asserting production boot refuses default master_encryption_key..."
  local neg_out
  set +e
  neg_out="$(docker run --rm \
    -v "$ROOT_DIR/configs/config.prod-test.yaml:/etc/goroute/config.yaml:ro" \
    -e GATEWAY_ENV=production \
    -e GATEWAY_POSTGRES_DSN="postgres://gateway:pass@127.0.0.1:5432/db?sslmode=disable" \
    -e GATEWAY_MASTER_ADMIN_KEY="$GATEWAY_MASTER_ADMIN_KEY" \
    -e GATEWAY_MASTER_ENCRYPTION_KEY="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" \
    -e GATEWAY_JWT_SECRET="$GATEWAY_JWT_SECRET" \
    goroute/ai-gateway:prod-test -config /etc/goroute/config.yaml 2>&1)"
  local neg_rc=$?
  set -e
  if [[ "$neg_rc" -eq 0 ]]; then
    echo "FAIL: gateway started despite default master_encryption_key in production!" >&2
    exit 1
  fi
  echo "$neg_out" | grep -q "cannot be the default key"

  echo "==> Booting 2-replica HA production-like stack..."
  rm -f "$RUN_DIR/state.env"
  docker compose -f "$PROD_COMPOSE" up -d --wait

  echo "==> Checking Distroless container hardening invariants on ai-gateway-1 & ai-gateway-2..."
  for svc in ai-gateway-1 ai-gateway-2; do
    local cid user ro caps nonewpriv
    cid="$(docker compose -f "$PROD_COMPOSE" ps -q "$svc")"
    user="$(docker inspect -f '{{.Config.User}}' "$cid")"
    ro="$(docker inspect -f '{{.HostConfig.ReadonlyRootfs}}' "$cid")"
    caps="$(docker inspect -f '{{json .HostConfig.CapDrop}}' "$cid")"
    nonewpriv="$(docker inspect -f '{{json .HostConfig.SecurityOpt}}' "$cid")"
    assert_eq "$user" "65532:65532" "$svc nonroot UID/GID"
    assert_eq "$ro" "true" "$svc ReadonlyRootfs"
    echo "$caps" | grep -q "ALL"
    echo "$nonewpriv" | grep -q "no-new-privileges:true"
  done

  echo "==> Verifying structured JSON logs on stdout..."
  docker compose -f "$PROD_COMPOSE" logs --no-color --tail=20 ai-gateway-1 | grep -q '"level":"INFO"'
  echo "==> Phase 2 PASSED."
}

phase_3() {
  echo "======================================================================"
  echo "  PHASE 3: Live Postgres + Redis Integration & Strict Go E2E Suites"
  echo "======================================================================"
  docker compose -f "$TEST_COMPOSE" up -d --wait
  make test-postgres
  make test-e2e-strict
  docker compose -f "$TEST_COMPOSE" down -v >/dev/null 2>&1 || true
  echo "==> Phase 3 PASSED."
}

phase_4() {
  echo "======================================================================"
  echo "  PHASE 4: Security Headers, Auth Scoping & Remediated SSRF Checks"
  echo "======================================================================"
  ensure_runtime_env
  provision_fixture_tenant
  local hdr_auth="Authorization: Bearer ${GATEWAY_MASTER_ADMIN_KEY}"

  echo "==> Verifying TLS edge security headers & X-Request-Id sanitization..."
  local api_hdrs ui_hdrs
  api_hdrs="$(curl_tls -fsS -D - -o /dev/null -H "Authorization: Bearer $VIRTUAL_KEY" -H 'X-Request-Id: evil<script>alert(1)</script>' "$BASE_HTTPS/v1/models" | tr -d '\r')"
  echo "$api_hdrs" | grep -iq '^x-frame-options: DENY'
  echo "$api_hdrs" | grep -iq '^x-content-type-options: nosniff'
  echo "$api_hdrs" | grep -iq '^strict-transport-security:'
  echo "$api_hdrs" | grep -iq "^content-security-policy: default-src 'none'"
  if echo "$api_hdrs" | grep -q '<script>'; then
    echo "FAIL: unsanitized <script> echoed in X-Request-Id header" >&2
    exit 1
  fi

  ui_hdrs="$(curl_tls -fsS -D - -o /dev/null "$BASE_HTTPS/ui/" | tr -d '\r')"
  echo "$ui_hdrs" | grep -iq "^content-security-policy:.*script-src 'self'"

  echo "==> Verifying /metrics and /admin/v1 RBAC isolation..."
  assert_eq "$(curl_tls -s -o /dev/null -w '%{http_code}' "$BASE_HTTPS/metrics")" "401" "unauthenticated /metrics"
  assert_eq "$(curl_tls -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $VIRTUAL_KEY" "$BASE_HTTPS/admin/v1/organizations")" "403" "virtual key blocked from /admin/v1"

  echo "==> Verifying CodeQL SSRF blocks across metadata, userinfo, http://, and unallowlisted internal subnets..."
  for bad_url in \
    "http://169.254.169.254/latest/meta-data/" \
    "https://user:pass@evil.example/v1" \
    "http://mock-upstream:8443/v1" \
    "https://metadata.google.internal/" \
    "https://127.0.0.1:8080/v1"; do
    local code
    code="$(curl_tls -s -o /dev/null -w '%{http_code}' -X POST "$BASE_HTTPS/admin/v1/credentials" \
      -H "$hdr_auth" -H "Content-Type: application/json" \
      -d "{\"org_id\":\"$ORG_ID\",\"provider\":\"openai\",\"name\":\"ssrf-bad\",\"base_url\":\"$bad_url\",\"api_key\":\"sk-bad\"}")"
    assert_eq "$code" "400" "SSRF credential create rejection for $bad_url"
  done
  local dial_ssrf_out
  dial_ssrf_out="$(curl_tls -fsS -X POST "$BASE_HTTPS/admin/v1/credentials/validate" \
    -H "$hdr_auth" -H "Content-Type: application/json" \
    -d '{"provider":"openai","base_url":"https://postgres:5432/","api_key":"sk-bad"}')"
  echo "$dial_ssrf_out" | grep -q '"valid":false'
  echo "$dial_ssrf_out" | grep -q 'forbidden by SSRF policy'

  echo "==> Verifying org_admin JWT blocked from private preflight credential validation (403)..."
  local admin_sub org_admin_jwt
  admin_sub="oidc-org-admin-$(date +%s)"
  curl_tls -fsS -X POST "$BASE_HTTPS/admin/v1/users" -H "$hdr_auth" -H "Content-Type: application/json" \
    -d "{\"org_id\":\"$ORG_ID\",\"email\":\"${admin_sub}@goroute.local\",\"name\":\"Org Admin\",\"role\":\"org_admin\",\"oidc_subject\":\"$admin_sub\"}" >/dev/null
  org_admin_jwt="$(node -e '
    const crypto = require("crypto");
    const hdr = Buffer.from(JSON.stringify({alg:"HS256",typ:"JWT"})).toString("base64url");
    const exp = Math.floor(Date.now()/1000) + 600;
    const pay = Buffer.from(JSON.stringify({
      sub: process.argv[1],
      iss: "https://auth.goroute.local",
      aud: "goroute-gateway",
      exp: exp
    })).toString("base64url");
    const sig = crypto.createHmac("sha256", process.argv[2]).update(hdr + "." + pay).digest("base64url");
    process.stdout.write(hdr + "." + pay + "." + sig);
  ' "$admin_sub" "$GATEWAY_JWT_SECRET")"
  local preflight_code
  preflight_code="$(curl_tls -s -o /dev/null -w '%{http_code}' -X POST "$BASE_HTTPS/admin/v1/credentials/validate" \
    -H "Authorization: Bearer $org_admin_jwt" -H "Content-Type: application/json" \
    -d '{"provider":"openai","base_url":"https://mock-upstream:8443/v1","api_key":"sk-test"}')"
  assert_eq "$preflight_code" "403" "org_admin blocked on private preflight validation"

  echo "==> Verifying isolated mediaPolicy blocks private image_url even against mock-upstream CIDR..."
  local media_code
  media_code="$(curl_tls -s -o /dev/null -w '%{http_code}' -X POST "$BASE_HTTPS/v1/chat/completions" \
    -H "Authorization: Bearer $VIRTUAL_KEY" -H "Content-Type: application/json" \
    -d '{"model":"prod-ollama","messages":[{"role":"user","content":[{"type":"text","text":"inspect"},{"type":"image_url","image_url":{"url":"https://mock-upstream:8443/secret.png"}}]}]}')"
  if [[ "$media_code" == "200" ]]; then
    echo "FAIL: isolated mediaPolicy allowed private image_url fetch!" >&2
    exit 1
  fi
  if docker compose -f "$PROD_COMPOSE" logs --no-color --tail=200 mock-upstream | grep -q "SECRET_PNG_TRAP_HIT"; then
    echo "FAIL: mock-upstream received /secret.png fetch despite mediaPolicy SSRF isolation!" >&2
    exit 1
  fi

  echo "==> Verifying Audio TTS Content-Type sanitization against spoofed text/html..."
  local tts_resp tts_status tts_ct
  tts_resp="$(curl_tls -s -D - -o /dev/null -w '\nHTTP_STATUS:%{http_code}' -X POST "$BASE_HTTPS/v1/audio/speech" \
    -H "Authorization: Bearer $VIRTUAL_KEY" -H "Content-Type: application/json" \
    -d '{"model":"prod-tts","input":"BADTYPE_HTML","voice":"alloy"}' | tr -d '\r')"
  tts_status="$(echo "$tts_resp" | awk -F: '/^HTTP_STATUS:/{print $2}')"
  tts_ct="$(echo "$tts_resp" | awk -F': ' 'tolower($1)=="content-type"{print tolower($2)}')"
  assert_eq "$tts_status" "200" "/v1/audio/speech BADTYPE_HTML HTTP 200"
  if echo "$tts_ct" | grep -q "text/html"; then
    echo "FAIL: unsafe text/html reflected from /v1/audio/speech ($tts_ct)" >&2
    exit 1
  fi
  echo "==> Phase 4 PASSED."
}

phase_5() {
  echo "======================================================================"
  echo "  PHASE 5: Multi-Replica Full-Modality Smoke & Pub/Sub Key Sync"
  echo "======================================================================"
  ensure_runtime_env
  provision_fixture_tenant
  local hdr_auth="Authorization: Bearer ${GATEWAY_MASTER_ADMIN_KEY}"
  local hdr_vk="Authorization: Bearer ${VIRTUAL_KEY}"

  echo "==> Chat completion (sync)..."
  curl_tls -fsS -X POST "$BASE_HTTPS/v1/chat/completions" -H "$hdr_vk" -H "Content-Type: application/json" \
    -d '{"model":"prod-chat","messages":[{"role":"user","content":"Hello HA"}]}' | grep -q "Hello from mock-upstream!"

  echo "==> SSE streaming + Opt-in stream cache replay..."
  local stream1 stream2
  stream1="$(curl_tls -fsS -X POST "$BASE_HTTPS/v1/chat/completions" -H "$hdr_vk" -H "Content-Type: application/json" \
    -H "X-Gateway-Cache-Control: gateway-stream-cache" \
    -d '{"model":"prod-chat","stream":true,"messages":[{"role":"user","content":"Stream cache probe"}]}')"
  echo "$stream1" | grep -q '\[DONE\]'
  stream2="$(curl_tls -fsS -D - -X POST "$BASE_HTTPS/v1/chat/completions" -H "$hdr_vk" -H "Content-Type: application/json" \
    -H "X-Gateway-Cache-Control: gateway-stream-cache" \
    -d '{"model":"prod-chat","stream":true,"messages":[{"role":"user","content":"Stream cache probe"}]}')"
  echo "$stream2" | grep -q '\[DONE\]'

  echo "==> Responses API, Anthropic Messages, Embeddings, Images, Audio..."
  curl_tls -fsS -X POST "$BASE_HTTPS/v1/responses" -H "$hdr_vk" -H "Content-Type: application/json" \
    -d '{"model":"prod-chat","input":"Respond via Responses API"}' | grep -q "Hello from mock-upstream!"
  curl_tls -fsS -X POST "$BASE_HTTPS/v1/messages" -H "$hdr_vk" -H "Content-Type: application/json" \
    -d '{"model":"prod-anthropic","max_tokens":64,"messages":[{"role":"user","content":"Hello Claude"}]}' | grep -q "Mock Anthropic reply"
  curl_tls -fsS -X POST "$BASE_HTTPS/v1/embeddings" -H "$hdr_vk" -H "Content-Type: application/json" \
    -d '{"model":"prod-embed","input":"embedding test"}' | grep -q '"embedding"'
  curl_tls -fsS -X POST "$BASE_HTTPS/v1/images/generations" -H "$hdr_vk" -H "Content-Type: application/json" \
    -d '{"model":"prod-image","prompt":"tiny icon","n":1,"quality":"standard","size":"1024x1024"}' | grep -q '"b64_json"'
  assert_eq "$(curl_tls -s -o /dev/null -w '%{http_code}' -X POST "$BASE_HTTPS/v1/audio/speech" -H "$hdr_vk" -H "Content-Type: application/json" -d '{"model":"prod-tts","input":"hello audio","voice":"alloy"}')" "200" "/v1/audio/speech 200"

  echo "==> MCP JSON-RPC (/mcp) & A2A Agent (/a2a/v1/agents/mock-a2a/)..."
  curl_tls -fsS -X POST "$BASE_HTTPS/mcp" -H "$hdr_vk" -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}' | grep -q "echo_tool"
  curl_tls -fsS -X POST "$BASE_HTTPS/a2a/v1/agents/mock-a2a/" -H "$hdr_vk" -H "Content-Type: application/json" \
    -d '{"message":{"messageId":"msg_in_1","role":"ROLE_USER","parts":[{"text":"ping agent"}]}}' | grep -q "Acknowledged by mock A2A agent"

  echo "==> WebSocket /v1/realtime round-trip & budgeted fail-closed check via Go SDK (ConnectRealtime)..."
  SSL_CERT_FILE="$RUN_DIR/tls/ca.crt" go run ./tests/fixtures/ws-probe -url "$BASE_HTTPS" -key "$VIRTUAL_KEY" -model "prod-chat" -expect-reject
  SSL_CERT_FILE="$RUN_DIR/tls/ca.crt" go run ./tests/fixtures/ws-probe -url "$BASE_HTTPS" -key "$UNBUDGETED_KEY" -model "openai/gpt-4o-mini"

  echo "==> HA Redis Pub/Sub virtual key revocation across both replicas..."
  assert_eq "$(curl_tls -s -o /dev/null -w '%{http_code}' -X POST "$BASE_HTTPS/v1/chat/completions" -H "Authorization: Bearer $ROTATE_KEY" -H "Content-Type: application/json" -d '{"model":"prod-chat","messages":[{"role":"user","content":"before revoke"}]}')" "200" "pre-revoke 200"
  curl_tls -fsS -X POST "$BASE_HTTPS/admin/v1/keys/$ROTATE_KEY_ID/revoke" -H "$hdr_auth" >/dev/null
  sleep 1
  for i in $(seq 1 10); do
    local code
    code="$(curl_tls -s -o /dev/null -w '%{http_code}' -X POST "$BASE_HTTPS/v1/chat/completions" -H "Authorization: Bearer $ROTATE_KEY" -H "Content-Type: application/json" -d '{"model":"prod-chat","messages":[{"role":"user","content":"after revoke"}]}')"
    assert_eq "$code" "401" "revoked key rejected everywhere (attempt $i)"
  done
  echo "==> Phase 5 PASSED."
}

phase_6() {
  echo "======================================================================"
  echo "  PHASE 6: Observability (Prometheus + OTel) & FinOps Reconciliation"
  echo "======================================================================"
  ensure_runtime_env
  provision_fixture_tenant
  local hdr_auth="Authorization: Bearer ${GATEWAY_MASTER_ADMIN_KEY}"

  echo "==> Polling Prometheus targets until ai-gateway-1 and ai-gateway-2 are UP..."
  local prom_ok=0
  for _ in $(seq 1 20); do
    local up_count
    up_count="$(curl -fsS "$PROM_URL/api/v1/query?query=up%7Bjob%3D%22ai-gateway-cluster%22%7D" | jq '[.data.result[] | select(.value[1]=="1")] | length')"
    if [[ "$up_count" -ge 2 ]]; then
      prom_ok=1
      break
    fi
    sleep 2
  done
  assert_eq "$prom_ok" "1" "Prometheus reports >= 2 UP gateway targets"

  local req_total
  req_total="$(curl -fsS "$PROM_URL/api/v1/query?query=sum(gateway_requests_total)" | jq -r '.data.result[0].value[1] // "0"')"
  echo "    Prometheus sum(gateway_requests_total) = $req_total"
  awk -v val="$req_total" 'BEGIN { exit !(val > 0) }'

  echo "==> Verifying OTel Collector received exported trace spans & metrics..."
  sleep 2
  local otel_logs
  otel_logs="$(docker compose -f "$PROD_COMPOSE" logs --no-color --tail=200 otel-collector)"
  grep -q "Trace ID" <<<"$otel_logs"

  echo "==> Verifying PostgreSQL FinOps spend_logs & Admin spend summary..."
  curl_tls -fsS -H "$hdr_auth" "$BASE_HTTPS/admin/v1/spend/summary?org_id=$ORG_ID" | grep -q "total_requests"
  local pg_cid row_count
  pg_cid="$(docker compose -f "$PROD_COMPOSE" ps -q postgres)"
  row_count="$(docker exec -e PGPASSWORD="$POSTGRES_PASSWORD" "$pg_cid" psql -U gateway -d aigateway_prod_test -tAc "SELECT COUNT(*) FROM spend_logs WHERE org_id = '$ORG_ID';")"
  echo "    Postgres spend_logs rows for $ORG_ID = $row_count"
  awk -v c="$row_count" 'BEGIN { exit !(c > 0) }'
  echo "==> Phase 6 PASSED."
}

phase_7() {
  echo "======================================================================"
  echo "  PHASE 7: k6 Mixed Load, pgbench, redis-benchmark & Chaos"
  echo "======================================================================"
  ensure_runtime_env
  provision_fixture_tenant

  echo "==> Running k6 mixed production workload against HTTPS Nginx LB..."
  GATEWAY_BASE_URL="$BASE_HTTPS" \
  GATEWAY_VIRTUAL_KEY="$VIRTUAL_KEY" \
  GATEWAY_BURST_KEY="$BURST_KEY" \
  GATEWAY_CHAT_MODEL="prod-chat" \
  k6 run "$ROOT_DIR/tests/load/k6_prod_suite.js"

  echo "==> Running pgbench & redis-benchmark inside data-net containers..."
  local pg_cid redis_cid
  pg_cid="$(docker compose -f "$PROD_COMPOSE" ps -q postgres)"
  redis_cid="$(docker compose -f "$PROD_COMPOSE" ps -q redis)"
  docker exec -e PGPASSWORD="$POSTGRES_PASSWORD" "$pg_cid" pgbench -U gateway -i -s 1 aigateway_prod_test >/dev/null
  docker exec -e PGPASSWORD="$POSTGRES_PASSWORD" "$pg_cid" pgbench -U gateway -c 8 -j 2 -T 5 aigateway_prod_test
  docker exec "$redis_cid" redis-benchmark -a "$REDIS_PASSWORD" -q -t get,set -c 16 -n 5000

  echo "==> Chaos A: Rolling restart of ai-gateway-1 during active HTTPS traffic..."
  docker compose -f "$PROD_COMPOSE" restart ai-gateway-1 &
  local restart_pid=$!
  for i in $(seq 1 15); do
    local code
    code="$(curl_tls -s -o /dev/null -w '%{http_code}' -X POST "$BASE_HTTPS/v1/chat/completions" \
      -H "Authorization: Bearer $VIRTUAL_KEY" -H "Content-Type: application/json" \
      -d '{"model":"prod-chat","messages":[{"role":"user","content":"chaos probe"}]}')"
    if [[ "$code" -ge 500 ]]; then
      echo "FAIL: unexpected 5xx ($code) during rolling restart at step $i" >&2
      wait "$restart_pid" || true
      exit 1
    fi
    sleep 0.4
  done
  wait "$restart_pid"
  docker compose -f "$PROD_COMPOSE" up -d --wait

  echo "==> Chaos B: Redis outage fail-closed & automatic recovery..."
  docker compose -f "$PROD_COMPOSE" stop redis
  local outage_code
  outage_code="$(curl_tls -s -o /dev/null -w '%{http_code}' -X POST "$BASE_HTTPS/v1/chat/completions" \
    -H "Authorization: Bearer $BURST_KEY" -H "Content-Type: application/json" \
    -d '{"model":"prod-chat","messages":[{"role":"user","content":"redis down probe"}]}')"
  echo "    Inference status during Redis outage (fallback_to_local_on_outage=false): HTTP $outage_code"
  if [[ "$outage_code" == "200" ]]; then
    echo "FAIL: expected fail-closed non-200 response for fresh key when Redis is down!" >&2
    docker compose -f "$PROD_COMPOSE" start redis
    exit 1
  fi
  assert_eq "$(curl_tls -s -o /dev/null -w '%{http_code}' "$BASE_HTTPS/healthz")" "200" "/healthz remains 200 during Redis outage"

  docker compose -f "$PROD_COMPOSE" up -d --wait redis
  local recovered=0 rec_code=""
  for _ in $(seq 1 20); do
    rec_code="$(curl_tls -s -o /dev/null -w '%{http_code}' -X POST "$BASE_HTTPS/v1/chat/completions" -H "Authorization: Bearer $VIRTUAL_KEY" -H "Content-Type: application/json" -d '{"model":"prod-chat","messages":[{"role":"user","content":"post redis recovery"}]}')"
    if [[ "$rec_code" == "200" ]]; then
      recovered=1
      break
    fi
    sleep 1
  done
  assert_eq "$recovered" "1" "recovery after Redis start (last HTTP $rec_code)"
  echo "==> Phase 7 PASSED."
}

phase_8() {
  echo "======================================================================"
  echo "  PHASE 8: Optional Live Provider Canary"
  echo "======================================================================"
  if [[ -n "${OPENAI_API_KEY:-}" || -n "${ANTHROPIC_API_KEY:-}" || -n "${GEMINI_API_KEY:-}" ]]; then
    make test-canary
  else
    echo "==> SKIPPED Phase 8 (no live provider API keys set in environment)."
  fi
}

should_run_phase 1 && phase_1
should_run_phase 2 && phase_2
should_run_phase 3 && phase_3
should_run_phase 4 && phase_4
should_run_phase 5 && phase_5
should_run_phase 6 && phase_6
should_run_phase 7 && phase_7
should_run_phase 8 && phase_8

echo "======================================================================"
echo "  All Requested Production Suite Phases PASSED ($PHASE_FILTER)"
echo "======================================================================"
