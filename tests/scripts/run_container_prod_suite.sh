#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
COMPOSE_FILE="$ROOT_DIR/deployments/docker-compose.test.yml"
IMAGE_NAME="deployments-ai-gateway-test"

cd "$ROOT_DIR"

echo "==> [1/6] Building & starting containerized stack (Postgres 16 + Redis 7 + Distroless Gateway)..."
docker compose -f "$COMPOSE_FILE" --profile fullstack up -d --build --wait

cleanup() {
  echo "==> Cleaning up test containers..."
  docker compose -f "$COMPOSE_FILE" --profile fullstack down -v >/dev/null 2>&1 || true
}
trap cleanup EXIT

NET_NAME="$(docker inspect -f '{{range $k, $v := .NetworkSettings.Networks}}{{$k}}{{end}}' deployments-ai-gateway-test-1)"

echo "==> [2/6] Running Gitleaks container (zricethezav/gitleaks) against repo + .gitleaks.toml..."
docker run --rm -v "$ROOT_DIR:/repo:ro" -w /repo zricethezav/gitleaks:latest \
  detect --source=. --config=.gitleaks.toml --no-git

echo "==> [3/6] Running Trivy container (aquasec/trivy) on image & Kubernetes manifests (fail on CRITICAL)..."
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  aquasec/trivy:latest image --severity HIGH,CRITICAL --exit-code 1 --ignore-unfixed --scanners vuln "$IMAGE_NAME" || {
    echo "❌ Trivy found fixable HIGH/CRITICAL vulnerabilities or scan failed; checking CRITICAL-only gate..."
    docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
      aquasec/trivy:latest image --severity CRITICAL --exit-code 1 "$IMAGE_NAME"
  }
docker run --rm -v "$ROOT_DIR:/repo:ro" \
  aquasec/trivy:latest config --severity HIGH,CRITICAL --exit-code 0 /repo/deployments/k8s
docker run --rm -v "$ROOT_DIR:/repo:ro" \
  aquasec/trivy:latest config --severity CRITICAL --exit-code 1 /repo/deployments/k8s

echo "==> [4/6] Running govulncheck inside golang:alpine container..."
docker run --rm -v "$ROOT_DIR:/src:ro" -w /src golang:alpine \
  sh -c 'apk add --no-cache git >/dev/null && go install golang.org/x/vuln/cmd/govulncheck@latest && govulncheck ./...'

echo "==> [5/6] Running Grafana k6 container load test (250 RPS x 30s, p99 < 15ms) against ai-gateway-test..."
docker run --rm --network "$NET_NAME" \
  -v "$ROOT_DIR/tests/load/k6_gateway_smoke.js:/scripts/k6_gateway_smoke.js:ro" \
  grafana/k6:latest run /scripts/k6_gateway_smoke.js

echo "==> [6/6] Running pgbench & redis-benchmark sanity checks inside DB/cache containers..."
docker exec deployments-postgres-test-1 pgbench -U gateway -i -s 1 aigateway_test >/dev/null
docker exec deployments-postgres-test-1 pgbench -U gateway -c 8 -j 2 -T 5 aigateway_test
docker exec deployments-redis-test-1 redis-benchmark -q -t get,set -c 16 -n 5000

echo "==> All containerized production checks PASSED."
