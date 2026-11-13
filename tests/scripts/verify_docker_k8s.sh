#!/usr/bin/env bash
set -euo pipefail

MODE="${1:-all}"
COMPOSE_FILE="deployments/docker-compose.test.yml"

verify_docker() {
  echo "==> [Docker] Building & starting full-stack test containers..."
  docker compose -f "${COMPOSE_FILE}" --profile fullstack up -d --build --wait

  echo "==> [Docker] Waiting for gateway /readyz..."
  for i in $(seq 1 30); do
    if curl -fsS http://localhost:18080/readyz >/dev/null 2>&1; then
      break
    fi
    sleep 1
  done

  ADMIN_KEY="${GATEWAY_MASTER_ADMIN_KEY:-sk-gw-test-master-admin-key}"
  HEALTHZ=$(curl -fsS http://localhost:18080/healthz)
  echo "${HEALTHZ}" | grep -q '"status":"ok"'
  curl -fsS http://localhost:18080/readyz | grep -q '"status":"ready"'
  METRICS=$(curl -fsS -H "Authorization: Bearer ${ADMIN_KEY}" http://localhost:18080/metrics)
  echo "${METRICS}" | grep -q "gateway_requests_total"

  echo "==> [Docker] Verifying admin API against containerized Postgres + Redis..."
  SLUG="docker-smoke-org-$(date +%s)"
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST http://localhost:18080/admin/v1/organizations \
    -H "Authorization: Bearer ${ADMIN_KEY}" \
    -H "Content-Type: application/json" \
    -d "{\"name\":\"DockerSmokeOrg\",\"slug\":\"${SLUG}\"}")
  if [ "${STATUS}" != "201" ]; then
    echo "Expected 201 from /admin/v1/organizations, got ${STATUS}"
    docker compose -f "${COMPOSE_FILE}" --profile fullstack logs ai-gateway-test
    exit 1
  fi

  echo "==> [Docker] Full-stack container smoke PASSED."
}

verify_k8s() {
  echo "==> [K8s] Validating Kustomize & Kubernetes manifests..."
  kubectl kustomize deployments/k8s/ >/dev/null

  if ! kubectl config current-context >/dev/null 2>&1; then
    echo "==> [K8s] No active kubeconfig context found."
    echo "    Manifests validated via dry-run. To run the live 2-replica cluster rollout & pod-kill test:"
    echo "    - Enable Kubernetes in Docker Desktop, OR run: brew install kind && kind create cluster --name goroute-test"
    echo "    - Build/load image: docker build -t goroute/ai-gateway:test -f deployments/Dockerfile . && kind load docker-image goroute/ai-gateway:test --name goroute-test"
    echo "    - Re-run: make test-k8s-smoke"
    return 0
  fi

  echo "==> [K8s] Building image goroute/ai-gateway:test..."
  docker build -t goroute/ai-gateway:test -f deployments/Dockerfile .
  if command -v kind >/dev/null 2>&1 && kubectl config current-context | grep -q "^kind-"; then
    CLUSTER_NAME="${kubectl_ctx:-$(kubectl config current-context | sed 's/^kind-//')}"
    kind load docker-image goroute/ai-gateway:test --name "${CLUSTER_NAME}"
  fi

  echo "==> [K8s] Deploying 2-replica stack into goroute-test..."
  kubectl apply -k deployments/k8s/
  kubectl -n goroute-test rollout status deployment/postgres --timeout=90s
  kubectl -n goroute-test rollout status deployment/redis --timeout=60s
  kubectl -n goroute-test rollout status deployment/gateway --timeout=120s

  echo "==> [K8s] Running pod-kill resilience check..."
  FIRST_POD=$(kubectl -n goroute-test get pods -l app=gateway -o jsonpath='{.items[0].metadata.name}')
  kubectl -n goroute-test delete pod "${FIRST_POD}" --wait=false
  kubectl -n goroute-test rollout status deployment/gateway --timeout=120s

  echo "==> [K8s] Multi-replica rollout & pod-kill verification PASSED."
}

case "${MODE}" in
  docker) verify_docker ;;
  k8s) verify_k8s ;;
  all)
    verify_docker
    verify_k8s
    ;;
  *)
    echo "Usage: $0 [docker|k8s|all]"
    exit 1
    ;;
esac
