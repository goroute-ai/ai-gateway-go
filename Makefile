.PHONY: all build fmt vet lint test test-unit test-e2e test-live-up test-live-down test-postgres test-e2e-strict test-load test-security test-docker-smoke test-k8s-smoke test-canary test-prod-containers specgen catalog-sync run docker-build docker-up docker-down clean release-check ui-install ui-build ui-check-dist ui-dev

all: release-check

# ------------------------------------------------------------------------------
# Code Generation & Build
# ------------------------------------------------------------------------------

generate:
	go generate ./...

build: generate
	@mkdir -p bin
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o bin/ai-gateway ./cmd/gateway

run:
	go run ./cmd/gateway -config configs/config.yaml

# ------------------------------------------------------------------------------
# Code Formatting & Static Analysis
# ------------------------------------------------------------------------------

fmt:
	@echo "==> Running gofmt..."
	@gofmt -s -w .

vet:
	@echo "==> Running go vet..."
	@go vet ./...

lint: vet
	@if command -v golangci-lint >/dev/null 2>&1; then \
		echo "==> Running golangci-lint..."; \
		golangci-lint run ./...; \
	fi

specgen:
	@echo "==> Regenerating gateway OpenAPI types and validating contracts..."
	@go generate ./internal/openapi

catalog-sync:
	@echo "==> Regenerating embedded model catalog from LiteLLM source..."
	go run ./cmd/catalog-sync -source "$${LITELLM_MODEL_CATALOG:-model_prices_and_context_window.json}" -out internal/modelcatalog/catalog.json.gz

# ------------------------------------------------------------------------------
# Testing Suites
# ------------------------------------------------------------------------------

test:
	@echo "==> Running full test suite with race detector..."
	go test -race -v -count=1 ./...

test-unit:
	@echo "==> Running unit tests with race detector..."
	go test -race -v -count=1 ./internal/... ./pkg/...

test-e2e:
	@echo "==> Running live stack end-to-end integration tests..."
	go test -race -v -count=1 ./tests/e2e

test-live-up:
	@echo "==> Starting isolated PostgreSQL 16 + Redis 7 test stack..."
	docker compose -f deployments/docker-compose.test.yml up -d --wait

test-live-down:
	@echo "==> Stopping isolated test stack..."
	docker compose -f deployments/docker-compose.test.yml --profile fullstack down -v

test-postgres:
	@echo "==> Running live PostgreSQL migration & persistence tests..."
	GATEWAY_REQUIRE_LIVE_DEPS=1 \
	GATEWAY_POSTGRES_DSN=$${GATEWAY_POSTGRES_DSN:-postgres://gateway:gateway@localhost:15432/aigateway_test?sslmode=disable} \
	GATEWAY_REDIS_ADDR=$${GATEWAY_REDIS_ADDR:-localhost:16379} \
	go test -race -v -count=1 ./internal/storage/...

test-e2e-strict:
	@echo "==> Running strict live-stack E2E tests (no skips allowed)..."
	GATEWAY_REQUIRE_LIVE_DEPS=1 \
	GATEWAY_POSTGRES_DSN=$${GATEWAY_POSTGRES_DSN:-postgres://gateway:gateway@localhost:15432/aigateway_test?sslmode=disable} \
	GATEWAY_REDIS_ADDR=$${GATEWAY_REDIS_ADDR:-localhost:16379} \
	go test -race -v -count=1 ./tests/e2e/...

test-load:
	@echo "==> Running load benchmarks & concurrency stress tests..."
	go test -bench=. -benchmem -run=^$$ ./internal/server ./internal/router
	GATEWAY_RUN_SOAK=$${GATEWAY_RUN_SOAK:-0} go test -v -count=1 ./tests/load/...

test-security:
	@echo "==> Running security & vulnerability checks..."
	@if command -v govulncheck >/dev/null 2>&1; then govulncheck ./...; else echo "govulncheck not installed; skipping"; fi
	go test -race -v -count=1 ./internal/security/... ./internal/auth/... ./tests/e2e -run TestSecurity

test-docker-smoke:
	@echo "==> Running full-stack Docker Compose smoke verification..."
	./tests/scripts/verify_docker_k8s.sh docker

test-k8s-smoke:
	@echo "==> Running Kubernetes multi-replica verification..."
	./tests/scripts/verify_docker_k8s.sh k8s

test-canary:
	@echo "==> Running key-gated live provider canary tests..."
	go test -tags=canary -v -count=1 ./tests/canary/...

test-prod-containers:
	@echo "==> Running containerized production security, vulnerability, and k6 load suite..."
	./tests/scripts/run_container_prod_suite.sh

# ------------------------------------------------------------------------------
# Docker & Deployment
# ------------------------------------------------------------------------------

docker-build:
	docker build -t goroute/ai-gateway:v1.6.0 -f deployments/Dockerfile .

docker-up:
	docker compose -f deployments/docker-compose.yml up -d --build

docker-down:
	docker compose -f deployments/docker-compose.yml down

# ------------------------------------------------------------------------------
# Operator Web UI & Chat Playground
# ------------------------------------------------------------------------------

ui-install:
	@echo "==> Installing frontend dependencies in web/..."
	cd web && npm ci

ui-build:
	@echo "==> Building frontend web assets and enforcing bundle budget..."
	cd web && npm run build && node scripts/check-budget.mjs
	@echo "==> Synchronizing compiled distribution to internal/ui/dist/..."
	rm -rf internal/ui/dist/* && cp -R web/dist/* internal/ui/dist/
	@echo "==> Frontend assets built and synchronized successfully."

ui-check-dist:
	@echo "==> Verifying internal/ui/dist synchronization..."
	@git diff --quiet internal/ui/dist || (echo "❌ internal/ui/dist is out of sync with web/. Run 'make ui-build' to synchronize." && exit 1)
	@echo "==> internal/ui/dist is in sync."

ui-dev:
	@echo "==> Starting Vite local dev server with API proxy..."
	cd web && npm run dev

# ------------------------------------------------------------------------------
# Release Verification Gate
# ------------------------------------------------------------------------------

clean:
	@echo "==> Cleaning build and test artifacts..."
	@rm -rf gateway bin/ dist/ *.test

release-check: fmt vet specgen test-unit test-e2e
	@echo "======================================================================"
	@echo "  GoRoute AI Gateway v1.6.0 — All Release Checks Passed Successfully! "
	@echo "======================================================================"
