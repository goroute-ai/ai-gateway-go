.PHONY: all build fmt vet lint deadcode test test-unit test-guardrails test-e2e test-live-up test-live-down test-keycloak-up test-keycloak-down test-postgres test-e2e-strict test-ui-e2e test-prod-docker test-cache-prod-docker test-obs-prod-docker test-security specgen catalog-sync run docker-build docker-up docker-down clean release-assets release-check ui-install ui-build ui-check-dist ui-dev

VERSION ?= v0.1.0
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo dev)
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

all: release-check

# ------------------------------------------------------------------------------
# Code Generation & Build
# ------------------------------------------------------------------------------

generate:
	go generate ./...

build: generate
	@mkdir -p bin
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(DATE)" -o bin/ai-gateway ./cmd/gateway

build-cli:
	@mkdir -p bin
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o bin/goroute ./cmd/goroute

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
	elif [ -x "$$(go env GOPATH)/bin/golangci-lint" ]; then \
		echo "==> Running golangci-lint from GOPATH/bin..."; \
		"$$(go env GOPATH)/bin/golangci-lint" run ./...; \
	else \
		echo "golangci-lint not installed; run: go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest"; \
	fi

deadcode:
	@echo "==> Running deadcode reachability analysis..."
	@if command -v deadcode >/dev/null 2>&1; then \
		deadcode ./cmd/... ./internal/... ./pkg/...; \
	elif [ -x "$$(go env GOPATH)/bin/deadcode" ]; then \
		"$$(go env GOPATH)/bin/deadcode" ./cmd/... ./internal/... ./pkg/...; \
	else \
		echo "deadcode not installed; run: go install golang.org/x/tools/cmd/deadcode@latest"; \
	fi

specgen:
	@echo "==> Regenerating gateway OpenAPI + MCP spec types and validating contracts..."
	@go generate ./internal/mcp/spec
	@go generate ./internal/openapi

catalog-sync:
	@echo "==> Regenerating embedded model catalog from upstream source..."
	go run ./cmd/catalog-sync -source "$${UPSTREAM_MODEL_CATALOG:-model_prices_and_context_window.json}" -out internal/modelcatalog/catalog.json.gz

# ------------------------------------------------------------------------------
# Testing Suites
# ------------------------------------------------------------------------------

test:
	@echo "==> Running full test suite with race detector..."
	go test -race -v -count=1 ./...

test-unit:
	@echo "==> Running unit tests with race detector..."
	go test -race -v -count=1 ./internal/... ./pkg/...

test-guardrails:
	@echo "==> Running isolated guardrails tests with race detector..."
	go test -race -v -count=1 ./internal/guardrails/... ./tests/guardrails/...

test-e2e:
	@echo "==> Running live stack end-to-end integration tests..."
	go test -race -v -count=1 ./tests/e2e

test-live-up:
	@echo "==> Starting isolated PostgreSQL 16 + Redis 8 test stack..."
	docker compose -f deployments/docker-compose.test.yml up -d --wait

test-live-down:
	@echo "==> Stopping isolated test stack..."
	docker compose -f deployments/docker-compose.test.yml --profile fullstack --profile keycloak down -v

test-keycloak-up:
	@echo "==> Starting local Keycloak 26 OIDC test IdP (port 18081)..."
	docker compose -f deployments/docker-compose.test.yml --profile keycloak up -d --wait keycloak-test

test-keycloak-down:
	@echo "==> Stopping local Keycloak 26 OIDC test IdP..."
	docker compose -f deployments/docker-compose.test.yml --profile keycloak stop keycloak-test && docker compose -f deployments/docker-compose.test.yml --profile keycloak rm -f keycloak-test

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

test-ui-e2e:
	@echo "==> Running headless Chromium Operator Web UI E2E suite (SSO, Virtual Keys & Multi-Window Quotas)..."
	bash tests/ui-e2e/run_ui_e2e.sh

test-prod-docker:
	@echo "==> Running production-like 2-replica Docker OIDC verification (Suites 1-6)..."
	bash tests/prod-docker/run_prod_tests.sh

test-cache-prod-docker:
	@echo "==> Running production-grade 2-replica Docker Caching verification (local, redis KV, redis-semantic HNSW & FLAT + chaos)..."
	bash tests/cache-prod-docker/run_cache_prod_tests.sh

test-obs-prod-docker:
	@echo "==> Running production-grade 2-replica Docker OTLP Observability verification (Suites O0-O5: traces, metrics, logs, 4-adapter traceparent, SIEM, Redis chaos)..."
	bash tests/obs-prod-docker/run_obs_prod_tests.sh

test-security:
	@echo "==> Running security & vulnerability checks..."
	@if command -v govulncheck >/dev/null 2>&1; then govulncheck ./...; else echo "govulncheck not installed; skipping"; fi
	go test -race -v -count=1 ./internal/security/... ./internal/auth/... ./tests/e2e -run TestSecurity

# ------------------------------------------------------------------------------
# Docker & Deployment
# ------------------------------------------------------------------------------

docker-build:
	docker build --build-arg VERSION=$(VERSION) --build-arg COMMIT=$(COMMIT) --build-arg BUILD_DATE=$(DATE) -t goroute/ai-gateway:$(VERSION) -f deployments/Dockerfile .

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
	@echo "==> Verifying internal/ui/dist synchronization and bundle budget..."
	@if [ -d web/dist ]; then \
		diff -rq web/dist internal/ui/dist >/dev/null || (echo "❌ internal/ui/dist is out of sync with web/dist. Run 'make ui-build' to synchronize." && exit 1); \
		if command -v node >/dev/null 2>&1; then \
			node web/scripts/check-budget.mjs web/dist; \
		fi; \
		echo "==> internal/ui/dist is in sync with web/dist."; \
	else \
		test -f internal/ui/dist/index.html || (echo "❌ internal/ui/dist/index.html missing. Run 'make ui-build'." && exit 1); \
		test -d internal/ui/dist/assets || (echo "❌ internal/ui/dist/assets missing. Run 'make ui-build'." && exit 1); \
		if command -v node >/dev/null 2>&1; then \
			node web/scripts/check-budget.mjs internal/ui/dist; \
		fi; \
		echo "ℹ️  web/dist not present (fresh checkout); verified committed internal/ui/dist assets & bundle budget. Run 'make ui-build' to rebuild from web/src."; \
	fi

security-scan:
	@echo "==> Running full working-tree secret scan (gitleaks --no-git)..."
	gitleaks detect --source=. --config=.gitleaks.toml --no-git --redact

ui-dev:
	@echo "==> Starting Vite local dev server with API proxy..."
	cd web && npm run dev

# ------------------------------------------------------------------------------
# Release Verification Gate
# ------------------------------------------------------------------------------

clean:
	@echo "==> Cleaning build and test artifacts..."
	@rm -rf gateway bin/ dist/ *.test tests/ui-e2e/node_modules

release-assets:
	@echo "==> Packaging multi-platform binaries, checksums, and Kubernetes/Helm artifacts ($(VERSION))..."
	@rm -rf dist && mkdir -p dist
	@CLEAN_VER="$(patsubst v%,%,$(VERSION))"; \
	for target in "darwin amd64" "darwin arm64" "linux amd64" "linux arm64" "windows amd64"; do \
	  set -- $$target; os="$$1"; arch="$$2"; \
	  stage="dist/stage-$${os}-$${arch}"; mkdir -p "$$stage"; \
	  bin_name="ai-gateway"; [ "$$os" = "windows" ] && bin_name="ai-gateway.exe"; \
	  CGO_ENABLED=0 GOOS="$$os" GOARCH="$$arch" go build -trimpath \
	    -ldflags="-s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(DATE)" \
	    -o "$${stage}/$${bin_name}" ./cmd/gateway; \
	  if [ "$$os" = "windows" ]; then \
	    (cd "$$stage" && zip -q "../ai-gateway_$${CLEAN_VER}_$${os}_$${arch}.zip" "$${bin_name}"); \
	  else \
	    tar -C "$$stage" -czf "dist/ai-gateway_$${CLEAN_VER}_$${os}_$${arch}.tar.gz" "$${bin_name}"; \
	  fi; \
	  rm -rf "$$stage"; \
	done; \
	tar -czf "dist/goroute-k8s-manifests-$${CLEAN_VER}.tar.gz" -C deployments k8s; \
	if command -v helm >/dev/null 2>&1; then \
	  mkdir -p dist/helm-stage && cp -R deployments/helm/goroute dist/helm-stage/goroute && \
	  (helm package --dependency-update dist/helm-stage/goroute --app-version "$${CLEAN_VER}" -d dist/ || ( \
	    rm -rf dist/helm-stage/goroute/charts dist/helm-stage/goroute/Chart.lock && \
	    sed '/^dependencies:/,$$d' dist/helm-stage/goroute/Chart.yaml > dist/helm-stage/goroute/Chart.yaml.tmp && \
	    mv dist/helm-stage/goroute/Chart.yaml.tmp dist/helm-stage/goroute/Chart.yaml && \
	    helm package dist/helm-stage/goroute --app-version "$${CLEAN_VER}" -d dist/)) && \
	  rm -rf dist/helm-stage; \
	fi; \
	(cd dist && if command -v sha256sum >/dev/null 2>&1; then sha256sum * > .checksums.txt.tmp; else shasum -a 256 * > .checksums.txt.tmp; fi && mv .checksums.txt.tmp checksums.txt); \
	ls -lh dist/

release-check: vet specgen ui-check-dist test-unit test-guardrails test-e2e
	@test -z "$$(gofmt -l .)" || (echo "❌ Unformatted Go files detected; run 'make fmt' or 'gofmt -w ...'" && exit 1)
	@test -z "$$(go mod tidy -diff)" || (echo "❌ go.mod/go.sum out of sync; run 'go mod tidy'" && exit 1)
	@cd web && npx tsc --noEmit && node scripts/check-budget.mjs
	go test -race -count=1 ./cmd/...
	@echo "======================================================================"
	@echo "  GoRoute AI Gateway $(VERSION) — All Release Checks Passed!          "
	@echo "======================================================================"
