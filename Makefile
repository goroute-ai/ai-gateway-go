.PHONY: all build fmt vet lint test test-unit test-e2e specgen demos run docker-build docker-up docker-down clean release-check

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
	@echo "==> Validating OpenAPI, JSON Schema & Protobuf contracts..."
	@go run ./cmd/specgen

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

demos:
	@echo "==> Running overview demo laboratory..."
	go run ./demo/main.go
	@echo "==> Running specialized demo laboratories (01-09)..."
	@for d in demo/0[1-9]*; do \
		echo "--- Running $$d ---"; \
		go run "$$d/main.go" || exit 1; \
	done

# ------------------------------------------------------------------------------
# Docker & Deployment
# ------------------------------------------------------------------------------

docker-build:
	docker build -t goroute/ai-gateway:v1.0.0 -f deployments/Dockerfile .

docker-up:
	docker compose -f deployments/docker-compose.yml up -d --build

docker-down:
	docker compose -f deployments/docker-compose.yml down

# ------------------------------------------------------------------------------
# Release Verification Gate
# ------------------------------------------------------------------------------

clean:
	@echo "==> Cleaning build and test artifacts..."
	@rm -rf bin/ *.test

release-check: fmt vet specgen test-unit test-e2e
	@echo "======================================================================"
	@echo "  GoRoute AI Gateway v1.0.0 — All Release Checks Passed Successfully! "
	@echo "======================================================================"
