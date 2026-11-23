#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(git rev-parse --show-toplevel)"
cd "$ROOT_DIR"

echo "==> [1/6] Checking Go formatting (read-only)..."
UNFORMATTED="$(gofmt -l .)"
if [ -n "$UNFORMATTED" ]; then
  echo "❌ Unformatted Go files detected:"
  echo "$UNFORMATTED"
  exit 1
fi

echo "==> [2/6] Running go vet..."
go vet ./...

echo "==> [3/6] Validating OpenAPI & 5-release MCP contracts (make specgen)..."
make specgen

echo "==> [4/6] Checking embedded Operator Web UI dist parity & bundle budget..."
if [ -d "web/dist" ]; then
  make ui-check-dist
  node web/scripts/check-budget.mjs
else
  echo "    Skipping web/dist budget check (web/dist not built locally; internal/ui/dist verified via go test ./internal/ui/...)"
fi

echo "==> [5/6] Compiling gateway and goroute CLI binaries..."
go build -o /dev/null ./cmd/gateway
go build -o /dev/null ./cmd/goroute

echo "==> [6/6] Running unit & guardrail test suites with -race..."
go test -race -count=1 ./internal/... ./pkg/... ./cmd/... ./tests/guardrails/...

if command -v gitleaks >/dev/null 2>&1; then
  echo "==> [Bonus] Running gitleaks secret scan on staged changes..."
  gitleaks protect --staged --config=.gitleaks.toml
fi

echo "✨ All GoRoute Tier 0 + Tier 1 unit/guardrail checks passed!"
