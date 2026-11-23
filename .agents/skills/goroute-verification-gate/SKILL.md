---
name: goroute-verification-gate
description: >-
  Run GoRoute's multi-tier verification gates (formatting, static analysis, OpenAPI/MCP specgen, Web UI bundle parity, race unit/guardrails tests, and optional live Postgres/Redis/Playwright/Docker E2E).
  Use before committing, opening a pull request, or claiming a fix is complete.
  Do not use to run destructive make release-check on a dirty worktree without checking prerequisites first.
---

# GoRoute Multi-Tier Verification Gate

Choose the verification tier matching your change scope and available local services. Always report exact commands run and any skipped live-service checks.

## Tier 0 + Tier 1 (Always Run — No External Services Required)

Execute the bundled deterministic verification script:

```bash
bash .agents/skills/goroute-verification-gate/scripts/verify_tier0.sh
```

This script runs (in read-only mode on your working tree):
1. `gofmt -l .` (fails if any Go file is unformatted)
2. `go vet ./...`
3. `make specgen` + parity check on generated OpenAPI/MCP outputs
4. `make ui-check-dist` and `node web/scripts/check-budget.mjs`
5. `go build -o /dev/null ./cmd/gateway` and `go build -o /dev/null ./cmd/goroute`
6. `go test -race -count=1 ./internal/... ./pkg/... ./cmd/... ./tests/guardrails/...`
7. Optional `gitleaks` secret hygiene scan (if `gitleaks` is installed)

## Tier 1 Live Stack (PostgreSQL 16 + Redis 7 via Docker)

Run when modifying `migrations/`, `internal/storage/`, `internal/ratelimit/`, `internal/finops/`, `internal/auth/`, or `internal/router/`:

```bash
make test-live-up
make test-postgres
make test-e2e-strict
make test-live-down
```

## Tier 2 Browser UI E2E (Playwright Chromium)

Run when modifying `web/`, `internal/ui/`, `/auth/*`, or `/admin/v1/*`:

```bash
make test-live-up
make test-ui-e2e
make test-live-down
```

## Tier 3 Production-Like HA Docker OIDC Suite

Run when changing OIDC federation, Keycloak SSO, `cmd/goroute`, `ExternalAuthorizer`, `audit.siem_webhook`, or TLS/SSRF production guards:

```bash
make test-prod-docker
```
