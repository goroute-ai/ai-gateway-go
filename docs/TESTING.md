# GoRoute AI Gateway — Testing & Verification Guide

GoRoute uses a 3-tier verification strategy spanning fast local static checks, in-memory `-race` package and live PostgreSQL/Redis E2E suites, and headless Chromium browser UI E2E verification.

---

## Prerequisites

| Tier | Required Local Tools / Services |
| :--- | :--- |
| **Tier 0 (Static, Contracts & Hygiene)** | Go `1.26+`, Node.js `20+`, `gitleaks` |
| **Tier 1 (Unit `-race` & Live Postgres/Redis E2E)** | Go `1.26+`, Docker Compose (PostgreSQL 16 on `:15432`, Redis 7 on `:16379`) |
| **Tier 2 (Headless Chromium Operator Web UI)** | Go `1.26+`, Node.js `20+`, Playwright Chromium (`tests/ui-e2e/`), Live Postgres + Redis |

---

## Tier 0 — Static Analysis, Contracts, UI Budget & Secret Hygiene

```bash
# Formatting (read-only check; use `gofmt -s -w <files>` to format)
test -z "$(gofmt -l .)"

# Go static analysis
go vet ./...

# Binary compilation
go build -o /dev/null ./cmd/gateway

# OpenAPI 3.1/3.0, Multi-Release MCP YAML Schema (`cmd/mcpgen`) & A2A v1.0 Protobuf parity
# Enforces /v1, /admin/v1, and /auth parity (125 total OpenAPI paths)
make specgen && git diff --exit-code -- internal/openapi/ internal/mcp/spec/

# Embedded Operator Web UI asset sync & 500 KB bundle budget
make ui-check-dist
node web/scripts/check-budget.mjs

# Secret scanning (excludes tests/ui-e2e/node_modules/)
gitleaks detect --source=. --config=.gitleaks.toml --no-git
```

---

## Tier 1 — Unit Race Suites & Live PostgreSQL + Redis E2E

### In-Memory & Package Suites (`-race`)
```bash
go test -race -count=1 ./internal/... ./pkg/... ./cmd/... ./tests/guardrails/...
```

### Live PostgreSQL 16 + Redis 7 Strict Suites
`make test-postgres` and `make test-e2e-strict` set `GATEWAY_REQUIRE_LIVE_DEPS=1` so zero tests are allowed to skip due to missing Postgres/Redis:

```bash
# 1. Start isolated Postgres 16 (localhost:15432) and Redis 7 (localhost:16379)
make test-live-up

# 2. Verify forward/reverse migrations 0001..0038, preflight checks, and Pg repositories
make test-postgres

# 3. Run full dual-node cluster E2E suite under -race:
#    - tests/e2e/auth_federation_test.go
#    - tests/e2e/identity_lifecycle_scim_test.go
#    - tests/e2e/operator_sso_iam_test.go
#    - tests/e2e/quota_engine_budget_test.go
#    - tests/e2e/quota_scopes_priority_test.go
#    - tests/e2e/rolling_budget_recovery_test.go
#    - tests/e2e/intelligent_routing_cluster_test.go
#    - agentic_protocols_test.go, security_boundaries_test.go, fault_tolerance_test.go, etc.
make test-e2e-strict

# 4. Tear down ephemeral DB containers & volumes
make test-live-down
```

---

## Tier 2 — Headless Chromium Operator Web UI E2E

Playwright dependencies and specs live strictly isolated in [`tests/ui-e2e/`](../tests/ui-e2e) so [`web/`](../web) and its `510 KB` (`150 KB` gzipped) embedded bundle remain untouched:

```bash
make test-live-up
make test-ui-e2e
make test-live-down
```

[`tests/ui-e2e/run_ui_e2e.sh`](../tests/ui-e2e/run_ui_e2e.sh) builds the real gateway binary, launches a local mock OIDC/HIBP server (`mock_idp.mjs`), executes migrations, boots the gateway on `http://localhost:<PORT>`, and drives Chromium across [`operator_ui.spec.mjs`](../tests/ui-e2e/operator_ui.spec.mjs):
- Strict `/ui/` CSP (`script-src 'self'` without `'unsafe-inline'`) and zero uncaught page/console errors
- OIDC SSO buttons & PKCE `S256` start redirect verification
- Password login (verifying no client-side `password_sha1` field) & server-side HIBP 5-char prefix rejection
- `HttpOnly` `goroute_session` persistence across page reloads
- `KeysView` `llm_api` preset creation and manual grace-period key rotation badges
- `FinOpsView` -> `QuotasTab` per-model policy (`model_per_key`), `rolling_24h` budget window, `TempBudgetModal` persistence across reload, and `/auth/logout` session revocation
- `AgenticView` multi-release MCP protocol switching across `2024-11-05`..`2026-07-28`, persistence across reload, and `Register Upstream MCP Server` auto-transport selection
