# GoRoute AI Gateway — Testing & Verification Guide

GoRoute uses a 5-tier verification strategy spanning fast local static checks up to full multi-replica Distroless Docker HA, browser Web UI E2E, `k6` load testing, chaos recovery, and live provider canaries.

---

## Prerequisites

| Tier | Required Local Tools / Services |
| :--- | :--- |
| **Tier 0 (Static, Contracts & Hygiene)** | Go `1.26+`, Node.js `20+`, `gitleaks` |
| **Tier 1 (Unit `-race` & Live Postgres/Redis E2E)** | Go `1.26+`, Docker Compose (PostgreSQL 16 on `:15432`, Redis 7 on `:16379`) |
| **Tier 2 (Headless Chromium Operator Web UI)** | Go `1.26+`, Node.js `20+`, Playwright Chromium (`tests/ui-e2e/`), Live Postgres + Redis |
| **Tier 3 (2-Replica HA Containers & Chaos)** | Docker + Buildx, `openssl`, `jq`, `curl`, `k6`, Node.js `20+` |
| **Tier 4 (Live Provider & Cloud IAM Canaries)** | Live credentials (`OPENAI_API_KEY`, `CANARY_OIDC_*`, `CANARY_AWS_*`, `CANARY_GCP_*`) |

---

## Tier 0 — Static Analysis, Contracts, UI Budget & Secret Hygiene

```bash
# Formatting (read-only check; use `gofmt -s -w <files>` to format)
test -z "$(gofmt -l .)"

# Go static analysis (standard + canary build tag)
go vet ./...
go vet -tags=canary ./tests/canary/...

# Binary compilation
go build -o /dev/null ./cmd/gateway

# OpenAPI 3.1/3.0, MCP 2026-07-28 Schema & A2A v1.0 Protobuf parity
# Enforces /v1, /admin/v1, and /auth parity (106 total OpenAPI paths)
make specgen && git diff --exit-code -- internal/openapi/

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

# 2. Verify forward/reverse migrations 0001..0034, preflight checks, and Pg repositories
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

*(Note: Individual Ollama integration tests skip gracefully when no local Ollama daemon is running.)*

---

## Tier 2 — Headless Chromium Operator Web UI E2E

Playwright dependencies and specs live strictly isolated in [`tests/ui-e2e/`](../tests/ui-e2e) so [`web/`](../web) and its `500 KB` embedded bundle are untouched:

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

---

## Tier 3 — 2-Replica Containerized Production HA, `k6` & Chaos Suite

Ensure `make test-live-down` has been run so host ports are free, then run the full 8-phase suite in [`tests/scripts/run_container_prod_suite.sh`](../tests/scripts/run_container_prod_suite.sh):

```bash
make test-prod-containers
```

Phases executed automatically with full container teardown on exit:
1. **Phase 1**: Static checks, OpenAPI/UI parity, Gitleaks, hardened Distroless image builds (`ai-gateway` & `mock-upstream`), containerized `govulncheck`, and Trivy image + deployment IaC scans.
2. **Phase 2**: Negative production boot check (refuses default encryption keys), 2-replica HA stack boot behind Nginx TLS LB (`https://localhost:28443`), and non-root/read-only/cap-drop container hardening invariants.
3. **Phase 3**: Isolated live Postgres + Redis `make test-postgres` and `make test-e2e-strict`.
4. **Phase 4**: TLS security headers, `X-Request-Id` sanitization, `/metrics` & `/admin/v1` RBAC, SSRF policy blocks, issuer-bound JWT preflight denial for `org_admin`, `mediaPolicy` isolation, and audio `Content-Type` sanitization.
5. **Phase 5**: Multi-replica sync/streaming/responses/messages/embeddings/images/audio/realtime WS, MCP & A2A, Redis Pub/Sub key revocation, OIDC RS256 Data Plane JWT, HIBP screening + cookie/CSRF/logout, `llm_api` preset + grace + scheduled HTTPS rotation delivery webhook, soft-budget webhook + `rolling_24h`, and SCIM v2 provisioning.
6. **Phase 6**: Prometheus target scraping, OTLP collector trace export, and PostgreSQL `spend_logs` FinOps reconciliation.
7. **Phase 7**: `k6_prod_suite.js` & `k6_auth_quota_prod.js` mixed load, `pgbench`, `redis-benchmark`, rolling restart chaos (`ai-gateway-1`), **rolling-24h Redis sorted-set deletion recovery** (`gw:dq:*:r24h:*` -> `429` over-cap block from PostgreSQL), **OIDC JWKS outage stale-cache fallback**, and Redis outage fail-closed `503` + recovery.
8. **Phase 8**: Invokes `make test-canary` when live provider keys are exported in the environment.

To inspect or debug individual phases:
```bash
./tests/scripts/run_container_prod_suite.sh --phase 5 --keep-stack
make prod-stack-down
```

---

## Tier 4 — Live Provider, External OIDC & Cloud IAM Canaries

All live-network tests are build-tag and environment gated under [`tests/canary/`](../tests/canary) so CI and offline runs stay deterministic:

```bash
# Runs both live_providers_test.go and auth_quota_canary_test.go;
# unconfigured targets skip cleanly.
make test-canary
```

Supported environment variables:
- **LLM Providers**: `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `GEMINI_API_KEY`, `OPENROUTER_API_KEY`, `GROQ_API_KEY` (plus optional `CANARY_<NAME>_MODEL`)
- **External OIDC**: `CANARY_OIDC_ISSUER`, `CANARY_OIDC_BEARER_TOKEN`, `CANARY_OIDC_AUDIENCE`
- **Cloud IAM**: `CANARY_AWS_BEDROCK_MODEL` (+ `CANARY_AWS_REGION`), `CANARY_GCP_VERTEX_PROJECT` + `CANARY_GCP_VERTEX_MODEL`, `CANARY_AWS_RDS_ENDPOINT` + `CANARY_AWS_RDS_REGION` + `CANARY_AWS_RDS_USER`
