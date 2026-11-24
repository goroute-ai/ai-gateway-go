# GoRoute AI Gateway — Testing & Verification Guide

GoRoute uses a 3-tier verification strategy spanning fast local static checks, in-memory `-race` package and live PostgreSQL/Redis E2E suites, and headless Chromium browser UI E2E verification.

---

## Prerequisites

| Tier | Required Local Tools / Services |
| :--- | :--- |
| **Tier 0 (Static, Contracts & Hygiene)** | Go `1.26+`, Node.js `20+`, `gitleaks` |
| **Tier 1 (Unit `-race` & Live Postgres/Redis E2E)** | Go `1.26+`, Docker Compose (PostgreSQL 16 on `:15432`, Redis 8 on `:16379`) |
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
# Enforces /v1, /admin/v1, and /auth parity (127 total OpenAPI paths)
make specgen && git diff --exit-code -- internal/openapi/ internal/mcp/spec/

# Embedded Operator Web UI asset sync & 700 KB raw / 185 KB gzipped bundle budget
# (Works both on fresh checkouts without web/dist and after `make ui-build`)
make ui-check-dist

# Full working-tree secret scanning (precision synthetic-fixture allowlists in .gitleaks.toml)
make security-scan
```

---

## Tier 1 — Unit Race Suites & Live PostgreSQL + Redis E2E

### In-Memory & Package Suites (`-race`)
```bash
go test -race -count=1 ./internal/... ./pkg/... ./cmd/... ./tests/guardrails/...
```

### Live PostgreSQL 16 + Redis 8 Strict Suites
`make test-postgres` and `make test-e2e-strict` set `GATEWAY_REQUIRE_LIVE_DEPS=1` so zero tests are allowed to skip due to missing Postgres/Redis:

```bash
# 1. Start isolated Postgres 16 (localhost:15432) and Redis 8 (localhost:16379)
make test-live-up

# 2. Verify forward/reverse migrations 0001..0041, preflight checks, and Pg repositories
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

Playwright dependencies and specs live strictly isolated in [`tests/ui-e2e/`](../tests/ui-e2e) so [`web/`](../web) and its `700 KB` raw (`185 KB` gzipped) embedded bundle remain untouched:

```bash
make test-live-up
make test-ui-e2e
make test-live-down
```

[`tests/ui-e2e/run_ui_e2e.sh`](../tests/ui-e2e/run_ui_e2e.sh) builds the real gateway binary, launches a local mock OIDC IdP server (`mock_idp.mjs`), executes migrations, boots the gateway on `http://localhost:<PORT>`, and drives Chromium across [`operator_ui.spec.mjs`](../tests/ui-e2e/operator_ui.spec.mjs):
- Strict `/ui/` CSP (`script-src 'self'` and `style-src 'self'` without `'unsafe-inline'`, plus zero `securitypolicyviolation`, page, or console errors)
- OIDC-only LoginView (no password inputs, legacy `/auth/login` and `/auth/password` return 404/405), PKCE `S256` start redirect, full OIDC callback, and `org_admin` vs `platform_admin` RBAC
- Emergency Break-Glass Key tab (`GATEWAY_MASTER_ADMIN_KEY`) unlock and `/ui/cli` CLI device-approval flow
- `HttpOnly` `goroute_session` persistence across page reloads
- `KeysView` `llm_api` preset creation and manual grace-period key rotation badges
- `FinOpsView` -> `QuotasTab` per-model policy (`model_per_key`), `rolling_24h` budget window, `TempBudgetModal` persistence across reload, and `/auth/logout` session revocation
- `AgenticView` multi-release MCP protocol switching across `2024-11-05`..`2026-07-28`, persistence across reload, and `Register Upstream MCP Server` auto-transport selection
- Caching UI wiring across `OverviewView` (rich Response Cache card, org-scoped default Purge modal with `"Invalidation revision"` feedback), `PlaygroundView` (`JSON (Cacheable)` mode & `Cache Controls`), and `FinOpsView` (`All` / `Cache Hits` / `Semantic Cache` filter pills)

---

## Tier 3 — Production-Like Docker OIDC Verification (`make test-prod-docker`)

Runs an isolated production-topology Docker Compose stack (`deployments/prod-test/docker-compose.prod-test.yml`) featuring:
- 2× read-only non-root GoRoute AI Gateway replicas (`GATEWAY_ENV=production`, `enable_hsts: true`, fail-closed SSRF policy)
- Live Keycloak 26 production instance (`start` mode backed by PostgreSQL, `sslRequired: "all"`)
- Caddy TLS 1.3 reverse proxy terminating `https://gateway.prod.test` and `https://auth.prod.test` with an ephemeral test CA
- PostgreSQL 16 (TLS) and Redis 8 (`--requirepass`) on an isolated internal data network plus an SSRF trap service

```bash
make test-prod-docker
```

Executes Suites `1`–`9`, `5b`, `6b`, `7b`, `11` (plus opt-in Suite `10` when ephemeral `PROD_LIVE_*_API_KEY` env vars are provided in CI/local shell — never committed) and Suite `99`, covering all 19 enterprise authorization & access-control capabilities: startup fail-closed container checks, migrations `0039`/`0040`/`0041`, asymmetric JWT (`RS256`/`ES256`/`EdDSA`), expired/wrong-aud/forged JWT rejection, positive & negative `jwt_key_mappings`, RFC 7662 introspection, multi-replica SCIM/admin session revocation, `group_role_mappings` + `sync_roles_on_login`, full 7-role RBAC matrix (`platform_admin`..`viewer`), positive/negative `team_admin` & `team_member_permissions`, CSRF cookie enforcement, Org deactivation cutoff, self-service `/v1/self/keys` isolation, wildcard models + Org Model Policy & Org Provider Subscription gates, `Team ∩ Project ∩ Key` `allowed_deployments` & mandatory `allowed_routing_tags` across chat/responses/embeddings, Project `enforce_project_model_quota`, distributed Redis RPM/TPM/concurrency limits, multi-window `rolling_24h` & temporary budget boosts, multi-server `/mcp` Virtual Hub isolation, positive `allowed_mcp_tools`/`toolsets` & unconditional `ToolPolicy`, A2A `key_strict` isolation + emergency kill-switch, positive Unified Access Group & gated `ModelAccessGroup` + Dynamic `AccessGroupRule` grants, fail-closed `ExternalAuthorizer` (`deny_models`/`deny_tools`/`deny_agents`/`deny_paths` + 503 outage), Virtual Key endpoint allowlists/expiry/rotation grace window/revocation/delegation narrowing, filtered cursor audit logs & HMAC-signed `audit.siem_webhook` (including MCP/A2A admin mutations), `cmd/goroute` CLI E2E, SSRF/secret-scrubbing log scans, resilience (Keycloak outage stale-JWKS survival, Redis restart, live KEK rotation), and Playwright Chromium browser login + seamless Keycloak RP-Initiated Logout (`id_token_hint`).

See [AUTHORIZATION_AND_ACCESS_CONTROL.md](./AUTHORIZATION_AND_ACCESS_CONTROL.md) for the full 19-capability architectural reference and single-node `deployments/docker-compose.yml` smoke test instructions.

---

## Tier 3b — Production-Grade Docker Caching Verification (`make test-cache-prod-docker`)

Runs an isolated 2-replica production Docker stack (`deployments/cache-prod-test/docker-compose.cache-prod.yml`) featuring:
- 2× read-only non-root distroless GoRoute replicas (`GATEWAY_ENV=production`, `enable_hsts: true`, strict `https`-only outbound SSRF)
- Caddy TLS 1.3 load balancer (`https://gateway.prod.test:19443`, direct replica ports `:19444` & `:19445`)
- PostgreSQL 16 (TLS), primary `redis:8-alpine` (`redis-primary` for Auth L2, rate limits, budgets), and dedicated `redis:8-alpine` (`redis-cache` with `--maxmemory 128mb --maxmemory-policy volatile-lru` strictly for KV & RediSearch vector caching)

```bash
GATEWAY_TEST_GEMINI_API_KEY="<ephemeral-key>" make test-cache-prod-docker
```

Executes Suites `C0`–`C6` across all live cache modes (`local`, `redis`, `redis-semantic` `HNSW`, and `redis-semantic` `FLAT`) against live Gemini (`gemini-3.5-flash-lite` + `gemini-embedding-001`), verifying fail-closed startup gates, LRU bounds, cross-replica KV & RediSearch vector hits (`FT.INFO`), dedicated vs primary Redis keyspace isolation, multi-tenant/scope isolation, strict AND admin invalidation, chaos fail-open survival & automatic recovery when `redis-cache` stops/restarts, 20-goroutine concurrency stress, PostgreSQL `$0` hit FinOps spend audit, Admin UI metrics snapshot parity, config secret redaction, and container log secret-leakage scanning.

---

## Tier 3c — Production-Grade Docker OTLP Observability Verification (`make test-obs-prod-docker`)

Runs an isolated 2-replica production Docker stack (`deployments/obs-prod-test/docker-compose.obs-prod.yml`) featuring:
- 2× read-only non-root distroless GoRoute replicas (`GATEWAY_ENV=production`, `enable_hsts: true`, strict `https`-only outbound SSRF, all 3 OTLP/HTTP signals enabled)
- Real `otel/opentelemetry-collector-contrib` instance writing OTLP JSONL for traces, metrics, and logs (`file` exporter)
- Caddy TLS 1.3 edge terminating `gateway.prod.test`, `otel.prod.test`, and `fixtures.prod.test`
- PostgreSQL 16 (TLS), Redis 8 (`--requirepass`), and deterministic HTTPS mock upstreams for all 4 adapters (`openai`, `anthropic`, `groq`, `openrouter`), MCP Streamable HTTP, A2A, and an HMAC-SHA256 SIEM audit webhook

```bash
make test-obs-prod-docker
```

Executes Suites `O0`–`O5`: fail-closed startup rejection on unresolved `os.environ/` in `otel.headers` & invalid sampler, `otel.enabled=false` zero-traffic verification, `404` on removed `/metrics`, GenAI semantic convention OTLP traces (`chat`, `embeddings`, `cache.lookup`, `guardrail.evaluate`, `execute_tool`, `invoke_agent`, `gen_ai.first_token`, zero prompt leakage), pure dot-separated `gen_ai.*` & `gateway.*` OTLP metrics, live Redis outage chaos proving `gateway.redis.circuit_breaker.state` transitions `0` → `2` in OTLP `metrics.jsonl` and `/admin/v1/observability/metrics`, post-scrub OTLP logs + JSON stdout correlation (`trace_id`, `span_id`, `org_id`, `virtual_key_id`), 4-adapter outbound W3C `traceparent` propagation, and HMAC-SHA256 SIEM webhook delivery + `/admin/v1/config` secret redaction.
