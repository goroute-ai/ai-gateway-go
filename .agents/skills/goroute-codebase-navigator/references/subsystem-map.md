# GoRoute AI Gateway — Subsystem & Entrypoint Map

| Domain | Primary Package / Directory | Key Files to Inspect First | Focused Tests & Contracts |
| :--- | :--- | :--- | :--- |
| **Binaries & CLI** | `cmd/` | `cmd/gateway/main.go`, `cmd/goroute/main.go`, `cmd/specgen/`, `cmd/mcpgen/`, `cmd/catalog-sync/` | `cmd/...` tests, `tests/prod-docker/` |
| **HTTP Server & Routes** | `internal/server/` | `server.go`, `handlers_inference.go`, `handlers_admin*.go`, `handlers_auth*.go`, `handlers_mcp.go`, `handlers_a2a.go`, `security_headers.go`, `audit_siem_sink.go` | `internal/server/*_test.go`, `docs/openapi/gateway.openapi.yaml` |
| **Canonical Domain Types** | `internal/domain/` | `entities.go`, `identity.go`, `inference.go`, `errors.go`, `governance.go` | Consumer tests |
| **4 Provider Adapters** | `internal/adapter/` | `adapter.go`, `registry.go`, `sse/`, `openai/`, `anthropic/`, `groq/`, `openrouter/` | `internal/adapter/.../*_test.go`, `docs/openapi/*.openapi.yaml` |
| **6-Stage Intelligent Router** | `internal/router/` | `intelligent_router.go`, `prerouter*.go`, `filters.go`, `priority_tiers.go`, `priority_capacity.go`, `load_balancer.go`, `bandit.go`, `hedged.go`, `chat_execution.go`, `nonchat_execution.go`, `reliability.go`, `fallback_chains.go`, `stream_continuation.go`, `deployment_slots.go` | `internal/router/*_test.go`, `tests/e2e/intelligent_routing_cluster_test.go` |
| **OIDC Auth, Authz & Vault** | `internal/auth/` | `authorizer.go`, `role_mapping.go`, `tool_authz.go`, `rbac.go`, `vault.go`, `rotation.go`, `oidc*.go`, `scim*.go`, `upstream/` | `internal/auth/.../*_test.go`, `tests/e2e/auth_federation_test.go`, `tests/e2e/operator_sso_iam_test.go` |
| **Outbound SSRF Policy** | `internal/security/network/` | `policy.go`, `dialer.go` | `internal/security/network/*_test.go` |
| **Rate Limits & Quotas** | `internal/ratelimit/` | `limiter.go`, `descriptors.go`, `scripts/*.lua` | `internal/ratelimit/*_test.go`, `tests/e2e/quota_*_test.go` |
| **FinOps & Budgets** | `internal/finops/` | Cost calculation, spend outbox, rolling 24h recovery | `internal/finops/*_test.go`, `tests/e2e/rolling_budget_recovery_test.go` |
| **Guardrails (15 Drivers)** | `internal/guardrails/` | `engine.go`, `pipeline.go`, `resolver.go`, `router_lb.go`, `stream_filter.go`, `mcp.go`, `drivers/` | `internal/guardrails/.../*_test.go`, `tests/guardrails/` |
| **5-Release MCP Hub** | `internal/mcp/` | `hub.go`, `spec_profile.go`, `spec/` (`v20241105`..`v20260728`), `transport_*.go` | `internal/mcp/.../*_test.go`, `docs/specs/mcp/` |
| **A2A v1.0 & Orchestrator** | `internal/a2a/`, `internal/orchestrator/` | `internal/a2a/hub.go`, `card.go`, `pb/`, `internal/orchestrator/` | `internal/a2a/*_test.go`, `docs/specs/a2a/v1.0/` |
| **Persistence & Migrations** | `internal/storage/`, `migrations/` | `repository.go`, `memory_*.go`, `postgres_*.go`, `redis.go`, `rds_iam.go`, `audit_cursor.go`, `migrations/0001..0041` | `internal/storage/*_test.go`, `make test-postgres` |
| **Config, Validation & Health** | `internal/config/`, `internal/validation/`, `internal/health/` | `internal/config/config.go`, `configs/config.example.yaml` | Package tests |
| **Public Go SDK** | `pkg/gateway/` | `sdk.go`, `auth.go`, `authz.go`, `routing.go`, `guardrails.go`, `types.go`, `example_test.go` | `pkg/gateway/*_test.go` |
| **Embedded Operator Web UI** | `web/`, `internal/ui/` | `web/src/views/`, `web/src/components/`, `web/scripts/check-budget.mjs`, `internal/ui/dist/` | `internal/ui/*_test.go`, `tests/ui-e2e/` |
