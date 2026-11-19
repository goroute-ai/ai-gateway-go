# Codebase Map

Use this page to find the implementation and the source of truth for a change. Package names below refer to Go packages in this repository.

## Main execution paths

| Area | Start here | Related tests or contracts |
| --- | --- | --- |
| HTTP server, routes, middleware, admin RBAC, file quotas, and bootstrap | `internal/server/` (`handlers_*.go`, `security_headers.go`, `server.go`) | `internal/server/*_test.go`, `tests/e2e/` |
| Native dedicated provider adapters | `internal/adapter/` (`anthropic/`, `azure/`, `bedrock/`, `cohere/`, `gemini/`, `mistral/`, `ollama/`, `openai/`, `vertex/`) | `internal/adapter/*/*_test.go`, `docs/openapi/` |
| Certified OpenAI-compatible provider profiles & dialect engine | `internal/adapter/openaicompat/` (`builtin_profiles.go`, `adapter.go`, `profile.go`) | `internal/adapter/openaicompat/*_test.go` |
| Canonical request, response, identity, and model types | `internal/domain/` | Tests colocated with consumers; gateway contract in `docs/openapi/gateway.openapi.yaml` |
| Model selection, pre-routing, candidate filtering, priority tiers, PTU capacity sharing, load balancing, retries, specialized fallbacks, hedged racing, affinity, and scheduling | `internal/router/` (`intelligent_router.go`, `prerouter*.go`, `filters.go`, `priority_tiers.go`, `priority_capacity.go`, `fallback_chains.go`, `retry_policy.go`, `stream_continuation.go`, `affinity.go`, `deployment_budgets.go`, `hedged.go`, `scheduler.go`, `load_balancer.go`, `reliability.go`) | `internal/router/*_test.go`, `tests/e2e/intelligent_routing_cluster_test.go` |
| Active deployment health probing & state tracking | `internal/health/` (`monitor.go`) | `internal/health/*_test.go` |
| Pre-routing request schema, capability, and context-window validation | `internal/validation/` (`validator.go`) | `internal/validation/*_test.go` |
| Embedded model catalogue engine and normalizer CLI | `internal/modelcatalog/`, `cmd/catalog-sync/` | `internal/modelcatalog/*_test.go`, `internal/modelcatalog/catalog.json.gz` |
| Model management, lifecycle discovery, and pricing provenance | `internal/modelmgmt/` | `internal/modelmgmt/*_test.go` |
| Configuration loading, defaults, and provider normalization | `internal/config/` | `internal/config/config_test.go`, `configs/config.example.yaml` |
| Persistence interfaces, PostgreSQL (+ RDS IAM), Redis Cluster/Sentinel, spend outbox, and memory implementations | `internal/storage/` | `internal/storage/*_test.go`, `migrations/` (`0001`–`0034`) |
| MCP transports, aggregation, and tool execution | `internal/mcp/` | `internal/mcp/*_test.go`, `docs/specs/mcp/` |
| A2A HTTP/gRPC service, task durability, and streaming | `internal/a2a/` | `internal/a2a/*_test.go`, `docs/specs/a2a/v1.0/` |
| Outbound URL and network policy (SSRF prevention) | `internal/security/network/` | `internal/security/network/network_test.go` |
| Operator RBAC, federated OIDC `(org_id, oidc_issuer, oidc_subject)`, SSO/CLI sessions, HIBP check, SCIM v2, key rotation grace windows, JWT/access-group rules, impersonation & Cloud IAM cache | `internal/auth/`, `internal/auth/upstream/` | `internal/auth/*_test.go`, `tests/e2e/auth_federation_test.go`, `tests/e2e/identity_lifecycle_scim_test.go`, `tests/e2e/operator_sso_iam_test.go` |
| Content, secret, and tool safety checks | `internal/guardrails/` (`engine.go`, `pipeline.go`, `resolver.go`, `router_lb.go`, `stream_filter.go`, `mcp.go`, `drivers/`) | `internal/guardrails/..._test.go`, `tests/guardrails/` |
| Integer micro-dollar cost calculation, multi-dimensional/per-model quotas, multi-window `rolling_24h` budgets & recovery, soft budgets, spend outbox, and reset processing | `internal/finops/`, `internal/ratelimit/` (`descriptors.go`, `scripts/check_descriptors.lua`, `scripts/reconcile_descriptors.lua`, `scripts/renew_descriptors.lua`) | `internal/finops/*_test.go`, `internal/ratelimit/*_test.go`, `tests/e2e/quota_engine_budget_test.go`, `tests/e2e/quota_scopes_priority_test.go`, `tests/e2e/rolling_budget_recovery_test.go` |
| OTLP tracing, structured log scrubbing, and protected metrics | `internal/observability/`, `internal/logger/`, `internal/server/` | Package tests and `tests/e2e/` |
| Public embeddable Go SDK & `CustomAuthenticator` | `pkg/gateway/` (`sdk.go`, `auth.go`, `routing.go`, `types.go`, `guardrails.go`) | `pkg/gateway/*_test.go` |
| Embedded Operator Web UI & Playground | `internal/ui/` (HTTP embed handler), `web/` (React SPA) | `internal/ui/*_test.go`, `web/scripts/check-budget.mjs`, `tests/ui-e2e/` |
| Executables and contract generation | `cmd/gateway/`, `cmd/specgen/`, `cmd/catalog-sync/`, `internal/openapi/` | Check each command's `main.go`, generation directives, and the Makefile |
| Production testing, Playwright UI E2E, load, canary, K8s manifests, and Helm chart | `tests/e2e/`, `tests/ui-e2e/`, `tests/load/`, `tests/canary/`, `tests/scripts/`, `deployments/k8s/`, `deployments/helm/goroute/` | `deployments/docker-compose.test.yml`, `deployments/docker-compose.prod-test.yml`, `Makefile`, [Testing Guide](./TESTING.md) |
| Release upgrading & testing guides | `docs/UPGRADING.md`, `docs/TESTING.md` | [Upgrade Guide](./UPGRADING.md), [Testing Guide](./TESTING.md) |

## Sources of truth

- **HTTP API shapes:** `docs/openapi/*.yaml`; gateway DTOs and standard/strict server interfaces are generated from `docs/openapi/gateway.openapi.yaml`. `make specgen` validates contracts and enforces `/v1`, `/admin/v1`, and `/auth` route parity (`118` OpenAPI paths: `28` `/v1`, `80` `/admin/v1`, `10` `/auth`). Runtime handlers are still partly handwritten, and unversioned/provider aliases, `/scim/v2/*`, MCP, and A2A route parity is not yet enforced.
- **MCP and A2A protocol schemas:** pinned files under `docs/specs/`. For A2A generated Go code, see `docs/specs/a2a/v1.0/generate.go` and its `go:generate` command.
- **Configuration keys and defaults:** `internal/config/config.go` and `configs/config.example.yaml`. This includes production key validation through `ENV` and `GATEWAY_ENV`, plus per-organization file storage and concurrent upload limits. The deployed sample `configs/config.yaml` may contain local/demo secrets; do not copy credentials into documentation.
- **Database shape and evolution:** ordered SQL migrations in `migrations/` (`0001`–`0035`), paired with repository behavior in `internal/storage/`. Key schema milestones include `0005`–`0021` (tri-state capabilities, pricing history, modality spend/files/batches, spend/budget outboxes, guardrail registry/bindings/toxicity/usage, specialized fallbacks, deployment tags/budgets) and `0022`–`0035` (`0022` realtime/batch quotas, `0023` soft budgets & budget fallbacks, `0024` `jwt_key_mappings`, `0025` `virtual_key_deprecated_hashes`, `0026` `access_group_rules`, `0027` `team_memberships` & `projects`, `0028` SCIM & impersonation columns, `0029` `quota_policies`, `0030` `budget_window_limits`, `0031` `end_users`, `tags`, & `model_access_groups`, `0032` `deployment_ptu_shares` & `priority_classes`, `0033` `user_credentials` & `operator_sessions`, `0034` `(org_id, oidc_issuer, oidc_subject)` index, staged key rotation columns, `rolling_hold_micros`, `rolling_24h` `spend_logs` index, and transaction-locked duplicate-subject rollback preflight, `0035` `team_member_permissions`, `audit_logs.before_value`/`after_value`, and virtual key `last_rotated_at`/`rotation_count`/`revoked_at`/`revoked_by`/`expiry_alert_sent_days`). See [UPGRADING.md](./UPGRADING.md).
- **Shared Redis state:** Redis connection modes and repository behavior live under `internal/storage/`; Lua scripts and rate-limit integration live under `internal/ratelimit/`. Preserve organization hash tags when changing keys used together by Redis Cluster scripts.
- **Security and observability:** outbound policy is implemented in `internal/security/network/`; operator and virtual-key authorization lives in `internal/auth/`; guardrail behavior is in `internal/guardrails/`; OTLP tracing and log scrubbing are in `internal/observability/` and `internal/logger/`.
- **Embedded model catalogue:** `internal/modelcatalog/catalog.json.gz`, generated by `cmd/catalog-sync/` from audited upstream model datasets. Runtime access is provided via `internal/modelcatalog/catalog.go`.
- **Operator Web UI and static assets:** `web/` is the source of truth for the frontend application (React 18 + Vite + TypeScript with `React.lazy` route chunks). Compiled assets are copied to `internal/ui/dist/` via `make ui-build` and embedded into the Go binary. Total bundle budget must remain `<= 560 KB` uncompressed and `<= 150 KB` gzipped (with CSS `<= 35 KB` / `<= 8 KB` gzipped and single JS chunks `<= 150 KB` / `<= 45 KB` gzipped), enforced by `web/scripts/check-budget.mjs`.
- **Runtime behavior:** implementation and focused tests in the corresponding package. Architecture and internals guides explain intent but can drift.
- **Build and CI behavior:** `Makefile` and `.github/workflows/ci.yml`.

## Change paths

- **Add or modify a provider adapter:**
  - For proprietary protocols (e.g. AWS SigV4, GCP OAuth2), create or update a subpackage under `internal/adapter/` implementing `adapter.ProviderAdapter`.
  - For OpenAI-compatible providers, add or update a profile entry in `internal/adapter/openaicompat/builtin_profiles.go` or `internal/adapter/openaicompat/extended_profiles.go` with explicit `SupportedOperations`.
  - Add the provider enum and aliases to `internal/config/config.go` (`NormalizeProvider`).
  - Register the provider in `internal/server/server.go` (`adapter.Registry`).
  - Route all network egress through `internal/security/network`.
- **Change an endpoint or wire type:** update the gateway OpenAPI contract, regenerate DTOs/interfaces with `make specgen`, update the server handler and explicit domain conversion as needed, and add focused handler/contract tests.
- **Change configuration:** update the config struct, defaults/loading/validation, example config, configuration guide, and config tests together.
- **Change persisted state:** update repository interfaces/implementations, add forward and rollback migrations in `migrations/`, and test both schema-dependent repository behavior and in-memory behavior where applicable.
- **Modify or extend the Operator Web UI:**
  - Make component and view edits in `web/src/`.
  - For local development with live reload, run `make ui-dev` (starts Vite dev server proxying to port 8080).
  - Before commit, run `make ui-build` to compile assets, enforce bundle size limits (`web/scripts/check-budget.mjs`), and sync files to `internal/ui/dist/`.
  - Run `make ui-check-dist` and `go test ./internal/ui/...` to verify embedded asset serving.
- **Change routing, authorization, or spend behavior:** inspect package invariants and tests before altering selection, fallback, budget, or precision semantics. Ensure fail-closed error handling in both Stage 1 routing (`internal/router/intelligent_router.go`) and Stage 2 dispatch (`internal/auth/rbac.go`).
