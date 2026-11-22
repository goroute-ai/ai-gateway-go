# Codebase Map

Use this page to find the implementation and the source of truth for a change. Package names below refer to Go packages in this repository.

## Main execution paths

| Area | Start here | Related tests or contracts |
| --- | --- | --- |
| HTTP server, routes, middleware, admin RBAC, file quotas, and bootstrap | `internal/server/` (`handlers_*.go`, `security_headers.go`, `server.go`) | `internal/server/*_test.go`, `tests/e2e/` |
| Native OpenAPI-first provider adapters | `internal/adapter/` (`openai/`, `anthropic/`, `groq/`, `openrouter/`) | `internal/adapter/*/*_test.go`, `docs/openapi/` |
| Canonical request, response, identity, and model types | `internal/domain/` | Tests colocated with consumers; gateway contract in `docs/openapi/gateway.openapi.yaml` |
| Model selection, pre-routing, candidate filtering, priority tiers, PTU capacity sharing, load balancing, retries, specialized fallbacks, hedged racing, affinity, and scheduling | `internal/router/` (`intelligent_router.go`, `prerouter*.go`, `filters.go`, `priority_tiers.go`, `priority_capacity.go`, `fallback_chains.go`, `retry_policy.go`, `stream_continuation.go`, `affinity.go`, `deployment_budgets.go`, `hedged.go`, `scheduler.go`, `load_balancer.go`, `reliability.go`, `chat_execution.go`, `nonchat_execution.go`) | `internal/router/*_test.go`, `tests/e2e/intelligent_routing_cluster_test.go` |
| Active deployment health probing & state tracking | `internal/health/` (`monitor.go`) | `internal/health/*_test.go` |
| Pre-routing request schema, capability, and context-window validation | `internal/validation/` (`validator.go`) | `internal/validation/*_test.go` |
| Embedded model catalogue engine and normalizer CLI | `internal/modelcatalog/`, `cmd/catalog-sync/` | `internal/modelcatalog/*_test.go`, `internal/modelcatalog/catalog.json.gz` |
| Model management, lifecycle discovery, and pricing provenance | `internal/modelmgmt/` | `internal/modelmgmt/*_test.go` |
| Configuration loading, defaults, and provider normalization | `internal/config/` | `internal/config/config_test.go`, `configs/config.example.yaml` |
| Persistence interfaces, PostgreSQL (+ RDS IAM), Redis Cluster/Sentinel, spend outbox, and memory implementations | `internal/storage/` (`repository.go`, `memory*.go`, `postgres*.go`, `redis.go`, `rds_iam.go`) | `internal/storage/*_test.go`, `migrations/` (`0001`–`0038`) |
| MCP codegen, spec profiles, transports, aggregation, and tool execution | `cmd/mcpgen/`, `internal/mcp/spec/`, `internal/mcp/` | `internal/mcp/*_test.go`, `docs/specs/mcp/` |
| A2A OpenAPI-first service, router, streaming, outbox, and gRPC adapter | `internal/a2a/` (`spec/`, `router_service.go`, `jsonrpc.go`, `card.go`, `streams.go`, `outbox_worker.go`, `openai_bridge.go`, `grpc_server.go`) | `internal/a2a/*_test.go`, `docs/openapi/a2a.openapi.yaml`, `docs/specs/a2a/v1.0/` |
| Outbound URL and network policy (SSRF prevention) | `internal/security/network/` | `internal/security/network/network_test.go` |
| Operator RBAC, federated OIDC `(org_id, oidc_issuer, oidc_subject)`, SSO/CLI sessions, HIBP check, SCIM v2, key rotation grace windows, JWT/access-group rules, impersonation & Cloud IAM cache | `internal/auth/`, `internal/auth/upstream/` | `internal/auth/*_test.go`, `tests/e2e/auth_federation_test.go`, `tests/e2e/identity_lifecycle_scim_test.go`, `tests/e2e/operator_sso_iam_test.go` |
| Content, secret, and tool safety checks | `internal/guardrails/` (`engine.go`, `pipeline.go`, `resolver.go`, `router_lb.go`, `stream_filter.go`, `mcp.go`, `drivers/`) | `internal/guardrails/..._test.go`, `tests/guardrails/` |
| Integer micro-dollar cost calculation, multi-dimensional/per-model quotas, multi-window `rolling_24h` budgets & recovery, soft budgets, spend outbox, and reset processing | `internal/finops/`, `internal/ratelimit/` (`descriptors.go`, `scripts/check_descriptors.lua`, `scripts/reconcile_descriptors.lua`, `scripts/renew_descriptors.lua`) | `internal/finops/*_test.go`, `internal/ratelimit/*_test.go`, `tests/e2e/quota_engine_budget_test.go`, `tests/e2e/quota_scopes_priority_test.go`, `tests/e2e/rolling_budget_recovery_test.go` |
| OTLP tracing, structured log scrubbing, and protected metrics | `internal/observability/`, `internal/logger/`, `internal/server/` | Package tests and `tests/e2e/` |
| Public embeddable Go SDK & `CustomAuthenticator` | `pkg/gateway/` (`sdk.go`, `auth.go`, `routing.go`, `types.go`, `a2a_types.go`, `guardrails.go`) | `pkg/gateway/*_test.go` |
| Embedded Operator Web UI & Playground | `internal/ui/` (HTTP embed handler), `web/` (React SPA) | `internal/ui/*_test.go`, `web/scripts/check-budget.mjs`, `tests/ui-e2e/` |
| Executables and contract generation | `cmd/gateway/`, `cmd/specgen/`, `cmd/mcpgen/`, `cmd/catalog-sync/`, `internal/openapi/`, `internal/mcp/spec/` | Check each command's `main.go`, generation directives, and the Makefile |
| Release E2E, Playwright UI E2E, Compose, K8s manifests, and Helm chart | `tests/e2e/`, `tests/guardrails/`, `tests/ui-e2e/`, `deployments/docker-compose*.yml`, `deployments/k8s/`, `deployments/helm/goroute/` | `deployments/docker-compose.test.yml`, `deployments/docker-compose.prod.yml`, `Makefile`, [Testing Guide](./TESTING.md) |
| Release upgrading & testing guides | `docs/UPGRADING.md`, `docs/TESTING.md` | [Upgrade Guide](./UPGRADING.md), [Testing Guide](./TESTING.md) |

## Sources of truth

- **HTTP API shapes:** `docs/openapi/*.yaml`; gateway and A2A DTOs/server interfaces are generated from `docs/openapi/gateway.openapi.yaml` and `docs/openapi/a2a.openapi.yaml`. `make specgen` validates OpenAPI/MCP/A2A contracts, regenerates `internal/openapi/gateway.gen.go` and `internal/a2a/spec/a2a.gen.go`, runs `cmd/mcpgen`, and enforces `/v1`, `/admin/v1`, `/auth`, and provider alias route parity (`128` gateway OpenAPI paths + `21` A2A OpenAPI paths). `/scim/v2/*` and MCP runtime route parity are still handwritten.
- **MCP and A2A protocol schemas:** pinned files under `docs/specs/`. For MCP multi-release code generation, see `internal/mcp/spec/generate.go` (`cmd/mcpgen`); for A2A OpenAPI code generation, see `docs/openapi/a2a.codegen.yaml` (`internal/a2a/spec/`); and for A2A gRPC protobuf code, see `docs/specs/a2a/v1.0/generate.go`.
- **Configuration keys and defaults:** `internal/config/config.go` and `configs/config.example.yaml`. This includes production key validation (`master_admin_key`, `master_encryption_key`, `jwt_secret`, `default_virtual_key`) through `ENV` and `GATEWAY_ENV`, SSRF env overrides, plus per-organization file storage and concurrent upload limits. `configs/config.yaml` is strictly for local development (paired with `deployments/docker-compose.yml`); production Compose stacks use `deployments/docker-compose.prod.yml` and `configs/config.example.yaml`.
- **Database shape and evolution:** ordered SQL migrations in `migrations/` (`0001`–`0040`), paired with repository behavior in `internal/storage/`. Key schema milestones include `0005`–`0021` (tri-state capabilities, pricing history, modality spend/files/batches, spend/budget outboxes, guardrail registry/bindings/toxicity/usage, specialized fallbacks, deployment tags/budgets), `0022`–`0036`, `0037` (pruning legacy non-4-provider / rerank rows), `0038` (`mcp_runtime_settings`), `0039` (`org_scoped_jwt_key_mappings`), and `0040` (`a2a_v1_production_spec`: `is_public_card`, `protocol_binding`, `auth_header_name`, encrypted push-config columns, outbox replay). See [UPGRADING.md](./UPGRADING.md).
- **Shared Redis state:** Redis connection modes and repository behavior live under `internal/storage/`; Lua scripts and rate-limit integration live under `internal/ratelimit/`. Preserve organization hash tags when changing keys used together by Redis Cluster scripts.
- **Security and observability:** outbound policy is implemented in `internal/security/network/`; operator and virtual-key authorization lives in `internal/auth/`; guardrail behavior is in `internal/guardrails/`; OTLP tracing and log scrubbing are in `internal/observability/` and `internal/logger/`.
- **Embedded model catalogue:** `internal/modelcatalog/catalog.json.gz`, generated by `cmd/catalog-sync/` from audited upstream model datasets. Runtime access is provided via `internal/modelcatalog/catalog.go`.
- **Operator Web UI and static assets:** `web/` is the source of truth for the frontend application (React 18 + Vite + TypeScript with `React.lazy` route chunks). Compiled assets are copied to `internal/ui/dist/` via `make ui-build` and embedded into the Go binary. Total bundle budget must remain `<= 560 KB` uncompressed and `<= 150 KB` gzipped (with CSS `<= 35 KB` / `<= 8 KB` gzipped and single JS chunks `<= 150 KB` / `<= 45 KB` gzipped), enforced by `web/scripts/check-budget.mjs`.
- **Runtime behavior:** implementation and focused tests in the corresponding package. Architecture and internals guides explain intent but can drift.
- **Build and CI behavior:** `Makefile` and `.github/workflows/ci.yml`.

## Change paths

- **Add or modify a provider adapter:**
  - Define or update the provider's OpenAPI specification and codegen config under `docs/openapi/`.
  - Generate wire DTOs in `internal/openapi/providers/` via `make specgen`.
  - Implement or update `adapter.ProviderAdapter` under `internal/adapter/<provider>/`.
  - Register the provider enum and aliases in `internal/domain/inference.go` and `internal/config/config.go` (`NormalizeProvider`).
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
