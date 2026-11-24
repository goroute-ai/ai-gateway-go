# Changelog

All notable changes to the GoRoute AI Gateway project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Single-Backend Response Caching (`local` | `redis` | `redis-semantic`), Hardening & Operator Web UI Wiring

#### Added
- **Single-Backend Response Caching (`internal/cache/`)**:
  - Clean `Backend` / `SemanticBackend` abstraction selected via `cache.type`: `local` (bounded in-memory LRU with multi-replica Redis Pub/Sub admin invalidation broadcast), `redis` (direct Redis KV with mutex-safe Redis Cluster `SCAN`, batched `MGET`/pipeline model invalidation, and `UNLINK`), and `redis-semantic` (Redis 8+ RediSearch `FLOAT32` `COSINE` `HNSW`/`FLAT` vector similarity search with atomic `TxPipeline` `HSET`+`EXPIRE`, `FT.INFO` vector dimension validation, single-embed-per-miss vector reuse, and automatic self-healing index recreation after ephemeral Redis restarts).
  - Strict tenant, multi-turn, and parameter isolation: hex-hashed RediSearch `TAG` filters (`scope`, `org_id`, `model` including both resolved upstream model and requested `ModelGroup` alias), multimodal (`image_url`/`document`) and tool-call semantic bypass, prior-turn + `user` + `extra_params` semantic scope binding, `seed` cache eligibility (`temperature > 0`), `cache.semantic.max_messages: -1` unlimited mode, and rune-safe UTF-8 prompt truncation.
  - Optional dedicated cache Redis (`cache.redis_addr`/`redis_addrs`/`redis_master_name`/`redis_pass`/`redis_db`/`redis_tls` with TLS 1.2+ and `500ms` fail-open timeouts), fail-open `/readyz` `"cache_status": "ok" | "degraded"` reporting, default `cache.excluded_call_types: ["embedding"]`, and `max_l1_entries` preserved as a silent deprecated YAML alias for `max_entries`.
  - Unified `$0` (`cache_hit: true`) FinOps `spend_logs` audit records across all 5 cached endpoints (`/v1/chat/completions`, `/v1/messages`, `/v1/responses`, `/v1/completions`, `/v1/embeddings`) plus async internal semantic-cache embedding spend logging under `endpoint: "_internal/semantic_cache"`.
  - Backend-agnostic Prometheus cache metrics (`gateway_cache_hits_total`, `gateway_cache_misses_total`, `gateway_cache_errors_total`, `gateway_cache_semantic_hits_total`, `gateway_cache_entries`, `gateway_cache_evictions_total`) and authoritative `Collector.SetCacheTelemetryProvider` parity on `GET /admin/v1/observability/metrics`.
  - Documented `X-Gateway-Cache`, `X-Gateway-Cache-Type`, and `X-Gateway-Cache-Similarity` headers in OpenAPI 3.1 (`docs/openapi/gateway.openapi.yaml`) and CORS `Access-Control-Expose-Headers`.
- **Operator Web UI Caching Wiring (`web/src/`, `internal/ui/dist/`)**:
  - `PlaygroundView`: `Stream SSE | JSON (Cacheable)` response mode toggle, collapsible **Cache Controls** (`Cache Mode`, `Seed`, `Semantic Similarity` override), token usage & cache telemetry display, and updated `curl`/Python/TypeScript/Go code exports.
  - `OverviewView`: Rich Response Cache KPI card showing active backend badge, semantic hits, local entry count, and degraded/error warnings; safe **Purge Cache** modal defaulting to `Current Organization` with `platform_admin`-gated Global scope and updated `"Invalidation revision"` copy.
  - `FinOpsView`: `All` / `Cache Hits` / `Semantic Cache` filter pills, `CACHE HIT` (`$0`) and `semantic cache` (`_internal/semantic_cache`) badges, endpoint search, and Inspector modal metadata.
- **Redis 8 & Production Docker Caching Verification (`deployments/cache-prod-test/`, `tests/cache-prod-docker/`)**:
  - Upgraded Docker Compose, Kubernetes, and CI Redis images to `redis:8-alpine`.
  - Added Tier 3b `make test-cache-prod-docker` 2-replica HA production Docker caching suite (`Suites C0–C6 + FLAT` + chaos fail-open & auto-recovery) and live Redis 8 integration tests (`tests/e2e/cache_semantic_test.go`).

#### Removed
- Removed dual-tier L1+L2 Redis Lua epoch response caching (`internal/cache/cache_epochs.go`, `internal/cache/response_cache_redis_test.go`).
- Removed raw SSE chunk-array streaming response caching (`internal/server/stream_cache_test.go` and per-handler chunk buffering; deferred to `v0.2` via canonical assembled-response replay).
- Removed `router.cache_aware_routing` (`QualityPreRouter` ↔ `ResponseCache` coupling; independent `router.prompt_cache_affinity` preserved) and the dead MCP `tools/call` cache hook.

---

## [0.1.0] - 2026-11-23

### Initial Baseline — OpenAPI-First AI Gateway, OIDC Federation, Multi-Release MCP Hub & A2A v1.0 Router

#### Added
- **Unified OpenAPI-First Data Plane & 4-Provider Inference Engine (`docs/openapi/gateway.openapi.yaml`, `internal/adapter/`, `cmd/specgen`)**:
  - OpenAI-compatible unified data plane (`/v1/chat/completions`, `/v1/responses`, `/v1/messages`, `/v1/completions`, `/v1/embeddings`, `/v1/moderations`, `/v1/images/*`, `/v1/audio/*`, `/v1/files`, `/v1/batches`, `/v1/realtime` WebSocket) across `127` OpenAPI 3.1.0 endpoints (`27` `/v1`, `88` `/admin/v1`, `8` `/auth`, `4` provider aliases).
  - Spec-generated provider adapters for **OpenAI**, **Anthropic Claude**, **Groq**, and **OpenRouter** with zero-buffer Server-Sent Events (SSE) streaming, reasoning token normalization, and provider parameter sanitization (`X-Gateway-Dropped-Params`).
- **6-Stage Intelligent Routing & Resilience Engine (`internal/router/`)**:
  - PreRouter model alias resolution, deployment candidate filter chain (health, region, tag, context window, modality, priority rank, deployment allowlist), priority-tier step-down, sliding-window health scoring, 3-state circuit breakers, UCB1 adaptive bandit routing, hedged request racing, session affinity pinning, distributed Redis slot leases, saturation fallbacks, and mid-stream SSE continuation.
- **Vendor-Neutral OIDC-Only Federation & 19-Feature Authorization Parity (`internal/auth/`, `migrations/0001`–`0041`)**:
  - Multi-issuer OIDC discovery and JWKS verification, Authorization Code + PKCE (`S256`) browser & CLI SSO, RP-Initiated Logout with encrypted `id_token_hint`, RFC 7662 token introspection / UserInfo, SCIM 2.0 user/group provisioning (`/scim/v2/*`), and emergency break-glass master admin key authentication.
  - Unified action-based authorization (`AuthAction`, `EvaluateAuthorization`), fail-closed `ExternalAuthorizer` (`auth.external_authorizer` HTTP/OPA webhook & `pkg/gateway.WithCustomAuthorizer` Go SDK hook), SSO group-to-role and group-to-team mappings (`group_role_mappings`), Access Groups covering models/MCP/A2A, and HMAC-signed SIEM audit webhook export (`audit.siem_webhook`) with keyset cursor pagination.
- **AES-256-GCM Envelope Encryption Vault, Virtual Keys & Secret Sinks (`internal/auth/vault.go`, `internal/auth/rotation.go`)**:
  - Per-credential DEK envelope encryption, zero-downtime rolling Master KEK rotation (`POST /admin/v1/security/rotate-kek` with `auth.previous_master_encryption_keys`), SHA-256 virtual key issuance (`sk-gw-...`), grace-period key rotation, expiry alert manager, self-service developer key APIs (`/v1/self/keys`), and transactional secret delivery sinks (`webhook`, `vault_kv2`, `aws_secrets_manager`).
- **Distributed Redis Lua Quota Engine & Integer Micro-Dollar FinOps (`internal/ratelimit/`, `internal/finops/`)**:
  - Multi-window sliding rate limits (RPM, TPM, ITPM, OTPM, RPD), descriptor-scoped quota policies (organization, team, project, user, virtual key, end-user, tag, session, MCP), PTU capacity fair-share scheduler, pre-execution budget leases, durable spend event outbox, and rolling 24-hour / periodic budget resets.
- **15-Driver Guardrail Pipeline & Sensitive Routing (`internal/guardrails/`)**:
  - Concurrent 3-phase (input, streaming chunk, output) guardrail evaluation across 15 built-in drivers (PII redaction, prompt injection, jailbreak, toxicity, secrets/credentials, code execution, topic blocklist, regex, schema validator, custom HTTP webhook, and `GuardrailActionRoute` sensitive route redirection).
- **Spec-Generated 5-Release MCP Virtual Hub (`cmd/mcpgen`, `internal/mcp/`)**:
  - Vendored YAML schemas and generated Go types/validators for all 5 official Model Context Protocol releases (`2024-11-05`, `2025-03-26`, `2025-06-18`, `2025-11-25`, `2026-07-28`) with live runtime spec switching, stdio/SSE/StatefulStreamable HTTP transports, AEAD-encrypted multi-round tool resumption tokens (MRTR), SHA-256 tool schema pinning, and unconditional `ToolPolicy` / 3-state tool allowlist enforcement.
- **Linux Foundation A2A v1.0 Protocol Router & ReAct Orchestrator (`internal/a2a/`, `internal/orchestrator/`)**:
  - OpenAPI-first and Protobuf/gRPC A2A v1.0 task hub (`SendMessage`, `SendStreamingMessage`, `GetTask`, `ListTasks`, `CancelTask`, `SubscribeToTask`, push notifications, Agent Card discovery), outbound gRPC/JSON-RPC/REST bindings, retention pruning, emergency kill-switch controls, and multi-step ReAct agent orchestration.
- **Embedded React Operator Web UI, Go SDK & `goroute` Developer CLI (`web/`, `internal/ui/`, `pkg/gateway/`, `cmd/goroute/`)**:
  - Zero-Node runtime embedded React SPA (`/ui/`) with OIDC SSO + break-glass login, streaming Playground, Organizations/Teams/Projects/Access-Groups console, Virtual Keys, Provider Credentials, Models & Routing, FinOps & Quotas, Guardrails, Agentic Hub (MCP & A2A), and Configuration/Audit diff viewer.
  - Embeddable in-process Go SDK (`pkg/gateway`) and standalone developer CLI (`cmd/goroute`) with OIDC PKCE device login (`goroute login`, `goroute whoami`, `goroute models`, `goroute keys`, `goroute projects`).
- **Production Deployment Packaging & Verification Suites (`deployments/`, `tests/`)**:
  - Multi-arch Distroless `Dockerfile`, OCI Helm chart (`deployments/helm/goroute`), Kubernetes manifests (`deployments/k8s`), and 3-tier verification harness including unit/race suites, PostgreSQL 16 + Redis 7 E2E tests, Playwright Chromium UI E2E tests, and Keycloak 26 HA Docker production verification (`tests/prod-docker/`).
