# Changelog

All notable changes to the GoRoute AI Gateway project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### First-Class OpenAPI-First Ollama Provider, Security Hardening & Production Verification

#### Added
- **Native OpenAPI-First Ollama Provider (`docs/openapi/ollama.openapi.yaml`, `internal/openapi/providers/ollama_types.gen.go`, `internal/adapter/ollama/`)**:
  - Added pinned OpenAPI 3.0.3 contract (`5` paths: `POST /v1/chat/completions`, `POST /v1/completions`, `POST /v1/embeddings`, `GET /api/tags`, `GET /v1/models`) and generated `Ollama*` wire DTOs via `make specgen` (`oapi-codegen@v2.8.0`).
  - Implemented `internal/adapter/ollama/` supporting sync & SSE streaming chat completions (`stream_options.include_usage`, tool calling, `json_schema` structured outputs, `reasoning_effort`, assistant prefill, prompt cache token metrics), sync & SSE streaming legacy text completions, batch vector embeddings, and primary `/api/tags` model discovery with automatic `/v1/models` fallback.
  - Added keyless local Ollama support (optional `api_key` strictly scoped to `provider == "ollama"` across adapter, `bootstrap.go`, `POST /admin/v1/credentials/validate`, and Operator Web UI `CredentialsView`), root & `/v1` base URL normalization, W3C `traceparent` propagation, and `OLLAMA_HOST`/`OLLAMA_BASE_URL`/`OLLAMA_API_KEY`/`OLLAMA_DEFAULT_MODEL` opt-in environment resolution.
  - Added paired idempotent PostgreSQL migration `0042_seed_ollama_models.{up,down}.sql` seeding `ollama/qwen2.5:0.5b` and `ollama/all-minilm:latest` at `0 µ$` default local cost (with matching memory repository seeds and `ProfileLlamaBPE` tokenization).
  - Wired Ollama across the Operator Web UI (`CredentialsView`, `ModelsView`, `Badge`, `types/index.ts`), embedded Go SDK demo mode (`pkg/gateway`), dual-node cluster E2E (`tests/e2e/ollama_provider_test.go`), Playwright UI E2E, and Tier 3c `make test-obs-prod-docker` (upgraded to 5-adapter W3C `traceparent` verification plus opt-in `SuiteO6_LiveRealOllamaOverTLS`).
  - Added reusable coding-agent runbook `.agents/skills/goroute-add-provider/` documenting GoRoute's OpenAPI-first provider onboarding architecture.

#### Security
- **Loopback Custom BaseURL RBAC Hardening (`internal/server/handlers_admin.go`)**: Extended `authorizeCustomBaseURL` to enforce `platform_admin` role whenever `security.network.outbound_ssrf.allow_loopback_http` is enabled (matching `allow_private_networks` and `allowed_private_cidrs`), preventing tenant `org_admin` actors from probing arbitrary loopback ports in multi-tenant deployments.
- **Ollama VRAM Eviction Protection (`internal/adapter/ollama/adapter.go`)**: Stripped caller-supplied `keep_alive` from `ExtraParams` in `marshalOllamaChatPayload` so untrusted callers cannot pass `keep_alive: 0` to force-evict shared models from GPU VRAM.

### OpenTelemetry (OTLP/HTTP) 3-Signal Observability Standardization (`v0.1` LTS)

#### Added
- **Unified 3-Signal OpenTelemetry OTLP/HTTP Runtime (`internal/observability/otel.go`, `instruments.go`, `genai_spans.go`)**:
  - Standardized GoRoute telemetry export exclusively on pure-Go official OpenTelemetry OTLP/HTTP SDKs across **Traces** (`otlptracehttp`), **Metrics** (`otlpmetrichttp`), and opt-in post-scrub **Logs** (`otelslog` + `otlploghttp`), with every signal endpoint validated against `internal/security/network` outbound SSRF policies.
  - Adopted OpenTelemetry **GenAI Semantic Conventions** (`gen_ai.operation.name`, `gen_ai.provider.name`, `gen_ai.request.model`, `gen_ai.response.model`, `gen_ai.usage.input_tokens`, `gen_ai.usage.output_tokens`, `gen_ai.first_token` streaming event, `execute_tool` MCP spans, `invoke_agent` A2A spans, `cache.lookup` spans, and privacy-first `capture_content: false` default).
  - Standardized all OTLP metric names to pure OpenTelemetry dot-separated naming under `gen_ai.*` (`gen_ai.client.operation.duration`, `gen_ai.client.token.usage`, `gen_ai.server.time_to_first_token`) and `gateway.*` (`gateway.requests`, `gateway.cache.*`, `gateway.guardrail.*`, `gateway.mcp.requests`, `gateway.a2a.requests`, `gateway.finops.outbox.*`, `gateway.audit.siem.*`, `gateway.redis.circuit_breaker.state`, `gateway.deployment.healthy`, and non-STW `runtime/metrics` Go runtime gauges).
  - Added W3C `traceparent` propagation across all 4 OpenAPI-first provider adapters (`openai`, `anthropic`, `groq`, `openrouter`), fixed real `spanContext.TraceFlags()` formatting, and low-cardinality `chi` route-template span naming (`HTTP POST /v1/chat/completions`).
  - Added top-level `otel:` and `health:` configuration sections with full standard `OTEL_*` and `GATEWAY_OTEL_*` / `GATEWAY_AUDIT_SIEM_*` / `GATEWAY_HEALTH_PROBE_*` environment overrides, fail-closed `os.environ/` validation on `otel.headers` & `audit.siem_webhook.*`, and silent deprecated `tracing:` YAML alias compatibility.
  - Fixed tenant identity attribution (`org_id`, `team_id`, `virtual_key_id`, `key_prefix`) on HTTP access logs & spans, replaced lifetime Algorithm-R latency reservoir with a bounded 1,024-sample sliding window, replaced STW `runtime.ReadMemStats()` with lock-free `runtime/metrics`, wired `pkg/gateway.WithLogger` to global `logger.SetGlobal`, and surfaced live OTLP 3-signal status, FinOps outbox depth, SIEM webhook delivery stats, and Redis circuit-breaker state in `GET /admin/v1/observability/metrics` and Operator Web UI (`OverviewView` + `ConfigView`).
  - Added Tier 3c `make test-obs-prod-docker` 2-replica HA production Docker OTLP verification suite (`Suites O0–O5`) using a real `otel/opentelemetry-collector-contrib` instance writing traces, metrics, and logs JSONL alongside 4-adapter `traceparent` capture, HMAC-SHA256 SIEM webhook verification, and Redis circuit-breaker chaos testing.

#### Removed
- **Removed Prometheus Exposition & Non-OTLP Telemetry Dependencies**: Deleted `GET /metrics`, `metricsAuthMiddleware`, `Collector.PrometheusHandler()`, `deployments/prometheus/prometheus.yml`, legacy `gw_*` metric names (`gw_redis_cb_state`, `gw_routing_signal_degraded_total`), and the custom protobuf OTLP encoder (`internal/observability/metrics_otlp.go`). GoRoute `v0.1` LTS exports telemetry exclusively over standard OpenTelemetry OTLP/HTTP; external observability platforms integrate on top of OTLP/HTTP directly or via an OpenTelemetry Collector.

### Single-Backend Response Caching (`local` | `redis` | `redis-semantic`), Hardening & Operator Web UI Wiring

#### Added
- **Single-Backend Response Caching (`internal/cache/`)**:
  - Clean `Backend` / `SemanticBackend` abstraction selected via `cache.type`: `local` (bounded in-memory LRU with multi-replica Redis Pub/Sub admin invalidation broadcast), `redis` (direct Redis KV with mutex-safe Redis Cluster `SCAN`, batched `MGET`/pipeline model invalidation, and `UNLINK`), and `redis-semantic` (Redis 8+ RediSearch `FLOAT32` `COSINE` `HNSW`/`FLAT` vector similarity search with atomic `TxPipeline` `HSET`+`EXPIRE`, `FT.INFO` vector dimension validation, single-embed-per-miss vector reuse, and automatic self-healing index recreation after ephemeral Redis restarts).
  - Strict tenant, multi-turn, and parameter isolation: hex-hashed RediSearch `TAG` filters (`scope`, `org_id`, `model` including both resolved upstream model and requested `ModelGroup` alias), multimodal (`image_url`/`document`) and tool-call semantic bypass, prior-turn + `user` + `extra_params` semantic scope binding, `seed` cache eligibility (`temperature > 0`), `cache.semantic.max_messages: -1` unlimited mode, and rune-safe UTF-8 prompt truncation.
  - Optional dedicated cache Redis (`cache.redis_addr`/`redis_addrs`/`redis_master_name`/`redis_pass`/`redis_db`/`redis_tls` with TLS 1.2+ and `500ms` fail-open timeouts), fail-open `/readyz` `"cache_status": "ok" | "degraded"` reporting, default `cache.excluded_call_types: ["embedding"]`, and `max_l1_entries` preserved as a silent deprecated YAML alias for `max_entries`.
  - Unified `$0` (`cache_hit: true`) FinOps `spend_logs` audit records across all 5 cached endpoints (`/v1/chat/completions`, `/v1/messages`, `/v1/responses`, `/v1/completions`, `/v1/embeddings`) plus async internal semantic-cache embedding spend logging under `endpoint: "_internal/semantic_cache"`.
  - Backend-agnostic OTLP cache metrics (`gateway.cache.hits`, `gateway.cache.misses`, `gateway.cache.errors`, `gateway.cache.semantic_hits`, `gateway.cache.entries`, `gateway.cache.evictions`) and authoritative `Collector.SetCacheTelemetryProvider` parity on `GET /admin/v1/observability/metrics`.
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
