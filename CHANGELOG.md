# Changelog

All notable changes to the GoRoute AI Gateway project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.0.0] - 2026-11-09

### Initial Major Production Release

#### Core Unified Data Plane
- **Unified OpenAI-Compatible Endpoints**: Synchronous chat completions (`/v1/chat/completions`), zero-buffer Server-Sent Events (SSE) streaming, embeddings (`/v1/embeddings`), and dynamic model catalogue discovery (`/v1/models`).
- **Multi-Provider LLM Adapters**: Native, strongly-typed adapters for OpenAI, Anthropic Claude (Messages API with stateful SSE parser), Google Gemini (v1beta and Vertex AI Express Mode), Mistral AI, and local Ollama.
- **Reasoning Model Normalization**: Automatic parameter normalization for OpenAI `o1`, `o3`, and `o3-mini` (system to developer role mapping, `max_completion_tokens`), and Anthropic extended thinking budgets.
- **Robust Scanner Truncation Guards**: Allocated 2MB maximum scan token buffer on SSE stream readers and Stdio transports, preventing `bufio.ErrTooLong` stream aborts on large reasoning chains or tool payloads.

#### Model Context Protocol (MCP 2026-07-28 & 2025-11-25)
- **Official MCP 2026-07-28 Transport**: Stateless Streamable HTTP transport implementation with stateful 2025-11-25 compatibility and legacy 2024 SSE adapters.
- **Virtual Hub Tool Aggregation (`POST /mcp`)**: Multi-server tool aggregation with parallel fan-out and partial failure isolation.
- **Plain MCP REST Bridge**: Lightweight HTTP REST endpoints (`GET /mcp-rest/tools/list`, `POST /mcp-rest/tools/call`).
- **Progressive Discovery**: Opaque 256-bit handles (`tool_hdl_...`) with schema hydration meta-tools (`search_tools`, `get_tool_schema`) at `GET /v1/goroute/mcp/registry`.
- **Governed OpenAPI Transport**: Automated tool synthesis from OpenAPI 3.0/3.1 specs with path parameter interpolation.
- **Stdio Sandboxing**: Local process transport with environment scrubbing, timeouts, and process group isolation.
- **MRTR & Anti-Poisoning**: Model-Result-Token-Resumption with AEAD-encrypted continuation tokens, cryptographic tool fingerprint pinning, and arbitrary decimal precision preservation (`big.Rat`).

#### Linux Foundation Agent-to-Agent Protocol (A2A v1.0)
- **Agent Card Discovery**: RFC 8785 JCS canonicalized and RFC 7515 JWS signed Agent Cards (`GET /.well-known/agent-card.json`).
- **Dual-Binding Engine**: Full support for both standard HTTP+JSON and JSON-RPC 2.0 dispatches (`POST /a2a/v1/agents/{agentSlug}`).
- **Native gRPC Service**: `lf.a2a.v1.A2AService` implementing task lifecycle (`SendMessage`, `GetTask`, `ListTasks`, `CancelTask`, `SubscribeToTask`).
- **A2A-to-OpenAI Compatibility Bridge**: Standard OpenAI client compatibility via `POST /v1/chat/completions` with `model: "a2a/{slug}"`.
- **Subscribe-First Real-Time SSE**: Task event streaming with strictly monotonic sequence numbers and zero event loss across reconnects.
- **Enterprise Isolation & Outbox**: Multi-tenant visibility isolation, transactional outbox with PostgreSQL `FOR UPDATE SKIP LOCKED`, dead-letter queue (DLQ), and emergency kill-switch.

#### Server-Side Autonomous Tool Loop
- **Autonomous Multi-Turn Execution**: `internal/orchestrator` ToolLoopOrchestrator executing model tool calls server-side.
- **Safety Budget Boundaries**: Configurable recursion limits (`MaxLoopRounds`), execution timeouts, and tool output truncation.
- **Anti-Double-Billing FinOps Ledger**: Consolidated token and cost accounting across all intermediate turns with single-charge commitment.

#### Intelligent Routing & High Availability
- **Two-Stage Routing Engine**: Stage 1 zero-LLM heuristic prompt complexity classifier and Stage 2 lock-free EWMA load balancer.
- **5 Distribution Strategies**: `weighted-shuffle`, `least-busy`, `latency-based`, `usage-based-headroom` (with 1-minute windowed monotonic tracking), and `lowest-cost`.
- **Resilience**: 3-state circuit breakers (Closed, Open, Half-Open), exponential backoff with full-jitter retries, and cross-provider fallback chains.
- **Active Health Probing**: Background deployment prober with `/healthz` liveness and deep PostgreSQL/Redis `/readyz` dependency checks.

#### Security, Auth Vault & Multi-Tenancy
- **AES-256-GCM Vault**: Envelope encryption with per-credential Data Encryption Key (DEK) derivation and rotation.
- **Virtual Keys**: Cryptographically hashed SHA-256 keys (`sk-gw-...`) with 2-tier cache (L1 in-memory + L2 Redis).
- **Multi-Tenant RBAC**: 4-layer hierarchical isolation (Organization -> Team -> User -> VirtualKey) with model allowlists.
- **Multi-Pod Key Revocation**: Instant cache eviction via Redis Pub/Sub invalidation with `KeyHash` propagation.
- **Enterprise Upstream Auth**: AWS SigV4 signer, Client Identifier Metadata Documents (CIMD with S256 PKCE), and RFC 8693 Token Exchange.
- **Corporate Egress Proxy**: Support for enterprise HTTP/HTTPS proxies with outbound SSRF protections.

#### FinOps & Budget Controls
- **Micro-Dollar Precision**: Integer pico/micro-dollar cost engine ($1 = 1,000,000 µ$) with zero floating-point drift.
- **Non-Blocking Async Spend Worker**: High-throughput queue with multi-row `pgx.Batch` batch execution.
- **Budget Enforcers**: Soft warnings and hard blocking limits enforced across organization, team, and key levels.

#### Caching, Rate Limiting & Observability
- **Atomic Redis Rate Limiter**: Sliding-window RPM/TPM quota enforcement using atomic Lua scripts with fail-open/fail-closed policies.
- **Deterministic Response Cache**: Tenant-isolated exact-match SHA-256 response cache enriched with model, temperature, top_p, and user ID.
- **Structured Contextual Logging**: Enterprise `internal/logger` slog subsystem with W3C traceparent propagation and probe filtering.
- **Prometheus Telemetry**: Native Prometheus `/metrics` registry exposing request rates, error codes, and latency percentiles (P50/P95/P99).

#### Developer Ergonomics & Tooling
- **Ergonomic Go SDK**: Public `pkg/gateway` client library for 1-line chat completions, streaming, and administration.
- **Interactive Runnable Demos**: 9 comprehensive, self-contained demonstration scripts in `demo/`.
- **Enterprise Verification Suite**: Multi-node Nginx cluster harness and 16-stage end-to-end integration test suite (`tests/e2e/`).
- **Universal Distribution**: Multi-architecture statically compiled release binaries, universal shell installer (`install.sh`), and Distroless container images.
