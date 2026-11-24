# GoRoute AI Gateway — Documentation Hub

Welcome to the **GoRoute AI Gateway** (`github.com/goroute-ai/ai-gateway-go`) documentation suite. Claude Code users should start with [CLAUDE.md](../CLAUDE.md), which imports the shared [AGENTS.md](../AGENTS.md) guidance; other coding agents and contributors can start with `AGENTS.md`. Use the [codebase map](./CODEBASE_MAP.md) to find implementations and sources of truth.

---

## Documentation Architecture

```
docs/
├── CODEBASE_MAP.md            # Package navigation and source-of-truth map
├── CODE_QUALITY_AUDIT.md      # Code quality audit, dead-code cleanup, doc coverage & refactor summary
├── API_REFERENCE.md           # Authoritative REST, /auth, SCIM v2, MCP, A2A, Admin & Metrics API reference
├── AUTHORIZATION_AND_ACCESS_CONTROL.md # Authoritative guide to all 19 access-control, RBAC, quota, and audit capabilities
├── INTERNALS.md               # Code-level deep dive: sequence diagrams, algorithms, formulas & storage
├── ARCHITECTURE.md            # High-level & low-level production reference architecture
├── CONFIGURATION_GUIDE.md     # Configuration & developer reference (YAML, Go SDK & REST APIs)
├── UPGRADING.md               # Zero-downtime upgrade path, schema notes & 0034 rollback safety runbook
├── TESTING.md                 # 3-tier verification manual (static/contracts, unit/Postgres/Redis E2E, Chromium UI)
├── openapi/                   # Formal OpenAPI 3.0/3.1 contracts (Gateway + MCP + A2A + 4 providers)
│   ├── gateway.openapi.yaml
│   ├── gateway.codegen.yaml
│   ├── mcp.openapi.yaml
│   ├── a2a.openapi.yaml
│   └── README.md
└── specs/                     # Pinned vendor protocol specifications
    ├── mcp/<2024-11-05..2026-07-28>/schema.yaml
    └── a2a/v1.0/a2a.proto
```

---

## Core Guides & Specifications

1. **[Codebase Map (`CODEBASE_MAP.md`)](./CODEBASE_MAP.md)**  
   *Implementation paths, tests, SQL migrations (`0001`–`0041`), change workflows, and authoritative source locations.*

2. **[Authorization & Access Control Guide (`AUTHORIZATION_AND_ACCESS_CONTROL.md`)](./AUTHORIZATION_AND_ACCESS_CONTROL.md)**  
   *Single authoritative reference for all 19 enterprise authorization & governance capabilities, 7-role RBAC hierarchy (with LiteLLM role mapping), tri-state allowlist truth table (`null` vs `[]` vs `[...]`), Unified Access Groups & dynamic ABAC rules, OIDC/JWT/SSO role mapping, `ExternalAuthorizer` (Webhook/OPA) & SDK hooks, multi-window micro-dollar budgets, Redis Lua rate/concurrency limits, full audit action catalog (including MCP/A2A mutations), and Dockerized production testing runbooks.*

3. **[API Reference (`API_REFERENCE.md`)](./API_REFERENCE.md)**  
   *Authoritative endpoint and protocol guide for data plane, auth/SSO, SCIM v2, admin control plane, and web interfaces (`127` OpenAPI paths: `27` `/v1`, `88` `/admin/v1`, `8` `/auth`, and `4` provider aliases):*
   - Unified Multi-Modal Data Plane (`27` `/v1` OpenAPI paths, self-service key APIs, virtual router aliases `auto` / `router/semantic` / `router/quality` / `router/adaptive`, routing hints & telemetry headers, chat, embeddings, audio, images, files, batches, responses, and realtime).
   - Embedded Operator Web UI (`GET /ui/*`) with streaming SSE & cacheable JSON chat playground, cache controls & rich Response Cache telemetry, OIDC SSO / break-glass master key login, virtual key rotation & temp budgets, multi-window quotas, KEK rotation, and Agentic Hub Gateway MCP spec switcher.
   - Model Context Protocol (Spec-Generated Multi-Release `2024-11-05`–`2026-07-28` Virtual Hub, Scoped Servers, and Curated Toolsets).
   - Agent-to-Agent Protocol (A2A v1.0 JWS Agent Cards, Dual-Binding dispatch, Subscribe-First SSE).
   - Control Plane & Provisioning (`/auth/*`, `/scim/v2/*`, `/admin/v1/*`), including federated OIDC binding, SCIM 2.0 Users & Groups, multi-dimensional quotas, multi-window budgets (`rolling_24h`), PTU shares & priority classes, preflight credential validation, specialized fallback & budget fields on model groups/deployments, named guardrail registry, tool trust policies, guardrail simulation, and Prometheus Metrics scraping (`/metrics`).

4. **[Subsystem Internals & Engineering Guide (`INTERNALS.md`)](./INTERNALS.md)**  
   *Deep-dive code tour and mathematical specifications for core contributors and platform architects:*
   - Synchronous and Real-Time SSE Streaming Data Plane lifecycles with sequence diagrams, including `StreamContinuationManager` mid-stream SSE continuation.
   - Embedded Operator Web UI serving mechanics, memory footprint, cache header policy, and HTML5 History fallback.
   - Two-layer Guardrails Pipeline (`Engine`, 15-driver registry, Starlark `custom_code` sandbox, tool trust taint tracking, `StreamWindowEvaluator`), `/v1/guardrails/apply`, and preflight credential validation mechanics.
   - Stage 0 `PreRouterRegistry` (heuristic complexity, semantic embedding centroids, quality tiering, Thompson-sampling adaptive bandit), `DeploymentFilterChain` (`RoutingPlugin`, region, `&`/`!` tags, staleness, capacity/budget caps, session & prompt-cache affinity), `Deployment.Priority` tier walk, 7-strategy Load Balancer (including `fastest-response` hedged racing), PTU priority capacity sharing, and `PriorityScheduler`.
   - Adaptive `RetryPolicy` & failure-rate `CooldownPolicy` (with lone-deployment safety net) and specialized fallback chains (`context_window_fallbacks`, `content_policy_fallbacks`, `fallback_targets`).
   - AES-256-GCM Envelope Encryption (DEK/KEK), `(org_id, oidc_issuer, oidc_subject)` federation, OIDC PKCE `S256` & RP-Initiated Logout, key rotation grace windows, `CustomAuthenticator`, and Cloud IAM `DistributedTokenCache`.
   - Exact 64-bit micro-dollar integer accounting formula ($10^{-6}\text{ USD}$) with zero float drift.
   - Single-roundtrip atomic Redis Lua rate limiting (`check_and_increment.lua`, `check_descriptors.lua`), `rolling_24h` PostgreSQL cold recovery, and distributed routing/affinity/bandit Lua scripts.
   - MCP Virtual Hub aggregation, AEAD-encrypted MRTR tokens, and SHA-256 tool pinning.
   - Linux Foundation A2A v1.0 durability, Subscribe-First SSE, and transactional outbox.

5. **[System Architecture & Production Reference (`ARCHITECTURE.md`)](./ARCHITECTURE.md)**  
   *High-Level and Low-Level enterprise architecture specification:*
   - Enterprise AI Control Plane topology and 9 foundational subsystems, including the Embedded Operator Web UI.
   - Low-level design of embedded assets, zero-node container build, and bundle budget constraints.
   - Centralized outbound SSRF protection network engine and connect-time IP pinning.
   - 6-stage routing pipeline and Reliability Manager (`CLOSED` $\rightarrow$ `OPEN` $\rightarrow$ `HALF_OPEN`, priority tier step-downs, specialized fallback chains, and mid-stream recovery).
   - Horizontal pod scalability, PostgreSQL schema (`migrations/0001`–`0041`), single-backend response & Redis 8 semantic vector caching (`local` | `redis` | `redis-semantic`), and Redis cluster keyspace.

6. **[Configuration & Developer Guide (`CONFIGURATION_GUIDE.md`)](./CONFIGURATION_GUIDE.md)**  
   *Step-by-step setup and operations guide:*
   - Embedded Operator Web UI browser access (`http://localhost:8080/ui/`) and Break-Glass Master Key / OIDC SSO authentication.
   - Declarative `model_list` setup via `configs/config.yaml`, `configs/config.example.yaml`, and environment variables.
   - In-process Go SDK (`pkg/gateway`, including `WithCustomAuthenticator`) integration and remote client usage.
   - Complete configuration parameters table with default values and security notes.

7. **[Upgrade & Rollback Guide (`UPGRADING.md`)](./UPGRADING.md)**  
   *Upgrade guidance for `v0.1.0`, migrations `0001`–`0041`, `0034` rollback duplicate-subject preflight checks, and `rolling_24h` cold recovery boundaries.*

8. **[Testing & Verification Guide (`TESTING.md`)](./TESTING.md)**  
   *Complete 3-tier testing workflow covering static/contract parity, unit/race checks, live PostgreSQL 16 & Redis 8 E2E suites, Playwright headless Chromium Web UI tests, and production Docker OIDC & Caching HA suites.*

9. **[OpenAPI Specifications (`openapi/README.md`)](./openapi/README.md)**  
   *Machine-readable API contracts:*
   - Unified Gateway Data Plane contract (`gateway.openapi.yaml`).
   - Model Context Protocol contract (`mcp.openapi.yaml`) and multi-release YAML schema generator (`cmd/mcpgen`).
   - Agent-to-Agent Protocol contract (`a2a.openapi.yaml`).
   - Official upstream provider contracts (`openai`, `anthropic`, `groq`, `openrouter`).

10. **[Code Quality Audit & Standards (`CODE_QUALITY_AUDIT.md`)](./CODE_QUALITY_AUDIT.md)**  
    *Inventory of dead-code removal, static analysis fixes, Go documentation coverage (`doc.go` & exported APIs), structural decompositions, and Go tooling setup (`.golangci.yml`, `make lint`, `make deadcode`, `cc-skills-golang`).*
