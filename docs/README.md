# GoRoute AI Gateway — Documentation Hub

Welcome to the **GoRoute AI Gateway** (`github.com/goroute-ai/ai-gateway-go`) comprehensive documentation suite.

---

## Documentation Architecture

```
docs/
├── API_REFERENCE.md           # Authoritative REST, MCP, A2A, Admin & Metrics API reference
├── INTERNALS.md               # Code-level deep dive: sequence diagrams, algorithms, formulas & storage
├── ARCHITECTURE.md            # High-level & low-level production reference architecture
├── CONFIGURATION_GUIDE.md     # Configuration & developer reference (YAML, Go SDK & REST APIs)
├── openapi/                   # Formal OpenAPI 3.0/3.1 contracts (Gateway + MCP + A2A + 5 providers)
│   ├── gateway.openapi.yaml
│   ├── mcp.openapi.yaml
│   ├── a2a.openapi.yaml
│   └── README.md
├── specs/                     # Pinned vendor protocol specifications
│   ├── mcp/2026-07-28/schema.json
│   └── a2a/v1.0/a2a.proto
└── ../demo/                   # 9 hands-on runnable demonstration laboratories
    └── README.md
```

---

## Core Guides & Specifications

1. **[Complete API Reference (`API_REFERENCE.md`)](./API_REFERENCE.md)**  
   *Authoritative endpoints, request/response schemas, and protocol wire formats:*
   - OpenAI-compatible Data Plane (`/v1/chat/completions`, `/v1/embeddings`, `/v1/models`).
   - Model Context Protocol (MCP 2026-07-28 Virtual Hub, Scoped Servers, and Curated Toolsets).
   - Agent-to-Agent Protocol (A2A v1.0 JWS Agent Cards, Dual-Binding dispatch, Subscribe-First SSE).
   - Admin Control Plane (`/admin/v1/*`) and Prometheus Metrics scraping (`/metrics`).

2. **[Subsystem Internals & Engineering Guide (`INTERNALS.md`)](./INTERNALS.md)**  
   *Deep-dive code tour and mathematical specifications for core contributors and platform architects:*
   - Synchronous and Real-Time SSE Streaming Data Plane lifecycles with sequence diagrams.
   - Stage-1 heuristic prompt complexity classifier formula (< 0.1ms) and Stage-2 load balancing models.
   - AES-256-GCM Envelope Encryption (DEK/KEK) and SHA-256 constant-time hash verification.
   - Exact 64-bit micro-dollar integer accounting formula ($10^{-6}\text{ USD}$) with zero float drift.
   - Single-roundtrip atomic Redis Lua rate limiting (`check_and_increment.lua`).
   - MCP Virtual Hub aggregation, AEAD-encrypted MRTR tokens, and SHA-256 tool pinning.
   - Linux Foundation A2A v1.0 durability, Subscribe-First SSE, and transactional outbox.

3. **[System Architecture & Production Reference (`ARCHITECTURE.md`)](./ARCHITECTURE.md)**  
   *High-Level and Low-Level enterprise architecture specification:*
   - Enterprise AI Control Plane topology and 4-layer model governance architecture.
   - Centralized outbound SSRF protection network engine and connect-time IP pinning.
   - Reliability manager state machine (`CLOSED` $\rightarrow$ `OPEN` $\rightarrow$ `HALF_OPEN`) and cross-provider failover chains.
   - Horizontal pod scalability and distributed caching hierarchy (L1 Memory + L2 Redis).

4. **[Configuration & Developer Guide (`CONFIGURATION_GUIDE.md`)](./CONFIGURATION_GUIDE.md)**  
   *Step-by-step setup and operations guide:*
   - Declarative `model_list` setup via `configs/config.yaml` and environment variables.
   - In-process Go SDK (`pkg/gateway`) integration and remote client usage.
   - Complete configuration parameters table with default values and security notes.

5. **[Hands-On Demonstration Suite (`../demo/README.md`)](../demo/README.md)**  
   *9 self-contained, runnable Go programs demonstrating each architectural system:*
   - `demo/main.go` — Overview: Explicit Model, Logical Alias (`fast`), and Smart Auto-Router (`auto`).
   - `demo/01_unified_api` — Unified API & Real-Time SSE Token Streaming.
   - `demo/02_model_management` — 4-Layer Model Management & Dynamic Wildcard Routing.
   - `demo/03_smart_routing` — Zero-LLM Complexity Classifier & Weighted Load Balancing.
   - `demo/04_auth_and_vault` — Scoped Virtual Keys (`sk-gw-...`), 4-Tier RBAC & Instant Revocation.
   - `demo/05_retries_and_fallbacks` — Outage Simulation, Circuit Breaker Cooldown & Failover to Claude.
   - `demo/06_finops_and_budgets` — Micro-Dollar Token Accounting & Aggregated Spend Ledgers.
   - `demo/07_ratelimit_and_cache` — 0ms Deterministic Exact-Match Cache & Atomic RPM Quotas.
   - `demo/08_mcp_gateway` — MCP 2026-07-28 Stateless Virtual Hub, Tool Pinning & Precision Math.
   - `demo/09_a2a_protocol` — Linux Foundation A2A v1.0 JCS Signing, SSE Streams & Kill-Switch.

6. **[OpenAPI 3.1 Specifications (`openapi/README.md`)](./openapi/README.md)**  
   *Machine-readable API contracts:*
   - Unified Gateway Data Plane contract (`gateway.openapi.yaml`).
   - Model Context Protocol contract (`mcp.openapi.yaml`).
   - Agent-to-Agent Protocol contract (`a2a.openapi.yaml`).
   - Official upstream provider contracts (`openai`, `anthropic`, `gemini`, `mistral`, `ollama`).
