# GoRoute AI Gateway — Documentation Hub

Welcome to the **GoRoute AI Gateway** (`github.com/goroute-ai/ai-gateway-go`) documentation suite. Coding agents and new contributors should start with the repository [AGENTS.md](../AGENTS.md), then use the [codebase map](./CODEBASE_MAP.md) to find implementations and sources of truth.

---

## Documentation Architecture

```
docs/
├── CODEBASE_MAP.md            # Package navigation and source-of-truth map
├── API_REFERENCE.md           # Authoritative REST, MCP, A2A, Admin & Metrics API reference
├── INTERNALS.md               # Code-level deep dive: sequence diagrams, algorithms, formulas & storage
├── ARCHITECTURE.md            # High-level & low-level production reference architecture
├── CONFIGURATION_GUIDE.md     # Configuration & developer reference (YAML, Go SDK & REST APIs)
├── openapi/                   # Formal OpenAPI 3.0/3.1 contracts (Gateway + MCP + A2A + 5 providers)
│   ├── gateway.openapi.yaml
│   ├── mcp.openapi.yaml
│   ├── a2a.openapi.yaml
│   └── README.md
└── specs/                     # Pinned vendor protocol specifications
    ├── mcp/2026-07-28/schema.json
    └── a2a/v1.0/a2a.proto
```

---

## Core Guides & Specifications

1. **[Codebase Map (`CODEBASE_MAP.md`)](./CODEBASE_MAP.md)**  
   *Implementation paths, tests, change workflows, and authoritative source locations.*

2. **[API Reference (`API_REFERENCE.md`)](./API_REFERENCE.md)**  
   *Human-readable endpoint and protocol guide. Machine-readable contracts under `openapi/` and `specs/` are authoritative for schema shapes.*
   - Unified Multi-Modal Data Plane (21 endpoints: `/v1/chat/completions`, `/v1/embeddings`, `/v1/models`, `/v1/rerank`, `/v1/moderations`, `/v1/completions`, `/v1/messages`, `/v1/messages/count_tokens`, `/v1/tokenize`, `/v1/audio/*`, `/v1/images/*`, `/v1/files/*`, `/v1/batches/*`, `/v1/responses`, `/v1/realtime`).
   - Model Context Protocol (MCP 2026-07-28 Virtual Hub, Scoped Servers, and Curated Toolsets).
   - Agent-to-Agent Protocol (A2A v1.0 JWS Agent Cards, Dual-Binding dispatch, Subscribe-First SSE).
   - Admin Control Plane (`/admin/v1/*`) and Prometheus Metrics scraping (`/metrics`).

3. **[Subsystem Internals & Engineering Guide (`INTERNALS.md`)](./INTERNALS.md)**  
   *Deep-dive code tour and mathematical specifications for core contributors and platform architects:*
   - Synchronous and Real-Time SSE Streaming Data Plane lifecycles with sequence diagrams.
   - Stage-1 heuristic prompt complexity classifier formula (< 0.1ms) and Stage-2 load balancing models.
   - AES-256-GCM Envelope Encryption (DEK/KEK) and SHA-256 constant-time hash verification.
   - Exact 64-bit micro-dollar integer accounting formula ($10^{-6}\text{ USD}$) with zero float drift.
   - Single-roundtrip atomic Redis Lua rate limiting (`check_and_increment.lua`).
   - MCP Virtual Hub aggregation, AEAD-encrypted MRTR tokens, and SHA-256 tool pinning.
   - Linux Foundation A2A v1.0 durability, Subscribe-First SSE, and transactional outbox.

4. **[System Architecture & Production Reference (`ARCHITECTURE.md`)](./ARCHITECTURE.md)**  
   *High-Level and Low-Level enterprise architecture specification:*
   - Enterprise AI Control Plane topology and 4-layer model governance architecture.
   - Centralized outbound SSRF protection network engine and connect-time IP pinning.
   - Reliability manager state machine (`CLOSED` $\rightarrow$ `OPEN` $\rightarrow$ `HALF_OPEN`) and cross-provider failover chains.
   - Horizontal pod scalability and distributed caching hierarchy (L1 Memory + L2 Redis).

5. **[Configuration & Developer Guide (`CONFIGURATION_GUIDE.md`)](./CONFIGURATION_GUIDE.md)**  
   *Step-by-step setup and operations guide:*
   - Declarative `model_list` setup via `configs/config.yaml` and environment variables.
   - In-process Go SDK (`pkg/gateway`) integration and remote client usage.
   - Complete configuration parameters table with default values and security notes.

6. **[OpenAPI Specifications (`openapi/README.md`)](./openapi/README.md)**  
   *Machine-readable API contracts:*
   - Unified Gateway Data Plane contract (`gateway.openapi.yaml`).
   - Model Context Protocol contract (`mcp.openapi.yaml`).
   - Agent-to-Agent Protocol contract (`a2a.openapi.yaml`).
   - Official upstream provider contracts (`openai`, `anthropic`, `gemini`, `mistral`, `ollama`).
