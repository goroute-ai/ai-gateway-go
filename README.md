<p align="center">
  <img src="./assets/logo.png" width="180" alt="GoRoute AI Gateway Logo" style="border-radius: 20px;" />
</p>

# GoRoute AI Gateway
*The ultra-fast, lightweight AI Gateway written in 100% Pure Go.*

Call **Google Gemini**, **Anthropic Claude**, **OpenAI**, **Mistral AI**, and **local Ollama** using a single, unified OpenAI-compatible format.

[![Go Reference](https://pkg.go.dev/badge/github.com/goroute-ai/ai-gateway-go/pkg/gateway.svg)](https://pkg.go.dev/github.com/goroute-ai/ai-gateway-go/pkg/gateway)
[![Go Version](https://img.shields.io/badge/Go-1.23%2B-00ADD8?logo=go)](https://go.dev/)
[![Release](https://img.shields.io/badge/Release-v1.0.0-success)](https://github.com/goroute-ai/ai-gateway-go/releases/tag/v1.0.0)
[![OpenAPI](https://img.shields.io/badge/OpenAPI-3.0%20%2F%203.1-6BA539?logo=openapiinitiative)](./docs/openapi/README.md)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](./LICENSE)

---

### What is GoRoute AI Gateway?

GoRoute AI Gateway provides a unified data plane and Go SDK for interacting with large language models with enterprise resilience and sub-millisecond routing overhead:

* **Unified OpenAI Format**: Single endpoint (`/v1/chat/completions`, `/v1/embeddings`, `/v1/models`) standardizing requests, streaming SSE, and tool calling across 5+ providers.
* **Model Context Protocol (MCP)**: Production gateway supporting MCP 2026-07-28 stateless Streamable HTTP, 2025-11-25 compatibility adapter, legacy 2024 SSE, Stdio sandboxing, Virtual Hub multi-server aggregation (`POST /mcp`), Plain REST Bridge (`GET /mcp-rest/tools/list`, `POST /mcp-rest/tools/call`), Progressive Discovery (`GET /v1/goroute/mcp/registry` & 256-bit handles), Governed OpenAPI Transport, curated toolsets, AEAD-encrypted MRTR resumption, anti-tool-poisoning scanner, and arbitrary decimal precision preservation (`big.Rat`).
* **Agent-to-Agent Protocol (A2A)**: Linux Foundation A2A v1.0 service featuring RFC 8785 JCS canonicalization, JWS cryptographic card signatures, dual HTTP+JSON and JSON-RPC 2.0 dispatch, Native gRPC Service (`lf.a2a.v1.A2AService`), OpenAI Compatibility Bridge (`model: "a2a/{slug}"`), Subscribe-First SSE task streaming, multi-tenant visibility isolation, transactional outbox with dead-letter queue, and administrative emergency kill-switch.
* **Server-Side Autonomous Tool Loop**: Multi-turn tool loop orchestrator (`internal/orchestrator`) executing model function calls via MCP tools server-side with strict safety bounds and anti-double-billing FinOps ledger accounting.
* **Enterprise Upstream Authentication**: Decoupled upstream security supporting AWS SigV4, Client Identifier Metadata Documents (CIMD with S256 PKCE), RFC 9207 & 8707 anti-mix-up validation, and RFC 8693 OAuth 2.0 Token Exchange with TTL-aware caching.
* **Dual Deployment**: Run as a standalone self-hosted proxy microservice or embed directly in your Go services via `pkg/gateway`.
* **Enterprise Reliability**: Automated cross-provider fallbacks, 3-state circuit breakers, and 5 load-balancing strategies (`weighted-shuffle`, `least-busy`, `latency-based`, `usage-based-headroom`, `lowest-cost`).
* **FinOps & Virtual Keys**: Micro-dollar spend tracking ($1 = 1,000,000 µ$), scoped virtual keys (`sk-gw-...`), and atomic Redis Lua rate limiting (RPM/TPM).
* **High-Throughput Performance**: Sustained 1,341+ req/s throughput across 80 concurrent virtual users with sub-2ms median latency under live PostgreSQL and Redis.

---

### Universal Installation & Quick Start

Deploy GoRoute AI Gateway in seconds using your preferred environment:

#### 1. Universal One-Line Shell Installer (macOS, Linux, WSL)
Automatically detects your OS/architecture, validates SHA-256 checksums, and installs the standalone binary:
```bash
curl -fsSL https://raw.githubusercontent.com/goroute-ai/ai-gateway-go/main/install.sh | bash
```
*To install a specific version:* `curl -fsSL https://raw.githubusercontent.com/goroute-ai/ai-gateway-go/main/install.sh | bash -s -- v1.0.0`

#### 2. Precompiled Release Binaries
Download prebuilt, statically linked binaries with zero runtime dependencies from the [**GitHub Releases Page**](https://github.com/goroute-ai/ai-gateway-go/releases/tag/v1.0.0):
* [macOS Apple Silicon (`darwin_arm64`)](https://github.com/goroute-ai/ai-gateway-go/releases/download/v1.0.0/ai-gateway_1.0.0_darwin_arm64.tar.gz)
* [macOS Intel (`darwin_amd64`)](https://github.com/goroute-ai/ai-gateway-go/releases/download/v1.0.0/ai-gateway_1.0.0_darwin_amd64.tar.gz)
* [Linux x86_64 (`linux_amd64`)](https://github.com/goroute-ai/ai-gateway-go/releases/download/v1.0.0/ai-gateway_1.0.0_linux_amd64.tar.gz)
* [Linux ARM64 / Graviton (`linux_arm64`)](https://github.com/goroute-ai/ai-gateway-go/releases/download/v1.0.0/ai-gateway_1.0.0_linux_arm64.tar.gz)
* [Windows x86_64 (`windows_amd64`)](https://github.com/goroute-ai/ai-gateway-go/releases/download/v1.0.0/ai-gateway_1.0.0_windows_amd64.zip)

#### 3. Containerized Microservice (Docker & Kubernetes)
Run the lightweight Distroless container image:
```bash
docker run -d --name ai-gateway \
  -p 8080:8080 -p 50051:50051 \
  -v $(pwd)/configs/config.yaml:/app/configs/config.yaml \
  ghcr.io/goroute-ai/ai-gateway-go:latest
```

#### 4. Full Production Stack (PostgreSQL 16 + Redis 7 + Gateway)
Spin up the complete multi-tenant production fabric with database migrations and rate-limiting cache:
```bash
curl -O https://raw.githubusercontent.com/goroute-ai/ai-gateway-go/main/deployments/docker-compose.yml
docker compose up -d
```

#### 5. Go Toolchain (`go install`)
Build and install directly using the official Go toolchain:
```bash
go install github.com/goroute-ai/ai-gateway-go/cmd/gateway@v1.0.0
```

---

### Embedded Go SDK (`pkg/gateway`)

For embedding GoRoute directly into your Go applications with full type safety and zero internal dependencies:

```bash
go get github.com/goroute-ai/ai-gateway-go/pkg/gateway@v1.0.0
```

Make your first call in seconds:

```go
package main

import (
	"context"
	"fmt"
	"log"

	"github.com/goroute-ai/ai-gateway-go/pkg/gateway"
)

func main() {
	ctx := context.Background()

	// Initialize with declarative model aliases, custom providers, and logging control
	gw, err := gateway.New(
		gateway.WithModelList(
			gateway.ModelEntry{ModelName: "fast", Model: "gemini/gemini-2.5-flash", APIKey: "os.environ/GEMINI_API_KEY"},
			gateway.ModelEntry{ModelName: "reasoning", Model: "anthropic/claude-sonnet-4-20250514", APIKey: "os.environ/ANTHROPIC_API_KEY"},
		),
		gateway.WithDemoMocksIfEnvMissing(), // Instant zero-config local testing
		gateway.WithSilentLogs(),             // Suppress internal gateway stdout logs in library mode
	)
	if err != nil {
		log.Fatal(err)
	}
	defer gw.Close()

	// 1-Line Chat Completion (supports explicit model names, logical aliases, or "auto")
	res, err := gw.Chat(ctx, "fast", "In one sentence, what is an AI Gateway?")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("[%s] %s (cost: %d µ$, latency: %d µs)\n", res.Provider, res.Content, res.CostMicros, res.RoutingMicros)

	// Multi-Turn Chat using exported public SDK types (no internal/domain imports needed)
	multiRes, err := gw.ChatWithRequest(ctx, gateway.ChatRequest{
		Model: "reasoning",
		Messages: []gateway.Message{
			{Role: "system", Content: "You are a distributed systems architect."},
			{Role: "user", Content: "Compare Raft vs Paxos in one paragraph."},
		},
	})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("[Reasoning Output]: %s\n", multiRes.Content)
}
```

---

### Quick Start: Self-Hosted AI Gateway (Proxy)

#### 1. Start the Gateway

```bash
# Start locally with in-memory storage (zero external dependencies)
make run

# Or launch the production stack (Gateway + PostgreSQL + Redis + Prometheus)
make docker-up
```

> [!NOTE]
> **Production Key Hardening**: When running with `ENV=production` or `GATEWAY_ENV=production`, GoRoute strictly rejects default keys (`sk-gw-master-admin-default-key-change-me`, default encryption keys, and JWT secrets) at startup to prevent insecure deployments. Always set `GATEWAY_MASTER_ADMIN_KEY`, `GATEWAY_MASTER_ENCRYPTION_KEY`, and `GATEWAY_JWT_SECRET` in your production environment.

#### 2. Call Using Any OpenAI-Compatible Client

##### via cURL:

```bash
curl -X POST http://localhost:8080/v1/chat/completions \
  -H "Authorization: Bearer sk-gw-master-admin-default-key-change-me" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "fast",
    "messages": [{"role": "user", "content": "Hello from GoRoute AI Gateway!"}]
  }'
```

##### via Official OpenAI Python SDK:

```python
from openai import OpenAI

client = OpenAI(
    api_key="sk-gw-master-admin-default-key-change-me",
    base_url="http://localhost:8080/v1"
)

response = client.chat.completions.create(
    model="fast",
    messages=[{"role": "user", "content": "Explain GoRoute in 10 words."}]
)
print(response.choices[0].message.content)
```

---

### Declarative Configuration (`configs/config.yaml`)

Define models, weights, routing strategies, and fallbacks declaratively (supporting `os.environ/VAR` substitution):

```yaml
model_list:
  - model_name: fast
    routing_strategy: weighted-shuffle
    model_params:
      model: gemini/gemini-2.5-flash
      api_key: os.environ/GEMINI_API_KEY
      weight: 100

  - model_name: reasoning
    routing_strategy: least-busy
    model_params:
      model: anthropic/claude-sonnet-4-20250514
      api_key: os.environ/ANTHROPIC_API_KEY
      fallbacks: ["backup-claude"]
```

---

### Core Features

* **Smart Routing & Load Balancing**: Zero-LLM `< 0.1ms` prompt complexity classifier (`model: "auto"`) plus 5 load balancing algorithms (`weighted-shuffle`, `least-busy`, `latency-based`, `usage-based-headroom`, `lowest-cost`).
* **Reliability & Circuit Breakers**: 3-state circuit breaker (`CLOSED` / `OPEN` / `HALF_OPEN`), exponential backoff retries, and cross-provider failover.
* **Virtual Keys & 4-Layer RBAC**: Issue scoped `sk-gw-...` keys with model allowlists, rate limits (RPM/TPM), and instant revocation.
* **FinOps & Token Accounting**: Integer micro-dollar arithmetic (`1 USD = 1,000,000 µ$`) eliminating IEEE-754 float drift with async batch flushing.
* **Distributed Rate Limiting & Cache**: Redis Lua atomic sliding window (`RPM`, `TPM`, budget gating) and deterministic SHA-256 exact-match cache.
* **Observability**: Built-in Prometheus metrics (`/metrics`), health checks (`/health`), and OpenTelemetry tracing.

---

### Runnable Demos

Explore each gateway capability with self-contained, runnable Go scripts:

| Demo | Path | Focus Area |
| :--- | :--- | :--- |
| **01. Unified API** | [`demo/01_unified_api`](./demo/01_unified_api/main.go) | Synchronous chat, zero-buffer SSE streaming, telemetry headers |
| **02. Model Management** | [`demo/02_model_management`](./demo/02_model_management/main.go) | Declarative `model_list`, `provider/model` wildcard routing |
| **03. Smart Routing** | [`demo/03_smart_routing`](./demo/03_smart_routing/main.go) | Zero-LLM complexity classifier (`model: "auto"`), load balancing |
| **04. Auth & Vault** | [`demo/04_auth_and_vault`](./demo/04_auth_and_vault/main.go) | Scoped Virtual Keys, 4-layer RBAC allowlists, instant revocation |
| **05. Retries & Fallbacks** | [`demo/05_retries_and_fallbacks`](./demo/05_retries_and_fallbacks/main.go) | 503 Outage simulation, circuit breakers, cross-provider fallback |
| **06. FinOps & Budgets** | [`demo/06_finops_and_budgets`](./demo/06_finops_and_budgets/main.go) | Micro-dollar accounting, spend limits, async batch ledger |
| **07. Rate Limit & Cache** | [`demo/07_ratelimit_and_cache`](./demo/07_ratelimit_and_cache/main.go) | Redis sliding window, HTTP 429 quota gating, exact-match cache |
| **08. MCP Gateway** | [`demo/08_mcp_gateway`](./demo/08_mcp_gateway/main.go) | MCP 2026-07-28 stateless hub, 2025-11-25 compat, anti-poisoning, tool pinning |
| **09. A2A Protocol** | [`demo/09_a2a_protocol`](./demo/09_a2a_protocol/main.go) | Linux Foundation A2A v1.0, JCS signing, Subscribe-First SSE, emergency kill-switch |

---

### Documentation

* **[Changelog (`CHANGELOG.md`)](./CHANGELOG.md)** — Detailed version history, breaking changes, and migration notes.
* **[Complete API Reference (`docs/API_REFERENCE.md`)](./docs/API_REFERENCE.md)** — Comprehensive Data Plane, MCP, A2A v1.0, Admin, and Prometheus metrics endpoints.
* **[Subsystem Internals & Engineering Guide (`docs/INTERNALS.md`)](./docs/INTERNALS.md)** — Code-level tour, sequence diagrams, algorithms, and formulas.
* **[Architecture Reference (`docs/ARCHITECTURE.md`)](./docs/ARCHITECTURE.md)** — Detailed system design, 4-layer RBAC, and ERD.
* **[Configuration Guide (`docs/CONFIGURATION_GUIDE.md`)](./docs/CONFIGURATION_GUIDE.md)** — In-depth YAML, Go SDK, and HTTP API reference.
* **[Hands-On Demonstration Suite (`demo/README.md`)](./demo/README.md)** — Interactive demonstration manual for all core gateway systems.
* **[OpenAPI Specifications (`docs/openapi/`)](./docs/openapi/README.md)** — Full OpenAPI 3.0/3.1 contracts.

---

### License

Licensed under the [Apache License, Version 2.0](./LICENSE).
