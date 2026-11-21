<p align="center">
  <img src="./assets/logo-dark.png" width="160" alt="GoRoute AI Gateway Logo" style="border-radius: 20px;" />
</p>

# GoRoute AI Gateway

**Ultra-fast, lightweight AI Gateway, Multi-Release MCP Hub, and Linux Foundation A2A v1.0 Router in 100% Pure Go with an Embedded Operator Web UI.**

[![Go Reference](https://pkg.go.dev/badge/github.com/goroute-ai/ai-gateway-go/pkg/gateway.svg)](https://pkg.go.dev/github.com/goroute-ai/ai-gateway-go/pkg/gateway)
[![Go Version](https://img.shields.io/badge/Go-1.26%2B-00ADD8?logo=go)](https://go.dev/)
[![Version](https://img.shields.io/badge/Version-v0.1.0-00ADD8)](./CHANGELOG.md)
[![Docker Hub](https://img.shields.io/badge/Docker%20Hub-qaadir%2Fai--gateway-2496ED?logo=docker&logoColor=white)](https://hub.docker.com/r/qaadir/ai-gateway)
[![Docker GHCR](https://img.shields.io/badge/GHCR-ghcr.io%2Fgoroute--ai%2Fai--gateway--go-2496ED?logo=docker&logoColor=white)](https://github.com/goroute-ai/ai-gateway-go/pkgs/container/ai-gateway-go)
[![OpenAPI](https://img.shields.io/badge/OpenAPI-3.0%20%2F%203.1-6BA539?logo=openapiinitiative)](./docs/openapi/README.md)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](./LICENSE)

GoRoute sits between your applications and OpenAPI-first model providers (**OpenAI**, **Anthropic Claude**, **Groq**, and **OpenRouter**), exposing a unified `/v1/*` API (`127` OpenAPI endpoints) with sub-millisecond routing, 3-state circuit breakers, Redis Lua sliding-window quotas, exact integer micro-dollar FinOps, vendor-neutral OIDC federation, 15 built-in guardrail drivers, and a zero-dependency React Operator Console embedded directly in the Go binary.

---

## Core Capabilities

| Pillar | Capabilities | Deep Dive |
| :--- | :--- | :--- |
| **Unified OpenAPI Data Plane** | `28` `/v1` operations (`chat/completions`, `responses`, `messages`, `embeddings`, `audio/*`, `images/*`, `files`, `batches`, `realtime` WebSockets) backed by spec-generated DTOs for **OpenAI**, **Anthropic**, **Groq**, and **OpenRouter**. | [API Reference](./docs/API_REFERENCE.md) |
| **6-Stage Intelligent Routing** | Pre-routers (`heuristic`, `semantic`, `quality`, `adaptive` UCB bandit), deployment filter chain, priority tiers, 7 load-balancing strategies, hedged racing, session affinity, Redis slot leases, and mid-stream SSE continuation. | [Architecture](./docs/ARCHITECTURE.md) |
| **OIDC Federation & Authz Parity** | Multi-issuer OIDC + PKCE (`S256`) browser & CLI SSO, RP-Initiated Logout, RFC 7662 introspection, SCIM 2.0 (`/scim/v2/*`), group-to-role sync, fail-closed `ExternalAuthorizer` (webhook/OPA/SDK), and HMAC SIEM audit export. | [Configuration](./docs/CONFIGURATION_GUIDE.md) |
| **Vault, Virtual Keys & Sinks** | AES-256-GCM envelope encryption (KEK/DEK), zero-downtime rolling Master KEK rotation, `sk-gw-...` virtual keys, grace-period rotation, self-service developer keys (`/v1/self/keys`), and transactional secret sinks (`webhook`, `vault_kv2`). | [Internals](./docs/INTERNALS.md) |
| **Redis Lua Quotas & FinOps** | Atomic cluster-safe Lua scripts enforcing RPM, TPM, split ITPM/OTPM, RPD, concurrency, PTU shares, and multi-window budgets (`daily`, `weekly`, `monthly`, `rolling_24h`) in **64-bit integer micro-dollars** ($1 = $1{,}000{,}000\ \mu\$$). | [Internals](./docs/INTERNALS.md) |
| **15-Driver Guardrail Pipeline** | Concurrent 3-phase (input, streaming chunk, output) evaluation for PII redaction, prompt injection, jailbreak, secrets, toxicity, code execution, regex, schema validation, and `GuardrailActionRoute` sensitive model routing. | [API Reference](./docs/API_REFERENCE.md) |
| **MCP Virtual Hub & A2A v1.0** | Spec-generated 5-release MCP engine (`2024-11-05` to `2026-07-28`) with live UI protocol switching, SHA-256 tool pinning, AEAD resumption tokens, `ToolPolicy` governance, and Linux Foundation A2A v1.0 (`gRPC`, `JSON-RPC`, `REST`). | [OpenAPI Specs](./docs/openapi/README.md) |
| **Embedded Web UI, SDK & CLI** | Built-in React Operator Console (`http://localhost:8080/ui/`), in-process Go SDK (`pkg/gateway`), and developer CLI (`cmd/goroute` for PKCE login, key rotation, and model discovery). | [Codebase Map](./docs/CODEBASE_MAP.md) |

---

## Quick Start

### 1. Build from Source, Docker Compose, or Kubernetes (Helm)

```bash
# Build and run the single static binary locally
make build
./bin/ai-gateway -config configs/config.yaml

# Or run the full stack (GoRoute + PostgreSQL 16 + Redis 7 + Prometheus)
docker compose -f deployments/docker-compose.yml up -d

# Or deploy to Kubernetes via Helm chart
helm install goroute ./deployments/helm/goroute
```

Open the embedded Operator Web UI & Streaming Playground at **`http://localhost:8080/ui/`**.

### 2. Drop-In OpenAI SDK & `goroute` Developer CLI

Point any standard OpenAI client (`python`, `node`, `curl`) to `http://localhost:8080/v1`, or authenticate via the `goroute` CLI:

```bash
# Authenticate via OIDC PKCE device flow and list models
goroute login --gateway http://localhost:8080
goroute models list

# Call the unified /v1/chat/completions endpoint
curl http://localhost:8080/v1/chat/completions \
  -H "Authorization: Bearer $GATEWAY_DEFAULT_KEY" \
  -H "Content-Type: application/json" \
  -d '{"model": "auto", "messages": [{"role": "user", "content": "Explain raft consensus in one sentence."}]}'
```

### 3. In-Process Embedded Go SDK (`pkg/gateway`)

```bash
go get github.com/goroute-ai/ai-gateway-go/pkg/gateway
```

```go
package main

import (
	"context"
	"fmt"
	"log"

	"github.com/goroute-ai/ai-gateway-go/pkg/gateway"
)

func main() {
	gw, err := gateway.New(
		gateway.WithModelList(
			gateway.ModelEntry{ModelName: "fast", Model: "openai/gpt-4o-mini", APIKey: "os.environ/OPENAI_API_KEY"},
			gateway.ModelEntry{ModelName: "reasoning", Model: "anthropic/claude-sonnet-4-20250514", APIKey: "os.environ/ANTHROPIC_API_KEY"},
		),
		gateway.WithDemoMocksIfEnvMissing(),
		gateway.WithSilentLogs(),
	)
	if err != nil {
		log.Fatal(err)
	}
	defer gw.Close()

	res, err := gw.Chat(context.Background(), "fast", "In one sentence, explain what an AI Gateway does.")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("[%s] %s (cost: %d µ$, routing: %d µs)\n", res.Provider, res.Content, res.CostMicros, res.RoutingMicros)
}
```

---

## Documentation Hub

| Guide | Description |
| :--- | :--- |
| **[Documentation Index (`docs/README.md`)](./docs/README.md)** | Master index for architecture, API reference, internals, operations, and specifications. |
| **[API Reference (`docs/API_REFERENCE.md`)](./docs/API_REFERENCE.md)** | Complete endpoint reference across `/v1`, `/admin/v1`, `/auth`, `/scim/v2`, `/mcp`, and `/a2a` (`127` OpenAPI paths). |
| **[Configuration Guide (`docs/CONFIGURATION_GUIDE.md`)](./docs/CONFIGURATION_GUIDE.md)** | Declarative YAML configuration, environment variables, OIDC SSO setup, and `pkg/gateway` SDK options. |
| **[System Architecture (`docs/ARCHITECTURE.md`)](./docs/ARCHITECTURE.md)** | High-Level (HLD) and Low-Level (LLD) design, PostgreSQL schema (`0001`–`0041`), and Redis cluster keyspace. |
| **[Subsystem Internals (`docs/INTERNALS.md`)](./docs/INTERNALS.md)** | Mathematical formulations, Lua quota algorithms, envelope encryption, and sequence diagrams. |
| **[Upgrade & Rollback Guide (`docs/UPGRADING.md`)](./docs/UPGRADING.md)** | Zero-downtime migration procedures (`0001`–`0041`), rolling KEK rotation, and rollback preflight checks. |
| **[Testing & Verification (`docs/TESTING.md`)](./docs/TESTING.md)** | 3-tier verification guide: contract parity, unit/race suites, Postgres/Redis E2E, Playwright UI E2E, and Keycloak 26 Docker tests. |
| **[OpenAPI & Protocol Specs (`docs/openapi/`)](./docs/openapi/README.md)** | Machine-readable OpenAPI 3.0/3.1 specs, 5-release MCP YAML schemas, and A2A v1.0 Protobuf contracts. |
| **[Codebase Map (`docs/CODEBASE_MAP.md`)](./docs/CODEBASE_MAP.md)** | Package layout, domain boundaries, and contributor navigation guide (see also [AGENTS.md](./AGENTS.md) & [CLAUDE.md](./CLAUDE.md)). |

---

## License

Licensed under the [Apache License, Version 2.0](./LICENSE).
