<p align="center">
  <img src="./assets/logo.png" width="180" alt="GoRoute AI Gateway Logo" style="border-radius: 20px;" />
</p>

# GoRoute AI Gateway
*The ultra-fast, lightweight AI Gateway, MCP Hub, and Agent-to-Agent Router in 100% Pure Go.*

Call major hosted and local model providers through a unified API. Dedicated provider adapters and configurable OpenAI-compatible provider profiles are implemented under `internal/adapter/`.

[![Go Reference](https://pkg.go.dev/badge/github.com/goroute-ai/ai-gateway-go/pkg/gateway.svg)](https://pkg.go.dev/github.com/goroute-ai/ai-gateway-go/pkg/gateway)
[![Go Version](https://img.shields.io/badge/Go-1.26%2B-00ADD8?logo=go)](https://go.dev/)
[![Release](https://img.shields.io/badge/Release-v1.2.0-success)](https://github.com/goroute-ai/ai-gateway-go/releases/tag/v1.2.0)
[![OpenAPI](https://img.shields.io/badge/OpenAPI-3.0%20%2F%203.1-6BA539?logo=openapiinitiative)](./docs/openapi/README.md)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](./LICENSE)

---

### What is GoRoute AI Gateway?

**GoRoute AI Gateway** is a fast, lightweight control plane for your AI apps. It sits between your software and AI providers (like OpenAI, Anthropic, Google Gemini, and AWS Bedrock), giving you **one single, standardized API** to call any model.

Instead of writing custom code for dozens of different providers, you connect to GoRoute once. GoRoute handles the routing, security, and cost tracking.

---

### Why Teams Use GoRoute

| Feature | What It Does |
| :--- | :--- |
| **One Unified API** | Connect to 30+ AI providers using one standard format. |
| **Smart Fallbacks** | Auto-switches models during outages so your apps stay online. |
| **Cost Controls** | Micro-dollar tracking and hard team budgets stop surprise bills. |
| **Enterprise Security** | Virtual Keys, rate limits, and network firewalls keep data safe. |
| **Agent Protocols** | Built-in support for MCP tools and agent-to-agent networks. |

---

### Why GoRoute?

- **100% Pure Go**: Sub-millisecond speed, ultra-low memory, and zero heavy Python runtime.
- **Dual Mode**: Run as a standalone container or embed directly in Go with `pkg/gateway`.

---

### Quick Start (Option A: Developer-First)

#### Path 1: Embedded Go SDK (`pkg/gateway`) — 1-Line Embed
Embed GoRoute directly inside your Go microservices with zero external proxy hops, full type safety, and sub-millisecond execution:

```bash
go get github.com/goroute-ai/ai-gateway-go/pkg/gateway@v1.2.0
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
	ctx := context.Background()

	// Initialize embedded gateway with model aliases and environment variables
	gw, err := gateway.New(
		gateway.WithModelList(
			gateway.ModelEntry{ModelName: "fast", Model: "gemini/gemini-2.5-flash", APIKey: "os.environ/GEMINI_API_KEY"},
			gateway.ModelEntry{ModelName: "reasoning", Model: "anthropic/claude-sonnet-4-20250514", APIKey: "os.environ/ANTHROPIC_API_KEY"},
		),
		gateway.WithDemoMocksIfEnvMissing(), // Instant zero-config local testing
		gateway.WithSilentLogs(),             // Suppress internal logs in library mode
	)
	if err != nil {
		log.Fatal(err)
	}
	defer gw.Close()

	// 1-Line synchronous completion
	res, err := gw.Chat(ctx, "fast", "In one sentence, explain what an AI Gateway does.")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("[%s] %s (cost: %d µ$, routing: %d µs)\n", res.Provider, res.Content, res.CostMicros, res.RoutingMicros)

	// Multi-turn chat using clean exported SDK types (no internal domain imports needed)
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

#### Path 2: Universal One-Line Shell Installer (macOS, Linux, WSL)
Installs the standalone static binary with automatic OS/architecture detection and SHA-256 verification:

```bash
curl -fsSL https://raw.githubusercontent.com/goroute-ai/ai-gateway-go/main/install.sh | bash
```

Run instantly with local mock fallback:
```bash
ai-gateway --config configs/config.yaml
```

*Precompiled binaries are also available on the [**GitHub Releases Page**](https://github.com/goroute-ai/ai-gateway-go/releases/tag/v1.2.0).*

#### Path 3: Production Multi-Tenant Stack (Docker Compose)
Spins up GoRoute, PostgreSQL 16 (for migrations and spend logs), Redis 7 (for sliding-window rate limiting), and Prometheus:

```bash
curl -O https://raw.githubusercontent.com/goroute-ai/ai-gateway-go/main/deployments/docker-compose.yml
docker compose up -d
```

---

### Multi-Language Client Ingress

GoRoute exposes a 100% OpenAI-compatible data plane (`/v1/chat/completions`, `/v1/embeddings`, `/v1/models`). Point any standard client to `http://localhost:8080/v1`:

#### Python (Official `openai` SDK)
```python
from openai import OpenAI

client = OpenAI(
    api_key="sk-gw-master-admin-default-key-change-me",
    base_url="http://localhost:8080/v1"
)

response = client.chat.completions.create(
    model="fast",
    messages=[{"role": "user", "content": "Explain GoRoute in 10 words."}],
    temperature=0.7
)
print(response.choices[0].message.content)
```

#### TypeScript / Node.js (Official `openai` SDK)
```typescript
import OpenAI from "openai";

const client = new OpenAI({
  apiKey: "sk-gw-master-admin-default-key-change-me",
  baseURL: "http://localhost:8080/v1",
});

async function run() {
  const stream = await client.chat.completions.create({
    model: "fast",
    messages: [{ role: "user", content: "Stream me a haiku about performance." }],
    stream: true,
  });

  for await (const chunk of stream) {
    process.stdout.write(chunk.choices[0]?.delta?.content || "");
  }
}
run();
```

#### cURL (Immediate Terminal Invocation)
```bash
curl -X POST http://localhost:8080/v1/chat/completions \
  -H "Authorization: Bearer sk-gw-master-admin-default-key-change-me" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "fast",
    "messages": [{"role": "user", "content": "Hello from GoRoute!"}],
    "stream": false
  }'
```

---

### Agentic Protocols Spotlight

#### Model Context Protocol (MCP 2026-07-28 & 2025-11-25)
GoRoute functions as a production MCP Hub aggregating multiple upstream MCP tools, running local tools in sandboxed Stdio processes, and bridging MCP tools into plain REST:

```bash
# List aggregated tools across all registered MCP servers
curl http://localhost:8080/mcp-rest/tools/list \
  -H "Authorization: Bearer sk-gw-master-admin-default-key-change-me"

# Call an MCP tool directly via lightweight REST bridge
curl -X POST http://localhost:8080/mcp-rest/tools/call \
  -H "Authorization: Bearer sk-gw-master-admin-default-key-change-me" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "calculate_tax",
    "arguments": {"amount": 250.00, "state": "CA"}
  }'
```

#### Linux Foundation Agent-to-Agent Protocol (A2A v1.0)
GoRoute exposes full RFC 8785 JCS canonicalized and RFC 7515 JWS signed Agent Cards, dual HTTP+JSON and JSON-RPC dispatch, and an OpenAI Compatibility Bridge:

```bash
# Discover cryptographic Agent Card
curl http://localhost:8080/.well-known/agent-card.json

# Call an A2A agent using standard OpenAI chat completions
curl -X POST http://localhost:8080/v1/chat/completions \
  -H "Authorization: Bearer sk-gw-master-admin-default-key-change-me" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "a2a/financial-analyst",
    "messages": [{"role": "user", "content": "Analyze Q3 portfolio spend."}]
  }'
```

#### Server-Side Autonomous Tool Loop
With `internal/orchestrator`, GoRoute intercepts function calls emitted by models, invokes the corresponding MCP tools server-side, feeds results back to the model recursively, and returns the final answer in a single roundtrip to the client. Token spend across all turns is consolidated into a single ledger transaction with **anti-double-billing protection**.

---

### FinOps Micro-Dollar Accounting & Virtual Keys

GoRoute operates with integer micro-dollar arithmetic ($1 = 1,000,000 µ$), completely eliminating IEEE-754 floating-point drift:

```bash
# 1. Issue a Scoped Virtual Key with Budget & Rate Limits
curl -X POST http://localhost:8080/admin/v1/keys \
  -H "Authorization: Bearer sk-gw-master-admin-default-key-change-me" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "mobile-app-prod",
    "org_id": "org_default",
    "team_id": "team_mobile",
    "role": "developer",
    "max_budget_micros": 50000000,
    "allowed_models": ["fast", "gemini-2.5-flash", "llama3.2:1b"],
    "rate_limit_rpm": 600,
    "rate_limit_tpm": 1000000
  }'

# 2. Query Live Aggregated Spend
curl http://localhost:8080/admin/v1/spend/summary \
  -H "Authorization: Bearer sk-gw-master-admin-default-key-change-me"
```

---

### Declarative Configuration (`configs/config.yaml`)

Define models, weights, routing strategies, and fallbacks declaratively (supporting `os.environ/VAR` substitution):

```yaml
gateway:
  port: 8080
  admin_key: os.environ/GATEWAY_MASTER_ADMIN_KEY

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

  - model_name: local
    routing_strategy: lowest-cost
    model_params:
      model: ollama/llama3.2:1b
      api_base: http://localhost:11434
```

---

### License

Licensed under the [Apache License, Version 2.0](./LICENSE).
