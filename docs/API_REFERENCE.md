# GoRoute AI Gateway — Complete API Reference

> **Version**: `v1.0.0`  
> **Base URL (Local)**: `http://localhost:8080`  
> **OpenAPI Contracts**: [docs/openapi/gateway.openapi.yaml](./openapi/gateway.openapi.yaml), [docs/openapi/mcp.openapi.yaml](./openapi/mcp.openapi.yaml), [docs/openapi/a2a.openapi.yaml](./openapi/a2a.openapi.yaml)

---

## 1. Authentication & Common Headers

All Gateway endpoints require authentication using a Virtual API Key (`sk-gw-...`) or Master Admin Key passed via the standard `Authorization` header.

```http
Authorization: Bearer sk-gw-prod-7f9a2b8c4d1e
```

### Standard Gateway Response Headers
Every response from GoRoute AI Gateway includes rich tracing and attribution metadata:

| Header | Description | Example |
| :--- | :--- | :--- |
| `X-Gateway-Request-Id` | Unique UUID assigned to the request lifecycle | `req_991efda4-7fab-4b03` |
| `X-Trace-Id` | W3C / OpenTelemetry Trace ID | `bad98e7deea34d7c810a963d9ed2c4ef` |
| `X-Gateway-Provider` | The winning upstream provider selected | `gemini`, `anthropic`, `openai` |
| `X-Gateway-Model` | The physical model that executed the inference | `gemini-2.5-flash`, `claude-sonnet-4` |
| `X-Gateway-Cost-Micros`| Micro-dollar spend incurred ($10^{-6}\text{ USD}$) | `45` ($0.000045 USD) |
| `X-Gateway-Routing-Time`| Gateway Stage 1 + Stage 2 routing overhead | `12 µs` |
| `X-Gateway-Cache` | Cache evaluation result | `HIT` or `MISS` |
| `Retry-After` | Cooldown period sent on HTTP 429 rate limit | `45` (seconds) |

---

## 2. OpenAI-Compatible Data Plane (`/v1/*`)

### 2.1 Chat Completions
`POST /v1/chat/completions`

Standardized endpoint supporting Google Gemini, Anthropic Claude, OpenAI, Mistral, and local Ollama models in synchronous JSON or real-time Server-Sent Events (SSE) streaming mode.

#### Request Schema
```json
{
  "model": "fast",
  "messages": [
    {"role": "system", "content": "You are a concise engineering assistant."},
    {"role": "user", "content": "What is the capital of France?"}
  ],
  "temperature": 0.7,
  "max_tokens": 1024,
  "stream": false,
  "tools": [
    {
      "type": "function",
      "function": {
        "name": "get_weather",
        "description": "Get current weather in a given city",
        "parameters": {
          "type": "object",
          "properties": {
            "city": {"type": "string"}
          },
          "required": ["city"]
        }
      }
    }
  ]
}
```

#### Synchronous Response (HTTP 200 OK)
```json
{
  "id": "chatcmpl-req_991efda4-7fab-4b03",
  "object": "chat.completion",
  "created": 1731081600,
  "model": "gemini-2.5-flash",
  "choices": [
    {
      "index": 0,
      "message": {
        "role": "assistant",
        "content": "The capital of France is Paris."
      },
      "finish_reason": "stop"
    }
  ],
  "usage": {
    "prompt_tokens": 18,
    "completion_tokens": 7,
    "total_tokens": 25
  }
}
```

#### Real-Time SSE Stream (`stream: true`)
```http
HTTP/1.1 200 OK
Content-Type: text/event-stream
Cache-Control: no-cache
Connection: keep-alive

data: {"id":"chatcmpl-req_1","object":"chat.completion.chunk","created":1731081600,"model":"gemini-2.5-flash","choices":[{"index":0,"delta":{"role":"assistant","content":"The"},"finish_reason":null}]}

data: {"id":"chatcmpl-req_1","object":"chat.completion.chunk","created":1731081600,"model":"gemini-2.5-flash","choices":[{"index":0,"delta":{"content":" capital"},"finish_reason":null}]}

data: {"id":"chatcmpl-req_1","object":"chat.completion.chunk","created":1731081600,"model":"gemini-2.5-flash","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}

data: [DONE]
```

#### Extended Reasoning & Parameter Normalization
GoRoute transparently normalizes requests targeting frontier reasoning models:
- **Reasoning Effort**: When `reasoning_effort` (`"low"`, `"medium"`, `"high"`) is provided:
  - **OpenAI Reasoning (`o1`, `o3`, `o3-mini`)**: Converts `role: "system"` to `role: "developer"`, translates `max_tokens` to `max_completion_tokens`, and omits unsupported parameters (`temperature`, `top_p`).
  - **Anthropic Claude**: Enables extended thinking with token budgets (`1024`, `4096`, `16384`) and automatically omits `temperature` and `top_p` as mandated by Anthropic.
  - **Google Gemini**: Sets `thinkingConfig.thinkingBudget` for Gemini 2.5 thinking models.
- **Anthropic Role Alternation on Tools**: When returning multiple parallel tool outputs (`role: "tool"`), GoRoute automatically consolidates consecutive tool results into a single `user` message with multiple `tool_result` content blocks to satisfy Anthropic's strict alternating turn protocol.

#### Upstream Error Handling & Safety Filters
When an upstream provider blocks a prompt or candidate, GoRoute returns standard OpenAI-compatible error payloads:
- **Gemini Safety Filter Blocks**: If a prompt is blocked by Google Gemini safety filters (`promptFeedback.blockReason`), GoRoute immediately intercepts the empty choice set and returns an explicit `HTTP 400 Bad Request`:
```json
{
  "error": {
    "message": "prompt blocked by safety filters (reason: SAFETY)",
    "type": "safety_violation",
    "code": "prompt_blocked"
  }
}
```

### 2.2 Vector Embeddings
`POST /v1/embeddings`

```json
{
  "model": "text-embedding-004",
  "input": ["GoRoute AI Gateway is ultra-fast", "Pure Go architecture"]
}
```

### 2.3 Model Inventory
`GET /v1/models`

Returns 4-layer tenant-filtered model inventory accessible to the caller's Virtual API Key, including rich tri-state capabilities and integer micro-dollar pricing metadata.

#### Response (HTTP 200 OK)
```json
{
  "object": "list",
  "data": [
    {
      "id": "openai/gpt-4.1",
      "object": "model",
      "created": 1731081600,
      "owned_by": "openai",
      "display_name": "OpenAI GPT-4.1",
      "max_input_tokens": 1047576,
      "max_output_tokens": 32768,
      "capabilities": {
        "tools": "supported",
        "streaming": "supported",
        "vision": "supported",
        "reasoning": "unknown",
        "structured_outputs": "supported",
        "embeddings": "unsupported"
      },
      "supports_streaming": true,
      "supports_tools": true,
      "supports_vision": true,
      "supports_reasoning": false,
      "supports_embeddings": false,
      "input_cost_micros_per_1m": 2000000,
      "output_cost_micros_per_1m": 8000000,
      "cached_input_cost_micros_per_1m": 500000,
      "pricing_status": "verified",
      "pricing_provenance_source": "official-vendor-pricing-2025",
      "pricing_effective_date": "2025-05-01",
      "lifecycle_status": "active"
    }
  ]
}
```

### 2.4 Direct Dynamic `provider/model` Routing
GoRoute supports direct model execution using `provider/model` notation (e.g. `cerebras/llama-3.3-70b`, `bedrock/anthropic.claude-3-5-sonnet-20241022-v2:0`, `vertex/gemini-2.5-pro`, `xai/grok-2`):
- **Layer 2 Provider Subscription Check**: The caller's organization must have an active subscription for the requested provider (if subscriptions are configured).
- **Layer 3 Model Policy Check**: The requested model must not be explicitly disabled by the organization's model availability policy.
- **Tenant Credential Isolation**: The organization must have an active credential for the target provider. Server environment variables are never leaked across tenant boundaries.
- **Dynamic Catalogue Provisioning**: If the model is not yet in the organization's database catalogue, GoRoute dynamically imports it from the embedded 4,627-model catalogue with active lifecycle status and provisions the route on the fly.
- **Fail-Closed Boundary**: If repository queries fail, or if the model is unconfigured/unauthorized, GoRoute fails closed and returns `HTTP 404 model_group_not_found` (explicit model requests never silently fall back to unrelated tenant model groups).

---

## 3. Model Context Protocol (MCP) APIs

GoRoute AI Gateway implements the official **MCP 2026-07-28** stateless Streamable HTTP specification with backward-compatible support for **MCP 2025-11-25**.

### 3.1 Virtual Hub Multi-Server Aggregator
`POST /mcp`

Dispatches MCP JSON-RPC 2.0 requests across all registered and accessible MCP servers for the caller's organization.

#### Headers Required:
```http
Content-Type: application/json
Accept: application/json, text/event-stream
Origin: http://localhost:8080
Authorization: Bearer sk-gw-...
```

#### Tool Discovery (`tools/list`):
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/list",
  "params": {}
}
```

#### Response:
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "tools": [
      {
        "name": "github__create_issue",
        "description": "Create an issue in a GitHub repository",
        "inputSchema": { "type": "object", "properties": { "title": {"type": "string"} }, "required": ["title"] }
      },
      {
        "name": "fin-tools__calculate_dcf",
        "description": "Calculate discounted cash flow with high precision",
        "inputSchema": { "type": "object", "properties": { "cash_flows": {"type": "array"} } }
      }
    ],
    "_meta": {
      "goroute.ai/server_outcomes": {
        "github": "success",
        "fin-tools": "success"
      }
    }
  }
}
```

### 3.2 Scoped Server Execution
`POST /mcp/{serverSlug}`

Direct invocation targeted at a single MCP server. Supports tool calling with arbitrary decimal precision preservation (`big.Rat` / `json.Number`).

```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "method": "tools/call",
  "params": {
    "name": "calculate_discounted_cash_flow",
    "arguments": {
      "discount_rate": 0.08251294819284719,
      "cash_flows": [1000000, 1500000, 2000000]
    }
  }
}
```

### 3.3 Curated Toolset Execution
`POST /mcp/toolsets/{toolsetSlug}`

Routes tool execution through a curated subset of vetted, pinned tools across multiple backend servers.

### 3.4 Plain MCP REST Bridge
Standard RESTful endpoints designed for traditional HTTP clients, SDKs, and frontend applications that interact without JSON-RPC 2.0 framing.

#### List Accessible Tools
`GET /mcp-rest/tools/list`
- **Query Parameters**:
  - `server_slug` (optional): Filter tools registered under a specific upstream server.
- **Headers**: `Authorization: Bearer sk-gw-...`
- **Response (HTTP 200 OK)**:
```json
{
  "tools": [
    {
      "id": "tool_019248ab-...",
      "server_id": "mcp_srv_771...",
      "name": "get_weather",
      "description": "Get current weather in a location",
      "input_schema": {
        "type": "object",
        "properties": {
          "location": { "type": "string" }
        },
        "required": ["location"]
      },
      "cost_per_call_micros": 100,
      "is_active": true
    }
  ]
}
```

#### Execute Tool Call
`POST /mcp-rest/tools/call`
- **Headers**: `Authorization: Bearer sk-gw-...`, `Content-Type: application/json`
- **Request Body**:
```json
{
  "server_slug": "weather-service",
  "tool_name": "get_weather",
  "arguments": {
    "location": "Kyoto, Japan"
  }
}
```
- **Response (HTTP 200 OK)**:
```json
{
  "content": [
    {
      "type": "text",
      "text": "Sunny, 22°C with light breeze in Kyoto"
    }
  ],
  "is_error": false
}
```
- **Error Handling**:
  - `HTTP 400 AmbiguousToolName`: Returned when `tool_name` matches multiple active servers and `server_slug` was omitted. Contains `matching_servers` array.
  - `HTTP 403 mcp_server_forbidden`: Caller virtual key is not authorized for the requested server.

### 3.5 Progressive Tool Discovery & Public Registry
`GET /v1/goroute/mcp/registry`

To drastically reduce prompt token overhead in agent loops, GoRoute issues compact 256-bit cryptographic tool handles (`tool_hdl_<64 hex chars>`).

#### Registry Catalog Feed
`GET /v1/goroute/mcp/registry`
- **Response (HTTP 200 OK)**:
```json
{
  "servers": [
    {
      "server_slug": "fin-tools",
      "tools": [
        {
          "name": "calculate_discounted_cash_flow",
          "description": "Calculates DCF valuation",
          "tool_handle": "tool_hdl_a1b2c3d4e5f6..."
        }
      ]
    }
  ]
}
```

#### Dynamic Schema Hydration Meta-Tools
When progressive discovery is active, models only receive tool handles and descriptions. When a model decides to invoke a tool, it calls built-in meta-tools:
1. `search_tools`: Keyword search over registered tool definitions.
   ```json
   { "query": "cash flow", "limit": 5 }
   ```
2. `get_tool_schema`: Resolves full JSON Schema by handle.
   ```json
   { "tool_handle": "tool_hdl_a1b2c3d4e5f6..." }
   ```
3. **Execution via Handle**: Directly call `POST /mcp-rest/tools/call` using `tool_name: "tool_hdl_..."`. If an upstream schema mutates, stale handles fail-closed with HTTP 404/410.

### 3.6 Governed OpenAPI-to-MCP Transport
`POST /admin/v1/mcp/servers` with `"transport_type": "openapi"`

Connect existing RESTful microservices directly to the MCP ecosystem without writing custom MCP servers. The Gateway dynamically digests OpenAPI 3.0/3.1 specs, synthesizes MCP tool definitions, performs path parameter interpolation (e.g. `/products/{productId}`), and enforces validation guardrails.

---

## 4. Agent-to-Agent Protocol (A2A v1.0) APIs

GoRoute AI Gateway implements the Linux Foundation **Agent-to-Agent (A2A v1.0)** protocol specification.

### 4.1 Cryptographic Agent Card Discovery
`GET /.well-known/agent-card.json`

Serves canonical agent card formatted with **RFC 8785 JSON Canonicalization Scheme (JCS)** and signed with **RFC 7515 JWS (`ES256`)**.

```json
{
  "name": "GoRoute AI Gateway Agent Service",
  "version": "1.0.0",
  "supportedInterfaces": [
    {
      "url": "http://localhost:8080/a2a/v1/agents/analyst",
      "protocolBinding": "HTTP+JSON"
    }
  ],
  "signatures": [
    {
      "header": { "alg": "ES256", "kid": "gw-a2a-signer-v1", "typ": "JWT" },
      "signature": "MEUCIQ..."
    }
  ]
}
```

### 4.2 Dual-Binding Agent Message Dispatch
`POST /a2a/v1/agents/{agentSlug}`

Accepts both standard HTTP+JSON (`application/json`) and JSON-RPC 2.0 payloads.

#### JSON-RPC 2.0 Format (`tasks/send`):
```json
{
  "jsonrpc": "2.0",
  "id": "req-a2a-001",
  "method": "tasks/send",
  "params": {
    "message": {
      "role": "ROLE_USER",
      "parts": [
        { "text": "Perform portfolio Value-at-Risk assessment." }
      ]
    }
  }
}
```

#### Response:
```json
{
  "jsonrpc": "2.0",
  "id": "req-a2a-001",
  "result": {
    "role": "ROLE_AGENT",
    "parts": [
      { "text": "Portfolio risk assessment: Value-at-Risk (VaR 95%) is 1.42%." }
    ],
    "taskId": "task_a2a_5b91a7c"
  }
}
```

### 4.3 Subscribe-First Real-Time SSE Task Streaming
`GET /a2a/v1/agents/{agentSlug}/tasks/{taskID}:subscribe`

Clients connect to stream durable task events (status transitions, intermediate thoughts, artifact publications) in real-time. Emits `a2a-event` Server-Sent Events with strictly monotonic sequence numbers (`seq`).

```http
HTTP/1.1 200 OK
Content-Type: text/event-stream
Cache-Control: no-cache
Connection: keep-alive

event: a2a-event
data: {"seq":1,"taskId":"task_a2a_5b91a7c","state":"working","timestamp":"2026-11-08T21:00:00Z"}

event: a2a-event
data: {"seq":2,"taskId":"task_a2a_5b91a7c","state":"completed","output":{"role":"ROLE_AGENT","parts":[{"text":"Done."}]}}
```

### 4.4 Native A2A gRPC Service
`lf.a2a.v1.A2AService`

For ultra-low latency inter-agent communication, the Gateway exposes a native gRPC server implementing the official Linux Foundation A2A Protobuf contract.

#### gRPC Service Definition
```protobuf
service A2AService {
  rpc SendMessage(SendMessageRequest) returns (SendMessageResponse);
  rpc GetTask(GetTaskRequest) returns (Task);
  rpc ListTasks(ListTasksRequest) returns (ListTasksResponse);
  rpc CancelTask(CancelTaskRequest) returns (Task);
  rpc SubscribeToTask(SubscribeToTaskRequest) returns (stream StreamTaskResponse);
}
```

#### gRPC Authentication & Metadata
Clients connect with standard gRPC Bearer authentication headers:
```go
md := metadata.Pairs("authorization", "Bearer sk-gw-...")
ctx := metadata.NewOutgoingContext(context.Background(), md)
resp, err := client.SendMessage(ctx, &pb.SendMessageRequest{
    Message: &pb.Message{
        Role: pb.MessageRole_ROLE_USER,
        Parts: []*pb.Part{pb.NewTextPart("Run code audit")},
    },
})
```

### 4.5 A2A-to-OpenAI Compatibility Bridge
`POST /v1/chat/completions` with `"model": "a2a/{agent_slug}"`

Allows standard OpenAI Python/TypeScript/Go SDKs to orchestrate multi-agent workflows without changing client libraries.

#### Request Format
```json
{
  "model": "a2a/risk-analyst",
  "messages": [
    { "role": "user", "content": "Compute Value-at-Risk for Portfolio 4" }
  ]
}
```

#### Multi-Turn Resumption (`TASK_STATE_INPUT_REQUIRED`)
When an upstream agent requires clarifying input, the Gateway returns a response with `finish_reason: "stop"` containing the agent's question. Callers resume the task by passing the same `model: "a2a/{agent_slug}"` and including the previous conversation history; the Gateway automatically resolves the active `taskId` and preserves execution context.

---

## 5. Admin Control Plane APIs (`/admin/v1/*`)

All Admin APIs require `Authorization: Bearer <MASTER_ADMIN_KEY>`.

### 5.1 Virtual Key Provisioning & RBAC
`POST /admin/v1/keys`

```json
{
  "org_id": "org_default",
  "name": "finance-agent-key",
  "role": "service_account",
  "rpm_limit": 1000,
  "tpm_limit": 500000,
  "max_budget_micros": 50000000,
  "allowed_models": ["fast", "gemini-2.5-flash"],
  "allowed_mcp_servers": ["fin-tools"],
  "allowed_a2a_agents": ["risk-analyst"]
}
```

### 5.2 MCP Server Registration & Sync
- `POST /admin/v1/mcp/servers`: Registers an MCP upstream endpoint.
- `POST /admin/v1/mcp/servers/{id}/sync`: Probes server, runs anti-poisoning scanner, and pins SHA-256 tool digests.

### 5.3 A2A Agent Registration & Emergency Kill-Switch
- `POST /admin/v1/a2a/agents`: Registers an upstream agent card and endpoint.
- `POST /admin/v1/a2a/agents/{id}/kill-switch`: Toggles emergency kill-switch.
  ```json
  { "killed": true }
  ```
  When killed, calls across all pods instantly return `HTTP 503 agent_killed`.

### 5.4 Active Health Probing
`POST /admin/v1/health/probe`

Triggers immediate synthetic health verification across all configured provider deployments.

### 5.5 Upstream Model Discovery and Embedded Catalogue Import
`POST /admin/v1/catalogue/sync`

Triggers model discovery against active provider credentials. To import entries from the embedded 4,627-model catalogue into the database, use `POST /admin/v1/catalogue/import` instead.

This endpoint has no request body; it polls active credentials that support model listing.
- `POST /admin/v1/catalogue/import?provider=cerebras` imports embedded catalogue metadata, optionally filtered by provider. Omit `provider` to import all entries.

```bash
curl -X POST http://localhost:8080/admin/v1/catalogue/import?provider=cerebras \
  -H "Authorization: Bearer $MASTER_ADMIN_KEY"
```

#### Discovery Response (HTTP 200 OK)
```json
{
  "synced_at": "2026-11-10T00:00:00Z",
  "total_discovered": 18,
  "new_models": [],
  "updated_models": []
}
```

The embedded catalogue import returns a separate summary:

```json
{
  "imported": 18,
  "provider": "cerebras",
  "total": 4627
}
```

### 5.6 Model Pricing & Provenance Promotion
`POST /admin/v1/catalogue/pricing`

Updates pricing rates and promotes pricing provenance for a catalogued model.

#### Request Body (JSON)
```json
{
  "global_model_id": "gemini/gemini-2.5-flash",
  "input_cost_micros_per_1m": 150000,
  "output_cost_micros_per_1m": 600000,
  "cached_input_cost_micros_per_1m": 37500,
  "reasoning_cost_micros_per_1m": 600000,
  "pricing_status": "verified",
  "pricing_provenance_source": "vendor-contract-amendment-2026",
  "pricing_effective_date": "2026-11-01"
}
```
- Promotes `pricing_status` to `"verified"`, which unblocks budget-restricted enterprise callers.
- Automatically appends an immutable, versioned audit record to `model_pricing_history`.

---

## 6. Observability & Telemetry APIs

### 6.1 Prometheus Metrics Scraper
`GET /metrics`

Returns standard OpenMetrics text format:
```prometheus
# HELP gateway_requests_total Total inference requests processed by the AI Gateway.
# TYPE gateway_requests_total counter
gateway_requests_total 14499

# HELP gateway_latency_ms Request latency percentiles in milliseconds.
# TYPE gateway_latency_ms gauge
gateway_latency_ms{quantile="0.5"} 1.50
gateway_latency_ms{quantile="0.95"} 3.27
gateway_latency_ms{quantile="0.99"} 4.53

# HELP gateway_cache_hits_total Total exact-match response cache hits.
# TYPE gateway_cache_hits_total counter
gateway_cache_hits_total 8675
```

### 6.2 Administrative Metrics Snapshot
`GET /admin/v1/observability/metrics`

Returns comprehensive JSON snapshot with P50/P95/P99 latencies, cache hit ratios, per-provider error rates, and routing overhead.

### 6.3 Health & Readiness Probes
GoRoute exposes production-grade Kubernetes health check probes:

#### Liveness Probe
`GET /health` or `GET /livez`

Fast, in-memory process health check returning `HTTP 200 {"status":"ok"}`. Indicates whether the gateway HTTP server is alive and receiving traffic.

#### Deep Readiness Probe
`GET /readyz`

Performs active, deep dependency health verification. Executes a live `Ping(ctx)` against the underlying storage engine (PostgreSQL or Memory) and Redis cache:
- **HTTP 200 OK**: Both storage repository and Redis respond healthy within timeout.
  ```json
  {"status":"ready"}
  ```
- **HTTP 503 Service Unavailable**: One or more dependencies failed to respond.
  ```json
  {"status":"not_ready","reason":"storage unreachable: connection refused"}
  ```

---

## 7. Enterprise Upstream Authentication Strategies

GoRoute AI Gateway strictly decouples caller credentials (incoming Virtual API Keys) from outbound upstream credentials. Configure outbound authentication strategies in provider or server configuration:

### 7.1 AWS Signature Version 4 (SigV4)
Signs outbound requests to AWS Bedrock, SageMaker, or API Gateway endpoints using AWS SDK v2.
```yaml
upstream_auth:
  type: "aws_sigv4"
  aws_sigv4:
    region: "us-east-1"
    service: "bedrock"
    access_key_id: "AKIA..."
    secret_access_key: "wJalr..."
```

### 7.2 Client Identifier Metadata Document (CIMD) & S256 PKCE
Implements RFC 7591 dynamic client registration and MCP 2026-07-28 client metadata documents with SHA-256 Proof Key for Code Exchange (PKCE).
```yaml
upstream_auth:
  type: "cimd_pkce"
  cimd:
    client_id: "https://gateway.example.com/oauth/client-metadata.json"
    redirect_uri: "https://gateway.example.com/oauth/callback"
```

### 7.3 RFC 9207 & RFC 8707 Security Validations
- **RFC 9207**: Prevents OAuth 2.0 authorization code mix-up attacks by verifying that the `iss` parameter returned by the authorization server exactly matches the configured upstream issuer URL.
- **RFC 8707**: Validates resource indicators against strict origin boundaries, ensuring tokens cannot be misdirected across microservices.

### 7.4 RFC 8693 OAuth 2.0 Token Exchange
Exchanges caller tokens or gateway service credentials for scoped downstream access tokens (On-Behalf-Of flows) with TTL-aware in-memory caching and proactive cache eviction before token expiry.
```yaml
upstream_auth:
  type: "token_exchange"
  token_exchange:
    token_endpoint: "https://auth.enterprise.com/oauth/v2/token"
    audience: "https://api.internal.service"
    subject_token_type: "urn:ietf:params:oauth:token-type:jwt"
```

