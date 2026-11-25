# GoRoute AI Gateway — Complete API Reference

> **Version**: `v0.1.0`\
> **Base URL (Local)**: `http://localhost:8080`  
> **OpenAPI Contracts**: [docs/openapi/gateway.openapi.yaml](./openapi/gateway.openapi.yaml) (`127` OpenAPI paths), [docs/openapi/mcp.openapi.yaml](./openapi/mcp.openapi.yaml), [docs/openapi/a2a.openapi.yaml](./openapi/a2a.openapi.yaml)\
> **Provisioning**: SCIM 2.0 `/scim/v2/*` (`12` endpoints across `/scim/v2/Users` and `/scim/v2/Groups`)

---

## 1. Authentication, Sessions, Provisioning & Common Headers

### 1.1 Data Plane & Control Plane Credential Extraction
All Data Plane (`/v1/*`) and Admin Control Plane (`/admin/v1/*`) endpoints extract caller credentials consistently:
- **Supported Key Headers**: `Authorization: Bearer <token>`, `x-api-key`, `api-key`, `x-goog-api-key`, or a configured override header (`auth.custom_api_key_header` / `GATEWAY_CUSTOM_API_KEY_HEADER`).
- **Conflicting Credentials Rejected**: Supplying contradictory credentials across multiple supported headers is rejected rather than silently picking one.
- **Enterprise Data Plane Identity Modes**: When enabled, `/v1/*` accepts asymmetric OIDC/JWT bearer tokens (`auth.enable_data_plane_jwt: true` + `auth.oidc_issuers` / `auth.oidc_jwks_url`) and RFC 7662 token introspection / OIDC UserInfo (`auth.introspection`).
- **Operator Session Cookie (`OperatorSession`)**: Browser sessions authenticated via `/auth/sso/{provider}/callback` receive an `HttpOnly` signed `goroute_session` cookie. State-changing cookie-authenticated requests must also echo `X-CSRF-Token`.

```http
Authorization: Bearer sk-gw-prod-7f9a2b8c4d1e
```

### 1.2 Inbound Request Routing, Impersonation & Delegation Headers
Callers can pass per-request routing hints via HTTP headers (equivalent to `goroute_extensions` fields in the request body) as well as enterprise impersonation/delegation headers:

| Header | Description | Example |
| :--- | :--- | :--- |
| `X-Gateway-Allowed-Region` | Restrict candidate deployments to a specific region | `us-east-1` |
| `X-Gateway-Session-Id` | Pin request session to a consistent deployment (`AffinityStore`) | `sess_01hf8a...` |
| `X-Gateway-Preferred-Deployment-Id` | Soft-prefer a specific deployment ID when healthy | `dep_primary_us` |
| `X-Gateway-Priority` | Request priority for `PriorityScheduler` queueing (higher = earlier dispatch) | `10` |
| `X-Gateway-Hedge-After-Ms` | Per-request stagger delay override for `fastest-response` hedged racing | `150` |
| `X-Gateway-Tags` | Comma-separated routing/guardrail tags (supports `&` / `!` expressions in filters) | `tier:fast, !experimental` |
| `X-Gateway-Tag-<Name>` | Inject an explicit tag key/value (`<Name>=<Value>`) | `env=prod` |
| `X-Gateway-Impersonate-User` | Impersonated end-user or member ID (requires impersonation-authorized service key/admin) | `usr_alice` |
| `X-Gateway-Impersonate-Email` | Impersonated user email within the same organization | `alice@acme.com` |
| `X-Gateway-Delegated-User-Id` | Delegated user ID attribution for service-account requests | `usr_bob` |
| `X-Gateway-Delegated-Team-Id` | Delegated team ID attribution for service-account requests | `team_core` |

### 1.3 Standard Gateway Response Headers
Every response from GoRoute AI Gateway includes tracing, attribution, and lifecycle metadata:

| Header | Description | Example |
| :--- | :--- | :--- |
| `X-Gateway-Request-Id` | Unique UUID assigned to the request lifecycle | `req_991efda4-7fab-4b03` |
| `X-Trace-Id` | W3C / OpenTelemetry Trace ID | `bad98e7deea34d7c810a963d9ed2c4ef` |
| `X-Gateway-Provider` | The winning upstream provider selected (also emitted before first SSE chunk) | `openai`, `anthropic`, `groq`, `openrouter`, `ollama` |
| `X-Gateway-Model` | The physical model that executed the inference (also emitted before first SSE chunk) | `gpt-4o-mini`, `claude-sonnet-4-20250514`, `llama-3.1-8b-instant` |
| `X-Gateway-Original-Model` | Original requested model name before budget-downgrade model fallback | `reasoning` |
| `X-Gateway-Cost-Micros` | Micro-dollar spend incurred ($10^{-6}\text{ USD}$) | `45` ($0.000045 USD) |
| `X-Gateway-Routing-Micros` | Gateway Stage 0–4 routing decision overhead in microseconds | `12` |
| `X-Gateway-Latency-Ms` | End-to-end request latency in milliseconds | `318` |
| `X-Gateway-Route-Reason` | Selection / step-down reason code from PreRouter or ReliabilityManager | `priority_tier_stepdown` |
| `X-Gateway-Fallback-Attempted` | Indicates whether an inter-group fallback executed | `true` or `false` |
| `X-Gateway-Budget-Fallback` | Indicates a soft/exceeded-budget model fallback took effect | `true` |
| `X-Gateway-Budget-Throttled` | Indicates probability-based soft budget throttling was evaluated/applied | `true` |
| `X-Gateway-Tier-Stepdowns` | Number of `Deployment.Priority` tier step-downs attempted | `1` |
| `X-Gateway-Stream-Continued` | Indicates whether mid-stream SSE continuation seamlessly stitched output | `true` or `false` |
| `X-Gateway-Cache` | Cache evaluation result | `HIT` or `MISS` |
| `X-Gateway-Cache-Type` | Cache match kind on hits | `exact` or `semantic` |
| `X-Gateway-Cache-Similarity` | Cosine similarity score on semantic cache hits (also accepted as a per-request threshold override header) | `0.9642` |
| `X-Gateway-Guardrail-Action` | Guardrail action applied during request/stream processing | `none`, `redact`, `block` |
| `X-Gateway-Pricing-Status` | Billing pricing verification status (`verified` vs `unverified`) | `verified` |
| `X-Gateway-Key-Deprecated` | Emitted as `true` when authenticating with a rotated key still inside its grace period | `true` |
| `X-Gateway-Key-Revoke-At` | RFC 3339 expiration timestamp of a deprecated key grace window | `2026-11-20T12:00:00Z` |
| `Retry-After` | Cooldown period sent on HTTP 429 rate limit | `45` (seconds) |

When CORS is configured (`server.cors_allowed_origins`), `Access-Control-Expose-Headers` exposes `X-Gateway-Request-Id`, `X-Gateway-Provider`, `X-Gateway-Model`, `X-Gateway-Cost-Micros`, `X-Gateway-Cache`, `X-Gateway-Cache-Type`, `X-Gateway-Cache-Similarity`, `X-Gateway-Guardrail-Action`, `X-Gateway-Pricing-Status`, `X-Gateway-Latency-Ms`, `X-Gateway-Route-Reason`, `X-Gateway-Fallback-Attempted`, `X-Gateway-Routing-Micros`, `X-Gateway-Stream-Continued`, `X-Gateway-Tier-Stepdowns`, `X-Gateway-Key-Deprecated`, `X-Gateway-Key-Revoke-At`, `X-Gateway-Budget-Throttled`, `X-Gateway-Budget-Fallback`, and `X-Gateway-Original-Model` to browser clients.

### 1.4 Operator OIDC Sessions & CLI SSO (`/auth/*`)
1. **Session Lifecycle**:
   - `POST /auth/logout` *(authenticated)*: Revokes the active session (`gw:auth:session:revoked:{jti}`), clears `goroute_session`, and returns `end_session_url` for OIDC RP-Initiated Logout when supported by the provider.
   - `GET /auth/me` *(authenticated)*: Returns current principal identity, role, organization/team scope, and CSRF token.
2. **Browser OIDC SSO**:
   - `GET /auth/sso/providers`: Lists configured OIDC SSO providers.
   - `GET /auth/sso/{provider}/login`: Generates PKCE `S256` + `state` + `nonce` and redirects (or returns JSON when `?format=json`).
   - `GET /auth/sso/{provider}/callback`: Validates `state`, `nonce`, asymmetric signature, `at_hash`, optional `/userinfo` `sub` match, email domain allowlist, and issuer binding `(org_id, oidc_issuer, oidc_subject)`, then mints a `goroute_session` cookie.
3. **CLI Device Login Flow**:
   - `POST /auth/cli/start`: Starts a CLI login session and returns `login_id` + verification URL.
   - `GET /auth/cli/poll/{login_id}`: Polls login status and retrieves a single-use CLI credential once completed.
   - `POST /auth/cli/complete/{login_id}` *(authenticated session + `X-CSRF-Token`)*: Approves the pending CLI login session.

### 1.5 SCIM 2.0 Identity Provisioning (`/scim/v2/*`)
Enterprise identity providers synchronize users and groups over bearer-authenticated SCIM 2.0 endpoints:
- **Users**: `GET /scim/v2/Users`, `POST /scim/v2/Users`, `GET /scim/v2/Users/{id}`, `PUT /scim/v2/Users/{id}`, `PATCH /scim/v2/Users/{id}`, `DELETE /scim/v2/Users/{id}`.
- **Groups (Teams & Memberships)**: `GET /scim/v2/Groups`, `POST /scim/v2/Groups`, `GET /scim/v2/Groups/{id}`, `PUT /scim/v2/Groups/{id}`, `PATCH /scim/v2/Groups/{id}`, `DELETE /scim/v2/Groups/{id}`. Group name and membership changes execute atomically inside one tenant-scoped PostgreSQL transaction, validating foreign-org user IDs cleanly.

---

## 2. OpenAI-Compatible Data Plane (`/v1/*`)

### 2.1 Chat Completions
`POST /v1/chat/completions`

Standardized endpoint supporting OpenAI, Anthropic Claude, Groq, and OpenRouter models in synchronous JSON or real-time Server-Sent Events (SSE) streaming mode.

Chat request bodies are limited to 10 MiB; larger requests return `413 request_body_too_large`. The default outbound client allows two minutes for upstream response headers, applies a two-minute total deadline to non-streaming calls, and cancels a response body after two minutes without upstream data. Streaming calls have no total upstream deadline while chunks continue to arrive. These provider timeouts are configurable under `providers`; the HTTP server's configured write timeout still bounds the client connection.

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
  "goroute_extensions": {
    "tags": ["prod", "tier:fast"],
    "allowed_region": "us-east-1",
    "session_id": "sess_01hf8a",
    "preferred_deployment_id": "dep_primary_us",
    "priority": 10,
    "hedge_after_ms": 150,
    "guardrails": [
      {"name": "strict-pii", "enabled": true}
    ]
  },
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
Optional `goroute_extensions.tags` activates tag-scoped `mode_rule` routing, bindings, and Stage 2 tag filtering (`&`/`!` boolean expressions). `allowed_region`, `session_id`, `preferred_deployment_id`, `priority`, and `hedge_after_ms` override region pinning, `AffinityStore` stickiness, `PriorityScheduler` queue priority, and `fastest-response` stagger intervals. Virtual model strings also support `auto`, `router/heuristic`, `router/semantic`, `router/quality`, `router/adaptive`, and comma-separated racing syntax (`"model-a,model-b"`). Meanwhile `goroute_extensions.guardrails` can opt into additional active named guardrails; request overrides can never disable `default_on` or admin-locked (`is_locked: true`) guardrails.

#### Synchronous Response (HTTP 200 OK)
```json
{
  "id": "chatcmpl-req_991efda4-7fab-4b03",
  "object": "chat.completion",
  "created": 1731081600,
  "model": "gpt-4o-mini",
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

data: {"id":"chatcmpl-req_1","object":"chat.completion.chunk","created":1731081600,"model":"gpt-4o-mini","choices":[{"index":0,"delta":{"role":"assistant","content":"The"},"finish_reason":null}]}

data: {"id":"chatcmpl-req_1","object":"chat.completion.chunk","created":1731081600,"model":"gpt-4o-mini","choices":[{"index":0,"delta":{"content":" capital"},"finish_reason":null}]}

data: {"id":"chatcmpl-req_1","object":"chat.completion.chunk","created":1731081600,"model":"gpt-4o-mini","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}

data: [DONE]
```

#### Extended Reasoning & Parameter Normalization
GoRoute transparently normalizes requests targeting frontier reasoning models:
- **Reasoning Effort**: When `reasoning_effort` (`"low"`, `"medium"`, `"high"`) is provided:
  - **OpenAI Reasoning (`o1`, `o3`, `o3-mini`)**: Converts `role: "system"` to `role: "developer"`, translates `max_tokens` to `max_completion_tokens`, and omits unsupported parameters (`temperature`, `top_p`).
  - **Anthropic Claude**: Enables extended thinking with token budgets (`1024`, `4096`, `16384`) and automatically omits `temperature` and `top_p` as mandated by Anthropic.
  - **OpenRouter**: Maps `reasoning_effort` to OpenRouter's `reasoning` parameter object (`openrouter_reasoning`).
  - **Ollama**: Forwards `reasoning_effort` to Ollama's `/v1/chat/completions` thinking controls and extracts `reasoning` / `reasoning_content` deltas and responses.
- **Anthropic Role Alternation on Tools**: When returning multiple parallel tool outputs (`role: "tool"`), GoRoute automatically consolidates consecutive tool results into a single `user` message with multiple `tool_result` content blocks to satisfy Anthropic's strict alternating turn protocol.

#### Upstream Error Handling & Safety Filters
When an upstream provider blocks or rejects a prompt, GoRoute maps upstream status codes and safety violations into standard OpenAI-compatible error payloads:
```json
{
  "error": {
    "message": "prompt blocked by safety filters",
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

Returns a 4-layer tenant-filtered inventory accessible to the caller's Virtual API Key, including tri-state capabilities and integer micro-dollar pricing metadata. Catalogue inclusion describes known metadata; it does not guarantee that the selected provider, operation, credentials, or account can call a model.

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
GoRoute supports direct model execution using `provider/model` notation (e.g. `openai/gpt-4o-mini`, `anthropic/claude-haiku-4-5-20251001`, `groq/llama-3.1-8b-instant`, `openrouter/openai/gpt-4o-mini`, `ollama/qwen2.5:0.5b`):
- **Layer 2 Provider Subscription Check**: The caller's organization must have an active subscription for the requested provider (if subscriptions are configured).
- **Layer 3 Model Policy Check**: The requested model must not be explicitly disabled by the organization's model availability policy.
- **Tenant Credential Isolation**: The organization must have an active credential for the target provider. Server environment variables are never leaked across tenant boundaries.
- **Dynamic Catalogue Provisioning**: If the model is not yet in the organization's database catalogue, GoRoute can import its metadata from the embedded OpenAPI-verified catalogue and provision a route when a matching provider adapter and tenant credential are available.
- **Fail-Closed Boundary**: If repository queries fail, or if the model is unconfigured/unauthorized, GoRoute fails closed and returns `HTTP 404 model_group_not_found` (explicit model requests never silently fall back to unrelated tenant model groups).

### 2.5 Content Moderation
`POST /v1/moderations`, `POST /moderations`

Evaluates text against safety categories using upstream moderation models (e.g. OpenAI `omni-moderation-latest`).

#### Request Schema
```json
{
  "model": "omni-moderation-latest",
  "input": ["I love coding with pure Go"]
}
```

#### Response (HTTP 200 OK)
```json
{
  "id": "modr-req_865bcf43",
  "model": "omni-moderation-latest",
  "results": [
    {
      "flagged": false,
      "categories": {
        "hate": false,
        "violence": false,
        "self-harm": false
      },
      "category_scores": {
        "hate": 0.00001,
        "violence": 0.00002,
        "self-harm": 0.00001
      }
    }
  ]
}
```

### 2.7 Legacy Text Completions
`POST /v1/completions`, `POST /completions`

OpenAI-compatible legacy prompt completion endpoint supporting both single string prompts and string arrays.

#### Request Schema
```json
{
  "model": "gpt-3.5-turbo-instruct",
  "prompt": "Write a haiku about Go concurrency",
  "max_tokens": 64,
  "temperature": 0.7
}
```

### 2.8 Anthropic Messages & Token Counting
`POST /v1/messages`, `POST /messages`, `POST /v1/messages/count_tokens`

Native Anthropic Messages ingress bridge. Translates Anthropic messages and tool definitions to the canonical gateway schema, dispatches through intelligent routing, and returns native Anthropic response payloads and Anthropic-formatted error envelopes (`{"type":"error","error":{"type":"...","message":"..."}}`).

#### Request Schema
```json
{
  "model": "claude-3-5-sonnet-20241022",
  "max_tokens": 1024,
  "system": "You are a helpful assistant.",
  "messages": [
    {"role": "user", "content": "Explain goroutines in 2 sentences."}
  ]
}
```

### 2.9 Fast Heuristic Tokenization
`POST /v1/tokenize`, `POST /tokenize`

In-gateway token count estimator (~4 characters per token average with whitespace/punctuation weighting). Returns instant token counts without upstream network requests or costs.

#### Request Schema
```json
{
  "model": "gpt-4o",
  "input": "GoRoute AI Gateway is ultra fast and reliable."
}
```

#### Response (HTTP 200 OK)
```json
{
  "count": 9,
  "model": "gpt-4o"
}
```

### 2.10 Audio Transcription & Speech Synthesis
- `POST /v1/audio/transcriptions` (STT Whisper)
- `POST /v1/audio/translations` (STT Translation to English)
- `POST /v1/audio/speech` (TTS Speech Synthesis)

Supports multipart file uploads spooled to disk for zero-memory retryability, streaming TTS audio responses on `/v1/audio/speech`, and micro-dollar FinOps billing based on integer duration seconds and character count.

#### Transcription Request (`multipart/form-data`)
```bash
curl -X POST http://localhost:8080/v1/audio/transcriptions \
  -H "Authorization: Bearer sk-gw-..." \
  -F "file=@speech.mp3" \
  -F "model=whisper-1" \
  -F "language=en"
```

#### Speech Request (`application/json`)
```bash
curl -X POST http://localhost:8080/v1/audio/speech \
  -H "Authorization: Bearer sk-gw-..." \
  -H "Content-Type: application/json" \
  -d '{
    "model": "tts-1",
    "input": "GoRoute AI Gateway deployed in production.",
    "voice": "alloy"
  }' --output speech.mp3
```

### 2.11 Image Generation, Edits & Variations
- `POST /v1/images/generations` (Image Generation)
- `POST /v1/images/edits` (Image Inpainting with mask)
- `POST /v1/images/variations` (Image Variations)

Supports DALL-E 2/3 and Imagen models, returning `url` or `b64_json` payloads with exact micro-dollar pricing matrices keyed to quality (`standard` vs `hd`) and dimensions (`1024x1024`, `1024x1792`).

### 2.12 Stateful Tenant File Assets
- `POST /v1/files` (Upload file)
- `GET /v1/files` (List tenant files)
- `GET /v1/files/{file_id}` (Retrieve file metadata)
- `GET /v1/files/{file_id}/content` (Download file stream)
- `DELETE /v1/files/{file_id}` (Delete file)

Files are stored securely on disk (`0700` directory mode, `0600` file mode) with automated streaming SHA-256 deduplication indexing, multi-tenant isolation, explicit multipart temporary-file cleanup, per-organization storage quotas (`server.max_file_storage_bytes_per_org`, returning `413 storage_quota_exceeded` when exceeded), and bounded upload concurrency (`server.max_concurrent_file_uploads`, returning `429 upload_concurrency_limit` when saturated).

### 2.13 Asynchronous Batch Processing
- `POST /v1/batches` (Create batch job)
- `GET /v1/batches` (List batch jobs)
- `GET /v1/batches/{batch_id}` (Inspect batch status & counts)
- `POST /v1/batches/{batch_id}/cancel` (Cancel running batch)

Processes JSONL line items asynchronously with per-item Virtual Key model-scope RBAC verification, reliable fallback execution, in-loop cancellation checks, and granular per-line FinOps spend tracking.

### 2.14 OpenAI Responses API
`POST /v1/responses`, `POST /responses`

Stateless translation bridge conforming to the OpenAI Responses API schema (`input`, `instructions`, `tools`, `extra_body`), routing through the gateway's 7-stage reliability pipeline and returning standard Responses objects. Unknown top-level parameters and `extra_body` fields are forwarded to compatible upstream providers without clobbering core request fields.

### 2.15 OpenAI Realtime WebSocket Protocol
`GET /v1/realtime`, `GET /realtime`, `GET /openai/v1/realtime`

Full-duplex bidirectional WebSocket session handler supporting real-time speech and text streaming over WebSockets. Authenticates via standard Bearer or `x-api-key` headers. Browser WebSocket clients can use `Sec-WebSocket-Protocol` (`openai-insecure-api-key.<key>`) or query parameters (`?api_key=` or `?token=`) on a valid WebSocket upgrade to a realtime route. Query and subprotocol credentials are ignored on ordinary HTTP routes. Prefer headers where the client supports them because URLs can be recorded by proxies and browser history.

### 2.16 Standalone Guardrail Evaluation
`POST /v1/guardrails/apply`

Evaluates a specific active named guardrail (`guardrail_name`) or the caller's effective hierarchical tenant guardrails against arbitrary `text`, `texts`, `messages`, `tools`, or `tool_calls` without dispatching upstream inference. Requires a valid Virtual API Key authorized for `/v1/guardrails/apply`.

#### Request Schema
```json
{
  "guardrail_name": "prod-pii-shield",
  "input_type": "request",
  "texts": ["Customer SSN 000-11-2222 email alice@example.com"],
  "tags": ["prod"],
  "model": "fast"
}
```
- `input_type`: `"request"` / `"input"` (`pre_call`) or `"response"` / `"output"` (`post_call`).
- Returns `blocked`, `decision` (`"allow"`, `"block"`, `"flag"`, `"modify"`), `action`, `violations`, `texts` / `modified_texts`, `modified_messages`, `modified_tool_calls`, `applied_guardrails`, `usage_units`, and `latency_ms`.

---

## 3. Model Context Protocol (MCP) APIs

GoRoute AI Gateway exposes a spec-generated, UI-selectable MCP engine supporting all 5 official releases (**`2024-11-05`**, **`2025-03-26`**, **`2025-06-18`**, **`2025-11-25`**, and **`2026-07-28`** default, including `server/discover` and `subscriptions/listen`), switchable at runtime via `PUT /admin/v1/mcp/spec`.

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

For ultra-low latency inter-agent communication, the Gateway exposes a native gRPC server implementing the official Linux Foundation A2A Protobuf contract. Configure `server.grpc_port` (default `0`, disabled; or set `GATEWAY_GRPC_PORT`) in YAML/env to enable the gRPC listener (for example `9090`).

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

Admin APIs authenticate via `Authorization: Bearer <MASTER_ADMIN_KEY>`, an organization/team-scoped admin Virtual API Key (subject to RBAC), an admin JWT/OIDC token, or an active operator `goroute_session` cookie (cookie-authenticated mutations must include `X-CSRF-Token`).

### 5.1 Organization Management
- `POST /admin/v1/organizations`: Create a new multi-tenant organization.
  ```json
  { "name": "acme-corp", "max_budget_micros": 500000000 }
  ```
- `GET /admin/v1/organizations`: List all registered organizations (`org_admin`/`org_viewer` see only their own organization).
  ```bash
  curl http://localhost:8080/admin/v1/organizations -H "Authorization: Bearer $MASTER_ADMIN_KEY"
  ```

### 5.2 Teams, Memberships & Projects
- `POST /admin/v1/teams`, `GET /admin/v1/teams?org_id={orgID}`, `PUT /admin/v1/teams/{teamID}`, `DELETE /admin/v1/teams/{teamID}`: Create, list, update, and delete teams (including `team_member_permissions`, `default_member_allowed_models`, `enforce_guaranteed_throughput`, per-team `max_budget_micros`, `allowed_models`, RPM/TPM limits, and `budget_reset_period`).
  ```json
  {
    "org_id": "org_default",
    "name": "core-platform",
    "max_budget_micros": 100000000,
    "allowed_models": ["fast", "reasoning", "gpt-4o-mini"]
  }
  ```
- `POST /admin/v1/teams/{teamID}/members`, `POST /admin/v1/teams/{teamID}/members/bulk`, `GET /admin/v1/teams/{teamID}/members`, `POST /admin/v1/teams/{teamID}/members/{userID}/reset-spend`, `DELETE /admin/v1/teams/{teamID}/members/{userID}`: Manage explicit multi-team user memberships (with transactional `remove_user_ids` support on `/members/bulk`), per-team budgets/roles (`team_memberships`), and spend resets.
- `POST /admin/v1/projects`, `GET /admin/v1/projects?org_id={orgID}`, `PUT /admin/v1/projects/{projectID}`, `DELETE /admin/v1/projects/{projectID}`: Provision project-scoped containers inside organizations/teams (including `enforce_project_model_quota`, budgets, and allowlists) for granular key and budget attribution.

### 5.3 User Management & Federated Issuer Binding
- `POST /admin/v1/users`, `GET /admin/v1/users?org_id={orgID}`, `PUT /admin/v1/users/{userID}`, `DELETE /admin/v1/users/{userID}`: Register, inspect, update, and remove organization users with enterprise RBAC roles (`platform_admin`, `org_admin`, `org_viewer`, `team_admin`, `developer`, `service_account`, `viewer`), per-user budgets/rate limits, and explicit OIDC identity binding `(org_id, oidc_issuer, oidc_subject)`.
  ```json
  {
    "org_id": "org_default",
    "team_id": "team_core",
    "email": "engineer@acme.com",
    "role": "developer",
    "oidc_issuer": "https://idp.example.com/oauth2/default",
    "oidc_subject": "00u1abc2def3"
  }
  ```

### 5.4 Virtual Key Provisioning, Lifecycle, Temp Budgets, Self-Service & Access Rules
- `POST /admin/v1/keys`: Issue a scoped Virtual API Key (`sk-gw-...`) with `key_type` presets (`default`, `llm_api`, `management`, `read_only`, `service_account`), budget caps, RPM/TPM/concurrency limits, expiration, soft budget alerts, budget fallback model, auto-rotation intervals, and model/MCP/A2A allowlists.
  ```json
  {
    "org_id": "org_default",
    "team_id": "team_core",
    "name": "data-pipeline-key",
    "role": "service_account",
    "max_budget_micros": 50000000,
    "rpm_limit": 1000,
    "tpm_limit": 500000,
    "allowed_models": ["fast", "reasoning"],
    "allowed_deployments": ["dep_eu_1"],
    "allowed_routing_tags": ["eu-gdpr"],
    "allowed_mcp_servers": ["github-tools"],
    "allowed_mcp_tools": ["github-tools:get_*"],
    "allowed_mcp_toolsets": ["github-readonly"],
    "allowed_a2a_agents": ["analyst-agent"]
  }
  ```
- `GET /admin/v1/keys?org_id={orgID}`, `GET /admin/v1/keys/{keyID}`, `PUT /admin/v1/keys/{keyID}`: List (`team_admin` restricted to administered teams), inspect, or update mutable virtual key limits, models, deployments, 3-state MCP/A2A allowlists (`null` = Inherit vs `[]` = Deny All), and metadata (invalidating both primary and active deprecated grace hashes across L1/L2 caches).
- `POST /admin/v1/keys/{keyID}/rotate`: Manually rotate a virtual key immediately or with a dual-active grace window (`grace_period_seconds`, marking previous hash in `virtual_key_deprecated_hashes` and emitting `X-Gateway-Key-Deprecated` / `X-Gateway-Key-Revoke-At` headers during grace).
- `POST /admin/v1/keys/{keyID}/temp-budget`: Grant an expiring temporary budget increase (`temp_budget_increase_micros` / `increase_micros` plus `temp_budget_expires_at` / `expires_at` / `ttl_seconds`) enforced immediately at quota admission.
- `POST /admin/v1/keys/{keyID}/block`, `POST /admin/v1/keys/{keyID}/unblock`, `POST /admin/v1/keys/{keyID}/reset-spend`, `POST /admin/v1/keys/bulk-update`: Temporarily block/unblock keys, reset spend, or atomically update up to `250` keys per batch.
- `POST /admin/v1/keys/{keyID}/revoke` or `DELETE /admin/v1/keys/{keyID}`: Instantly revokes a key and purges cached primary & deprecated grace permissions from L1 memory and Redis via Pub/Sub.
- `POST /admin/v1/jwt-mappings`, `GET /admin/v1/jwt-mappings`, `DELETE /admin/v1/jwt-mappings/{id}`: Configure explicit tenant-scoped JWT claim-to-Virtual-Key (`(org_id, issuer, claim_name, claim_value) -> virtual_key_id`) bindings.
- `POST /admin/v1/access-group-rules`, `GET /admin/v1/access-group-rules`, `DELETE /admin/v1/access-group-rules/{id}`: Configure ABAC claim/attribute dynamic access rules (`allowed_models`, `allowed_mcp_servers`, `allowed_mcp_tools`, `allowed_a2a_agents`, `access_group_id`, `operator`, `priority`).
- `POST /admin/v1/access-groups` (alias `/admin/v1/model-access-groups`): Manage Unified Access Groups bundling models, MCP servers/tools, A2A agents, and shared budgets. See [AUTHORIZATION_AND_ACCESS_CONTROL.md](./AUTHORIZATION_AND_ACCESS_CONTROL.md) for the complete 19-capability RBAC, tri-state allowlist, external authorizer, and audit event reference.
- **Data Plane Self-Inspection & Developer Self-Service**: `GET /v1/key/info` inspects the caller's active key identity, effective limits, and spend; `GET /v1/self/keys`, `POST /v1/self/keys`, `POST /v1/self/keys/{keyID}/rotate`, and `DELETE /v1/self/keys/{keyID}` allow scoped self-service governed by `team_member_permissions` and `self_serve_budget_policy`.

### 5.5 Upstream Provider Credentials Vault
- `POST /admin/v1/credentials`: Securely stores provider credentials encrypted with AES-256-GCM.
  ```json
  {
    "provider": "openai",
    "api_key": "sk-proj-...",
    "base_url": "https://api.openai.com/v1"
  }
  ```
- `GET /admin/v1/credentials`: Lists credentials (API keys are redacted as `sk-proj-***`).
- `POST /admin/v1/credentials/validate`: Preflight validator that tests raw credentials against the target provider API *before* saving them.
  ```bash
  curl -X POST http://localhost:8080/admin/v1/credentials/validate \
    -H "Authorization: Bearer $MASTER_ADMIN_KEY" \
    -H "Content-Type: application/json" \
    -d '{ "provider": "openai", "api_key": "sk-proj-...", "base_url": "https://api.openai.com/v1" }'
  ```
  Returns `{ "valid": true, "validation_status": "success", "discovered_models": 18, "latency_ms": 142 }`.
- `POST /admin/v1/credentials/{credID}/rotate`: Atomically replaces an existing credential's key with zero downtime.
- `POST /admin/v1/credentials/{credID}/validate`: Validates an already-persisted vault credential.

### 5.6 Model Groups & Deployment Management
- `POST /admin/v1/model-groups`: Creates a virtual model group (alias) with routing strategy (`weighted-shuffle`, `round-robin`, `least-busy`, `latency-based`, `fastest-response`, `usage-based-headroom`, `lowest-cost`), specialized fallbacks, retry policy, and adaptive cooldown policy.
  ```json
  {
    "alias": "fast",
    "routing_strategy": "latency-based",
    "fallback_group_ids": ["reasoning"],
    "context_window_fallbacks": [{"target": "long-context", "overrides": {"max_tokens": 4096}}],
    "content_policy_fallbacks": [{"target": "safe-fallback"}],
    "fallback_targets": [{"target": "backup-claude"}],
    "retry_policy": {"rate_limit_retries": 3, "server_error_retries": 2},
    "cooldown_policy": {"failure_rate_threshold": 0.5, "min_requests_per_minute": 10}
  }
  ```
- `GET /admin/v1/model-groups`: Lists all configured model groups.
- `POST /admin/v1/deployments`: Adds a model deployment to a group with priority tier, weight, region, tags, rate limits, and optional deployment spend budget.
  ```json
  {
    "model_group_id": "mg_fast",
    "global_model_id": "groq/llama-3.1-8b-instant",
    "credential_id": "cred_groq",
    "priority": 0,
    "weight": 80,
    "region": "us-east",
    "tags": ["tier:fast", "low-cost"],
    "max_budget_micros": 50000000,
    "budget_reset_period": "daily",
    "rpm_capacity": 1000,
    "tpm_capacity": 1000000
  }
  ```
- `GET /admin/v1/deployments?model_group_id={groupID}`: Lists deployments, optionally filtered by model group. Without the query parameter, returns deployments across all groups; statuses are not filtered.
- `POST /admin/v1/deployments/{depID}/ptu-shares`, `GET /admin/v1/deployments/{depID}/ptu-shares`, `DELETE /admin/v1/deployments/{depID}/ptu-shares/{teamID}`: Manage Provisioned Throughput Unit (PTU) reserved `reserved_rpm` and `reserved_tpm` allocations per team with elastic saturation borrowing.
- `POST /admin/v1/priority-classes`, `GET /admin/v1/priority-classes`: Configure team/key QoS scheduling weights (`weight`, `priority_rank`, `max_borrow_multiple`).

### 5.7 Model Catalogue & Pricing Provenance
- `GET /admin/v1/catalogue?provider={provider}&search={query}`: Queries the global model catalogue.
- `POST /admin/v1/catalogue/sync`: Polls active upstream provider credentials for new models.
- `POST /admin/v1/catalogue/import?provider={provider}`: Imports metadata from the embedded OpenAPI-verified catalogue dataset.
- `POST /admin/v1/catalogue/pricing`: Updates model pricing rates and promotes pricing status to `"verified"`.
  ```json
  {
    "global_model_id": "openai/gpt-4o-mini",
    "input_cost_micros_per_1m": 150000,
    "output_cost_micros_per_1m": 600000,
    "cached_input_cost_micros_per_1m": 37500,
    "reasoning_cost_micros_per_1m": 600000,
    "pricing_status": "verified",
    "pricing_provenance_source": "vendor-contract-2026",
    "pricing_effective_date": "2026-11-01"
  }
  ```
- `GET /admin/v1/catalogue/pricing?global_model_id={modelID}`: Retrieves immutable pricing revision audit history.

### 5.8 Organization Subscriptions & Model Policies
- `GET /admin/v1/organizations/{orgID}/subscriptions`: Lists Layer 2 provider subscription statuses.
- `POST /admin/v1/organizations/{orgID}/subscriptions`: Enables or disables an upstream provider for an organization.
- `GET /admin/v1/organizations/{orgID}/models`: Lists Layer 3 model policies and overrides.
- `POST /admin/v1/organizations/{orgID}/models`: Configures model access and token overrides for an organization.

### 5.9 Security Guardrails, Registry, Tool Policies & Simulator
- **Org Baseline Policy (`guardrail_policies`):**
  - `GET /admin/v1/organizations/{orgID}/guardrails`: Retrieves active baseline guardrail policies (prompt injection, PII, secrets, blocked keywords, output redaction, `mode`, `scan_all_roles`, plus PostgreSQL-persisted toxicity fields: `enable_toxicity_filter`, `toxicity_action`, `toxicity_threshold`, `enabled_content_categories`, `content_exceptions`).
  - `POST /admin/v1/organizations/{orgID}/guardrails`: Configures or updates the organization's baseline policy.
- **Named Guardrails & Provider Registry (`guardrail_definitions`):**
  - `POST /admin/v1/organizations/{orgID}/guardrail-definitions`: Creates a named guardrail backed by any of the 15 built-in drivers (`local_content_filter`, `custom_code`, `llm_as_a_judge`, `decision_model`, `openai_moderation`, `presidio`, `lakera_v2`, `guardrails_ai`, `pangea`, `generic_http`, `tool_permission`, `tool_policy`, `block_code_execution`, `mcp_security`, `mcp_end_user_permission`) with Vault-encrypted secrets, `event_hooks`, `stream_scope`, `mode_rule`, and load-balancing `weight`.
  - `GET /admin/v1/organizations/{orgID}/guardrail-definitions`: Lists guardrail definitions (optional query filters: `status`, `name`; secrets remain redacted).
  - `GET /admin/v1/guardrail-definitions/{guardrailID}`, `PUT /admin/v1/guardrail-definitions/{guardrailID}`, `PATCH /admin/v1/guardrail-definitions/{guardrailID}`, `DELETE /admin/v1/guardrail-definitions/{guardrailID}`: Inspects, replaces, patches, or deletes a definition.
  - `POST /admin/v1/guardrail-definitions/{guardrailID}/status`: Transitions approval status (`active`, `pending_review`, `rejected`).
- **Hierarchical Scope Bindings (`guardrail_bindings`):**
  - `POST /admin/v1/guardrail-bindings`: Scopes a named guardrail to a `team_id`, `virtual_key_id`, `end_user_id`, `model_group_id`, and/or `tag` with optional `param_overrides` and anti-bypass `is_locked` enforcement.
  - `GET /admin/v1/organizations/{orgID}/guardrail-bindings`: Lists bindings for an organization.
  - `DELETE /admin/v1/guardrail-bindings/{bindingID}`: Removes a binding.
- **Tool Trust Policies (`tool_policies`):**
  - `POST /admin/v1/organizations/{orgID}/tool-policies`: Creates or updates cross-turn tool trust rules (`input_policy`: `"blocked" | "untrusted" | "trusted"`, `output_policy`: `"untrusted" | "trusted"`) scoped per org, team, or virtual key.
  - `GET /admin/v1/organizations/{orgID}/tool-policies`: Lists tool trust policies.
  - `DELETE /admin/v1/organizations/{orgID}/tool-policies/{policyID}`: Deletes a tool trust policy.
- **Guardrail Simulator & Usage Telemetry:**
  - `POST /admin/v1/organizations/{orgID}/guardrails/simulate`: Stateless pipeline evaluator supporting both baseline draft policies and named definitions across `prompt` / `texts` / `messages` / `tools` / `tool_calls`, `direction` (`"input"` or `"output"`), `tags`, and simulated `stream_chunk_size` windowing without modifying records or incurring upstream LLM token costs.
  ```bash
  curl -X POST http://localhost:8080/admin/v1/organizations/org_default/guardrails/simulate \
    -H "Authorization: Bearer $MASTER_ADMIN_KEY" \
    -H "Content-Type: application/json" \
    -d '{
      "prompt": "Here is my secret sk-1234567890123456 and SSN 000-11-2222",
      "policy": {
        "enable_secret_detection": true,
        "secret_action": "redact",
        "enable_pii_detection": true,
        "pii_action": "redact"
      }
    }'
  ```
  - `GET /admin/v1/organizations/{orgID}/guardrail-usage`: Returns daily guardrail metrics, top triggered guardrails, usage units, and integer micro-dollar (`cost_micros`) attribution rollups (optional filters: `start_date`, `end_date`, `guardrail_id`, `team_id`, `virtual_key_id`, `top_limit`).

### 5.10 Quotas, Multi-Window Budgets, PTU Sharing, Config, Security & Audit Ledgers
- `PUT /admin/v1/quotas`, `GET /admin/v1/quotas`, `DELETE /admin/v1/quotas/{policyID}`: Configure multi-dimensional per-model and scope quota policies (`scope_type`: `org`, `team`, `team_member`, `project`, `user`, `key` — alias `virtual_key` also accepted, `model_per_key` — alias `model_per_virtual_key`, `end_user`, `tag`, `model_access_group`, `agent_session`; `model_pattern`, `rpm_limit`, `tpm_limit`, `itpm_limit`, `otpm_limit`, `tpd_limit`, `max_concurrent`, `max_budget_micros`, `max_iterations`).
- `PUT /admin/v1/budget-windows`, `GET /admin/v1/budget-windows`: Configure multi-window budgets (`hourly`, `daily`, `weekly`, `monthly`, `rolling_24h`, `never`) evaluated simultaneously during atomic descriptor admission (`rolling_24h` expires each settled spend charge independently 24 hours after its spend timestamp and recovers from PostgreSQL `spend_logs` on cold Redis state).
- `POST|PUT /admin/v1/end-users`, `GET /admin/v1/end-users`, `GET /admin/v1/end-users/{id}`, `DELETE /admin/v1/end-users/{id}`: Manage persisted end-user budgets, RPM/TPM/TPD limits, and aliases.
- `POST|PUT /admin/v1/tags`, `GET /admin/v1/tags`, `GET /admin/v1/tags/{id}`, `DELETE /admin/v1/tags/{id}`: Manage persisted tag budgets and rate-limit policies matched on `X-Gateway-Tags` / request tags.
- `POST|PUT /admin/v1/model-access-groups`, `GET /admin/v1/model-access-groups`, `GET /admin/v1/model-access-groups/{id}`, `DELETE /admin/v1/model-access-groups/{id}`, plus `POST /admin/v1/model-access-groups/{id}/members`, `GET /admin/v1/model-access-groups/{id}/members`, `DELETE /admin/v1/model-access-groups/{id}/members/{memberID}`: Group model aliases and deployments into named quota/budget policies.
- `POST /admin/v1/deployments/{depID}/ptu-shares`, `GET /admin/v1/deployments/{depID}/ptu-shares`, `DELETE /admin/v1/deployments/{depID}/ptu-shares/{teamID}`, `POST /admin/v1/priority-classes`: Configure PTU capacity shares and weighted priority classes.
- `GET /admin/v1/spend/summary?org_id={orgID}&team_id={teamID}`: Aggregated real-time spend summary in integer micro-dollars. `unpriced_requests` and `unpriced_tokens` identify usage whose price is unknown or unrecorded and is not represented by the cost total.
- `GET /admin/v1/spend/logs?org_id={orgID}&limit={limit}&offset={offset}`: Paginated raw spend ledger records including prompt, completion, cached, reasoning tokens, and modality units.
- `GET /admin/v1/audit/logs?org_id={orgID}&limit={limit}`: Immutable governance audit trail of administrative changes (recording redacted `before_value`/`after_value` JSON snapshots across control-plane mutations).
- `GET /admin/v1/config`: Returns sanitized runtime configuration summary (secrets redacted) for the Operator Console.
- `POST /admin/v1/security/rotate-kek`: Transactionally re-wraps encrypted DEKs (`provider_credentials`, `mcp_servers`, `a2a_agents`, `guardrail_definitions`) under a new Master KEK (`platform_admin` only) and emits `"vault_kek_rotated"` peer-pod restart alerts without broadcasting secret material over Redis.

### 5.11 Health Probing, Telemetry & Cache Invalidation
- `GET /admin/v1/health/deployments`: Health state machine status (`CLOSED`, `HALF_OPEN`, `OPEN`), failure counts, and latency EWMA for all deployments.
- `POST /admin/v1/health/probe`: Triggers an immediate synthetic health probe across all configured deployments.
- `GET /admin/v1/observability/metrics`: Real-time JSON telemetry snapshot (P50, P95, P99 latencies, authoritative response cache metrics including `cache_enabled`, `cache_type`, `cache_status`, `cache_hits`, `cache_misses`, `cache_semantic_hits`, `cache_errors`, `cache_entries`, `cache_evictions`, `cache_hit_rate`, and route counters).
- `POST /admin/v1/cache/invalidate`: Purges cached responses from the active cache backend (`local` LRU with multi-replica Redis Pub/Sub broadcast, `redis` KV via batched `MGET`+`UNLINK`, or `redis-semantic` RediSearch vector documents) using global, organization, model/alias, or strict `(org_id AND model)` semantics.
  ```json
  { "org_id": "org_default", "model": "fast" }
  ```

### 5.12 MCP & A2A Administration
- `GET /admin/v1/mcp/spec`: Returns the active Gateway MCP specification, `strict_schema_validation` flag, and metadata for all 5 code-generated releases.
- `PUT /admin/v1/mcp/spec`: Hot-switches the active Gateway MCP specification (`protocol_version`, `strict_schema_validation`), persists to `mcp_runtime_settings`, and broadcasts invalidation across cluster pods.
- `POST /admin/v1/mcp/servers`: Registers an upstream MCP server endpoint (validates `protocol_version` against supported official releases).
- `GET /admin/v1/mcp/servers`: Lists registered MCP servers.
- `PUT /admin/v1/mcp/servers/{serverID}`: Updates an existing upstream MCP server's `protocol_version`, `transport_type`, `is_active`, or connection settings.
- `POST /admin/v1/mcp/servers/{serverID}/sync`: Synchronizes tools, runs anti-poisoning scans, and pins SHA-256 tool digests.
- `GET /admin/v1/mcp/tools`: Lists synchronized MCP tools scoped to the operator's organization (used by the Operator Web UI).
- `POST /admin/v1/mcp/toolsets`: Groups tools into curated, permissioned toolsets.
- `GET /admin/v1/mcp/toolsets`: Lists curated toolsets.
- `POST /admin/v1/mcp/credentials`: Stores or updates per-user BYOK credentials for an MCP server.
- `POST /admin/v1/a2a/agents`: Registers an upstream Agent-to-Agent endpoint and card.
- `GET /admin/v1/a2a/agents`: Lists registered A2A agents.
- `GET /admin/v1/a2a/agents/{id}`: Retrieves details for a registered A2A agent.
- `POST /admin/v1/a2a/agents/{id}/kill-switch`: Toggles emergency kill-switch (`{ "killed": true }`), instantly returning `HTTP 503 agent_killed` across all cluster pods.
- `POST /admin/v1/a2a/push-configs`: Configures webhook push notifications for A2A tasks.

---

## 6. Observability & Telemetry APIs

### 6.1 OpenTelemetry (OTLP/HTTP) Export (`v0.1` LTS)
GoRoute `v0.1` LTS supports **pure OpenTelemetry OTLP/HTTP only** for telemetry export (`otel.enabled: true`), emitting **Traces**, **Metrics**, and opt-in post-scrub **Logs** with zero vendor SDK lock-in. No non-OTLP scrape endpoints (such as Prometheus `/metrics`) or vendor-specific exporters are built into the gateway; external observability platforms integrate on top of GoRoute's standard OTLP/HTTP output directly or through an OpenTelemetry Collector.

Standardized OTLP metric instruments follow pure dot-separated OpenTelemetry GenAI Semantic Conventions (`gen_ai.*`) and gateway telemetry (`gateway.*`):
- **GenAI Client & Streaming Histograms**: `gen_ai.client.operation.duration` (`s`), `gen_ai.client.token.usage` (`{token}`, `gen_ai.token.type=input|output`), `gen_ai.server.time_to_first_token` (`s`).
- **Gateway Inference, Routing & Reliability**: `gateway.requests`, `gateway.errors`, `gateway.request.duration`, `gateway.provider.spend`, `gateway.streams`, `gateway.stream.errors`, `gateway.stream.duration`, `gateway.stream.ttft`, `gateway.routing.overhead`, `gateway.routing.fallbacks`, `gateway.routing.retries`, `gateway.routing.signal_degraded`.
- **Caching, Guardrails & Agentic Protocols**: `gateway.cache.hits`, `gateway.cache.misses`, `gateway.cache.semantic_hits`, `gateway.cache.errors`, `gateway.cache.entries`, `gateway.cache.evictions`, `gateway.guardrail.evaluations`, `gateway.guardrail.blocks`, `gateway.guardrail.errors`, `gateway.guardrail.duration`, `gateway.mcp.requests`, `gateway.a2a.requests`.
- **Platform Health, Outbox, SIEM & Runtime**: `gateway.redis.circuit_breaker.state` (`0=closed`, `1=half_open`, `2=open`), `gateway.deployment.healthy`, `gateway.finops.outbox.pending`, `gateway.finops.outbox.dead_letter`, `gateway.finops.outbox.backpressure`, `gateway.audit.siem.delivered`, `gateway.audit.siem.failed`, `gateway.audit.siem.dropped`, `gateway.go.memory.heap_alloc`, `gateway.go.memory.heap_inuse`, `gateway.go.gc.cycles`, `gateway.go.gc.pause`, `gateway.model_catalog.size`.

### 6.2 Administrative Metrics Snapshot (Operator Web UI)
`GET /admin/v1/observability/metrics`

Requires Admin Control Plane authentication (`Authorization: Bearer` or operator session). Returns a real-time JSON telemetry snapshot powering the embedded Operator Web UI (`OverviewView`): sliding-window P50/P95/P99 latencies, authoritative response cache metrics (`cache_enabled`, `cache_type`, `cache_status`, `cache_hits`, `cache_misses`, `cache_semantic_hits`, `cache_errors`, `cache_entries`, `cache_evictions`, `cache_hit_rate`), per-provider stats, `otel_enabled`, `otel_signals`, `finops_outbox_pending`, `audit_siem_delivered`, and `redis_cb_state`.

### 6.3 Health & Readiness Probes
GoRoute exposes production-grade Kubernetes health check probes:

#### Liveness Probe
`GET /healthz`

Fast, in-memory process health check returning `HTTP 200 {"status":"ok"}`. Indicates whether the gateway HTTP server is alive and receiving traffic.

#### Deep Readiness Probe
`GET /readyz`

Performs active, deep dependency health verification. Executes a live `Ping(ctx)` against the primary storage engine (PostgreSQL or Memory) and primary Redis fabric; when a dedicated response-cache Redis (`cache.redis_addr` / `cache.redis_addrs`) is configured, it also checks cache connectivity fail-open without failing pod readiness:
- **HTTP 200 OK**: Primary storage repository and primary Redis respond healthy within timeout (`cache_status` is `"ok"` or `"degraded"` when a dedicated cache Redis is configured).
  ```json
  {"status":"ready","cache_status":"ok"}
  ```
- **HTTP 503 Service Unavailable**: Primary storage or primary Redis failed to respond.
  ```json
  {"status":"unready","error":"storage unavailable: connection refused"}
  ```

---

## 7. Enterprise Upstream Authentication Strategies

GoRoute AI Gateway strictly decouples caller credentials (incoming Virtual API Keys) from outbound upstream credentials. Configure outbound authentication strategies in provider or server configuration:

### 7.1 AWS Signature Version 4 (SigV4)
Signs outbound requests to AWS API Gateway or SigV4-protected HTTPS endpoints (such as custom MCP or guardrail webhooks) using AWS SDK v2.
```yaml
upstream_auth:
  type: "aws_sigv4"
  aws_sigv4:
    region: "us-east-1"
    service: "execute-api"
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

---

## 8. Embedded Operator Web UI & Static Serving (`/ui/*`)

GoRoute AI Gateway embeds a production-grade single-page application (SPA) directly into the Go executable, allowing operators, engineers, and administrators to interact with all gateway capabilities without deploying a separate web server.

### 8.1 Base Web Routes
- `GET /ui`: 301 Permanent Redirect to `/ui/` (enforces trailing slash for accurate relative asset resolution).
- `GET /ui/`: Serves `index.html` with header `Cache-Control: no-cache`.
- `GET /ui/assets/{filename}`: Serves hashed static bundles (JavaScript, CSS, fonts) with header `Cache-Control: public, max-age=31536000, immutable`. Directory paths (e.g. `/ui/assets/`) return `404 Not Found`.
- `GET /ui/*`: Client-Side History API fallback. Any unmapped subpath under `/ui/` (e.g. `/ui/playground`, `/ui/organizations`, `/ui/models`, `/ui/keys`, `/ui/finops`, `/ui/guardrails`, `/ui/credentials`, `/ui/agentic`) serves `index.html` with status `200 OK` for SPA client-side routing (`window.location.pathname` + `history.pushState`).

### 8.2 Client Authentication
The Operator UI (`LoginView`) supports two authentication mechanisms:
1. **OIDC SSO (Primary)**: Discovers configured `type: "oidc"` providers via `GET /auth/sso/providers` and completes Authorization Code + PKCE (`S256`) login via `/auth/sso/{provider}/login` and `/auth/sso/{provider}/callback`, storing an `HttpOnly` `goroute_session` cookie and sending `X-CSRF-Token` on mutations (and RP-Initiated Logout `end_session_url` on sign-out).
2. **Break-Glass Key (Secondary)**: Enter the Master Admin Key configured by `auth.master_admin_key` (`GATEWAY_MASTER_ADMIN_KEY`) for emergency/CLI access. The UI probes `GET /admin/v1/organizations` with `Authorization: Bearer <key>` and clears invalid credentials on `401 Unauthorized` or error.

### 8.3 Supported Frontend Views
| In-app view | Component | Core Functionality |
| :--- | :--- | :--- |
| Sign In | `LoginView` | OIDC SSO provider selector and secondary Break-Glass Master Admin Key unlock tab. |
| Sidebar: Overview | `OverviewView` | Gateway health, latency, request, model, and error summaries. |
| Sidebar: Playground | `PlaygroundView` | Streaming chat playground with cost & guardrail telemetry and escaped code export. |
| Sidebar: Orgs & Teams | `OrganizationsView` (`ProjectsTab`, `AccessGroupsTab`, `JWTMappingsTab`) | Organizations, teams & member permissions, projects, users, unified access groups & dynamic rules, JWT key mappings, micro-dollar budgets, provider subscriptions, and org model policies. |
| Sidebar: Models & Routing | `ModelsView` | Model catalogue (context window, capabilities, pricing), model groups, deployments, PTU shares, and priority classes. |
| Sidebar: Virtual Keys | `KeysView` + `TempBudgetModal` | Virtual key creation (project/team/user scope, `allowed_deployments`, `allowed_mcp_tools`/`toolsets`, `can_impersonate`, session/batch/MCP limits, soft/hard budgets), rotation, temporary budget increases, and revocation. |
| Sidebar: FinOps & Spend | `FinOpsView` + `QuotasTab` | Spend summaries (by provider, model, team, virtual key), spend logs, filtered cursor-paginated audit trail with `before_value`/`after_value` JSON Diff Viewer, multi-window budgets, end-users, tags, and model-access-group quotas. |
| Sidebar: Guardrails | `GuardrailsView` (`RegistryTab`, `ToolPoliciesTab`, `SimulatorUsageTab`) | Guardrail policy configuration, 15-driver registry & bindings, tool trust policies, stateless simulation, and usage rollups. |
| Sidebar: Credentials Vault | `CredentialsView` | Provider credentials, preflight validation, and key rotation. |
| Sidebar: Agentic Hub | `AgenticView` | MCP servers, toolsets, synchronized tools, and A2A agent management. |
| Sidebar: Configuration | `ConfigView` | Read-only sanitized runtime configuration inspection (`/admin/v1/config`) and `platform_admin` Master KEK rotation (`POST /admin/v1/security/rotate-kek`). |


## 9. Provider & Modality Compatibility Matrix

GoRoute separates **operation-level adapter support** (`OperationSupportChecker`), **model-level operation/capability support** (`GlobalModel.SupportsOperation` and `CapabilityState`), and **pricing trust status** (`PricingStatusVerified` / `PricingStatusCustom` vs `PricingStatusUnknown` / `PricingStatusUnrecorded`). `ReliabilityManager` enforces both adapter-level `OperationSupportChecker` and model-level `SupportsOperation` across all inference dispatch paths.

| Provider | Specification | Supported Operations | Notes |
| :--- | :--- | :--- | :--- |
| **`openai`** | `docs/openapi/openai.openapi.yaml` | Chat, Streaming, Completions, Embeddings, Moderation, Images, Audio (STT/TTS), Files, Batches, Responses, Realtime | Native canonical adapter using generated `providers.OpenAI*` DTOs; reasoning models (`o1`/`o3`/`o4`/`gpt-5`) map `system` -> `developer` and `max_tokens` -> `max_completion_tokens`. |
| **`anthropic`** | `docs/openapi/anthropic.openapi.yaml` | Chat (`Messages` & OpenAI bridge), Streaming, Tools, Vision/Documents, Token Counting (`/v1/messages/count_tokens`), Batches | Native adapter using generated `providers.Anthropic*` DTOs; supports adaptive thinking, prompt caching (`cache_control`), tool-name sanitization, and structured `output_config`. |
| **`groq`** | `docs/openapi/groq.openapi.yaml` | Chat, Streaming, Tools, Structured Outputs, Completions, Audio (STT/TTS), `ListModels` | Dedicated OpenAPI-backed adapter in `internal/adapter/groq`; strips unsupported params (`logprobs`, `logit_bias`, `service_tier`), maps `max_completion_tokens` -> `max_tokens`, and enforces distill tool/temperature rules. |
| **`openrouter`** | `docs/openapi/openrouter.openapi.yaml` | Chat, Streaming, Tools, Structured Outputs, `ListModels` | Dedicated OpenAPI-backed adapter in `internal/adapter/openrouter`; forwards attribution headers (`HTTP-Referer`, `X-Title`) and `openrouter_reasoning` mappings. |
| **`ollama`** | `docs/openapi/ollama.openapi.yaml` | Chat, Streaming, Tools, Structured Outputs, Completions (sync & stream), Embeddings, `ListModels` (`/api/tags` + `/v1/models` fallback) | Dedicated OpenAPI-backed adapter in `internal/adapter/ollama`; supports optional Bearer auth (keyless for local Ollama), root or `/v1` base URL normalization, and fail-closed loopback SSRF opt-in (`allow_loopback_http: true`). |

### Budgeted Caller Modality Coverage

For callers with active budgets, GoRoute requires a verified/custom price (`PricingStatusVerified` or `PricingStatusCustom`) and a deterministic pre-dispatch upper bound:
- **Supported with pre-dispatch reservation & settlement when verified/custom rates and an estimator are available**: `/v1/chat/completions`, `/v1/messages`, `/v1/responses`, `/v1/completions`, `/v1/embeddings`, `/v1/images/generations`, `/v1/images/edits`, `/v1/images/variations`, and `/v1/audio/speech` (TTS billed by Unicode character/rune count `len([]rune(input))` for both reservation and settlement).
- **Realtime and batch**: WebSocket turns and individual JSONL batch items check applicable descriptor quotas before provider dispatch. A denied batch item records its quota error in the batch output. Submission still reserves enqueued tokens and applicable legacy budgets for the batch.
- **Fail-closed for budgeted callers (`503 budget_estimate_unavailable`)**: Audio transcription, audio translation, and moderation require a safe pre-dispatch cost estimator before they can accept requests subject to a spend cap.
