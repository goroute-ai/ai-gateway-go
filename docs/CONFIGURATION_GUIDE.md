# GoRoute AI Gateway — Configuration & Developer Guide

Welcome to the official configuration and developer guide for **GoRoute AI Gateway** (`github.com/goroute-ai/ai-gateway-go`).

This guide explains how to configure, operate, and integrate every architectural system and platform module in your system using:
1. **Declarative YAML (`configs/config.yaml`)** — Declarative `model_list` and gateway settings.
2. **Go SDK (`pkg/gateway`)** — 1-line embedded router or remote client.
3. **HTTP Data Plane (`/v1/*`) & Control Plane (`/admin/v1/*`)** — OpenAI-compatible inference and multi-tenant enterprise governance.

---

## Table of Contents

- [Quickstart: Configuration Modes](#quickstart-configuration-modes)
- [Embedded Operator Web UI & Chat Playground](#embedded-operator-web-ui--chat-playground)
- [Unified API & Wire Normalization](#unified-api--wire-normalization)
- [Multi-Tenant Model & Provider Management](#multi-tenant-model--provider-management)
- [Intelligent Routing & Load Balancing](#intelligent-routing--load-balancing)
- [Dual-Boundary Auth, 4-Layer RBAC & Credential Vault](#dual-boundary-auth-4-layer-rbac--credential-vault)
- [Retries, 3-State Circuit Breakers & Fallbacks](#retries-3-state-circuit-breakers--fallbacks)
- [FinOps Usage, Micro-Dollar Cost Tracking & Budgets](#finops-usage-micro-dollar-cost-tracking--budgets)
- [Rate Limiting & Deterministic Response Caching](#rate-limiting--deterministic-response-caching)
- [Cross-Cutting Platform Modules (Guardrails, Validation & Observability)](#cross-cutting-platform-modules-guardrails-validation--observability)
- [Complete Configuration & Environment Variable Reference](#complete-configuration--environment-variable-reference)

---

## Quickstart: Configuration Modes

### Option A: Zero-Config Environment Variables (Fastest)
Set any upstream provider API key in your environment and start the server or SDK. The gateway automatically seeds the default organization (`org_default`), encrypts your keys in the in-memory AES-256-GCM vault, and registers standard aliases (`"fast"`, `"reasoning"`, `"auto"`):

```bash
# Frontier LLM Providers
export OPENAI_API_KEY="sk-proj-..."
export ANTHROPIC_API_KEY="sk-ant-..."
export GEMINI_API_KEY="AIzaSy..."
export MISTRAL_API_KEY="mis_..."

# Enterprise Cloud Hyperscalers
export AWS_ACCESS_KEY_ID="AKIA..."
export AWS_SECRET_ACCESS_KEY="..."
export AWS_REGION="us-east-1"

export GCP_SERVICE_ACCOUNT_JSON='{"type":"service_account","project_id":"my-proj",...}'
export GCP_PROJECT_ID="my-project"
export GCP_REGION="us-central1"

# Cohere v2
export COHERE_API_KEY="co-..."

# Certified High-Performance OpenAI-Compatible Engines
export GROQ_API_KEY="gsk_..."
export CEREBRAS_API_KEY="csk_..."
export SAMBANOVA_API_KEY="..."
export XAI_API_KEY="xai-..."
export TOGETHER_API_KEY="..."
export FIREWORKS_API_KEY="..."
export DEEPSEEK_API_KEY="dsk_..."
export PERPLEXITY_API_KEY="pplx-..."

go run ./cmd/gateway -config configs/config.yaml
```

### Option B: Declarative `model_list` in `configs/config.yaml`
Define your models, logical aliases (`fast`, `reasoning`), load-balancing strategies, and fallback chains declaratively in YAML:

```yaml
auth:
  master_admin_key: "sk-gw-master-admin-default-key-change-me"
  default_virtual_key: "sk-gw-demo-client-key"

model_list:
  - model_name: "fast"
    routing_strategy: "weighted-shuffle"
    fallbacks: ["reasoning"]
    model_params:
      model: "groq/llama-3.3-70b-versatile"
      api_key: "os.environ/GROQ_API_KEY"
      weight: 80
      rpm: 1000

  - model_name: "fast"
    model_params:
      model: "gemini/gemini-2.5-flash"
      api_key: "os.environ/GEMINI_API_KEY"
      weight: 20
      rpm: 1000

  - model_name: "reasoning"
    routing_strategy: "latency-based"
    model_params:
      model: "bedrock/anthropic.claude-3-5-sonnet-20241022-v2:0"
      api_key: "os.environ/AWS_ACCESS_KEY_ID:os.environ/AWS_SECRET_ACCESS_KEY:us-east-1"
      weight: 100

  - model_name: "enterprise-vertex"
    model_params:
      model: "vertex/gemini-2.5-pro"
      api_key: "os.environ/GCP_SERVICE_ACCOUNT_JSON"
      weight: 100
```

### Option C: Embedded Go SDK (`pkg/gateway`)
Import `github.com/goroute-ai/ai-gateway-go/pkg/gateway` directly in your Go application. The SDK provides self-contained public mirror types (`gateway.ChatRequest`, `gateway.Message`, `gateway.VirtualKeyRequest`, `gateway.VirtualKeyInfo`, `gateway.MCPServerConfig`, `gateway.A2AAgentConfig`) so callers do not need to import gateway internals:

```bash
go get github.com/goroute-ai/ai-gateway-go/pkg/gateway@v1.3.0
```

```go
// Embedded gateway with silent stdout logging in library mode
gw, err := gateway.New(
    gateway.WithModelList(
        gateway.ModelEntry{ModelName: "fast", Model: "gemini/gemini-2.5-flash", APIKey: "os.environ/GEMINI_API_KEY"},
    ),
    gateway.WithSilentLogs(), // Suppresses internal gateway logger
)
```

---

## Embedded Operator Web UI & Chat Playground

GoRoute AI Gateway embeds an operator web application directly into the binary. No Node.js runtime or separate static server is required.

### Accessing the Web UI
1. Launch GoRoute AI Gateway (`ai-gateway --config configs/config.yaml` or `docker compose up`).
2. Navigate to **`http://localhost:8080/ui/`** in any modern web browser.
3. When prompted, enter your Master Admin Key (configured via `auth.master_admin_key` or `GATEWAY_MASTER_ADMIN_KEY`; the development default is `sk-gw-master-admin-default-key-change-me`).

### Operator Console Features
- **Streaming Chat Playground**: Test prompts against any configured alias (`fast`, `reasoning`) or model with real-time SSE token streaming, temperature/token dials, latency graphs, and tool call inspection.
- **Model Catalogue Explorer**: Search and filter 100+ AI models across 12+ providers, inspect micro-dollar pricing, context window boundaries, and supported modalities (text, vision, audio).
- **Virtual Key Provisioning**: Create and revoke virtual API keys (`sk-gw-...`) with scoped team ownership, monthly micro-dollar budget limits, and RPM/TPM rate limits.
- **Live FinOps Analytics**: View real-time spend dashboards with breakdown by team, model, and provider.
- **Interactive Guardrail Simulator**: Test regex PII redaction and secret scanning against arbitrary text without invoking upstream models or incurring token charges.
- **Upstream Credentials Vault**: Add and rotate AES-256-GCM encrypted provider credentials with live preflight validation against provider endpoints.

---

## Unified API & Wire Normalization

### What It Does
Exposes a single OpenAI-compatible Data Plane (`/v1/chat/completions`, `/v1/embeddings`, `/v1/models`) and translates requests/responses through dedicated adapters and configurable OpenAI-compatible provider profiles. The current adapter implementations are under `internal/adapter/`; consult those packages and provider tests for exact capabilities.
- **OpenAI** (`/v1/chat/completions`, `/v1/embeddings`)
- **Anthropic Claude** (`/v1/messages` with stateful SSE event synthesis: `message_start` $\rightarrow$ `content_block_delta` $\rightarrow$ `message_delta` $\rightarrow$ `message_stop`)
- **Google Gemini** (`/v1beta/models/{model}:generateContent` & `:streamGenerateContent?alt=sse`, plus Vertex AI Express Mode auto-detection)
- **Mistral AI** (`/v1/chat/completions`, `/v1/embeddings`)
- **Ollama** (Local `/v1/chat/completions`, `/v1/embeddings`)

### Key Techniques Normalized Automatically
| Feature | How the Gateway Normalizes It |
| :--- | :--- |
| **System Prompts** | Extracted into top-level `system` parameter for Anthropic and `systemInstruction` for Gemini. |
| **Reasoning / Thinking** | `reasoning_effort: "low" \| "medium" \| "high"` maps to `budget_tokens` (`1024`/`4096`/`16384`) on Anthropic and `thinkingConfig.thinkingBudget` on Gemini 2.5. |
| **Tool / Function Calling** | OpenAI `tools[]` & `tool_calls[]` translate bidirectionally to Anthropic `tool_use`/`tool_result` blocks and Gemini `functionDeclarations`/`functionCall` parts. |
| **Zero-Buffer SSE Framing** | Flushes every SSE `data:` frame immediately via `http.Flusher` with zero intermediate response buffering. |

### Go SDK Usage
```go
res, err := gw.Chat(ctx, "fast", "Explain Pure Go network proxies.",
    gateway.WithSystem("Answer in one concise sentence."),
    gateway.WithTemperature(0.2),
    gateway.WithMaxTokens(256),
    gateway.WithReasoningEffort("medium"),
)

// Real-time SSE Streaming
streamRes, err := gw.StreamChat(ctx, "fast", "Stream a summary.", func(delta string) error {
    fmt.Print(delta)
    return nil
})
```

### HTTP Response Telemetry Headers
Every `/v1/chat/completions` response includes real-time gateway telemetry headers:
- `X-Gateway-Request-Id`: Unique request correlation ID (`req_...`)
- `X-Gateway-Provider`: Winning upstream provider (`gemini`, `anthropic`, `openai`, `mistral`, `ollama`)
- `X-Gateway-Model`: Resolved upstream model (`gemini-2.5-flash`, `claude-sonnet-4-20250514`, etc.)
- `X-Gateway-Cost-Micros`: Exact request cost in micro-USD ($10^{-6}\text{ USD}$)
- `X-Gateway-Routing-Micros`: Stage 1 + Stage 2 routing decision time in microseconds
- `X-Gateway-Cache`: `HIT` or `MISS` (for deterministic requests)
- `X-Gateway-Fallback-Attempted`: `true` or `false`

---

## Multi-Tenant Model & Provider Management

### What It Does
Enforces a strict **4-Layer Multi-Tenant Model Hierarchy** while supporting zero-friction **Dynamic `provider/model` Wildcard Routing** and **Automated Upstream Model Discovery**:
1. **Layer 1 (Global Model Catalogue)**: Capabilities (`supports_tools`, `supports_reasoning`, `max_input_tokens`) and versioned pricing (`input_cost_micros_per_1m`, `output_cost_micros_per_1m`) for all models.
2. **Layer 2 (Organization Provider Subscriptions)**: Controls which upstream vendors (`openai`, `anthropic`, `gemini`, `mistral`, `ollama`) a tenant organization is entitled to use.
3. **Layer 3 (Organization Model Policies)**: Explicit tenant compliance approval per `global_model_id`.
4. **Layer 4 (Model Groups & Physical Deployments)**: Maps logical aliases (`"fast"`, `"reasoning"`) to physical provider endpoints and encrypted Vault credentials.

### Configuring Automated Model Discovery (`configs/config.yaml`)
```yaml
discovery:
  enabled: true
  sync_interval: 6h
  auto_approve: true # Automatically enable newly discovered models for subscribed tenants
```

### Go SDK & Dynamic Wildcard Usage
You can pass any `"provider/model"` string (e.g., `"gemini/gemini-2.5-flash"`, `"anthropic/claude-sonnet-4-20250514"`, `"openai/gpt-4.1-mini"`) directly to `gw.Chat(...)` without pre-creating an alias:

```go
models, _ := gw.ListModels(ctx) // Returns tenant-filtered model IDs from GET /v1/models
res, _ := gw.Chat(ctx, "gemini/gemini-2.5-flash", "Direct wildcard routing!")
```

### Control Plane HTTP Endpoints
```bash
# Trigger immediate upstream model discovery sync across all active credentials
curl -X POST http://localhost:8080/admin/v1/catalogue/sync \
  -H "Authorization: Bearer $MASTER_ADMIN_KEY"

# Enable a provider subscription for an organization (Layer 2)
curl -X POST http://localhost:8080/admin/v1/organizations/org_default/subscriptions \
  -H "Authorization: Bearer $MASTER_ADMIN_KEY" \
  -d '{"provider":"anthropic","is_enabled":true,"auto_enable_new":true}'
```

---

## Intelligent Routing & Load Balancing

### Stage 1: The 3 Routing Modes
1. **Mode 1 — Explicit Model (`"gemini-2.5-flash"`, `"claude-sonnet-4-20250514"`)**: Routes directly to the specified model or `"provider/model"`.
2. **Mode 2 — Logical Alias (`"fast"`, `"reasoning"`, `"coding"`)**: Routes to a named `ModelGroup` containing one or more load-balanced deployments across regions or providers.
3. **Mode 3 — Smart Auto-Router (`"auto"`)**: Runs a **Zero-LLM Sub-Millisecond Heuristic Complexity Classifier** ($<1\text{ ms}$) that scores the prompt on `[0.0, 1.0]` using:
   - Total token length (`> 32,000` tokens routes immediately to long-context tier)
   - Fenced code blocks (` ``` `) and tool/function definitions (`+0.25`)
   - Multi-step reasoning/architecture markers (`"step by step"`, `"prove"`, `"analyze"`, `"architect"`, `"consensus"`)
   - `reasoning_effort == "high"` (`+0.35`)
   - If $\text{score} \ge \text{complexity\_threshold}$ (default `0.40`), routes to `default_reasoning_alias` (`"reasoning"`); otherwise routes to `default_fast_alias` (`"fast"`).

### Stage 2: The 5 Load-Balancing Strategies
Configure `routing_strategy` per `model_list` entry or `ModelGroup`:

| Strategy Value | Selection Algorithm | Best For |
| :--- | :--- | :--- |
| `weighted-shuffle` | Random selection proportional to deployment `weight` ($P(d_i) = w_i / \sum w_j$). | Traffic splitting (e.g., 80% Gemini / 20% OpenAI). |
| `least-busy` | Picks deployment with lowest atomic in-flight request count. | Long-running streaming & reasoning workloads. |
| `latency-based` | Tracks lock-free EWMA latency ($\text{EWMA}_{\text{new}} = 0.2\cdot L + 0.8\cdot \text{EWMA}_{\text{old}}$) and picks fastest endpoint. | Latency-critical interactive chat. |
| `usage-based-headroom` | Picks deployment with highest remaining RPM/TPM quota ratio over a 1-minute window: $\min(1 - \text{rpm}/\text{cap}, 1 - \text{tpm}/\text{cap})$. Counters reset every 60s. Falls back to lowest-utilization deployment if all exceed rated capacity. | Multi-region rate-limit maximization without starvation. |
| `lowest-cost` | Picks deployment with lowest `(InputCostMicrosPer1M + OutputCostMicrosPer1M)`. | Cost-optimized batch processing. |

### YAML Configuration (`configs/config.yaml`)
```yaml
router:
  default_fast_alias: "fast"
  default_reasoning_alias: "reasoning"
  default_coding_alias: "coding"
  complexity_threshold: 0.40
  long_context_tokens: 32000
```

---

## Dual-Boundary Auth, 4-Layer RBAC & Credential Vault

### Dual-Boundary Security Architecture
- **Boundary 1 (Client $\rightarrow$ Gateway)**: Clients authenticate with Gateway-issued **Virtual API Keys (`sk-gw-...`)**. Only the **SHA-256 hex digest** is persisted; the raw key is returned once upon creation. Validated in $<1\text{ ms}$ via a 2-tier cache (**L1 In-Process RWMutex Map** + **L2 Redis Cache** with instant Pub/Sub invalidation).
- **Boundary 2 (Gateway $\rightarrow$ Upstream Provider)**: Upstream vendor keys (`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `GEMINI_API_KEY`) are encrypted using **AES-256-GCM Envelope Encryption**:
  - Every credential gets a unique random 32-byte **Data Encryption Key (DEK)** + 12-byte `DataNonce`.
  - The DEK is encrypted by the gateway's 32-byte **Master Key Encryption Key (`master_encryption_key`)** + 12-byte `DEKNonce`.

> [!WARNING]
> **Production Key Hardening**: In production environments (`ENV=production` or `GATEWAY_ENV=production`), `Config.Validate()` strictly enforces that `auth.master_admin_key`, `auth.master_encryption_key`, and `auth.jwt_secret_key` must be overridden with non-default, high-entropy secrets. Leaving default demo keys in production results in a fatal startup error.

### Go SDK: Issuing, Scoping & Revoking Virtual Keys
```go
// 1. Issue a Virtual Key restricted to "fast" with 60 RPM limit using exported public types
vk, err := gw.IssueVirtualKey(ctx, gateway.VirtualKeyRequest{
    Name:          "checkout-service",
    AllowedModels: []string{"fast"},
    RPMLimit:      60,
})

// 2. Authenticate requests using the scoped Virtual Key
scopedClient := gw.WithKey(vk.RawKey)
res, err := scopedClient.Chat(ctx, "fast", "Allowed request")       // 200 OK
_, err = scopedClient.Chat(ctx, "reasoning", "Restricted request") // HTTP 403 Forbidden

// 3. Instant revocation (evicts L1 across all pods via Redis Pub/Sub KeyHash broadcast + marks inactive)
_ = gw.RevokeVirtualKey(ctx, vk.ID)
```

### Zero-Downtime Provider Key Rotation & Live Validation (`curl`)
```bash
# Rotate an upstream provider API key (re-encrypts with a fresh DEK and increments key_version)
curl -X POST http://localhost:8080/admin/v1/credentials/{credID}/rotate \
  -H "Authorization: Bearer $MASTER_ADMIN_KEY" \
  -d '{"api_key":"AIzaSyNewRotatedKey..."}'

# Validate live upstream connectivity for a stored credential
curl -X POST http://localhost:8080/admin/v1/credentials/{credID}/validate \
  -H "Authorization: Bearer $MASTER_ADMIN_KEY"
```

---

## Retries, 3-State Circuit Breakers & Fallbacks

### How High-Availability Failover Works
1. **Upstream Error Classification**:
   - `429 Too Many Requests`, `500`, `502`, `503`, `504`: Classified as **Retryable**.
   - `401 Unauthorized`, `403 Forbidden`: Classified as **AuthFailure** — immediately trips the deployment's circuit breaker to `OPEN` and fails over without wasting retry attempts.
   - `400 Bad Request`: Non-retryable client error; returned immediately.
2. **Full-Jitter Exponential Backoff**:
   $$\text{sleep} = \text{rand}\left(0,\ \min\left(\text{MaxDelay},\ \text{BaseDelay} \times 2^{\text{attempt}}\right)\right)$$
   Honors upstream `Retry-After` headers when $\le \text{MaxDelay}$.
3. **3-State Circuit Breaker (`CLOSED` $\rightarrow$ `OPEN` $\rightarrow$ `HALF_OPEN`)**:
   - Trips from `CLOSED` to `OPEN` when failures reach `failure_threshold` (default `3`) within `failure_window` (`30s`).
   - Remains `OPEN` for `default_cooldown` (`60s`), removing the deployment from the candidate pool.
   - Transitions to `HALF_OPEN` after cooldown and admits **strictly 1 trial recovery probe** while blocking concurrent callers; a successful probe resets to `CLOSED`, while a failure re-trips to `OPEN`.
4. **Cross-Provider Fallback Chains (`fallbacks`)**:
   - When all deployments in the primary `ModelGroup` are exhausted or in cooldown, `ReliabilityManager` automatically walks `Fallbacks` (e.g., failing over from Google Gemini to Anthropic Claude) and sets `X-Gateway-Fallback-Attempted: true`.

### YAML & SDK Configuration
```yaml
router:
  default_max_retries: 2
  base_retry_delay: 50ms
  max_retry_delay: 2s
  default_cooldown: 60s
  failure_window: 30s
  failure_threshold: 3

model_list:
  - model_name: "production-chat"
    fallbacks: ["backup-claude"]
    model_params:
      model: "gemini/gemini-2.5-flash"
      api_key: "os.environ/GEMINI_API_KEY"
  - model_name: "backup-claude"
    model_params:
      model: "anthropic/claude-sonnet-4-20250514"
      api_key: "os.environ/ANTHROPIC_API_KEY"
```

---

## FinOps Usage, Micro-Dollar Cost Tracking & Budgets

### Integer Pico/Micro-Dollar Cost Formula
To eliminate IEEE-754 floating-point drift across millions of transactions, all pricing and spend ledgers use **64-bit integer micro-dollars** ($1\text{ USD} = 1,000,000\text{ micro-USD}$), computed via **pico-dollars** ($10^{-12}\text{ USD}$) with half-up rounding:

$$\text{picos} = (\text{UncachedPrompt} \times \text{InRate}) + (\text{CachedPrompt} \times \text{CacheRate}) + (\text{Completion} \times \text{OutRate}) + (\text{Reasoning} \times \text{ReasonRate})$$

$$\text{CostMicros} = \left\lfloor \frac{\text{picos} + 500,000}{1,000,000} \right\rfloor$$

### Non-Blocking Async Spend Worker & Hard Budgets
- **Hot Path ($0\text{ ms}$ DB Blocking)**: After every inference call, `SpendWorker.Enqueue()` synchronously increments real-time budget counters and pushes a `SpendEvent` into a `16,384`-slot buffered Go channel flushed in batches of `250` every `500ms`.
- **Hierarchical Hard Budgets**: Configure `MaxBudgetMicros` and `BudgetResetPeriod` (`"daily"`, `"monthly"`, `"never"`) at the **Virtual Key**, **Team**, or **Organization** level. Exceeding any cap immediately returns `HTTP 429 Too Many Requests (budget_exceeded)`.

### Go SDK & Control Plane Usage
```go
res, _ := gw.Chat(ctx, "fast", "Track my token cost.")
fmt.Printf("Cost: %d micro-USD\n", res.CostMicros)

summary, _ := gw.SpendSummary(ctx)
fmt.Printf("Total Spend: %d micro-USD ($%.6f)\n", summary.TotalCostMicros, summary.TotalCostUSD)
```

```bash
# Update model pricing (automatically increments pricing_version and records audit history)
curl -X POST http://localhost:8080/admin/v1/catalogue/pricing \
  -H "Authorization: Bearer $MASTER_ADMIN_KEY" \
  -d '{
    "global_model_id": "gemini/gemini-2.5-flash",
    "input_cost_micros_per_1m": 150000,
    "output_cost_micros_per_1m": 600000
  }'
```

---

## Rate Limiting & Deterministic Response Caching

### Part A: Multi-Level Atomic Rate Limiting (RPM, TPM & Concurrency)
1. **Model-Specific BPE Pre-Flight Token Estimation**: Estimates input tokens using family-specific character-to-token ratios (`3.2` for Claude, `3.5` for GPT-4o/4.1/o3, `3.8` for Gemini/Mistral/Llama) + per-message chat template overhead + `1024` reserve when `reasoning_effort` is active.
2. **Single-Roundtrip Redis Lua Quota Check & Post-Response Reconciliation**: Atomically verifies Key, Team, and Org RPM, TPM, Concurrency, and Spend limits in 1 RTT, then reconciles `actual_tokens - estimated_tokens` after completion.
3. **3 Configurable Redis Outage Fallback Modes**:
   - `local_divided_by_replicas` (Default): Scales in-memory limits to `max(1, limit / expectedPods)` so cluster-wide traffic never overshoots tenant quotas during a Redis outage.
   - `local_per_pod`: Enforces full limit per pod.
   - `fail_closed`: Rejects requests with `HTTP 503` when Redis is unreachable.

### Part B: Tenant-Isolated Deterministic Response Cache (`0ms`, `$0.00`)
- **Eligibility**: Caches non-streaming requests where `temperature <= 0` or `seed != nil` (unless `X-Gateway-Cache-Control: no-cache` is sent).
- **Collision-Proof SHA-256 Key**: `gw:cache:v2:{nsVer}:org:{orgID}:{sha256(canonical_payload)}`. The payload hash strictly binds `ResolvedModel`, `Messages`, `Tools`, `ResponseFormat`, `Temperature`, `TopP`, `ReasoningEffort`, and `User` identifier to prevent collisions across varying models or user sessions.
- **Cache Hit Behavior**: Returns `X-Gateway-Cache: HIT` in `0ms` with `X-Gateway-Cost-Micros: 0` without calling the upstream provider.

### YAML & SDK Usage
```yaml
rate_limit:
  enabled: true
  window_seconds: 60
  concurrency_ttl_sec: 300
  redis_timeout: 50ms

cache:
  enabled: true
  default_ttl: 1h
```

```go
// Temperature 0.0 enables deterministic exact-match caching
r1, _ := gw.Chat(ctx, "fast", "What is 2 + 2?", gateway.WithTemperature(0.0)) // CacheStatus="MISS"
r2, _ := gw.Chat(ctx, "fast", "What is 2 + 2?", gateway.WithTemperature(0.0)) // CacheStatus="HIT", CostMicros=0
```

---

## Cross-Cutting Platform Modules (Guardrails, Validation & Observability)

### Module A: Security Guardrails Engine (`POST /admin/v1/organizations/{orgID}/guardrails`)
Inspects prompts pre-flight and completions post-response with zero external ML dependencies:
- **Prompt Injection & Jailbreak Detection**: Checks user prompts against a fixed set of known text signatures, such as `ignore previous instructions`, `disregard your system prompt`, and `you are now dan`.
- **PII & Secret Detection/Redaction**: Detects email addresses, SSNs, payment card patterns, and selected API key patterns. Redaction uses type-specific tags such as `[REDACTED_EMAIL]`, `[REDACTED_SSN]`, `[REDACTED_CARD]`, and `[REDACTED_SECRET]`.
- **Configurable Actions**: `"block"`, `"redact"`, or `"audit"` for prompt-injection, PII, and secret checks. `audit` records a violation without blocking, and `redact` modifies matching content before upstream execution. Custom blocked keywords always block when matched.

```bash
curl -X POST http://localhost:8080/admin/v1/organizations/org_default/guardrails \
  -H "Authorization: Bearer $MASTER_ADMIN_KEY" \
  -d '{
    "enable_prompt_injection": true,
    "prompt_injection_action": "block",
    "enable_pii_detection": true,
    "pii_action": "redact",
    "enable_secret_detection": true,
    "secret_action": "redact",
    "redact_output_pii": true
  }'
```

### Module B: Pre-Flight Request Validator
Validates parameters (`temperature` in `[0, 2]`, `top_p` in `[0, 1]`), model capabilities (`supports_tools`, `supports_reasoning`), and context window limits (`estPromptTokens + maxTokens <= GlobalModel.MaxInputTokens`) before consuming upstream quota.

### Module C: Observability, W3C Tracing & Active Health Monitor
- **Prometheus Metrics (`GET /metrics`)**: Exposes `ai_gateway_requests_total`, `ai_gateway_tokens_total`, `ai_gateway_spend_micros_total`, `ai_gateway_cache_hits_total`, `ai_gateway_rate_limited_total`, `ai_gateway_guardrail_blocks_total`, and `ai_gateway_latency_ms_{p50,p95,p99}`.
- **JSON Telemetry Snapshot (`GET /admin/v1/observability/metrics`)**: Real-time P50/P95/P99 latency and per-provider/per-deployment health breakdown.
- **Active Health Monitor (`GET /admin/v1/health/deployments` & `POST /admin/v1/health/probe`)**: Periodically probes upstream credentials and preemptively marks failing deployments unhealthy before user traffic hits them.

---

## Complete Configuration & Environment Variable Reference

| YAML Path | Environment Variable Override | Default | Description |
| :--- | :--- | :--- | :--- |
| `server.host` | — | `"0.0.0.0"` | HTTP network bind address. |
| `server.port` | `GATEWAY_PORT` | `8080` | HTTP listen port (1–65535). |
| `server.read_timeout` | — | `30s` | Maximum duration for reading the entire request. |
| `server.write_timeout` | — | `300s` | Maximum duration before timing out writes of the response (sized for reasoning streams). |
| `server.idle_timeout` | — | `120s` | Maximum amount of time to wait for the next request when keep-alives are enabled. |
| `server.shutdown_timeout` | — | `15s` | Graceful shutdown timeout before closing active connections. |
| `logging.level` | `GATEWAY_LOG_LEVEL` | `"info"` | Log verbosity: `"debug"`, `"info"`, `"warn"`, `"error"`. |
| `logging.format` | `GATEWAY_LOG_FORMAT` | `"text"` | Log encoding: `"json"` (cloud structured) or `"text"` (human readable). Auto-switches to `"json"` if `ENV=production`. |
| `logging.add_source` | `GATEWAY_LOG_ADD_SOURCE` | `false` | When true, annotates log records with caller `file:line`. |
| `storage.mode` | `GATEWAY_STORAGE_MODE` | `"memory"` | Storage backend: `"memory"` (zero external dependencies) or `"postgres"`. |
| `storage.postgres_dsn` | `GATEWAY_POSTGRES_DSN` | `postgres://...` | PostgreSQL connection string (auto-switches storage mode to `"postgres"` when present). |
| `storage.redis_addr` | `GATEWAY_REDIS_ADDR` | `"localhost:6379"` | Redis host:port for L2 auth caching, Lua rate limiting, and response caching. |
| `storage.redis_pass` | `GATEWAY_REDIS_PASS` | `""` | Optional Redis authentication password. |
| `storage.redis_db` | — | `0` | Redis logical database index. |
| `auth.master_admin_key` | `GATEWAY_MASTER_ADMIN_KEY` | `sk-gw-master-...` | Control plane bearer token (min 12 chars; must be changed in `production`). |
| `auth.master_encryption_key` | `GATEWAY_MASTER_ENCRYPTION_KEY` | 64-char hex | 32-byte AES-256-GCM Master Key Encryption Key (must be changed in `production`). |
| `auth.jwt_secret` | `GATEWAY_JWT_SECRET` | `"gateway-jwt-..."` | HMAC secret for signing internal JWT tokens. |
| `auth.default_org_id` | — | `"org_default"` | Initial default organization ID seeded at startup. |
| `auth.default_virtual_key` | `GATEWAY_DEFAULT_KEY` | `""` | Optional pre-seeded client virtual key for immediate local testing. |
| `auth.l1_cache_ttl` | — | `15s` | In-memory L1 cache TTL for virtual key identity and permissions. |
| `auth.l2_cache_ttl` | — | `5m` | Redis L2 cache TTL for virtual key identity and permissions. |
| `router.default_fast_alias` | — | `"fast"` | Default model group aliased to low-latency models. |
| `router.default_reasoning_alias` | — | `"reasoning"` | Default model group aliased to high-reasoning frontier models. |
| `router.default_coding_alias` | — | `"coding"` | Default model group aliased to code generation models. |
| `router.complexity_threshold` | — | `0.40` | Heuristic prompt complexity score `[0, 1]` above which `"auto"` routes to `"reasoning"`. |
| `router.long_context_tokens` | — | `32000` | Token threshold for routing to long-context-specialized models. |
| `router.default_max_retries` | — | `2` | Intra-group retry attempts before failing over to next fallback group. |
| `router.base_retry_delay` | `GATEWAY_ROUTER_BASE_RETRY_DELAY` | `50ms` | Base backoff delay for full-jitter exponential retries. |
| `router.max_retry_delay` | `GATEWAY_ROUTER_MAX_RETRY_DELAY` | `2s` | Upper bound for exponential backoff retry delays. |
| `router.default_cooldown` | `GATEWAY_ROUTER_DEFAULT_COOLDOWN` | `60s` | Duration a tripped deployment stays in `OPEN` circuit-breaker cooldown. |
| `router.failure_window` | — | `30s` | Sliding window for counting consecutive upstream errors. |
| `router.failure_threshold` | — | `3` | Consecutive errors required to trip circuit breaker into `OPEN` state. |
| `rate_limit.enabled` | — | `true` | Enables distributed sliding-window rate limiting via Redis Lua. |
| `rate_limit.window_seconds` | — | `60` | Fixed window duration in seconds for RPM/TPM calculation. |
| `rate_limit.concurrency_ttl_sec` | — | `300` | Lease duration in seconds for concurrent in-flight request locks. |
| `rate_limit.default_estimated_tpm` | — | `128` | Pre-flight token heuristic estimate when prompt tokens are unmeasured. |
| `rate_limit.redis_timeout` | — | `50ms` | Maximum timeout for Redis Lua rate-limit checks before failing closed. |
| `finops.channel_buffer_size` | — | `16384` | Capacity of asynchronous spend event channel. |
| `finops.batch_size` | — | `250` | Maximum spend events aggregated per database flush. |
| `finops.flush_interval` | `GATEWAY_FINOPS_FLUSH_INTERVAL` | `500ms` | Maximum duration between asynchronous spend ledger flushes. |
| `finops.worker_count` | — | `4` | Number of concurrent background spend processor goroutines. |
| `discovery.enabled` | — | `true` | Enables background upstream model catalogue discovery. |
| `discovery.sync_interval` | — | `6h` | Polling interval for model catalogue synchronization worker. |
| `discovery.auto_approve` | — | `false` | When true, auto-enables newly discovered upstream models. |
| `cache.enabled` | — | `true` | Enables deterministic exact-match response caching. |
| `cache.default_ttl` | — | `1h` | Default TTL for exact-match response cache entries. |
| `mcp.enabled` | `GATEWAY_MCP_ENABLED` | `true` | Enables Model Context Protocol (MCP) data plane & control plane. |
| `mcp.allow_stdio_servers` | `GATEWAY_MCP_ALLOW_STDIO` | `false` | Enables local stdio subprocess MCP transport (requires explicit opt-in). |
| `mcp.allowed_stdio_binaries` | — | `[]` | Explicit allowlist of absolute binary paths permitted for stdio transport. |
| `mcp.enable_session_compat_2025` | — | `true` | Enables MCP 2025-11-25 stateful session translation adapter. |
| `mcp.session_ttl_2025` | — | `15m` | Session expiration TTL for legacy 2025 MCP connections. |
| `mcp.cache_key_secret` | `GATEWAY_MCP_CACHE_KEY_SECRET` | — | HMAC-SHA256 secret for delimiter-collision-proof MCP cache keys. |
| `mcp.max_payload_bytes` | — | `10485760` | Maximum allowed payload size for MCP requests (10 MB). |
| `mcp.default_timeout` | — | `30s` | Default execution timeout for upstream MCP tool calls. |
| `mcp.subscriptions_listen_active` | `GATEWAY_MCP_SUBSCRIPTIONS_LISTEN` | `true` | Enables multiplexed SSE subscriptions endpoint (`/mcp/subscriptions/listen`). |
| `a2a.enabled` | `GATEWAY_A2A_ENABLED` | `true` | Enables Agent-to-Agent (A2A v1.0) protocol service. |
| `a2a.enable_jsonrpc` | — | `true` | Enables JSON-RPC 2.0 transport for A2A message exchange. |
| `a2a.enable_http_json` | — | `true` | Enables REST/HTTP+JSON transport for A2A message exchange. |
| `a2a.enable_subscribe_post_compat` | — | `false` | Allows legacy `POST /tasks/{id}:subscribe` in addition to canonical `GET`. |
| `a2a.allow_legacy_card_discovery` | — | `false` | Allows unsigned or legacy uncanonicalized agent card discovery. |
| `a2a.max_task_lifespan` | — | `24h` | Maximum durability lifespan for active A2A task records. |
| `a2a.stream_buffer_capacity` | — | `256` | Per-task SSE event streaming buffer capacity. |
| `a2a.stream_publish_interval` | `GATEWAY_A2A_STREAM_PUBLISH_INTERVAL` | `50ms` | Interval for background task stream publication daemon. |
| `a2a.max_push_retries` | `GATEWAY_A2A_MAX_PUSH_RETRIES` | `5` | Maximum retry attempts for transactional outbox webhooks before DLQ. |
| `a2a.signing_key_id` | `GATEWAY_A2A_SIGNING_KEY_ID` | `"gw-a2a-signer-v1"` | Key ID for RFC 8785 JCS / JWS Agent Card signing. |
| `a2a.allowed_signing_algs` | — | `["ES256", "RS256", "EdDSA"]` | Allowed cryptographic signature algorithms for inbound Agent Cards. |
| `a2a.trusted_card_jwks` | — | `{}` | Upstream agent slug -> JWKS URL mapping for card verification. |
| `security.network.egress_proxy_url` | `GATEWAY_EGRESS_PROXY_URL` | `""` | Corporate HTTP/HTTPS egress proxy URL for enterprise outbound firewalls. |
| `security.network.outbound_ssrf.allow_private_networks` | `GATEWAY_SSRF_ALLOW_PRIVATE` | `false` | Enables private/internal IP egress (must remain false in production). |
| `security.network.outbound_ssrf.allowed_private_cidrs` | — | `[]` | Explicit private CIDR allowlist (e.g. `["10.0.0.0/8"]`) when egress is gated. |
| `security.network.outbound_ssrf.allow_insecure_http` | `GATEWAY_SSRF_ALLOW_INSECURE_HTTP` | `false` | Allows plaintext HTTP upstream requests. |
| `security.network.outbound_ssrf.allowed_schemes` | — | `["https"]` | Allowed URL schemes for provider endpoints (`https`, `http`). |
| `security.network.outbound_ssrf.blocked_ips` | — | `["169.254.169.254", ...]` | Cloud metadata and sensitive IP addresses blocked from egress. |
| `security.network.outbound_ssrf.dial_timeout` | — | `10s` | Network connect and TLS handshake timeout for provider egress. |
| `security.network.outbound_ssrf.max_redirects` | — | `3` | Maximum HTTP redirect hops permitted on outbound provider calls. |
| `security.network.inbound_caller.expose_on_public_internet` | — | `false` | Network policy flag documenting internet exposure stance. |
| `security.network.inbound_caller.allowed_client_cidrs` | — | `[]` | Client CIDR allowlist for incoming network requests. |
| `providers.custom_openai_compatible[].id` | — | — | Unique provider identifier (e.g. `"custom-vllm"`). |
| `providers.custom_openai_compatible[].display_name` | — | — | Human-readable provider label. |
| `providers.custom_openai_compatible[].base_url` | — | — | Upstream endpoint base URL. |
| `providers.custom_openai_compatible[].supports_streaming` | — | `"true"` | Streaming capability override (`"true"`, `"false"`, `"unknown"`). |
| `providers.custom_openai_compatible[].supports_tools` | — | `"true"` | Function/tool calling capability override. |
| `providers.custom_openai_compatible[].supports_structured_outputs` | — | `"true"` | Structured outputs (`response_format: json_schema`) capability. |
| `providers.custom_openai_compatible[].supports_list_models` | — | `true` | Whether upstream provider implements `GET /models`. |
| `providers.custom_openai_compatible[].default_headers` | — | `{}` | Key-value HTTP headers automatically attached to outbound calls. |
| `model_list[].model_name` | — | — | Virtual model name or alias presented to clients (`"fast"`, `"reasoning"`). |
| `model_list[].routing_strategy` | — | `"weighted-shuffle"` | Routing policy: `"weighted-shuffle"`, `"least-busy"`, `"latency-based"`, `"lowest-cost"`, `"usage-based-headroom"`. |
| `model_list[].fallbacks` | — | `[]` | Ordered array of fallback model names triggered on upstream outage or rate-limit. |
| `model_list[].model_params.model` | — | — | Upstream provider/model identifier (e.g. `"gemini/gemini-2.5-flash"`). |
| `model_list[].model_params.api_key` | — | — | Upstream provider API key (supports `os.environ/VAR`). |
| `model_list[].model_params.api_base` | — | `""` | Custom upstream base URL override. |
| `model_list[].model_params.region` | — | `""` | Cloud region for Bedrock/Vertex deployments. |
| `model_list[].model_params.weight` | — | `100` | Integer weight for weighted load balancing. |
| `model_list[].model_params.rpm` | — | `0` | Per-deployment Requests Per Minute capacity limit. |
| `model_list[].model_params.tpm` | — | `0` | Per-deployment Tokens Per Minute capacity limit. |
| `model_list[].model_params.azure_deployment_name` | — | `""` | Deployment name for Azure OpenAI endpoints. |
| `model_list[].model_params.api_version` | — | `""` | API version query parameter for Azure OpenAI endpoints. |
| `model_list[].model_params.headers` | — | `{}` | Custom HTTP headers forwarded to the upstream model provider. |
| `files.storage_dir` | `GOROUTE_FILES_DIR` | `os.TempDir()/goroute-files` | Local disk directory for stateful tenant files and batch JSONL files (enforces `0700` directory mode and `0600` file mode). |
