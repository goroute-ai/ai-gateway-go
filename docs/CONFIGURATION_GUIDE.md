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
# OpenAPI-First LLM Providers
export OPENAI_API_KEY="sk-proj-..."
export ANTHROPIC_API_KEY="sk-ant-..."
export GROQ_API_KEY="gsk_..."
export OPENROUTER_API_KEY="sk-or-v1-..."

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
      model: "openai/gpt-4o-mini"
      api_key: "os.environ/OPENAI_API_KEY"
      weight: 20
      rpm: 1000

  - model_name: "reasoning"
    routing_strategy: "latency-based"
    model_params:
      model: "anthropic/claude-sonnet-4-20250514"
      api_key: "os.environ/ANTHROPIC_API_KEY"
      weight: 100

  - model_name: "openrouter-sonnet"
    model_params:
      model: "openrouter/anthropic/claude-sonnet-4-5"
      api_key: "os.environ/OPENROUTER_API_KEY"
      weight: 100
```

### Option C: Embedded Go SDK (`pkg/gateway`)
Import `github.com/goroute-ai/ai-gateway-go/pkg/gateway` directly in your Go application. The SDK provides self-contained public mirror types (`gateway.ChatRequest`, `gateway.Message`, `gateway.RoutingHints`, `gateway.RouterOptions`, `gateway.FallbackTarget`, `gateway.VirtualKeyRequest`, `gateway.VirtualKeyInfo`, `gateway.MCPServerConfig`, `gateway.A2AAgentConfig`) so callers do not need to import gateway internals:

```bash
go get github.com/goroute-ai/ai-gateway-go/pkg/gateway
```

```go
// Embedded gateway with silent stdout logging, v0.1.0 routing/rotation, and custom auth options
gw, err := gateway.New(
    gateway.WithModelList(
        gateway.ModelEntry{
            ModelName:         "fast",
            Model:             "openai/gpt-4o-mini",
            APIKey:            "os.environ/OPENAI_API_KEY",
            RoutingStrategy:   "latency-based",
            Priority:          0,
            Region:            "us-central1",
            Tags:              []string{"tier:fast", "low-cost"},
            MaxBudgetMicros:   50_000_000,
            BudgetResetPeriod: "daily",
            ContextWindowFallbacks: []string{"long-context"},
        },
    ),
    gateway.WithSessionAffinity(30*time.Minute, true),
    gateway.WithMidStreamContinuation(true, 1),
    gateway.WithHedgeConfig(150, 2),
    gateway.WithSilentLogs(), // Suppresses internal gateway logger
)
```

For embedded Go applications integrating bespoke corporate identity headers or mTLS claims, attach `gateway.WithCustomAuthenticator`:

```go
gw, err := gateway.New(
    gateway.WithCustomAuthenticator(gateway.CustomAuthModeAuto, gateway.CustomAuthenticatorFunc(
        func(ctx context.Context, r *http.Request) (*gateway.AuthDecision, error) {
            if rawKey := r.Header.Get("X-Corp-Gateway-Key"); rawKey != "" {
                return &gateway.AuthDecision{VirtualKey: rawKey}, nil
            }
            return nil, nil // abstain -> fall through to standard gateway auth in CustomAuthModeAuto
        },
    )),
)
```
Use `CustomAuthModeOn` to require the hook unconditionally (fail closed on errors or nil abstentions) and set `RunPostChecks: true` when supplying a direct `Identity` so model, endpoint, RBAC, and quota rules are enforced.

---

## Embedded Operator Web UI & Chat Playground

GoRoute AI Gateway embeds an operator web application directly into the binary. No Node.js runtime or separate static server is required.

### Accessing the Web UI
1. Launch GoRoute AI Gateway (`ai-gateway --config configs/config.yaml` or `docker compose up`).
2. Navigate to **`http://localhost:8080/ui/`** (or deep-link directly to `/ui/playground`, `/ui/organizations`, `/ui/models`, etc.) in any modern web browser.
3. When prompted, enter your Master Admin Key (configured via `auth.master_admin_key` or `GATEWAY_MASTER_ADMIN_KEY`; the development default is `sk-gw-master-admin-default-key-change-me`). The UI validates the key against `/admin/v1/organizations` before unlocking.

### Operator Console Features
- **Streaming Chat Playground**: Test prompts against any configured alias (`fast`, `reasoning`) or model with real-time SSE token streaming, temperature/token dials, latency, micro-dollar cost, and guardrail action telemetry.
- **Organizations, Teams & Policies**: Create and manage organizations, teams, users, micro-dollar budgets, provider subscriptions, and org-level model policies.
- **Model Catalogue & Routing Explorer**: Search and filter models across `openai`, `anthropic`, `groq`, and `openrouter`, inspect micro-dollar pricing, context window boundaries, supported capabilities, and attach deployments to model groups.
- **Virtual Key Provisioning**: Create and revoke virtual API keys (`sk-gw-...`) with scoped team/user ownership, expiry, allowed MCP servers / A2A agents, monthly micro-dollar budget limits, and RPM/TPM rate limits.
- **Live FinOps Analytics**: View real-time spend dashboards with breakdown by team, virtual key, model, and provider.
- **Guardrails Console & Usage Metrics**: Configure Layer 0 baseline rules (prompt injection, PII, secrets, 5 toxicity categories), register & bind any of the 15 built-in guardrail drivers (external moderation/PII services, Starlark `custom_code`, webhooks, LLM judges, tool/MCP governance), manage cross-turn tool trust policies, simulate via `/v1/guardrails/apply`, and track micro-dollar guardrail cost attribution.
- **Upstream Credentials Vault**: Add and rotate AES-256-GCM encrypted provider credentials with live preflight validation against provider endpoints.

---

## Unified API & Wire Normalization

### What It Does
Exposes a single OpenAI-compatible Data Plane (`/v1/chat/completions`, `/v1/embeddings`, `/v1/models`, `/v1/responses`, `/v1/messages`, `/v1/audio/*`, `/v1/images/*`, `/v1/files`, `/v1/batches`, `/v1/realtime`) and translates requests/responses strictly through OpenAPI-first adapters under `internal/adapter/`:
- **OpenAI** (`/v1/chat/completions`, `/v1/responses`, `/v1/embeddings`, `/v1/audio/*`, `/v1/images/*`, `/v1/realtime`)
- **Anthropic Claude** (`/v1/messages` with stateful SSE event synthesis: `message_start` $\rightarrow$ `content_block_delta` $\rightarrow$ `message_delta` $\rightarrow$ `message_stop`)
- **Groq** (`/openai/v1/chat/completions`, `/openai/v1/completions`, `/openai/v1/audio/*`, `/openai/v1/models`)
- **OpenRouter** (`/api/v1/chat/completions`, `/api/v1/models` with reasoning parameter mapping)

### Key Techniques Normalized Automatically
| Feature | How the Gateway Normalizes It |
| :--- | :--- |
| **System Prompts** | Extracted into top-level `system` parameter for Anthropic and `developer` role for OpenAI reasoning models. |
| **Reasoning / Thinking** | `reasoning_effort: "low" \| "medium" \| "high"` maps to `budget_tokens` (`1024`/`4096`/`16384`) on Anthropic and OpenRouter `reasoning` effort fields. |
| **Tool / Function Calling** | OpenAI `tools[]` & `tool_calls[]` translate bidirectionally to Anthropic `tool_use`/`tool_result` blocks and Groq/OpenRouter tool calls. |
| **Zero-Buffer SSE Framing** | Flushes every SSE `data:` frame immediately via `http.Flusher` with zero intermediate response buffering. |

### Go SDK Usage & Routing Options
```go
res, err := gw.Chat(ctx, "fast", "Explain Pure Go network proxies.",
    gateway.WithSystem("Answer in one concise sentence."),
    gateway.WithTemperature(0.2),
    gateway.WithMaxTokens(256),
    gateway.WithReasoningEffort("medium"),
    gateway.WithRoutingHints(gateway.RoutingHints{
        AllowedRegion: "us-central1",
        Tags:          []string{"tier:fast", "!deprecated"},
        SessionID:     "sess_123",
        Priority:      10,
    }),
)
fmt.Printf("Provider=%s Reason=%s Stepdowns=%d Continued=%v\n",
    res.Provider, res.RouteReason, res.TierStepdowns, res.StreamContinued)

// Real-time SSE Streaming
streamRes, err := gw.StreamChat(ctx, "fast", "Stream a summary.", func(delta string) error {
    fmt.Print(delta)
    return nil
})
```
Custom Go hooks can also be injected at initialization with `WithRouterConfig`, `WithPreRouterMode`, `WithPreRouter`, `WithPreRouterAlias`, `WithRoutingPlugin`, `WithDefaultFallbacks`, and `WithDefaultFallbackTargets`.

### HTTP Request Routing Hints & Response Telemetry Headers
Every `/v1/chat/completions` call accepts optional inbound routing hint headers (`X-Gateway-Allowed-Region`, `X-Gateway-Session-Id`, `X-Gateway-Preferred-Deployment-Id`, `X-Gateway-Priority`, `X-Gateway-Hedge-After-Ms`, `X-Gateway-Tags`, `X-Gateway-Tag-<Name>`) and returns real-time telemetry headers:
- `X-Gateway-Request-Id`: Unique request correlation ID (`req_...`)
- `X-Gateway-Provider`: Winning upstream provider (`openai`, `anthropic`, `groq`, `openrouter`)
- `X-Gateway-Model`: Resolved upstream model (`gpt-4o-mini`, `claude-sonnet-4-20250514`, etc.)
- `X-Gateway-Cost-Micros`: Exact request cost in micro-USD ($10^{-6}\text{ USD}$)
- `X-Gateway-Latency-Ms`: End-to-end request latency in milliseconds
- `X-Gateway-Routing-Micros`: Stage 0–4 routing decision time in microseconds
- `X-Gateway-Route-Reason`: PreRouter or step-down routing reason (e.g., `priority_tier_stepdown`)
- `X-Gateway-Tier-Stepdowns`: Number of `Deployment.Priority` tier step-downs attempted
- `X-Gateway-Stream-Continued`: `true` if mid-stream SSE continuation stitched the response
- `X-Gateway-Cache`: `HIT` or `MISS` (for deterministic requests)
- `X-Gateway-Fallback-Attempted`: `true` or `false`

---

## Multi-Tenant Model & Provider Management

### What It Does
Enforces a strict **4-Layer Multi-Tenant Model Hierarchy** while supporting zero-friction **Dynamic `provider/model` Wildcard Routing** and **Automated Upstream Model Discovery**:
1. **Layer 1 (Global Model Catalogue)**: Capabilities (`supports_tools`, `supports_reasoning`, `max_input_tokens`) and versioned pricing (`input_cost_micros_per_1m`, `output_cost_micros_per_1m`) for all models.
2. **Layer 2 (Organization Provider Subscriptions)**: Controls which upstream vendors (`openai`, `anthropic`, `groq`, `openrouter`) a tenant organization is entitled to use.
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
You can pass any `"provider/model"` string (e.g., `"groq/llama-3.1-8b-instant"`, `"anthropic/claude-sonnet-4-20250514"`, `"openai/gpt-4.1-mini"`, `"openrouter/openai/gpt-4o-mini"`) directly to `gw.Chat(...)` without pre-creating an alias:

```go
models, _ := gw.ListModels(ctx) // Returns tenant-filtered model IDs from GET /v1/models
res, _ := gw.Chat(ctx, "openai/gpt-4o-mini", "Direct wildcard routing!")
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

## Intelligent Pre-Routing, Candidate Filtering & Load Balancing

### Stage 0: PreRouter & Model Resolution Modes
1. **Explicit Model (`"gpt-4o-mini"`, `"claude-sonnet-4-20250514"`)**: Routes directly to the specified model or `"provider/model"`.
2. **Logical Alias (`"fast"`, `"reasoning"`, `"coding"`)**: Routes to a named `ModelGroup` containing one or more priority-tiered, load-balanced deployments across regions or providers.
3. **Comma-Separated Racing (`"model-a,model-b"`)**: Races candidate groups/models concurrently with hedged stagger delays (`hedge_delay_ms`).
4. **Virtual Pre-Routers (`PreRouterRegistry`)**:
   - **`"auto"` / `"router/heuristic"`**: Runs a **Zero-LLM Sub-Millisecond Heuristic Complexity Classifier** ($<0.1\text{ ms}$) scoring prompt tokens, fenced code blocks, tools, `reasoning_effort`, and analytical keywords against `complexity_threshold` (`0.40`).
   - **`"router/semantic"`**: Matches request intent via embedding cosine similarity (`semantic_router.embedding_model`, `similarity_threshold`, `routes[]`) with Redis centroid caching.
   - **`"router/quality"`**: Escalates or maps prompts across `GlobalModel.QualityTier` capabilities.
   - **`"router/adaptive"`**: Runs a **Thompson-Sampling Contextual Bandit** (`bandit.*`) balancing Beta reward posteriors, latency weight, and cost weight with Postgres/Redis state sync.

### Stage 2: Candidate Filter Chain, Priority Tiers & 7 Load-Balancing Strategies
Before selection, `DeploymentFilterChain` narrows candidates by deployment health & `health_staleness_threshold`, 3-state circuit breakers, context window capacity, `allowed_region`, boolean `&`/`!` `tags` expressions, per-deployment `rpm`/`tpm`/`max_budget_micros` & `provider_budgets`, session/prompt-cache affinity (`AffinityStore`), and registered `RoutingPlugin` filters. Surviving candidates are grouped by ascending `Deployment.Priority` tier and ordered using `routing_strategy` (optionally gated by `PriorityScheduler`):

| Strategy Value | Selection Algorithm | Best For |
| :--- | :--- | :--- |
| `weighted-shuffle` | Random selection proportional to deployment `weight` ($P(d_i) = w_i / \sum w_j$). | Traffic splitting (e.g., 80% Groq / 20% OpenAI). |
| `round-robin` | Atomic deterministic rotation across healthy peers in the tier. | Even request distribution across homogeneous nodes. |
| `least-busy` | Picks deployment with lowest shared in-flight request count. | Long-running streaming & reasoning workloads. |
| `latency-based` | Picks lowest shared time-to-first-token EWMA (alpha 0.3); uses a 250 ms baseline for deployments without a sample. | Latency-critical interactive chat. |
| `fastest-response` | Dispatches staggered hedged requests (`hedge_delay_ms`, `max_hedge_concurrency`) and commits to the first responder. | Ultra-low tail-latency tolerance (P99 shielding). |
| `usage-based-headroom` | Picks deployment with most remaining TPM capacity over a 1-minute window. | Avoiding provider token limits across deployments. |
| `lowest-cost` | Picks deployment with lowest `(InputCostMicrosPer1M + OutputCostMicrosPer1M)`. | Cost-optimized batch processing. |

Adaptive strategies, affinity pins, and bandit updates share expiring state through Redis. If shared state cannot be read or updated, routing degrades gracefully to process-local observations, increments `gw_routing_signal_degraded_total`, and emits a structured `routing_signal_store_unavailable` warning.

### YAML Configuration (`configs/config.yaml`)
```yaml
router:
  pre_router_mode: "heuristic" # "heuristic" | "semantic" | "quality" | "adaptive"
  default_fast_alias: "fast"
  default_reasoning_alias: "reasoning"
  default_coding_alias: "coding"
  complexity_threshold: 0.40
  long_context_tokens: 32000
  health_staleness_threshold: 90s
  strict_capacity_filtering: true
  session_affinity_ttl: 30m
  session_affinity_repin_on_failover: true
  prompt_cache_affinity: true
  cache_aware_routing: true
  hedge_delay_ms: 150
  max_hedge_concurrency: 2
  scheduler:
    enabled: true
    max_queue_depth: 256
    max_wait_time: 2s
    default_priority: 0
```

---

## Dual-Boundary Auth, 4-Layer RBAC & Credential Vault

### Dual-Boundary Security Architecture
- **Boundary 1 (Client $\rightarrow$ Gateway)**: Clients authenticate with Gateway-issued **Virtual API Keys (`sk-gw-...`)** (via `Authorization: Bearer`, `x-api-key`, `api-key`, `x-goog-api-key`, or `auth.custom_api_key_header`; conflicting credentials across sources are rejected). Only the **SHA-256 hex digest** is persisted; the raw key is returned once upon creation. Validated via a 2-tier cache (**L1 In-Process RWMutex Map** + **L2 Redis Cache** with instant Pub/Sub invalidation).
- **Enterprise Federation, SSO, Provisioning & Key Rotation**:
  - **Multi-Issuer OIDC & Introspection**: Configure `auth.enable_data_plane_jwt`, `auth.oidc_issuers[]` (per-issuer asymmetric JWKS/Discovery, claim mappings, email domain allowlists), and `auth.introspection` (RFC 7662 / OIDC UserInfo, supporting `issuer` / `discovery_url`). Bind human identities explicitly by `(org_id, oidc_issuer, oidc_subject)`.
  - **Operator OIDC SSO & CLI Login**: Browser sessions authenticate exclusively via standard OpenID Connect (`type: "oidc"`, PKCE `S256`, `state`, `nonce`, `at_hash`) and receive signed `goroute_session` cookies plus `X-CSRF-Token` validation on mutations; `/auth/logout` supports RP-Initiated Logout (`end_session_url`), and emergency break-glass access remains available via `GATEWAY_MASTER_ADMIN_KEY`.
  - **SCIM 2.0 Provisioning & Key Rotation Grace Periods**: `/scim/v2/Users` and `/scim/v2/Groups` apply user and team membership changes in tenant-scoped atomic transactions. Scheduled or manual key rotations (`POST /admin/v1/keys/{keyID}/rotate`) support dual-valid grace windows emitting `X-Gateway-Key-Deprecated` and `X-Gateway-Key-Revoke-At`.
- **Boundary 2 (Gateway $\rightarrow$ Upstream Provider)**: Upstream vendor keys (`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `GROQ_API_KEY`, `OPENROUTER_API_KEY`) are encrypted using **AES-256-GCM Envelope Encryption** (or resolved via opt-in `auth.allow_ambient_cloud_iam` / `storage.rds_iam`):
  - Every credential gets a unique random 32-byte **Data Encryption Key (DEK)** + 12-byte `DataNonce`.
  - The DEK is encrypted by the gateway's 32-byte **Master Key Encryption Key (`master_encryption_key`)** + 12-byte `DEKNonce`.

> [!WARNING]
> **Production Key Hardening**: In production environments (`ENV=production` or `GATEWAY_ENV=production`), `Config.Validate()` strictly enforces that `auth.master_admin_key` and `auth.master_encryption_key` must be overridden with non-default, high-entropy secrets. Leaving default demo keys in production results in a fatal startup error.

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

## Retries, Priority Tiers, Specialized Fallbacks & Mid-Stream Recovery

### How High-Availability Failover Works
1. **Per-Exception `RetryPolicy` & Error Classification**:
   - `retry_policy` configures distinct retry budgets per error class (`rate_limit_retries`, `timeout_retries`, `server_error_retries`, `auth_error_retries`, `not_found_retries`, `bad_request_retries`, `default_retries`).
   - `401 Unauthorized`, `403 Forbidden`: Classified as **AuthFailure** — immediately trips the deployment's circuit breaker to `OPEN` and fails over unless blocked by the lone-deployment safety net.
   - `400 Bad Request`: Non-retryable client error unless classified as `context_length_exceeded` / content-policy violation eligible for specialized fallbacks.
2. **Full-Jitter Exponential Backoff**:
   $$\text{sleep} = \text{rand}\left(0,\ \min\left(\text{MaxDelay},\ \text{BaseDelay} \times 2^{\text{attempt}}\right)\right)$$
   Honors upstream `Retry-After` headers when $\le \text{MaxDelay}$.
3. **3-State Circuit Breaker & Adaptive Cooldowns (`CooldownPolicy`)**:
   - Trips from `CLOSED` to `OPEN` when failure counts reach `failure_threshold` (`allowed_fails` per class) within `failure_window` **or** when 1-minute failure rates exceed `cooldown_policy.failure_rate_threshold` at or above `min_requests_per_minute`.
   - Includes a **lone-deployment safety net**: when only one deployment exists for an org/model group, non-auth transient errors avoid locking out 100% of traffic indefinitely.
   - With Redis configured, an atomic shared lease admits one `HALF_OPEN` probe across replicas before closing or extending backoff up to `max_cooldown_seconds`.
4. **Priority Tier Walk (`Deployment.Priority`) & Specialized Fallback Chains**:
   - Within a `ModelGroup`, healthy deployments in ascending `priority` tiers (e.g. `0` → `1` → `2`) are exhausted before stepping across groups (`X-Gateway-Tier-Stepdowns`).
   - `ReliabilityManager` routes `context_length_exceeded` errors via `context_window_fallbacks`, content/safety blocks via `content_policy_fallbacks`, and generic errors via `fallback_targets` (with per-target parameter `overrides`), legacy `fallbacks`, or global `router.default_fallbacks` (bounded by `max_fallback_depth`).
5. **Mid-Stream SSE Continuation (`StreamContinuationManager`)**:
   - When `enable_mid_stream_continuation: true` is configured, plain-text streaming interruptions retry via seamless assistant prefill with adjusted `max_tokens` (`max_stream_continuations`) and emit `X-Gateway-Stream-Continued: true`.

### YAML & SDK Configuration
```yaml
router:
  default_max_retries: 2
  base_retry_delay: 50ms
  max_retry_delay: 2s
  default_cooldown: 60s
  failure_window: 30s
  failure_threshold: 3
  max_fallback_depth: 16
  enable_mid_stream_continuation: true
  max_stream_continuations: 1
  retry_policy:
    rate_limit_retries: 3
    timeout_retries: 2
    server_error_retries: 2
  cooldown_policy:
    failure_rate_threshold: 0.50
    min_requests_per_minute: 20
    max_cooldown_seconds: 300
  default_fallbacks:
    - target: "safe-backup"

model_list:
  - model_name: "production-chat"
    context_window_fallbacks:
      - target: "long-context-claude"
        overrides: { max_tokens: 4096 }
    content_policy_fallbacks:
      - target: "backup-claude"
    fallback_targets:
      - target: "backup-claude"
    model_params:
      model: "openai/gpt-4o-mini"
      api_key: "os.environ/OPENAI_API_KEY"
      priority: 0
      region: "us-east"
      tags: ["tier:primary"]
  - model_name: "backup-claude"
    model_params:
      model: "anthropic/claude-sonnet-4-20250514"
      api_key: "os.environ/ANTHROPIC_API_KEY"
      priority: 1
```

---

## FinOps Usage, Micro-Dollar Cost Tracking & Budgets

### Integer Pico/Micro-Dollar Cost Formula
To eliminate IEEE-754 floating-point drift across millions of transactions, all pricing and spend ledgers use **64-bit integer micro-dollars** ($1\text{ USD} = 1,000,000\text{ micro-USD}$), computed via **pico-dollars** ($10^{-12}\text{ USD}$) with half-up rounding:

$$\text{picos} = (\text{UncachedPrompt} \times \text{InRate}) + (\text{CachedPrompt} \times \text{CacheRate}) + (\text{Completion} \times \text{OutRate}) + (\text{Reasoning} \times \text{ReasonRate})$$

$$\text{CostMicros} = \left\lfloor \frac{\text{picos} + 500,000}{1,000,000} \right\rfloor$$

### Non-Blocking Async Spend Worker & Hard Budgets
- **Hot Path ($0\text{ ms}$ DB Blocking)**: After every inference call, `SpendWorker.Enqueue()` synchronously commits a durable outbox event and pushes a `SpendEvent` into a `16,384`-slot buffered Go channel flushed in batches of `250` every `500ms`.
- **Multi-Dimensional Quotas & Multi-Window Budgets**: Configure `MaxBudgetMicros` and `BudgetResetPeriod` across **Virtual Key**, **Team**, **Organization**, **User**, **End User** (`/admin/v1/end-users`), **Tag** (`/admin/v1/tags`), **Model Access Group** (`/admin/v1/model-access-groups`), per-model `/admin/v1/quotas`, **Deployment**, and **Provider** levels, plus simultaneous **Multi-Window Budgets** (`/admin/v1/budget-windows`: `hourly`, `daily`, `weekly`, `monthly`, `rolling_24h`, `never`).
- **Soft Budget Alerts, Throttling & Temp Increases**: Configure `finops.soft_budget_webhook_url`, `finops.soft_budget_cooldown_sec`, `finops.budget_exceeded_throttle_pct`, per-key budget model fallback, and temporary budget boosts (`POST /admin/v1/keys/{keyID}/temp-budget`). Configure `router.priority_capacity` alongside `/admin/v1/deployments/{depID}/ptu-shares` and `/admin/v1/priority-classes` for Provisioned Throughput Unit guarantees and elastic borrowing.
- **Fail-Closed Estimate Requirements**: Budgeted chat, completion, Anthropic Messages, Responses, embeddings, image generation/edit/variation, and audio speech requests require known pricing and a deterministic pre-dispatch upper bound. For routed aliases, the reservation uses the maximum verified/custom rates available across matching catalog models. Embeddings use input byte length as a conservative token bound. Audio transcription, moderation, Realtime, and Batch currently return `503 budget_estimate_unavailable` before upstream dispatch/session/job creation. Redis unavailability prevents a budgeted request from dispatching unless `rate_limit.fallback_to_local_on_outage: true` is explicitly configured for single-replica degradation. Reservations expire after one hour if a process crashes before settlement; this can temporarily reduce available budget until expiry.

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
    "global_model_id": "openai/gpt-4o-mini",
    "input_cost_micros_per_1m": 150000,
    "output_cost_micros_per_1m": 600000
  }'
```

---

## Rate Limiting & Deterministic Response Caching

### Part A: Multi-Level Atomic Rate Limiting (RPM, TPM, TPD & Concurrency)
1. **Model-Specific BPE Pre-Flight Token Estimation**: Estimates input tokens using family-specific character-to-token ratios (`3.2` for Claude, `3.5` for GPT-4o/4.1/o3, `3.8` for Llama/open-weight models) + per-message chat template overhead + `1024` reserve when `reasoning_effort` is active.
2. **Single-Roundtrip Redis Lua Quota Check & Post-Response Reconciliation**: `check_descriptors.lua` atomically verifies RPM, TPM, ITPM, OTPM, TPD, Concurrency, Session Iterations, and Spend/Multi-Window Budgets across Key, Team, User, Org, End-User, Tag, Model-Access-Group, and per-model descriptors in 1 RTT, then `reconcile_descriptors.lua` reconciles `actual - estimated` tokens and replaces the micro-dollar reservation with settled spend.
3. **`rolling_24h` Windows & Cold Recovery Boundary**: In `rolling_24h` windows, settled spend expires 24 hours after its spend timestamp (`gw:dq:{org:<org_id>}:r24h:<entity>`). On cold or evicted Redis state, `AcquireDescriptors` loads timestamped PostgreSQL `spend_logs` (plus any unexpired migration hold) and initializes Redis atomically with admission (`503 quota_policy_unavailable` if PostgreSQL history cannot load). Note the recovery boundary: PostgreSQL restores persisted spend after complete Redis state loss; Redis-only in-flight reservations and settlements not yet persisted to PostgreSQL cannot be reconstructed from that history.
4. **Fail-Closed Redis Availability**: Requests with configured limits require shared Redis counters by default (`fallback_to_local_on_outage: false`). If Redis is unavailable, the gateway returns `HTTP 503 rate_limiter_unavailable`.

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
  max_l1_entries: 4096
```

```go
// Temperature 0.0 enables deterministic exact-match caching
r1, _ := gw.Chat(ctx, "fast", "What is 2 + 2?", gateway.WithTemperature(0.0)) // CacheStatus="MISS"
r2, _ := gw.Chat(ctx, "fast", "What is 2 + 2?", gateway.WithTemperature(0.0)) // CacheStatus="HIT", CostMicros=0
```

---

## Cross-Cutting Platform Modules (Guardrails, Validation & Observability)

### Module A: Security Guardrails Engine & Multi-Provider Pipeline

GoRoute combines a **Layer 0** per-organization baseline policy (`POST /admin/v1/organizations/{orgID}/guardrails`) with a **Layer 1** Named Guardrail Registry & Hierarchical Binding Pipeline (`internal/guardrails`):

- **Layer 0 Baseline Policy (`guardrail_policies`)**:
  - **Prompt Injection & Jailbreak Detection**: Checks text against normalized override signatures (`ignore previous instructions`, `disregard your system prompt`, `you are now dan`, etc.).
  - **PII & Secret Detection/Redaction**: Detects email addresses (`[REDACTED_EMAIL]`), SSNs (`[REDACTED_SSN]`), Luhn-validated credit cards (`[REDACTED_CARD]`), and sensitive API key patterns (`[REDACTED_SECRET]`).
  - **Built-in Toxicity & Content Filtering**: Evaluates prompts and outputs across 5 selectable categories (`harm_toxic_abuse`, `harmful_violence`, `harmful_self_harm`, `denied_insults`, `bias`) with `low`/`medium`/`high` severity thresholds and custom `content_exceptions`, persisted in PostgreSQL (`0016`).
  - **Configurable Modes & Actions**: `"block"`, `"redact"`, or `"audit"` actions under `"enforce"` or `"logging_only"` mode (`0010`), plus custom blocked keywords.
- **Layer 1 Named Guardrail Registry & Hierarchical Bindings (`guardrail_definitions` & `guardrail_bindings`)**:
  - **15 Built-In Drivers**: `local_content_filter`, `custom_code` (sandboxed Starlark executing `def apply_guardrail(inputs, request_data, input_type):` with deterministic step/timeout caps and SSRF-checked `http_get`/`http_post`), `generic_http` (rich webhook payload with `modify` support and independent per-scanner timeouts/fail-open policies), `llm_as_a_judge`, `decision_model`, `openai_moderation`, `presidio`, `lakera_v2`, `guardrails_ai`, `pangea`, `tool_permission`, `tool_policy` (cross-turn untrusted->trusted taint tracking), `block_code_execution`, `mcp_security`, and `mcp_end_user_permission`. Upstream MCP hops also support `mcp_jwt_signer` token verification, claim transforms, and short-lived Vault JWT signing.
  - **7 Lifecycle Hooks & Scopes**: Supports `pre_call`, parallel `during_call` (cancels upstream dispatch immediately on violation), `post_call`, async `logging_only`, `pre_mcp_call`, `during_mcp_call`, and `post_mcp_call`; configurable per-hook `stream_scope` (`both`, `streaming`, `non_streaming`), tag-driven `mode_rule` matrices, weighted load balancing with cooldowns across same-named definitions, and anti-bypass `default_on` / `is_locked` enforcement.
- **Endpoint & Streaming Coverage**: Text input/output checks run across `/v1/chat/completions`, `/v1/completions`, `/v1/messages`, `/v1/responses`, `/v1/embeddings`, `/v1/moderations`, `/v1/images/*`, `/v1/audio/*`, `/v1/realtime`, Batch items, MCP hubs, and A2A flows. SSE streaming responses are scanned chunk-by-chunk through bounded rolling-overlap buffers (`StreamRedactor` and `StreamWindowEvaluator`) plus incremental streamed `tool_calls` delta inspection, masking or halting the stream immediately if sensitive content crosses chunk boundaries.
- **Fail-Closed Policy Lookup**: If policy storage is unavailable, requests fail closed with `503 guardrail_policy_unavailable` before dispatch (or withhold outputs). A confirmed missing policy allows the request cleanly unless named `default_on` or locked guardrails apply.
- **Standalone Evaluation API**: Virtual Keys authorized for `POST /v1/guardrails/apply` can evaluate any active named guardrail against texts, messages, tools, or tool calls without upstream LLM calls.

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
    "redact_output_pii": true,
    "enable_toxicity_filter": true,
    "toxicity_action": "block",
    "toxicity_threshold": "medium"
  }'
```

#### Declarative YAML Seeding (`configs/config.yaml`)
Seed external HTTP webhooks (`guardrails.scanners[]`), named driver definitions (`guardrails.definitions[]` with Vault-encrypted `secrets`), and tool trust rules (`guardrails.tool_policies[]`) at startup:

```yaml
guardrails:
  scanners:
    - name: "dlp-webhook"
      url: "https://guardrails.internal.corp/v1/scan"
      timeout_ms: 2000
      fail_open: false
      headers:
        Authorization: "os.environ/GUARDRAIL_SCANNER_TOKEN"
  definitions:
    - name: "pii-shield"
      provider: "local_content_filter"
      event_hooks: ["pre_call", "post_call"]
      stream_scope: "both"
      default_on: true
      status: "active"
      config:
        action: "modify"
      bindings:
        - team_id: "team_security"
          is_locked: true
  tool_policies:
    - tool_name: "shell_exec"
      input_policy: "blocked"
      output_policy: "untrusted"
```

#### Embedded Go SDK Guardrail Scanners (`pkg/gateway`)
Applications embedding GoRoute can attach in-process `gateway.GuardrailScanner` implementations supporting `allow`, `block`, `flag`, and `modify` decisions, per-scanner timeouts, hooks, precedence, and fail-open control:

```go
gw, err := gateway.New(
    gateway.WithGuardrailScanner("custom-policy", gateway.GuardrailScannerFunc(
        func(ctx context.Context, req gateway.GuardrailScanRequest) (gateway.GuardrailScanResult, error) {
            return gateway.GuardrailScanResult{Decision: gateway.GuardrailDecisionAllow}, nil
        },
    ), gateway.WithGuardrailTimeout(1500*time.Millisecond), gateway.WithGuardrailDefaultOn(true)),
)
```

For lower-level internal embedding, `GatewayServer.ConfigureGuardrailScanners` continues to accept `guardrails.Scanner` implementations routed through the gateway network policy.

### Module B: Pre-Flight Request Validator
Validates parameters (`temperature` in `[0, 2]`, `top_p` in `[0, 1]`), model capabilities (`supports_tools`, `supports_reasoning`), and context window limits (`estPromptTokens + maxTokens <= GlobalModel.MaxInputTokens`) before consuming upstream quota.

### Module C: Observability, W3C Tracing & Active Health Monitor
- **Prometheus Metrics (`GET /metrics`)**: Requires the Master Admin Key in the `Authorization: Bearer` header. Scrape from a trusted monitoring network. The endpoint exposes gateway/provider aggregates, stream duration/errors/TTFT, Go heap and GC counters, response-cache L1/L2 hits and epoch lookup latency, budget reservation checks and their share of recorded requests, catalog size, and Postgres read-through misses. Upstream HTTP protocol, connection reuse, dials, TLS handshakes, first-byte timing, and idle-timeout counters are included when the gateway creates its default outbound client; an injected `http.Client` owns its own transport and metrics. Per-deployment identifiers are omitted to keep metric cardinality bounded.
- **Distributed Tracing**: Set `tracing.otlp_endpoint` to an OTLP/HTTP traces URL such as `https://collector.example:4318/v1/traces`. Tracing is disabled when the endpoint is empty. The exporter uses the outbound SSRF/network policy and supports optional `tracing.headers` for collector authentication.
- **JSON Telemetry Snapshot (`GET /admin/v1/observability/metrics`)**: Real-time P50/P95/P99 latency and per-provider/per-deployment health breakdown.
- **Active Health Monitor (`GET /admin/v1/health/deployments` & `POST /admin/v1/health/probe`)**: Periodically probes upstream credentials and preemptively marks failing deployments unhealthy before user traffic hits them.

---

## Complete Configuration & Environment Variable Reference

| YAML Path | Environment Variable Override | Default | Description |
| :--- | :--- | :--- | :--- |
| `server.host` | — | `"0.0.0.0"` | HTTP network bind address. |
| `server.port` | `GATEWAY_PORT` | `8080` | HTTP listen port (1–65535). |
| `server.grpc_port` | `GATEWAY_GRPC_PORT` | `0` | Optional A2A gRPC listen port (`0` disables gRPC; `1–65535` enables). |
| `server.cors_allowed_origins` | `GATEWAY_CORS_ALLOWED_ORIGINS` | `[]` | Allowed CORS origins (empty disables CORS headers; wildcard `*`, `"null"`, and non-HTTPS origins are rejected in production). |
| `server.cors_allow_credentials` | — | `false` | Allows `Access-Control-Allow-Credentials: true` (rejected if origins include `*`). |
| `server.enable_hsts` | — | `false` | Emits `Strict-Transport-Security` header on HTTP responses. |
| `server.max_file_storage_bytes_per_org` | `GATEWAY_MAX_FILE_STORAGE_BYTES_PER_ORG` | `5368709120` | Per-organization file storage quota in bytes (`5 GiB` default; `0` = unlimited). |
| `server.max_concurrent_file_uploads` | `GATEWAY_MAX_CONCURRENT_FILE_UPLOADS` | `8` | Maximum concurrent `/v1/files` uploads (`0` = unlimited). |
| `server.read_timeout` | — | `30s` | Maximum duration for reading the entire request. |
| `server.write_timeout` | — | `300s` | Maximum duration before timing out writes of the response (sized for reasoning streams). |
| `server.idle_timeout` | — | `120s` | Maximum amount of time to wait for the next request when keep-alives are enabled. |
| `server.shutdown_timeout` | — | `15s` | Graceful shutdown timeout before closing active connections. |
| `providers.request_timeout` | — | `2m` | Total deadline for non-streaming upstream provider requests. |
| `providers.response_header_timeout` | — | `2m` | Maximum wait for upstream response headers, including model prefill/TTFT. |
| `providers.stream_idle_timeout` | — | `2m` | Maximum gap between upstream response-body chunks, including streams. |
| `providers.max_idle_conns` | — | `256` | Maximum retained idle provider connections across all hosts. Tune using dial and connection-reuse metrics. |
| `providers.max_idle_conns_per_host` | — | `16` | Maximum retained idle connections per host. Tune using protocol, dial, and connection-reuse metrics. |
| `logging.level` | `GATEWAY_LOG_LEVEL` | `"info"` | Log verbosity: `"debug"`, `"info"`, `"warn"`, `"error"`. |
| `logging.format` | `GATEWAY_LOG_FORMAT` | `"text"` | Log encoding: `"json"` (cloud structured) or `"text"` (human readable). Auto-switches to `"json"` if `ENV=production`. |
| `logging.add_source` | `GATEWAY_LOG_ADD_SOURCE` | `false` | When true, annotates log records with caller `file:line`. |
| `storage.mode` | `GATEWAY_STORAGE_MODE` | `"memory"` | Storage backend: `"memory"` (zero external dependencies) or `"postgres"`. |
| `storage.postgres_dsn` | `GATEWAY_POSTGRES_DSN` | `postgres://...` | PostgreSQL connection string (auto-switches storage mode to `"postgres"` when present). |
| `storage.rds_iam.enabled` | — | `false` | Enables dynamic AWS RDS IAM token generation for new PostgreSQL connections and migrations (`sslmode=verify-full`). |
| `storage.rds_iam.region` / `role_arn` / `web_identity_token_file` | — | `""` | Explicit RDS IAM region and credentials/IRSA fields. |
| `storage.redis_addr` | `GATEWAY_REDIS_ADDR` | `"localhost:6379"` | Standalone Redis host:port for L2 auth caching, Lua rate limiting, and response caching. |
| `storage.redis_addrs` | `GATEWAY_REDIS_ADDRS` | `[]` | Comma-separated Redis Cluster or Sentinel seed nodes (takes precedence over `redis_addr`). |
| `storage.redis_master_name` | `GATEWAY_REDIS_MASTER_NAME` | `""` | Redis Sentinel master name when using Sentinel topology. |
| `storage.redis_pass` | `GATEWAY_REDIS_PASS` | `""` | Optional Redis authentication password. |
| `storage.redis_db` | — | `0` | Redis logical database index. |
| `auth.master_admin_key` | `GATEWAY_MASTER_ADMIN_KEY` | `sk-gw-master-...` | Control plane bearer token (min 12 chars; must be changed in `production`). |
| `auth.master_encryption_key` | `GATEWAY_MASTER_ENCRYPTION_KEY` | 64-char hex | 32-byte AES-256-GCM Master Key Encryption Key (must be changed in `production`). |
| `auth.previous_master_encryption_keys` | `GATEWAY_PREVIOUS_MASTER_ENCRYPTION_KEYS` | `[]` | Ordered list (or comma-separated env list) of prior 32-byte KEKs accepted read-only during rolling restarts after KEK rotation. |
| `auth.allow_master_key_data_plane` | `GATEWAY_ALLOW_MASTER_KEY_DATA_PLANE` | `false` | Opt-in flag allowing Master Admin Key on `/v1/*` data plane endpoints (disabled by default). |
| `auth.allow_ambient_cloud_iam` | — | `false` | Opt-in flag allowing ambient `storage.rds_iam` credential resolution. |
| `auth.enable_data_plane_jwt` | `GATEWAY_ENABLE_DATA_PLANE_JWT` | `false` | Enables OIDC/JWT bearer token verification on `/v1/*` data plane routes. |
| `auth.custom_api_key_header` | `GATEWAY_CUSTOM_API_KEY_HEADER` | `""` | Custom header override for virtual key extraction (conflicts across sources are rejected). |
| `auth.jwt_issuer` | `GATEWAY_JWT_ISSUER` | `""` | Default expected JWT `iss` claim for single-issuer verification. |
| `auth.jwt_audience` | `GATEWAY_JWT_AUDIENCE` | `""` | Default expected JWT `aud` claim. |
| `auth.oidc_jwks_url` | `GATEWAY_OIDC_JWKS_URL` | `""` | Single-issuer OIDC JWKS URL (`auth.oidc_issuers[]` preferred for multi-issuer). |
| `auth.oidc_issuers[]` | — | `[]` | Multi-issuer asymmetric OIDC verifier list (`issuer`, `audience`, `jwks_url`, `discovery_url`, `algorithms`, `claim_mapping`, `allowed_email_domains`). |
| `auth.sso_providers[]` | — | `[]` | Browser & CLI OIDC SSO identity providers (`id`, `type: "oidc"`, `client_id`, `client_secret`, `issuer`, `discovery_url`, `redirect_url`, `claim_mapping`, `group_role_mappings`, `group_team_mappings`, `role_mapping_strategy`, `sync_roles_on_login`). |
| `auth.introspection.*` | — | `{}` | RFC 7662 token introspection / OIDC UserInfo verification settings (`issuer`, `discovery_url`, `token_info_endpoint`, `mode`, `cache_ttl`). |
| `auth.external_authorizer.*` | — | `{}` | Optional post-auth external policy authorizer (`enabled`, `mode`: `webhook` \| `opa`, `url`, `timeout`, `fail_mode`: `closed` \| `open`, `cache_ttl`, `auth_header`, `hmac_secret`). |
| `audit.siem_webhook.*` | — | `{}` | Optional async HMAC-SHA256 batched audit sink (`enabled`, `url`, `secret`, `auth_header`, `batch_size`, `flush_interval`, `timeout`, `max_queue_size`). |
| `auth.key_rotation_delivery_url` / `key_rotation_delivery_token` | `GATEWAY_KEY_ROTATION_DELIVERY_URL` / `_TOKEN` | `""` | HTTPS webhook destination and bearer secret required to promote scheduled replacement keys. |
| `auth.key_rotation_sink.*` | `GATEWAY_KEY_ROTATION_SINK_*` | `""` | Declarative secret-manager sink (`driver`: `webhook` or `vault_kv2`; `address`, `mount`, `path_prefix`, `namespace`, `token`). |
| `auth.key_rotation_poll_interval` | `GATEWAY_KEY_ROTATION_POLL_INTERVAL` | `1m` | Background worker interval checking due virtual key rotations and expired grace-hash cleanup. |
| `auth.key_rotation_grace_period` | `GATEWAY_KEY_ROTATION_GRACE_PERIOD` | `24h` | Default grace window during which a rotated key remains valid with deprecation headers. |
| `auth.key_expiry_alert_poll_interval` | — | `1h` | Background poll interval for organization `key_expiry_alert_days` webhook notifications. |
| `auth.session_secret` | `GATEWAY_SESSION_SECRET` | `""` | Signing secret for Control Plane operator cookie sessions (`goroute_session`). |
| `auth.session_ttl` | `GATEWAY_SESSION_TTL` | `0s` (`24h` runtime default) | Lifetime of revocable operator UI sessions in `operator_sessions`. |
| `auth.default_org_id` | — | `"org_default"` | Initial default organization ID seeded at startup. |
| `auth.default_virtual_key` | `GATEWAY_DEFAULT_KEY` | `""` | Optional pre-seeded client virtual key for immediate local testing. |
| `auth.l1_cache_ttl` | — | `15s` | In-memory L1 cache TTL for virtual key identity and permissions. |
| `auth.l2_cache_ttl` | — | `5m` | Redis L2 cache TTL for virtual key identity and permissions. |
| `security.network.outbound_ssrf.allow_loopback_http` | `GATEWAY_ALLOW_LOOPBACK_HTTP` | `false` | Permits plain `http://` strictly to loopback addresses (`127.0.0.1`, `::1`, `localhost`) for local OIDC IdPs like Keycloak dev while blocking private networks. |
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
| `router.default_fallbacks` | — | `[]` | Global fallback targets (`{target, overrides}`) evaluated if group-level chains are exhausted. |
| `router.max_fallback_depth` | `GATEWAY_ROUTER_MAX_FALLBACK_DEPTH` | `16` | Maximum inter-group fallback hops allowed per request. |
| `router.retry_policy.*` | — | `{}` | Per-class retry budgets (`rate_limit_retries`, `timeout_retries`, `server_error_retries`, `auth_error_retries`, `not_found_retries`, `bad_request_retries`, `default_retries`). |
| `router.cooldown_policy.*` | — | `{}` | Adaptive cooldown bounds (`allowed_fails`, `failure_rate_threshold`, `min_requests_per_minute`, `max_cooldown_seconds`). |
| `router.enable_mid_stream_continuation` | `GATEWAY_ROUTER_ENABLE_MID_STREAM_CONTINUATION` | `false` | Enables seamless SSE assistant-prefill recovery on plain-text mid-stream drops. |
| `router.max_stream_continuations` | `GATEWAY_ROUTER_MAX_STREAM_CONTINUATIONS` | `1` | Maximum mid-stream continuation retries permitted per request. |
| `router.health_staleness_threshold` | `GATEWAY_ROUTER_HEALTH_STALENESS_THRESHOLD` | `0s` | Rejects deployments whose last health heartbeat exceeds this age (`0` disables staleness filter). |
| `router.strict_capacity_filtering` | `GATEWAY_ROUTER_STRICT_CAPACITY_FILTERING` | `false` | Enforces strict per-deployment RPM/TPM filtering before load balancer selection. |
| `router.provider_budgets` | — | `{}` | Map of `provider -> max_budget_micros` spending ceiling across deployments. |
| `router.session_affinity_ttl` | `GATEWAY_ROUTER_SESSION_AFFINITY_TTL` | `30m` | TTL for `AffinityStore` session and response deployment pins. |
| `router.session_affinity_repin_on_failover` | `GATEWAY_ROUTER_SESSION_AFFINITY_REPIN_ON_FAILOVER` | `true` | Automatically updates sticky deployment pin when failover succeeds on an alternate node. |
| `router.prompt_cache_affinity` | `GATEWAY_ROUTER_PROMPT_CACHE_AFFINITY` | `false` | Pins requests sharing prefix hashes (`pcache`) to improve upstream prompt cache hit rates. |
| `router.pre_router_mode` | `GATEWAY_ROUTER_PRE_ROUTER_MODE` | `""` | Default Stage 0 pre-router mode (`"heuristic"`, `"semantic"`, `"quality"`, `"adaptive"`). |
| `router.semantic_router.enabled` | — | `false` | Enables embedding cosine-similarity pre-routing (`router/semantic`). |
| `router.semantic_router.embedding_model` | — | `""` | Model alias or ID used to compute semantic centroids and prompt embeddings. |
| `router.semantic_router.similarity_threshold` | — | `0` | Minimum cosine similarity required to match a semantic route. |
| `router.semantic_router.timeout` | — | `0s` | Maximum timeout for semantic embedding calls before falling back. |
| `router.semantic_router.routes[]` | — | `[]` | Intent routes (`name`, `target_model`, `utterances[]`, `description`). |
| `router.cache_aware_routing` | `GATEWAY_ROUTER_CACHE_AWARE_ROUTING` | `false` | Enables prompt-cache-prefix-aware candidate affinity scoring. |
| `router.bandit.enabled` | — | `false` | Enables Thompson-sampling contextual bandit routing (`router/adaptive`). |
| `router.bandit.default_alpha` / `default_beta` | — | `0` | Prior Beta distribution parameters for new bandit arms. |
| `router.bandit.exploration_rate` | — | `0` | Exploration factor controlling random arm sampling. |
| `router.bandit.decay_half_life` | — | `0s` | Exponential decay window applied to historical bandit observations. |
| `router.bandit.latency_weight` / `cost_weight` | — | `0` | Multi-objective weights penalizing latency and token spend in bandit rewards. |
| `router.bandit.sync_interval` | — | `0s` | Background Redis synchronization interval for cluster bandit state. |
| `router.bandit.candidate_models[]` | — | `[]` | Candidate model aliases eligible for adaptive bandit selection. |
| `router.hedge_delay_ms` | `GATEWAY_ROUTER_HEDGE_DELAY_MS` | `0` | Default stagger delay in milliseconds before firing secondary hedged requests (`fastest-response`). |
| `router.max_hedge_concurrency` | `GATEWAY_ROUTER_MAX_HEDGE_CONCURRENCY` | `2` | Maximum parallel hedged attempts per request. |
| `router.scheduler.enabled` | — | `false` | Enables bounded `PriorityScheduler` request queueing. |
| `router.scheduler.max_queue_depth` | — | `0` | Maximum queued requests before rejecting overflow with `503`. |
| `router.scheduler.max_wait_time` | — | `0s` | Maximum queue wait timeout before failing a queued request. |
| `router.scheduler.default_priority` | — | `0` | Default scheduling priority assigned when callers omit `X-Gateway-Priority`. |
| `router.scheduler.max_parallel_wait_ms` | — | `0` | Bounded wait in milliseconds when all candidates hit `max_parallel_requests` before failing or failing over. |
| `router.priority_capacity.*` | — | `false` | Dynamic PTU priority-capacity borrowing (`enabled`, `saturation_threshold`, `active_caller_ttl`, `window_duration`, `default_weight`, `default_borrow_multiple`). |
| `router.latency_tolerance_pct` | — | `0` | Normalized tolerance fraction above the fastest deployment's EWMA latency included in `latency-based` selection. |
| `router.max_honored_retry_after` | — | `60s` | Maximum upstream `Retry-After` duration honored before failing over or bounding sleep. |
| `router.disable_cooldowns` | — | `false` | Disables circuit-breaker cooldown tripping globally across groups (per-group `disable_cooldowns` overrides to `true`). |
| `router.fallback_on_saturation` | — | `false` | Enables fallback chain traversal (`saturation_fallbacks` or general fallbacks) on capacity/concurrency/priority saturation. |
| `router.drop_unsupported_params` | — | `false` | Strips unsupported parameters (`tools`, `response_format`, `reasoning_effort`, O-series `temperature`/`top_p`, OpenAI-only extra params) and clamps `max_tokens` rather than rejecting requests. |
| `router.fallback_on_unsupported_params` | — | `false` | Treats upstream unsupported-parameter responses as failover-eligible without tripping deployment cooldowns. |
| `router.allow_strategy_override` | — | `false` | Allows callers to override `routing_strategy` per request via `X-Gateway-Routing-Strategy` or `goroute_extensions.routing_strategy`. |
| `router.debug_routing_headers` | — | `false` | Emits redacted `X-Gateway-Fallback-Errors` diagnostic header when requests also send `X-Gateway-Debug-Routing: true`. |
| `rate_limit.enabled` | — | `true` | Enables distributed sliding-window rate limiting via Redis Lua. |
| `rate_limit.fallback_to_local_on_outage` | — | `false` | Opt-in in-memory fallback when Redis is unreachable (`false` fails closed with `503`). |
| `rate_limit.window_seconds` | — | `60` | Fixed window duration in seconds for RPM/TPM calculation. |
| `rate_limit.concurrency_ttl_sec` | — | `300` | Lease duration in seconds for concurrent in-flight request locks and distributed `max_parallel_requests` deployment slot leases (`SetDeploymentSlotTTL`). |
| `rate_limit.default_estimated_tpm` | — | `128` | Pre-flight token heuristic estimate when prompt tokens are unmeasured. |
| `rate_limit.redis_timeout` | — | `50ms` | Maximum timeout for Redis Lua rate-limit checks before failing closed. |
| `rate_limit.global_rpm_limit` / `global_tpm_limit` / `global_max_concurrent` | — | `0` | Gateway-wide global rate/concurrency caps (`0` = unlimited). |
| `rate_limit.default_agent_session_max_iterations` / `max_budget_micros` / `ttl_sec` | — | `0` | Default per-agent-session loop, budget, and TTL ceilings (`0` = unlimited). |
| `finops.channel_buffer_size` | — | `16384` | Capacity of asynchronous spend event channel. |
| `finops.batch_size` | — | `250` | Maximum spend events aggregated per database flush. |
| `finops.flush_interval` | `GATEWAY_FINOPS_FLUSH_INTERVAL` | `500ms` | Maximum duration between asynchronous spend ledger flushes. |
| `finops.worker_count` | — | `4` | Number of concurrent background spend processor goroutines. |
| `finops.soft_budget_webhook_url` | `GATEWAY_FINOPS_SOFT_BUDGET_WEBHOOK_URL` | `""` | Webhook URL notified when soft budget thresholds are crossed. |
| `finops.soft_budget_cooldown_sec` | `GATEWAY_FINOPS_SOFT_BUDGET_COOLDOWN_SEC` | `0` (`3600` in example) | Cooldown window in seconds between duplicate soft-budget alerts. |
| `finops.budget_exceeded_throttle_pct` | `GATEWAY_FINOPS_BUDGET_EXCEEDED_THROTTLE_PCT` | `0` (`0.10` in example) | Throttle probability fraction when soft budget throttling applies. |
| `discovery.enabled` | — | `true` | Enables background upstream model catalogue discovery. |
| `discovery.sync_interval` | — | `6h` | Polling interval for model catalogue synchronization worker. |
| `discovery.auto_approve` | — | `false` | When true, auto-enables newly discovered upstream models. |
| `cache.enabled` | — | `true` | Enables deterministic exact-match response caching. |
| `cache.default_ttl` | — | `1h` | Default TTL for exact-match response cache entries. |
| `cache.max_l1_entries` | — | `4096` | Maximum process-local response cache entries. LRU eviction bounds memory use. |
| `guardrails.scanners[]` | — | `[]` | Legacy external webhook scanner list (`name`, `url`, `timeout_ms`, `fail_open`, `headers`). |
| `guardrails.definitions[]` | — | `[]` | Declarative named guardrail definitions seeded into the registry on startup (encrypts `secrets` via Vault). |
| `guardrails.tool_policies[]` | — | `[]` | Declarative per-tool `input_policy` / `output_policy` trust rules seeded on startup. |
| `mcp.enabled` | `GATEWAY_MCP_ENABLED` | `true` | Enables Model Context Protocol (MCP) data plane & control plane. |
| `mcp.default_protocol_version` | — | `"2026-07-28"` | Default active Gateway MCP specification (`2024-11-05`, `2025-03-26`, `2025-06-18`, `2025-11-25`, or `2026-07-28`; overridable at runtime via `PUT /admin/v1/mcp/spec` / Web UI). |
| `mcp.strict_schema_validation` | — | `false` | Validates incoming `/mcp` JSON-RPC payloads against the active release's embedded `schema.yaml` via `jsonschema/v6`. |
| `mcp.allow_stdio_servers` | `GATEWAY_MCP_ALLOW_STDIO` | `false` | Enables local stdio subprocess MCP transport (requires explicit opt-in). |
| `mcp.allowed_stdio_binaries` | — | `[]` | Explicit allowlist of absolute binary paths permitted for stdio transport. |
| `mcp.enable_session_compat_2025` | — | `true` | Enables `StatefulStreamableTransport` session translation for `2025-03-26`, `2025-06-18`, and `2025-11-25` MCP servers. |
| `mcp.session_ttl_2025` | — | `15m` | Session expiration TTL for legacy 2025 MCP connections. |
| `mcp.cache_key_secret` | — | — | HMAC-SHA256 secret for delimiter-collision-proof MCP cache keys (defaults to `auth.master_encryption_key`). |
| `mcp.max_payload_bytes` | — | `10485760` | Maximum allowed payload size for MCP requests (10 MB). |
| `mcp.default_timeout` | — | `30s` | Default execution timeout for upstream MCP tool calls. |
| `mcp.subscriptions_listen_active` | — | `true` | Enables multiplexed SSE subscriptions endpoint (`/mcp/subscriptions/listen`). |
| `a2a.enabled` | `GATEWAY_A2A_ENABLED` | `true` | Enables Agent-to-Agent (A2A v1.0) protocol service. |
| `a2a.enable_jsonrpc` | — | `true` | Enables JSON-RPC 2.0 transport for A2A message exchange. |
| `a2a.enable_http_json` | — | `true` | Enables REST/HTTP+JSON transport for A2A message exchange. |
| `a2a.enable_subscribe_post_compat` | — | `false` | Allows legacy `POST /tasks/{id}:subscribe` in addition to canonical `GET`. |
| `a2a.allow_legacy_card_discovery` | — | `false` | Allows unsigned or legacy uncanonicalized agent card discovery. |
| `a2a.max_task_lifespan` | — | `24h` | Maximum durability lifespan for active A2A task records. |
| `a2a.stream_buffer_capacity` | — | `256` | Per-task SSE event streaming buffer capacity. |
| `a2a.stream_publish_interval` | — | `50ms` | Interval for background task stream publication daemon. |
| `a2a.max_push_retries` | — | `5` | Maximum retry attempts for transactional outbox webhooks before DLQ. |
| `a2a.signing_key_id` | `GATEWAY_A2A_SIGNING_KEY_ID` | `"gw-a2a-signer-v1"` | Key ID for RFC 8785 JCS / JWS Agent Card signing. |
| `a2a.allowed_signing_algs` | — | `["ES256", "RS256", "EdDSA"]` | Allowed cryptographic signature algorithms for inbound Agent Cards. |
| `a2a.trusted_card_jwks` | — | `{}` | Upstream agent slug -> JWKS URL mapping for card verification. |
| `security.network.outbound_ssrf.egress_proxy_url` | — | `""` | Corporate HTTP/HTTPS egress proxy URL for enterprise outbound firewalls. |
| `security.network.outbound_ssrf.allow_private_networks` | `GATEWAY_SECURITY_SSRF_ALLOW_PRIVATE` | `false` | Enables private/internal IP egress (must remain false in production). |
| `security.network.outbound_ssrf.allowed_private_cidrs` | `GATEWAY_SECURITY_SSRF_ALLOWED_PRIVATE_CIDRS` | `[]` | Explicit private VPC CIDR allowlist (e.g. `["10.20.0.0/16"]`); in production, prefix length must be `>= /8` (IPv4) / `>= /7` (IPv6) and must not overlap loopback, link-local, multicast, or cloud IMDS ranges. |
| `security.network.outbound_ssrf.allow_insecure_http` | `GATEWAY_SECURITY_SSRF_ALLOW_INSECURE_HTTP` | `false` | Allows plaintext HTTP upstream requests. |
| `security.network.outbound_ssrf.allowed_schemes` | — | `["https"]` | Allowed URL schemes for provider endpoints (`https`, `http`). |
| `security.network.outbound_ssrf.blocked_ips` | — | `["169.254.169.254", ...]` | Cloud metadata and sensitive IP addresses blocked from egress. |
| `security.network.outbound_ssrf.dial_timeout` | — | `10s` | Network connect and TLS handshake timeout for provider egress. |
| `security.network.outbound_ssrf.max_redirects` | — | `3` | Maximum HTTP redirect hops permitted on outbound provider calls. |
| `security.network.inbound_caller.expose_on_public_internet` | — | `false` | Network policy flag documenting internet exposure stance. |
| `security.network.inbound_caller.allowed_client_cidrs` | — | `[]` | Client CIDR allowlist for incoming network requests. |
| `model_list[].model_name` | — | — | Virtual model name or alias presented to clients (`"fast"`, `"reasoning"`). |
| `model_list[].routing_strategy` | — | `"weighted-shuffle"` | Routing policy: `"weighted-shuffle"`, `"round-robin"`, `"least-busy"`, `"latency-based"`, `"fastest-response"`, `"usage-based-headroom"`, `"lowest-cost"`. |
| `model_list[].fallbacks` | — | `[]` | Ordered array of fallback model names triggered on upstream outage or rate-limit. |
| `model_list[].context_window_fallbacks` | — | `[]` | Ordered specialized fallback targets (`{target, overrides}`) triggered on `context_length_exceeded`. |
| `model_list[].content_policy_fallbacks` | — | `[]` | Ordered specialized fallback targets triggered on content-policy/safety blocks. |
| `model_list[].fallback_targets` | — | `[]` | Structured generic fallback targets with per-target request parameter `overrides`. |
| `model_list[].saturation_fallbacks` | — | `[]` | Ordered specialized fallback targets triggered on saturation when `router.fallback_on_saturation` is true. |
| `model_list[].drop_unsupported_params` | — | `false` | Group-level parameter stripping toggle overriding `router.drop_unsupported_params`. |
| `model_list[].disable_cooldowns` | — | `false` | Group-level toggle suppressing circuit-breaker cooldown tripping. |
| `model_list[].model_params.model` | — | — | Upstream provider/model identifier (e.g. `"openai/gpt-4o-mini"`, `"groq/llama-3.1-8b-instant"`). |
| `model_list[].model_params.api_key` | — | — | Upstream provider API key (supports `os.environ/VAR`). |
| `model_list[].model_params.api_base` | — | `""` | Custom upstream base URL override. |
| `model_list[].model_params.region` | — | `""` | Region tag for deployment affinity/region filtering. |
| `model_list[].model_params.priority` | — | `0` | Numeric priority tier (`0` is highest priority; lower tiers are exhausted before higher ones). |
| `model_list[].model_params.tags` | — | `[]` | Deployment tags matched by request `&`/`!` tag filter expressions and enforced against team/key `allowed_routing_tags`. |
| `model_list[].model_params.max_budget_micros` | — | `0` | Per-deployment spend cap in integer micro-dollars (`0` = unlimited). |
| `model_list[].model_params.budget_reset_period` | — | `"monthly"` | Deployment spend reset cadence (`"hourly"`, `"daily"`, `"weekly"`, `"monthly"`, `"never"`). |
| `model_list[].model_params.weight` | — | `100` | Integer weight for weighted load balancing. |
| `model_list[].model_params.rpm` | — | `0` | Per-deployment Requests Per Minute capacity limit. |
| `model_list[].model_params.tpm` | — | `0` | Per-deployment Tokens Per Minute capacity limit. |
| `model_list[].model_params.itpm` | — | `0` | Per-deployment Input Tokens Per Minute capacity limit (persisted as `itpm_capacity` in Admin API / OpenAPI / database). |
| `model_list[].model_params.otpm` | — | `0` | Per-deployment Output Tokens Per Minute capacity limit (persisted as `otpm_capacity` in Admin API / OpenAPI / database). |
| `model_list[].model_params.max_parallel_requests` | — | `0` | Distributed per-deployment concurrent in-flight request limit (`0` = unlimited). |
| `model_list[].model_params.headers` | — | `{}` | Custom HTTP headers forwarded to the upstream model provider. |
| `files.storage_dir` | `GOROUTE_FILES_DIR` | `os.TempDir()/goroute-files` | Local disk directory for stateful tenant files and batch JSONL files (enforces `0700` directory mode and `0600` file mode). |

### Provider Options
- All supported upstream providers (`openai`, `anthropic`, `groq`, `openrouter`) are OpenAPI-backed with explicit per-adapter capabilities and operation sets.
- Imported catalog pricing defaults to `PricingStatusUnknown` (non-zero rates) or `PricingStatusUnrecorded` (zero rates); budgeted traffic requires `PricingStatusVerified` or `PricingStatusCustom` plus a deterministic pre-dispatch bound.

### Federated identity, key delivery, and upstream IAM

Link an existing user with the `oidc_issuer` and `oidc_subject` fields on the admin user API. The issuer must match the verified provider issuer, and the subject must match the configured subject claim. The gateway searches for this pair within the resolved organization. Legacy subject-only JWT links are accepted only with one enabled verifier and an unambiguous match. Browser SSO requires an issuer-bound link or explicit JIT provisioning.

Operator authentication uses OpenID Connect Authorization Code + PKCE (`S256`) configured under `auth.sso_providers` (with emergency break-glass access via `GATEWAY_MASTER_ADMIN_KEY`), plus developer CLI login via `cmd/goroute` (`goroute login` driving `/auth/cli/start` → `/ui/cli` → `/auth/cli/poll`). In production (`GATEWAY_ENV=production`), configure `server.public_base_url` (or explicit HTTPS `redirect_url`), a `>= 32`-byte `auth.session_secret` (`GATEWAY_SESSION_SECRET`), and per-issuer `audience` on all `auth.oidc_issuers[]`; global `allow_private_networks`, `allow_insecure_http`, and `allow_loopback_http` are rejected at startup (use targeted `allowed_private_cidrs` for internal VPC endpoints). Email-domain restrictions enforce `email_verified: true` unless `allow_unverified_email: true` is explicitly set, and JIT or group-mapped `platform_admin` role claims require `allow_privileged_role_claims: true`. Enable `sync_roles_on_login: true` with `group_role_mappings` / `group_team_mappings` and `claim_mapping.groups` to synchronize IdP group role/team changes on every login and immediately revoke prior operator sessions and caches on demotion.

For fine-grained data-plane and control-plane authorization, configure `allowed_deployments`, mandatory `allowed_routing_tags` (pruning candidate deployments even when callers omit routing tag headers), positive 3-state `allowed_mcp_tools` / `allowed_mcp_toolsets` alongside unconditional `ToolPolicy` enforcement on direct `/mcp` routes, Unified Access Groups (`/admin/v1/access-groups` covering models, MCP servers, MCP tools, and A2A agents), and optional `auth.external_authorizer` (`webhook` or OPA REST API with `X-GoRoute-Signature-256` HMAC signing) plus `audit.siem_webhook` over GoRoute's SSRF-protected outbound transport.

Scheduled key rotation requires either an in-process Go SDK `KeySecretSink`, `auth.key_rotation_delivery_url` + `auth.key_rotation_delivery_token`, or a declarative `auth.key_rotation_sink` (`webhook` or `vault_kv2`). Both `Deliver` webhooks and `SecretSink` pushes execute transactionally inside scheduled rotation sweeps with strict SSRF controls (`https://` only, redirects disabled, private IP checks) and reuse the same AES-GCM-encrypted staged replacement across transient delivery failures until a `2xx` response promotes the key and begins the old key's grace window. Delivery success/failure counters are exported as `gateway_key_rotation_deliveries_total` and `gateway_key_rotation_delivery_failures_total`. Manual rotations return the replacement directly to the authorized caller.

For zero-downtime master KEK rotation (`POST /admin/v1/security/rotate-kek`), `RotateKEKsTransactionally` atomically re-wraps all provider credentials, MCP servers, A2A agents, guardrail definitions, and `virtual_keys.staged_key_dek` rows before promoting the new KEK locally. During rolling multi-pod restarts, keep the retired key in `auth.previous_master_encryption_keys` (or `GATEWAY_PREVIOUS_MASTER_ENCRYPTION_KEYS`) until all replicas have rolled onto the new primary KEK.

For RDS IAM, enable `storage.rds_iam.enabled`, set the region, and use the actual RDS endpoint and database user in a PostgreSQL DSN with `sslmode=verify-full`. Both startup and migration-only mode refresh IAM tokens on new connections. Use explicit credentials or configure the role and web identity token file. Set `auth.allow_ambient_cloud_iam` to opt in to RDS ambient credential resolution. Gateway replicas sharing a Redis upstream cache must use the same master encryption key.
