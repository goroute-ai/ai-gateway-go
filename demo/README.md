# GoRoute AI Gateway — Hands-On Demonstration Suite (`demo/`)

Welcome to the **GoRoute AI Gateway** hands-on demonstration suite. Each core system of the gateway has a dedicated, self-contained runnable Go program in this directory.

All demos run out-of-the-box with **zero external setup**:
- If you have live provider API keys set in your environment (`GEMINI_API_KEY`, `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`), the demos automatically use them.
- If no keys are set, the demos automatically fall back to built-in, zero-setup local mock providers via `gateway.WithDemoMocksIfEnvMissing()`.

---

## Capabilities & Demos Index

| System | Directory | Execution Command | Core Capability Demonstrated |
| :--- | :--- | :--- | :--- |
| **System Overview** | [`demo/main.go`](./main.go) | `go run ./demo` | Routing modes: Explicit Model, Logical Alias (`"fast"`), and Zero-LLM Smart Auto-Router (`"auto"`). |
| **Unified API & SSE Streaming** | [`demo/01_unified_api`](./01_unified_api/main.go) | `go run ./demo/01_unified_api` | Synchronous Chat, Zero-Buffer SSE Token Streaming (`StreamChat`), System Prompts, Telemetry Headers. |
| **Model Management & Wildcard Routing** | [`demo/02_model_management`](./02_model_management/main.go) | `go run ./demo/02_model_management` | Declarative model configuration, 4-Layer multi-tenant catalogue filtering (`ListModels`), Dynamic `provider/model` wildcard routing. |
| **Intelligent Routing & Load Balancing** | [`demo/03_smart_routing`](./03_smart_routing/main.go) | `go run ./demo/03_smart_routing` | Zero-LLM sub-millisecond complexity classifier (`< 0.1ms`), weighted load balancing across multiple provider deployments. |
| **Virtual Keys, Auth & RBAC** | [`demo/04_auth_and_vault`](./04_auth_and_vault/main.go) | `go run ./demo/04_auth_and_vault` | Scoped Virtual API Keys (`sk-gw-...`), 4-layer RBAC model allowlist enforcement (`HTTP 403`), and instant key revocation (`HTTP 401`). |
| **Retries, Circuit Breakers & Failover** | [`demo/05_retries_and_fallbacks`](./05_retries_and_fallbacks/main.go) | `go run ./demo/05_retries_and_fallbacks` | Simulated upstream 503 outage, full-jitter exponential retries, 3-state circuit breaker trip, and cross-provider fallback to Claude. |
| **FinOps Micro-Dollar Accounting & Spend** | [`demo/06_finops_and_budgets`](./06_finops_and_budgets/main.go) | `go run ./demo/06_finops_and_budgets` | Exact 64-bit micro-dollar integer accounting (`CostMicros`), zero float drift, and aggregated real-time spend ledger breakdown. |
| **Rate Limiting & Response Caching** | [`demo/07_ratelimit_and_cache`](./07_ratelimit_and_cache/main.go) | `go run ./demo/07_ratelimit_and_cache` | 0ms deterministic exact-match response cache (`HIT`/`MISS`) and atomic sliding-window RPM quota enforcement (`HTTP 429`). |
| **Model Context Protocol (MCP)** | [`demo/08_mcp_gateway`](./08_mcp_gateway/main.go) | `go run ./demo/08_mcp_gateway` | MCP 2026-07-28 stateless primary & 2025-11-25 compat, Virtual Hub aggregation, anti-tool-poisoning scanner, cryptographic SHA-256 tool pinning, and arbitrary decimal precision. |
| **Agent-to-Agent Protocol (A2A)** | [`demo/09_a2a_protocol`](./09_a2a_protocol/main.go) | `go run ./demo/09_a2a_protocol` | Linux Foundation A2A v1.0, RFC 8785 JCS canonicalization, JWS card signatures, dual-binding dispatch, task state durability, and instant emergency kill-switch. |

---

## Detailed Walkthroughs & Internal Mechanics

### System Overview: Routing Modes
**Source**: [`demo/main.go`](./main.go)  
**Command**: `go run ./demo`

#### What It Demonstrates
Demonstrates the three core ways developers interact with GoRoute:
- **Explicit Model Name**: Target a specific model like `"gemini-2.5-flash"`.
- **Logical Alias**: Target a logical group like `"fast"` or `"reasoning"`, allowing platform teams to change backing models without code changes.
- **Smart Routing (`"auto"`)**: Let GoRoute's heuristic classifier analyze prompt complexity and route to either `"fast"` or `"reasoning"` in `< 0.1 ms`.

#### Under the Hood
- Initializes an in-process gateway instance using `gateway.New(...)`.
- Registers model entries with declarative parameters.
- For Smart Routing, evaluates token length, code syntax, and analytical keywords to route the prompt to the reasoning tier without making any external classification calls.

---

### Unified API & Wire Normalization
**Source**: [`demo/01_unified_api/main.go`](./01_unified_api/main.go)  
**Command**: `go run ./demo/01_unified_api`

#### What It Demonstrates
- **Synchronous Chat**: Invokes `gw.Chat(...)` with system prompt instructions and max token limits.
- **Real-Time SSE Streaming**: Invokes `gw.StreamChat(...)`, receiving token deltas live via an `onDelta` callback function with zero buffer lag.

#### Under the Hood
- The provider adapter converts canonical OpenAI-compatible parameters into the upstream vendor's native schema.
- For streaming, `internal/adapter/sse` streams normalized `chat.completion.chunk` frames over `http.Flusher`, immediately delivering each token delta to the terminal as it is received.

---

### Multi-Tenant Model Management & Dynamic Routing
**Source**: [`demo/02_model_management/main.go`](./02_model_management/main.go)  
**Command**: `go run ./demo/02_model_management`

#### What It Demonstrates
- **Tenant Filtering**: `gw.ListModels(ctx)` queries `GET /v1/models` and returns the strict intersection of active global models, subscribed providers, approved policies, and key permissions.
- **Dynamic Wildcard Routing**: Call `gw.Chat(ctx, "gemini/gemini-2.5-flash", ...)` directly using `provider/model` syntax without pre-configuring an alias.

#### Under the Hood
- The 4-layer model hierarchy (`global_models` $\rightarrow$ `org_provider_subscriptions` $\rightarrow$ `org_model_policies` $\rightarrow$ `model_groups`) guarantees multi-tenant isolation.
- When an unaliased `provider/model` string is received, the gateway dynamically matches an active vault credential for that provider and synthesizes an ephemeral deployment.

---

### Intelligent Routing & Load Balancing
**Source**: [`demo/03_smart_routing/main.go`](./03_smart_routing/main.go)  
**Command**: `go run ./demo/03_smart_routing`

#### What It Demonstrates
- **Weighted Traffic Splitting**: Routes to `"fast"`, which load-balances between Gemini (80% weight) and OpenAI (20% weight) using the `weighted-shuffle` strategy.
- **Zero-LLM Classifier**: Submits a technical prompt with code and proof instructions to `model: "auto"`. Inspects the returned `RouteReason` badge (`heuristic:high_complexity`).

#### Under the Hood
- The Stage-1 complexity scorer evaluates:
  $$\text{Score} = \min(1.0,\ \text{LengthScore} + \text{ReasoningScore} + \text{CodeScore} + \text{TurnScore})$$
  Because the score exceeds the $0.40$ threshold, it selects `"reasoning"`.
- Stage 2 filters out unhealthy deployments and selects the target using weighted random probability.

---

### Dual-Boundary Auth, Scoped Virtual Keys & RBAC
**Source**: [`demo/04_auth_and_vault/main.go`](./04_auth_and_vault/main.go)  
**Command**: `go run ./demo/04_auth_and_vault`

#### What It Demonstrates
- Issues a scoped Virtual Key (`sk-gw-...`) restricted to `"fast"` with a 60 RPM limit.
- **Success (200 OK)**: Key executes allowed model `"fast"`.
- **RBAC Block (403 Forbidden)**: Key attempts to execute `"reasoning"` and is blocked.
- **Instant Revocation (401 Unauthorized)**: Revoking the key immediately invalidates L1/L2 caches, causing subsequent calls to fail.

#### Under the Hood
- The raw key secret is hashed with SHA-256 and compared in constant time (`crypto/subtle.ConstantTimeCompare`).
- Key metadata is cached in L1 memory (15s) and L2 Redis (300s).
- Revocation updates the database and publishes an eviction event on `gw:events:invalidation` to invalidate L1 memory across all gateway pods instantly.

---

### Automated Retries, Circuit Breakers & Failover
**Source**: [`demo/05_retries_and_fallbacks/main.go`](./05_retries_and_fallbacks/main.go)  
**Command**: `go run ./demo/05_retries_and_fallbacks`

#### What It Demonstrates
- Configures `production-chat` to simulate an upstream `HTTP 503` outage with `fallbacks: ["backup-claude"]`.
- The gateway detects the failure, executes full-jitter exponential backoff, trips the primary deployment's circuit breaker to `OPEN`, and transparently fails over to Anthropic Claude.
- Response header `X-Gateway-Fallback-Attempted: true` confirms the recovery.

#### Under the Hood
- `ReliabilityManager` classifies `503` as a retryable error.
- When retries in the primary group are exhausted, the circuit breaker enters cooldown in Redis (`gw:router:cooldown:<id>`).
- The fallback chain is walked, re-translating the canonical request to Anthropic Claude wire format and completing successfully.

---

### FinOps Micro-Dollar Accounting & Spend Ledgers
**Source**: [`demo/06_finops_and_budgets/main.go`](./06_finops_and_budgets/main.go)  
**Command**: `go run ./demo/06_finops_and_budgets`

#### What It Demonstrates
- Makes calls to fast and reasoning tiers and prints the exact cost in micro-dollars (`res.CostMicros`).
- Queries `gw.SpendSummary(ctx)` to inspect real-time aggregated spend by provider, model, and total USD.

#### Under the Hood
- Uses 64-bit integer arithmetic ($1\text{ USD} = 1,000,000\ \mu\$$) with intermediate pico-dollar ($10^{-12}$) half-up rounding.
- Spend events are enqueued to a 16,384-slot non-blocking channel, introducing 0 ms database latency on the HTTP response path.
- Background workers flush spend batches into PostgreSQL `spend_logs`.

---

### Deterministic Response Caching & Rate Limiting
**Source**: [`demo/07_ratelimit_and_cache/main.go`](./07_ratelimit_and_cache/main.go)  
**Command**: `go run ./demo/07_ratelimit_and_cache`

#### What It Demonstrates
- **Exact-Match Cache**: Request 1 with `Temperature = 0.0` records a `MISS`. Request 2 with identical payload records `HIT` with `CostMicros: 0` and 0 ms upstream latency.
- **Atomic Rate Limiting**: Issues a key with `RPMLimit = 2`. Requests 1 and 2 succeed; Request 3 is blocked immediately with `HTTP 429 Too Many Requests`.

#### Under the Hood
- The response cache computes a canonical SHA-256 hash over tenant ID, model, messages, tools, and temperature.
- Rate limiting executes `check_and_increment.lua` in a single Redis roundtrip, atomically checking RPM, TPM, concurrency, and budgets.

---

### Model Context Protocol (MCP 2026-07-28 & 2025-11-25) Gateway
**Source**: [`demo/08_mcp_gateway/main.go`](./08_mcp_gateway/main.go)  
**Command**: `go run ./demo/08_mcp_gateway`

#### What It Demonstrates
- **Upstream Server Registration & Sync**: Registers upstream MCP servers and automatically syncs tool definitions with anti-poisoning scanning (blocks prompt injections, scripts, and RTL Trojans).
- **Cryptographic Tool Pinning**: Computes and pins SHA-256 hashes of tool schemas; blocks modified tools if hashes drift.
- **Virtual Hub Aggregation (`POST /mcp`)**: Aggregates tools, resources, and prompts across upstream servers into a unified catalog with partial-outcomes metadata.
- **High-Precision Decimal Invocations**: Preserves IEEE-754 overflow and arbitrary decimal precision using `big.Rat` / `json.Number`.

#### Under the Hood
- Routes requests via stateless Streamable HTTP (2026-07-28 primary) with sessionless headers, or transparently bridges to stateful 2025-11-25 sessions.
- Evaluates inbound SSRF policies on all egress traffic, preventing loopback or private network traversal.

---

### Agent-to-Agent Protocol (A2A v1.0) Service
**Source**: [`demo/09_a2a_protocol/main.go`](./09_a2a_protocol/main.go)  
**Command**: `go run ./demo/09_a2a_protocol`

#### What It Demonstrates
- **Cryptographic Agent Card Discovery**: Serves `GET /.well-known/agent-card.json` signed using gateway keys with RFC 8785 JSON Canonicalization Scheme (JCS).
- **Dual-Binding Agent Invocations**: Dispatches messages to upstream agents via either HTTP+JSON or JSON-RPC 2.0 dual-binding.
- **Stateful Task Durability**: Monotonically increments event sequences and records state transitions (`submitted` -> `working` -> `completed`).
- **Emergency Administrative Kill-Switch**: Instantly cuts off agent invocations across all pods with `HTTP 503 agent_killed`.

#### Under the Hood
- Implements Subscribe-First SSE task streaming: Redis channel subscription first, followed by historical backfill from PostgreSQL with deduplication.
- Executes webhook push notifications through a Transactional Outbox with exponential backoff and dead-letter queues.

---

## Running Demos with Live Provider Keys (Optional)

To run the demonstration suite using live upstream provider connections:

```bash
# macOS / Linux
export GEMINI_API_KEY="AIzaSy..."
export ANTHROPIC_API_KEY="sk-ant-..."
export OPENAI_API_KEY="sk-proj-..."

go run ./demo/01_unified_api
go run ./demo/03_smart_routing
go run ./demo/05_retries_and_fallbacks
```
