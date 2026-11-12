# AI Gateway Production Readiness Assessment

**Date:** 2026-11-12
**Scope:** GoRoute AI Gateway compared with LiteLLM's Python proxy and its published repository documentation.
**Repository snapshots:** GoRoute `ffdaffe`, LiteLLM `001126cd1c`, LiteLLM docs `704f99b`.

## Executive summary

GoRoute already has the major gateway building blocks: virtual-key authentication and RBAC, Redis Lua rate-limit admission, integer micro-dollar accounting, two-stage routing, retries and fallbacks, response caching, guardrails, structured logs, and Prometheus exposition. The codebase is organized around a clear request path, with focused packages under `internal/` and a public SDK under `pkg/gateway/`.

**Assessment: not production-ready for an unqualified multi-tenant production deployment yet.** Several paths work well in a single process or when Redis and storage are healthy, but important guarantees weaken during dependency failures or across replicas. Highest-priority issues are guardrail policy lookup failures allowing requests through, cached credentials surviving key expiry, rate-limit fallback losing cluster-wide enforcement, budget checks allowing concurrent overspend, and cache invalidation not propagating safely across replicas. `/metrics` also exposes operational data without authentication.

LiteLLM's Python proxy is a broader and more mature comparison for these capabilities, with substantially wider policy, integration, and test coverage. It also has complexity and explicit failure-mode tradeoffs. Its separate Rust gateway is still an incomplete foundation for several of these areas, so this review compares GoRoute primarily to the Python proxy rather than presenting the Rust gateway as feature-equivalent.

## How the codebase fits together

The main inference path is in `internal/server/`. It authenticates and authorizes a request, validates it, applies guardrails, checks quota, looks up the response cache, chooses a route and deployment, then dispatches through provider adapters. `internal/router/` holds intelligent model selection, load balancing, and reliability behavior. `internal/auth/`, `internal/ratelimit/`, `internal/finops/`, `internal/cache/`, `internal/guardrails/`, and `internal/observability/` hold the cross-cutting controls. PostgreSQL and Redis implementations are under `internal/storage/`.

The repository's `docs/CODEBASE_MAP.md` is a useful navigation guide. Runtime behavior and tests are the evidence for this assessment. Some architecture/internal documentation describes intended behavior that the current implementation does not fully provide, particularly for distributed cache invalidation and telemetry. Treat those documents as design intent until the gaps below are resolved.

## Readiness by capability

| Capability | GoRoute status | Main production concern | Comparison with LiteLLM Python proxy |
| --- | --- | --- | --- |
| Authentication | **Needs hardening** | Query-string credentials are accepted outside WebSocket-only routes; cached identity can outlive key expiry. | Wider auth and identity plumbing; auth cache invalidation can broadcast between workers. |
| Rate limiting | **Conditional** | Redis Lua path is atomic, but local fallback is per-process and default expected replica count is one. | More scopes and extensive tests; still falls back to process-local limits when Redis is unavailable. |
| Cost tracking | **Not ready for strict caps** | Budget admission checks current spend but does not reserve the next request's estimated cost. Spend persistence can drop failed batches. | Has pre-dispatch budget reservation/reconciliation; some optional event paths remain at-most-once. |
| Model routing | **Conditional** | Useful two-stage selection, but load and health telemetry is process-local; nested fallback expansion is absent. | More strategies and shared selection state/reservations. |
| Retries and fallbacks | **Needs distributed reliability fixes** | Half-open circuit-breaker coordination is not atomic/shared across replicas; streaming retries skip backoff. | Broader retry/fallback policies and bounded fallback traversal. |
| Caching | **Not ready for multi-replica correctness** | Targeted and global invalidation do not reliably invalidate other replicas or all Redis entries. Some request parameters are absent from the key. | Wider cache support and deletion controls; local-cache limitations are documented. |
| Guardrails | **Not ready where policy enforcement is required** | Policy repository errors silently disable input checks and output sanitization; detectors are narrow heuristics. | Pluggable integrations and modes, with per-integration failure behavior and broader tests. |
| Logging and monitoring | **Conditional** | `/metrics` is unauthenticated and includes deployment/spend data; metrics and trace context are process-local/basic. | More exporters and integrations; Prometheus exposure still needs network restriction or auth configuration. |

## Findings

### 1. Authentication

**High: credentials can be supplied in query parameters on ordinary HTTP routes.** `internal/auth/middleware.go:62-78` accepts `api_key` and `token` query values, while the helper is used by the general data-plane middleware at `:81-101`. The comment scopes this to WebSockets, but the code does not restrict it to WebSocket requests. URLs commonly reach proxy/access logs, browser history, and monitoring systems. Restrict query credentials to the routes that require them, or remove this mechanism where possible.

**High: a cached key identity is returned before expiry is checked.** `internal/auth/service.go:171-197` returns identities from L1 and Redis caches directly. The virtual-key expiry check occurs only after a repository read at `:199-235`. A key that expires while cached can therefore continue to authenticate until cache expiration. The same staleness window applies to key/org state and changed authorization limits. LiteLLM's Python proxy has a broad cache invalidation path that broadcasts revocations to workers (`litellm/proxy/auth/auth_checks.py:3462-3498`), although that does not remove the need to reason about cache failure modes.

**Strength:** GoRoute generates random virtual keys and stores hashes rather than raw tokens (`internal/auth/service.go:59-115`); master-key comparison uses constant-time comparison (`:307-314`). Endpoint RBAC is applied after identity resolution (`internal/auth/middleware.go:81-103`).

### 2. Rate limiting

**High: Redis failure silently weakens global limits.** The Redis path checks/increments scopes atomically through one Lua script (`internal/ratelimit/limiter.go:110-158`, `internal/ratelimit/scripts/check_and_increment.lua:14-64`). On errors, `Acquire` uses local state. The default fallback is `local_divided_by_replicas` with `expectedPodCount: 1` (`limiter.go:58-75`), so a multi-replica deployment can grant each process the full quota while Redis is down. A static divisor also cannot guarantee a global cap when replicas scale or receive uneven traffic. Configure fail-closed behavior when the limit is a hard tenant boundary, or implement shared outage coordination.

**Medium: local fallback state can grow with identity churn.** `localCounters` and `localSpend` are maps (`limiter.go:53-56`); rolling the time window replaces a value but does not remove old scope keys (`:205-215`). This can grow memory over a long-running process as keys/teams/orgs churn.

**Medium: TPM admission is approximate for several modalities.** The admission decision uses estimated tokens (`limiter.go:124-128`), while some handler estimates are fixed or coarse, such as audio and image estimates. Actual token reconciliation happens after execution. Treat these as approximate protection rather than a strict pre-execution token ceiling.

LiteLLM's limiter supports more dimensions, including key, user, team, end-user, model, tags, agents, and sessions (`litellm/proxy/hooks/parallel_request_limiter_v3.py:2883-3038`). It also has Redis fallback behavior that becomes process-local, so it does not preserve strict global enforcement during a Redis outage either. Its main advantage here is breadth and deeper tests, not a guarantee that dependency failure has no effect.

### 3. Cost tracking and budgets

**High: configured dollar budgets are not strict admission caps.** `Acquire` checks current spend but does not reserve the expected cost of a new request (`internal/ratelimit/limiter.go:98-152`; Lua checks at `internal/ratelimit/scripts/check_and_increment.lua:14-37`). Spend is recorded after the response (`internal/finops/spend_worker.go:55-59`). Several concurrent requests can all pass just below the cap and then exceed it. LiteLLM has a pre-dispatch reservation and post-response reconciliation flow (`litellm/proxy/spend_tracking/budget_reservation.py:250-375`).

**High/Medium: spend-log persistence may lose events.** The worker uses a bounded in-memory channel (`internal/finops/spend_worker.go:29-46`). A failed batch is logged and then cleared rather than requeued (`:120-129`, `:146-165`); the synchronous overflow fallback also ignores repository write errors (`:55-71`). A process crash before flush loses queued records. This is unsuitable as the only durable financial ledger without a recovery mechanism.

**Strength and limitation:** GoRoute's integer micro-dollar calculator avoids floating-point drift (`internal/finops/calculator.go:10-44`). However, unknown or missing pricing can produce zero cost for unbudgeted calls (`:12-15`, `:38-40`). Budgeted routing filters out unverified pricing (`internal/router/reliability.go:123-140`, `:181-212`), which is a useful fail-closed control. LiteLLM supports broader pricing inputs and reservation, but uses floating-point USD in its core cost calculations (`litellm/cost_calculator.py:239-282`, `:1783-1827`).

### 4. Model routing

**Medium: adaptive routing signals are process-local.** GoRoute has stage-one request classification and stage-two strategies including weighted, least-busy, latency, headroom, and lowest-cost (`internal/router/intelligent_router.go:28-53`; `internal/router/load_balancer.go:32-70`). The stage-two counters and latency state are held in process memory (`load_balancer.go:12-18`, `:39-47`, `:97-218`), so replica decisions can diverge and local RPM/TPM observations do not represent cluster load. LiteLLM least-busy uses shared cache state and short-lived selection reservations (`litellm/router_strategy/least_busy.py:14-30`, `:137-139`, `:215-239`).

**Medium: fallback groups are expanded only one level.** `buildGroupChain` appends the primary group's immediate configured fallbacks and does not recursively walk their own fallback lists (`internal/router/reliability.go:1704-1719`). LiteLLM traverses fallback chains with visited-target tracking and a depth bound (`litellm/router_utils/fallback_event_handlers.py:815-870`).

### 5. Retries and fallbacks

**High: circuit-breaker half-open coordination is not distributed.** GoRoute writes cooldown TTLs to Redis (`internal/router/reliability.go:1871-1891`) but checks half-open probe ownership in local memory (`:1801-1832`). Once the shared TTL expires, multiple pods can admit probes. On success, local state is cleared but the Redis cooldown key is not explicitly removed (`:1900-1910`), so other pods can remain blocked until TTL expiry. LiteLLM also uses shared Redis cooldown state when configured; its docs recommend shared state for multi-worker routing (`litellm/litellm/router_utils/cooldown_handlers.py:493`; `litellm-docs/docs/router/learn/shared_state.md:43`).

**Medium: streaming retry attempts do not back off before the first chunk.** GoRoute correctly stops retrying once data has been sent, but its pre-chunk streaming failure loop continues without the normal backoff (`internal/router/reliability.go:445`; regular backoff helper at `:1922`). This can amplify provider outages and ignore `Retry-After`.

LiteLLM has broader failure-type and status-aware retry policies and bounded fallback traversal. Its docs also describe mid-stream continuation with restrictions. Neither gateway can safely replay an arbitrary request after partial output without clear protocol semantics, but GoRoute currently returns the stream error after output begins.

### 6. Caching

**High: invalidation is not cluster-safe.** Targeted invalidation removes Redis keys only while iterating the current process's L1 entries (`internal/cache/response_cache.go:147-178`). Global invalidation increments a process-local namespace counter and clears only local L1 state (`:149-158`). The Redis invalidation Pub/Sub channel documented by the repository is not used by this response cache. Also, entries restored from Redis are inserted into L1 without `orgID` (`:110-120`), so later org-targeted invalidation cannot match them (`:161-178`). Stale responses can therefore survive policy/model changes or administrative invalidation on other replicas.

**Medium: cache key omits output-affecting request parameters.** The key includes model/messages/tools/response format/token limit/stop/temperature/top-p/reasoning effort/user (`response_cache.go:62-94`), but omits fields such as seed and frequency/presence penalties. Requests that differ only in omitted fields may collide and return a response generated under different settings. LiteLLM builds keys from recognized API and optional provider parameters and has explicit cache deletion controls (`litellm/caching/caching.py:428`; `litellm/proxy/caching_routes.py:151`).

GoRoute currently caches only non-streaming chat and defaults to temperature-zero requests (`response_cache.go:47-59`). LiteLLM supports more endpoint types and documents that local caches are not shared among replicas (`litellm-docs/docs/proxy/caching.md:155-167`).

**Documentation drift:** `docs/INTERNALS.md:531` describes a Pub/Sub invalidation channel for cache propagation, while the response cache implementation does not publish or subscribe to that channel. Update the architecture docs after implementing or removing that intended behavior.

### 7. Guardrails

**High: policy lookup failures fail open.** Chat input evaluation returns an empty, successful outcome when `GetGuardrailPolicy` errors or returns nil (`internal/guardrails/engine.go:51-61`). Output sanitization also silently skips on lookup failure (`:177-184`), and MCP evaluation has the same lookup pattern (`internal/guardrails/mcp.go:107-122`). For organizations that depend on these policies, a database or repository error bypasses enforcement. Make failure behavior explicit per policy and fail closed for mandatory controls.

**Medium: detection is a narrow heuristic baseline.** Prompt-injection detection is a short list of literal substrings, blocked keywords use substring matching, and PII/secret detection uses regular expressions (`internal/guardrails/engine.go:78-159`). This is not a comprehensive prompt-injection, credential, or PII detector. The current focused test covers one injection phrase and basic email/SSN/key redaction (`internal/guardrails/guardrails_test.go:12-55`), not false negatives, lookup failure, all actions, or modality coverage.

**Medium: enforcement coverage is uneven.** The standard chat handler calls input evaluation and output sanitization (`internal/server/handlers_inference.go:100-126`, `:417-421`). A source search found no equivalent calls in other modality/message handlers. Do not assume policy applies consistently to all API endpoints or streaming output.

LiteLLM's generic guardrail integration defaults to fail closed and offers an explicit fail-open override (`litellm/proxy/guardrails/guardrail_hooks/generic_guardrail_api/generic_guardrail_api.py:270-319`, `:475-494`). It has more provider integrations and mode-specific behavior, though coverage and failure semantics still vary by integration.

### 8. Logging and monitoring

**High/Medium: `/metrics` is outside authentication and exposes operational data.** It is registered before protected route groups (`internal/server/server.go:202-230`), and exports provider spend and deployment IDs/names (`internal/observability/collector.go:439-448`). Restrict it at the network boundary or add an authenticated metrics listener.

**Medium: telemetry is process-local and in-memory.** Collector state is held in maps and counters on one process (`internal/observability/collector.go:152-175`); data resets on restart and isn't aggregated across replicas by the gateway. Deployment entries grow with unique IDs (`:237-258`), and those IDs become Prometheus labels (`:446-448`), creating cardinality and memory risks if deployments churn. Percentiles are estimated from a bounded sample reservoir (`:17-36`).

**Medium: trace middleware propagates IDs but does not create/export spans.** `ParseOrGenerateTrace` accepts a trace ID based mainly on length (`internal/observability/tracing.go:27-55`), creates a new span ID, and injects headers (`:71-94`). This is useful correlation but not distributed tracing by itself. Validate incoming trace context and connect to an exporter if trace-level observability is required.

GoRoute has useful structured access logging and request correlation (`internal/logger/middleware.go:49-119`), health/readiness endpoints, and Prometheus text exposition. LiteLLM offers more exporters and logging callbacks plus multiprocess Prometheus aggregation (`litellm/integrations/prometheus.py:5020-5031`; `litellm-docs/docs/proxy/logging.md:7-20`). LiteLLM's docs also warn that its dedicated metrics listener needs network restriction (`litellm-docs/docs/proxy/prometheus.md:80-82`), so exposure is an operational control for both systems.

## Recommended order of work

1. **Close enforcement bypasses:** propagate guardrail policy lookup errors and default mandatory policies to fail closed; check virtual-key expiry on every cache hit; remove or constrain query-string credentials.
2. **Make budgets and spend durable:** reserve estimated cost atomically before dispatch and reconcile after; use a durable queue/outbox or retryable ledger writes for spend events.
3. **Define outage behavior:** use fail-closed rate-limit behavior for hard quotas, and make Redis outage modes visible through health and alerting. Avoid claiming globally enforced quotas from per-process fallback.
4. **Repair multi-replica cache and breaker behavior:** implement shared cache epochs/invalidation with Redis-backed metadata or Pub/Sub; ensure targeted invalidation can locate all entries; coordinate half-open probes atomically in Redis.
5. **Protect and improve telemetry:** restrict `/metrics`, cap or remove unbounded labels, add cross-replica aggregation/export, and wire trace IDs into real spans.
6. **Expand behavior coverage:** recursively traverse bounded fallback graphs, make cache keys include all output-affecting parameters, and add endpoint coverage for guardrails.
7. **Align docs with runtime:** revise `docs/INTERNALS.md` and `docs/ARCHITECTURE.md` wherever they state distributed guarantees not present in code.

## Review method and limits

This is a static source and test review of the repository snapshots above. I inspected the relevant implementation, tests, and LiteLLM documentation. **No tests, builds, benchmarks, live-provider calls, Redis/PostgreSQL failure drills, or multi-replica exercises were run.** Therefore this report identifies code-level risks and coverage gaps; it is not a certification or proof of runtime behavior. LiteLLM is also a moving codebase, so these findings are pinned to the listed commits.

## GitHub tracking

The following issues track implementation work from this assessment:

- Authentication: [#18](https://github.com/goroute-ai/ai-gateway-go/issues/18), [#20](https://github.com/goroute-ai/ai-gateway-go/issues/20)
- Rate limits: [#3](https://github.com/goroute-ai/ai-gateway-go/issues/3), [#5](https://github.com/goroute-ai/ai-gateway-go/issues/5)
- Cost tracking: [#16](https://github.com/goroute-ai/ai-gateway-go/issues/16), [#8](https://github.com/goroute-ai/ai-gateway-go/issues/8), [#21](https://github.com/goroute-ai/ai-gateway-go/issues/21)
- Routing and reliability: [#15](https://github.com/goroute-ai/ai-gateway-go/issues/15), [#10](https://github.com/goroute-ai/ai-gateway-go/issues/10), [#13](https://github.com/goroute-ai/ai-gateway-go/issues/13), [#6](https://github.com/goroute-ai/ai-gateway-go/issues/6)
- Caching: [#14](https://github.com/goroute-ai/ai-gateway-go/issues/14), [#19](https://github.com/goroute-ai/ai-gateway-go/issues/19)
- Guardrails: [#9](https://github.com/goroute-ai/ai-gateway-go/issues/9), [#4](https://github.com/goroute-ai/ai-gateway-go/issues/4), [#11](https://github.com/goroute-ai/ai-gateway-go/issues/11)
- Logging and monitoring: [#7](https://github.com/goroute-ai/ai-gateway-go/issues/7), [#12](https://github.com/goroute-ai/ai-gateway-go/issues/12)
- Assessment publication and documentation: [#17](https://github.com/goroute-ai/ai-gateway-go/issues/17)
