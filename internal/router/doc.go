// Package router implements the GoRoute 2-stage intelligent routing pipeline and reliability engine.
//
// Stage 1 (Intelligent Router):
//   - Zero-LLM Prompt Complexity Classifier: Determines task complexity in < 0.1ms using
//     token length heuristics, code fence detection, reasoning keywords, and constraint counting.
//   - Logical Model Aliases: Resolves high-level aliases such as "fast", "reasoning", "coding",
//     or "auto" into physical model groups.
//   - Provider Wildcards: Resolves explicit names (e.g. "gemini-2.5-flash") or wildcard identifiers
//     (e.g. "anthropic/*") across registered provider credentials.
//
// Stage 2 (Load Balancer & Reliability Manager):
//   - 5 Production Routing Strategies:
//     1. weighted-shuffle: Probabilistic distribution based on deployment weights.
//     2. least-busy: Selects healthy deployments with lowest active concurrent requests.
//     3. latency-based: Directs traffic to the lowest exponential moving average (EMA) latency deployment.
//     4. usage-based-headroom: Optimizes for remaining organization/deployment rate limit capacity.
//     5. lowest-cost: Prioritizes active deployments with lowest token pricing per 1M tokens.
//   - 3-State Circuit Breakers: Protects deployments using CLOSED -> OPEN -> HALF-OPEN state machines
//     with configurable failure thresholds and cooldown windows.
//   - Cross-Provider Failover: Cascades failed requests across configured fallback chains transparently.
package router
