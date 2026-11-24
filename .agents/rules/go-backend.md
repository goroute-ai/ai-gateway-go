---
trigger: glob
globs: "**/*.go, go.mod"
description: "Go backend architecture, public SDK isolation, router performance, and verification standards for GoRoute AI Gateway."
---

# Go Backend & SDK Rules

- **Dependency Direction**: Keep package dependencies pointed inward toward `internal/domain/` types and repository/adapter interfaces.
- **Public SDK Isolation (`pkg/gateway/`)**: Keep all exported types and options in `pkg/gateway/` self-contained (`CustomAuthenticator`, `CustomAuthorizer`, `KeySecretSink`, `RoutingPlugin`, `PreRouter`, `RoutingHints`, `ConnectRealtime`, modality/spend helpers). Never expose `internal/*` types in `pkg/gateway` exported signatures.
- **Router Hot-Path Performance (`internal/router/`)**:
  - Keep single-tier fast paths zero-alloc and Stage 1 + Stage 2 non-embedding routing overhead within `< 500 µs` P99 in memory (`< 2 ms` with Redis pipelining).
  - Preserve lone-deployment circuit-breaker cooldown protection (minimum request volume & safety-net logic), priority tier step-downs, specialized fallback chains (`context_window_fallbacks`, `content_policy_fallbacks`, `fallback_targets`), PTU capacity sharing, and `PriorityScheduler` bounds.
  - Graceful degradation is allowed **only** for adaptive routing signals and affinity caches (falling back to local state with `gw_routing_signal_degraded_total`), never for auth, RBAC, or quota checks.
- **Tri-State Model Capabilities & Pricing**:
  - Preserve explicit tri-state capabilities (`supported`, `unsupported`, `unknown`); never downgrade `unknown` to `unsupported` without verification.
  - Keep model pricing history append-only.
- **Strict 4-Provider Surface**: Only `openai`, `anthropic`, `groq`, and `openrouter` adapters are first-class OpenAPI-first providers.
- **Code Quality & Documentation**:
  - Exported APIs (especially `pkg/gateway/`) require intent-focused godoc comments starting with the symbol name and ending with a period (`revive: exported`, `godot`).
  - Wrap errors with `%w`, inspect with `errors.Is`/`errors.As`, pass `context.Context` as the first argument, and close HTTP bodies and SQL rows (`errorlint`, `noctx`, `bodyclose`, `sqlclosecheck`, `rowserrcheck`).
  - Prefer Go 1.26 idioms (`modernize`, `intrange`, `slices`/`maps`, `t.Helper()`, `t.Context()`); every `//nolint` directive must specify the linter name and a rationale (`nolintlint`).
  - Load the `goroute-go-quality` and `goroute-go-docs` skills when conducting Go code reviews, refactoring, or authoring documentation.
- **Verification**: Before finishing Go edits, run read-only `gofmt -l .`, `go vet ./...`, and `go test -race -count=1` on modified packages (plus `./tests/guardrails/...` when touching inference, MCP, A2A, or guardrails).
