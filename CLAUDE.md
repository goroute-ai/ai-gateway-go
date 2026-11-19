# GoRoute AI Gateway — Claude Code Instructions

Shared repository guidance:

@AGENTS.md

Use [the codebase map](docs/CODEBASE_MAP.md) to find implementation, tests, and sources of truth. Treat runtime code and tests as authoritative when documentation differs.

## Common Commands

| Task | Command |
| --- | --- |
| Check Go formatting | `gofmt -l .` |
| Static analysis | `go vet ./...` |
| Generate and validate API contracts | `make specgen` |
| Unit tests with race detector | `go test -race -count=1 ./internal/... ./pkg/... ./cmd/...` |
| Focused package tests | `go test -race -count=1 ./internal/<pkg>/...` |
| Live PostgreSQL persistence tests | `make test-postgres` (requires PostgreSQL and Redis) |
| Strict live E2E tests (no skips) | `make test-e2e-strict` (requires PostgreSQL and Redis) |
| Headless Chromium UI E2E | `make test-ui-e2e` (requires PostgreSQL, Redis, Node.js, and Playwright Chromium) |
| Full containerized prod suite (Phases 1–8) | `make test-prod-containers` |
| Live upstream provider canary | `make test-canary` (key-gated via `-tags=canary`) |
| Build gateway into ignored output directory | `go build -o bin/ai-gateway ./cmd/gateway` |
| Install UI dependencies | `make ui-install` |
| Build and synchronize UI assets | `make ui-build` |
| Check embedded UI asset parity | `make ui-check-dist` |
| Build release tarballs & Helm package | `make release-assets` |

`make release-check` runs `gofmt -w` through its `fmt` prerequisite, then vet, generation, unit tests, and E2E tests. It modifies files and requires PostgreSQL and Redis; inspect its prerequisites before running it on an existing worktree. `make ui-build` writes generated files under `internal/ui/dist/`.

## Release Invariants (v1.22.0)

- Route provider and tool egress through `internal/security/network`; validate custom `BaseURL` inputs via `adapter.ValidateAndResolveBaseURL`, isolate untrusted user media fetches behind `DefaultPublicMediaPolicy` (`mediaPolicy`/`mediaClient`), and keep private-network preflight probes restricted to `platform_admin`.
- Preserve tenant identity, `(org_id, oidc_issuer, oidc_subject)` federated binding (`0034`, including the transaction-locked duplicate-subject rollback preflight), single-transaction SCIM group updates, `team_member_permissions` and `self_serve_budget_policy` enforcement, `team_admin` hierarchy boundaries (`0035`), tri-state JSON allowlist semantics (`null` = Inherit vs `[]` = Deny All via `optionalStringSlice` and explicit JSON tags without `,omitempty` on `IdentityContext`, `Team`, and `VirtualKey`), and fail-closed authorization across `PreRouter`, `DeploymentFilterChain`, operator roles, virtual keys, `CustomAuthenticator`, MCP tools, and A2A agents.
- Keep `internal/router/` single-tier fast paths zero-alloc and preserve Stage 1 + Stage 2 non-embedding routing overhead within `< 500 µs` P99 in memory (`< 2 ms` with Redis pipelining). Graceful degradation is allowed only for adaptive routing signals and affinity caches (falling back to process-local state with `gw_routing_signal_degraded_total` telemetry), while security/RBAC/quota checks remain fail-closed.
- Preserve lone-deployment circuit-breaker cooldown protection (minimum request volume & safety-net logic) alongside specialized fallback chains (`context_window_fallbacks`, `content_policy_fallbacks`, `fallback_targets`), PTU priority capacity sharing, and `PriorityScheduler` bounds.
- Keep accounting in integer micro-dollars, with integer pico-dollar intermediate arithmetic in `internal/finops`; never use floating point for cost or balance calculations.
- Keep provider credentials encrypted through the vault. Production validation must reject default admin, encryption, and JWT keys when either `ENV` or `GATEWAY_ENV` signals production.
- Preserve file-upload quotas and concurrency limits. Defaults are 5 GiB per organization and 8 concurrent uploads; zero disables the corresponding limit.
- Preserve durable spend delivery, idempotent Redis reconciliation, upper-bound budget reservations, lease renewal, `rolling_24h` `__init__:0` single-ZSET cold recovery from PostgreSQL (`503 quota_policy_unavailable` on history load failure), and budget-reset synchronization across multi-replica PostgreSQL/Redis deployments.
- Preserve streaming guardrail inspection and redaction, including fail-closed policy handling, `logging_only` behavior, pre-first-chunk `X-Gateway-Provider`/`X-Gateway-Model` emission, and CORS `Access-Control-Expose-Headers`.
- Treat OpenAPI and protocol specs as contract sources. `make specgen` validates OpenAPI/MCP/A2A specs and enforces `/v1`, `/admin/v1`, and `/auth` route parity (`118` OpenAPI paths: `28` `/v1`, `80` `/admin/v1`, `10` `/auth`); it does not verify aliases, `/scim/v2/*`, MCP, or A2A routes automatically.
- Keep `pkg/gateway` public SDK types self-contained (including `WithCustomAuthenticator`, `CustomAuthenticator`, `WithKeyRotationSecretSink`, `WithRoutingPlugin`, `WithPreRouter`, `WithRoutingHints`, `ConnectRealtime`, modality/spend helpers, and `WithHTTPClient`), model pricing history append-only, and `internal/ui/dist/` strictly synced with `web/dist/` within the `<= 560 KB` / `<= 150 KB` gzip bundle budget.

## Scoped Rules

Claude Code discovers Markdown rules in `.claude/rules/`; `paths` frontmatter limits each rule to matching files:

- Go backend: `.claude/rules/go-backend.md`
- Frontend and embedded UI: `.claude/rules/frontend-web.md`
- API and protocol contracts: `.claude/rules/api-contracts.md`

## Verification

- Run focused tests for changed packages; add race-tested repository checks when the change warrants them.
- Run `make specgen` after contract changes and review generated diffs.
- For `web/` changes, run `cd web && npm run typecheck`, `make ui-build`, `diff -rq web/dist internal/ui/dist`, and `go test ./internal/ui/...` (`make ui-check-dist` checks clean `git diff` against HEAD after committing).
- Run E2E tests only when PostgreSQL and Redis are available, and state which checks were run.
