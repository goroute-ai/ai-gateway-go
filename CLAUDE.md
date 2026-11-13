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
| Unit tests with race detector | `go test -race -count=1 ./internal/... ./pkg/...` |
| Focused package tests | `go test -race -count=1 ./internal/<pkg>/...` |
| E2E tests | `go test -race -count=1 ./tests/e2e` (requires PostgreSQL and Redis) |
| Build gateway into ignored output directory | `go build -o bin/ai-gateway ./cmd/gateway` |
| Build and synchronize UI assets | `make ui-build` |
| Check embedded UI asset parity | `make ui-check-dist` |

`make release-check` runs `gofmt -w` through its `fmt` prerequisite, then vet, generation, unit tests, and E2E tests. It modifies files and requires PostgreSQL and Redis; inspect its prerequisites before running it on an existing worktree. `make ui-build` writes generated files under `internal/ui/dist/`.

## v1.5.0 Invariants

- Route provider egress through `internal/security/network`; use the shared `network.NewHTTPClient` policy rather than an unconfigured client.
- Preserve tenant identity and fail-closed authorization for operator roles, virtual keys, MCP tools, and A2A agents.
- Keep accounting in integer micro-dollars, with integer pico-dollar intermediate arithmetic in `internal/finops`; never use floating point for cost or balance calculations.
- Keep provider credentials encrypted through the vault. Production validation must reject default admin, encryption, and JWT keys when either `ENV` or `GATEWAY_ENV` signals production.
- Preserve file-upload quotas and concurrency limits. Defaults are 5 GiB per organization and 8 concurrent uploads; zero disables the corresponding limit.
- Preserve durable spend delivery, idempotent Redis reconciliation, upper-bound budget reservations, lease renewal, and budget-reset synchronization.
- Preserve streaming guardrail inspection and redaction, including fail-closed policy handling and `logging_only` behavior.
- Treat OpenAPI and protocol specs as contract sources. `make specgen` checks primary `/v1` route parity; it does not prove parity for admin, aliases, MCP, or A2A routes.
- Keep model pricing history append-only and update the frontend source in `web/`; `internal/ui/dist/` is generated and must stay within the checked bundle budget.

## Scoped Rules

Claude Code discovers Markdown rules in `.claude/rules/`; `paths` frontmatter limits each rule to matching files:

- Go backend: `.claude/rules/go-backend.md`
- Frontend and embedded UI: `.claude/rules/frontend-web.md`
- API and protocol contracts: `.claude/rules/api-contracts.md`

## Verification

- Run focused tests for changed packages; add race-tested repository checks when the change warrants them.
- Run `make specgen` after contract changes and review generated diffs.
- For `web/` changes, run `make ui-build`, `make ui-check-dist`, and `go test ./internal/ui/...`.
- Run E2E tests only when PostgreSQL and Redis are available.
- Report the commands run and any checks not run. Do not claim service-dependent checks passed unless those services were available.
