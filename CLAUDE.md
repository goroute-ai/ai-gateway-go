# GoRoute AI Gateway — Claude Code Guidelines

GoRoute AI Gateway is an ultra-fast, lightweight AI Gateway, MCP Hub, and Agent-to-Agent (A2A) Router written in 100% pure Go with an embedded React/Vite Operator Web UI.

This guide provides persistent instructions and invariants for Claude Code sessions. For deeper architecture details, see [@AGENTS.md](AGENTS.md) and [@docs/CODEBASE_MAP.md](docs/CODEBASE_MAP.md).

---

## Common Commands

| Task | Command |
| :--- | :--- |
| **Format Go** | `gofmt -w <changed-go-files>` |
| **Check Go formatting** | `gofmt -l .` |
| **Static analysis** | `go vet ./...` |
| **Validate API & protocol specs** | `go run ./cmd/specgen` |
| **Run unit tests (race detector)** | `go test -race -count=1 ./internal/... ./pkg/...` |
| **Run focused package test** | `go test -v -race -run <TestName> ./internal/<pkg>/...` |
| **Run E2E tests** | `go test -race -count=1 ./tests/e2e` *(requires Postgres & Redis)* |
| **Install web UI dependencies** | `make ui-install` *(or `cd web && npm ci`)* |
| **Build web UI & verify budget** | `make ui-build` *(builds `web/`, checks budget, syncs `internal/ui/dist`)* |
| **Verify UI dist sync** | `make ui-check-dist` |
| **Build gateway binary** | `go build ./cmd/gateway` |
| **Full release verification** | `make release-check` |

---

## Repository Invariants

These invariants must be preserved without exception:

1. **Integer Micro-Dollar FinOps**: All financial and spend calculations must use 64-bit integer micro-dollars ($1\text{ USD} = 1,000,000\ \mu\$$) with intermediate pico-dollar precision. Never use floating-point types (`float32`/`float64`) for money.
2. **SSRF & Egress Protection**: Outbound network requests must use `internal/security/network` safe HTTP transport (`SafeTransport`, `DialContext`). Never use raw unvalidated `http.DefaultClient` or unpinned IPs for provider egress.
3. **Fail-Closed RBAC & Auth**: Multi-tenant authorization (`internal/auth/rbac.go`) is strictly fail-closed across all 4 tiers (Organization $\rightarrow$ Team $\rightarrow$ User $\rightarrow$ Virtual Key).
4. **Credential Vault**: Upstream provider API keys and secrets must remain encrypted via AES-256-GCM (`internal/storage/vault.go`) at rest and in transit.
5. **Contract-Guided Architecture**: API and wire contracts are defined in `docs/openapi/gateway.openapi.yaml`, `docs/specs/mcp/`, and `docs/specs/a2a/`. Verify contracts with `go run ./cmd/specgen`.
6. **Single-Binary Web UI Embedding**: The Operator UI in `web/` compiles into `internal/ui/dist/` and is embedded via Go `embed.FS` (`//go:embed all:dist`). Total frontend bundle size must strictly respect budget constraints (< 400 KB total; verified via `web/scripts/check-budget.mjs`).
7. **Immutable Pricing History**: Model pricing updates must append an immutable audit record to `model_pricing_history`.

---

## Code Style & Architectural Patterns

- **Pure Go Standard Library First**: Routing uses `go-chi/chi/v5` with standard `net/http` handlers. Avoid heavyweight framework abstractions.
- **Dependency Flow**: Package dependencies point inward toward domain definitions in `internal/domain`. Handlers parse requests into domain models, invoke domain services, and serialize via `writeJSON` or SSE flushers.
- **Error Handling**: Use structured gateway errors (`domain.NewGatewayError`) with machine-readable error codes, HTTP status mappings, and wrapped internal errors.
- **Zero-Allocation Hot Path**: Hot inference routes (`/v1/chat/completions`) must avoid unnecessary heap allocations, synchronous database queries, or blocking locks.

---

## Modular Rules Directory

For specialized workflows, Claude Code automatically leverages scoped rules in `.claude/rules/`:
- **Go Backend**: `.claude/rules/go-backend.md`
- **Frontend & Web UI**: `.claude/rules/frontend-web.md`
- **API Contracts & Protocols**: `.claude/rules/api-contracts.md`

---

## Verification & Self-Correction Protocol

Before declaring any coding task complete:
1. Run `gofmt -l .` to ensure formatting is pristine.
2. Run `go vet ./...` to ensure zero static analysis warnings.
3. Run targeted unit tests for the modified packages: `go test -race -count=1 ./internal/<modified-pkg>/...`.
4. If contracts changed, run `go run ./cmd/specgen`.
5. If frontend code in `web/` changed, run `make ui-build` to verify the bundle budget and sync `internal/ui/dist`.
6. Build the binary with `go build ./cmd/gateway`.
