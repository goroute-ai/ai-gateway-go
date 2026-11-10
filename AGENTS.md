# Repository Guide for Coding Agents

GoRoute AI Gateway is a Go service and embeddable SDK that routes inference requests across model providers and exposes MCP and A2A interfaces. This file is the portable entry point for repository guidance; use linked source files as the authority for details.

## Start Here

- Read [the codebase map](docs/CODEBASE_MAP.md) to locate behavior, contracts, configuration, persistence, and tests.
- Read [the documentation index](docs/README.md) for API, architecture, internals, and configuration guides.
- Before editing, inspect the relevant implementation and tests. Treat docs as navigation and explanation, not proof of current behavior.

## Repository Invariants

- Keep public API and provider wire behavior aligned with the applicable OpenAPI or protocol contract.
- Keep provider egress behind the network security policy; inspect `internal/security/network` before adding outbound HTTP calls.
- Preserve tenant identity and authorization checks when changing model, tool, or agent access.
- Financial values use integer micro-dollars; avoid floating-point accounting.
- Generated files must be updated through their documented generator, not hand-edited. Check `go:generate` directives and `Makefile` before changing generated code.
- Keep package dependencies pointed inward toward domain types and interfaces. Add package-specific guidance only where a real local convention needs explanation.

## Common Commands

| Goal | Command |
| --- | --- |
| Format Go | `gofmt -w <changed-go-files>` |
| Check formatting | `gofmt -l .` |
| Static analysis | `go vet ./...` |
| Validate API and protocol specs | `go run ./cmd/specgen` |
| Unit tests (race detector) | `go test -race -count=1 ./internal/... ./pkg/...` |
| End-to-end tests | `go test -race -count=1 ./tests/e2e` (requires PostgreSQL and Redis; see `.github/workflows/ci.yml`) |
| Build | `go build ./cmd/gateway` |

The CI workflow also builds the Docker image. `make release-check` runs formatting in write mode, so prefer the read-only formatting check above when validating an existing worktree.

## Change Expectations

- Update the authoritative contract, config example, migration, or generated output when the change affects it.
- Add or update focused tests alongside behavior changes; run the narrow relevant tests, then applicable repository checks.
- State commands run and any checks not run in the change summary. Do not claim an integration check passed unless its required services were available.
- Preserve unrelated work already present in the working tree.
