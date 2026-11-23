# Contributing to GoRoute AI Gateway

Thank you for your interest in contributing to **GoRoute AI Gateway**!

GoRoute AI Gateway is a Go service and embeddable SDK (`v0.1.0`) that routes inference requests across OpenAPI-first model providers (`openai`, `anthropic`, `groq`, `openrouter`), exposes UI-selectable multi-release Model Context Protocol (MCP) virtual hubs, and connects Agent-to-Agent (A2A) networks.

---

## Code of Conduct

We are committed to providing a welcoming, inclusive, and harassment-free environment for everyone. Please be respectful, constructive, and collaborative in all issues, pull requests, and discussions.

---

## Architectural Invariants

Before writing code, review [`CLAUDE.md`](./CLAUDE.md) for Claude Code workflow and shared [repository guidance in `AGENTS.md`](./AGENTS.md), which the Claude guide imports. Use the [`codebase map`](./docs/CODEBASE_MAP.md) to locate implementation and tests:

1. **100% Pure Go, Zero CGO**: All adapters, protocol parsers, and utilities must compile with `CGO_ENABLED=0` across Linux, macOS, and Windows.
2. **FinOps Integer Accounting**: All financial calculations use 64-bit integer micro-dollars (`$1.00 = 1,000,000 µ$`). Never use floating-point math for cost accumulation or pricing.
3. **SSRF-Protected Network Egress**: All outbound HTTP traffic to upstream LLM providers or webhooks must route through the SSRF-guarded transport in `internal/security/network`. Admin credential `BaseURL` inputs and adapter `ListModels` endpoints must validate URLs via `adapter.ValidateAndResolveBaseURL`, and remote media fetches must use the strict HTTPS-only public `mediaPolicy`.
4. **Multi-Tenant Isolation & Security Headers**: Boundary 1 Virtual Key / JWT authentication, tri-state multi-tenant RBAC allowlists (`null` inherit vs `[]` deny all across `Org > Team > User > VirtualKey`), fail-closed quota/policy checks, Redis Pub/Sub cross-replica invalidation, and `SecurityHeadersMiddleware` ([`internal/server/security_headers.go`](./internal/server/security_headers.go)) must be preserved across all endpoints.
5. **OpenAPI-First Design**: The gateway OpenAPI contract ([`docs/openapi/gateway.openapi.yaml`](./docs/openapi/gateway.openapi.yaml)) and protocol schemas under `docs/specs/` are authoritative. Gateway DTOs, provider DTOs, and MCP spec types/validators are generated, and `/v1`, `/admin/v1`, and `/auth` routes (`127` OpenAPI paths: `27` `/v1`, `88` `/admin/v1`, `8` `/auth`, `4` provider aliases) are checked against the contract. Update handlers and explicit domain mappings as needed, then run `make specgen` after contract changes.
6. **Tri-State Capabilities**: Model capabilities must use explicit tri-state semantics (`supported`, `unsupported`, `unknown`). Never downgrade `unknown` to `unsupported` unless verified.
7. **Single-Binary Web UI Embedding**: Frontend assets in `web/` are compiled into `internal/ui/dist/` and embedded via Go `embed.FS`. The production bundle must remain within `<= 700 KB` uncompressed and `<= 185 KB` gzipped, strictly enforced by `web/scripts/check-budget.mjs`.
8. **Secret & CI Hygiene**: Never commit real or realistic secret/token literals—even in unit tests (construct synthetic fixtures dynamically if needed). Keep tests compatible with `.gitleaks.toml` and GitHub Push Protection.

---

## Getting Started

### Prerequisites
- **Go**: Version `1.26.0+` (matching [`go.mod`](./go.mod))
- **Git**
- **Node.js `20+` & npm** (required only if contributing to the Operator Web UI in `web/`)
- **Optional Tooling**: **Docker** (live PostgreSQL 16 + Redis 7 integration tests), **`gitleaks`**, and **`govulncheck`**

### Local Build and Test
Clone the repository and verify your local toolchain:

```bash
# Clone the repository
git clone https://github.com/goroute-ai/ai-gateway-go.git
cd ai-gateway-go

# Download Go dependencies
go mod download

# Run unit tests with the Go race detector across all packages
go test -race -count=1 ./internal/... ./pkg/... ./cmd/... ./tests/guardrails/...

# Generate gateway DTOs and validate OpenAPI, JSON Schema & Protobuf contracts
make specgen

# (Optional) Build frontend assets, check bundle budget, and sync internal/ui/dist
make ui-build

# Build the gateway executable (with embedded UI)
make build

# Optional: start PostgreSQL 16 + Redis 7 and run strict live-stack Go & Browser UI E2E tests (see docs/TESTING.md)
make test-live-up
make test-e2e-strict
make test-ui-e2e
make test-live-down

# Optional: run security checks
make test-security
```

> [!NOTE]
> `make release-check` runs `gofmt -s -w .` in write mode and invokes `test-e2e` (which skips live-dependency tests unless PostgreSQL and Redis are already running). Prefer the read-only `gofmt -l .` check and `make test-live-up && make test-e2e-strict` when validating changes before committing.

### Developing the Operator Web UI
When making changes to the embedded React console in `web/`:
```bash
# Install frontend dependencies
make ui-install

# Start Vite dev server on http://localhost:5173 (proxies /admin/v1, /v1, /mcp-rest to http://localhost:8080)
make ui-dev

# Typecheck TypeScript sources
(cd web && npm run typecheck)

# Compile assets, check bundle budget, and synchronize to internal/ui/dist/
make ui-build

# Verify that embedded distribution is cleanly synchronized in git
make ui-check-dist
```

---

## Good First Issues & Starter Tasks

If you are new to the codebase, look for issues labeled [`good first issue`](https://github.com/goroute-ai/ai-gateway-go/labels/good%20first%20issue) or [`help wanted`](https://github.com/goroute-ai/ai-gateway-go/labels/help%20wanted).

Here are great areas to get started:

### 1. Add or Extend an OpenAPI-First Provider Adapter
All first-class providers (`openai`, `anthropic`, `groq`, `openrouter`) generate wire DTOs directly from pinned specifications under [`docs/openapi/`](./docs/openapi/README.md) via `make specgen`:
1. Pin the upstream OpenAPI spec (`docs/openapi/<provider>.openapi.yaml`) and codegen config (`docs/openapi/<provider>.codegen.yaml`).
2. Add the `//go:generate` directive in `internal/openapi/generate.go` and run `make specgen`.
3. Implement `adapter.ProviderAdapter` under `internal/adapter/<provider>/` using the generated DTOs and `internal/security/network`.

### 2. Expand Protocol & Safety Coverage
- **MCP Protocol Extensions**: Extend multi-release schema tests in [`internal/mcp/schema_conformance_test.go`](./internal/mcp/schema_conformance_test.go) or `SpecProfile` helpers in `internal/mcp/spec_profile.go`.
- **Custom Guardrail Drivers**: Add new safety or policy scanner drivers under `internal/guardrails/drivers/`.

### 3. Documentation & Examples
- Add client code examples (Python, TypeScript, cURL, Go SDK via `pkg/gateway`).
- Improve configuration and troubleshooting guides in [`docs/`](./docs/).

---

## How to Make a Change

### 1. Branching & Naming
Create a feature branch off `main`:
```bash
git checkout -b feat/my-new-feature
# or: git checkout -b fix/issue-description
```

### 2. Commit Message Conventions
We follow [Conventional Commits](https://www.conventionalcommits.org/):
- `feat(component): add new feature` (e.g. `feat(mcp): add schema validation rule`)
- `fix(component): fix bug description` (e.g. `fix(finops): prevent integer overflow in audio calculation`)
- `docs(component): update documentation`
- `test(component): add unit or integration tests`
- `refactor(component): code cleanup without functional change`
- `chore(release): bump version and update changelog`

### 3. Pre-Pull Request Verification Checklist
Run the same validation gates checked by [`.github/workflows/ci.yml`](./.github/workflows/ci.yml):

```bash
# 1. Read-only formatting check (run `gofmt -s -w <files>` if anything is listed)
test -z "$(gofmt -l .)"

# 2. Static analysis
go vet ./...

# 3. OpenAPI / Protobuf contract regeneration & parity check
make specgen
git diff --exit-code -- internal/openapi/gateway.gen.go

# 4. Unit tests with race detector
go test -race -count=1 ./internal/... ./pkg/... ./cmd/... ./tests/guardrails/...

# 5. If web/ changed: TypeScript check, bundle budget build, and dist sync check
(cd web && npm run typecheck)
make ui-build
make ui-check-dist

# 6. Secret scan and binary build verification
gitleaks detect --source=. --config=.gitleaks.toml --no-git
go build -o /dev/null ./cmd/gateway
```

When changing storage, auth, caching, FinOps, or HTTP/UI routes, also verify live PostgreSQL + Redis Go and Playwright UI E2E tests (`make test-live-up && make test-e2e-strict && make test-ui-e2e && make test-live-down`, see [`docs/TESTING.md`](./docs/TESTING.md)).

---

## Submitting a Pull Request (PR)

1. Push your branch to your fork or branch on GitHub.
2. Open a Pull Request against the `main` branch.
3. In the PR description:
   - Reference any related issues (e.g., `Closes #123`).
   - Describe what changed and why.
   - List the commands run and tests executed (noting any live-service checks skipped if PostgreSQL/Redis/Playwright were unavailable).
4. Maintainers will review your PR and verify CI (`CI` and `CodeQL`) passes before merging.

---

## Community & Questions

- **Issues**: Report bugs or suggest features via [GitHub Issues](https://github.com/goroute-ai/ai-gateway-go/issues).
- **Security Reports**: Follow the private disclosure instructions in [`SECURITY.md`](./SECURITY.md).
- **Discussions**: Ask questions or share ideas via [GitHub Discussions](https://github.com/goroute-ai/ai-gateway-go/discussions).

Thank you for helping make GoRoute AI Gateway faster, safer, and more reliable!
