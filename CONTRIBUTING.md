# Contributing to GoRoute AI Gateway

Thank you for your interest in contributing to **GoRoute AI Gateway**! 🎉

GoRoute AI Gateway is an enterprise-grade, high-performance Go service and embeddable SDK that routes inference requests across model providers, exposes Model Context Protocol (MCP) virtual hubs, and connects Agent-to-Agent (A2A) networks.

---

## Code of Conduct

We are committed to providing a welcoming, inclusive, and harassment-free environment for everyone. Please be respectful, constructive, and collaborative in all issues, pull requests, and discussions.

---

## Architectural Invariants

Before writing code, please review the core repository invariants defined in [`CLAUDE.md`](./CLAUDE.md), [`AGENTS.md`](./AGENTS.md), and [`docs/CODEBASE_MAP.md`](./docs/CODEBASE_MAP.md):

1. **100% Pure Go, Zero CGO**: All adapters, protocol parsers, and utilities must compile with `CGO_ENABLED=0` across Linux, macOS, and Windows.
2. **FinOps Integer Accounting**: All financial calculations use 64-bit integer micro-dollars (\$1.00 = 1,000,000 µ\$). Never use floating-point math for cost accumulation or pricing.
3. **SSRF-Protected Network Egress**: All outbound HTTP traffic to upstream LLM providers or webhooks must route through the SSRF-guarded transport in `internal/security/network`.
4. **Multi-Tenant Isolation**: Boundary 1 Virtual Key authentication and multi-tenant RBAC allowlists (`OrgID > TeamID > UserID > VirtualKeyID`) must be preserved across all endpoints.
5. **OpenAPI-First Design (in progress)**: The gateway OpenAPI contract ([`docs/openapi/gateway.openapi.yaml`](./docs/openapi/gateway.openapi.yaml)) and protocol schemas under `docs/specs/` are authoritative. Gateway DTOs and interfaces are generated, and primary `/v1` routes are checked against the contract. Update handlers and explicit domain mappings as needed, then run `make specgen` after contract changes.
6. **Tri-State Capabilities**: Model capabilities must use explicit tri-state semantics (`supported`, `unsupported`, `unknown`). Never downgrade `unknown` to `unsupported` unless verified.
7. **Single-Binary Web UI Embedding**: Frontend assets in `web/` are compiled into `internal/ui/dist/` and embedded via Go `embed.FS`. The uncompressed production bundle must remain under 400 KB, strictly enforced by `web/scripts/check-budget.mjs`.

---

## Getting Started

### Prerequisites
- **Go**: Version `1.22+` (Go `1.26` recommended)
- **Git**
- **Node.js 18+ & npm** (required only if contributing to the Operator Web UI in `web/`)
- **Docker** (optional, for live PostgreSQL and Redis integration tests)

### Local Build and Test
Clone the repository and verify your local toolchain:

```bash
# Clone the repository
git clone https://github.com/goroute-ai/ai-gateway-go.git
cd ai-gateway-go

# Verify Go dependencies
go mod download

# Run unit tests with the Go race detector
go test -race -count=1 ./internal/... ./pkg/...

# Generate gateway DTOs and validate OpenAPI, JSON Schema & Protobuf contracts
make specgen

# (Optional) Build frontend assets and verify bundle budget
make ui-build

# Build the gateway executable (with embedded UI)
go build -o bin/ai-gateway ./cmd/gateway

# Run full release verification check
make release-check
```

### Developing the Operator Web UI
When making changes to the embedded React console in `web/`:
```bash
# Install frontend dependencies
make ui-install

# Start Vite live reload dev server (proxies to http://localhost:8080)
make ui-dev

# Compile assets, check bundle budget, and synchronize to internal/ui/dist/
make ui-build

# Verify that embedded distribution is in sync with web/
make ui-check-dist
```

---

## Good First Issues & Starter Tasks

If you are new to the codebase, look for issues labeled [`good first issue`](https://github.com/goroute-ai/ai-gateway-go/labels/good%20first%20issue) or [`help wanted`](https://github.com/goroute-ai/ai-gateway-go/labels/help%20wanted).

Here are great areas to get started:

### 1. Add an OpenAI-Compatible Provider Profile
GoRoute has a certified dialect engine in [`internal/adapter/openaicompat/builtin_profiles.go`](./internal/adapter/openaicompat/builtin_profiles.go). Adding a new OpenAI-compatible provider (e.g. specialized regional or inference clouds) takes just a few lines:
```go
RegisterBuiltinProfile(CertifiedProfile{
    Provider:      "myprovider",
    DisplayName:   "My Provider Cloud",
    DefaultBaseURL: "https://api.myprovider.com/v1",
    HeaderAuthKey: "Authorization",
    AuthPrefix:    "Bearer ",
    // Configure parameter quirks and reasoning field extractions
})
```

### 2. Implement a Secondary Modality Adapter
Expand modality coverage for:
- **Voyage AI Rerank**: Implement `adapter.RerankAdapter` calling Voyage's `/v1/rerank` endpoint.
- **AWS Bedrock Rerank**: Implement `adapter.RerankAdapter` for Bedrock's `amazon.rerank-v1`.
- **ElevenLabs Speech**: Implement `adapter.AudioAdapter` for ElevenLabs TTS.
- **Vertex AI Imagen**: Implement `adapter.ImageAdapter` for Imagen 3.

### 3. Documentation & Examples
- Add client code examples (Python, TypeScript, cURL, Go SDK).
- Improve error troubleshooting guides in `docs/`.

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
- `feat(component): add new feature` (e.g. `feat(adapter): add voyage rerank adapter`)
- `fix(component): fix bug description` (e.g. `fix(finops): prevent integer overflow in audio calculation`)
- `docs(component): update documentation`
- `test(component): add unit or integration tests`
- `refactor(component): code cleanup without functional change`
- `chore(release): bump version and update changelog`

### 3. Pre-Pull Request Verification Checklist
Before submitting a pull request, run the release verification suite:

```bash
# 1. Format code
gofmt -s -w .

# 2. Check formatting
gofmt -l .

# 3. Static analysis
go vet ./...

# 4. Contract validation
make specgen

# 5. Unit tests with race detector
go test -race -count=1 ./internal/... ./pkg/...

# 6. Build executable
go build -o /dev/null ./cmd/gateway
```

Or simply run:
```bash
make release-check
```

---

## Submitting a Pull Request (PR)

1. Push your branch to your fork or branch on GitHub.
2. Open a Pull Request against the `main` branch.
3. In the PR description:
   - Reference any related issues (e.g., `Closes #123`).
   - Describe what changed and why.
   - List the commands run and tests executed.
4. Maintainers will review your PR and run CI checks.

---

## Community & Questions

- **Issues**: Report bugs or suggest features via [GitHub Issues](https://github.com/goroute-ai/ai-gateway-go/issues).
- **Discussions**: Ask questions or share ideas via [GitHub Discussions](https://github.com/goroute-ai/ai-gateway-go/discussions).

Thank you for helping make GoRoute AI Gateway faster, safer, and more reliable! 🚀
