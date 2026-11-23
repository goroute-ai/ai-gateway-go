---
name: goroute-codebase-navigator
description: >-
  Locate source files, entrypoints, contracts, migrations, and focused tests across GoRoute AI Gateway.
  Use when starting an unfamiliar task, tracing a request lifecycle, or mapping a feature to its exact Go or React packages.
  Do not use for executing migrations or UI builds directly (use the dedicated domain skills instead).
---

# GoRoute Codebase Navigator

Follow this fast lookup flow before grepping across the entire repository:

## Step 1: Identify the Target Subsystem

Read [references/subsystem-map.md](./references/subsystem-map.md) for the exact package-to-file table covering all 16 subsystems (HTTP Server, 4 Providers, Router, Quotas/FinOps, OIDC/Authz, Vault, Guardrails, MCP, A2A, SDK, CLI, Embedded Web UI, Migrations, and E2E suites).

## Step 2: Check the Authoritative Source of Truth

1. **Runtime behavior**: Read the package implementation and its colocated `*_test.go` files first; treat prose docs as orientation, not proof.
2. **HTTP contracts**: Inspect `docs/openapi/gateway.openapi.yaml` (`127` paths) and `cmd/specgen/routes.go`.
3. **Configuration keys & defaults**: Inspect `internal/config/config.go` and `configs/config.example.yaml`.
4. **Database schema**: Inspect ordered SQL migrations in `migrations/` (`0001`–`0041`) alongside `internal/storage/repository.go`.
5. **Web UI**: Inspect `web/src/views/` and `web/src/api/` (never edit `internal/ui/dist/`).

## Step 3: Trace End-to-End Request Paths

- **Data Plane (`/v1/*`)**:
  `internal/server/server.go` → `middleware*` (RealIP, Tracing, Auth, RBAC) → `internal/validation/` → `internal/guardrails/` (pre-call) → `internal/ratelimit/` (Lua descriptors) → `internal/router/` (PreRouter → FilterChain → Priority Tiers → LoadBalancer → Reliability/Fallbacks) → `internal/adapter/{openai,anthropic,groq,openrouter}/` (via `internal/security/network/`) → `internal/finops/` (micro-dollar ledger).
- **Control Plane (`/admin/v1/*`, `/auth/*`, `/scim/v2/*`)**:
  `internal/server/handlers_admin*.go` / `handlers_auth*.go` / `handlers_scim*.go` → `internal/auth/` (`authorizer.go`, `role_mapping.go`, `vault.go`, `oidc*`) → `internal/storage/` (`postgres_*.go` / `memory_*.go` / `redis.go`) → `audit_siem_sink.go`.
- **Agentic Hub (`/mcp*`, `/a2a*`, `/.well-known/agent-card.json`)**:
  `internal/mcp/` (`hub.go`, `spec/`, `spec_profile.go`) and `internal/a2a/` (`hub.go`, `pb/`, `card.go`) + `internal/orchestrator/`.
