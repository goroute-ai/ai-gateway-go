---
name: goroute-openapi-contract
description: >-
  Update OpenAPI 3.1/3.0 contracts, add or modify HTTP endpoints or provider adapters, and regenerate Go DTOs and MCP protocol packages via make specgen.
  Use when changing /v1, /admin/v1, /auth routes, provider specs (openai, anthropic, groq, openrouter), or MCP YAML schemas.
  Do not use for database-only or UI-only edits.
---

# GoRoute OpenAPI & Protocol Contract Workflow

## Step 1: Edit the Authoritative Specification First

- **Gateway HTTP routes (`/v1`, `/admin/v1`, `/auth`, `/openai/v1`, `/anthropic/v1`)**: Edit `docs/openapi/gateway.openapi.yaml`.
- **Provider wire contracts**: Edit `docs/openapi/{openai,anthropic,groq,openrouter}.openapi.yaml` and its matching `*.codegen.yaml`.
- **MCP protocol schemas**: Update `docs/specs/mcp/<version>/schema.yaml` (`2024-11-05`..`2026-07-28`) and keep `internal/mcp/spec/schemas/` synced via `cmd/mcpgen`.

Never hand-edit generated files under `internal/openapi/` or `internal/mcp/spec/v*`.

## Step 2: Update Runtime Handlers & Route Registration

1. Implement or update the HTTP handler in `internal/server/handlers_*.go` with explicit domain conversions and RBAC/authz enforcement.
2. Register new `/v1` routes **inline** inside `r.Route("/v1", ...)` in `internal/server/server.go` so `cmd/specgen/routes.go` AST route parity verification discovers them.
3. For provider adapters under `internal/adapter/<provider>/`, route all upstream HTTP calls through `internal/security/network` and validate custom base URLs with `adapter.ValidateAndResolveBaseURL`.

## Step 3: Regenerate & Verify Contract Parity

Run the contract generator and parity verifier:

```bash
make specgen
```

Confirm all checks pass:
- `cmd/mcpgen` regenerates all 5 MCP schema releases (`2024-11-05` through `2026-07-28`).
- `cmd/specgen` reports `Verified /v1, /admin/v1, and /auth route/spec parity` and validates all OpenAPI & A2A protobuf specs (`127` gateway paths baseline).

## Step 4: Test & Sync Docs

```bash
go test -race -count=1 ./cmd/specgen/... ./internal/server/... ./internal/adapter/... ./internal/mcp/...
```

Update `docs/API_REFERENCE.md` and `docs/openapi/README.md` if the path count or request/response schema changed.
