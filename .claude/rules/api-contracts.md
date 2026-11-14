---
paths:
  - "docs/openapi/**/*"
  - "docs/specs/**/*"
  - "internal/openapi/**/*.go"
  - "internal/server/server.go"
  - "internal/server/handlers*.go"
  - "internal/adapter/**/*.go"
---
# API Contracts and Protocol Guidelines

## Contract sources

- Gateway HTTP contracts are in `docs/openapi/gateway.openapi.yaml`; related provider contracts are in `docs/openapi/`.
- MCP and A2A protocol schemas are pinned under `docs/specs/`. Keep runtime behavior aligned with the matching protocol contract.
- Some runtime routes and handlers remain handwritten. `make specgen` validates both primary `/v1` and `/admin/v1` route parity, while aliases, MCP, and A2A routes remain verified by focused server and E2E tests.

## Contract changes

- For route, request/response, or protocol changes, update the authoritative contract, implementation, explicit domain mappings, and focused tests together.
- Run `make specgen` to regenerate gateway types and validate contracts; review the generated diff and do not hand-edit generated files.
- Keep `make specgen` route parity green for `/v1` and `/admin/v1`, and add or update focused tests for aliases, MCP, and A2A route groups.

## Wire behavior

- Preserve provider-specific request and response behavior, including Anthropic Messages envelopes, SSE `event: error` framing, tool calls, and usage accounting.
- Preserve standard gateway error envelopes, pre-first-chunk `X-Gateway-Provider` / `X-Gateway-Model` / `X-Gateway-*` response headers, and CORS `Access-Control-Expose-Headers`.
- Keep tenant authorization and guardrail checks on all inference, MCP, and A2A entry points.
