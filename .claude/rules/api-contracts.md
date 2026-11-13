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
- Runtime routes and handlers remain partly handwritten. OpenAPI generation does not prove full parity for admin, alias, MCP, or A2A routes.

## Contract changes

- For route, request/response, or protocol changes, update the authoritative contract, implementation, explicit domain mappings, and focused tests together.
- Run `make specgen` to regenerate gateway types and validate contracts; review the generated diff and do not hand-edit generated files.
- The current route-parity check covers the primary `/v1` route group only. Add or update focused tests for other route groups.

## Wire behavior

- Preserve provider-specific request and response behavior, including Anthropic Messages envelopes, SSE event framing, tool calls, and usage accounting.
- Preserve standard gateway error envelopes and documented `X-Gateway-*` response headers where applicable.
- Keep tenant authorization and guardrail checks on all inference, MCP, and A2A entry points.
