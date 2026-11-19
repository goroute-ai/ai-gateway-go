---
paths:
  - "docs/openapi/**/*"
  - "docs/specs/**/*"
  - "internal/openapi/**/*.go"
  - "internal/server/server.go"
  - "internal/server/handlers*.go"
  - "internal/server/security_headers.go"
  - "internal/server/quota_descriptors.go"
  - "internal/adapter/**/*.go"
  - "docs/API_REFERENCE.md"
---
# API Contracts and Protocol Guidelines

## Contract sources

- Gateway HTTP contracts are in `docs/openapi/gateway.openapi.yaml`; related provider contracts are in `docs/openapi/`.
- MCP and A2A protocol schemas are pinned under `docs/specs/`. Keep runtime behavior aligned with the matching protocol contract.
- Some runtime routes and handlers remain handwritten. `make specgen` validates `/v1`, `/admin/v1`, and `/auth` route parity (`106` OpenAPI paths: `24` `/v1`, `72` `/admin/v1`, `10` `/auth`), while unversioned/provider aliases, `/scim/v2/*`, MCP, and A2A routes remain verified by focused server and E2E tests.

## Contract changes

- For route, request/response, or protocol changes, update the authoritative contract, implementation, explicit domain mappings, and focused tests together.
- Run `make specgen` to regenerate gateway types and validate contracts; review the generated diff and do not hand-edit generated files.
- Keep `make specgen` route parity green for `/v1`, `/admin/v1`, and `/auth`, and add or update focused tests for aliases, `/scim/v2/*`, MCP, and A2A route groups.

## Wire behavior

- Preserve provider-specific request and response behavior, including Anthropic Messages envelopes, SSE `event: error` framing, tool calls, and usage accounting.
- Preserve Operator cookie sessions (`OperatorSession` `goroute_session` cookie + `X-CSRF-Token` validation on cookie-authenticated mutations) and inbound impersonation/delegation headers (`X-Gateway-Impersonate-User`, `X-Gateway-Impersonate-Email`, `X-Gateway-Delegated-User-Id`, `X-Gateway-Delegated-Team-Id`).
- Preserve standard gateway error envelopes, pre-first-chunk `X-Gateway-Provider` / `X-Gateway-Model` / `X-Gateway-*` response headers, key rotation deprecation headers (`X-Gateway-Key-Deprecated`, `X-Gateway-Key-Revoke-At`), soft/fallback budget headers (`X-Gateway-Budget-Throttled`, `X-Gateway-Budget-Fallback`, `X-Gateway-Original-Model`), and CORS `Access-Control-Expose-Headers`.
- Keep tenant authorization and guardrail checks on all inference, MCP, and A2A entry points.
