# API Contracts & Protocol Specifications Guidelines

## Contract Locations
- **Unified Gateway OpenAPI**: `docs/openapi/gateway.openapi.yaml` (OpenAPI 3.1.0).
- **Model Context Protocol (MCP)**: `docs/openapi/mcp.openapi.yaml` and `docs/specs/mcp/2026-07-28/schema.json`.
- **Agent-to-Agent Protocol (A2A)**: `docs/openapi/a2a.openapi.yaml` and `docs/specs/a2a/v1.0/a2a.proto`.
- **Upstream Provider OpenAPI Specs**: `docs/openapi/providers/*.yaml`.

## Contract Validation
Before committing any changes to routes, payloads, or protocol handlers:
```bash
go run ./cmd/specgen
```
This utility parses and validates all checked-in OpenAPI 3.0/3.1 files, verifies that generated A2A protobuf code is present and up to date, and checks MCP JSON Schema definitions.

## Data Plane Wire Compatibility
- Endpoints under `/v1/*` must adhere to standard OpenAI REST schemas:
  - Error responses format: `{"error": {"message": "...", "type": "...", "code": "..."}}`.
  - SSE streaming chunks must emit `data: { ... }\n\n` followed by `data: [DONE]\n\n`.
  - Header attribution: ensure `X-Gateway-*` headers (`X-Gateway-Request-Id`, `X-Gateway-Provider`, `X-Gateway-Model`, `X-Gateway-Cost-Micros`, `X-Gateway-Routing-Time`, `X-Gateway-Cache`) are present.
