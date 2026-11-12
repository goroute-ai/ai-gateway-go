# API Contracts & Protocol Specifications Guidelines

## Contract Locations
- **Unified Gateway OpenAPI**: `docs/openapi/gateway.openapi.yaml` (OpenAPI 3.1.0).
- **Model Context Protocol (MCP)**: `docs/openapi/mcp.openapi.yaml` and `docs/specs/mcp/2026-07-28/schema.json`.
- **Agent-to-Agent Protocol (A2A)**: `docs/openapi/a2a.openapi.yaml` and `docs/specs/a2a/v1.0/a2a.proto`.
- **Provider OpenAPI Specs**: `docs/openapi/{openai,anthropic,gemini,mistral,ollama}.openapi.yaml`.

## Contract Validation
Before committing any changes to routes, payloads, or protocol handlers:
```bash
make specgen
```
This regenerates gateway DTOs and standard/strict server interfaces, validates the checked-in OpenAPI documents, verifies the generated A2A protobuf file is present, and checks MCP JSON Schema definitions. It enforces route parity for the primary `/v1` route group. Admin, alias, MCP, and A2A route parity is not yet checked, and the generated gateway server interface is not yet wired to every runtime handler.

## Data Plane Wire Compatibility
- Endpoints under `/v1/*` must adhere to standard OpenAI REST schemas:
  - Error responses format: `{"error": {"message": "...", "type": "...", "code": "..."}}`.
  - SSE streaming chunks must emit `data: { ... }\n\n` followed by `data: [DONE]\n\n`.
  - Header attribution: ensure `X-Gateway-*` headers (`X-Gateway-Request-Id`, `X-Gateway-Provider`, `X-Gateway-Model`, `X-Gateway-Cost-Micros`, `X-Gateway-Routing-Time`, `X-Gateway-Cache`) are present.
