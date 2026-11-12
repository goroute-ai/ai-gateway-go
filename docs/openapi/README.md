# OpenAPI Specifications Documentation Hub

This directory serves as the centralized documentation repository for all **OpenAPI Specifications** used by `ai-gateway-go`.

The gateway is moving toward an **OpenAPI-first** workflow. The gateway contract and selected provider contracts exist, but runtime route registration and much gateway request decoding are still handwritten. Generated gateway types and interfaces are now reproducible; they are not yet the runtime source of truth for every route. Provider adapters translate between canonical domain requests and provider wire formats, and only some provider wire formats currently use generated DTOs.

---

## Specification Directory & Source Index

| Provider | Specification File | Format / Version | Upstream Origin / Fetch Command | Core Covered Endpoints |
| :--- | :--- | :---: | :--- | :--- |
| **Gateway Unified Contract** | [`gateway.openapi.yaml`](./gateway.openapi.yaml) | OpenAPI 3.1.0 | `internal/domain`, `internal/server`, and `internal/openapi` | All 23 primary `/v1` paths; selected admin operations, with remaining contract gaps documented below |
| **Google Gemini** | [`gemini.openapi.yaml`](./gemini.openapi.yaml) | OpenAPI 3.0.3 | Google Discovery Engine v1beta:<br/>`curl "https://generativelanguage.googleapis.com/$discovery/OPENAPI3_0?version=v1beta"` | `POST /v1beta/models/{model}:generateContent`<br/>`POST /v1beta/models/{model}:streamGenerateContent`<br/>`POST /v1beta/models/{model}:embedContent`<br/>`GET /v1beta/models` |
| **OpenAI** | [`openai.openapi.yaml`](./openai.openapi.yaml) | OpenAPI 3.0.0 | Official OpenAI Repository (release `0c432eb`):<br/>`curl "https://raw.githubusercontent.com/openai/openai-openapi/0c432eb66fd0c758fd8b9bd69db41c1096e5f4db/openapi.yaml"` | `POST /v1/chat/completions`<br/>`POST /v1/embeddings`<br/>`GET /v1/models` |
| **Anthropic Claude** | [`anthropic.openapi.yaml`](./anthropic.openapi.yaml) | OpenAPI 3.0.0 | Anthropic Messages REST API | `POST /v1/messages`<br/>`POST /v1/messages/count_tokens`<br/>`GET /v1/models` |
| **Mistral AI** | [`mistral.openapi.yaml`](./mistral.openapi.yaml) | OpenAPI 3.1.0 | Mistral AI Platform Spec | `POST /v1/chat/completions`<br/>`POST /v1/embeddings`<br/>`GET /v1/models` |
| **Ollama** | [`ollama.openapi.yaml`](./ollama.openapi.yaml) | OpenAPI 3.1.0 | Ollama Local Inference REST Spec | `POST /api/chat`<br/>`POST /api/embed`<br/>`GET /api/tags` |

---

## How the Gateway Uses These Specifications

```
                       ┌───────────────────────────────┐
                       │     Client Application        │
                       └──────────────┬────────────────┘
                                      │
                      (Standard OpenAI Wire Format)
                                      ▼
                       ┌───────────────────────────────┐
                       │  gateway.openapi.yaml (Hub)   │
                       │    CanonicalChatRequest       │
                       └──────────────┬────────────────┘
                                      │
             ┌────────────────────────┼────────────────────────┐
             ▼                        ▼                        ▼
┌────────────────────────┐┌────────────────────────┐┌────────────────────────┐
│  gemini.openapi.yaml   ││ anthropic.openapi.yaml ││  openai.openapi.yaml   │
│ GenerateContentRequest ││  MessageRequestBody    ││  CreateChatCompletion  │
│  (x-goog-api-key)      ││   (x-api-key, 2023)    ││    (Bearer auth)       │
└────────────────────────┘└────────────────────────┘└────────────────────────┘
```

1. **Reproducible Gateway Generation**: `gateway.gen.go` is generated from `gateway.openapi.yaml` with `oapi-codegen` v2.8.0 using [`gateway.codegen.yaml`](./gateway.codegen.yaml). It contains gateway DTOs plus standard-library and strict server interfaces. CI regenerates the file and fails if committed output is stale.
2. **Contract Validation**: `oapi-codegen` validates the gateway OpenAPI document during generation. `cmd/specgen` semantically validates the checked-in OpenAPI documents and checks the MCP JSON Schema and generated A2A protobuf file. The validator currently skips schema validation of example and default values because upstream provider specs include invalid or overlapping examples/defaults. The local OpenAI and Gemini snapshots contain small normalization fixes for invalid values and path-template syntax. Route parity is enforced for the primary `/v1` group; it does not yet compare all aliases, admin, MCP, A2A, health, metrics, and UI routes.
3. **Runtime Mapping**: Existing chi routes and handlers still decode many requests into domain or handler-local structs. The generated gateway interfaces are not yet implemented by `GatewayServer` or used to register all runtime routes. Provider adapters translate wire payloads and normalize errors; only selected adapters use generated provider DTOs.

### Current Contract Coverage Gaps

`/v1/audio/translations` and `/v1/messages/count_tokens` were registered in the server but absent from the gateway contract; both are now documented. The `/admin/v1` contract still documents only a small subset of registered control-plane routes. Aliases (`/openai/v1/*`, `/anthropic/v1/*`, and unversioned paths), optional MCP/A2A endpoints, operational endpoints, and the rest of the admin routes have not yet been reconciled with OpenAPI. Do not treat generated interfaces as proof that the runtime implements every documented operation. The strict wrapper provides typed decoding and response encoding; it does not validate incoming requests against every JSON Schema by itself.

---

## Updating Specifications

To refresh or update the upstream specifications:

### 1. Refresh Google Gemini Specification
```bash
# Fetch from Google Discovery and pipe or convert to YAML:
curl -s "https://generativelanguage.googleapis.com/\$discovery/OPENAPI3_0?version=v1beta" | yq -P > docs/openapi/gemini.openapi.yaml
```
*(If using an authenticated key)*:
```bash
curl -s "https://generativelanguage.googleapis.com/\$discovery/OPENAPI3_0?version=v1beta&key=${GOOGLE_API_KEY}" | yq -P > docs/openapi/gemini.openapi.yaml
```

### 2. Refresh OpenAI Specification
```bash
curl -s "https://raw.githubusercontent.com/openai/openai-openapi/0c432eb66fd0c758fd8b9bd69db41c1096e5f4db/openapi.yaml" -o docs/openapi/openai.openapi.yaml
```

### 3. Validate All Specifications
```bash
make specgen
```
