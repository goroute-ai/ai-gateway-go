# OpenAPI Specifications Documentation Hub

This directory serves as the centralized documentation repository for all **OpenAPI Specifications** used by `ai-gateway-go`.

The gateway is moving toward an **OpenAPI-first** workflow. The gateway contract and selected provider contracts exist, but runtime route registration and much gateway request decoding are still handwritten. Generated gateway types and interfaces are now reproducible; they are not yet the runtime source of truth for every route. Provider adapters translate between canonical domain requests and provider wire formats, and only some provider wire formats currently use generated DTOs.

---

## Specification Directory & Source Index

| Provider | Specification File | Format / Version | Upstream Origin / Fetch Command | Core Covered Endpoints |
| :--- | :--- | :---: | :--- | :--- |
| **Gateway Unified Contract** | [`gateway.openapi.yaml`](./gateway.openapi.yaml) | OpenAPI 3.1.0 | `internal/domain`, `internal/server`, and `internal/openapi` | `127` paths across `/v1` (`27`), `/admin/v1` (`88`), `/auth` (`8`), `/openai/v1` (`2`), and `/anthropic/v1` (`2`) |
| **OpenAI** | [`openai.openapi.yaml`](./openai.openapi.yaml) | OpenAPI 3.0.0 | Official OpenAI Repository (release `0c432eb`) | `POST /v1/chat/completions`, `POST /v1/embeddings`, `GET /v1/models` |
| **Anthropic Claude** | [`anthropic.openapi.yaml`](./anthropic.openapi.yaml) | OpenAPI 3.0.0 | Anthropic Messages REST API | `POST /v1/messages`, `POST /v1/messages/count_tokens`, `GET /v1/models` |
| **Groq** | [`groq.openapi.yaml`](./groq.openapi.yaml) | OpenAPI 3.0.3 | Groq OpenAI-Compatible Inference REST Spec | `POST /openai/v1/chat/completions`, `POST /openai/v1/completions`, `POST /openai/v1/audio/*`, `GET /openai/v1/models` |
| **OpenRouter** | [`openrouter.openapi.yaml`](./openrouter.openapi.yaml) | OpenAPI 3.0.3 | OpenRouter Unified Inference REST Spec | `POST /api/v1/chat/completions`, `GET /api/v1/models` |

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
        ┌───────────────────┬─────────┴──────────┬──────────────────┐
        ▼                   ▼                    ▼                  ▼
┌────────────────┐ ┌──────────────────┐ ┌────────────────┐ ┌────────────────────┐
│  openai.yaml   │ │  anthropic.yaml  │ │   groq.yaml    │ │  openrouter.yaml   │
│ ChatCompletion │ │MessageRequestBody│ │ ChatCompletion │ │  ChatCompletion    │
│ (Bearer auth)  │ │  (x-api-key)     │ │ (Bearer auth)  │ │  (Bearer+Referer)  │
└────────────────┘ └──────────────────┘ └────────────────┘ └────────────────────┘
```

1. **Reproducible Gateway Generation**: `gateway.gen.go` is generated from `gateway.openapi.yaml` with `oapi-codegen` v2.8.0 using [`gateway.codegen.yaml`](./gateway.codegen.yaml), alongside provider DTO packages generated from `openai.codegen.yaml`, `anthropic.codegen.yaml`, `groq.codegen.yaml`, and `openrouter.codegen.yaml`. CI regenerates via `make specgen` and fails if committed output is stale.
2. **Contract Validation**: `oapi-codegen` validates the gateway and provider OpenAPI documents during generation. `cmd/specgen` semantically validates all checked-in OpenAPI documents (`gateway`, `openai`, `anthropic`, `groq`, `openrouter`), the MCP JSON Schema, and the generated A2A protobuf descriptor. Route parity is enforced across `/v1`, `/admin/v1`, `/auth`, `/openai/v1`, and `/anthropic/v1`.
3. **Runtime Mapping**: Provider adapters (`internal/adapter/{openai,anthropic,groq,openrouter}`) translate canonical requests/responses using the OpenAPI-generated DTOs in `internal/openapi/providers`.

---

## Updating Specifications

To refresh or update the upstream specifications:

### 1. Refresh OpenAI Specification
```bash
curl -s "https://raw.githubusercontent.com/openai/openai-openapi/0c432eb66fd0c758fd8b9bd69db41c1096e5f4db/openapi.yaml" -o docs/openapi/openai.openapi.yaml
```

### 2. Validate All Specifications
```bash
make specgen
```
