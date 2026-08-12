# OpenAPI Specifications Documentation Hub

This directory serves as the centralized documentation repository for all **OpenAPI Specifications** used by `ai-gateway-go`.

The gateway uses an **OpenAPI Contract-First** architecture: every provider adapter translates between the unified public ingress contract and each upstream provider's native OpenAPI schema.

---

## Specification Directory & Source Index

| Provider | Specification File | Format / Version | Upstream Origin / Fetch Command | Core Covered Endpoints |
| :--- | :--- | :---: | :--- | :--- |
| **Gateway Unified Contract** | [`gateway.openapi.yaml`](./gateway.openapi.yaml) | OpenAPI 3.1.0 | `internal/domain` & `api/openapi` | `POST /v1/chat/completions`<br/>`POST /v1/embeddings`<br/>`GET /v1/models` |
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

1. **Type Safety Without Reflection**:
   Struct types in `internal/openapi/providers/*_types.gen.go` are generated directly from these schemas, eliminating Go reflection overhead on the hot request path.
2. **Schema Drift Detection**:
   Running `go run ./cmd/specgen` validates all specifications, ensuring their paths, parameters, and models remain compliant with upstream releases.
3. **Automated Error Normalization**:
   Upstream HTTP error schemas defined in these specs are mapped deterministically into the standard OpenAI error envelope.

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
go run ./cmd/specgen -dir docs/openapi
```
