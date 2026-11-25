---
name: goroute-add-provider
description: >-
  Add a new first-class upstream LLM provider to GoRoute AI Gateway following its OpenAPI-first adapter architecture.
  Use when integrating a new model vendor (OpenAI-compatible or custom wire protocol), generating provider DTOs, registering provider enums/adapters, or wiring a provider across router, catalog, SDK, and Operator Web UI.
  Do not use for modifying existing /v1 or /admin/v1 gateway routes only (use goroute-openapi-contract instead).
---

# Adding a New Provider to GoRoute AI Gateway

Every first-class provider in GoRoute follows the **OpenAPI-first adapter architecture**: pinned provider spec → generated wire DTOs in `internal/openapi/providers/` → SSRF-safe `adapter.ProviderAdapter` in `internal/adapter/<provider>/` → registry, config, router, catalog, and UI wiring.

Consult [references/provider-touchpoints.md](./references/provider-touchpoints.md) for the complete file-by-file checklist and edge cases (including non-OpenAI wire providers).

## Step 1: Author the Provider OpenAPI Contract & Generate Wire DTOs

1. Create `docs/openapi/<provider>.openapi.yaml` (OpenAPI 3.0.x or 3.1.x) covering the provider's supported endpoints (chat completions/messages, streaming chunk schema, models list, and optional embeddings/audio/images).
   - **Schema Prefix Convention**: Prefix every `components.schemas` name with the PascalCase provider name (e.g., `OllamaChatCompletionRequest`, `MistralMessage`) because all provider specs generate into the shared Go package `providers` (`internal/openapi/providers/`). Unprefixed names will collide and break compilation.
2. Create `docs/openapi/<provider>.codegen.yaml` pinned to `oapi-codegen` v2.8.0:
   ```yaml
   # yaml-language-server: $schema=https://raw.githubusercontent.com/oapi-codegen/oapi-codegen/v2.8.0/configuration-schema.json
   package: providers
   generate:
     models: true
   output: providers/<provider>_types.gen.go
   ```
3. Add a `//go:generate` line in `internal/openapi/generate.go` **before** `cmd/specgen`:
   ```go
   //go:generate go run github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@v2.8.0 -config ../../docs/openapi/<provider>.codegen.yaml ../../docs/openapi/<provider>.openapi.yaml
   ```
4. Register the new spec in `cmd/specgen/main.go` (`specs` slice) so CI validates it semantically.
5. Update provider identifier descriptions in `docs/openapi/gateway.openapi.yaml` (and add any provider-native alias paths if applicable).
6. Run `make specgen` to generate `internal/openapi/providers/<provider>_types.gen.go` and validate contracts. Never hand-edit `*.gen.go`.

## Step 2: Register Domain Enum & Config Normalization

1. `internal/domain/inference.go`: Add `Provider<Name> ProviderType = "<provider>"` and append it to `AllProviders()`.
   - Adding it to `AllProviders()` automatically enables `config.IsKnownProviderAlias`, `internal/modelcatalog` filtering, and `cmd/catalog-sync` ingestion.
2. `internal/config/config.go`:
   - Map canonical name and vendor aliases in `NormalizeProvider(raw string)`.
   - Optionally add bare-model prefix heuristics in `ParseProviderModel(modelSpec string)` only if model prefixes uniquely identify the vendor.

## Step 3: Implement the Provider Adapter (`internal/adapter/<provider>/`)

Use `internal/adapter/openrouter/adapter.go` (minimal OpenAI-compatible), `internal/adapter/groq/adapter.go` (multi-modality OpenAI-compatible with parameter shaping), `internal/adapter/ollama/adapter.go` (optional-auth local/cloud OpenAI-compatible + native `/api/tags`), or `internal/adapter/anthropic/adapter.go` (custom wire format + custom SSE state machine) as reference templates.

1. Create `internal/adapter/<provider>/doc.go` (package godoc) and `internal/adapter/<provider>/adapter.go`.
2. Struct & Constructor:
   - Store `client *http.Client` and `ssrfPolicy *network.Policy`.
   - In `NewAdapter(client *http.Client) *Adapter`, default nil `client` to `adapter.NewPooledHTTPClient(120 * time.Second)`. Never use `http.DefaultClient`.
   - Expose `SetSSRFPolicy(policy *network.Policy)`.
3. Implement `adapter.ProviderAdapter`:
   - `Provider() domain.ProviderType`
   - `ChatCompletion(ctx, dep, req)` — translate canonical request to generated `providers.<Prefix>*` DTOs; map response choices, tool calls, `ReasoningContent`, and `TokenUsage` (`CachedPromptTokens`, `ReasoningTokens`).
   - `StreamChatCompletion(ctx, dep, req, onChunk)` — call `ctx = adapter.StreamingContext(ctx)` before building the request so the network client uses idle timeouts instead of a total deadline; parse SSE with `internal/adapter/sse` (`sse.ReadEvents`).
   - `Embeddings(ctx, dep, req)` — implement or return `*domain.GatewayError{StatusCode: http.StatusBadRequest, Type: domain.ErrorTypeInvalidRequest, Code: "unsupported_capability", Provider: ...}`.
   - `ListModels(ctx, cred)` — fetch upstream models and return `[]domain.DiscoveredModel`.
4. Implement optional capability interfaces in `internal/adapter/adapter.go` as applicable:
   - `OperationSupportChecker` (`SupportsOperation(op domain.OperationType) bool`) — strongly recommended so the router enforces operation support accurately.
   - `PrefillSupportChecker` (`SupportsAssistantPrefill() bool`).
   - `CompletionAdapter`, `StreamingCompletionAdapter`, `AudioAdapter`, `ImageAdapter`, `ModerationAdapter` if supported.
5. Enforce mandatory adapter invariants:
   - **SSRF & Base URL**: Resolve every endpoint via `adapter.ResolveCredentialBaseURL(cred, defaultBaseURL, a.ssrfPolicy, domain.Provider<Name>)` (or `adapter.StandardOpenAIEndpointStrategy`).
   - **Auth**: Apply `adapter.BearerAuthStrategy`, `adapter.HeaderAuthStrategy`, or custom auth while preserving `cred.Headers`; return `StatusUnauthorized` + `AuthFailure: true` when credentials are required and missing.
   - **Tracing**: Call `observability.InjectTraceHeaders(req.Context(), httpReq)` on every outbound request.
   - **Bounded I/O**: Always `defer resp.Body.Close()` and read with `adapter.ReadBoundedBody(resp.Body, adapter.DefaultMaxResponseBytes, ...)` (`DefaultMaxErrorBytes` for error bodies).
   - **Error Classification**: Map non-2xx responses with `domain.ClassifyUpstreamStatus(domain.Provider<Name>, resp.StatusCode, msg, adapter.ParseRetryAfter(resp.Header))`.
   - **ExtraParams Guard**: Never let `req.ExtraParams` overwrite reserved wire fields (`model`, `messages`, `stream`, `stream_options`).
   - **Remote Media**: Validate/fetch media URLs strictly through `adapter.ValidateAndSanitizeMediaURL` / `adapter.FetchRemoteDataURIWithPolicy`.

## Step 4: Wire Across Server, Router, FinOps, Catalog, SDK & UI

Walk through [references/provider-touchpoints.md](./references/provider-touchpoints.md) and update every applicable integration point:
1. **Registry**: Register in `buildAdapterRegistry(...)` in `internal/server/server.go` (`SetSSRFPolicy(netPolicy)` + `reg.Register(adp)`).
2. **Bootstrap**: Add `<PROVIDER>_API_KEY` env lookup in `resolveProviderEnvKey` (and optional default alias in `discoverEnvModelEntries`) in `internal/server/bootstrap.go`.
3. **Router Sanitization**: If the provider does **not** speak OpenAI wire format, update `isOpenAIWireProvider` in `internal/router/sanitization.go` so OpenAI-only extra params are stripped when `drop_unsupported_params` is enabled.
4. **Tokenizer & Pricing Heuristics**: Update `internal/ratelimit/tokenizer.go` (`ResolveTokenizerProfile`) if a distinct tokenization profile applies, and `internal/modelmgmt/repository.go` default pricing fallback (integer micro-dollars only).
5. **Baseline Seeds & Catalog**: Add baseline model entry to `internal/storage/memory.go` (and a new paired migration in `migrations/` if seeding Postgres—never modify existing migrations like `0037`). Re-run `make catalog-sync` if refreshing `internal/modelcatalog/catalog.json.gz`.
6. **SDK & Config Example**: Add demo mock fallback in `pkg/gateway/sdk.go` (if needed) and an example entry in `configs/config.example.yaml`.
7. **Operator Web UI**: Update `web/src/types/index.ts`, `web/src/views/CredentialsView.tsx`, `web/src/views/ModelsView.tsx`, and `web/src/components/common/Badge.tsx`, then run `make ui-build && make ui-check-dist`.

## Step 5: Write Tests & Run Verification Gates

1. Add focused unit tests in `internal/adapter/<provider>/adapter_test.go` covering:
   - Sync chat, SSE streaming (including usage and reasoning deltas), tool calling, and `ListModels`.
   - Upstream error classification (`401`, `429` with `Retry-After`, `500`), bounded response errors, `traceparent` propagation, and SSRF `BaseURL` rejection.
2. Add the new adapter to cross-adapter suites:
   - `internal/adapter/adapter_test.go`
   - `internal/adapter/prefill_test.go`
   - `internal/config/config_test.go` (`NormalizeProvider`, `IsKnownProviderAlias`, `ParseProviderModel`)
3. Run verification gates:
   ```bash
   make specgen
   gofmt -l .
   go vet ./...
   go test -race -count=1 ./cmd/specgen/... ./internal/domain/... ./internal/config/... ./internal/adapter/... ./internal/router/... ./internal/server/... ./internal/modelmgmt/... ./internal/storage/... ./pkg/gateway/...
   ```
   If Operator Web UI files changed, also run:
   ```bash
   make ui-build && make ui-check-dist && go test -race -count=1 ./internal/ui/...
   ```
4. Update documentation (`docs/openapi/README.md`, `docs/API_REFERENCE.md`, `docs/CODEBASE_MAP.md`, `docs/CONFIGURATION_GUIDE.md`).
