# GoRoute Provider Integration Touchpoints Checklist

Use this reference alongside `SKILL.md` to ensure no subsystem is missed when adding a new first-class provider `<provider>` (e.g., `ollama`, `gemini`, `mistral`).

## 1. Contracts & Codegen

| File | Required Change |
| :--- | :--- |
| `docs/openapi/<provider>.openapi.yaml` | Authoritative OpenAPI 3.0/3.1 contract; prefix all schema names with PascalCase provider name to avoid collisions in `package providers`. |
| `docs/openapi/<provider>.codegen.yaml` | `oapi-codegen` v2.8.0 config writing `models: true` to `providers/<provider>_types.gen.go`. |
| `internal/openapi/generate.go` | Add `//go:generate` directive for `<provider>` before `cmd/specgen`. |
| `cmd/specgen/main.go` | Add `<provider>.openapi.yaml` to the `specs` validation slice. |
| `docs/openapi/gateway.openapi.yaml` | Update provider identifier descriptions (and add provider alias paths if introducing a native pass-through route). |
| `internal/openapi/providers/<provider>_types.gen.go` | Generated via `make specgen` — never hand-edit. |

## 2. Core Domain, Config & Adapter

| File | Required Change |
| :--- | :--- |
| `internal/domain/inference.go` | Add `Provider<Name> ProviderType = "<provider>"` and include it in `AllProviders()`. |
| `internal/config/config.go` | Add cases in `NormalizeProvider(raw)` and (if unambiguous) bare-model heuristics in `ParseProviderModel(modelSpec)`. |
| `internal/adapter/<provider>/doc.go` | Package doc comment (`// Package <provider> implements the OpenAPI-spec-first ProviderAdapter...`). |
| `internal/adapter/<provider>/adapter.go` | Implement `ProviderAdapter`, `SetSSRFPolicy`, `OperationSupportChecker`, `PrefillSupportChecker`, and any modality interfaces (`AudioAdapter`, `ImageAdapter`, `CompletionAdapter`, `ModerationAdapter`). |
| `internal/adapter/<provider>/adapter_test.go` | Unit tests with `httptest.NewServer` + loopback `network.Policy` covering sync, SSE stream, tools, models, auth/error classification, `traceparent`, and SSRF rejection. |
| `internal/adapter/adapter_test.go` | Add `<provider>` to the multi-adapter integration matrix test. |
| `internal/adapter/prefill_test.go` | Add `<provider>` to `TestSupportsAssistantPrefill_Matrix` and trailing-assistant serialization tests. |

## 3. Server, Router, FinOps, Storage & SDK

| File | Required Change |
| :--- | :--- |
| `internal/server/server.go` | Construct `<provider>.NewAdapter(adapterClient)`, call `SetSSRFPolicy(netPolicy)`, and `reg.Register(...)` in `buildAdapterRegistry`. |
| `internal/server/bootstrap.go` | Add `<PROVIDER>_API_KEY` env var in `resolveProviderEnvKey`; optionally add zero-config default alias or env base URL handling in `bootstrap` / `discoverEnvModelEntries`. |
| `internal/server/handlers_admin.go` | If the provider allows keyless/local auth (like `ollama`), update `handleAdminPreflightValidateCredential` accordingly. |
| `internal/router/sanitization.go` | **Critical for non-OpenAI wire providers**: update `isOpenAIWireProvider(p)` if `<provider>` rejects OpenAI-only extra params (`logprobs`, `logit_bias`, `service_tier`, etc.). |
| `internal/ratelimit/tokenizer.go` | Update `ResolveTokenizerProfile` if `<provider>` / its model family uses a non-`o200k_base` tokenization heuristic. |
| `internal/modelmgmt/repository.go` | Add fallback pricing/context heuristics in the provider `switch` (exact integer micro-dollars only). |
| `internal/storage/memory.go` | Add baseline seed `domain.GlobalModel` entries (with `PricingStatusVerified`, micro-dollar costs, and explicit tri-state `Capabilities`). |
| `migrations/NNNN_seed_<provider>_models.{up,down}.sql` | Optional: add paired idempotent migration (`ON CONFLICT DO NOTHING`) if seeding PostgreSQL `global_models`. **Never** edit existing migrations (e.g., `0037`). |
| `internal/modelcatalog/catalog.json.gz` | Regenerate via `make catalog-sync` when an upstream catalog JSON includes `<provider>` models. |
| `internal/modelcatalog/catalog_test.go` | Move `domain.Provider<Name>` into `callableProviders` (and remove from `uncallableProviders` if previously listed). |
| `pkg/gateway/sdk.go` | Optional: add demo mock server + `switch prov` case in `demoMocksFallback` block. |
| `configs/config.example.yaml` | Add documented example deployment using `<provider>/<model>` notation. |

## 4. Operator Web UI (When Exposing in Control Plane UI)

| File | Required Change |
| :--- | :--- |
| `web/src/types/index.ts` | Add `'<provider>'` to `ProviderType` union. |
| `web/src/views/CredentialsView.tsx` | Add `{ id: '<provider>', label: '<Display Name>' }` to `providersList` (and adjust optional API key handling if keyless). |
| `web/src/views/ModelsView.tsx` | Add `<option value="<provider>"><Display Name></option>` to the provider filter `<select>`. |
| `web/src/components/common/Badge.tsx` | Add color style mapping for `<provider>` badges. |
| `internal/ui/dist/*` | Rebuild & sync via `make ui-build && make ui-check-dist` (must stay within bundle budget). |

## 5. Documentation & Observability Suites

| File | Required Change |
| :--- | :--- |
| `docs/openapi/README.md` | Add row to Specification Directory & Source Index. |
| `docs/API_REFERENCE.md` | Add provider capability row and `X-Gateway-Provider` value. |
| `docs/CODEBASE_MAP.md` | Add `<provider>/` to the adapter table. |
| `docs/CONFIGURATION_GUIDE.md` | Add example configuration and model notation. |
| `tests/obs-prod-docker/fixtures/main.go` | Optional: add deterministic mock upstream handler for full OTLP `traceparent` verification. |
