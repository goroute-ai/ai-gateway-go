# Go Backend Guidelines for GoRoute AI Gateway

## Architecture & Code Structure
- **Package Hierarchy**: Keep package dependencies directed strictly inward:
  - `cmd/`: Application entrypoints (`cmd/gateway`, `cmd/specgen`, `cmd/catalog-sync`).
  - `pkg/`: Public, stable, embeddable SDKs (`pkg/gateway`).
  - `internal/`: Private implementation packages (`internal/server`, `internal/router`, `internal/adapter`, etc.).
  - `internal/domain`: Foundational domain types, interfaces, request/response models, and error codes.
- **Routing with Chi (`go-chi/chi/v5`)**:
  - Route groups are configured in `internal/server/server.go`.
  - Handlers follow the `http.HandlerFunc` signature: `func (s *GatewayServer) handleX(w http.ResponseWriter, r *http.Request)`.
  - Read path parameters using `chi.URLParam(r, "paramName")`.
  - Read query parameters using `r.URL.Query().Get("key")`.
  - Return JSON via `writeJSON(w, statusCode, data)` helper.
  - Return domain errors via `domain.WriteHTTPError(w, err)`.

## Network & SSRF Security
- Never instantiate an unconfigured `http.Client{}` for outbound provider or webhook calls.
- Always use the centralized network security engine:
  - `internal/security/network.NewSafeTransport(...)`
  - Enforce IP pinning, private subnet blocking (RFC 1918, RFC 3927, RFC 4193, loopback, link-local), and DNS rebinding protections.

## FinOps & Currency Precision
- All monetary values are integer micro-dollars ($1\text{ USD} = 1,000,000\ \mu\$$).
- Zero floating-point drift: Never use `float64` or `float32` for pricing or balance calculations.
- Accumulate intermediate amounts with 64-bit integer arithmetic in `internal/finops`.

## Error Handling & Logging
- Wrap errors with domain-level context using `fmt.Errorf("failed to do X: %w", err)`.
- Use structured logging via `slog` (`internal/logger`):
  - Pass the request context: `logger.InfoContext(r.Context(), "message", slog.String("key", val))`.
  - Avoid logging raw API keys, bearer tokens, or user sensitive payloads (PII).

## Testing Conventions
- Use table-driven tests with standard `testing.T`.
- Ensure tests execute cleanly under the race detector: `go test -race -count=1 ./internal/...`.
- For mock upstream testing, use the mock adapter or `httptest.Server`.
