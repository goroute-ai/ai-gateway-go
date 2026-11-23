---
trigger: always_on
---

# GoRoute Core Invariants

These repository-wide invariants apply to every change in `goroute-ai/ai-gateway-go`:

1. **Pure Go (`CGO_ENABLED=0`)**: All Go binaries and packages must compile cleanly without Cgo across Linux, macOS, and Windows.
2. **Exact Integer Micro-Dollar Accounting**: All financial values (prices, spend, budgets, leases) use 64-bit integer micro-dollars (`$1.00 = 1,000,000 µ$`) with integer pico-dollar intermediates in `internal/finops/`. Never use `float64` for financial accounting.
3. **SSRF-Protected Outbound Egress**: Every outbound HTTP/HTTPS call to upstream providers, webhooks, OIDC issuers, or media URLs must use `internal/security/network`. Never bypass network policy checks with raw `http.DefaultClient`.
4. **Fail-Closed Multi-Tenant Security**: Preserve tenant isolation, RBAC boundaries, and tri-state allowlists (`null` = Inherit vs `[]` = Deny All). Security, auth, quota, and guardrail failures must fail closed unless explicitly configured otherwise.
5. **Never Hand-Edit Generated Artifacts**:
   - OpenAPI / provider DTOs (`internal/openapi/gateway.gen.go`, `internal/openapi/providers/*`) and MCP types (`internal/mcp/spec/*`) → regenerate with `make specgen`.
   - A2A protobufs (`internal/a2a/pb/*`) → regenerate via `docs/specs/a2a/v1.0/generate.go`.
   - Embedded Web UI (`internal/ui/dist/*`) → rebuild and sync with `make ui-build`.
6. **Secret & Repo Hygiene**: Never commit real or realistic API keys, tokens, or credentials—even in tests (construct synthetic fixtures dynamically to pass `.gitleaks.toml`).
7. **Honest Verification Reporting**: Always state exact commands executed and explicitly note any integration suites skipped due to unavailable services (PostgreSQL, Redis, Docker, Playwright). Never run `make release-check` blindly on a dirty worktree (it runs `gofmt -w`).
