---
paths:
  - "cmd/**/*.go"
  - "internal/**/*.go"
  - "pkg/**/*.go"
  - "tests/**/*.go"
  - "go.mod"
  - "go.sum"
---
# Go Backend Guidelines

## Architecture and routing

- Keep dependencies directed inward toward `internal/domain`; put public SDK interfaces under `pkg/gateway` and private implementations under `internal/`.
- Configure Chi routes in `internal/server/server.go`. Keep handlers small, validate inputs, preserve identity and organization scope, and return structured errors with `domain.WriteHTTPError`.
- Inspect the repository and focused tests before changing behavior. Avoid synchronous database work, unbounded locks, and unnecessary allocations on inference hot paths.

## Network, identity, and secrets

- Route provider and tool egress through `internal/security/network`; use `network.NewHTTPClient`, validate custom `BaseURL` inputs through `adapter.ValidateAndResolveBaseURL`, isolate user-supplied remote media fetches behind strict public-HTTPS `DefaultPublicMediaPolicy`, and preserve DNS/IP pinning, private-address checks, and redirect validation.
- Preserve operator RBAC, federated `(org_id, oidc_issuer, oidc_subject)` JWT/OIDC binding (`migrations/0034`, including the transaction-locked duplicate-subject rollback preflight), single-transaction SCIM v2 group updates, virtual-key model authorization, tri-state allowlists (`null` Inherit vs `[]` Deny All across HTTP JSON, storage, and Redis L2 cache), and organization/team/project/user boundaries. Authorization failures must fail closed.
- Keep provider credentials encrypted by the vault and restrict private-network preflight checks to `platform_admin`. Production config must reject default admin, encryption, and JWT secrets when `ENV` or `GATEWAY_ENV` is production.
- MCP stdio is disabled unless its release guard and OS sandbox requirements are satisfied; do not bypass that configuration validation.

## Accounting, storage, and shared state

- Record cost as integer micro-dollars; use the integer pico-dollar intermediate arithmetic in `internal/finops`. Never use floating point for financial calculations.
- Preserve spend outbox delivery and idempotent reconciliation, upper-bound reservations, lease renewal, `rolling_24h` `"__init__:0"` single-ZSET cold recovery from PostgreSQL (`503 quota_policy_unavailable` on history load failure), and budget reset synchronization (`migrations/0001`–`0034`).
- Preserve Redis Cluster hash-tag alignment for keys used by shared Lua scripts and distributed cache, routing, and circuit-breaker state.
- Preserve per-organization file storage quotas and bounded upload concurrency. Defaults are 5 GiB and 8 concurrent uploads; zero means unlimited. Keep multipart spill-file cleanup on every successful parse path.
- Do not log credentials, bearer tokens, or sensitive request payloads; use contextual structured logging.

## Tests and generated files

- Use table-driven tests and `httptest.Server` or repository mocks for upstream behavior. Run focused race tests for changed packages.
- Update API/protocol contracts through `make specgen`; review generated output instead of hand-editing it.
- Run E2E tests only with PostgreSQL and Redis available, and state which checks were run.
