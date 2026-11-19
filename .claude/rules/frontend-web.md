---
paths:
  - "web/src/**/*"
  - "web/package.json"
  - "web/package-lock.json"
  - "web/vite.config.ts"
  - "web/index.html"
  - "web/scripts/check-budget.mjs"
  - "internal/ui/**/*.go"
  - "tests/ui-e2e/**/*"
---
# Frontend and Embedded Operator UI Guidelines

## Source and embedded output

- The React 18, TypeScript, and Vite application lives in `web/`; embedded assets are generated into `internal/ui/dist/` and served by `internal/ui/`.
- Edit frontend source under `web/`. Do not hand-edit generated `internal/ui/dist/` assets.
- After frontend changes, run `cd web && npm run typecheck` and `make ui-build` to build, enforce the `<= 500 KB` uncompressed / `<= 150 KB` gzip bundle budget, and synchronize embedded assets into `internal/ui/dist/`.
- Run `diff -rq web/dist internal/ui/dist`, `make ui-check-dist` (clean when committed), and `go test ./internal/ui/...` to verify asset parity and serving behavior.

## Auth, Views & UI Constraints

- Keep total bundle sizes within the limits enforced by `web/scripts/check-budget.mjs` (`<= 500 KB` uncompressed, `<= 150 KB` gzipped, `<= 150 KB` per JS chunk).
- Reference static assets with absolute `/ui/` paths (`/ui/favicon.png`, `/ui/logo-dark.png`) so nested SPA routes load assets reliably.
- Import only required icons and avoid adding large dependencies without a clear need.
- Preserve Operator Console authentication flows (`LoginView`: Master Admin Key bearer token, `/auth/login` password login, and `/auth/sso/{provider}/login` OIDC PKCE) using `HttpOnly` signed `goroute_session` cookies and sending `X-CSRF-Token` on cookie-authenticated mutations.
- Keep `KeysView` key-type presets, deprecation grace indicators (`X-Gateway-Key-Deprecated`, `X-Gateway-Key-Revoke-At`), `TempBudgetModal`, `FinOpsView` (`QuotasTab` for per-model, `end_user`, `tag`, `model_access_group`, and `rolling_24h` windows), and `ConfigView` aligned with backend Admin/Auth contracts.
- Use the existing Fetch API and SSE reader patterns in `web/src/api/` (`enc`/`qs` URL encoding, tri-state `null` vs `[]` allowlist semantics, explicit `event: error` SSE parsing, and EOF decoder flushing); keep auth, tenant scope, and error handling aligned with the backend.
- The production UI is mounted at `/ui/`; the Go embed handler provides the SPA fallback.

## Local Development & Browser E2E

- Install dependencies with `make ui-install`.
- Start the Vite server with `make ui-dev`; it proxies API traffic to the local gateway on port 8080.
- Run headless Chromium browser tests from isolated `tests/ui-e2e/` (`make test-ui-e2e`, which starts PostgreSQL + Redis and exercises SSO, HIBP screening, `KeysView`, and `QuotasTab` end to end); keep Playwright dependencies out of `web/` so the frontend bundle budget stays clean.
