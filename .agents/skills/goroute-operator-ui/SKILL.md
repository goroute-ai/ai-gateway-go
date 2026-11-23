---
name: goroute-operator-ui
description: >-
  Develop, build, budget-check, embed, and E2E-test GoRoute's React Operator Web UI (web/ -> internal/ui/dist/).
  Use when modifying frontend views, components, Tailwind styles, API clients in web/src/, or Playwright tests in tests/ui-e2e/.
  Do not use for pure Go backend tasks.
---

# GoRoute Embedded Operator Web UI Workflow

## Step 1: Develop in `web/src/`

- Edit components and views under `web/src/` (never edit generated files in `internal/ui/dist/`).
- Keep views lazy-loaded (`React.lazy` + `Suspense`) to respect chunk size budgets.
- Respect strict CSP (`script-src 'self'`, `style-src 'self'`, **no `'unsafe-inline'`** and no external CDN assets).
- Keep admin/virtual keys in React memory (`AuthContext`) only and echo `X-CSRF-Token` on cookie-authenticated mutations.
- For live local development against a gateway on `:8080`, run `make ui-dev`.

## Step 2: Typecheck, Build, Enforce Budgets & Sync Embedded Dist

```bash
(cd web && npm run typecheck)
make ui-build
make ui-check-dist
```

Confirm `web/scripts/check-budget.mjs` passes all thresholds:
- Total dist: `<= 700 KB` uncompressed / `<= 185 KB` gzipped
- CSS: `<= 35 KB` uncompressed / `<= 8 KB` gzipped
- Single JS chunk: `<= 150 KB` uncompressed / `<= 45 KB` gzipped

## Step 3: Verify Go Embedding & Playwright UI E2E

Always run the Go embedding test:

```bash
go test -race -count=1 ./internal/ui/...
```

When PostgreSQL, Redis, Node.js, and Playwright Chromium are available, run the full headless browser E2E suite (which also validates zero CSP violations and zero console/page errors):

```bash
make test-live-up
make test-ui-e2e
make test-live-down
```
