---
paths:
  - "web/src/**/*"
  - "web/package.json"
  - "web/package-lock.json"
  - "web/vite.config.ts"
  - "web/index.html"
  - "web/scripts/check-budget.mjs"
  - "internal/ui/**/*.go"
---
# Frontend and Embedded Operator UI Guidelines

## Source and embedded output

- The React 19, TypeScript, and Vite application lives in `web/`; embedded assets are generated into `internal/ui/dist/` and served by `internal/ui/`.
- Edit frontend source under `web/`. Do not hand-edit generated `internal/ui/dist/` assets.
- After frontend changes, run `make ui-build` to build, check the bundle budget, and synchronize embedded assets. This target writes files under `internal/ui/dist/`.
- Run `make ui-check-dist` and `go test ./internal/ui/...` to verify asset parity and serving behavior.

## UI constraints

- Keep the uncompressed production bundle under the limit enforced by `web/scripts/check-budget.mjs`.
- Import only required icons and avoid adding large dependencies without a clear need.
- Use the existing Fetch API and SSE reader patterns in `web/src/api/`; keep auth, tenant scope, and error handling aligned with the backend.
- The production UI is mounted at `/ui/`; the Go embed handler provides the SPA fallback.

## Local development

- Install dependencies with `make ui-install`.
- Start the Vite server with `make ui-dev`; it proxies API traffic to the local gateway on port 8080.
