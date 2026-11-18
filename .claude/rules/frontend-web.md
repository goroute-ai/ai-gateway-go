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

- The React 18, TypeScript, and Vite application lives in `web/`; embedded assets are generated into `internal/ui/dist/` and served by `internal/ui/`.
- Edit frontend source under `web/`. Do not hand-edit generated `internal/ui/dist/` assets.
- After frontend changes, run `cd web && npm run typecheck` and `make ui-build` to build, enforce the `<= 500 KB` uncompressed / `<= 150 KB` gzip bundle budget, and synchronize embedded assets into `internal/ui/dist/`.
- Run `diff -rq web/dist internal/ui/dist`, `make ui-check-dist` (clean when committed), and `go test ./internal/ui/...` to verify asset parity and serving behavior.

## UI constraints

- Keep total bundle sizes within the limits enforced by `web/scripts/check-budget.mjs` (`<= 500 KB` uncompressed, `<= 150 KB` gzipped, `<= 150 KB` per JS chunk).
- Reference static assets with absolute `/ui/` paths (`/ui/favicon.png`, `/ui/logo-dark.png`) so nested SPA routes load assets reliably.
- Import only required icons and avoid adding large dependencies without a clear need.
- Use the existing Fetch API and SSE reader patterns in `web/src/api/` (`enc`/`qs` URL encoding, tri-state `null` vs `[]` allowlist semantics, explicit `event: error` SSE parsing, and EOF decoder flushing); keep auth, tenant scope, and error handling aligned with the backend.
- The production UI is mounted at `/ui/`; the Go embed handler provides the SPA fallback.

## Local development

- Install dependencies with `make ui-install`.
- Start the Vite server with `make ui-dev`; it proxies API traffic to the local gateway on port 8080.
