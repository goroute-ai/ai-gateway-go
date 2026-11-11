# Frontend Web & Operator UI Guidelines

## Overview
The Operator Web UI is an embedded Single Page Application (SPA) located under `web/`. It compiles into static HTML, JS, and CSS, which are embedded directly into the Go binary via `go:embed all:dist` in `internal/ui/ui.go`.

## Key Technologies
- **Framework**: React 19 + TypeScript + Vite.
- **Styling**: Tailwind CSS v3 (dark mode enabled via slate/zinc palette).
- **Icons**: `lucide-react` (import only required icons to preserve bundle budget).
- **HTTP & SSE**: Fetch API + custom streaming reader in `web/src/api/sse.ts`.

## Bundle Budget Invariant
The gateway enforces a strict bundle size limit to preserve embedded binary footprint:
- Total production bundle must remain under 400 KB uncompressed.
- Every production build must pass:
  ```bash
  cd web && npm run build && node scripts/check-budget.mjs
  ```
- Avoid adding heavy third-party charting or utility libraries (e.g. avoid Moment.js, heavy lodash, large component frameworks).

## Asset Synchronization Workflow
When modifying frontend code:
1. Make changes in `web/src/`.
2. Run `make ui-build` from repository root (or `cd web && npm run build && node scripts/check-budget.mjs && rm -rf ../internal/ui/dist/* && cp -R dist/* ../internal/ui/dist/`).
3. Verify synchronization with `make ui-check-dist`.
4. Run `go test ./internal/ui/...` to confirm the embedded filesystem and HTTP handlers serve the new assets cleanly.

## SPA Routing & Local Dev
- Local development runs Vite dev server with reverse proxy to Go backend: `make ui-dev` (port 5173 proxies `/v1` and `/admin/v1` to `localhost:8080`).
- Production route is `/ui/`. The Go server in `internal/ui/ui.go` serves files from embedded `dist/` and falls back to `index.html` for client-side routing.
