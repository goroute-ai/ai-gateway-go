---
trigger: glob
globs: "web/**, internal/ui/**, tests/ui-e2e/**"
description: "Embedded React Operator Web UI standards, strict CSP compliance, bundle budgets, and Playwright UI E2E rules."
---

# Operator Web UI Rules

- **Single-Binary Embedding**: Source code lives in `web/src/` (React 18 + Vite + TypeScript + Tailwind). Compiled output is copied into `internal/ui/dist/` via `make ui-build` and embedded into the Go binary via `go:embed`. Never edit files directly inside `internal/ui/dist/`.
- **Strict Content Security Policy (CSP)**:
  - The `/ui/` console runs under `script-src 'self'` and `style-src 'self'` with **zero `'unsafe-inline'`**.
  - Never add inline `<script>` tags, inline `style="..."` attributes that violate CSP, or external CDN font/script imports.
- **Strict Bundle Size Budgets (`web/scripts/check-budget.mjs`)**:
  - Total dist: `<= 700 KB` uncompressed / `<= 185 KB` gzipped.
  - CSS: `<= 35 KB` uncompressed / `<= 8 KB` gzipped.
  - Single JS chunk: `<= 150 KB` uncompressed / `<= 45 KB` gzipped.
  - Keep route views split with `React.lazy` + `Suspense` and avoid adding heavy npm runtime dependencies.
- **In-Memory Key Safety & OIDC Login**:
  - Keep admin/virtual keys strictly in React memory (`AuthContext`), clear TanStack Query caches on lock/logout, and keep `LoginView` OIDC-only + break-glass master key unlock (no password forms).
  - Echo `X-CSRF-Token` on all cookie-authenticated mutations.
- **Playwright Isolation**: Keep Playwright dependencies and specs strictly inside `tests/ui-e2e/`, never inside `web/package.json`.
- **Mandatory UI Verification Sequence**:
  1. `cd web && npm run typecheck`
  2. `make ui-build` (builds, enforces `check-budget.mjs`, and syncs `internal/ui/dist/`)
  3. `make ui-check-dist`
  4. `go test -race -count=1 ./internal/ui/...`
