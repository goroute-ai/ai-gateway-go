// Package storage implements the gateway persistence boundary and its memory,
// PostgreSQL, and Redis-backed components. Keep repository interface changes
// aligned with every implementation and with ordered migrations under
// migrations/. Persistence ownership and related tests are mapped in
// docs/CODEBASE_MAP.md.
package storage
