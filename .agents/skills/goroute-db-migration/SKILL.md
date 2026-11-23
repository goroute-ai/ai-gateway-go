---
name: goroute-db-migration
description: >-
  Author paired PostgreSQL forward/down SQL migrations, maintain memory and Postgres repository parity, and update Redis Cluster Lua quota scripts safely.
  Use when adding tables or columns, altering internal/storage/ repositories, or changing internal/ratelimit/scripts/*.lua.
  Do not use for HTTP-only or frontend-only tasks.
---

# GoRoute Database Migration & Storage Workflow

## Step 1: Determine Next Migration Number

Inspect existing migrations before creating a new one:

```bash
ls -1 migrations/ | tail -n 10
```

Never edit or renumber existing applied migrations (`0001`–`0041`).

## Step 2: Author Paired Forward & Rollback SQL Files

Create both:
- `migrations/<NNNN>_<descriptive_name>.up.sql`
- `migrations/<NNNN>_<descriptive_name>.down.sql`

Rules:
- Use idempotent DDL (`CREATE TABLE IF NOT EXISTS`, `ALTER TABLE ... ADD COLUMN IF NOT EXISTS`, `DROP COLUMN IF EXISTS`) where safe.
- Financial columns **must** use `BIGINT` micro-dollars (`*_micros`), never `DOUBLE PRECISION` or `NUMERIC` floats.
- If a down-migration tightens a unique constraint or could lose data on rollback, add a transaction-locked preflight check (see `migrations/0034_auth_quota_reconciliation.down.sql` for the canonical pattern).

## Step 3: Maintain Storage & Redis Parity

1. Update domain structs in `internal/domain/` and repository interfaces in `internal/storage/repository.go`.
2. Update **both** domain-split implementations:
   - `internal/storage/memory_*.go`
   - `internal/storage/postgres_*.go` (parameterized SQL queries only; batch flushes via `pgx.Batch` with per-statement error checks).
3. If modifying `internal/ratelimit/scripts/*.lua`, keep all multi-key operations scoped inside `{org:<orgID>}` Redis Cluster hash slots.

## Step 4: Verify Migrations & Repositories

Run in-memory tests first:

```bash
go test -race -count=1 ./internal/storage/... ./internal/ratelimit/... ./internal/finops/...
```

When Docker is available, verify the full `0001..NNNN` forward + rollback lifecycle against live PostgreSQL 16 and Redis 7:

```bash
make test-live-up
make test-postgres
make test-live-down
```

Update `docs/UPGRADING.md` and `docs/CODEBASE_MAP.md` with the new migration entry.
