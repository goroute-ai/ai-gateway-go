---
trigger: glob
globs: "docs/openapi/**, docs/specs/**, migrations/**, internal/storage/**, internal/ratelimit/**"
description: "OpenAPI 3.1 contract parity, 5-release MCP YAML codegen, SQL migration safety, and Redis Cluster slot rules."
---

# Contracts, Migrations & Storage Rules

- **OpenAPI & Protocol Contract Parity**:
  - Treat `docs/openapi/gateway.openapi.yaml` (`127` paths: `27` `/v1`, `88` `/admin/v1`, `8` `/auth`, `4` provider aliases), provider specs (`docs/openapi/*.openapi.yaml`), and `docs/specs/mcp/*/schema.yaml` (`2024-11-05`..`2026-07-28`) as authoritative contracts.
  - Always run `make specgen` after contract or route changes and verify `git diff --exit-code -- internal/openapi/ internal/mcp/spec/` once regenerated artifacts are committed.
  - Keep `/v1` routes inline inside `r.Route("/v1", ...)` in `internal/server/server.go` so `cmd/specgen/routes.go` AST parity checks continue to resolve them.
- **PostgreSQL Migrations (`migrations/0001`–`0042+`)**:
  - Every new schema change requires paired forward (`NNNN_name.up.sql`) and rollback (`NNNN_name.down.sql`) files using idempotent DDL (`IF NOT EXISTS` / `IF EXISTS`) where safe.
  - Never modify or renumber existing applied migrations (`0001`–`0042`).
  - Preserve migration `0034` transaction-locked duplicate `(org_id, oidc_subject)` rollback preflight safety.
  - Keep `internal/storage/memory_*.go` and `internal/storage/postgres_*.go` behavior aligned across every `Repository` method change, using parameterized queries exclusively.
- **Redis Cluster Hash Slots & Rolling Budgets**:
  - Preserve `{org:<orgID>}` hash tags on all Redis keys accessed together inside multi-key Lua scripts (`internal/ratelimit/scripts/*.lua`).
  - Preserve durable spend delivery (`spend_event_outbox`), idempotent reconciliation, upper-bound budget reservations, lease renewal, and `rolling_24h` `__init__:0` single-ZSET cold recovery from PostgreSQL (`503 quota_policy_unavailable` on history load failure).
- **AWS RDS IAM**: Require certificate-verifying TLS (`sslmode=verify-full` or `verify-ca`) whenever `storage.rds_iam.enabled` is true.
