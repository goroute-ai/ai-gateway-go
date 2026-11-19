# GoRoute AI Gateway — Upgrade & Rollback Guide

This guide covers safe zero-downtime upgrades and rollback precautions when upgrading GoRoute AI Gateway to **`v1.21.2`**.

> [!IMPORTANT]
> Always back up your PostgreSQL database before running schema migrations, and upgrade gateway replicas in lockstep with schema migrations.

---

## Upgrading from v1.21.0 / v1.21.1

`v1.21.2` is a drop-in distribution and release-automation upgrade over `v1.21.1` using the existing database schema through migration `0034` (no schema changes between `v1.21.1` and `v1.21.2`). When upgrading from `v1.21.0` or earlier, review the `v1.21.1` precautions below: before restarting replicas that use AWS RDS IAM, check that the PostgreSQL DSN verifies the server certificate; after upgrading, image, speech, rerank, and individual batch requests enforce applicable descriptor limits before provider dispatch. See the [API reference](./API_REFERENCE.md#budgeted-caller-modality-coverage) for endpoint behavior.

## 1. Summary of Breaking & Behavior Changes (`v1.21.0`)

1. **Ambient Cloud IAM Is Disabled by Default (`auth.allow_ambient_cloud_iam: false`)**:
   - AWS Bedrock (IMDSv2/ECS/IRSA), GCP Vertex AI ADC, Azure Managed Identity, and AWS RDS IAM no longer consume ambient host/pod metadata credentials automatically unless `auth.allow_ambient_cloud_iam: true` is explicitly configured (or explicit static credentials are supplied).
2. **Issuer-Bound OIDC Identities (`(org_id, oidc_issuer, oidc_subject)`)**:
   - Data Plane JWT and Control Plane OIDC bindings now isolate subjects per issuer via `users.oidc_issuer` and unique index `idx_users_org_issuer_subject`.
   - Legacy rows with empty `oidc_issuer` resolve only when exactly one trusted issuer can be determined unambiguously for the tenant; multi-issuer deployments require explicit administrator issuer binding.
3. **Conflicting Inbound Credentials Fail Closed (`400`)**:
   - Presenting different credentials simultaneously across supported sources (e.g., mismatched `Authorization` bearer token and `X-API-Key` / configured `auth.custom_api_key_header`) is rejected with `400 ambiguous_gateway_credentials`.
4. **Scheduled Key Auto-Rotation Requires HTTPS Delivery + Bearer Token**:
   - Keys with `rotation_interval_sec > 0` remain untouched unless `auth.key_rotation_delivery_url` (strictly `https://`, without embedded userinfo, query strings, or fragments) and `auth.key_rotation_delivery_token` are configured. Replacement secrets are encrypted at rest during staged retries and promoted only after a `2xx` ACK.
5. **Server-Side Password Breach Screening (`auth.enable_hibp_check`)**:
   - Passwords are submitted over TLS to `POST /auth/login` and `POST /auth/password`; client-side SHA-1 hashing (`password_sha1`) is removed. When `enable_hibp_check: true`, GoRoute hashes server-side, queries HIBP k-anonymity range APIs with strictly the **5-character uppercase SHA-1 prefix**, and fails open on upstream HIBP availability errors according to existing availability settings.
6. **AWS RDS IAM Requires TLS Verification (`sslmode=verify-full` / `verify-ca`)**:
   - When `storage.rds_iam.enabled: true`, every PostgreSQL connection candidate must verify the server certificate. Use `sslmode=verify-full` or `verify-ca`. The gateway rejects unverified TLS or plaintext fallback before dialing.

---

## 2. Database Migrations (`0022`–`0034`)

Run migrations with the `-migrate-only` flag before rolling gateway pods:

```bash
ai-gateway -config /etc/goroute/config.yaml -migrate-only
```

| Migration | Schema & Behavioral Summary |
| :--- | :--- |
| `0022_realtime_and_batch_quotas` | Adds `estimated_tokens`, `reserved_cost_micros` on `batches`; `batch_enqueued_token_limit` on `organizations`, `teams`, `users`, `virtual_keys`. |
| `0023_soft_budgets_and_fallbacks` | Adds `soft_budget_micros`, `throttle_on_budget_exceeded`, and `budget_fallbacks` JSONB across orgs, teams, users, and virtual keys. |
| `0024_jwt_key_mappings_and_oidc_index` | Creates `jwt_key_mappings` and `idx_users_org_oidc_subject`. |
| `0025_key_rotation_grace` | Creates `virtual_key_deprecated_hashes` and adds `rotation_interval_sec`, `key_rotation_at`, `key_type` on `virtual_keys`. |
| `0026_access_group_rules` | Creates `access_group_rules` for attribute-based dynamic access policies. |
| `0027_team_memberships_and_projects` | Creates `team_memberships` and `projects` tables and adds `project_id` / membership budget scoping to `virtual_keys`. |
| `0028_scim_and_impersonation` | Adds `scim_external_id`, `scim_active` on `users` (`idx_users_org_scim_external_id`) and `can_impersonate` on `virtual_keys`. |
| `0029_quota_policies` | Creates `quota_policies` for per-model and multi-scope `rpm`/`tpm`/`itpm`/`otpm`/`tpd`/concurrency/session/budget limits. |
| `0030_multi_window_budgets` | Creates `budget_window_limits` (`daily`, `weekly`, `monthly`, `rolling_24h`) plus `temp_budget_increase_micros`, `temp_budget_expires_at`, and `self_serve_budget_policy`. |
| `0031_end_users_tags_and_access_groups` | Creates `end_users`, `tags`, `model_access_groups`, and `model_access_group_members`, plus contextual attribution/limits columns. |
| `0032_ptu_team_shares` | Creates `deployment_ptu_shares` and `priority_classes` for PTU reservation/borrowing and priority-weighted capacity control. |
| `0033_operator_sessions_and_passwords` | Creates `user_credentials` (`scrypt` hash, lockout tracking) and `operator_sessions` (`csrf_token`, expiration, revocation). |
| `0034_auth_quota_reconciliation` | Adds `users.oidc_issuer` (`idx_users_org_issuer_subject`), `virtual_keys` staged rotation columns, `spend_logs` attribution columns (`project_id`, `model_access_group_ids`, `matched_quota_policy_ids`), and `budget_window_limits.rolling_hold_micros` / `rolling_hold_expires_at` with 24h backfill. |

---

## 3. Rolling 24-Hour Budget Upgrade & Cold Recovery Boundary

During upgrade (`0034`), existing `rolling_24h` rows in `budget_window_limits` are handled safely without losing pre-existing spend enforcement:
- For scopes with attributable 24-hour history in `spend_logs` (`org`, `team`, `user`, `key`, `team_member`, `end_user`, `tag`), `spent_micros` is reconciled to trailing 24-hour spend.
- For scopes without attributable history (such as historical pre-`0034` project or model-access-group counters), any nonzero `spent_micros` is preserved in `rolling_hold_micros` with a 24-hour `rolling_hold_expires_at` deadline.

**Operational Recovery Boundary**:
- PostgreSQL `spend_logs` is the source of truth for **persisted settled spend** within the trailing 24 hours.
- If Redis loses all keys or loses only the `rolling_24h` sorted set (`gw:dq:{org:<orgID>}:r24h:<entity>`), admission detects the missing `__init__:0` sentinel and atomically reloads trailing 24h spend from PostgreSQL inside the `{org:<orgID>}` hash slot.
- **Limitation**: Unsettled in-flight reservations or settlements that existed *only* in Redis prior to flush/crash cannot be reconstructed from PostgreSQL `spend_logs`. Older Redis entries keyed by request ID can temporarily count alongside persisted spend if recovery runs while older replicas are still settling requests. Those entries age out of the 24-hour window.

---

## 4. Migration `0034` Rollback Preflight & Conflict Resolution

`migrations/0034_auth_quota_reconciliation.down.sql` executes inside a single transaction and acquires `LOCK TABLE users IN SHARE ROW EXCLUSIVE MODE` before altering indexes.

Because `v1.21.0` allows two different issuers (`oidc_issuer`) within the same `org_id` to hold the same `oidc_subject`, rolling back `0034` back to the pre-`0034` unique index `(org_id, oidc_subject)` **fails safely** if duplicate nonempty `(org_id, oidc_subject)` rows exist:

```text
cannot rollback migration 0034: duplicate nonempty (org_id, oidc_subject) bindings exist ...
resolve conflicting bindings explicitly before retrying rollback
```

### Resolving Duplicate Subjects Before Rollback

1. Inspect conflicting `(org_id, oidc_subject)` rows:
   ```sql
   SELECT id, org_id, email, oidc_issuer, oidc_subject
   FROM users
   WHERE (org_id, oidc_subject) IN (
       SELECT org_id, oidc_subject
       FROM users
       WHERE oidc_subject IS NOT NULL AND oidc_subject <> ''
       GROUP BY org_id, oidc_subject
       HAVING COUNT(*) > 1
   )
   ORDER BY org_id, oidc_subject, id;
   ```
2. Explicitly update or clear/deactivate the redundant binding(s) (never delete active audit-referenced users blindly), verify `COUNT(*) = 0` duplicates remain, and then re-run down migration `0034`.

---

## 5. Post-Upgrade Verification Checklist

1. Confirm `/readyz` returns `HTTP 200` on all gateway replicas.
2. Confirm Control Plane `/ui/` loads with strict CSP (`script-src 'self'`) and expected OIDC SSO providers under `/auth/sso/providers`.
3. If using AWS Bedrock, GCP Vertex AI, Azure Managed Identity, or AWS RDS IAM via host/pod credentials, verify `auth.allow_ambient_cloud_iam: true` is set in your config.
4. Run `make test-postgres` and `make test-e2e-strict` (or `make test-prod-containers`) against staging before production rollout; see the [Testing Guide](./TESTING.md).
