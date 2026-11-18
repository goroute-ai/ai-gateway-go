ALTER TABLE budget_window_limits
    DROP COLUMN IF EXISTS rolling_hold_expires_at,
    DROP COLUMN IF EXISTS rolling_hold_micros;

DROP INDEX IF EXISTS idx_spend_logs_org_team_user_created;
DROP INDEX IF EXISTS idx_spend_logs_project_created;
ALTER TABLE spend_logs
    DROP COLUMN IF EXISTS matched_quota_policy_ids,
    DROP COLUMN IF EXISTS model_access_group_ids,
    DROP COLUMN IF EXISTS project_id;

ALTER TABLE virtual_keys
    DROP COLUMN IF EXISTS staged_created_at,
    DROP COLUMN IF EXISTS staged_key_dek,
    DROP COLUMN IF EXISTS staged_encrypted_raw_key,
    DROP COLUMN IF EXISTS staged_key_prefix,
    DROP COLUMN IF EXISTS staged_key_hash;

DROP INDEX IF EXISTS idx_users_org_issuer_subject;
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_org_oidc_subject
    ON users (org_id, oidc_subject)
    WHERE oidc_subject IS NOT NULL AND oidc_subject <> '';
ALTER TABLE users DROP COLUMN IF EXISTS oidc_issuer;
