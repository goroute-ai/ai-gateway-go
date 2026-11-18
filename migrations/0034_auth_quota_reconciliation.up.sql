ALTER TABLE users ADD COLUMN IF NOT EXISTS oidc_issuer VARCHAR(512) NOT NULL DEFAULT '';

DROP INDEX IF EXISTS idx_users_org_oidc_subject;
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_org_issuer_subject
    ON users (org_id, oidc_issuer, oidc_subject)
    WHERE oidc_subject IS NOT NULL AND oidc_subject <> '';

ALTER TABLE virtual_keys
    ADD COLUMN IF NOT EXISTS staged_key_hash VARCHAR(128),
    ADD COLUMN IF NOT EXISTS staged_key_prefix VARCHAR(32),
    ADD COLUMN IF NOT EXISTS staged_encrypted_raw_key TEXT,
    ADD COLUMN IF NOT EXISTS staged_key_dek TEXT,
    ADD COLUMN IF NOT EXISTS staged_created_at TIMESTAMPTZ;

ALTER TABLE spend_logs
    ADD COLUMN IF NOT EXISTS project_id VARCHAR(64),
    ADD COLUMN IF NOT EXISTS model_access_group_ids TEXT[] NOT NULL DEFAULT '{}',
    ADD COLUMN IF NOT EXISTS matched_quota_policy_ids TEXT[] NOT NULL DEFAULT '{}';

CREATE INDEX IF NOT EXISTS idx_spend_logs_project_created
    ON spend_logs (org_id, project_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_spend_logs_org_team_user_created
    ON spend_logs (org_id, team_id, user_id, created_at DESC);

ALTER TABLE budget_window_limits
    ADD COLUMN IF NOT EXISTS rolling_hold_micros BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS rolling_hold_expires_at TIMESTAMPTZ;

UPDATE budget_window_limits bw
SET
    spent_micros = CASE
        WHEN att.has_attributable_history THEN att.recent_micros
        ELSE bw.spent_micros
    END,
    rolling_hold_micros = CASE
        WHEN att.has_attributable_history THEN 0
        ELSE bw.spent_micros
    END,
    rolling_hold_expires_at = CASE
        WHEN att.has_attributable_history THEN NULL
        WHEN bw.spent_micros > 0 THEN NOW() + INTERVAL '24 hours'
        ELSE NULL
    END,
    updated_at = NOW()
FROM (
    SELECT
        b.id,
        (
            b.scope_type IN ('org', 'team', 'user', 'key', 'team_member', 'end_user', 'tag')
            AND EXISTS (
                SELECT 1 FROM spend_logs sl0
                WHERE sl0.org_id = b.org_id
                  AND (
                    (b.scope_type = 'org' AND b.scope_id = b.org_id)
                    OR (b.scope_type = 'team' AND sl0.team_id = b.scope_id)
                    OR (b.scope_type = 'user' AND sl0.user_id = b.scope_id)
                    OR (b.scope_type = 'key' AND sl0.virtual_key_id = b.scope_id)
                    OR (b.scope_type = 'team_member' AND (sl0.team_id || ':' || sl0.user_id) = b.scope_id)
                    OR (b.scope_type = 'end_user' AND sl0.end_user_id = b.scope_id)
                    OR (b.scope_type = 'tag' AND b.scope_id = ANY(sl0.tags))
                  )
            )
        ) AS has_attributable_history,
        (
            SELECT COALESCE(SUM(sl.cost_micros), 0)
            FROM spend_logs sl
            WHERE sl.org_id = b.org_id
              AND sl.created_at > NOW() - INTERVAL '24 hours'
              AND (
                (b.scope_type = 'org' AND b.scope_id = b.org_id)
                OR (b.scope_type = 'team' AND sl.team_id = b.scope_id)
                OR (b.scope_type = 'user' AND sl.user_id = b.scope_id)
                OR (b.scope_type = 'key' AND sl.virtual_key_id = b.scope_id)
                OR (b.scope_type = 'team_member' AND (sl.team_id || ':' || sl.user_id) = b.scope_id)
                OR (b.scope_type = 'end_user' AND sl.end_user_id = b.scope_id)
                OR (b.scope_type = 'tag' AND b.scope_id = ANY(sl.tags))
              )
        ) AS recent_micros
    FROM budget_window_limits b
    WHERE b.window_type = 'rolling_24h'
) att
WHERE bw.id = att.id;
