BEGIN;

DO $$
DECLARE
    dup RECORD;
BEGIN
    -- Lock concurrent user writes for the remainder of the rollback transaction so no duplicate
    -- (org_id, oidc_subject) binding can be inserted after the preflight check passes.
    LOCK TABLE users IN SHARE ROW EXCLUSIVE MODE;

    SELECT org_id, oidc_subject, COUNT(*) AS binding_count
    INTO dup
    FROM users
    WHERE oidc_subject IS NOT NULL AND oidc_subject <> ''
    GROUP BY org_id, oidc_subject
    HAVING COUNT(*) > 1
    ORDER BY org_id ASC, oidc_subject ASC
    LIMIT 1;

    IF FOUND THEN
        RAISE EXCEPTION
            'cannot rollback migration 0034: duplicate nonempty (org_id, oidc_subject) bindings exist (first conflict: org_id=%, oidc_subject=%, count=%); index idx_users_org_oidc_subject cannot be restored without losing identity uniqueness — resolve conflicting bindings explicitly before retrying rollback',
            dup.org_id, dup.oidc_subject, dup.binding_count;
    END IF;
END $$;

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

COMMIT;
