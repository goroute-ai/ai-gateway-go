-- =============================================================================
-- Migration 0034: Production Governance, Lifecycle & Audit Diff Hardening
-- =============================================================================

ALTER TABLE organizations
    ADD COLUMN IF NOT EXISTS enforce_guaranteed_throughput BOOLEAN   NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS developer_self_serve_keys     BOOLEAN   NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS key_expiry_alert_days         INTEGER[] NOT NULL DEFAULT '{7,1}',
    ADD COLUMN IF NOT EXISTS lifecycle_webhook_url         TEXT      NOT NULL DEFAULT '';

ALTER TABLE teams
    ADD COLUMN IF NOT EXISTS enforce_guaranteed_throughput BOOLEAN  NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS default_member_max_budget_micros BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS default_member_rpm_limit      INTEGER  NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS default_member_tpm_limit      INTEGER  NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS default_member_allowed_models TEXT[]   NOT NULL DEFAULT '{}',
    ADD COLUMN IF NOT EXISTS team_member_permissions       TEXT[]   NOT NULL DEFAULT '{}';

ALTER TABLE virtual_keys
    ADD COLUMN IF NOT EXISTS last_rotated_at        TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS rotation_count         INTEGER     NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS revoked_at             TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS revoked_by             VARCHAR(128) NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS expiry_alert_sent_days INTEGER[]   NOT NULL DEFAULT '{}';

CREATE INDEX IF NOT EXISTS idx_virtual_keys_active_expires
    ON virtual_keys(expires_at)
    WHERE is_active = TRUE AND expires_at IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_virtual_keys_org_status
    ON virtual_keys(org_id, is_active, expires_at);

ALTER TABLE audit_logs
    ADD COLUMN IF NOT EXISTS before_value JSONB,
    ADD COLUMN IF NOT EXISTS after_value  JSONB;
