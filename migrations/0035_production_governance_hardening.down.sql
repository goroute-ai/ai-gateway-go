-- =============================================================================
-- Rollback Migration 0034: Production Governance, Lifecycle & Audit Diff Hardening
-- =============================================================================

ALTER TABLE audit_logs
    DROP COLUMN IF EXISTS after_value,
    DROP COLUMN IF EXISTS before_value;

DROP INDEX IF EXISTS idx_virtual_keys_org_status;
DROP INDEX IF EXISTS idx_virtual_keys_active_expires;

ALTER TABLE virtual_keys
    DROP COLUMN IF EXISTS expiry_alert_sent_days,
    DROP COLUMN IF EXISTS revoked_by,
    DROP COLUMN IF EXISTS revoked_at,
    DROP COLUMN IF EXISTS rotation_count,
    DROP COLUMN IF EXISTS last_rotated_at;

ALTER TABLE teams
    DROP COLUMN IF EXISTS team_member_permissions,
    DROP COLUMN IF EXISTS default_member_allowed_models,
    DROP COLUMN IF EXISTS default_member_tpm_limit,
    DROP COLUMN IF EXISTS default_member_rpm_limit,
    DROP COLUMN IF EXISTS default_member_max_budget_micros,
    DROP COLUMN IF EXISTS enforce_guaranteed_throughput;

ALTER TABLE organizations
    DROP COLUMN IF EXISTS lifecycle_webhook_url,
    DROP COLUMN IF EXISTS key_expiry_alert_days,
    DROP COLUMN IF EXISTS developer_self_serve_keys,
    DROP COLUMN IF EXISTS enforce_guaranteed_throughput;
