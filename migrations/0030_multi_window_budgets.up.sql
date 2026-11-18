CREATE TABLE IF NOT EXISTS budget_window_limits (
    id VARCHAR(64) PRIMARY KEY,
    org_id VARCHAR(64) NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    scope_type VARCHAR(32) NOT NULL,
    scope_id VARCHAR(128) NOT NULL,
    window_type VARCHAR(32) NOT NULL,
    max_budget_micros BIGINT NOT NULL DEFAULT 0,
    spent_micros BIGINT NOT NULL DEFAULT 0,
    window_reset_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (org_id, scope_type, scope_id, window_type)
);

CREATE INDEX IF NOT EXISTS idx_budget_window_limits_org_scope
    ON budget_window_limits (org_id, scope_type, scope_id);

CREATE INDEX IF NOT EXISTS idx_budget_window_limits_reset_at
    ON budget_window_limits (window_reset_at);

ALTER TABLE organizations
    ADD COLUMN IF NOT EXISTS temp_budget_increase_micros BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS temp_budget_expires_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS self_serve_budget_policy VARCHAR(32) NOT NULL DEFAULT 'disabled';

ALTER TABLE teams
    ADD COLUMN IF NOT EXISTS temp_budget_increase_micros BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS temp_budget_expires_at TIMESTAMPTZ;

ALTER TABLE users
    ADD COLUMN IF NOT EXISTS temp_budget_increase_micros BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS temp_budget_expires_at TIMESTAMPTZ;

ALTER TABLE virtual_keys
    ADD COLUMN IF NOT EXISTS temp_budget_increase_micros BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS temp_budget_expires_at TIMESTAMPTZ;
