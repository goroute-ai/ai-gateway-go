CREATE TABLE IF NOT EXISTS quota_policies (
    id VARCHAR(64) PRIMARY KEY,
    org_id VARCHAR(64) NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    scope_type VARCHAR(32) NOT NULL,
    scope_id VARCHAR(128) NOT NULL,
    model_pattern VARCHAR(128) NOT NULL DEFAULT '*',
    rpm_limit INTEGER NOT NULL DEFAULT 0,
    tpm_limit INTEGER NOT NULL DEFAULT 0,
    itpm_limit INTEGER NOT NULL DEFAULT 0,
    otpm_limit INTEGER NOT NULL DEFAULT 0,
    tpd_limit BIGINT NOT NULL DEFAULT 0,
    max_concurrent INTEGER NOT NULL DEFAULT 0,
    max_budget_micros BIGINT NOT NULL DEFAULT 0,
    spent_micros BIGINT NOT NULL DEFAULT 0,
    budget_reset_period VARCHAR(32) NOT NULL DEFAULT 'monthly',
    budget_reset_at TIMESTAMPTZ,
    max_iterations INTEGER NOT NULL DEFAULT 0,
    window_ttl_sec INTEGER NOT NULL DEFAULT 0,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (org_id, scope_type, scope_id, model_pattern)
);

CREATE INDEX IF NOT EXISTS idx_quota_policies_org_scope
    ON quota_policies (org_id, scope_type, scope_id);
