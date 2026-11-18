CREATE TABLE IF NOT EXISTS access_group_rules (
    id VARCHAR(64) PRIMARY KEY,
    org_id VARCHAR(64) NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    attribute VARCHAR(128) NOT NULL,
    operator VARCHAR(32) NOT NULL,
    value TEXT NOT NULL,
    allowed_models TEXT[] NOT NULL DEFAULT '{}',
    access_group_id VARCHAR(128) NOT NULL DEFAULT '',
    priority INTEGER NOT NULL DEFAULT 0,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_access_group_rules_org_active
    ON access_group_rules(org_id, is_active);
