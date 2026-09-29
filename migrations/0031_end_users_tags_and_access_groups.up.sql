CREATE TABLE IF NOT EXISTS end_users (
    id VARCHAR(64) PRIMARY KEY,
    org_id VARCHAR(64) NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    end_user_id VARCHAR(255) NOT NULL,
    alias VARCHAR(255) NOT NULL DEFAULT '',
    max_budget_micros BIGINT NOT NULL DEFAULT 0,
    spent_micros BIGINT NOT NULL DEFAULT 0,
    budget_reset_period VARCHAR(32) NOT NULL DEFAULT 'monthly',
    budget_reset_at TIMESTAMPTZ,
    rpm_limit INTEGER NOT NULL DEFAULT 0,
    tpm_limit INTEGER NOT NULL DEFAULT 0,
    itpm_limit INTEGER NOT NULL DEFAULT 0,
    otpm_limit INTEGER NOT NULL DEFAULT 0,
    tpd_limit BIGINT NOT NULL DEFAULT 0,
    max_concurrent INTEGER NOT NULL DEFAULT 0,
    allowed_models TEXT[] NOT NULL DEFAULT '{}',
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (org_id, end_user_id)
);

CREATE INDEX IF NOT EXISTS idx_end_users_org_active
    ON end_users (org_id, is_active);

CREATE TABLE IF NOT EXISTS tags (
    id VARCHAR(64) PRIMARY KEY,
    org_id VARCHAR(64) NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    tag VARCHAR(255) NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    max_budget_micros BIGINT NOT NULL DEFAULT 0,
    spent_micros BIGINT NOT NULL DEFAULT 0,
    budget_reset_period VARCHAR(32) NOT NULL DEFAULT 'monthly',
    budget_reset_at TIMESTAMPTZ,
    rpm_limit INTEGER NOT NULL DEFAULT 0,
    tpm_limit INTEGER NOT NULL DEFAULT 0,
    itpm_limit INTEGER NOT NULL DEFAULT 0,
    otpm_limit INTEGER NOT NULL DEFAULT 0,
    tpd_limit BIGINT NOT NULL DEFAULT 0,
    max_concurrent INTEGER NOT NULL DEFAULT 0,
    allowed_models TEXT[] NOT NULL DEFAULT '{}',
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (org_id, tag)
);

CREATE INDEX IF NOT EXISTS idx_tags_org_active
    ON tags (org_id, is_active);

CREATE TABLE IF NOT EXISTS model_access_groups (
    id VARCHAR(64) PRIMARY KEY,
    org_id VARCHAR(64) NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    max_budget_micros BIGINT NOT NULL DEFAULT 0,
    spent_micros BIGINT NOT NULL DEFAULT 0,
    budget_reset_period VARCHAR(32) NOT NULL DEFAULT 'monthly',
    budget_reset_at TIMESTAMPTZ,
    rpm_limit INTEGER NOT NULL DEFAULT 0,
    tpm_limit INTEGER NOT NULL DEFAULT 0,
    itpm_limit INTEGER NOT NULL DEFAULT 0,
    otpm_limit INTEGER NOT NULL DEFAULT 0,
    tpd_limit BIGINT NOT NULL DEFAULT 0,
    max_concurrent INTEGER NOT NULL DEFAULT 0,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (org_id, name)
);

CREATE INDEX IF NOT EXISTS idx_model_access_groups_org_active
    ON model_access_groups (org_id, is_active);

CREATE TABLE IF NOT EXISTS model_access_group_members (
    id VARCHAR(64) PRIMARY KEY,
    org_id VARCHAR(64) NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    group_id VARCHAR(64) NOT NULL REFERENCES model_access_groups(id) ON DELETE CASCADE,
    member_type VARCHAR(32) NOT NULL CHECK (member_type IN ('model', 'key', 'team', 'user', 'project', 'org')),
    member_id VARCHAR(255) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (group_id, member_type, member_id)
);

CREATE INDEX IF NOT EXISTS idx_mag_members_org_type_id
    ON model_access_group_members (org_id, member_type, member_id);

CREATE INDEX IF NOT EXISTS idx_mag_members_group
    ON model_access_group_members (group_id);

ALTER TABLE organizations
    ADD COLUMN IF NOT EXISTS max_iterations INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS max_budget_per_session_micros BIGINT NOT NULL DEFAULT 0;

ALTER TABLE teams
    ADD COLUMN IF NOT EXISTS mcp_rpm_limit INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS max_iterations INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS max_budget_per_session_micros BIGINT NOT NULL DEFAULT 0;

ALTER TABLE virtual_keys
    ADD COLUMN IF NOT EXISTS tags TEXT[] NOT NULL DEFAULT '{}',
    ADD COLUMN IF NOT EXISTS mcp_rpm_limit INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS max_iterations INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS max_budget_per_session_micros BIGINT NOT NULL DEFAULT 0;

ALTER TABLE mcp_servers
    ADD COLUMN IF NOT EXISTS rpm_limit INTEGER NOT NULL DEFAULT 0;

ALTER TABLE spend_logs
    ADD COLUMN IF NOT EXISTS end_user_id VARCHAR(255),
    ADD COLUMN IF NOT EXISTS tags TEXT[] NOT NULL DEFAULT '{}',
    ADD COLUMN IF NOT EXISTS session_id VARCHAR(255);
