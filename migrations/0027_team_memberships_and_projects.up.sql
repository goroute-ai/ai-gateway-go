CREATE TABLE IF NOT EXISTS team_memberships (
    id VARCHAR(64) PRIMARY KEY,
    org_id VARCHAR(64) NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    team_id VARCHAR(64) NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    user_id VARCHAR(64) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role VARCHAR(32) NOT NULL DEFAULT 'developer',
    max_budget_micros BIGINT NOT NULL DEFAULT 0,
    spent_micros BIGINT NOT NULL DEFAULT 0,
    rpm_limit INTEGER NOT NULL DEFAULT 0,
    tpm_limit INTEGER NOT NULL DEFAULT 0,
    allowed_models TEXT[] NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(team_id, user_id)
);

CREATE INDEX IF NOT EXISTS idx_team_memberships_org_user
    ON team_memberships(org_id, user_id);

CREATE INDEX IF NOT EXISTS idx_team_memberships_team
    ON team_memberships(team_id);

CREATE TABLE IF NOT EXISTS projects (
    id VARCHAR(64) PRIMARY KEY,
    org_id VARCHAR(64) NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    team_id VARCHAR(64) NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    max_budget_micros BIGINT NOT NULL DEFAULT 0,
    spent_micros BIGINT NOT NULL DEFAULT 0,
    rpm_limit INTEGER NOT NULL DEFAULT 0,
    tpm_limit INTEGER NOT NULL DEFAULT 0,
    allowed_models TEXT[] NOT NULL DEFAULT '{}',
    enforce_project_model_quota BOOLEAN NOT NULL DEFAULT FALSE,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(team_id, name)
);

CREATE INDEX IF NOT EXISTS idx_projects_org_team
    ON projects(org_id, team_id);

ALTER TABLE virtual_keys
    ADD COLUMN IF NOT EXISTS project_id VARCHAR(64) REFERENCES projects(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS idx_virtual_keys_project_id
    ON virtual_keys(project_id);
