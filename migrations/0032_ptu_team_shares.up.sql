CREATE TABLE IF NOT EXISTS deployment_ptu_shares (
    id VARCHAR(64) PRIMARY KEY,
    org_id VARCHAR(64) NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    deployment_id VARCHAR(64) NOT NULL REFERENCES model_deployments(id) ON DELETE CASCADE,
    team_id VARCHAR(64) NOT NULL REFERENCES teams(id) ON DELETE RESTRICT,
    reserved_rpm INTEGER NOT NULL DEFAULT 0,
    reserved_tpm INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(deployment_id, team_id)
);

CREATE INDEX IF NOT EXISTS idx_deployment_ptu_shares_org_dep
    ON deployment_ptu_shares (org_id, deployment_id);

CREATE INDEX IF NOT EXISTS idx_deployment_ptu_shares_team
    ON deployment_ptu_shares (team_id);

CREATE TABLE IF NOT EXISTS priority_classes (
    id VARCHAR(64) PRIMARY KEY,
    org_id VARCHAR(64) NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name VARCHAR(64) NOT NULL,
    weight DOUBLE PRECISION NOT NULL DEFAULT 1.0,
    priority_rank INTEGER NOT NULL DEFAULT 0,
    max_borrow_multiple DOUBLE PRECISION NOT NULL DEFAULT 2.0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(org_id, name)
);

CREATE INDEX IF NOT EXISTS idx_priority_classes_org
    ON priority_classes (org_id, priority_rank);
