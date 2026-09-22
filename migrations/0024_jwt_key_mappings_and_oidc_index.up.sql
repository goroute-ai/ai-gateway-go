CREATE TABLE IF NOT EXISTS jwt_key_mappings (
    id VARCHAR(64) PRIMARY KEY,
    org_id VARCHAR(64) NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    issuer VARCHAR(512) NOT NULL,
    claim_name VARCHAR(128) NOT NULL,
    claim_value VARCHAR(512) NOT NULL,
    virtual_key_id VARCHAR(64) NOT NULL REFERENCES virtual_keys(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (issuer, claim_name, claim_value)
);

CREATE INDEX IF NOT EXISTS idx_jwt_key_mappings_org_id
    ON jwt_key_mappings(org_id);

CREATE UNIQUE INDEX IF NOT EXISTS idx_users_org_oidc_subject
    ON users(org_id, oidc_subject)
    WHERE oidc_subject IS NOT NULL AND oidc_subject <> '';
