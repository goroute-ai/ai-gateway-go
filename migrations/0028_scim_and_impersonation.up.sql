ALTER TABLE users
    ADD COLUMN IF NOT EXISTS scim_external_id VARCHAR(255),
    ADD COLUMN IF NOT EXISTS scim_active BOOLEAN NOT NULL DEFAULT TRUE;

CREATE UNIQUE INDEX IF NOT EXISTS idx_users_org_scim_external_id
    ON users(org_id, scim_external_id)
    WHERE scim_external_id IS NOT NULL AND scim_external_id <> '';

ALTER TABLE virtual_keys
    ADD COLUMN IF NOT EXISTS can_impersonate BOOLEAN NOT NULL DEFAULT FALSE;
