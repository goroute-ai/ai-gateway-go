ALTER TABLE virtual_keys
    DROP COLUMN IF EXISTS can_impersonate;

DROP INDEX IF EXISTS idx_users_org_scim_external_id;

ALTER TABLE users
    DROP COLUMN IF EXISTS scim_active,
    DROP COLUMN IF EXISTS scim_external_id;
