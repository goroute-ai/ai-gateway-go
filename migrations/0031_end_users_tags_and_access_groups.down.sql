ALTER TABLE spend_logs
    DROP COLUMN IF EXISTS session_id,
    DROP COLUMN IF EXISTS tags,
    DROP COLUMN IF EXISTS end_user_id;

ALTER TABLE mcp_servers
    DROP COLUMN IF EXISTS rpm_limit;

ALTER TABLE virtual_keys
    DROP COLUMN IF EXISTS max_budget_per_session_micros,
    DROP COLUMN IF EXISTS max_iterations,
    DROP COLUMN IF EXISTS mcp_rpm_limit,
    DROP COLUMN IF EXISTS tags;

ALTER TABLE teams
    DROP COLUMN IF EXISTS max_budget_per_session_micros,
    DROP COLUMN IF EXISTS max_iterations,
    DROP COLUMN IF EXISTS mcp_rpm_limit;

ALTER TABLE organizations
    DROP COLUMN IF EXISTS max_budget_per_session_micros,
    DROP COLUMN IF EXISTS max_iterations;

DROP INDEX IF EXISTS idx_mag_members_group;
DROP INDEX IF EXISTS idx_mag_members_org_type_id;
DROP TABLE IF EXISTS model_access_group_members;

DROP INDEX IF EXISTS idx_model_access_groups_org_active;
DROP TABLE IF EXISTS model_access_groups;

DROP INDEX IF EXISTS idx_tags_org_active;
DROP TABLE IF EXISTS tags;

DROP INDEX IF EXISTS idx_end_users_org_active;
DROP TABLE IF EXISTS end_users;
