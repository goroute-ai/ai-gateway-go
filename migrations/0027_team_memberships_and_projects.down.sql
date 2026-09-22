DROP INDEX IF EXISTS idx_virtual_keys_project_id;

ALTER TABLE virtual_keys
    DROP COLUMN IF EXISTS project_id;

DROP INDEX IF EXISTS idx_projects_org_team;

DROP TABLE IF EXISTS projects;

DROP INDEX IF EXISTS idx_team_memberships_team;

DROP INDEX IF EXISTS idx_team_memberships_org_user;

DROP TABLE IF EXISTS team_memberships;
