-- Rollback Migration 0041: Authorization Parity

DROP INDEX IF EXISTS idx_audit_logs_org_action_resource;
DROP INDEX IF EXISTS idx_audit_logs_org_actor_created;
DROP INDEX IF EXISTS idx_audit_logs_org_created_id;

ALTER TABLE model_access_groups
    DROP COLUMN IF EXISTS allowed_a2a_agents,
    DROP COLUMN IF EXISTS allowed_mcp_tools,
    DROP COLUMN IF EXISTS allowed_mcp_servers;

ALTER TABLE access_group_rules
    DROP COLUMN IF EXISTS allowed_a2a_agents,
    DROP COLUMN IF EXISTS allowed_mcp_tools,
    DROP COLUMN IF EXISTS allowed_mcp_servers;

ALTER TABLE projects
    DROP COLUMN IF EXISTS allowed_a2a_agents,
    DROP COLUMN IF EXISTS allowed_mcp_toolsets,
    DROP COLUMN IF EXISTS allowed_mcp_tools,
    DROP COLUMN IF EXISTS allowed_mcp_servers,
    DROP COLUMN IF EXISTS allowed_routing_tags,
    DROP COLUMN IF EXISTS allowed_deployments;

ALTER TABLE teams
    DROP COLUMN IF EXISTS allowed_mcp_toolsets,
    DROP COLUMN IF EXISTS allowed_mcp_tools,
    DROP COLUMN IF EXISTS allowed_deployments;

ALTER TABLE virtual_keys
    DROP COLUMN IF EXISTS allowed_mcp_toolsets,
    DROP COLUMN IF EXISTS allowed_mcp_tools,
    DROP COLUMN IF EXISTS allowed_deployments;
