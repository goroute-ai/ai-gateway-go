-- Migration 0041: Authorization Parity (Deployment allowlists, MCP tool/toolset permissions,
-- Project MCP/A2A/routing-tag parity, Unified Access Group MCP/A2A grants, and Audit Log indexes).

ALTER TABLE virtual_keys
    ADD COLUMN IF NOT EXISTS allowed_deployments  TEXT[] NOT NULL DEFAULT '{}',
    ADD COLUMN IF NOT EXISTS allowed_mcp_tools    TEXT[],
    ADD COLUMN IF NOT EXISTS allowed_mcp_toolsets TEXT[];

ALTER TABLE teams
    ADD COLUMN IF NOT EXISTS allowed_deployments  TEXT[] NOT NULL DEFAULT '{}',
    ADD COLUMN IF NOT EXISTS allowed_mcp_tools    TEXT[],
    ADD COLUMN IF NOT EXISTS allowed_mcp_toolsets TEXT[];

ALTER TABLE projects
    ADD COLUMN IF NOT EXISTS allowed_deployments  TEXT[] NOT NULL DEFAULT '{}',
    ADD COLUMN IF NOT EXISTS allowed_routing_tags TEXT[] NOT NULL DEFAULT '{}',
    ADD COLUMN IF NOT EXISTS allowed_mcp_servers  TEXT[],
    ADD COLUMN IF NOT EXISTS allowed_mcp_tools    TEXT[],
    ADD COLUMN IF NOT EXISTS allowed_mcp_toolsets TEXT[],
    ADD COLUMN IF NOT EXISTS allowed_a2a_agents   TEXT[];

ALTER TABLE access_group_rules
    ADD COLUMN IF NOT EXISTS allowed_mcp_servers  TEXT[] NOT NULL DEFAULT '{}',
    ADD COLUMN IF NOT EXISTS allowed_mcp_tools    TEXT[] NOT NULL DEFAULT '{}',
    ADD COLUMN IF NOT EXISTS allowed_a2a_agents   TEXT[] NOT NULL DEFAULT '{}';

ALTER TABLE model_access_groups
    ADD COLUMN IF NOT EXISTS allowed_mcp_servers  TEXT[] NOT NULL DEFAULT '{}',
    ADD COLUMN IF NOT EXISTS allowed_mcp_tools    TEXT[] NOT NULL DEFAULT '{}',
    ADD COLUMN IF NOT EXISTS allowed_a2a_agents   TEXT[] NOT NULL DEFAULT '{}';

CREATE INDEX IF NOT EXISTS idx_audit_logs_org_created_id
    ON audit_logs (org_id, created_at DESC, id DESC);

CREATE INDEX IF NOT EXISTS idx_audit_logs_org_actor_created
    ON audit_logs (org_id, actor_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_audit_logs_org_action_resource
    ON audit_logs (org_id, action, resource, created_at DESC);
