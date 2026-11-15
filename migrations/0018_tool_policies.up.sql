-- =============================================================================
-- Migration 0018: Tool Trust Policies & Taint Tracking
-- =============================================================================

CREATE TABLE IF NOT EXISTS tool_policies (
    id             VARCHAR(64)  PRIMARY KEY DEFAULT gen_random_uuid()::text,
    org_id         VARCHAR(64)  NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    team_id        VARCHAR(64)  DEFAULT NULL,
    virtual_key_id VARCHAR(64)  DEFAULT NULL,
    tool_name      VARCHAR(255) NOT NULL,
    input_policy   VARCHAR(32)  NOT NULL DEFAULT 'untrusted' CHECK (input_policy IN ('untrusted', 'trusted', 'blocked')),
    output_policy  VARCHAR(32)  NOT NULL DEFAULT 'untrusted' CHECK (output_policy IN ('untrusted', 'trusted')),
    created_at     TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at     TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    UNIQUE NULLS NOT DISTINCT (org_id, team_id, virtual_key_id, tool_name)
);

CREATE INDEX IF NOT EXISTS idx_tool_policies_org
    ON tool_policies(org_id);
CREATE INDEX IF NOT EXISTS idx_tool_policies_org_team
    ON tool_policies(org_id, team_id);
CREATE INDEX IF NOT EXISTS idx_tool_policies_org_key
    ON tool_policies(org_id, virtual_key_id);
CREATE INDEX IF NOT EXISTS idx_tool_policies_org_tool
    ON tool_policies(org_id, tool_name);
