-- =============================================================================
-- Migration 0038: UI-Selectable Active MCP Protocol Specification Settings
-- =============================================================================

CREATE TABLE IF NOT EXISTS mcp_runtime_settings (
    id                       VARCHAR(32)  PRIMARY KEY DEFAULT 'default',
    active_protocol_version  VARCHAR(32)  NOT NULL DEFAULT '2026-07-28',
    strict_schema_validation BOOLEAN      NOT NULL DEFAULT FALSE,
    updated_by               VARCHAR(255) NOT NULL DEFAULT 'system',
    updated_at               TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

INSERT INTO mcp_runtime_settings (id, active_protocol_version, strict_schema_validation, updated_by)
VALUES ('default', '2026-07-28', FALSE, 'system')
ON CONFLICT (id) DO NOTHING;
