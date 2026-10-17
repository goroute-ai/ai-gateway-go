-- =============================================================================
-- Migration 0003 Down: Rollback MCP and A2A Support
-- =============================================================================

DROP TABLE IF EXISTS a2a_push_notification_configs;
DROP TABLE IF EXISTS a2a_outbox_events;
DROP TABLE IF EXISTS a2a_stream_publications;
DROP TABLE IF EXISTS a2a_task_events;
DROP TABLE IF EXISTS a2a_tasks;
DROP TABLE IF EXISTS a2a_agents;

DROP TABLE IF EXISTS mcp_user_credentials;
DROP TABLE IF EXISTS mcp_toolsets;
DROP TABLE IF EXISTS mcp_tools;
DROP TABLE IF EXISTS mcp_servers;

ALTER TABLE spend_logs DROP COLUMN IF EXISTS protocol_target;
ALTER TABLE spend_logs DROP COLUMN IF EXISTS protocol;

ALTER TABLE teams DROP COLUMN IF EXISTS allowed_client_apps;
ALTER TABLE teams DROP COLUMN IF EXISTS allowed_a2a_agents;
ALTER TABLE teams DROP COLUMN IF EXISTS allowed_mcp_servers;

ALTER TABLE virtual_keys DROP COLUMN IF EXISTS allowed_client_apps;
ALTER TABLE virtual_keys DROP COLUMN IF EXISTS allowed_a2a_agents;
ALTER TABLE virtual_keys DROP COLUMN IF EXISTS allowed_mcp_servers;
