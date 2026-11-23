-- Reverse Migration 0040: A2A v1.0 OpenAPI-First Production Schema Extensions

DROP INDEX IF EXISTS idx_a2a_outbox_task_status;
ALTER TABLE a2a_outbox_events
    DROP COLUMN IF EXISTS updated_at,
    DROP COLUMN IF EXISTS last_error,
    DROP COLUMN IF EXISTS push_config_id;

DROP INDEX IF EXISTS idx_a2a_push_configs_task_created;
ALTER TABLE a2a_push_notification_configs
    DROP COLUMN IF EXISTS updated_at,
    DROP COLUMN IF EXISTS encrypted_auth_dek,
    DROP COLUMN IF EXISTS encrypted_auth_creds,
    DROP COLUMN IF EXISTS encrypted_auth_scheme,
    DROP COLUMN IF EXISTS token,
    DROP COLUMN IF EXISTS tenant;
CREATE UNIQUE INDEX IF NOT EXISTS idx_a2a_push_configs_task ON a2a_push_notification_configs(task_id);

DROP INDEX IF EXISTS idx_a2a_tasks_org_updated;
DROP INDEX IF EXISTS idx_a2a_tasks_agent_filter;
ALTER TABLE a2a_tasks
    DROP COLUMN IF EXISTS metadata_json,
    DROP COLUMN IF EXISTS artifacts_json,
    DROP COLUMN IF EXISTS history_json,
    DROP COLUMN IF EXISTS status_timestamp,
    DROP COLUMN IF EXISTS status_message_json,
    DROP COLUMN IF EXISTS context_id;

ALTER TABLE a2a_agents
    DROP COLUMN IF EXISTS auth_header_name,
    DROP COLUMN IF EXISTS extended_agent_card_json,
    DROP COLUMN IF EXISTS protocol_binding,
    DROP COLUMN IF EXISTS is_public_card;
