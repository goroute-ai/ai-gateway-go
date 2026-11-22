-- =============================================================================
-- Migration 0040: A2A v1.0 OpenAPI-First Production Schema Extensions
-- =============================================================================

ALTER TABLE a2a_agents
    ADD COLUMN IF NOT EXISTS is_public_card            BOOLEAN      NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS protocol_binding          VARCHAR(32)  NOT NULL DEFAULT 'HTTP+JSON',
    ADD COLUMN IF NOT EXISTS extended_agent_card_json  TEXT,
    ADD COLUMN IF NOT EXISTS auth_header_name          VARCHAR(128) NOT NULL DEFAULT 'Authorization';

ALTER TABLE a2a_tasks
    ADD COLUMN IF NOT EXISTS context_id                VARCHAR(128) NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS status_message_json       TEXT,
    ADD COLUMN IF NOT EXISTS status_timestamp          TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS history_json              TEXT,
    ADD COLUMN IF NOT EXISTS artifacts_json            TEXT,
    ADD COLUMN IF NOT EXISTS metadata_json             TEXT;

CREATE INDEX IF NOT EXISTS idx_a2a_tasks_agent_filter
    ON a2a_tasks(agent_id, context_id, state, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_a2a_tasks_org_updated
    ON a2a_tasks(org_id, updated_at DESC);

-- Support multiple push notification configurations per task (A2A v1.0 ListTaskPushNotificationConfigs)
DROP INDEX IF EXISTS idx_a2a_push_configs_task;

ALTER TABLE a2a_push_notification_configs
    ADD COLUMN IF NOT EXISTS tenant                    VARCHAR(128) NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS token                     TEXT         NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS encrypted_auth_scheme     VARCHAR(64)  NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS encrypted_auth_creds      TEXT,
    ADD COLUMN IF NOT EXISTS encrypted_auth_dek        TEXT,
    ADD COLUMN IF NOT EXISTS updated_at                TIMESTAMPTZ  NOT NULL DEFAULT NOW();

CREATE INDEX IF NOT EXISTS idx_a2a_push_configs_task_created
    ON a2a_push_notification_configs(task_id, created_at DESC);

ALTER TABLE a2a_outbox_events
    ADD COLUMN IF NOT EXISTS push_config_id            VARCHAR(64)  NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS last_error                TEXT         NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS updated_at                TIMESTAMPTZ  NOT NULL DEFAULT NOW();

CREATE INDEX IF NOT EXISTS idx_a2a_outbox_task_status
    ON a2a_outbox_events(task_id, status, created_at DESC);
