-- =============================================================================
-- Migration 0003: Model Context Protocol (MCP) & Agent-to-Agent (A2A) Support
-- =============================================================================

-- 1. Virtual Keys & Teams 3-State RBAC Expansion
ALTER TABLE virtual_keys ADD COLUMN IF NOT EXISTS allowed_mcp_servers TEXT[] DEFAULT '{}';
ALTER TABLE virtual_keys ADD COLUMN IF NOT EXISTS allowed_a2a_agents TEXT[] DEFAULT '{}';
ALTER TABLE virtual_keys ADD COLUMN IF NOT EXISTS allowed_client_apps TEXT[] DEFAULT '{}';

ALTER TABLE teams ADD COLUMN IF NOT EXISTS allowed_mcp_servers TEXT[] DEFAULT NULL;
ALTER TABLE teams ADD COLUMN IF NOT EXISTS allowed_a2a_agents TEXT[] DEFAULT NULL;
ALTER TABLE teams ADD COLUMN IF NOT EXISTS allowed_client_apps TEXT[] DEFAULT NULL;

-- 2. FinOps Protocol Spend Attribution
ALTER TABLE spend_logs ADD COLUMN IF NOT EXISTS protocol VARCHAR(32) NOT NULL DEFAULT 'inference';
ALTER TABLE spend_logs ADD COLUMN IF NOT EXISTS protocol_target VARCHAR(255);
CREATE INDEX IF NOT EXISTS idx_spend_logs_protocol ON spend_logs(protocol, created_at DESC);

-- 3. MCP Servers
CREATE TABLE IF NOT EXISTS mcp_servers (
    id                    VARCHAR(64)  PRIMARY KEY DEFAULT gen_random_uuid()::text,
    org_id                VARCHAR(64)  NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name                  VARCHAR(255) NOT NULL,
    slug                  VARCHAR(128) NOT NULL,
    protocol_version       VARCHAR(32)  NOT NULL DEFAULT '2026-07-28',
    transport_type        VARCHAR(32)  NOT NULL DEFAULT 'streamable_http',
    endpoint_url          TEXT         NOT NULL,
    config_version        BIGINT       NOT NULL DEFAULT 1,
    auth_type             VARCHAR(32)  NOT NULL DEFAULT 'none',
    encrypted_auth_secret TEXT,
    encrypted_auth_dek    TEXT,
    static_headers        JSONB,
    oauth2_endpoint       TEXT,
    oauth2_client_id      VARCHAR(255),
    oauth2_scopes         TEXT[],
    pinned_tool_hash      VARCHAR(128),
    is_active             BOOLEAN      NOT NULL DEFAULT TRUE,
    created_at            TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at            TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_mcp_servers_org_slug ON mcp_servers(org_id, slug);

-- 4. MCP Tools
CREATE TABLE IF NOT EXISTS mcp_tools (
    id                   VARCHAR(64)  PRIMARY KEY DEFAULT gen_random_uuid()::text,
    server_id            VARCHAR(64)  NOT NULL REFERENCES mcp_servers(id) ON DELETE CASCADE,
    org_id               VARCHAR(64)  NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name                 VARCHAR(255) NOT NULL,
    description          TEXT,
    input_schema         JSONB,
    tool_def_hash        VARCHAR(128) NOT NULL,
    cost_per_call_micros BIGINT       NOT NULL DEFAULT 0,
    is_active            BOOLEAN      NOT NULL DEFAULT TRUE,
    created_at           TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at           TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_mcp_tools_server_name ON mcp_tools(server_id, name);

-- 5. MCP Toolsets
CREATE TABLE IF NOT EXISTS mcp_toolsets (
    id         VARCHAR(64)  PRIMARY KEY DEFAULT gen_random_uuid()::text,
    org_id     VARCHAR(64)  NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name       VARCHAR(255) NOT NULL,
    slug       VARCHAR(128) NOT NULL,
    tool_ids   TEXT[]       NOT NULL DEFAULT '{}',
    is_active  BOOLEAN      NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_mcp_toolsets_org_slug ON mcp_toolsets(org_id, slug);

-- 6. MCP User Credentials (BYOK)
CREATE TABLE IF NOT EXISTS mcp_user_credentials (
    id              VARCHAR(64) PRIMARY KEY DEFAULT gen_random_uuid()::text,
    server_id       VARCHAR(64) NOT NULL REFERENCES mcp_servers(id) ON DELETE CASCADE,
    user_id         VARCHAR(64) NOT NULL,
    org_id          VARCHAR(64) NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    encrypted_token TEXT        NOT NULL,
    encrypted_dek   TEXT        NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_mcp_user_creds_server_user ON mcp_user_credentials(server_id, user_id);

-- 7. A2A Agents
CREATE TABLE IF NOT EXISTS a2a_agents (
    id                     VARCHAR(64)  PRIMARY KEY DEFAULT gen_random_uuid()::text,
    org_id                 VARCHAR(64)  NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name                   VARCHAR(255) NOT NULL,
    slug                   VARCHAR(128) NOT NULL,
    endpoint_url           TEXT         NOT NULL,
    agent_card_url         TEXT,
    agent_card_json        TEXT,
    task_visibility_mode   VARCHAR(32)  NOT NULL DEFAULT 'key_strict',
    auth_type              VARCHAR(32)  NOT NULL DEFAULT 'none',
    encrypted_auth_secret  TEXT,
    encrypted_auth_dek     TEXT,
    max_task_iterations    INTEGER      NOT NULL DEFAULT 50,
    max_task_budget_micros BIGINT       NOT NULL DEFAULT 0,
    is_active              BOOLEAN      NOT NULL DEFAULT TRUE,
    is_killed              BOOLEAN      NOT NULL DEFAULT FALSE,
    created_at             TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at             TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_a2a_agents_org_slug ON a2a_agents(org_id, slug);

-- 8. A2A Tasks
CREATE TABLE IF NOT EXISTS a2a_tasks (
    id                  VARCHAR(64) PRIMARY KEY DEFAULT gen_random_uuid()::text,
    agent_id            VARCHAR(64) NOT NULL REFERENCES a2a_agents(id) ON DELETE CASCADE,
    org_id              VARCHAR(64) NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    team_id             VARCHAR(64),
    virtual_key_id      VARCHAR(64) NOT NULL,
    user_id             VARCHAR(64),
    client_task_id      VARCHAR(255),
    state               VARCHAR(32) NOT NULL DEFAULT 'submitted',
    last_event_seq      BIGINT      NOT NULL DEFAULT 0,
    input_message_json  TEXT,
    output_message_json TEXT,
    total_cost_micros   BIGINT      NOT NULL DEFAULT 0,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at        TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_a2a_tasks_agent ON a2a_tasks(agent_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_a2a_tasks_virtual_key ON a2a_tasks(virtual_key_id, state);

-- 9. A2A Task Events (Durable Event Log)
CREATE TABLE IF NOT EXISTS a2a_task_events (
    id           VARCHAR(64) PRIMARY KEY DEFAULT gen_random_uuid()::text,
    task_id      VARCHAR(64) NOT NULL REFERENCES a2a_tasks(id) ON DELETE CASCADE,
    event_seq    BIGINT      NOT NULL,
    event_type   VARCHAR(64) NOT NULL,
    payload_json TEXT        NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_a2a_task_events_seq ON a2a_task_events(task_id, event_seq);

-- 10. A2A Stream Publications (Redis Delivery Buffer)
CREATE TABLE IF NOT EXISTS a2a_stream_publications (
    id              VARCHAR(64) PRIMARY KEY DEFAULT gen_random_uuid()::text,
    task_id         VARCHAR(64) NOT NULL REFERENCES a2a_tasks(id) ON DELETE CASCADE,
    event_seq       BIGINT      NOT NULL,
    payload_json    TEXT        NOT NULL,
    published       BOOLEAN     NOT NULL DEFAULT FALSE,
    attempt_count   INTEGER     NOT NULL DEFAULT 0,
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_a2a_stream_pub_pending ON a2a_stream_publications(published, next_attempt_at) WHERE NOT published;

-- 11. A2A Outbox Events (Transactional Webhooks)
CREATE TABLE IF NOT EXISTS a2a_outbox_events (
    id              VARCHAR(64) PRIMARY KEY DEFAULT gen_random_uuid()::text,
    task_id         VARCHAR(64) NOT NULL REFERENCES a2a_tasks(id) ON DELETE CASCADE,
    event_type      VARCHAR(64) NOT NULL,
    target_url      TEXT        NOT NULL,
    payload_json    TEXT        NOT NULL,
    status          VARCHAR(32) NOT NULL DEFAULT 'pending',
    attempt_count   INTEGER     NOT NULL DEFAULT 0,
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_a2a_outbox_pending ON a2a_outbox_events(status, next_attempt_at) WHERE status = 'pending';

-- 12. A2A Push Notification Configurations
CREATE TABLE IF NOT EXISTS a2a_push_notification_configs (
    id         VARCHAR(64) PRIMARY KEY DEFAULT gen_random_uuid()::text,
    task_id    VARCHAR(64) NOT NULL REFERENCES a2a_tasks(id) ON DELETE CASCADE,
    target_url TEXT        NOT NULL,
    auth_token TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_a2a_push_configs_task ON a2a_push_notification_configs(task_id);
