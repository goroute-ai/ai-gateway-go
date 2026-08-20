-- =============================================================================
-- Enterprise AI Gateway (Pure Go) — Complete PostgreSQL 16+ Schema
-- =============================================================================

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- -----------------------------------------------------------------------------
-- LAYER 1: Global Model Catalogue (Populated by Automated Discovery Service)
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS global_models (
    id                              VARCHAR(128) PRIMARY KEY, -- e.g. "openai/gpt-4.1", "anthropic/claude-sonnet-4-20250514"
    provider                        VARCHAR(32)  NOT NULL,    -- "openai", "anthropic", "gemini", "mistral", "ollama"
    model_name                      VARCHAR(128) NOT NULL,    -- Upstream model identifier e.g. "gpt-4.1"
    display_name                    VARCHAR(255) NOT NULL,
    max_input_tokens                INTEGER      NOT NULL DEFAULT 128000,
    max_output_tokens               INTEGER      NOT NULL DEFAULT 16384,
    supports_streaming              BOOLEAN      NOT NULL DEFAULT TRUE,
    supports_tools                  BOOLEAN      NOT NULL DEFAULT TRUE,
    supports_vision                 BOOLEAN      NOT NULL DEFAULT FALSE,
    supports_reasoning              BOOLEAN      NOT NULL DEFAULT FALSE,
    supports_embeddings             BOOLEAN      NOT NULL DEFAULT FALSE,
    input_cost_micros_per_1m        BIGINT       NOT NULL DEFAULT 0, -- Micro-USD ($1e-6) per 1M input tokens
    output_cost_micros_per_1m       BIGINT       NOT NULL DEFAULT 0, -- Micro-USD ($1e-6) per 1M output tokens
    cached_input_cost_micros_per_1m BIGINT       NOT NULL DEFAULT 0, -- Micro-USD ($1e-6) per 1M cached input tokens
    reasoning_cost_micros_per_1m    BIGINT       NOT NULL DEFAULT 0, -- Micro-USD ($1e-6) per 1M reasoning tokens
    lifecycle_status                VARCHAR(32)  NOT NULL DEFAULT 'active', -- 'discovered', 'active', 'preview', 'deprecated', 'retired'
    deprecation_date                TIMESTAMPTZ,
    metadata                        JSONB        NOT NULL DEFAULT '{}'::jsonb,
    discovered_at                   TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at                      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    UNIQUE (provider, model_name)
);

CREATE INDEX IF NOT EXISTS idx_global_models_provider ON global_models(provider);
CREATE INDEX IF NOT EXISTS idx_global_models_status ON global_models(lifecycle_status);

-- -----------------------------------------------------------------------------
-- MULTI-TENANT ROOT: Organizations
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS organizations (
    id                  VARCHAR(64)  PRIMARY KEY DEFAULT gen_random_uuid()::text,
    name                VARCHAR(255) NOT NULL,
    slug                VARCHAR(128) NOT NULL UNIQUE,
    max_budget_micros   BIGINT       NOT NULL DEFAULT 0, -- 0 = unlimited
    spent_micros        BIGINT       NOT NULL DEFAULT 0,
    budget_reset_period VARCHAR(32)  NOT NULL DEFAULT 'monthly', -- 'daily', 'monthly', 'never'
    budget_reset_at     TIMESTAMPTZ,
    rpm_limit           INTEGER      NOT NULL DEFAULT 0, -- 0 = unlimited
    tpm_limit           INTEGER      NOT NULL DEFAULT 0,
    is_active           BOOLEAN      NOT NULL DEFAULT TRUE,
    metadata            JSONB        NOT NULL DEFAULT '{}'::jsonb,
    created_at          TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

-- -----------------------------------------------------------------------------
-- LAYER 2: Organization Provider Subscriptions
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS org_provider_subscriptions (
    org_id          VARCHAR(64) NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    provider        VARCHAR(32) NOT NULL, -- 'openai', 'anthropic', 'gemini', 'mistral', 'ollama'
    is_enabled      BOOLEAN     NOT NULL DEFAULT TRUE,
    auto_enable_new BOOLEAN     NOT NULL DEFAULT FALSE,
    subscribed_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (org_id, provider)
);

-- -----------------------------------------------------------------------------
-- LAYER 3: Organization Model Availability Policies
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS org_model_policies (
    org_id          VARCHAR(64)  NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    global_model_id VARCHAR(128) NOT NULL REFERENCES global_models(id) ON DELETE CASCADE,
    is_enabled      BOOLEAN      NOT NULL DEFAULT TRUE,
    approved_by     VARCHAR(255) NOT NULL DEFAULT 'system',
    approved_at     TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    PRIMARY KEY (org_id, global_model_id)
);

-- -----------------------------------------------------------------------------
-- MULTI-TENANT HIERARCHY: Teams & Users
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS teams (
    id                  VARCHAR(64)  PRIMARY KEY DEFAULT gen_random_uuid()::text,
    org_id              VARCHAR(64)  NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name                VARCHAR(255) NOT NULL,
    max_budget_micros   BIGINT       NOT NULL DEFAULT 0,
    spent_micros        BIGINT       NOT NULL DEFAULT 0,
    budget_reset_period VARCHAR(32)  NOT NULL DEFAULT 'monthly',
    budget_reset_at     TIMESTAMPTZ,
    rpm_limit           INTEGER      NOT NULL DEFAULT 0,
    tpm_limit           INTEGER      NOT NULL DEFAULT 0,
    allowed_models      TEXT[]       NOT NULL DEFAULT '{}', -- Empty = inherit all org enabled models
    is_active           BOOLEAN      NOT NULL DEFAULT TRUE,
    created_at          TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    UNIQUE (org_id, name)
);

CREATE INDEX IF NOT EXISTS idx_teams_org_id ON teams(org_id);

CREATE TABLE IF NOT EXISTS users (
    id           VARCHAR(64)  PRIMARY KEY DEFAULT gen_random_uuid()::text,
    org_id       VARCHAR(64)  NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    team_id      VARCHAR(64)  REFERENCES teams(id) ON DELETE SET NULL,
    email        VARCHAR(255) NOT NULL UNIQUE,
    name         VARCHAR(255) NOT NULL,
    role         VARCHAR(32)  NOT NULL DEFAULT 'developer', -- 'org_admin', 'team_admin', 'developer', 'viewer'
    oidc_subject VARCHAR(255),
    is_active    BOOLEAN      NOT NULL DEFAULT TRUE,
    created_at   TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at   TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_users_org_team ON users(org_id, team_id);

-- -----------------------------------------------------------------------------
-- BOUNDARY 1 AUTH: Virtual API Keys (SHA-256 Hashed)
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS virtual_keys (
    id                      VARCHAR(64)  PRIMARY KEY DEFAULT gen_random_uuid()::text,
    key_prefix              VARCHAR(24)  NOT NULL,          -- e.g. "sk-gw-a1b2c3d4"
    key_hash                CHAR(64)     NOT NULL UNIQUE,   -- SHA-256 hex digest of full key
    name                    VARCHAR(255) NOT NULL,
    org_id                  VARCHAR(64)  NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    team_id                 VARCHAR(64)  REFERENCES teams(id) ON DELETE SET NULL,
    user_id                 VARCHAR(64)  REFERENCES users(id) ON DELETE SET NULL,
    role                    VARCHAR(32)  NOT NULL DEFAULT 'service_account',
    allowed_models          TEXT[]       NOT NULL DEFAULT '{}', -- Empty = inherit team/org models
    allowed_endpoints       TEXT[]       NOT NULL DEFAULT '{/v1/chat/completions,/v1/embeddings,/v1/models}',
    max_budget_micros       BIGINT       NOT NULL DEFAULT 0,
    spent_micros            BIGINT       NOT NULL DEFAULT 0,
    budget_reset_period     VARCHAR(32)  NOT NULL DEFAULT 'monthly',
    budget_reset_at         TIMESTAMPTZ,
    rpm_limit               INTEGER      NOT NULL DEFAULT 0,
    tpm_limit               INTEGER      NOT NULL DEFAULT 0,
    max_concurrent_requests INTEGER      NOT NULL DEFAULT 0,
    expires_at              TIMESTAMPTZ,
    is_active               BOOLEAN      NOT NULL DEFAULT TRUE,
    metadata                JSONB        NOT NULL DEFAULT '{}'::jsonb,
    created_at              TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at              TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_virtual_keys_org_team ON virtual_keys(org_id, team_id);
CREATE INDEX IF NOT EXISTS idx_virtual_keys_hash ON virtual_keys(key_hash);

-- -----------------------------------------------------------------------------
-- BOUNDARY 2 AUTH: Upstream Provider Credentials Vault (AES-256-GCM Envelope)
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS provider_credentials (
    id                VARCHAR(64)  PRIMARY KEY DEFAULT gen_random_uuid()::text,
    org_id            VARCHAR(64)  NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    provider          VARCHAR(32)  NOT NULL, -- 'openai', 'anthropic', 'gemini', 'mistral', 'ollama'
    name              VARCHAR(255) NOT NULL,
    base_url          VARCHAR(512) NOT NULL,
    encrypted_api_key BYTEA,
    data_nonce        BYTEA,
    encrypted_dek     BYTEA,
    dek_nonce         BYTEA,
    headers           JSONB        NOT NULL DEFAULT '{}'::jsonb,
    is_active         BOOLEAN      NOT NULL DEFAULT TRUE,
    created_at        TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at        TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    UNIQUE (org_id, name)
);

CREATE INDEX IF NOT EXISTS idx_provider_credentials_org ON provider_credentials(org_id, provider);

-- -----------------------------------------------------------------------------
-- LAYER 4: Model Groups & Physical Deployments (Routing & Load Balancing)
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS model_groups (
    id                 VARCHAR(64)  PRIMARY KEY DEFAULT gen_random_uuid()::text,
    org_id             VARCHAR(64)  NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    alias              VARCHAR(128) NOT NULL, -- e.g. 'gpt-4.1', 'fast', 'reasoning', 'auto'
    description         TEXT         NOT NULL DEFAULT '',
    routing_strategy   VARCHAR(64)  NOT NULL DEFAULT 'weighted-shuffle', -- 'weighted-shuffle', 'least-busy', 'latency-based', 'usage-based-headroom', 'lowest-cost'
    fallback_group_ids TEXT[]       NOT NULL DEFAULT '{}',
    max_retries        INTEGER      NOT NULL DEFAULT 2,
    cooldown_seconds   INTEGER      NOT NULL DEFAULT 60,
    failure_threshold  INTEGER      NOT NULL DEFAULT 3,
    is_active          BOOLEAN      NOT NULL DEFAULT TRUE,
    created_at         TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at         TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    UNIQUE (org_id, alias)
);

CREATE INDEX IF NOT EXISTS idx_model_groups_org_alias ON model_groups(org_id, alias);

CREATE TABLE IF NOT EXISTS model_deployments (
    id              VARCHAR(64)  PRIMARY KEY DEFAULT gen_random_uuid()::text,
    model_group_id  VARCHAR(64)  NOT NULL REFERENCES model_groups(id) ON DELETE CASCADE,
    global_model_id VARCHAR(128) NOT NULL REFERENCES global_models(id) ON DELETE RESTRICT,
    credential_id   VARCHAR(64)  NOT NULL REFERENCES provider_credentials(id) ON DELETE RESTRICT,
    deployment_name VARCHAR(255) NOT NULL,
    region          VARCHAR(64)  NOT NULL DEFAULT 'global',
    weight          INTEGER      NOT NULL DEFAULT 100,
    rpm_capacity    INTEGER      NOT NULL DEFAULT 1000,
    tpm_capacity    INTEGER      NOT NULL DEFAULT 1000000,
    timeout_ms      INTEGER      NOT NULL DEFAULT 60000,
    priority        INTEGER      NOT NULL DEFAULT 1,
    status          VARCHAR(32)  NOT NULL DEFAULT 'active', -- 'active', 'cooldown', 'disabled'
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_model_deployments_group ON model_deployments(model_group_id);

-- -----------------------------------------------------------------------------
-- FINOPS & OBSERVABILITY: Immutable Spend Logs & Audit Logs
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS spend_logs (
    id                  VARCHAR(64)  PRIMARY KEY DEFAULT gen_random_uuid()::text,
    request_id          VARCHAR(64)  NOT NULL,
    org_id              VARCHAR(64)  NOT NULL,
    team_id             VARCHAR(64),
    user_id             VARCHAR(64),
    virtual_key_id      VARCHAR(64),
    endpoint            VARCHAR(128) NOT NULL,
    requested_model     VARCHAR(128) NOT NULL,
    resolved_model      VARCHAR(128) NOT NULL,
    provider            VARCHAR(32)  NOT NULL,
    deployment_id       VARCHAR(64),
    prompt_tokens       INTEGER      NOT NULL DEFAULT 0,
    completion_tokens   INTEGER      NOT NULL DEFAULT 0,
    cached_tokens       INTEGER      NOT NULL DEFAULT 0,
    reasoning_tokens    INTEGER      NOT NULL DEFAULT 0,
    total_tokens        INTEGER      NOT NULL DEFAULT 0,
    cost_micros         BIGINT       NOT NULL DEFAULT 0,
    latency_ms          BIGINT       NOT NULL DEFAULT 0,
    ttft_ms             BIGINT       NOT NULL DEFAULT 0,
    status_code         INTEGER      NOT NULL DEFAULT 200,
    is_stream           BOOLEAN      NOT NULL DEFAULT FALSE,
    cache_hit           BOOLEAN      NOT NULL DEFAULT FALSE,
    fallback_attempted  BOOLEAN      NOT NULL DEFAULT FALSE,
    retry_count         INTEGER      NOT NULL DEFAULT 0,
    error_message       TEXT,
    created_at          TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_spend_logs_org_created ON spend_logs(org_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_spend_logs_key_created ON spend_logs(virtual_key_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_spend_logs_provider_model ON spend_logs(provider, resolved_model);

CREATE TABLE IF NOT EXISTS audit_logs (
    id          VARCHAR(64)  PRIMARY KEY DEFAULT gen_random_uuid()::text,
    org_id      VARCHAR(64),
    actor_id    VARCHAR(128) NOT NULL,
    action      VARCHAR(128) NOT NULL, -- e.g. 'virtual_key.created', 'virtual_key.revoked', 'model.discovered'
    resource    VARCHAR(128) NOT NULL,
    resource_id VARCHAR(128) NOT NULL,
    details     JSONB        NOT NULL DEFAULT '{}'::jsonb,
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_audit_logs_org_created ON audit_logs(org_id, created_at DESC);
