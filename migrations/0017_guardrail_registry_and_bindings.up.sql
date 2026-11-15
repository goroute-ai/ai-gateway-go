-- =============================================================================
-- Migration 0017: Named Guardrail Definitions Registry & Hierarchical Bindings
-- =============================================================================

CREATE TABLE IF NOT EXISTS guardrail_definitions (
    id                VARCHAR(64)  PRIMARY KEY DEFAULT gen_random_uuid()::text,
    org_id            VARCHAR(64)  NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name              VARCHAR(255) NOT NULL,
    provider          VARCHAR(64)  NOT NULL,
    hooks             JSONB        NOT NULL DEFAULT '[]'::jsonb,
    stream_scope      JSONB        NOT NULL DEFAULT '{}'::jsonb,
    mode_rule         JSONB        NOT NULL DEFAULT '{}'::jsonb,
    default_on        BOOLEAN      NOT NULL DEFAULT FALSE,
    enabled_roles     JSONB        NOT NULL DEFAULT '[]'::jsonb,
    timeout_ms        INTEGER      NOT NULL DEFAULT 0,
    fail_open         BOOLEAN      NOT NULL DEFAULT FALSE,
    precedence        INTEGER      NOT NULL DEFAULT 0,
    config            JSONB        NOT NULL DEFAULT '{}'::jsonb,
    encrypted_secrets TEXT         NOT NULL DEFAULT '',
    encrypted_dek     TEXT         NOT NULL DEFAULT '',
    status            VARCHAR(32)  NOT NULL DEFAULT 'active',
    guardrail_info    JSONB        NOT NULL DEFAULT '{}'::jsonb,
    weight            INTEGER      NOT NULL DEFAULT 1,
    created_at        TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at        TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_guardrail_defs_org_status
    ON guardrail_definitions(org_id, status);
CREATE INDEX IF NOT EXISTS idx_guardrail_defs_org_name
    ON guardrail_definitions(org_id, name);
CREATE INDEX IF NOT EXISTS idx_guardrail_defs_org_precedence
    ON guardrail_definitions(org_id, precedence ASC, created_at ASC);

CREATE TABLE IF NOT EXISTS guardrail_bindings (
    id             VARCHAR(64)  PRIMARY KEY DEFAULT gen_random_uuid()::text,
    org_id         VARCHAR(64)  NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    guardrail_id   VARCHAR(64)  NOT NULL REFERENCES guardrail_definitions(id) ON DELETE CASCADE,
    guardrail_name VARCHAR(255) NOT NULL,
    team_id        VARCHAR(64)  DEFAULT NULL,
    virtual_key_id VARCHAR(64)  DEFAULT NULL,
    end_user_id    VARCHAR(255) DEFAULT NULL,
    model_group_id VARCHAR(64)  DEFAULT NULL,
    tag            VARCHAR(255) DEFAULT NULL,
    overrides      JSONB        NOT NULL DEFAULT '{}'::jsonb,
    is_locked      BOOLEAN      NOT NULL DEFAULT FALSE,
    created_at     TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at     TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_guardrail_bindings_org
    ON guardrail_bindings(org_id);
CREATE INDEX IF NOT EXISTS idx_guardrail_bindings_guardrail
    ON guardrail_bindings(guardrail_id);
CREATE INDEX IF NOT EXISTS idx_guardrail_bindings_org_team
    ON guardrail_bindings(org_id, team_id);
CREATE INDEX IF NOT EXISTS idx_guardrail_bindings_org_key
    ON guardrail_bindings(org_id, virtual_key_id);
CREATE INDEX IF NOT EXISTS idx_guardrail_bindings_org_model_group
    ON guardrail_bindings(org_id, model_group_id);
CREATE INDEX IF NOT EXISTS idx_guardrail_bindings_org_tag
    ON guardrail_bindings(org_id, tag);
CREATE INDEX IF NOT EXISTS idx_guardrail_bindings_org_name
    ON guardrail_bindings(org_id, guardrail_name);
