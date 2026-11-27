-- =============================================================================
-- Rollback Migration 0044: Restore Extended Guardrail Tables & Columns
-- =============================================================================

DROP INDEX IF EXISTS idx_guardrail_defs_org_enabled;

ALTER TABLE guardrail_definitions
    ADD COLUMN IF NOT EXISTS stream_scope           JSONB        NOT NULL DEFAULT '{}'::jsonb,
    ADD COLUMN IF NOT EXISTS mode_rule              JSONB        NOT NULL DEFAULT '{}'::jsonb,
    ADD COLUMN IF NOT EXISTS default_on             BOOLEAN      NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS enabled_roles          JSONB        NOT NULL DEFAULT '[]'::jsonb,
    ADD COLUMN IF NOT EXISTS status                 VARCHAR(32)  NOT NULL DEFAULT 'active',
    ADD COLUMN IF NOT EXISTS guardrail_info         JSONB        NOT NULL DEFAULT '{}'::jsonb,
    ADD COLUMN IF NOT EXISTS weight                 INTEGER      NOT NULL DEFAULT 1,
    ADD COLUMN IF NOT EXISTS sensitive_route_target TEXT         NOT NULL DEFAULT '';

DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'guardrail_definitions' AND column_name = 'enabled'
    ) THEN
        EXECUTE 'UPDATE guardrail_definitions SET status = CASE WHEN enabled THEN ''active'' ELSE ''rejected'' END';
    END IF;
END $$;

ALTER TABLE guardrail_definitions
    DROP COLUMN IF EXISTS enabled;

CREATE INDEX IF NOT EXISTS idx_guardrail_defs_org_status
    ON guardrail_definitions(org_id, status);

ALTER TABLE guardrail_policies
    ADD COLUMN IF NOT EXISTS sensitive_route_target TEXT NOT NULL DEFAULT '',
    DROP COLUMN IF EXISTS blocked_patterns;

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

CREATE INDEX IF NOT EXISTS idx_guardrail_bindings_org ON guardrail_bindings(org_id);
CREATE INDEX IF NOT EXISTS idx_guardrail_bindings_guardrail ON guardrail_bindings(guardrail_id);
CREATE INDEX IF NOT EXISTS idx_guardrail_bindings_org_team ON guardrail_bindings(org_id, team_id);
CREATE INDEX IF NOT EXISTS idx_guardrail_bindings_org_key ON guardrail_bindings(org_id, virtual_key_id);
CREATE INDEX IF NOT EXISTS idx_guardrail_bindings_org_model_group ON guardrail_bindings(org_id, model_group_id);
CREATE INDEX IF NOT EXISTS idx_guardrail_bindings_org_tag ON guardrail_bindings(org_id, tag);
CREATE INDEX IF NOT EXISTS idx_guardrail_bindings_org_name ON guardrail_bindings(org_id, guardrail_name);

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

CREATE INDEX IF NOT EXISTS idx_tool_policies_org ON tool_policies(org_id);
CREATE INDEX IF NOT EXISTS idx_tool_policies_org_team ON tool_policies(org_id, team_id);
CREATE INDEX IF NOT EXISTS idx_tool_policies_org_key ON tool_policies(org_id, virtual_key_id);
CREATE INDEX IF NOT EXISTS idx_tool_policies_org_tool ON tool_policies(org_id, tool_name);

CREATE TABLE IF NOT EXISTS daily_guardrail_metrics (
    org_id TEXT NOT NULL,
    guardrail_id TEXT NOT NULL,
    guardrail_name TEXT NOT NULL DEFAULT '',
    date DATE NOT NULL,
    evaluations BIGINT NOT NULL DEFAULT 0,
    blocks BIGINT NOT NULL DEFAULT 0,
    redactions BIGINT NOT NULL DEFAULT 0,
    flags BIGINT NOT NULL DEFAULT 0,
    errors BIGINT NOT NULL DEFAULT 0,
    latency_sum_ms BIGINT NOT NULL DEFAULT 0,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (org_id, guardrail_id, date)
);

CREATE INDEX IF NOT EXISTS idx_daily_guardrail_metrics_org_date ON daily_guardrail_metrics (org_id, date DESC);

CREATE TABLE IF NOT EXISTS daily_guardrail_usage_units (
    org_id TEXT NOT NULL,
    guardrail_id TEXT NOT NULL,
    date DATE NOT NULL,
    team_id TEXT NOT NULL DEFAULT '',
    virtual_key_id TEXT NOT NULL DEFAULT '',
    usage_unit TEXT NOT NULL DEFAULT 'call',
    units BIGINT NOT NULL DEFAULT 0,
    cost_micros BIGINT NOT NULL DEFAULT 0,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (org_id, guardrail_id, date, team_id, virtual_key_id, usage_unit)
);

CREATE INDEX IF NOT EXISTS idx_daily_guardrail_usage_units_org_date ON daily_guardrail_usage_units (org_id, date DESC);

CREATE TABLE IF NOT EXISTS spend_log_guardrails (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL,
    spend_log_id TEXT NOT NULL,
    guardrail_id TEXT NOT NULL,
    guardrail_name TEXT NOT NULL DEFAULT '',
    hook TEXT NOT NULL,
    decision TEXT NOT NULL,
    units BIGINT NOT NULL DEFAULT 0,
    cost_micros BIGINT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_spend_log_guardrails_org_spend_log ON spend_log_guardrails (org_id, spend_log_id);
CREATE INDEX IF NOT EXISTS idx_spend_log_guardrails_org_created ON spend_log_guardrails (org_id, created_at DESC);
