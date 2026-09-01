-- Phase 5: Guardrail Usage Metrics & Spend Attribution
-- Adds daily guardrail evaluation metrics, micro-dollar usage unit rollups, and spend log attribution.

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

CREATE INDEX IF NOT EXISTS idx_daily_guardrail_metrics_org_date
    ON daily_guardrail_metrics (org_id, date DESC);

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

CREATE INDEX IF NOT EXISTS idx_daily_guardrail_usage_units_org_date
    ON daily_guardrail_usage_units (org_id, date DESC);

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

CREATE INDEX IF NOT EXISTS idx_spend_log_guardrails_org_spend_log
    ON spend_log_guardrails (org_id, spend_log_id);

CREATE INDEX IF NOT EXISTS idx_spend_log_guardrails_org_created
    ON spend_log_guardrails (org_id, created_at DESC);
