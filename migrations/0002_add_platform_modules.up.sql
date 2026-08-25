-- =============================================================================
-- Migration 0002: Add Cross-Cutting Platform Modules & Production Hardening
-- =============================================================================

-- 1. Versioned Model Pricing
ALTER TABLE global_models ADD COLUMN IF NOT EXISTS pricing_version INTEGER NOT NULL DEFAULT 1;

CREATE TABLE IF NOT EXISTS model_pricing_history (
    id                              VARCHAR(64)  PRIMARY KEY DEFAULT gen_random_uuid()::text,
    global_model_id                 VARCHAR(128) NOT NULL REFERENCES global_models(id) ON DELETE CASCADE,
    pricing_version                 INTEGER      NOT NULL,
    input_cost_micros_per_1m        BIGINT       NOT NULL DEFAULT 0,
    output_cost_micros_per_1m       BIGINT       NOT NULL DEFAULT 0,
    cached_input_cost_micros_per_1m BIGINT       NOT NULL DEFAULT 0,
    reasoning_cost_micros_per_1m    BIGINT       NOT NULL DEFAULT 0,
    changed_by                      VARCHAR(255) NOT NULL DEFAULT 'system',
    effective_from                  TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_model_pricing_hist_model ON model_pricing_history(global_model_id, pricing_version DESC);

-- 2. Provider Credential Lifecycle (Rotation, Expiration & Live Validation)
ALTER TABLE provider_credentials ADD COLUMN IF NOT EXISTS key_version INTEGER NOT NULL DEFAULT 1;
ALTER TABLE provider_credentials ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ;
ALTER TABLE provider_credentials ADD COLUMN IF NOT EXISTS last_rotated_at TIMESTAMPTZ;
ALTER TABLE provider_credentials ADD COLUMN IF NOT EXISTS last_validated_at TIMESTAMPTZ;

-- 3. Security Guardrail Policies
CREATE TABLE IF NOT EXISTS guardrail_policies (
    org_id                  VARCHAR(64)  PRIMARY KEY REFERENCES organizations(id) ON DELETE CASCADE,
    enable_prompt_injection BOOLEAN      NOT NULL DEFAULT FALSE,
    prompt_injection_action VARCHAR(32)  NOT NULL DEFAULT 'block',
    enable_pii_detection    BOOLEAN      NOT NULL DEFAULT FALSE,
    pii_action              VARCHAR(32)  NOT NULL DEFAULT 'redact',
    enable_secret_detection BOOLEAN      NOT NULL DEFAULT FALSE,
    secret_action           VARCHAR(32)  NOT NULL DEFAULT 'redact',
    blocked_keywords        TEXT[]       NOT NULL DEFAULT '{}',
    redact_output_pii       BOOLEAN      NOT NULL DEFAULT FALSE,
    updated_at              TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

-- 4. Spend Event Observability Tracing & Pricing Version Tracking
ALTER TABLE spend_logs ADD COLUMN IF NOT EXISTS pricing_version INTEGER NOT NULL DEFAULT 1;
ALTER TABLE spend_logs ADD COLUMN IF NOT EXISTS trace_id VARCHAR(64);
CREATE INDEX IF NOT EXISTS idx_spend_logs_trace_id ON spend_logs(trace_id);
