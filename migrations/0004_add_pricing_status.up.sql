-- -----------------------------------------------------------------------------
-- Migration 0004: Add pricing_status and provenance tracking to global_models and spend_logs,
-- and add Azure configuration fields to provider_credentials
-- -----------------------------------------------------------------------------

ALTER TABLE global_models
    ADD COLUMN IF NOT EXISTS pricing_status VARCHAR(32) NOT NULL DEFAULT 'unknown',
    ADD COLUMN IF NOT EXISTS pricing_provenance_source VARCHAR(255),
    ADD COLUMN IF NOT EXISTS pricing_effective_date VARCHAR(64);

ALTER TABLE provider_credentials
    ADD COLUMN IF NOT EXISTS azure_deployment_name VARCHAR(255),
    ADD COLUMN IF NOT EXISTS api_version VARCHAR(64);

ALTER TABLE spend_logs
    ADD COLUMN IF NOT EXISTS pricing_status VARCHAR(32) NOT NULL DEFAULT 'unrecorded',
    ADD COLUMN IF NOT EXISTS pricing_provenance_source VARCHAR(255);

-- Backfill ONLY the 15 explicitly audited seed models with known verified sources
UPDATE global_models
SET pricing_status = 'verified',
    pricing_provenance_source = 'official-vendor-pricing-2025',
    pricing_effective_date = '2025-05-01'
WHERE id IN (
    'openai/gpt-4.1',
    'openai/gpt-4.1-mini',
    'openai/o3-mini',
    'openai/text-embedding-3-small',
    'anthropic/claude-sonnet-4-20250514',
    'anthropic/claude-3-5-haiku-latest',
    'anthropic/claude-haiku-4-5-20251001',
    'gemini/gemini-2.5-pro',
    'gemini/gemini-2.5-flash',
    'gemini/gemini-2.5-flash-lite',
    'gemini/text-embedding-004',
    'mistral/mistral-large-latest',
    'mistral/mistral-embed',
    'ollama/llama3.3',
    'ollama/llama3.2:1b'
);

CREATE INDEX IF NOT EXISTS idx_global_models_pricing_status ON global_models(pricing_status);
CREATE INDEX IF NOT EXISTS idx_spend_logs_pricing_status ON spend_logs(pricing_status);
