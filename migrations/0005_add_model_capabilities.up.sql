-- Migration 0005: Add persistent tri-state capabilities to global_models and pricing provenance to model_pricing_history

ALTER TABLE global_models 
    ADD COLUMN IF NOT EXISTS capabilities JSONB NOT NULL DEFAULT '{}'::jsonb;

ALTER TABLE model_pricing_history 
    ADD COLUMN IF NOT EXISTS pricing_status VARCHAR(32) NOT NULL DEFAULT 'unknown',
    ADD COLUMN IF NOT EXISTS pricing_provenance_source VARCHAR(255);
