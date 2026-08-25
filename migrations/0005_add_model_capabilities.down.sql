-- Rollback Migration 0005

ALTER TABLE model_pricing_history 
    DROP COLUMN IF EXISTS pricing_provenance_source,
    DROP COLUMN IF EXISTS pricing_status;

ALTER TABLE global_models 
    DROP COLUMN IF EXISTS capabilities;
