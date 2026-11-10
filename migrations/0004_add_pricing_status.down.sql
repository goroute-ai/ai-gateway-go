-- -----------------------------------------------------------------------------
-- Migration 0004 Rollback: Drop pricing_status and provenance tracking
-- Warning: This rollback is lossy for pricing verification metadata and spend provenance.
-- -----------------------------------------------------------------------------

DROP INDEX IF EXISTS idx_spend_logs_pricing_status;
DROP INDEX IF EXISTS idx_global_models_pricing_status;

ALTER TABLE spend_logs
    DROP COLUMN IF EXISTS pricing_status;

ALTER TABLE global_models
    DROP COLUMN IF EXISTS pricing_effective_date,
    DROP COLUMN IF EXISTS pricing_provenance_source,
    DROP COLUMN IF EXISTS pricing_status;
