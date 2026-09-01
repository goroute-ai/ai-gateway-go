ALTER TABLE global_models
    DROP COLUMN IF EXISTS quality_tier;

ALTER TABLE model_deployments
    DROP COLUMN IF EXISTS budget_reset_period,
    DROP COLUMN IF EXISTS max_budget_micros,
    DROP COLUMN IF EXISTS tags;
