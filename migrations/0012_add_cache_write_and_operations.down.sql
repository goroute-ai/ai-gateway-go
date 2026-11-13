ALTER TABLE global_models
    DROP COLUMN IF EXISTS supported_operations,
    DROP COLUMN IF EXISTS cache_write_cost_micros_per_1m;
