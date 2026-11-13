ALTER TABLE global_models
    ADD COLUMN IF NOT EXISTS cache_write_cost_micros_per_1m BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS supported_operations JSONB NOT NULL DEFAULT '[]'::jsonb;
