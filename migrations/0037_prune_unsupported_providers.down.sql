ALTER TABLE global_models
    ADD COLUMN IF NOT EXISTS rerank_cost_micros_per_search_unit BIGINT NOT NULL DEFAULT 0;

ALTER TABLE provider_credentials
    ADD COLUMN IF NOT EXISTS azure_deployment_name VARCHAR(255),
    ADD COLUMN IF NOT EXISTS api_version VARCHAR(64);
