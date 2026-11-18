ALTER TABLE batches
    ADD COLUMN IF NOT EXISTS estimated_tokens BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS reserved_cost_micros BIGINT NOT NULL DEFAULT 0;

ALTER TABLE organizations
    ADD COLUMN IF NOT EXISTS batch_enqueued_token_limit BIGINT NOT NULL DEFAULT 0;

ALTER TABLE teams
    ADD COLUMN IF NOT EXISTS batch_enqueued_token_limit BIGINT NOT NULL DEFAULT 0;

ALTER TABLE users
    ADD COLUMN IF NOT EXISTS batch_enqueued_token_limit BIGINT NOT NULL DEFAULT 0;

ALTER TABLE virtual_keys
    ADD COLUMN IF NOT EXISTS batch_enqueued_token_limit BIGINT NOT NULL DEFAULT 0;
