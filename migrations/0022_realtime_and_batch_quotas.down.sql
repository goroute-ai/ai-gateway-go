ALTER TABLE virtual_keys
    DROP COLUMN IF EXISTS batch_enqueued_token_limit;

ALTER TABLE users
    DROP COLUMN IF EXISTS batch_enqueued_token_limit;

ALTER TABLE teams
    DROP COLUMN IF EXISTS batch_enqueued_token_limit;

ALTER TABLE organizations
    DROP COLUMN IF EXISTS batch_enqueued_token_limit;

ALTER TABLE batches
    DROP COLUMN IF EXISTS reserved_cost_micros,
    DROP COLUMN IF EXISTS estimated_tokens;
