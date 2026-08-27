CREATE TABLE IF NOT EXISTS budget_reset_outbox (
    id UUID PRIMARY KEY,
    scope TEXT NOT NULL CHECK (scope IN ('org', 'team', 'key')),
    entity_id TEXT NOT NULL,
    org_id TEXT NOT NULL,
    reset_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    delivered_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_budget_reset_outbox_pending
    ON budget_reset_outbox (created_at)
    WHERE delivered_at IS NULL;
