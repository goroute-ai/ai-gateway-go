ALTER TABLE users
    ADD COLUMN IF NOT EXISTS rpm_limit INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS tpm_limit INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS max_concurrent_requests INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS max_budget_micros BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS spent_micros BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS budget_reset_period VARCHAR(32) NOT NULL DEFAULT 'monthly',
    ADD COLUMN IF NOT EXISTS budget_reset_at TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS idx_spend_logs_org_team ON spend_logs(org_id, team_id);
CREATE INDEX IF NOT EXISTS idx_spend_logs_org_user ON spend_logs(org_id, user_id);
