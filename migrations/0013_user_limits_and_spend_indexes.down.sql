DROP INDEX IF EXISTS idx_spend_logs_org_user;
DROP INDEX IF EXISTS idx_spend_logs_org_team;

ALTER TABLE users
    DROP COLUMN IF EXISTS budget_reset_at,
    DROP COLUMN IF EXISTS budget_reset_period,
    DROP COLUMN IF EXISTS spent_micros,
    DROP COLUMN IF EXISTS max_budget_micros,
    DROP COLUMN IF EXISTS max_concurrent_requests,
    DROP COLUMN IF EXISTS tpm_limit,
    DROP COLUMN IF EXISTS rpm_limit;
