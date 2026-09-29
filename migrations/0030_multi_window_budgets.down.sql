ALTER TABLE virtual_keys
    DROP COLUMN IF EXISTS temp_budget_expires_at,
    DROP COLUMN IF EXISTS temp_budget_increase_micros;

ALTER TABLE users
    DROP COLUMN IF EXISTS temp_budget_expires_at,
    DROP COLUMN IF EXISTS temp_budget_increase_micros;

ALTER TABLE teams
    DROP COLUMN IF EXISTS temp_budget_expires_at,
    DROP COLUMN IF EXISTS temp_budget_increase_micros;

ALTER TABLE organizations
    DROP COLUMN IF EXISTS self_serve_budget_policy,
    DROP COLUMN IF EXISTS temp_budget_expires_at,
    DROP COLUMN IF EXISTS temp_budget_increase_micros;

DROP INDEX IF EXISTS idx_budget_window_limits_reset_at;
DROP INDEX IF EXISTS idx_budget_window_limits_org_scope;
DROP TABLE IF EXISTS budget_window_limits;
