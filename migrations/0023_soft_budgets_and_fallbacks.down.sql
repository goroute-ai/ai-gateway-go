ALTER TABLE virtual_keys
    DROP COLUMN IF EXISTS budget_fallbacks,
    DROP COLUMN IF EXISTS throttle_on_budget_exceeded,
    DROP COLUMN IF EXISTS soft_budget_micros;

ALTER TABLE users
    DROP COLUMN IF EXISTS budget_fallbacks,
    DROP COLUMN IF EXISTS throttle_on_budget_exceeded,
    DROP COLUMN IF EXISTS soft_budget_micros;

ALTER TABLE teams
    DROP COLUMN IF EXISTS budget_fallbacks,
    DROP COLUMN IF EXISTS throttle_on_budget_exceeded,
    DROP COLUMN IF EXISTS soft_budget_micros;

ALTER TABLE organizations
    DROP COLUMN IF EXISTS budget_fallbacks,
    DROP COLUMN IF EXISTS throttle_on_budget_exceeded,
    DROP COLUMN IF EXISTS soft_budget_micros;
