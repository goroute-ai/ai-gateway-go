ALTER TABLE guardrail_policies
    DROP COLUMN IF EXISTS scan_all_roles,
    DROP COLUMN IF EXISTS mode;
