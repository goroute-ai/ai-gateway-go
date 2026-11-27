-- =============================================================================
-- Migration 0044: Simplify Guardrails Schema to Standard Core Surface
-- =============================================================================

DROP TABLE IF EXISTS guardrail_bindings;
DROP TABLE IF EXISTS tool_policies;
DROP TABLE IF EXISTS daily_guardrail_metrics;
DROP TABLE IF EXISTS daily_guardrail_usage_units;
DROP TABLE IF EXISTS spend_log_guardrails;

ALTER TABLE guardrail_policies
    ADD COLUMN IF NOT EXISTS blocked_patterns TEXT[] NOT NULL DEFAULT '{}',
    DROP COLUMN IF EXISTS sensitive_route_target;

ALTER TABLE guardrail_definitions
    ADD COLUMN IF NOT EXISTS enabled BOOLEAN NOT NULL DEFAULT TRUE;

DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'guardrail_definitions' AND column_name = 'status'
    ) THEN
        EXECUTE 'UPDATE guardrail_definitions SET enabled = (status = ''active'')';
    END IF;
END $$;

DROP INDEX IF EXISTS idx_guardrail_defs_org_status;

ALTER TABLE guardrail_definitions
    DROP COLUMN IF EXISTS stream_scope,
    DROP COLUMN IF EXISTS mode_rule,
    DROP COLUMN IF EXISTS default_on,
    DROP COLUMN IF EXISTS enabled_roles,
    DROP COLUMN IF EXISTS status,
    DROP COLUMN IF EXISTS guardrail_info,
    DROP COLUMN IF EXISTS weight,
    DROP COLUMN IF EXISTS sensitive_route_target;

CREATE INDEX IF NOT EXISTS idx_guardrail_defs_org_enabled
    ON guardrail_definitions(org_id, enabled);
