-- =============================================================================
-- Migration 0036: Production Routing, Capacity, Quota & Guardrail Hardening
-- =============================================================================

ALTER TABLE model_deployments
    ADD COLUMN IF NOT EXISTS max_parallel_requests INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS itpm_capacity         INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS otpm_capacity         INTEGER NOT NULL DEFAULT 0;

ALTER TABLE model_groups
    ADD COLUMN IF NOT EXISTS drop_unsupported_params BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS disable_cooldowns       BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS saturation_fallbacks    JSONB   NOT NULL DEFAULT '[]'::jsonb;

ALTER TABLE quota_policies
    ADD COLUMN IF NOT EXISTS rpd_limit BIGINT NOT NULL DEFAULT 0;

ALTER TABLE virtual_keys
    ADD COLUMN IF NOT EXISTS min_priority_rank    INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS allowed_routing_tags TEXT[]  NOT NULL DEFAULT '{}';

ALTER TABLE teams
    ADD COLUMN IF NOT EXISTS min_priority_rank    INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS allowed_routing_tags TEXT[]  NOT NULL DEFAULT '{}';

ALTER TABLE guardrail_policies
    ADD COLUMN IF NOT EXISTS sensitive_route_target TEXT NOT NULL DEFAULT '';

ALTER TABLE guardrail_definitions
    ADD COLUMN IF NOT EXISTS sensitive_route_target TEXT NOT NULL DEFAULT '';
