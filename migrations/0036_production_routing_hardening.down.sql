-- =============================================================================
-- Rollback Migration 0036: Production Routing, Capacity, Quota & Guardrail Hardening
-- =============================================================================

ALTER TABLE guardrail_definitions
    DROP COLUMN IF EXISTS sensitive_route_target;

ALTER TABLE guardrail_policies
    DROP COLUMN IF EXISTS sensitive_route_target;

ALTER TABLE teams
    DROP COLUMN IF EXISTS allowed_routing_tags,
    DROP COLUMN IF EXISTS min_priority_rank;

ALTER TABLE virtual_keys
    DROP COLUMN IF EXISTS allowed_routing_tags,
    DROP COLUMN IF EXISTS min_priority_rank;

ALTER TABLE quota_policies
    DROP COLUMN IF EXISTS rpd_limit;

ALTER TABLE model_groups
    DROP COLUMN IF EXISTS saturation_fallbacks,
    DROP COLUMN IF EXISTS disable_cooldowns,
    DROP COLUMN IF EXISTS drop_unsupported_params;

ALTER TABLE model_deployments
    DROP COLUMN IF EXISTS otpm_capacity,
    DROP COLUMN IF EXISTS itpm_capacity,
    DROP COLUMN IF EXISTS max_parallel_requests;
