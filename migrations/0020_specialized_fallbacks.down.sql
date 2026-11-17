ALTER TABLE model_groups
    DROP COLUMN IF EXISTS cooldown_policy,
    DROP COLUMN IF EXISTS retry_policy,
    DROP COLUMN IF EXISTS fallback_targets,
    DROP COLUMN IF EXISTS content_policy_fallbacks,
    DROP COLUMN IF EXISTS context_window_fallbacks;
