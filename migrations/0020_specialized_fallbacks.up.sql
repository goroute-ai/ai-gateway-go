ALTER TABLE model_groups
    ADD COLUMN IF NOT EXISTS context_window_fallbacks JSONB NOT NULL DEFAULT '[]'::jsonb,
    ADD COLUMN IF NOT EXISTS content_policy_fallbacks JSONB NOT NULL DEFAULT '[]'::jsonb,
    ADD COLUMN IF NOT EXISTS fallback_targets JSONB NOT NULL DEFAULT '[]'::jsonb,
    ADD COLUMN IF NOT EXISTS retry_policy JSONB NOT NULL DEFAULT '{}'::jsonb,
    ADD COLUMN IF NOT EXISTS cooldown_policy JSONB NOT NULL DEFAULT '{}'::jsonb;
