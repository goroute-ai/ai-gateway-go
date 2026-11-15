ALTER TABLE guardrail_policies
    ADD COLUMN IF NOT EXISTS enable_toxicity_filter BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS toxicity_action VARCHAR(32) NOT NULL DEFAULT 'block',
    ADD COLUMN IF NOT EXISTS toxicity_threshold VARCHAR(32) NOT NULL DEFAULT 'medium',
    ADD COLUMN IF NOT EXISTS enabled_content_categories TEXT[] NOT NULL DEFAULT '{}',
    ADD COLUMN IF NOT EXISTS content_exceptions TEXT[] NOT NULL DEFAULT '{}';
