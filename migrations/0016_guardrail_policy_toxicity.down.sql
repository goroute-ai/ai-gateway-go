ALTER TABLE guardrail_policies
    DROP COLUMN IF EXISTS content_exceptions,
    DROP COLUMN IF EXISTS enabled_content_categories,
    DROP COLUMN IF EXISTS toxicity_threshold,
    DROP COLUMN IF EXISTS toxicity_action,
    DROP COLUMN IF EXISTS enable_toxicity_filter;
