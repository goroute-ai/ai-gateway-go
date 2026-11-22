-- -----------------------------------------------------------------------------
-- Migration 0037: Prune unsupported providers, rerank columns, Azure credential
-- columns, and cloud guardrail definitions for the spec-first 4-provider release
-- (openai, anthropic, groq, openrouter).
-- -----------------------------------------------------------------------------

DELETE FROM model_deployments
WHERE global_model_id IN (
    SELECT id FROM global_models WHERE provider NOT IN ('openai', 'anthropic', 'groq', 'openrouter')
)
OR credential_id IN (
    SELECT id FROM provider_credentials WHERE provider NOT IN ('openai', 'anthropic', 'groq', 'openrouter')
);

DELETE FROM org_model_policies
WHERE global_model_id IN (
    SELECT id FROM global_models WHERE provider NOT IN ('openai', 'anthropic', 'groq', 'openrouter')
);

DELETE FROM model_pricing_history
WHERE global_model_id IN (
    SELECT id FROM global_models WHERE provider NOT IN ('openai', 'anthropic', 'groq', 'openrouter')
);

DELETE FROM global_models
WHERE provider NOT IN ('openai', 'anthropic', 'groq', 'openrouter');

DELETE FROM org_provider_subscriptions
WHERE provider NOT IN ('openai', 'anthropic', 'groq', 'openrouter');

DELETE FROM provider_credentials
WHERE provider NOT IN ('openai', 'anthropic', 'groq', 'openrouter');

DELETE FROM guardrail_definitions
WHERE provider IN ('bedrock', 'azure/prompt_shield', 'azure/text_moderations', 'model_armor');

ALTER TABLE provider_credentials
    DROP COLUMN IF EXISTS azure_deployment_name,
    DROP COLUMN IF EXISTS api_version;

ALTER TABLE global_models
    DROP COLUMN IF EXISTS rerank_cost_micros_per_search_unit;

INSERT INTO global_models (
    id, provider, model_name, display_name, max_input_tokens, max_output_tokens,
    supports_streaming, supports_tools, supports_vision, supports_reasoning, supports_embeddings,
    input_cost_micros_per_1m, output_cost_micros_per_1m, pricing_version, pricing_status,
    pricing_provenance_source, pricing_effective_date, lifecycle_status, capabilities, supported_operations, supports_inference
) VALUES
    (
        'groq/llama-3.1-8b-instant', 'groq', 'llama-3.1-8b-instant', 'Groq Llama 3.1 8B Instant',
        131072, 8192, TRUE, TRUE, FALSE, FALSE, FALSE,
        50000, 80000, 1, 'verified', 'official-vendor-pricing-2025', '2025-05-01', 'active',
        '{"streaming":"supported","tools":"supported"}'::jsonb, '["chat","completion"]'::jsonb, TRUE
    ),
    (
        'openrouter/openai/gpt-4o-mini', 'openrouter', 'openai/gpt-4o-mini', 'OpenRouter OpenAI GPT-4o Mini',
        128000, 16384, TRUE, TRUE, TRUE, FALSE, FALSE,
        150000, 600000, 1, 'verified', 'official-vendor-pricing-2025', '2025-05-01', 'active',
        '{"streaming":"supported","tools":"supported","vision":"supported"}'::jsonb, '["chat"]'::jsonb, TRUE
    )
ON CONFLICT (id) DO NOTHING;
