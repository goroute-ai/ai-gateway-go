-- Migration 0043: Seed baseline Google Gemini inference and embedding models
-- Pricing uses exact integer micro-dollars per 1M tokens ($1.00 = 1,000,000 micros).

INSERT INTO global_models (
    id, provider, model_name, display_name, max_input_tokens, max_output_tokens,
    supports_streaming, supports_tools, supports_vision, supports_reasoning, supports_embeddings,
    input_cost_micros_per_1m, output_cost_micros_per_1m, cached_input_cost_micros_per_1m, reasoning_cost_micros_per_1m,
    pricing_version, pricing_status, pricing_provenance_source, pricing_effective_date,
    lifecycle_status, capabilities, supported_operations, supports_inference
) VALUES
    (
        'gemini/gemini-2.5-flash', 'gemini', 'gemini-2.5-flash', 'Google Gemini 2.5 Flash',
        1048576, 65536, TRUE, TRUE, TRUE, TRUE, FALSE,
        300000, 2500000, 30000, 2500000,
        1, 'verified', 'official-vendor-pricing-2025', '2025-05-01',
        'active', '{"streaming":"supported","tools":"supported","vision":"supported","reasoning":"supported","structured_outputs":"supported"}'::jsonb, '["chat"]'::jsonb, TRUE
    ),
    (
        'gemini/gemini-2.5-pro', 'gemini', 'gemini-2.5-pro', 'Google Gemini 2.5 Pro',
        1048576, 65536, TRUE, TRUE, TRUE, TRUE, FALSE,
        1250000, 10000000, 125000, 10000000,
        1, 'verified', 'official-vendor-pricing-2025', '2025-05-01',
        'active', '{"streaming":"supported","tools":"supported","vision":"supported","reasoning":"supported","structured_outputs":"supported"}'::jsonb, '["chat"]'::jsonb, TRUE
    ),
    (
        'gemini/gemini-2.5-flash-lite', 'gemini', 'gemini-2.5-flash-lite', 'Google Gemini 2.5 Flash-Lite',
        1048576, 65536, TRUE, TRUE, TRUE, TRUE, FALSE,
        100000, 400000, 10000, 400000,
        1, 'verified', 'official-vendor-pricing-2025', '2025-05-01',
        'active', '{"streaming":"supported","tools":"supported","vision":"supported","reasoning":"supported","structured_outputs":"supported"}'::jsonb, '["chat"]'::jsonb, TRUE
    ),
    (
        'gemini/gemini-embedding-001', 'gemini', 'gemini-embedding-001', 'Google Gemini Embedding 001',
        2048, 3072, FALSE, FALSE, FALSE, FALSE, TRUE,
        150000, 0, 0, 0,
        1, 'verified', 'official-vendor-pricing-2025', '2025-05-01',
        'active', '{"embeddings":"supported"}'::jsonb, '["embedding"]'::jsonb, TRUE
    )
ON CONFLICT (id) DO NOTHING;
