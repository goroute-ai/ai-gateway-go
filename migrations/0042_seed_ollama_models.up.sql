-- Migration 0042: Seed baseline Ollama local inference and embedding models
-- Self-hosted Ollama models default to 0 micro-dollars per 1M tokens unless overridden
-- with custom internal chargeback pricing via the Admin API or Operator Web UI.

INSERT INTO global_models (
    id, provider, model_name, display_name, max_input_tokens, max_output_tokens,
    supports_streaming, supports_tools, supports_vision, supports_reasoning, supports_embeddings,
    input_cost_micros_per_1m, output_cost_micros_per_1m, pricing_version, pricing_status,
    pricing_provenance_source, pricing_effective_date, lifecycle_status, capabilities, supported_operations, supports_inference
) VALUES
    (
        'ollama/qwen2.5:0.5b', 'ollama', 'qwen2.5:0.5b', 'Ollama Qwen 2.5 0.5B',
        32768, 8192, TRUE, TRUE, FALSE, FALSE, FALSE,
        0, 0, 1, 'verified', 'self-hosted-ollama-default', '2026-11-25', 'active',
        '{"streaming":"supported","tools":"supported","structured_outputs":"supported"}'::jsonb, '["chat","completion"]'::jsonb, TRUE
    ),
    (
        'ollama/all-minilm:latest', 'ollama', 'all-minilm:latest', 'Ollama All-MiniLM Embeddings',
        512, 384, FALSE, FALSE, FALSE, FALSE, TRUE,
        0, 0, 1, 'verified', 'self-hosted-ollama-default', '2026-11-25', 'active',
        '{"embeddings":"supported"}'::jsonb, '["embedding"]'::jsonb, TRUE
    )
ON CONFLICT (id) DO NOTHING;
