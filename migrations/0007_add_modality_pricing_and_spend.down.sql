-- Migration 0007 Down: Rollback modality pricing, spend_logs additions, files and batches tables

DROP TABLE IF EXISTS batches;
DROP TABLE IF EXISTS files;

DROP INDEX IF EXISTS idx_spend_logs_org_modality_created;

ALTER TABLE spend_logs
    DROP COLUMN IF EXISTS modality,
    DROP COLUMN IF EXISTS modality_units;

ALTER TABLE global_models
    DROP COLUMN IF EXISTS rerank_cost_micros_per_search_unit,
    DROP COLUMN IF EXISTS image_cost_micros_base,
    DROP COLUMN IF EXISTS image_cost_micros_hd,
    DROP COLUMN IF EXISTS audio_stt_cost_micros_per_second,
    DROP COLUMN IF EXISTS audio_tts_cost_micros_per_1k_chars,
    DROP COLUMN IF EXISTS modality_pricing_json;
