-- Migration 0007: Add modality pricing to global_models, modality units to spend_logs, and files & batches tables

ALTER TABLE global_models 
    ADD COLUMN IF NOT EXISTS rerank_cost_micros_per_search_unit BIGINT DEFAULT 0,
    ADD COLUMN IF NOT EXISTS image_cost_micros_base BIGINT DEFAULT 0,
    ADD COLUMN IF NOT EXISTS image_cost_micros_hd BIGINT DEFAULT 0,
    ADD COLUMN IF NOT EXISTS audio_stt_cost_micros_per_second BIGINT DEFAULT 0,
    ADD COLUMN IF NOT EXISTS audio_tts_cost_micros_per_1k_chars BIGINT DEFAULT 0,
    ADD COLUMN IF NOT EXISTS modality_pricing_json JSONB DEFAULT '{}'::jsonb;

ALTER TABLE spend_logs 
    ADD COLUMN IF NOT EXISTS modality VARCHAR(32) NOT NULL DEFAULT 'chat',
    ADD COLUMN IF NOT EXISTS modality_units JSONB DEFAULT '{}'::jsonb;

CREATE INDEX IF NOT EXISTS idx_spend_logs_org_modality_created 
    ON spend_logs (org_id, modality, created_at DESC);

-- Files table for stateful tenant assets
CREATE TABLE IF NOT EXISTS files (
    id VARCHAR(64) PRIMARY KEY,
    org_id VARCHAR(64) NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    team_id VARCHAR(64) REFERENCES teams(id) ON DELETE SET NULL,
    user_id VARCHAR(64) REFERENCES users(id) ON DELETE SET NULL,
    bytes BIGINT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    filename VARCHAR(255) NOT NULL,
    purpose VARCHAR(64) NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'uploaded',
    content_sha256 VARCHAR(64) NOT NULL,
    storage_path TEXT NOT NULL,
    upstream_provider VARCHAR(64),
    upstream_id VARCHAR(128),
    expires_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_files_org_purpose ON files (org_id, purpose);
CREATE INDEX IF NOT EXISTS idx_files_org_sha ON files (org_id, content_sha256);

-- Batches table for asynchronous batch jobs
CREATE TABLE IF NOT EXISTS batches (
    id VARCHAR(64) PRIMARY KEY,
    org_id VARCHAR(64) NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    team_id VARCHAR(64) REFERENCES teams(id) ON DELETE SET NULL,
    input_file_id VARCHAR(64) NOT NULL REFERENCES files(id),
    output_file_id VARCHAR(64) REFERENCES files(id),
    error_file_id VARCHAR(64) REFERENCES files(id),
    endpoint VARCHAR(128) NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'validating',
    completion_window VARCHAR(32) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ,
    metadata JSONB DEFAULT '{}'::jsonb,
    request_counts JSONB DEFAULT '{"total":0,"completed":0,"failed":0}'::jsonb,
    upstream_provider VARCHAR(64),
    upstream_id VARCHAR(128)
);
CREATE INDEX IF NOT EXISTS idx_batches_org_status ON batches (org_id, status);
