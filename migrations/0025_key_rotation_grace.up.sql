CREATE TABLE IF NOT EXISTS virtual_key_deprecated_hashes (
    key_hash CHAR(64) PRIMARY KEY,
    virtual_key_id VARCHAR(64) NOT NULL REFERENCES virtual_keys(id) ON DELETE CASCADE,
    revoke_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_virtual_key_deprecated_hashes_revoke_at
    ON virtual_key_deprecated_hashes(revoke_at);

CREATE INDEX IF NOT EXISTS idx_virtual_key_deprecated_hashes_virtual_key_id
    ON virtual_key_deprecated_hashes(virtual_key_id);

ALTER TABLE virtual_keys
    ADD COLUMN IF NOT EXISTS rotation_interval_sec BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS key_rotation_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS key_type VARCHAR(32) NOT NULL DEFAULT 'default';

CREATE INDEX IF NOT EXISTS idx_virtual_keys_key_rotation_at
    ON virtual_keys(key_rotation_at)
    WHERE is_active = TRUE AND key_rotation_at IS NOT NULL;
