DROP INDEX IF EXISTS idx_virtual_keys_key_rotation_at;

ALTER TABLE virtual_keys
    DROP COLUMN IF EXISTS key_type,
    DROP COLUMN IF EXISTS key_rotation_at,
    DROP COLUMN IF EXISTS rotation_interval_sec;

DROP INDEX IF EXISTS idx_virtual_key_deprecated_hashes_virtual_key_id;
DROP INDEX IF EXISTS idx_virtual_key_deprecated_hashes_revoke_at;
DROP TABLE IF EXISTS virtual_key_deprecated_hashes;
