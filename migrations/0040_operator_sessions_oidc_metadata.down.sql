ALTER TABLE operator_sessions
    DROP COLUMN IF EXISTS encrypted_id_token_dek,
    DROP COLUMN IF EXISTS encrypted_id_token,
    DROP COLUMN IF EXISTS provider_id;
