DROP INDEX IF EXISTS idx_jwt_key_mappings_org_issuer_claim;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'jwt_key_mappings_issuer_claim_name_claim_value_key'
    ) THEN
        ALTER TABLE jwt_key_mappings
            ADD CONSTRAINT jwt_key_mappings_issuer_claim_name_claim_value_key
            UNIQUE (issuer, claim_name, claim_value);
    END IF;
END $$;
