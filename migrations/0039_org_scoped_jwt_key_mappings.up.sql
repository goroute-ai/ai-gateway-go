-- =============================================================================
-- Migration 0039: Organization-Scoped JWT Key Mappings Uniqueness
-- =============================================================================

ALTER TABLE jwt_key_mappings
    DROP CONSTRAINT IF EXISTS jwt_key_mappings_issuer_claim_name_claim_value_key;

DROP INDEX IF EXISTS idx_jwt_key_mappings_org_issuer_claim;
CREATE UNIQUE INDEX IF NOT EXISTS idx_jwt_key_mappings_org_issuer_claim
    ON jwt_key_mappings (org_id, issuer, claim_name, claim_value);
