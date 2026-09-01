ALTER TABLE teams
    DROP COLUMN IF EXISTS max_concurrent_requests;

ALTER TABLE organizations
    DROP COLUMN IF EXISTS max_concurrent_requests;
