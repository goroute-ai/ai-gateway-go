-- =============================================================================
-- Rollback Migration 0001
-- =============================================================================

DROP TABLE IF EXISTS audit_logs;
DROP TABLE IF EXISTS spend_logs;
DROP TABLE IF EXISTS model_deployments;
DROP TABLE IF EXISTS model_groups;
DROP TABLE IF EXISTS provider_credentials;
DROP TABLE IF EXISTS virtual_keys;
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS teams;
DROP TABLE IF EXISTS org_model_policies;
DROP TABLE IF EXISTS org_provider_subscriptions;
DROP TABLE IF EXISTS organizations;
DROP TABLE IF EXISTS global_models;
