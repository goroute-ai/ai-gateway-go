package storage

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/domain"
)

func livePostgresDSN() string {
	if v := os.Getenv("GATEWAY_POSTGRES_DSN"); v != "" {
		return v
	}
	return "postgres://gateway:gateway@localhost:15432/aigateway_test?sslmode=disable"
}

func TestPostgres_MigrationsUpDownIdempotentAndModelRoundTrip(t *testing.T) {
	ctx := context.Background()
	pool, err := NewPostgresPool(ctx, livePostgresDSN())
	if err != nil {
		if os.Getenv("GATEWAY_REQUIRE_LIVE_DEPS") == "1" {
			t.Fatalf("GATEWAY_REQUIRE_LIVE_DEPS=1 set, but PostgreSQL unreachable: %v", err)
		}
		t.Skipf("skipping live PostgreSQL migration test: %v", err)
	}
	defer pool.Close()

	// Reset public schema so we verify migrations from a completely clean database.
	if _, err := pool.Exec(ctx, `DROP SCHEMA public CASCADE; CREATE SCHEMA public;`); err != nil {
		t.Fatalf("reset schema: %v", err)
	}

	migrationsDir := filepath.Join("..", "..", "migrations")

	// 1. Run all *.up.sql migrations.
	if err := RunMigrationsDir(ctx, pool, migrationsDir); err != nil {
		t.Fatalf("RunMigrationsDir up failed: %v", err)
	}

	// 2. Verify idempotent re-run succeeds and schema_migrations recorded applied files.
	if err := RunMigrationsDir(ctx, pool, migrationsDir); err != nil {
		t.Fatalf("RunMigrationsDir idempotent re-run failed: %v", err)
	}
	var recordedCount int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM schema_migrations`).Scan(&recordedCount); err != nil {
		t.Fatalf("query schema_migrations count: %v", err)
	}
	if recordedCount == 0 {
		t.Fatalf("expected schema_migrations to record applied migrations")
	}

	// 3. Assert critical compatibility & modality columns exist on global_models.
	requiredCols := []string{
		"supported_operations",
		"cache_write_cost_micros_per_1m",
		"image_cost_micros_base",
		"audio_tts_cost_micros_per_1k_chars",
		"pricing_status",
		"supports_inference",
		"quality_tier",
	}
	for _, col := range requiredCols {
		var exists bool
		err := pool.QueryRow(ctx, `
			SELECT EXISTS (
				SELECT 1 FROM information_schema.columns
				WHERE table_schema = 'public' AND table_name = 'global_models' AND column_name = $1
			)`, col).Scan(&exists)
		if err != nil {
			t.Fatalf("check column %s: %v", col, err)
		}
		if !exists {
			t.Fatalf("expected column global_models.%s to exist after migrations", col)
		}
	}

	// 4. Verify reversible down migrations (0012..0003) execute cleanly in reverse order, then re-up cleanly.
	entries, err := os.ReadDir(migrationsDir)
	if err != nil {
		t.Fatalf("read migrations dir: %v", err)
	}
	var downFiles []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".down.sql") && !strings.HasPrefix(e.Name(), "0001_") {
			downFiles = append(downFiles, e.Name())
		}
	}
	sort.Sort(sort.Reverse(sort.StringSlice(downFiles)))
	for _, f := range downFiles {
		sqlBytes, err := os.ReadFile(filepath.Join(migrationsDir, f))
		if err != nil {
			t.Fatalf("read down migration %s: %v", f, err)
		}
		if _, err := pool.Exec(ctx, string(sqlBytes)); err != nil {
			t.Fatalf("exec down migration %s: %v", f, err)
		}
		upName := strings.TrimSuffix(f, ".down.sql") + ".up.sql"
		if _, err := pool.Exec(ctx, `DELETE FROM schema_migrations WHERE filename = $1`, upName); err != nil {
			t.Fatalf("delete schema_migrations entry for %s: %v", upName, err)
		}
	}

	if err := RunMigrationsDir(ctx, pool, migrationsDir); err != nil {
		t.Fatalf("RunMigrationsDir re-up after down failed: %v", err)
	}

	// Assert toxicity & content category columns exist on guardrail_policies after migrations.
	guardrailCols := []string{
		"enable_toxicity_filter",
		"toxicity_action",
		"toxicity_threshold",
		"enabled_content_categories",
		"content_exceptions",
	}
	for _, col := range guardrailCols {
		var exists bool
		err := pool.QueryRow(ctx, `
			SELECT EXISTS (
				SELECT 1 FROM information_schema.columns
				WHERE table_schema = 'public' AND table_name = 'guardrail_policies' AND column_name = $1
			)`, col).Scan(&exists)
		if err != nil {
			t.Fatalf("check guardrail_policies column %s: %v", col, err)
		}
		if !exists {
			t.Fatalf("expected column guardrail_policies.%s to exist after migrations", col)
		}
	}

	// 5. Round-trip GlobalModel with SupportedOperations and modality pricing through PostgresRepository.
	repo, err := NewPostgresRepository(ctx, pool)
	if err != nil {
		t.Fatalf("NewPostgresRepository: %v", err)
	}

	gm := &domain.GlobalModel{
		ID:                           "openai/live-pg-roundtrip",
		Provider:                     domain.ProviderOpenAI,
		ModelName:                    "live-pg-roundtrip",
		DisplayName:                  "Live PG Roundtrip",
		SupportsInference:            true,
		LifecycleStatus:              domain.ModelStatusActive,
		PricingStatus:                domain.PricingStatusVerified,
		InputCostMicrosPer1M:         2500000,
		OutputCostMicrosPer1M:        10000000,
		CachedInputCostMicrosPer1M:   1250000,
		CacheWriteCostMicrosPer1M:    3125000,
		ImageCostMicrosBase:          40000,
		AudioTTSCostMicrosPer1KChars: 15000,
		SupportedOperations: []domain.OperationType{
			domain.OperationChat,
			domain.OperationResponses,
		},
		Capabilities: domain.ModelCapabilities{
			Tools:  domain.CapabilitySupported,
			Vision: domain.CapabilitySupported,
		},
	}
	if err := repo.UpsertGlobalModel(ctx, gm); err != nil {
		t.Fatalf("UpsertGlobalModel: %v", err)
	}

	got, err := repo.GetGlobalModel(ctx, gm.ID)
	if err != nil {
		t.Fatalf("GetGlobalModel: %v", err)
	}
	if got.CacheWriteCostMicrosPer1M != gm.CacheWriteCostMicrosPer1M ||
		got.ImageCostMicrosBase != gm.ImageCostMicrosBase ||
		got.AudioTTSCostMicrosPer1KChars != gm.AudioTTSCostMicrosPer1KChars ||
		len(got.SupportedOperations) != 2 {
		t.Fatalf("round-trip mismatch: got=%+v want=%+v", got, gm)
	}

	// 6. Round-trip GuardrailPolicy toxicity & content category fields through PostgresRepository.
	org := &domain.Organization{
		ID:       "org-guardrail-pg-roundtrip",
		Name:     "Guardrail PG Roundtrip",
		Slug:     "guardrail-pg-roundtrip",
		IsActive: true,
	}
	if err := repo.CreateOrganization(ctx, org); err != nil {
		t.Fatalf("CreateOrganization: %v", err)
	}

	pol := &domain.GuardrailPolicy{
		OrgID:                    org.ID,
		Mode:                     domain.GuardrailModeEnforce,
		ScanAllRoles:             true,
		EnablePromptInjection:    true,
		PromptInjectionAction:    domain.GuardrailActionBlock,
		EnablePIIDetection:       true,
		PIIAction:                domain.GuardrailActionRedact,
		EnableSecretDetection:    true,
		SecretAction:             domain.GuardrailActionAudit,
		BlockedKeywords:          []string{"forbidden"},
		RedactOutputPII:          true,
		EnableToxicityFilter:     true,
		ToxicityAction:           domain.GuardrailActionRedact,
		ToxicityThreshold:        "low",
		EnabledContentCategories: []string{"bias", "harm_toxic_abuse"},
		ContentExceptions:        []string{"medical_term"},
	}
	if err := repo.SetGuardrailPolicy(ctx, pol); err != nil {
		t.Fatalf("SetGuardrailPolicy: %v", err)
	}

	// Use a fresh repository instance to ensure reads come from PostgreSQL rather than in-memory state.
	freshRepo, err := NewPostgresRepository(ctx, pool)
	if err != nil {
		t.Fatalf("NewPostgresRepository fresh: %v", err)
	}
	gotPol, err := freshRepo.GetGuardrailPolicy(ctx, org.ID)
	if err != nil {
		t.Fatalf("GetGuardrailPolicy: %v", err)
	}
	if gotPol == nil {
		t.Fatalf("expected non-nil GuardrailPolicy from PostgreSQL")
	}
	if !gotPol.EnableToxicityFilter ||
		gotPol.ToxicityAction != domain.GuardrailActionRedact ||
		gotPol.ToxicityThreshold != "low" ||
		!reflect.DeepEqual(gotPol.EnabledContentCategories, []string{"bias", "harm_toxic_abuse"}) ||
		!reflect.DeepEqual(gotPol.ContentExceptions, []string{"medical_term"}) {
		t.Fatalf("guardrail policy round-trip mismatch: got=%+v want=%+v", gotPol, pol)
	}

	// Verify nil slices normalize to empty arrays ({}) and empty toxicity action/threshold use defaults.
	nilSlicePol := &domain.GuardrailPolicy{
		OrgID:                org.ID,
		EnableToxicityFilter: false,
	}
	if err := repo.SetGuardrailPolicy(ctx, nilSlicePol); err != nil {
		t.Fatalf("SetGuardrailPolicy nil slices: %v", err)
	}
	gotNilPol, err := freshRepo.GetGuardrailPolicy(ctx, org.ID)
	if err != nil {
		t.Fatalf("GetGuardrailPolicy nil slices: %v", err)
	}
	if gotNilPol.EnableToxicityFilter {
		t.Fatalf("EnableToxicityFilter = true, want false")
	}
	if gotNilPol.ToxicityAction != domain.GuardrailActionBlock {
		t.Fatalf("ToxicityAction = %q, want %q", gotNilPol.ToxicityAction, domain.GuardrailActionBlock)
	}
	if gotNilPol.ToxicityThreshold != "medium" {
		t.Fatalf("ToxicityThreshold = %q, want %q", gotNilPol.ToxicityThreshold, "medium")
	}
	if gotNilPol.BlockedKeywords == nil || len(gotNilPol.BlockedKeywords) != 0 {
		t.Fatalf("BlockedKeywords = %#v, want non-nil empty slice", gotNilPol.BlockedKeywords)
	}
	if gotNilPol.EnabledContentCategories == nil || len(gotNilPol.EnabledContentCategories) != 0 {
		t.Fatalf("EnabledContentCategories = %#v, want non-nil empty slice", gotNilPol.EnabledContentCategories)
	}
	if gotNilPol.ContentExceptions == nil || len(gotNilPol.ContentExceptions) != 0 {
		t.Fatalf("ContentExceptions = %#v, want non-nil empty slice", gotNilPol.ContentExceptions)
	}

	// 7. Assert routing foundation columns on model_groups & model_deployments and round-trip them.
	for _, tc := range []struct {
		table string
		cols  []string
	}{
		{"model_groups", []string{"context_window_fallbacks", "content_policy_fallbacks", "fallback_targets", "retry_policy", "cooldown_policy"}},
		{"model_deployments", []string{"tags", "max_budget_micros", "budget_reset_period"}},
		{"organizations", []string{"enforce_guaranteed_throughput", "developer_self_serve_keys", "key_expiry_alert_days", "lifecycle_webhook_url"}},
		{"teams", []string{"enforce_guaranteed_throughput", "default_member_max_budget_micros", "default_member_rpm_limit", "default_member_tpm_limit", "default_member_allowed_models", "team_member_permissions"}},
		{"virtual_keys", []string{"last_rotated_at", "rotation_count", "revoked_at", "revoked_by", "expiry_alert_sent_days"}},
		{"audit_logs", []string{"before_value", "after_value"}},
		{"mcp_runtime_settings", []string{"id", "active_protocol_version", "strict_schema_validation", "updated_by", "updated_at"}},
	} {
		for _, col := range tc.cols {
			var exists bool
			if err := pool.QueryRow(ctx, `
				SELECT EXISTS (
					SELECT 1 FROM information_schema.columns
					WHERE table_schema = 'public' AND table_name = $1 AND column_name = $2
				)`, tc.table, col).Scan(&exists); err != nil {
				t.Fatalf("check %s.%s: %v", tc.table, col, err)
			}
			if !exists {
				t.Fatalf("expected column %s.%s to exist after migrations", tc.table, col)
			}
		}
	}

	// 8. Verify 0038_mcp_runtime_spec default row & live Get/Update persistence across fresh PostgresRepository.
	rsDefault, err := freshRepo.GetMCPRuntimeSettings(ctx)
	if err != nil {
		t.Fatalf("GetMCPRuntimeSettings default: %v", err)
	}
	if rsDefault.ActiveProtocolVersion != domain.MCPProtocolVersion20260728 || rsDefault.StrictSchemaValidation {
		t.Fatalf("unexpected default MCP runtime settings: %+v", rsDefault)
	}
	if err := repo.UpdateMCPRuntimeSettings(ctx, &domain.MCPRuntimeSettings{
		ActiveProtocolVersion:  domain.MCPProtocolVersion20250326,
		StrictSchemaValidation: true,
		UpdatedBy:              "pg-live-test",
	}); err != nil {
		t.Fatalf("UpdateMCPRuntimeSettings 2025-03-26: %v", err)
	}
	reloadRepo, err := NewPostgresRepository(ctx, pool)
	if err != nil {
		t.Fatalf("reload PostgresRepository: %v", err)
	}
	rsReloaded, err := reloadRepo.GetMCPRuntimeSettings(ctx)
	if err != nil {
		t.Fatalf("GetMCPRuntimeSettings reloaded: %v", err)
	}
	if rsReloaded.ActiveProtocolVersion != domain.MCPProtocolVersion20250326 || !rsReloaded.StrictSchemaValidation || rsReloaded.UpdatedBy != "pg-live-test" {
		t.Fatalf("reloaded MCP runtime settings mismatch: %+v", rsReloaded)
	}
	if err := reloadRepo.UpdateMCPRuntimeSettings(ctx, &domain.MCPRuntimeSettings{
		ActiveProtocolVersion:  domain.MCPProtocolVersion20260728,
		StrictSchemaValidation: false,
		UpdatedBy:              "system",
	}); err != nil {
		t.Fatalf("restore default MCP runtime settings: %v", err)
	}
}

func TestPostgres_Migration0034_UpgradeAndRollbackConflictPreflight(t *testing.T) {
	ctx := context.Background()
	pool, err := NewPostgresPool(ctx, livePostgresDSN())
	if err != nil {
		if os.Getenv("GATEWAY_REQUIRE_LIVE_DEPS") == "1" {
			t.Fatalf("GATEWAY_REQUIRE_LIVE_DEPS=1 set, but PostgreSQL unreachable: %v", err)
		}
		t.Skipf("skipping live PostgreSQL migration 0034 test: %v", err)
	}
	defer pool.Close()

	if _, err := pool.Exec(ctx, `DROP SCHEMA public CASCADE; CREATE SCHEMA public;`); err != nil {
		t.Fatalf("reset schema: %v", err)
	}

	migrationsDir := filepath.Join("..", "..", "migrations")
	entries, err := os.ReadDir(migrationsDir)
	if err != nil {
		t.Fatalf("read migrations dir: %v", err)
	}
	var pre0034 []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".up.sql") && e.Name() < "0034_" {
			pre0034 = append(pre0034, filepath.Join(migrationsDir, e.Name()))
		}
	}
	sort.Strings(pre0034)
	for _, file := range pre0034 {
		if err := RunMigrations(ctx, pool, file); err != nil {
			t.Fatalf("apply %s: %v", file, err)
		}
	}

	// Populate 0033 rows before upgrading to 0034.
	if _, err := pool.Exec(ctx, `
		INSERT INTO organizations (id, name, slug) VALUES ('org-m34', 'Mig34 Org', 'org-m34');
		INSERT INTO teams (id, org_id, name) VALUES ('team-m34', 'org-m34', 'Mig34 Team');
		INSERT INTO users (id, org_id, team_id, email, name, oidc_subject)
			VALUES ('usr-m34-1', 'org-m34', 'team-m34', 'u1@m34.example', 'User 1', 'shared-sub');
		INSERT INTO virtual_keys (id, key_prefix, key_hash, name, org_id, team_id, user_id)
			VALUES ('vk-m34', 'sk-gw-m34', 'hash-m34', 'Mig34 VK', 'org-m34', 'team-m34', 'usr-m34-1');
		INSERT INTO budget_window_limits (id, org_id, scope_type, scope_id, window_type, max_budget_micros, spent_micros, window_reset_at)
			VALUES ('bw-m34', 'org-m34', 'key', 'vk-m34', 'rolling_24h', 100000, 75000, NOW() - INTERVAL '48 hours');
	`); err != nil {
		t.Fatalf("seed 0033 rows: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO spend_logs (id, request_id, org_id, team_id, user_id, virtual_key_id, endpoint, requested_model, resolved_model, provider, cost_micros, created_at)
		VALUES ('sp-m34-recent', 'req-m34', 'org-m34', 'team-m34', 'usr-m34-1', 'vk-m34', '/v1/chat/completions', 'gpt-4.1', 'gpt-4.1', 'openai', 20000, $1)
	`, time.Now().UTC().Add(-2*time.Hour)); err != nil {
		t.Fatalf("seed 0033 spend_log: %v", err)
	}

	// Upgrade to 0034.
	if err := RunMigrationsDir(ctx, pool, migrationsDir); err != nil {
		t.Fatalf("upgrade 0033 -> 0034: %v", err)
	}

	// Insert two users with distinct issuers sharing nonempty (org_id, oidc_subject).
	if _, err := pool.Exec(ctx, `
		UPDATE users SET oidc_issuer = 'https://issuer-a.example' WHERE id = 'usr-m34-1';
		INSERT INTO users (id, org_id, team_id, email, name, oidc_issuer, oidc_subject)
			VALUES ('usr-m34-2', 'org-m34', 'team-m34', 'u2@m34.example', 'User 2', 'https://issuer-b.example', 'shared-sub');
	`); err != nil {
		t.Fatalf("insert duplicate subject bindings across issuers: %v", err)
	}

	downPath := filepath.Join(migrationsDir, "0034_auth_quota_reconciliation.down.sql")
	downSQL, err := os.ReadFile(downPath)
	if err != nil {
		t.Fatalf("read 0034 down migration: %v", err)
	}

	// Rollback must fail with descriptive error and preserve all rows and 0034 schema objects.
	_, rollbackErr := pool.Exec(ctx, string(downSQL))
	if rollbackErr == nil {
		t.Fatal("expected 0034 rollback to abort when duplicate nonempty (org_id, oidc_subject) bindings exist")
	}
	if !strings.Contains(rollbackErr.Error(), "duplicate nonempty (org_id, oidc_subject)") || !strings.Contains(rollbackErr.Error(), "idx_users_org_oidc_subject") {
		t.Fatalf("unexpected rollback error message: %v", rollbackErr)
	}

	var userCount int
	var hasIssuerCol, hasHoldCol bool
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM users WHERE org_id = 'org-m34' AND oidc_subject = 'shared-sub'`).Scan(&userCount); err != nil {
		t.Fatalf("count preserved bindings: %v", err)
	}
	if userCount != 2 {
		t.Fatalf("expected both identity bindings preserved after failed rollback, got %d", userCount)
	}
	if err := pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='public' AND table_name='users' AND column_name='oidc_issuer')`).Scan(&hasIssuerCol); err != nil || !hasIssuerCol {
		t.Fatalf("expected users.oidc_issuer preserved after aborted rollback (has=%v, err=%v)", hasIssuerCol, err)
	}
	if err := pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='public' AND table_name='budget_window_limits' AND column_name='rolling_hold_micros')`).Scan(&hasHoldCol); err != nil || !hasHoldCol {
		t.Fatalf("expected budget_window_limits.rolling_hold_micros preserved after aborted rollback (has=%v, err=%v)", hasHoldCol, err)
	}

	// Explicitly resolve the conflict, then rollback and reapply cleanly.
	if _, err := pool.Exec(ctx, `UPDATE users SET oidc_subject = 'resolved-sub-2' WHERE id = 'usr-m34-2'`); err != nil {
		t.Fatalf("resolve duplicate conflict: %v", err)
	}
	if _, err := pool.Exec(ctx, string(downSQL)); err != nil {
		t.Fatalf("expected 0034 rollback to succeed after resolving duplicate bindings: %v", err)
	}
	if _, err := pool.Exec(ctx, `DELETE FROM schema_migrations WHERE filename = '0034_auth_quota_reconciliation.up.sql'`); err != nil {
		t.Fatalf("delete 0034 schema_migrations row: %v", err)
	}
	var legacyIndexExists, issuerColStillExists bool
	_ = pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_indexes WHERE schemaname='public' AND indexname='idx_users_org_oidc_subject')`).Scan(&legacyIndexExists)
	_ = pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='public' AND table_name='users' AND column_name='oidc_issuer')`).Scan(&issuerColStillExists)
	if !legacyIndexExists || issuerColStillExists {
		t.Fatalf("expected legacy index restored (%v) and oidc_issuer dropped (%v) after rollback", legacyIndexExists, issuerColStillExists)
	}

	if err := RunMigrationsDir(ctx, pool, migrationsDir); err != nil {
		t.Fatalf("reapply 0034 after clean rollback: %v", err)
	}
}

func TestPostgres_MigrationLifecycle_0001_to_0034(t *testing.T) {
	ctx := context.Background()
	pool, err := NewPostgresPool(ctx, livePostgresDSN())
	if err != nil {
		if os.Getenv("GATEWAY_REQUIRE_LIVE_DEPS") == "1" {
			t.Fatalf("GATEWAY_REQUIRE_LIVE_DEPS=1 set, but PostgreSQL unreachable: %v", err)
		}
		t.Skipf("skipping live PostgreSQL migration lifecycle test: %v", err)
	}
	defer pool.Close()

	if _, err := pool.Exec(ctx, `DROP SCHEMA public CASCADE; CREATE SCHEMA public;`); err != nil {
		t.Fatalf("reset schema: %v", err)
	}

	migrationsDir := filepath.Join("..", "..", "migrations")
	if err := RunMigrationsDir(ctx, pool, migrationsDir); err != nil {
		t.Fatalf("RunMigrationsDir fresh 0001..0034 failed: %v", err)
	}

	expectedTables := []string{
		"jwt_key_mappings",
		"virtual_key_deprecated_hashes",
		"access_group_rules",
		"team_memberships",
		"projects",
		"quota_policies",
		"budget_window_limits",
		"end_users",
		"tags",
		"model_access_groups",
		"model_access_group_members",
		"deployment_ptu_shares",
		"priority_classes",
		"user_credentials",
		"operator_sessions",
	}
	for _, tbl := range expectedTables {
		var exists bool
		if err := pool.QueryRow(ctx, `
			SELECT EXISTS (
				SELECT 1 FROM information_schema.tables
				WHERE table_schema = 'public' AND table_name = $1
			)`, tbl).Scan(&exists); err != nil || !exists {
			t.Fatalf("expected table %s after 0001..0034 (exists=%v, err=%v)", tbl, exists, err)
		}
	}

	expectedCols := []struct {
		table string
		col   string
	}{
		{"batches", "estimated_tokens"},
		{"batches", "reserved_cost_micros"},
		{"organizations", "soft_budget_micros"},
		{"organizations", "throttle_on_budget_exceeded"},
		{"organizations", "budget_fallbacks"},
		{"organizations", "self_serve_budget_policy"},
		{"virtual_keys", "rotation_interval_sec"},
		{"virtual_keys", "key_rotation_at"},
		{"virtual_keys", "key_type"},
		{"virtual_keys", "project_id"},
		{"virtual_keys", "can_impersonate"},
		{"virtual_keys", "temp_budget_increase_micros"},
		{"virtual_keys", "staged_key_hash"},
		{"users", "scim_external_id"},
		{"users", "scim_active"},
		{"users", "oidc_issuer"},
		{"spend_logs", "project_id"},
		{"spend_logs", "model_access_group_ids"},
		{"spend_logs", "matched_quota_policy_ids"},
		{"spend_logs", "end_user_id"},
		{"spend_logs", "tags"},
		{"spend_logs", "session_id"},
		{"budget_window_limits", "rolling_hold_micros"},
		{"budget_window_limits", "rolling_hold_expires_at"},
		{"teams", "team_member_permissions"},
		{"audit_logs", "before_value"},
		{"audit_logs", "after_value"},
		{"virtual_keys", "last_rotated_at"},
		{"virtual_keys", "rotation_count"},
		{"virtual_keys", "revoked_at"},
		{"virtual_keys", "revoked_by"},
		{"virtual_keys", "expiry_alert_sent_days"},
	}
	for _, tc := range expectedCols {
		var exists bool
		if err := pool.QueryRow(ctx, `
			SELECT EXISTS (
				SELECT 1 FROM information_schema.columns
				WHERE table_schema = 'public' AND table_name = $1 AND column_name = $2
			)`, tc.table, tc.col).Scan(&exists); err != nil || !exists {
			t.Fatalf("expected column %s.%s after 0001..0035 (exists=%v, err=%v)", tc.table, tc.col, exists, err)
		}
	}

	for _, idx := range []string{"idx_users_org_issuer_subject", "idx_users_org_scim_external_id"} {
		var exists bool
		if err := pool.QueryRow(ctx, `
			SELECT EXISTS (
				SELECT 1 FROM pg_indexes WHERE schemaname = 'public' AND indexname = $1
			)`, idx).Scan(&exists); err != nil || !exists {
			t.Fatalf("expected index %s after 0001..0035 (exists=%v, err=%v)", idx, exists, err)
		}
	}

	// Exercise reverse down migrations from latest (0038) down through 0022.
	entries, err := os.ReadDir(migrationsDir)
	if err != nil {
		t.Fatalf("read migrations dir: %v", err)
	}
	var waveDowns []string
	for _, e := range entries {
		name := e.Name()
		if !e.IsDir() && strings.HasSuffix(name, ".down.sql") && name >= "0022_" {
			waveDowns = append(waveDowns, name)
		}
	}
	sort.Sort(sort.Reverse(sort.StringSlice(waveDowns)))
	if len(waveDowns) != 17 {
		t.Fatalf("expected 17 down migrations for 0022..0038, got %d: %v", len(waveDowns), waveDowns)
	}
	for _, f := range waveDowns {
		sqlBytes, err := os.ReadFile(filepath.Join(migrationsDir, f))
		if err != nil {
			t.Fatalf("read down migration %s: %v", f, err)
		}
		if _, err := pool.Exec(ctx, string(sqlBytes)); err != nil {
			t.Fatalf("exec down migration %s: %v", f, err)
		}
		upName := strings.TrimSuffix(f, ".down.sql") + ".up.sql"
		if _, err := pool.Exec(ctx, `DELETE FROM schema_migrations WHERE filename = $1`, upName); err != nil {
			t.Fatalf("delete schema_migrations %s: %v", upName, err)
		}
	}

	for _, removedTable := range []string{"jwt_key_mappings", "operator_sessions"} {
		var exists bool
		if err := pool.QueryRow(ctx, `
			SELECT EXISTS (
				SELECT 1 FROM information_schema.tables
				WHERE table_schema = 'public' AND table_name = $1
			)`, removedTable).Scan(&exists); err != nil || exists {
			t.Fatalf("expected table %s removed after 0034..0022 rollback (exists=%v, err=%v)", removedTable, exists, err)
		}
	}

	// Reapply 0022..0034 cleanly and verify idempotency.
	if err := RunMigrationsDir(ctx, pool, migrationsDir); err != nil {
		t.Fatalf("RunMigrationsDir reapply 0022..0034 failed: %v", err)
	}
	if err := RunMigrationsDir(ctx, pool, migrationsDir); err != nil {
		t.Fatalf("RunMigrationsDir second idempotent reapply failed: %v", err)
	}
	var jwtMapExists bool
	if err := pool.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM information_schema.tables
			WHERE table_schema = 'public' AND table_name = 'jwt_key_mappings'
		)`).Scan(&jwtMapExists); err != nil || !jwtMapExists {
		t.Fatalf("expected jwt_key_mappings restored after reapply (exists=%v, err=%v)", jwtMapExists, err)
	}

	// Verify live Postgres RotateKEKsTransactionally re-wraps virtual_keys.staged_key_dek atomically.
	pgRepo, err := NewPostgresRepository(ctx, pool)
	if err != nil {
		t.Fatalf("NewPostgresRepository: %v", err)
	}
	if err := pgRepo.CreateOrganization(ctx, &domain.Organization{
		ID:       "org_live_kek",
		Name:     "Live KEK Org",
		Slug:     "live-kek-org",
		IsActive: true,
	}); err != nil {
		t.Fatalf("CreateOrganization(live kek): %v", err)
	}
	if err := pgRepo.CreateVirtualKey(ctx, &domain.VirtualKey{
		ID:            "vk_live_staged_1",
		OrgID:         "org_live_kek",
		Name:          "live-staged-kek",
		KeyPrefix:     "sk-gw-lvk",
		KeyHash:       "hash-live-kek-active",
		StagedKeyHash: "hash-live-kek-staged",
		StagedKeyDEK:  "live-old-staged-dek",
		IsActive:      true,
	}); err != nil {
		t.Fatalf("CreateVirtualKey(live staged): %v", err)
	}
	liveSum, err := pgRepo.RotateKEKsTransactionally(ctx, func(batch KEKRotationBatch) (KEKRotationBatch, error) {
		var out KEKRotationBatch
		for _, vk := range batch.StagedVirtualKeys {
			cp := *vk
			cp.StagedKeyDEK = "live-new-staged-dek"
			out.StagedVirtualKeys = append(out.StagedVirtualKeys, &cp)
		}
		return out, nil
	})
	if err != nil || liveSum.StagedVirtualKeysRewrapped != 1 {
		t.Fatalf("live RotateKEKsTransactionally(staged_key_dek) failed: %+v err=%v", liveSum, err)
	}
	liveVK, err := pgRepo.GetVirtualKeyByID(ctx, "vk_live_staged_1")
	if err != nil || liveVK.StagedKeyDEK != "live-new-staged-dek" {
		t.Fatalf("expected live staged_key_dek updated, got vk=%+v err=%v", liveVK, err)
	}

	// Verify 0036 production routing hardening columns & reversible rollback/reapply.
	hardeningCols := []struct {
		table string
		col   string
	}{
		{"model_deployments", "max_parallel_requests"},
		{"model_deployments", "itpm_capacity"},
		{"model_deployments", "otpm_capacity"},
		{"model_groups", "drop_unsupported_params"},
		{"model_groups", "disable_cooldowns"},
		{"model_groups", "saturation_fallbacks"},
		{"quota_policies", "rpd_limit"},
		{"virtual_keys", "min_priority_rank"},
		{"virtual_keys", "allowed_routing_tags"},
		{"teams", "min_priority_rank"},
		{"teams", "allowed_routing_tags"},
		{"guardrail_policies", "sensitive_route_target"},
		{"guardrail_definitions", "sensitive_route_target"},
	}
	for _, tc := range hardeningCols {
		var exists bool
		if err := pool.QueryRow(ctx, `
			SELECT EXISTS (
				SELECT 1 FROM information_schema.columns
				WHERE table_schema = 'public' AND table_name = $1 AND column_name = $2
			)`, tc.table, tc.col).Scan(&exists); err != nil || !exists {
			t.Fatalf("expected column %s.%s after 0036 (exists=%v, err=%v)", tc.table, tc.col, exists, err)
		}
	}

	down0036, err := os.ReadFile(filepath.Join(migrationsDir, "0036_production_routing_hardening.down.sql"))
	if err != nil {
		t.Fatalf("read 0036 down migration: %v", err)
	}
	if _, err := pool.Exec(ctx, string(down0036)); err != nil {
		t.Fatalf("exec 0036 down migration: %v", err)
	}
	if _, err := pool.Exec(ctx, `DELETE FROM schema_migrations WHERE filename = $1`, "0036_production_routing_hardening.up.sql"); err != nil {
		t.Fatalf("delete schema_migrations 0036: %v", err)
	}
	if err := RunMigrationsDir(ctx, pool, migrationsDir); err != nil {
		t.Fatalf("RunMigrationsDir reapply 0036 failed: %v", err)
	}
}
