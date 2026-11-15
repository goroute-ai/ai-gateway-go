package storage

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

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
		"rerank_cost_micros_per_search_unit",
		"image_cost_micros_base",
		"audio_tts_cost_micros_per_1k_chars",
		"pricing_status",
		"supports_inference",
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
		ID:                            "openai/live-pg-roundtrip",
		Provider:                      domain.ProviderOpenAI,
		ModelName:                     "live-pg-roundtrip",
		DisplayName:                   "Live PG Roundtrip",
		SupportsInference:             true,
		LifecycleStatus:               domain.ModelStatusActive,
		PricingStatus:                 domain.PricingStatusVerified,
		InputCostMicrosPer1M:          2500000,
		OutputCostMicrosPer1M:         10000000,
		CachedInputCostMicrosPer1M:    1250000,
		CacheWriteCostMicrosPer1M:     3125000,
		RerankCostMicrosPerSearchUnit: 2000,
		ImageCostMicrosBase:           40000,
		AudioTTSCostMicrosPer1KChars:  15000,
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
		got.RerankCostMicrosPerSearchUnit != gm.RerankCostMicrosPerSearchUnit ||
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
}
