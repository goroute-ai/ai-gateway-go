package storage

import (
	"context"
	"os"
	"path/filepath"
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

	// 2. Verify idempotent re-run succeeds.
	if err := RunMigrationsDir(ctx, pool, migrationsDir); err != nil {
		t.Fatalf("RunMigrationsDir idempotent re-run failed: %v", err)
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
	}

	if err := RunMigrationsDir(ctx, pool, migrationsDir); err != nil {
		t.Fatalf("RunMigrationsDir re-up after down failed: %v", err)
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
}
