package storage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PostgresPoolOptions configures pgxpool sizing and lifetimes.
// Zero values preserve DSN parameters (e.g. pool_max_conns, pool_min_conns)
// or fall back to production defaults when unset in the DSN.
type PostgresPoolOptions struct {
	MaxConns        int32
	MinConns        int32
	MaxConnLifetime time.Duration
	MaxConnIdleTime time.Duration
	RDSIAM          *RDSIAMConfig
}

func dsnHasPoolParam(dsn, param string) bool {
	return strings.Contains(strings.ToLower(dsn), strings.ToLower(param)+"=")
}

func configurePostgresPool(dsn string, opts PostgresPoolOptions) (*pgxpool.Config, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("parse postgres dsn: %w", err)
	}
	if opts.MaxConns > 0 {
		cfg.MaxConns = opts.MaxConns
	} else if !dsnHasPoolParam(dsn, "pool_max_conns") {
		cfg.MaxConns = 32
	}
	if opts.MinConns > 0 {
		cfg.MinConns = opts.MinConns
	} else if !dsnHasPoolParam(dsn, "pool_min_conns") {
		cfg.MinConns = 4
	}
	if opts.MaxConnLifetime > 0 {
		cfg.MaxConnLifetime = opts.MaxConnLifetime
	} else if !dsnHasPoolParam(dsn, "pool_max_conn_lifetime") {
		cfg.MaxConnLifetime = 30 * time.Minute
	}
	if opts.MaxConnIdleTime > 0 {
		cfg.MaxConnIdleTime = opts.MaxConnIdleTime
	} else if !dsnHasPoolParam(dsn, "pool_max_conn_idle_time") {
		cfg.MaxConnIdleTime = 5 * time.Minute
	}
	if opts.RDSIAM != nil && opts.RDSIAM.Enabled {
		iamCfg := *opts.RDSIAM
		if iamCfg.Host == "" {
			iamCfg.Host = cfg.ConnConfig.Host
		}
		if iamCfg.Port == 0 {
			iamCfg.Port = cfg.ConnConfig.Port
		}
		if iamCfg.DBUser == "" {
			iamCfg.DBUser = cfg.ConnConfig.User
		}
		provider, err := NewRDSIAMTokenProvider(iamCfg)
		if err != nil {
			return nil, fmt.Errorf("configure rds iam token provider: %w", err)
		}
		cfg.BeforeConnect = provider.BeforeConnect
	}
	return cfg, nil
}

// NewPostgresPool creates a configured pgxpool.Pool for PostgreSQL 16+ persistence.
func NewPostgresPool(ctx context.Context, dsn string) (*pgxpool.Pool, error) {
	return NewPostgresPoolWithOptions(ctx, dsn, PostgresPoolOptions{})
}

// NewPostgresPoolWithOptions creates a pgxpool.Pool respecting explicit options and DSN pool parameters.
func NewPostgresPoolWithOptions(ctx context.Context, dsn string, opts PostgresPoolOptions) (*pgxpool.Pool, error) {
	cfg, err := configurePostgresPool(dsn, opts)
	if err != nil {
		return nil, err
	}

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("create postgres pool: %w", err)
	}
	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := pool.Ping(pingCtx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping postgres: %w", err)
	}
	return pool, nil
}

const schemaMigrationsAdvisoryLockID int64 = 0x676f726f75746501

func withMigrationLock(ctx context.Context, pool *pgxpool.Pool, fn func(conn *pgxpool.Conn) error) error {
	if pool == nil {
		return errors.New("postgres pool is nil")
	}
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("acquire migration connection: %w", err)
	}
	defer conn.Release()

	if _, err := conn.Exec(ctx, `SELECT pg_advisory_lock($1)`, schemaMigrationsAdvisoryLockID); err != nil {
		return fmt.Errorf("acquire migration advisory lock: %w", err)
	}
	defer func() {
		unlockCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, _ = conn.Exec(unlockCtx, `SELECT pg_advisory_unlock($1)`, schemaMigrationsAdvisoryLockID)
	}()

	if _, err := conn.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			filename TEXT PRIMARY KEY,
			applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)
	`); err != nil {
		return fmt.Errorf("ensure schema_migrations table: %w", err)
	}

	return fn(conn)
}

func applyMigrationFile(ctx context.Context, conn *pgxpool.Conn, migrationFilePath string) error {
	filename := filepath.Base(migrationFilePath)
	var applied bool
	if err := conn.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM schema_migrations WHERE filename = $1)`, filename).Scan(&applied); err != nil {
		return fmt.Errorf("check migration %s: %w", filename, err)
	}
	if applied {
		return nil
	}

	sqlBytes, err := os.ReadFile(migrationFilePath)
	if err != nil {
		return fmt.Errorf("read migration file %s: %w", migrationFilePath, err)
	}

	tx, err := conn.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin migration tx %s: %w", filename, err)
	}
	if _, err := tx.Exec(ctx, string(sqlBytes)); err != nil {
		_ = tx.Rollback(ctx)
		return fmt.Errorf("execute migration %s: %w", migrationFilePath, err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO schema_migrations (filename) VALUES ($1)`, filename); err != nil {
		_ = tx.Rollback(ctx)
		return fmt.Errorf("record migration %s: %w", filename, err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit migration %s: %w", filename, err)
	}
	return nil
}

// RunMigrations executes a single SQL schema migration file on the PostgreSQL pool
// under a PostgreSQL advisory lock, skipping it if already recorded in schema_migrations.
func RunMigrations(ctx context.Context, pool *pgxpool.Pool, migrationFilePath string) error {
	return withMigrationLock(ctx, pool, func(conn *pgxpool.Conn) error {
		return applyMigrationFile(ctx, conn, migrationFilePath)
	})
}

// RunMigrationsDir executes all unapplied *.up.sql migration files in dir in alphabetical order
// under a PostgreSQL advisory lock, recording each applied file in schema_migrations.
func RunMigrationsDir(ctx context.Context, pool *pgxpool.Pool, dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("read migrations dir %s: %w", dir, err)
	}
	var upFiles []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".up.sql") {
			upFiles = append(upFiles, filepath.Join(dir, e.Name()))
		}
	}
	sort.Strings(upFiles)

	return withMigrationLock(ctx, pool, func(conn *pgxpool.Conn) error {
		for _, file := range upFiles {
			if err := applyMigrationFile(ctx, conn, file); err != nil {
				return err
			}
		}
		return nil
	})
}

// PostgresRepository implements Repository backed by PostgreSQL 16+ with a synchronized write-through
// in-memory projection for ultra-fast relational joins on deployments and global models.
type PostgresRepository struct {
	pool                     *pgxpool.Pool
	mem                      *MemoryRepository
	lookupMu                 sync.Mutex
	lookupCalls              map[string]*postgresLookupCall
	subscriptionQueries      atomic.Uint64
	emptySubscriptionQueries atomic.Uint64
	guardrailQueries         atomic.Uint64
	missingGuardrailQueries  atomic.Uint64
}

type postgresLookupCall struct {
	done  chan struct{}
	value any
	err   error
}

// coalesceLookup shares only concurrent reads; missing rows are not retained,
// so policy changes on another replica become visible on the next lookup.
func (p *PostgresRepository) coalesceLookup(ctx context.Context, key string, fn func(context.Context) (any, error)) (any, error) {
	p.lookupMu.Lock()
	if p.lookupCalls == nil {
		p.lookupCalls = make(map[string]*postgresLookupCall)
	}
	if call := p.lookupCalls[key]; call != nil {
		p.lookupMu.Unlock()
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-call.done:
			return call.value, call.err
		}
	}
	call := &postgresLookupCall{done: make(chan struct{})}
	p.lookupCalls[key] = call
	p.lookupMu.Unlock()

	lookupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
	call.value, call.err = fn(lookupCtx)
	cancel()
	p.lookupMu.Lock()
	delete(p.lookupCalls, key)
	close(call.done)
	p.lookupMu.Unlock()
	return call.value, call.err
}

func (p *PostgresRepository) LookupQueryStats() (uint64, uint64, uint64, uint64) {
	return p.subscriptionQueries.Load(), p.emptySubscriptionQueries.Load(), p.guardrailQueries.Load(), p.missingGuardrailQueries.Load()
}

func NewPostgresRepository(ctx context.Context, pool *pgxpool.Pool) (*PostgresRepository, error) {
	pr := &PostgresRepository{
		pool:        pool,
		mem:         NewMemoryRepository(),
		lookupCalls: make(map[string]*postgresLookupCall),
	}
	// Seed default global catalogue into PostgreSQL
	models, _ := pr.mem.ListGlobalModels(ctx)
	for _, m := range models {
		_ = pr.UpsertGlobalModel(ctx, m)
	}
	return pr, nil
}

// Ping verifies PostgreSQL database pool connectivity.
func (p *PostgresRepository) Ping(ctx context.Context) error {
	if p.pool == nil {
		return fmt.Errorf("postgres pool is uninitialized")
	}
	return p.pool.Ping(ctx)
}

func (p *PostgresRepository) UpsertGlobalModel(ctx context.Context, m *domain.GlobalModel) error {
	if err := p.mem.UpsertGlobalModel(ctx, m); err != nil {
		return err
	}
	if p.pool == nil {
		return nil
	}
	capsJSON, _ := json.Marshal(m.ResolveCapabilities())
	if len(capsJSON) == 0 {
		capsJSON = []byte("{}")
	}
	opsJSON, _ := json.Marshal(m.SupportedOperations)
	if len(opsJSON) == 0 || string(opsJSON) == "null" {
		opsJSON = []byte("[]")
	}
	modPricingJSON, _ := json.Marshal(m.ModalityPricingJSON)
	if len(modPricingJSON) == 0 || string(modPricingJSON) == "null" {
		modPricingJSON = []byte("{}")
	}
	const q = `
		INSERT INTO global_models (
			id, provider, model_name, display_name, max_input_tokens, max_output_tokens,
			supports_streaming, supports_tools, supports_vision, supports_reasoning, supports_embeddings,
			input_cost_micros_per_1m, output_cost_micros_per_1m, cached_input_cost_micros_per_1m,
			cache_write_cost_micros_per_1m, reasoning_cost_micros_per_1m,
			rerank_cost_micros_per_search_unit, image_cost_micros_base, image_cost_micros_hd,
			audio_stt_cost_micros_per_second, audio_tts_cost_micros_per_1k_chars, modality_pricing_json,
			pricing_version, pricing_status, pricing_provenance_source,
			pricing_effective_date, quality_tier, lifecycle_status, deprecation_date, capabilities, supported_operations,
			supports_inference, discovered_at, updated_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28,$29,$30,$31,$32,NOW(),NOW())
		ON CONFLICT (id) DO UPDATE SET
			display_name = EXCLUDED.display_name,
			max_input_tokens = EXCLUDED.max_input_tokens,
			max_output_tokens = EXCLUDED.max_output_tokens,
			supports_streaming = EXCLUDED.supports_streaming,
			supports_tools = EXCLUDED.supports_tools,
			supports_vision = EXCLUDED.supports_vision,
			supports_reasoning = EXCLUDED.supports_reasoning,
			supports_embeddings = EXCLUDED.supports_embeddings,
			input_cost_micros_per_1m = EXCLUDED.input_cost_micros_per_1m,
			output_cost_micros_per_1m = EXCLUDED.output_cost_micros_per_1m,
			cached_input_cost_micros_per_1m = EXCLUDED.cached_input_cost_micros_per_1m,
			cache_write_cost_micros_per_1m = EXCLUDED.cache_write_cost_micros_per_1m,
			reasoning_cost_micros_per_1m = EXCLUDED.reasoning_cost_micros_per_1m,
			rerank_cost_micros_per_search_unit = EXCLUDED.rerank_cost_micros_per_search_unit,
			image_cost_micros_base = EXCLUDED.image_cost_micros_base,
			image_cost_micros_hd = EXCLUDED.image_cost_micros_hd,
			audio_stt_cost_micros_per_second = EXCLUDED.audio_stt_cost_micros_per_second,
			audio_tts_cost_micros_per_1k_chars = EXCLUDED.audio_tts_cost_micros_per_1k_chars,
			modality_pricing_json = EXCLUDED.modality_pricing_json,
			pricing_version = EXCLUDED.pricing_version,
			pricing_status = EXCLUDED.pricing_status,
			pricing_provenance_source = EXCLUDED.pricing_provenance_source,
			pricing_effective_date = EXCLUDED.pricing_effective_date,
			quality_tier = EXCLUDED.quality_tier,
			lifecycle_status = EXCLUDED.lifecycle_status,
			deprecation_date = EXCLUDED.deprecation_date,
			capabilities = EXCLUDED.capabilities,
			supported_operations = EXCLUDED.supported_operations,
			supports_inference = EXCLUDED.supports_inference,
			updated_at = NOW()`
	pv := m.PricingVersion
	if pv <= 0 {
		pv = 1
	}
	pricingStatus := string(domain.ResolvePricingStatus(m))
	_, err := p.pool.Exec(ctx, q,
		m.ID, string(m.Provider), m.ModelName, m.DisplayName, m.MaxInputTokens, m.MaxOutputTokens,
		m.SupportsStreaming, m.SupportsTools, m.SupportsVision, m.SupportsReasoning, m.SupportsEmbeddings,
		m.InputCostMicrosPer1M, m.OutputCostMicrosPer1M, m.CachedInputCostMicrosPer1M,
		m.CacheWriteCostMicrosPer1M, m.ReasoningCostMicrosPer1M,
		m.RerankCostMicrosPerSearchUnit, m.ImageCostMicrosBase, m.ImageCostMicrosHD,
		m.AudioSTTCostMicrosPerSecond, m.AudioTTSCostMicrosPer1KChars, modPricingJSON,
		pv, pricingStatus, m.PricingProvenanceSource,
		m.PricingEffectiveDate, m.QualityTier, string(m.LifecycleStatus), m.DeprecationDate, capsJSON, opsJSON,
		m.SupportsInference,
	)
	return err
}

const globalModelSelectCols = `id, provider, model_name, display_name, max_input_tokens, max_output_tokens, supports_streaming, supports_tools, supports_vision, supports_reasoning, supports_embeddings, input_cost_micros_per_1m, output_cost_micros_per_1m, cached_input_cost_micros_per_1m, cache_write_cost_micros_per_1m, reasoning_cost_micros_per_1m, rerank_cost_micros_per_search_unit, image_cost_micros_base, image_cost_micros_hd, audio_stt_cost_micros_per_second, audio_tts_cost_micros_per_1k_chars, COALESCE(modality_pricing_json, '{}'::jsonb), pricing_version, COALESCE(pricing_status, 'unknown'), COALESCE(pricing_provenance_source, ''), COALESCE(pricing_effective_date, ''), COALESCE(quality_tier, 0), lifecycle_status, deprecation_date, COALESCE(capabilities, '{}'::jsonb), COALESCE(supported_operations, '[]'::jsonb), supports_inference`

func scanGlobalModel(row rowScanner) (*domain.GlobalModel, error) {
	var m domain.GlobalModel
	var prov, status, pricingStatus string
	var rawCaps, rawOps, rawModPricing []byte
	if err := row.Scan(
		&m.ID, &prov, &m.ModelName, &m.DisplayName, &m.MaxInputTokens, &m.MaxOutputTokens,
		&m.SupportsStreaming, &m.SupportsTools, &m.SupportsVision, &m.SupportsReasoning, &m.SupportsEmbeddings,
		&m.InputCostMicrosPer1M, &m.OutputCostMicrosPer1M, &m.CachedInputCostMicrosPer1M,
		&m.CacheWriteCostMicrosPer1M, &m.ReasoningCostMicrosPer1M,
		&m.RerankCostMicrosPerSearchUnit, &m.ImageCostMicrosBase, &m.ImageCostMicrosHD,
		&m.AudioSTTCostMicrosPerSecond, &m.AudioTTSCostMicrosPer1KChars, &rawModPricing,
		&m.PricingVersion, &pricingStatus, &m.PricingProvenanceSource,
		&m.PricingEffectiveDate, &m.QualityTier, &status, &m.DeprecationDate, &rawCaps, &rawOps, &m.SupportsInference,
	); err != nil {
		return nil, err
	}
	m.Provider = domain.ProviderType(prov)
	m.PricingStatus = domain.PricingStatus(pricingStatus)
	m.LifecycleStatus = domain.ModelLifecycleStatus(status)
	if len(rawCaps) > 0 {
		_ = json.Unmarshal(rawCaps, &m.Capabilities)
	}
	if len(rawOps) > 0 {
		_ = json.Unmarshal(rawOps, &m.SupportedOperations)
	}
	if len(rawModPricing) > 0 {
		_ = json.Unmarshal(rawModPricing, &m.ModalityPricingJSON)
	}
	return &m, nil
}

func (p *PostgresRepository) GetGlobalModel(ctx context.Context, id string) (*domain.GlobalModel, error) {
	if p.pool == nil {
		return p.mem.GetGlobalModel(ctx, id)
	}
	const q = `SELECT ` + globalModelSelectCols + ` FROM global_models WHERE id = $1`
	m, err := scanGlobalModel(p.pool.QueryRow(ctx, q, id))
	if err != nil {
		return nil, fmt.Errorf("global model not found: %w", err)
	}
	_ = p.mem.UpsertGlobalModel(ctx, m)
	return m, nil
}

func (p *PostgresRepository) hydrateGlobalModels(ctx context.Context, ids []string) error {
	if len(ids) == 0 {
		return nil
	}
	const q = `SELECT ` + globalModelSelectCols + ` FROM global_models WHERE id = ANY($1)`
	rows, err := p.pool.Query(ctx, q, ids)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		m, err := scanGlobalModel(rows)
		if err != nil {
			return err
		}
		_ = p.mem.UpsertGlobalModel(ctx, m)
	}
	return rows.Err()
}

func (p *PostgresRepository) ListGlobalModels(ctx context.Context) ([]*domain.GlobalModel, error) {
	if p.pool == nil {
		return p.mem.ListGlobalModels(ctx)
	}
	const q = `SELECT ` + globalModelSelectCols + ` FROM global_models ORDER BY id ASC`
	rows, err := p.pool.Query(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*domain.GlobalModel
	for rows.Next() {
		m, err := scanGlobalModel(rows)
		if err != nil {
			return nil, err
		}
		_ = p.mem.UpsertGlobalModel(ctx, m)
		out = append(out, m)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func (p *PostgresRepository) ListGlobalModelsByName(ctx context.Context, provider domain.ProviderType, modelName string) ([]*domain.GlobalModel, error) {
	if p.pool == nil {
		return p.mem.ListGlobalModelsByName(ctx, provider, modelName)
	}
	var (
		rows pgx.Rows
		err  error
	)
	if provider != "" {
		const q = `SELECT ` + globalModelSelectCols + ` FROM global_models WHERE provider = $1 AND model_name = $2`
		rows, err = p.pool.Query(ctx, q, string(provider), modelName)
	} else {
		const q = `SELECT ` + globalModelSelectCols + ` FROM global_models WHERE model_name = $1`
		rows, err = p.pool.Query(ctx, q, modelName)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*domain.GlobalModel
	for rows.Next() {
		m, err := scanGlobalModel(rows)
		if err != nil {
			return nil, err
		}
		_ = p.mem.UpsertGlobalModel(ctx, m)
		out = append(out, m)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func (p *PostgresRepository) GlobalModelCatalogSize() int {
	return p.mem.GlobalModelCatalogSize()
}

func (p *PostgresRepository) GetGlobalModelPricingSummary(ctx context.Context) (GlobalModelPricingSummary, error) {
	return p.mem.GetGlobalModelPricingSummary(ctx)
}

func (p *PostgresRepository) PricingSummaryRebuilds() uint64 {
	return p.mem.PricingSummaryRebuilds()
}

func (p *PostgresRepository) UpdateModelPricing(ctx context.Context, modelID string, inputMicros, outputMicros, cachedMicros, reasoningMicros int64, status domain.PricingStatus, provenance, effectiveDate, changedBy string) (*domain.GlobalModel, error) {
	if p.pool != nil {
		if _, err := p.GetGlobalModel(ctx, modelID); err != nil {
			_, _ = p.ListGlobalModelsByName(ctx, "", modelID)
		}
	}
	gm, err := p.mem.UpdateModelPricing(ctx, modelID, inputMicros, outputMicros, cachedMicros, reasoningMicros, status, provenance, effectiveDate, changedBy)
	if err != nil {
		return nil, err
	}
	_, _ = p.pool.Exec(ctx, `
		UPDATE global_models SET
			pricing_version = $2,
			input_cost_micros_per_1m = $3,
			output_cost_micros_per_1m = $4,
			cached_input_cost_micros_per_1m = $5,
			reasoning_cost_micros_per_1m = $6,
			pricing_status = $7,
			pricing_provenance_source = $8,
			pricing_effective_date = $9,
			updated_at = NOW()
		WHERE id = $1`,
		gm.ID, gm.PricingVersion, gm.InputCostMicrosPer1M, gm.OutputCostMicrosPer1M, gm.CachedInputCostMicrosPer1M, gm.ReasoningCostMicrosPer1M,
		string(gm.PricingStatus), gm.PricingProvenanceSource, gm.PricingEffectiveDate,
	)
	histID := uuid.NewString()
	_, _ = p.pool.Exec(ctx, `
		INSERT INTO model_pricing_history (
			id, global_model_id, pricing_version, input_cost_micros_per_1m, output_cost_micros_per_1m,
			cached_input_cost_micros_per_1m, reasoning_cost_micros_per_1m, pricing_status, pricing_provenance_source, changed_by, effective_from
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,NOW())`,
		histID, gm.ID, gm.PricingVersion, gm.InputCostMicrosPer1M, gm.OutputCostMicrosPer1M,
		gm.CachedInputCostMicrosPer1M, gm.ReasoningCostMicrosPer1M, string(gm.PricingStatus), gm.PricingProvenanceSource, changedBy,
	)
	return gm, nil
}

func (p *PostgresRepository) ListModelPricingHistory(ctx context.Context, modelID string) ([]*domain.ModelPricingHistory, error) {
	return p.mem.ListModelPricingHistory(ctx, modelID)
}

func marshalBudgetFallbacks(fallbacks map[string][]string) []byte {
	if len(fallbacks) == 0 {
		return []byte("{}")
	}
	b, err := json.Marshal(fallbacks)
	if err != nil || len(b) == 0 || string(b) == "null" {
		return []byte("{}")
	}
	return b
}

func unmarshalBudgetFallbacks(raw []byte) map[string][]string {
	if len(raw) == 0 {
		return nil
	}
	var m map[string][]string
	if err := json.Unmarshal(raw, &m); err != nil || len(m) == 0 {
		return nil
	}
	return m
}

func intsToInt32(in []int) []int32 {
	if in == nil {
		return nil
	}
	out := make([]int32, len(in))
	for i, v := range in {
		out[i] = int32(v)
	}
	return out
}

func int32sToInts(in []int32) []int {
	if in == nil {
		return nil
	}
	out := make([]int, len(in))
	for i, v := range in {
		out[i] = int(v)
	}
	return out
}

const orgSelectCols = `id, name, slug, max_budget_micros, temp_budget_increase_micros, temp_budget_expires_at, COALESCE(NULLIF(self_serve_budget_policy, ''), 'disabled'), soft_budget_micros, throttle_on_budget_exceeded, COALESCE(budget_fallbacks, '{}'::jsonb), spent_micros, budget_reset_period, budget_reset_at, rpm_limit, tpm_limit, max_concurrent_requests, batch_enqueued_token_limit, max_iterations, max_budget_per_session_micros, enforce_guaranteed_throughput, developer_self_serve_keys, COALESCE(key_expiry_alert_days, '{7,1}'), COALESCE(lifecycle_webhook_url, ''), is_active`

func scanOrganization(row rowScanner) (*domain.Organization, error) {
	var o domain.Organization
	var period, selfServePolicy string
	var rawFallbacks []byte
	var alertDays []int32
	if err := row.Scan(
		&o.ID, &o.Name, &o.Slug, &o.MaxBudgetMicros, &o.TempBudgetIncreaseMicros, &o.TempBudgetExpiresAt, &selfServePolicy, &o.SoftBudgetMicros, &o.ThrottleOnBudgetExceeded, &rawFallbacks, &o.SpentMicros, &period, &o.BudgetResetAt, &o.RPMLimit, &o.TPMLimit, &o.MaxConcurrentRequests, &o.BatchEnqueuedTokenLimit, &o.MaxIterations, &o.MaxBudgetPerSessionMicros, &o.EnforceGuaranteedThroughput, &o.DeveloperSelfServeKeys, &alertDays, &o.LifecycleWebhookURL, &o.IsActive,
	); err != nil {
		return nil, err
	}
	o.BudgetResetPeriod = domain.BudgetResetPeriod(period)
	o.SelfServeBudgetPolicy = domain.SelfServeBudgetPolicy(selfServePolicy)
	o.BudgetFallbacks = unmarshalBudgetFallbacks(rawFallbacks)
	o.KeyExpiryAlertDays = int32sToInts(alertDays)
	return &o, nil
}

func (p *PostgresRepository) CreateOrganization(ctx context.Context, org *domain.Organization) error {
	if org.ID == "" {
		org.ID = uuid.NewString()
	}
	if org.SelfServeBudgetPolicy == "" {
		org.SelfServeBudgetPolicy = domain.SelfServeBudgetDisabled
	} else {
		pol := domain.SelfServeBudgetPolicy(strings.ToLower(strings.TrimSpace(string(org.SelfServeBudgetPolicy))))
		if !pol.IsValid() {
			return fmt.Errorf("invalid self_serve_budget_policy %q", org.SelfServeBudgetPolicy)
		}
		org.SelfServeBudgetPolicy = pol
	}
	alertDays := org.KeyExpiryAlertDays
	if alertDays == nil {
		alertDays = []int{7, 1}
		org.KeyExpiryAlertDays = alertDays
	}
	org.BudgetResetPeriod, org.BudgetResetAt = resolveBudgetResetSchedule(org.BudgetResetPeriod, org.BudgetResetAt, time.Now().UTC())
	if p.pool == nil {
		return p.mem.CreateOrganization(ctx, org)
	}
	const q = `
		INSERT INTO organizations (id, name, slug, max_budget_micros, temp_budget_increase_micros, temp_budget_expires_at, self_serve_budget_policy, soft_budget_micros, throttle_on_budget_exceeded, budget_fallbacks, spent_micros, budget_reset_period, budget_reset_at, rpm_limit, tpm_limit, max_concurrent_requests, batch_enqueued_token_limit, max_iterations, max_budget_per_session_micros, enforce_guaranteed_throughput, developer_self_serve_keys, key_expiry_alert_days, lifecycle_webhook_url, is_active)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24)`
	if _, err := p.pool.Exec(ctx, q, org.ID, org.Name, org.Slug, org.MaxBudgetMicros, org.TempBudgetIncreaseMicros, org.TempBudgetExpiresAt, string(org.SelfServeBudgetPolicy), org.SoftBudgetMicros, org.ThrottleOnBudgetExceeded, marshalBudgetFallbacks(org.BudgetFallbacks), org.SpentMicros, string(org.BudgetResetPeriod), org.BudgetResetAt, org.RPMLimit, org.TPMLimit, org.MaxConcurrentRequests, org.BatchEnqueuedTokenLimit, org.MaxIterations, org.MaxBudgetPerSessionMicros, org.EnforceGuaranteedThroughput, org.DeveloperSelfServeKeys, intsToInt32(alertDays), org.LifecycleWebhookURL, org.IsActive); err != nil {
		return err
	}
	return p.mem.CreateOrganization(ctx, org)
}

func (p *PostgresRepository) UpdateOrganization(ctx context.Context, org *domain.Organization) error {
	if org == nil || org.ID == "" {
		return fmt.Errorf("organization id is required")
	}
	if org.SelfServeBudgetPolicy == "" {
		org.SelfServeBudgetPolicy = domain.SelfServeBudgetDisabled
	} else {
		pol := domain.SelfServeBudgetPolicy(strings.ToLower(strings.TrimSpace(string(org.SelfServeBudgetPolicy))))
		if !pol.IsValid() {
			return fmt.Errorf("invalid self_serve_budget_policy %q", org.SelfServeBudgetPolicy)
		}
		org.SelfServeBudgetPolicy = pol
	}
	alertDays := org.KeyExpiryAlertDays
	if alertDays == nil {
		alertDays = []int{7, 1}
		org.KeyExpiryAlertDays = alertDays
	}
	org.BudgetResetPeriod, org.BudgetResetAt = resolveBudgetResetSchedule(org.BudgetResetPeriod, org.BudgetResetAt, time.Now().UTC())
	if p.pool != nil {
		const q = `
			UPDATE organizations SET
				name = $2,
				slug = COALESCE(NULLIF($3, ''), slug),
				max_budget_micros = $4,
				temp_budget_increase_micros = $5,
				temp_budget_expires_at = $6,
				self_serve_budget_policy = $7,
				soft_budget_micros = $8,
				throttle_on_budget_exceeded = $9,
				budget_fallbacks = $10,
				spent_micros = $11,
				budget_reset_period = $12,
				budget_reset_at = $13,
				rpm_limit = $14,
				tpm_limit = $15,
				max_concurrent_requests = $16,
				batch_enqueued_token_limit = $17,
				max_iterations = $18,
				max_budget_per_session_micros = $19,
				enforce_guaranteed_throughput = $20,
				developer_self_serve_keys = $21,
				key_expiry_alert_days = $22,
				lifecycle_webhook_url = $23,
				is_active = $24,
				updated_at = NOW()
			WHERE id = $1`
		tag, err := p.pool.Exec(ctx, q,
			org.ID, org.Name, org.Slug, org.MaxBudgetMicros, org.TempBudgetIncreaseMicros, org.TempBudgetExpiresAt,
			string(org.SelfServeBudgetPolicy), org.SoftBudgetMicros, org.ThrottleOnBudgetExceeded, marshalBudgetFallbacks(org.BudgetFallbacks),
			org.SpentMicros, string(org.BudgetResetPeriod), org.BudgetResetAt, org.RPMLimit, org.TPMLimit,
			org.MaxConcurrentRequests, org.BatchEnqueuedTokenLimit, org.MaxIterations, org.MaxBudgetPerSessionMicros,
			org.EnforceGuaranteedThroughput, org.DeveloperSelfServeKeys, intsToInt32(alertDays), org.LifecycleWebhookURL, org.IsActive,
		)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return fmt.Errorf("organization %q %w", org.ID, ErrNotFound)
		}
	}
	if err := p.mem.UpdateOrganization(ctx, org); err != nil {
		if p.pool == nil {
			return err
		}
		_ = p.mem.CreateOrganization(ctx, org)
	}
	return nil
}

func (p *PostgresRepository) GetOrganization(ctx context.Context, id string) (*domain.Organization, error) {
	if p.pool == nil {
		return p.mem.GetOrganization(ctx, id)
	}
	const q = `SELECT ` + orgSelectCols + ` FROM organizations WHERE id = $1`
	o, err := scanOrganization(p.pool.QueryRow(ctx, q, id))
	if err != nil {
		return nil, fmt.Errorf("organization not found: %w", err)
	}
	_ = p.mem.CreateOrganization(ctx, o)
	return o, nil
}

func (p *PostgresRepository) ListOrganizations(ctx context.Context) ([]*domain.Organization, error) {
	if p.pool == nil {
		return p.mem.ListOrganizations(ctx)
	}
	const q = `SELECT ` + orgSelectCols + ` FROM organizations ORDER BY name ASC`
	rows, err := p.pool.Query(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*domain.Organization
	for rows.Next() {
		o, err := scanOrganization(rows)
		if err != nil {
			return nil, err
		}
		_ = p.mem.CreateOrganization(ctx, o)
		out = append(out, o)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func (p *PostgresRepository) SetOrgProviderSubscription(ctx context.Context, sub *domain.OrgProviderSubscription) error {
	const q = `
		INSERT INTO org_provider_subscriptions (org_id, provider, is_enabled, auto_enable_new, subscribed_at)
		VALUES ($1,$2,$3,$4,NOW())
		ON CONFLICT (org_id, provider) DO UPDATE SET is_enabled = EXCLUDED.is_enabled, auto_enable_new = EXCLUDED.auto_enable_new`
	if _, err := p.pool.Exec(ctx, q, sub.OrgID, string(sub.Provider), sub.IsEnabled, sub.AutoEnableNew); err != nil {
		return err
	}
	return p.mem.SetOrgProviderSubscription(ctx, sub)
}

func (p *PostgresRepository) GetOrgProviderSubscriptions(ctx context.Context, orgID string) ([]*domain.OrgProviderSubscription, error) {
	if p.pool == nil {
		return p.mem.GetOrgProviderSubscriptions(ctx, orgID)
	}
	value, err := p.coalesceLookup(ctx, "subscriptions:"+orgID, func(lookupCtx context.Context) (any, error) {
		p.subscriptionQueries.Add(1)
		const q = `SELECT org_id, provider, is_enabled, auto_enable_new, subscribed_at FROM org_provider_subscriptions WHERE org_id = $1`
		rows, queryErr := p.pool.Query(lookupCtx, q, orgID)
		if queryErr != nil {
			return nil, queryErr
		}
		defer rows.Close()
		var out []*domain.OrgProviderSubscription
		for rows.Next() {
			var s domain.OrgProviderSubscription
			var prov string
			if scanErr := rows.Scan(&s.OrgID, &prov, &s.IsEnabled, &s.AutoEnableNew, &s.SubscribedAt); scanErr != nil {
				return nil, scanErr
			}
			s.Provider = domain.ProviderType(prov)
			if p.mem != nil {
				_ = p.mem.SetOrgProviderSubscription(lookupCtx, &s)
			}
			out = append(out, &s)
		}
		if rowsErr := rows.Err(); rowsErr != nil {
			return nil, rowsErr
		}
		if len(out) == 0 {
			p.emptySubscriptionQueries.Add(1)
		}
		return out, nil
	})
	if err != nil {
		return nil, err
	}
	result, _ := value.([]*domain.OrgProviderSubscription)
	return result, nil
}

func (p *PostgresRepository) SetOrgModelPolicy(ctx context.Context, pol *domain.OrgModelPolicy) error {
	const q = `
		INSERT INTO org_model_policies (org_id, global_model_id, is_enabled, approved_by, approved_at)
		VALUES ($1,$2,$3,$4,NOW())
		ON CONFLICT (org_id, global_model_id) DO UPDATE SET is_enabled = EXCLUDED.is_enabled`
	if _, err := p.pool.Exec(ctx, q, pol.OrgID, pol.GlobalModelID, pol.IsEnabled, pol.ApprovedBy); err != nil {
		return err
	}
	return p.mem.SetOrgModelPolicy(ctx, pol)
}

func (p *PostgresRepository) GetOrgModelPolicies(ctx context.Context, orgID string) ([]*domain.OrgModelPolicy, error) {
	if p.pool == nil {
		return p.mem.GetOrgModelPolicies(ctx, orgID)
	}
	const q = `SELECT org_id, global_model_id, is_enabled, approved_by, approved_at FROM org_model_policies WHERE org_id = $1`
	rows, err := p.pool.Query(ctx, q, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*domain.OrgModelPolicy
	for rows.Next() {
		var pol domain.OrgModelPolicy
		if err := rows.Scan(&pol.OrgID, &pol.GlobalModelID, &pol.IsEnabled, &pol.ApprovedBy, &pol.ApprovedAt); err != nil {
			return nil, err
		}
		_ = p.mem.SetOrgModelPolicy(ctx, &pol)
		out = append(out, &pol)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

type rowScanner interface {
	Scan(dest ...any) error
}

const teamSelectCols = `id, org_id, name, max_budget_micros, temp_budget_increase_micros, temp_budget_expires_at, soft_budget_micros, throttle_on_budget_exceeded, COALESCE(budget_fallbacks, '{}'::jsonb), spent_micros, budget_reset_period, budget_reset_at, rpm_limit, tpm_limit, mcp_rpm_limit, max_concurrent_requests, batch_enqueued_token_limit, max_iterations, max_budget_per_session_micros, enforce_guaranteed_throughput, default_member_max_budget_micros, default_member_rpm_limit, default_member_tpm_limit, COALESCE(default_member_allowed_models, '{}'), COALESCE(team_member_permissions, '{}'), allowed_models, allowed_mcp_servers, allowed_a2a_agents, allowed_client_apps, is_active, created_at, updated_at`

func scanTeam(row rowScanner) (*domain.Team, error) {
	var t domain.Team
	var period string
	var rawFallbacks []byte
	if err := row.Scan(
		&t.ID, &t.OrgID, &t.Name, &t.MaxBudgetMicros, &t.TempBudgetIncreaseMicros, &t.TempBudgetExpiresAt, &t.SoftBudgetMicros, &t.ThrottleOnBudgetExceeded, &rawFallbacks, &t.SpentMicros, &period, &t.BudgetResetAt,
		&t.RPMLimit, &t.TPMLimit, &t.MCPRPMLimit, &t.MaxConcurrentRequests, &t.BatchEnqueuedTokenLimit, &t.MaxIterations, &t.MaxBudgetPerSessionMicros,
		&t.EnforceGuaranteedThroughput, &t.DefaultMemberMaxBudgetMicros, &t.DefaultMemberRPMLimit, &t.DefaultMemberTPMLimit, &t.DefaultMemberAllowedModels, &t.TeamMemberPermissions,
		&t.AllowedModels, &t.AllowedMCPServers, &t.AllowedA2AAgents, &t.AllowedClientApps,
		&t.IsActive, &t.CreatedAt, &t.UpdatedAt,
	); err != nil {
		return nil, err
	}
	t.BudgetResetPeriod = domain.BudgetResetPeriod(period)
	t.BudgetFallbacks = unmarshalBudgetFallbacks(rawFallbacks)
	return &t, nil
}

func (p *PostgresRepository) CreateTeam(ctx context.Context, team *domain.Team) error {
	if team.ID == "" {
		team.ID = uuid.NewString()
	}
	team.BudgetResetPeriod, team.BudgetResetAt = resolveBudgetResetSchedule(team.BudgetResetPeriod, team.BudgetResetAt, time.Now().UTC())
	allowedModels := team.AllowedModels
	if allowedModels == nil {
		allowedModels = []string{}
	}
	defaultMemberAllowedModels := team.DefaultMemberAllowedModels
	if defaultMemberAllowedModels == nil {
		defaultMemberAllowedModels = []string{}
	}
	teamMemberPermissions := team.TeamMemberPermissions
	if teamMemberPermissions == nil {
		teamMemberPermissions = []string{}
	}
	if p.pool == nil {
		return p.mem.CreateTeam(ctx, team)
	}
	const q = `
		INSERT INTO teams (
			id, org_id, name, max_budget_micros, temp_budget_increase_micros, temp_budget_expires_at, soft_budget_micros, throttle_on_budget_exceeded, budget_fallbacks, spent_micros, budget_reset_period, budget_reset_at,
			rpm_limit, tpm_limit, mcp_rpm_limit, max_concurrent_requests, batch_enqueued_token_limit, max_iterations, max_budget_per_session_micros,
			enforce_guaranteed_throughput, default_member_max_budget_micros, default_member_rpm_limit, default_member_tpm_limit, default_member_allowed_models, team_member_permissions,
			allowed_models, allowed_mcp_servers, allowed_a2a_agents, allowed_client_apps, is_active
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28,$29,$30)`
	if _, err := p.pool.Exec(ctx, q,
		team.ID, team.OrgID, team.Name, team.MaxBudgetMicros, team.TempBudgetIncreaseMicros, team.TempBudgetExpiresAt, team.SoftBudgetMicros, team.ThrottleOnBudgetExceeded, marshalBudgetFallbacks(team.BudgetFallbacks), team.SpentMicros, string(team.BudgetResetPeriod), team.BudgetResetAt,
		team.RPMLimit, team.TPMLimit, team.MCPRPMLimit, team.MaxConcurrentRequests, team.BatchEnqueuedTokenLimit, team.MaxIterations, team.MaxBudgetPerSessionMicros,
		team.EnforceGuaranteedThroughput, team.DefaultMemberMaxBudgetMicros, team.DefaultMemberRPMLimit, team.DefaultMemberTPMLimit, defaultMemberAllowedModels, teamMemberPermissions,
		allowedModels, team.AllowedMCPServers, team.AllowedA2AAgents, team.AllowedClientApps, team.IsActive,
	); err != nil {
		return err
	}
	return p.mem.CreateTeam(ctx, team)
}

func (p *PostgresRepository) UpdateTeam(ctx context.Context, team *domain.Team) error {
	if team == nil || team.ID == "" {
		return fmt.Errorf("team id is required")
	}
	team.BudgetResetPeriod, team.BudgetResetAt = resolveBudgetResetSchedule(team.BudgetResetPeriod, team.BudgetResetAt, time.Now().UTC())
	allowedModels := team.AllowedModels
	if allowedModels == nil {
		allowedModels = []string{}
	}
	defaultMemberAllowedModels := team.DefaultMemberAllowedModels
	if defaultMemberAllowedModels == nil {
		defaultMemberAllowedModels = []string{}
	}
	teamMemberPermissions := team.TeamMemberPermissions
	if teamMemberPermissions == nil {
		teamMemberPermissions = []string{}
	}
	const q = `
		UPDATE teams SET
			name = $2, max_budget_micros = $3, temp_budget_increase_micros = $4, temp_budget_expires_at = $5,
			soft_budget_micros = $6, throttle_on_budget_exceeded = $7, budget_fallbacks = $8,
			spent_micros = $9, budget_reset_period = $10, budget_reset_at = $11,
			rpm_limit = $12, tpm_limit = $13, mcp_rpm_limit = $14, max_concurrent_requests = $15, batch_enqueued_token_limit = $16,
			max_iterations = $17, max_budget_per_session_micros = $18,
			enforce_guaranteed_throughput = $19, default_member_max_budget_micros = $20, default_member_rpm_limit = $21, default_member_tpm_limit = $22, default_member_allowed_models = $23, team_member_permissions = $24,
			allowed_models = $25, allowed_mcp_servers = $26, allowed_a2a_agents = $27, allowed_client_apps = $28, is_active = $29,
			updated_at = NOW()
		WHERE id = $1`
	if p.pool != nil {
		tag, err := p.pool.Exec(ctx, q,
			team.ID, team.Name, team.MaxBudgetMicros, team.TempBudgetIncreaseMicros, team.TempBudgetExpiresAt,
			team.SoftBudgetMicros, team.ThrottleOnBudgetExceeded, marshalBudgetFallbacks(team.BudgetFallbacks),
			team.SpentMicros, string(team.BudgetResetPeriod), team.BudgetResetAt,
			team.RPMLimit, team.TPMLimit, team.MCPRPMLimit, team.MaxConcurrentRequests, team.BatchEnqueuedTokenLimit,
			team.MaxIterations, team.MaxBudgetPerSessionMicros,
			team.EnforceGuaranteedThroughput, team.DefaultMemberMaxBudgetMicros, team.DefaultMemberRPMLimit, team.DefaultMemberTPMLimit, defaultMemberAllowedModels, teamMemberPermissions,
			allowedModels, team.AllowedMCPServers, team.AllowedA2AAgents, team.AllowedClientApps, team.IsActive,
		)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return fmt.Errorf("team %q %w", team.ID, ErrNotFound)
		}
	}
	if err := p.mem.UpdateTeam(ctx, team); err != nil {
		if p.pool == nil {
			return err
		}
		_ = p.mem.CreateTeam(ctx, team)
	}
	return nil
}

func (p *PostgresRepository) GetTeam(ctx context.Context, id string) (*domain.Team, error) {
	if p.pool == nil {
		return p.mem.GetTeam(ctx, id)
	}
	const q = `SELECT ` + teamSelectCols + ` FROM teams WHERE id = $1`
	t, err := scanTeam(p.pool.QueryRow(ctx, q, id))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("team %q %w", id, ErrNotFound)
		}
		return nil, err
	}
	cp := cloneTeam(t)
	_ = p.mem.CreateTeam(ctx, cp)
	return t, nil
}

func (p *PostgresRepository) GetTeamByName(ctx context.Context, orgID, name string) (*domain.Team, error) {
	orgID = strings.TrimSpace(orgID)
	name = strings.TrimSpace(name)
	if orgID == "" || name == "" {
		return nil, fmt.Errorf("team with org_id %q and name %q %w", orgID, name, ErrNotFound)
	}
	if p.pool == nil {
		return p.mem.GetTeamByName(ctx, orgID, name)
	}
	const q = `SELECT ` + teamSelectCols + ` FROM teams WHERE org_id = $1 AND name = $2 LIMIT 1`
	t, err := scanTeam(p.pool.QueryRow(ctx, q, orgID, name))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("team with org_id %q and name %q %w", orgID, name, ErrNotFound)
		}
		return nil, err
	}
	cp := cloneTeam(t)
	_ = p.mem.CreateTeam(ctx, cp)
	return t, nil
}

func (p *PostgresRepository) ListTeams(ctx context.Context, orgID string) ([]*domain.Team, error) {
	const q = `SELECT ` + teamSelectCols + ` FROM teams WHERE org_id = $1 ORDER BY created_at ASC`
	rows, err := p.pool.Query(ctx, q, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var teams []*domain.Team
	for rows.Next() {
		t, err := scanTeam(rows)
		if err != nil {
			return nil, err
		}
		teams = append(teams, t)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return teams, nil
}

func (p *PostgresRepository) DeleteTeam(ctx context.Context, id string) error {
	if p.pool != nil {
		tag, err := p.pool.Exec(ctx, `DELETE FROM teams WHERE id = $1`, id)
		if err != nil {
			var pgErr *pgconn.PgError
			if errors.As(err, &pgErr) && pgErr.Code == "23503" {
				if hasPTU, checkErr := p.HasTeamPTUShares(ctx, id); checkErr == nil && hasPTU {
					return fmt.Errorf("team %q cannot be deleted while it holds active PTU shares: %w", id, ErrTeamHasActivePTUShares)
				}
			}
			return err
		}
		if tag.RowsAffected() == 0 {
			return fmt.Errorf("team %q %w", id, ErrNotFound)
		}
		_ = p.mem.DeleteTeam(ctx, id)
		return nil
	}
	return p.mem.DeleteTeam(ctx, id)
}

const teamMembershipSelectCols = `id, org_id, team_id, user_id, role, max_budget_micros, spent_micros, rpm_limit, tpm_limit, COALESCE(allowed_models, '{}'), created_at, updated_at`

func scanTeamMembership(row rowScanner) (*domain.TeamMembership, error) {
	var m domain.TeamMembership
	var role string
	if err := row.Scan(
		&m.ID, &m.OrgID, &m.TeamID, &m.UserID, &role,
		&m.MaxBudgetMicros, &m.SpentMicros, &m.RPMLimit, &m.TPMLimit,
		&m.AllowedModels, &m.CreatedAt, &m.UpdatedAt,
	); err != nil {
		return nil, err
	}
	m.Role = domain.Role(role)
	if m.AllowedModels == nil {
		m.AllowedModels = []string{}
	}
	return &m, nil
}

func (p *PostgresRepository) UpsertTeamMembership(ctx context.Context, m *domain.TeamMembership) error {
	if err := normalizeTeamMembership(m); err != nil {
		return err
	}
	if p.pool == nil {
		return p.mem.UpsertTeamMembership(ctx, m)
	}
	if m.ID == "" {
		m.ID = uuid.NewString()
	}
	const q = `
		INSERT INTO team_memberships (
			id, org_id, team_id, user_id, role,
			max_budget_micros, spent_micros, rpm_limit, tpm_limit, allowed_models
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		ON CONFLICT (team_id, user_id) DO UPDATE SET
			org_id = EXCLUDED.org_id,
			role = EXCLUDED.role,
			max_budget_micros = EXCLUDED.max_budget_micros,
			spent_micros = GREATEST(team_memberships.spent_micros, EXCLUDED.spent_micros),
			rpm_limit = EXCLUDED.rpm_limit,
			tpm_limit = EXCLUDED.tpm_limit,
			allowed_models = EXCLUDED.allowed_models,
			updated_at = NOW()
		RETURNING id, spent_micros, created_at, updated_at`
	if err := p.pool.QueryRow(ctx, q,
		m.ID, m.OrgID, m.TeamID, m.UserID, string(m.Role),
		m.MaxBudgetMicros, m.SpentMicros, m.RPMLimit, m.TPMLimit, m.AllowedModels,
	).Scan(&m.ID, &m.SpentMicros, &m.CreatedAt, &m.UpdatedAt); err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return fmt.Errorf("team membership conflict: %w", ErrConflict)
		}
		return err
	}
	_ = p.mem.UpsertTeamMembership(ctx, m)
	return nil
}

func (p *PostgresRepository) GetTeamMembership(ctx context.Context, teamID, userID string) (*domain.TeamMembership, error) {
	if p.pool == nil {
		return p.mem.GetTeamMembership(ctx, teamID, userID)
	}
	m, err := scanTeamMembership(p.pool.QueryRow(ctx,
		`SELECT `+teamMembershipSelectCols+` FROM team_memberships WHERE team_id = $1 AND user_id = $2`,
		strings.TrimSpace(teamID), strings.TrimSpace(userID),
	))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("team membership (%q, %q) %w", teamID, userID, ErrNotFound)
		}
		return nil, err
	}
	return m, nil
}

func (p *PostgresRepository) ListTeamMemberships(ctx context.Context, orgID, teamID, userID string) ([]*domain.TeamMembership, error) {
	if p.pool == nil {
		return p.mem.ListTeamMemberships(ctx, orgID, teamID, userID)
	}
	var conds []string
	var args []any
	addCond := func(col, val string) {
		if v := strings.TrimSpace(val); v != "" {
			args = append(args, v)
			conds = append(conds, fmt.Sprintf("%s = $%d", col, len(args)))
		}
	}
	addCond("org_id", orgID)
	addCond("team_id", teamID)
	addCond("user_id", userID)

	q := `SELECT ` + teamMembershipSelectCols + ` FROM team_memberships`
	if len(conds) > 0 {
		q += ` WHERE ` + strings.Join(conds, " AND ")
	}
	q += ` ORDER BY created_at ASC, id ASC`

	rows, err := p.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*domain.TeamMembership
	for rows.Next() {
		m, scanErr := scanTeamMembership(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

func (p *PostgresRepository) DeleteTeamMembership(ctx context.Context, teamID, userID string) error {
	if p.pool == nil {
		return p.mem.DeleteTeamMembership(ctx, teamID, userID)
	}
	tag, err := p.pool.Exec(ctx,
		`DELETE FROM team_memberships WHERE team_id = $1 AND user_id = $2`,
		strings.TrimSpace(teamID), strings.TrimSpace(userID),
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("team membership (%q, %q) %w", teamID, userID, ErrNotFound)
	}
	_ = p.mem.DeleteTeamMembership(ctx, teamID, userID)
	return nil
}

func (p *PostgresRepository) BulkSyncTeamMemberships(ctx context.Context, orgID, teamID string, upserts []*domain.TeamMembership, removeUserIDs []string) ([]*domain.TeamMembership, int, error) {
	if p.pool == nil {
		return p.mem.BulkSyncTeamMemberships(ctx, orgID, teamID, upserts, removeUserIDs)
	}
	orgID = strings.TrimSpace(orgID)
	teamID = strings.TrimSpace(teamID)

	tx, err := p.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	const upsertQ = `
		INSERT INTO team_memberships (
			id, org_id, team_id, user_id, role,
			max_budget_micros, spent_micros, rpm_limit, tpm_limit, allowed_models
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		ON CONFLICT (team_id, user_id) DO UPDATE SET
			org_id = EXCLUDED.org_id,
			role = EXCLUDED.role,
			max_budget_micros = EXCLUDED.max_budget_micros,
			spent_micros = GREATEST(team_memberships.spent_micros, EXCLUDED.spent_micros),
			rpm_limit = EXCLUDED.rpm_limit,
			tpm_limit = EXCLUDED.tpm_limit,
			allowed_models = EXCLUDED.allowed_models,
			updated_at = NOW()
		RETURNING id, spent_micros, created_at, updated_at`

	results := make([]*domain.TeamMembership, 0, len(upserts))
	for _, entry := range upserts {
		if entry == nil {
			continue
		}
		cp := *entry
		cp.OrgID = orgID
		cp.TeamID = teamID
		if err := normalizeTeamMembership(&cp); err != nil {
			return nil, 0, err
		}
		if cp.ID == "" {
			cp.ID = uuid.NewString()
		}
		if err := tx.QueryRow(ctx, upsertQ,
			cp.ID, cp.OrgID, cp.TeamID, cp.UserID, string(cp.Role),
			cp.MaxBudgetMicros, cp.SpentMicros, cp.RPMLimit, cp.TPMLimit, cp.AllowedModels,
		).Scan(&cp.ID, &cp.SpentMicros, &cp.CreatedAt, &cp.UpdatedAt); err != nil {
			var pgErr *pgconn.PgError
			if errors.As(err, &pgErr) && pgErr.Code == "23505" {
				return nil, 0, fmt.Errorf("team membership conflict: %w", ErrConflict)
			}
			return nil, 0, err
		}
		results = append(results, &cp)
	}

	cleanedRemovals := make([]string, 0, len(removeUserIDs))
	for _, rawUID := range removeUserIDs {
		if uid := strings.TrimSpace(rawUID); uid != "" {
			cleanedRemovals = append(cleanedRemovals, uid)
		}
	}
	var removed int
	if len(cleanedRemovals) > 0 {
		tag, err := tx.Exec(ctx, `DELETE FROM team_memberships WHERE team_id = $1 AND user_id = ANY($2)`, teamID, cleanedRemovals)
		if err != nil {
			return nil, 0, err
		}
		removed = int(tag.RowsAffected())
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, 0, err
	}
	_, _, _ = p.mem.BulkSyncTeamMemberships(ctx, orgID, teamID, results, cleanedRemovals)
	return results, removed, nil
}

func (p *PostgresRepository) RotateKEKsTransactionally(ctx context.Context, rewrap func(batch KEKRotationBatch) (KEKRotationBatch, error)) (KEKRotationSummary, error) {
	if p.pool == nil {
		return p.mem.RotateKEKsTransactionally(ctx, rewrap)
	}
	var summary KEKRotationSummary
	if rewrap == nil {
		return summary, fmt.Errorf("rewrap callback is required")
	}

	tx, err := p.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return summary, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var batch KEKRotationBatch

	credRows, err := tx.Query(ctx, `SELECT `+providerCredentialSelectCols+` FROM provider_credentials WHERE length(encrypted_dek) > 0 ORDER BY id ASC FOR UPDATE`)
	if err != nil {
		return summary, err
	}
	for credRows.Next() {
		c, sErr := scanProviderCredential(credRows)
		if sErr != nil {
			credRows.Close()
			return summary, sErr
		}
		batch.Credentials = append(batch.Credentials, c)
	}
	if rErr := credRows.Err(); rErr != nil {
		credRows.Close()
		return summary, rErr
	}
	credRows.Close()

	mcpRows, err := tx.Query(ctx, `
		SELECT id, org_id, name, slug, protocol_version, transport_type, endpoint_url,
		       config_version, auth_type, encrypted_auth_secret, encrypted_auth_dek,
		       static_headers, oauth2_endpoint, oauth2_client_id, oauth2_scopes,
		       pinned_tool_hash, rpm_limit, is_active, created_at, updated_at
		FROM mcp_servers WHERE encrypted_auth_dek <> '' ORDER BY id ASC FOR UPDATE`)
	if err != nil {
		return summary, err
	}
	for mcpRows.Next() {
		var s domain.MCPServer
		var headersJSON []byte
		if sErr := mcpRows.Scan(
			&s.ID, &s.OrgID, &s.Name, &s.Slug, &s.ProtocolVersion, &s.TransportType, &s.EndpointURL,
			&s.ConfigVersion, &s.AuthType, &s.EncryptedAuthSecret, &s.EncryptedAuthDEK,
			&headersJSON, &s.OAuth2Endpoint, &s.OAuth2ClientID, &s.OAuth2Scopes,
			&s.PinnedToolHash, &s.RPMLimit, &s.IsActive, &s.CreatedAt, &s.UpdatedAt,
		); sErr != nil {
			mcpRows.Close()
			return summary, sErr
		}
		if len(headersJSON) > 0 {
			_ = json.Unmarshal(headersJSON, &s.StaticHeaders)
		}
		batch.MCPServers = append(batch.MCPServers, &s)
	}
	if rErr := mcpRows.Err(); rErr != nil {
		mcpRows.Close()
		return summary, rErr
	}
	mcpRows.Close()

	a2aRows, err := tx.Query(ctx, `
		SELECT id, org_id, name, slug, endpoint_url, agent_card_url, agent_card_json,
		       task_visibility_mode, auth_type, encrypted_auth_secret, encrypted_auth_dek,
		       max_task_iterations, max_task_budget_micros, is_active, is_killed,
		       created_at, updated_at
		FROM a2a_agents WHERE encrypted_auth_dek <> '' ORDER BY id ASC FOR UPDATE`)
	if err != nil {
		return summary, err
	}
	for a2aRows.Next() {
		var a domain.A2AAgent
		if sErr := a2aRows.Scan(
			&a.ID, &a.OrgID, &a.Name, &a.Slug, &a.EndpointURL, &a.AgentCardURL, &a.AgentCardJSON,
			&a.TaskVisibilityMode, &a.AuthType, &a.EncryptedAuthSecret, &a.EncryptedAuthDEK,
			&a.MaxTaskIterations, &a.MaxTaskBudgetMicros, &a.IsActive, &a.IsKilled,
			&a.CreatedAt, &a.UpdatedAt,
		); sErr != nil {
			a2aRows.Close()
			return summary, sErr
		}
		batch.A2AAgents = append(batch.A2AAgents, &a)
	}
	if rErr := a2aRows.Err(); rErr != nil {
		a2aRows.Close()
		return summary, rErr
	}
	a2aRows.Close()

	grRows, err := tx.Query(ctx, `SELECT `+guardrailDefinitionSelectCols+` FROM guardrail_definitions WHERE encrypted_dek <> '' ORDER BY id ASC FOR UPDATE`)
	if err != nil {
		return summary, err
	}
	for grRows.Next() {
		gd, sErr := scanGuardrailDefinition(grRows)
		if sErr != nil {
			grRows.Close()
			return summary, sErr
		}
		batch.Guardrails = append(batch.Guardrails, gd)
	}
	if rErr := grRows.Err(); rErr != nil {
		grRows.Close()
		return summary, rErr
	}
	grRows.Close()

	updated, err := rewrap(batch)
	if err != nil {
		return summary, err
	}

	for _, c := range updated.Credentials {
		if c == nil || c.ID == "" {
			continue
		}
		kv := c.KeyVersion
		if kv <= 0 {
			kv = 1
		}
		if _, err := tx.Exec(ctx, `
			UPDATE provider_credentials
			SET encrypted_dek = $2, dek_nonce = $3, key_version = $4, last_rotated_at = $5, updated_at = NOW()
			WHERE id = $1`,
			c.ID, c.EncryptedDEK, c.DEKNonce, kv, c.LastRotatedAt,
		); err != nil {
			return summary, err
		}
		summary.CredentialsRewrapped++
	}
	for _, s := range updated.MCPServers {
		if s == nil || s.ID == "" {
			continue
		}
		if _, err := tx.Exec(ctx, `
			UPDATE mcp_servers
			SET encrypted_auth_dek = $2, config_version = config_version + 1, updated_at = NOW()
			WHERE id = $1`,
			s.ID, s.EncryptedAuthDEK,
		); err != nil {
			return summary, err
		}
		summary.MCPServersRewrapped++
	}
	for _, a := range updated.A2AAgents {
		if a == nil || a.ID == "" {
			continue
		}
		if _, err := tx.Exec(ctx, `
			UPDATE a2a_agents
			SET encrypted_auth_dek = $2, updated_at = NOW()
			WHERE id = $1`,
			a.ID, a.EncryptedAuthDEK,
		); err != nil {
			return summary, err
		}
		summary.A2AAgentsRewrapped++
	}
	for _, g := range updated.Guardrails {
		if g == nil || g.ID == "" {
			continue
		}
		if _, err := tx.Exec(ctx, `
			UPDATE guardrail_definitions
			SET encrypted_dek = $2, updated_at = NOW()
			WHERE id = $1`,
			g.ID, g.EncryptedDEK,
		); err != nil {
			return summary, err
		}
		summary.GuardrailsRewrapped++
	}

	if err := tx.Commit(ctx); err != nil {
		return summary, err
	}
	for _, c := range updated.Credentials {
		if c != nil {
			if err := p.mem.UpdateProviderCredential(ctx, c); err != nil {
				_ = p.mem.CreateProviderCredential(ctx, c)
			}
		}
	}
	for _, s := range updated.MCPServers {
		if s != nil {
			if err := p.mem.UpdateMCPServer(ctx, s); err != nil {
				_ = p.mem.CreateMCPServer(ctx, s)
			}
		}
	}
	for _, a := range updated.A2AAgents {
		if a != nil {
			if err := p.mem.UpdateA2AAgent(ctx, a); err != nil {
				_ = p.mem.CreateA2AAgent(ctx, a)
			}
		}
	}
	for _, g := range updated.Guardrails {
		if g != nil {
			if err := p.mem.UpdateGuardrailDefinition(ctx, g); err != nil {
				_ = p.mem.CreateGuardrailDefinition(ctx, g)
			}
		}
	}
	return summary, nil
}

const projectSelectCols = `id, org_id, team_id, name, description, max_budget_micros, spent_micros, rpm_limit, tpm_limit, COALESCE(allowed_models, '{}'), enforce_project_model_quota, is_active, created_at, updated_at`

func scanProject(row rowScanner) (*domain.Project, error) {
	var pr domain.Project
	if err := row.Scan(
		&pr.ID, &pr.OrgID, &pr.TeamID, &pr.Name, &pr.Description,
		&pr.MaxBudgetMicros, &pr.SpentMicros, &pr.RPMLimit, &pr.TPMLimit,
		&pr.AllowedModels, &pr.EnforceProjectModelQuota, &pr.IsActive,
		&pr.CreatedAt, &pr.UpdatedAt,
	); err != nil {
		return nil, err
	}
	if pr.AllowedModels == nil {
		pr.AllowedModels = []string{}
	}
	return &pr, nil
}

func (p *PostgresRepository) CreateProject(ctx context.Context, pr *domain.Project) error {
	if err := normalizeProject(pr); err != nil {
		return err
	}
	if p.pool == nil {
		return p.mem.CreateProject(ctx, pr)
	}
	if pr.ID == "" {
		pr.ID = uuid.NewString()
	}
	const q = `
		INSERT INTO projects (
			id, org_id, team_id, name, description,
			max_budget_micros, spent_micros, rpm_limit, tpm_limit,
			allowed_models, enforce_project_model_quota, is_active
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
		RETURNING created_at, updated_at`
	if err := p.pool.QueryRow(ctx, q,
		pr.ID, pr.OrgID, pr.TeamID, pr.Name, pr.Description,
		pr.MaxBudgetMicros, pr.SpentMicros, pr.RPMLimit, pr.TPMLimit,
		pr.AllowedModels, pr.EnforceProjectModelQuota, pr.IsActive,
	).Scan(&pr.CreatedAt, &pr.UpdatedAt); err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return fmt.Errorf("project already exists: %w", ErrConflict)
		}
		return err
	}
	_ = p.mem.CreateProject(ctx, pr)
	return nil
}

func (p *PostgresRepository) GetProject(ctx context.Context, id string) (*domain.Project, error) {
	if p.pool == nil {
		return p.mem.GetProject(ctx, id)
	}
	pr, err := scanProject(p.pool.QueryRow(ctx,
		`SELECT `+projectSelectCols+` FROM projects WHERE id = $1`,
		strings.TrimSpace(id),
	))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("project %q %w", id, ErrNotFound)
		}
		return nil, err
	}
	return pr, nil
}

func (p *PostgresRepository) ListProjects(ctx context.Context, orgID, teamID string) ([]*domain.Project, error) {
	if p.pool == nil {
		return p.mem.ListProjects(ctx, orgID, teamID)
	}
	var conds []string
	var args []any
	addCond := func(col, val string) {
		if v := strings.TrimSpace(val); v != "" {
			args = append(args, v)
			conds = append(conds, fmt.Sprintf("%s = $%d", col, len(args)))
		}
	}
	addCond("org_id", orgID)
	addCond("team_id", teamID)

	q := `SELECT ` + projectSelectCols + ` FROM projects`
	if len(conds) > 0 {
		q += ` WHERE ` + strings.Join(conds, " AND ")
	}
	q += ` ORDER BY created_at ASC, id ASC`

	rows, err := p.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*domain.Project
	for rows.Next() {
		pr, scanErr := scanProject(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		out = append(out, pr)
	}
	return out, rows.Err()
}

func (p *PostgresRepository) UpdateProject(ctx context.Context, pr *domain.Project) error {
	if err := normalizeProject(pr); err != nil {
		return err
	}
	if pr.ID == "" {
		return fmt.Errorf("project id is required")
	}
	if p.pool == nil {
		return p.mem.UpdateProject(ctx, pr)
	}
	const q = `
		UPDATE projects SET
			team_id = $2,
			name = $3,
			description = $4,
			max_budget_micros = $5,
			spent_micros = $6,
			rpm_limit = $7,
			tpm_limit = $8,
			allowed_models = $9,
			enforce_project_model_quota = $10,
			is_active = $11,
			updated_at = NOW()
		WHERE id = $1
		RETURNING created_at, updated_at`
	if err := p.pool.QueryRow(ctx, q,
		pr.ID, pr.TeamID, pr.Name, pr.Description,
		pr.MaxBudgetMicros, pr.SpentMicros, pr.RPMLimit, pr.TPMLimit,
		pr.AllowedModels, pr.EnforceProjectModelQuota, pr.IsActive,
	).Scan(&pr.CreatedAt, &pr.UpdatedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("project %q %w", pr.ID, ErrNotFound)
		}
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return fmt.Errorf("project conflict: %w", ErrConflict)
		}
		return err
	}
	if err := p.mem.UpdateProject(ctx, pr); err != nil {
		_ = p.mem.CreateProject(ctx, pr)
	}
	return nil
}

func (p *PostgresRepository) DeleteProject(ctx context.Context, id string) error {
	if p.pool == nil {
		return p.mem.DeleteProject(ctx, id)
	}
	tag, err := p.pool.Exec(ctx, `DELETE FROM projects WHERE id = $1`, strings.TrimSpace(id))
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("project %q %w", id, ErrNotFound)
	}
	_ = p.mem.DeleteProject(ctx, id)
	return nil
}

const userSelectCols = `id, org_id, COALESCE(team_id, ''), email, name, role, COALESCE(oidc_subject, ''), COALESCE(scim_external_id, ''), scim_active, max_budget_micros, temp_budget_increase_micros, temp_budget_expires_at, soft_budget_micros, throttle_on_budget_exceeded, COALESCE(budget_fallbacks, '{}'::jsonb), spent_micros, budget_reset_period, budget_reset_at, rpm_limit, tpm_limit, max_concurrent_requests, batch_enqueued_token_limit, is_active, created_at, updated_at`

func scanUser(row rowScanner) (*domain.User, error) {
	var u domain.User
	var role, period string
	var rawFallbacks []byte
	if err := row.Scan(
		&u.ID, &u.OrgID, &u.TeamID, &u.Email, &u.Name, &role, &u.OIDCSubject, &u.SCIMExternalID, &u.SCIMActive,
		&u.MaxBudgetMicros, &u.TempBudgetIncreaseMicros, &u.TempBudgetExpiresAt, &u.SoftBudgetMicros, &u.ThrottleOnBudgetExceeded, &rawFallbacks, &u.SpentMicros, &period, &u.BudgetResetAt,
		&u.RPMLimit, &u.TPMLimit, &u.MaxConcurrentRequests, &u.BatchEnqueuedTokenLimit, &u.IsActive, &u.CreatedAt, &u.UpdatedAt,
	); err != nil {
		return nil, err
	}
	u.Role = domain.Role(role)
	u.BudgetResetPeriod = domain.BudgetResetPeriod(period)
	u.BudgetFallbacks = unmarshalBudgetFallbacks(rawFallbacks)
	return &u, nil
}

func (p *PostgresRepository) CreateUser(ctx context.Context, user *domain.User) error {
	if user.ID == "" {
		user.ID = uuid.NewString()
	}
	if user.IsActive && strings.TrimSpace(user.SCIMExternalID) == "" {
		user.SCIMActive = true
	}
	user.BudgetResetPeriod, user.BudgetResetAt = resolveBudgetResetSchedule(user.BudgetResetPeriod, user.BudgetResetAt, time.Now().UTC())
	if p.pool == nil {
		return p.mem.CreateUser(ctx, user)
	}
	const q = `
		INSERT INTO users (
			id, org_id, team_id, email, name, role, oidc_subject, scim_external_id, scim_active,
			max_budget_micros, temp_budget_increase_micros, temp_budget_expires_at, soft_budget_micros, throttle_on_budget_exceeded, budget_fallbacks, spent_micros, budget_reset_period, budget_reset_at,
			rpm_limit, tpm_limit, max_concurrent_requests, batch_enqueued_token_limit, is_active
		) VALUES ($1,$2,NULLIF($3,''),$4,$5,$6,NULLIF($7,''),NULLIF($8,''),$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23)`
	if _, err := p.pool.Exec(ctx, q,
		user.ID, user.OrgID, user.TeamID, user.Email, user.Name, string(user.Role), user.OIDCSubject, user.SCIMExternalID, user.SCIMActive,
		user.MaxBudgetMicros, user.TempBudgetIncreaseMicros, user.TempBudgetExpiresAt, user.SoftBudgetMicros, user.ThrottleOnBudgetExceeded, marshalBudgetFallbacks(user.BudgetFallbacks), user.SpentMicros, string(user.BudgetResetPeriod), user.BudgetResetAt,
		user.RPMLimit, user.TPMLimit, user.MaxConcurrentRequests, user.BatchEnqueuedTokenLimit, user.IsActive,
	); err != nil {
		return err
	}
	return p.mem.CreateUser(ctx, user)
}

func (p *PostgresRepository) UpdateUser(ctx context.Context, user *domain.User) error {
	if user == nil || user.ID == "" {
		return fmt.Errorf("user id is required")
	}
	user.BudgetResetPeriod, user.BudgetResetAt = resolveBudgetResetSchedule(user.BudgetResetPeriod, user.BudgetResetAt, time.Now().UTC())
	const q = `
		UPDATE users SET
			team_id = NULLIF($2,''), email = $3, name = $4, role = $5, oidc_subject = NULLIF($6,''),
			scim_external_id = NULLIF($7,''), scim_active = $8,
			max_budget_micros = $9, temp_budget_increase_micros = $10, temp_budget_expires_at = $11,
			soft_budget_micros = $12, throttle_on_budget_exceeded = $13, budget_fallbacks = $14,
			spent_micros = $15, budget_reset_period = $16, budget_reset_at = $17,
			rpm_limit = $18, tpm_limit = $19, max_concurrent_requests = $20, batch_enqueued_token_limit = $21, is_active = $22,
			updated_at = NOW()
		WHERE id = $1`
	if p.pool != nil {
		tag, err := p.pool.Exec(ctx, q,
			user.ID, user.TeamID, user.Email, user.Name, string(user.Role), user.OIDCSubject,
			user.SCIMExternalID, user.SCIMActive,
			user.MaxBudgetMicros, user.TempBudgetIncreaseMicros, user.TempBudgetExpiresAt,
			user.SoftBudgetMicros, user.ThrottleOnBudgetExceeded, marshalBudgetFallbacks(user.BudgetFallbacks),
			user.SpentMicros, string(user.BudgetResetPeriod), user.BudgetResetAt,
			user.RPMLimit, user.TPMLimit, user.MaxConcurrentRequests, user.BatchEnqueuedTokenLimit, user.IsActive,
		)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return fmt.Errorf("user %q %w", user.ID, ErrNotFound)
		}
	}
	if err := p.mem.UpdateUser(ctx, user); err != nil {
		if p.pool == nil {
			return err
		}
		_ = p.mem.CreateUser(ctx, user)
	}
	return nil
}

func (p *PostgresRepository) GetUser(ctx context.Context, id string) (*domain.User, error) {
	if u, err := p.mem.GetUser(ctx, id); err == nil && u != nil {
		return u, nil
	}
	u, err := scanUser(p.pool.QueryRow(ctx, `SELECT `+userSelectCols+` FROM users WHERE id = $1`, id))
	if err != nil {
		return nil, fmt.Errorf("user not found: %w", err)
	}
	_ = p.mem.CreateUser(ctx, u)
	return u, nil
}

func (p *PostgresRepository) GetUserByOIDCSubject(ctx context.Context, subject string) (*domain.User, error) {
	if subject == "" {
		return nil, fmt.Errorf("user with oidc_subject %q not found", subject)
	}
	u, err := scanUser(p.pool.QueryRow(ctx, `SELECT `+userSelectCols+` FROM users WHERE oidc_subject = $1 LIMIT 1`, subject))
	if err != nil {
		return p.mem.GetUserByOIDCSubject(ctx, subject)
	}
	return u, nil
}

func (p *PostgresRepository) ListUsers(ctx context.Context, orgID string) ([]*domain.User, error) {
	rows, err := p.pool.Query(ctx, `SELECT `+userSelectCols+` FROM users WHERE org_id = $1 ORDER BY created_at ASC`, orgID)
	if err != nil {
		return p.mem.ListUsers(ctx, orgID)
	}
	defer rows.Close()

	var users []*domain.User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		users = append(users, u)
	}
	if len(users) == 0 {
		return p.mem.ListUsers(ctx, orgID)
	}
	return users, rows.Err()
}

func (p *PostgresRepository) DeleteUser(ctx context.Context, id string) error {
	if p.pool != nil {
		tag, err := p.pool.Exec(ctx, `DELETE FROM users WHERE id = $1`, id)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return fmt.Errorf("user %q %w", id, ErrNotFound)
		}
	}
	if err := p.mem.DeleteUser(ctx, id); err != nil && p.pool == nil {
		return err
	}
	return nil
}

func (p *PostgresRepository) GetUserByOrgAndOIDCSubject(ctx context.Context, orgID, subject string) (*domain.User, error) {
	if orgID == "" || subject == "" {
		return nil, fmt.Errorf("user with org_id %q and oidc_subject %q %w", orgID, subject, ErrNotFound)
	}
	if p.pool == nil {
		return p.mem.GetUserByOrgAndOIDCSubject(ctx, orgID, subject)
	}
	u, err := scanUser(p.pool.QueryRow(ctx, `SELECT `+userSelectCols+` FROM users WHERE org_id = $1 AND oidc_subject = $2 LIMIT 1`, orgID, subject))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("user with org_id %q and oidc_subject %q %w", orgID, subject, ErrNotFound)
		}
		return nil, err
	}
	_ = p.mem.CreateUser(ctx, u)
	return u, nil
}

func (p *PostgresRepository) GetUserByEmail(ctx context.Context, email string) (*domain.User, error) {
	email = strings.TrimSpace(email)
	if email == "" {
		return nil, fmt.Errorf("user with email %q %w", email, ErrNotFound)
	}
	if p.pool == nil {
		return p.mem.GetUserByEmail(ctx, email)
	}
	u, err := scanUser(p.pool.QueryRow(ctx, `SELECT `+userSelectCols+` FROM users WHERE LOWER(email) = LOWER($1) LIMIT 1`, email))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("user with email %q %w", email, ErrNotFound)
		}
		return nil, err
	}
	_ = p.mem.CreateUser(ctx, u)
	return u, nil
}

func (p *PostgresRepository) GetUserBySCIMExternalID(ctx context.Context, orgID, externalID string) (*domain.User, error) {
	orgID = strings.TrimSpace(orgID)
	externalID = strings.TrimSpace(externalID)
	if orgID == "" || externalID == "" {
		return nil, fmt.Errorf("user with org_id %q and scim_external_id %q %w", orgID, externalID, ErrNotFound)
	}
	if p.pool == nil {
		return p.mem.GetUserBySCIMExternalID(ctx, orgID, externalID)
	}
	u, err := scanUser(p.pool.QueryRow(ctx, `SELECT `+userSelectCols+` FROM users WHERE org_id = $1 AND scim_external_id = $2 LIMIT 1`, orgID, externalID))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("user with org_id %q and scim_external_id %q %w", orgID, externalID, ErrNotFound)
		}
		return nil, err
	}
	_ = p.mem.CreateUser(ctx, u)
	return u, nil
}

func (p *PostgresRepository) GetOrCreateUserByOIDCSubject(ctx context.Context, user *domain.User) (*domain.User, bool, error) {
	if user == nil || strings.TrimSpace(user.OrgID) == "" {
		return nil, false, fmt.Errorf("org_id is required to provision user")
	}
	if p.pool == nil {
		return p.mem.GetOrCreateUserByOIDCSubject(ctx, user)
	}

	cp := *user
	if cp.ID == "" {
		cp.ID = uuid.NewString()
	}
	if cp.IsActive && strings.TrimSpace(cp.SCIMExternalID) == "" {
		cp.SCIMActive = true
	}
	now := time.Now().UTC()
	cp.BudgetResetPeriod, cp.BudgetResetAt = resolveBudgetResetSchedule(cp.BudgetResetPeriod, cp.BudgetResetAt, now)

	const q = `
		INSERT INTO users (
			id, org_id, team_id, email, name, role, oidc_subject, scim_external_id, scim_active,
			max_budget_micros, soft_budget_micros, throttle_on_budget_exceeded, budget_fallbacks, spent_micros, budget_reset_period, budget_reset_at,
			rpm_limit, tpm_limit, max_concurrent_requests, batch_enqueued_token_limit, is_active
		) VALUES ($1,$2,NULLIF($3,''),$4,$5,$6,NULLIF($7,''),NULLIF($8,''),$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21)
		ON CONFLICT DO NOTHING`
	tag, err := p.pool.Exec(ctx, q,
		cp.ID, cp.OrgID, cp.TeamID, cp.Email, cp.Name, string(cp.Role), cp.OIDCSubject, cp.SCIMExternalID, cp.SCIMActive,
		cp.MaxBudgetMicros, cp.SoftBudgetMicros, cp.ThrottleOnBudgetExceeded, marshalBudgetFallbacks(cp.BudgetFallbacks), cp.SpentMicros, string(cp.BudgetResetPeriod), cp.BudgetResetAt,
		cp.RPMLimit, cp.TPMLimit, cp.MaxConcurrentRequests, cp.BatchEnqueuedTokenLimit, cp.IsActive,
	)
	if err != nil {
		return nil, false, err
	}
	if tag.RowsAffected() > 0 {
		created, getErr := p.GetUser(ctx, cp.ID)
		if getErr == nil && created != nil {
			return created, true, nil
		}
		_ = p.mem.CreateUser(ctx, &cp)
		return &cp, true, nil
	}

	// Concurrent creation or pre-existing user: re-read deterministically by (org_id, oidc_subject), then email.
	if cp.OIDCSubject != "" {
		existing, err := p.GetUserByOrgAndOIDCSubject(ctx, cp.OrgID, cp.OIDCSubject)
		if err == nil && existing != nil {
			return existing, false, nil
		}
		if err != nil && !errors.Is(err, ErrNotFound) {
			return nil, false, err
		}
	}
	if cp.Email != "" {
		existing, err := p.GetUserByEmail(ctx, cp.Email)
		if err == nil && existing != nil {
			if existing.OrgID != cp.OrgID {
				return nil, false, fmt.Errorf("email %q already belongs to another organization: %w", cp.Email, ErrConflict)
			}
			if existing.OIDCSubject != "" && cp.OIDCSubject != "" && existing.OIDCSubject != cp.OIDCSubject {
				return nil, false, fmt.Errorf("email %q is bound to another OIDC subject: %w", cp.Email, ErrConflict)
			}
			return existing, false, nil
		}
		if err != nil && !errors.Is(err, ErrNotFound) {
			return nil, false, err
		}
	}
	return nil, false, fmt.Errorf("failed to resolve or provision user for org %q", cp.OrgID)
}

const jwtKeyMappingSelectCols = `id, org_id, issuer, claim_name, claim_value, virtual_key_id, created_at`

func scanJWTKeyMapping(row rowScanner) (*domain.JWTKeyMapping, error) {
	var m domain.JWTKeyMapping
	if err := row.Scan(&m.ID, &m.OrgID, &m.Issuer, &m.ClaimName, &m.ClaimValue, &m.VirtualKeyID, &m.CreatedAt); err != nil {
		return nil, err
	}
	return &m, nil
}

func (p *PostgresRepository) CreateJWTKeyMapping(ctx context.Context, mapping *domain.JWTKeyMapping) error {
	if mapping == nil {
		return fmt.Errorf("jwt key mapping is required")
	}
	if strings.TrimSpace(mapping.OrgID) == "" ||
		strings.TrimSpace(mapping.Issuer) == "" ||
		strings.TrimSpace(mapping.ClaimName) == "" ||
		strings.TrimSpace(mapping.ClaimValue) == "" ||
		strings.TrimSpace(mapping.VirtualKeyID) == "" {
		return fmt.Errorf("org_id, issuer, claim_name, claim_value, and virtual_key_id are required")
	}
	if p.pool == nil {
		return p.mem.CreateJWTKeyMapping(ctx, mapping)
	}
	if mapping.ID == "" {
		mapping.ID = uuid.NewString()
	}
	const q = `
		INSERT INTO jwt_key_mappings (id, org_id, issuer, claim_name, claim_value, virtual_key_id)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING created_at`
	if err := p.pool.QueryRow(ctx, q,
		mapping.ID, mapping.OrgID, mapping.Issuer, mapping.ClaimName, mapping.ClaimValue, mapping.VirtualKeyID,
	).Scan(&mapping.CreatedAt); err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return fmt.Errorf("jwt key mapping already exists: %w", ErrConflict)
		}
		return err
	}
	_ = p.mem.CreateJWTKeyMapping(ctx, mapping)
	return nil
}

func (p *PostgresRepository) GetJWTKeyMapping(ctx context.Context, id string) (*domain.JWTKeyMapping, error) {
	if p.pool == nil {
		return p.mem.GetJWTKeyMapping(ctx, id)
	}
	m, err := scanJWTKeyMapping(p.pool.QueryRow(ctx, `SELECT `+jwtKeyMappingSelectCols+` FROM jwt_key_mappings WHERE id = $1`, id))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("jwt key mapping %q %w", id, ErrNotFound)
		}
		return nil, err
	}
	return m, nil
}

func (p *PostgresRepository) ListJWTKeyMappings(ctx context.Context, orgID string) ([]*domain.JWTKeyMapping, error) {
	if p.pool == nil {
		return p.mem.ListJWTKeyMappings(ctx, orgID)
	}
	var (
		rows pgx.Rows
		err  error
	)
	if orgID != "" {
		rows, err = p.pool.Query(ctx, `SELECT `+jwtKeyMappingSelectCols+` FROM jwt_key_mappings WHERE org_id = $1 ORDER BY created_at ASC, id ASC`, orgID)
	} else {
		rows, err = p.pool.Query(ctx, `SELECT `+jwtKeyMappingSelectCols+` FROM jwt_key_mappings ORDER BY created_at ASC, id ASC`)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*domain.JWTKeyMapping
	for rows.Next() {
		m, scanErr := scanJWTKeyMapping(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

func (p *PostgresRepository) DeleteJWTKeyMapping(ctx context.Context, id string) error {
	if p.pool == nil {
		return p.mem.DeleteJWTKeyMapping(ctx, id)
	}
	tag, err := p.pool.Exec(ctx, `DELETE FROM jwt_key_mappings WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("jwt key mapping %q %w", id, ErrNotFound)
	}
	_ = p.mem.DeleteJWTKeyMapping(ctx, id)
	return nil
}

func (p *PostgresRepository) ResolveJWTKeyMapping(ctx context.Context, issuer, claimName, claimValue string) (*domain.JWTKeyMapping, error) {
	if p.pool == nil {
		return p.mem.ResolveJWTKeyMapping(ctx, issuer, claimName, claimValue)
	}
	m, err := scanJWTKeyMapping(p.pool.QueryRow(ctx,
		`SELECT `+jwtKeyMappingSelectCols+` FROM jwt_key_mappings WHERE issuer = $1 AND claim_name = $2 AND claim_value = $3 LIMIT 1`,
		issuer, claimName, claimValue,
	))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("jwt key mapping %w", ErrNotFound)
		}
		return nil, err
	}
	return m, nil
}

const quotaPolicySelectCols = `id, org_id, scope_type, scope_id, model_pattern, rpm_limit, tpm_limit, itpm_limit, otpm_limit, tpd_limit, max_concurrent, max_budget_micros, spent_micros, budget_reset_period, budget_reset_at, max_iterations, window_ttl_sec, is_active, created_at, updated_at`

func scanQuotaPolicy(row rowScanner) (*domain.QuotaPolicy, error) {
	var qp domain.QuotaPolicy
	var scopeType, period string
	if err := row.Scan(
		&qp.ID, &qp.OrgID, &scopeType, &qp.ScopeID, &qp.ModelPattern,
		&qp.RPMLimit, &qp.TPMLimit, &qp.ITPMLimit, &qp.OTPMLimit, &qp.TPDLimit,
		&qp.MaxConcurrent, &qp.MaxBudgetMicros, &qp.SpentMicros,
		&period, &qp.BudgetResetAt, &qp.MaxIterations, &qp.WindowTTLSec,
		&qp.IsActive, &qp.CreatedAt, &qp.UpdatedAt,
	); err != nil {
		return nil, err
	}
	qp.ScopeType = domain.QuotaScopeType(scopeType)
	qp.BudgetResetPeriod = domain.BudgetResetPeriod(period)
	return &qp, nil
}

func (p *PostgresRepository) syncQuotaPolicyMem(policy *domain.QuotaPolicy) {
	if p == nil || p.mem == nil || policy == nil {
		return
	}
	p.mem.mu.Lock()
	tupleKey := quotaPolicyTupleKey(policy.OrgID, policy.ScopeType, policy.ScopeID, policy.ModelPattern)
	if oldID, ok := p.mem.quotaPoliciesByTuple[tupleKey]; ok && oldID != policy.ID {
		delete(p.mem.quotaPolicies, oldID)
	}
	if existing, ok := p.mem.quotaPolicies[policy.ID]; ok {
		delete(p.mem.quotaPoliciesByTuple, quotaPolicyTupleKey(existing.OrgID, existing.ScopeType, existing.ScopeID, existing.ModelPattern))
	}
	cp := policy.Clone()
	p.mem.quotaPolicies[cp.ID] = cp
	p.mem.quotaPoliciesByTuple[tupleKey] = cp.ID
	p.mem.mu.Unlock()
}

func (p *PostgresRepository) UpsertQuotaPolicy(ctx context.Context, policy *domain.QuotaPolicy) error {
	if p.pool == nil {
		return p.mem.UpsertQuotaPolicy(ctx, policy)
	}
	now := time.Now().UTC()
	if err := normalizeQuotaPolicy(policy, now); err != nil {
		return err
	}
	if policy.ID == "" {
		policy.ID = uuid.NewString()
	}
	const q = `
		INSERT INTO quota_policies (
			id, org_id, scope_type, scope_id, model_pattern,
			rpm_limit, tpm_limit, itpm_limit, otpm_limit, tpd_limit,
			max_concurrent, max_budget_micros, spent_micros,
			budget_reset_period, budget_reset_at, max_iterations,
			window_ttl_sec, is_active
		) VALUES (
			$1, $2, $3, $4, $5,
			$6, $7, $8, $9, $10,
			$11, $12, $13,
			$14, $15, $16,
			$17, $18
		)
		ON CONFLICT (org_id, scope_type, scope_id, model_pattern) DO UPDATE SET
			rpm_limit = EXCLUDED.rpm_limit,
			tpm_limit = EXCLUDED.tpm_limit,
			itpm_limit = EXCLUDED.itpm_limit,
			otpm_limit = EXCLUDED.otpm_limit,
			tpd_limit = EXCLUDED.tpd_limit,
			max_concurrent = EXCLUDED.max_concurrent,
			max_budget_micros = EXCLUDED.max_budget_micros,
			spent_micros = GREATEST(quota_policies.spent_micros, EXCLUDED.spent_micros),
			budget_reset_period = EXCLUDED.budget_reset_period,
			budget_reset_at = EXCLUDED.budget_reset_at,
			max_iterations = EXCLUDED.max_iterations,
			window_ttl_sec = EXCLUDED.window_ttl_sec,
			is_active = EXCLUDED.is_active,
			updated_at = NOW()
		RETURNING id, spent_micros, created_at, updated_at`

	if err := p.pool.QueryRow(ctx, q,
		policy.ID, policy.OrgID, string(policy.ScopeType), policy.ScopeID, policy.ModelPattern,
		policy.RPMLimit, policy.TPMLimit, policy.ITPMLimit, policy.OTPMLimit, policy.TPDLimit,
		policy.MaxConcurrent, policy.MaxBudgetMicros, policy.SpentMicros,
		string(policy.BudgetResetPeriod), policy.BudgetResetAt, policy.MaxIterations,
		policy.WindowTTLSec, policy.IsActive,
	).Scan(&policy.ID, &policy.SpentMicros, &policy.CreatedAt, &policy.UpdatedAt); err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return fmt.Errorf("quota policy conflict: %w", ErrConflict)
		}
		return err
	}
	p.syncQuotaPolicyMem(policy)
	return nil
}

func (p *PostgresRepository) GetQuotaPolicy(ctx context.Context, id string) (*domain.QuotaPolicy, error) {
	if p.pool == nil {
		return p.mem.GetQuotaPolicy(ctx, id)
	}
	qp, err := scanQuotaPolicy(p.pool.QueryRow(ctx,
		`SELECT `+quotaPolicySelectCols+` FROM quota_policies WHERE id = $1`, id,
	))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("quota policy %q %w", id, ErrNotFound)
		}
		return nil, err
	}
	return qp, nil
}

func (p *PostgresRepository) ListQuotaPolicies(ctx context.Context, filter QuotaPolicyFilter) ([]*domain.QuotaPolicy, error) {
	if p.pool == nil {
		return p.mem.ListQuotaPolicies(ctx, filter)
	}
	var conds []string
	var args []any
	addCond := func(col string, val any) {
		args = append(args, val)
		conds = append(conds, fmt.Sprintf("%s = $%d", col, len(args)))
	}
	if v := strings.TrimSpace(filter.OrgID); v != "" {
		addCond("org_id", v)
	}
	if v := strings.ToLower(strings.TrimSpace(string(filter.ScopeType))); v != "" {
		addCond("scope_type", v)
	}
	if v := strings.TrimSpace(filter.ScopeID); v != "" {
		addCond("scope_id", v)
	}
	if v := strings.TrimSpace(filter.ModelPattern); v != "" {
		addCond("model_pattern", v)
	}
	if filter.ActiveOnly {
		conds = append(conds, "is_active = TRUE")
	}

	q := `SELECT ` + quotaPolicySelectCols + ` FROM quota_policies`
	if len(conds) > 0 {
		q += ` WHERE ` + strings.Join(conds, " AND ")
	}
	q += ` ORDER BY org_id ASC, scope_type ASC, scope_id ASC, model_pattern ASC, id ASC`

	rows, err := p.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*domain.QuotaPolicy
	for rows.Next() {
		qp, scanErr := scanQuotaPolicy(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		out = append(out, qp)
	}
	return out, rows.Err()
}

func (p *PostgresRepository) DeleteQuotaPolicy(ctx context.Context, id string) error {
	if p.pool == nil {
		return p.mem.DeleteQuotaPolicy(ctx, id)
	}
	tag, err := p.pool.Exec(ctx, `DELETE FROM quota_policies WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("quota policy %q %w", id, ErrNotFound)
	}
	_ = p.mem.DeleteQuotaPolicy(ctx, id)
	return nil
}

func (p *PostgresRepository) IncrementQuotaPolicySpend(ctx context.Context, id string, deltaMicros int64) error {
	id = strings.TrimSpace(id)
	if id == "" {
		return fmt.Errorf("quota policy id is required")
	}
	if deltaMicros < 0 {
		return fmt.Errorf("delta_micros must be non-negative")
	}
	if p.pool == nil {
		return p.mem.IncrementQuotaPolicySpend(ctx, id, deltaMicros)
	}
	tag, err := p.pool.Exec(ctx,
		`UPDATE quota_policies SET spent_micros = spent_micros + $2, updated_at = NOW() WHERE id = $1`,
		id, deltaMicros,
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("quota policy %q %w", id, ErrNotFound)
	}
	_ = p.mem.IncrementQuotaPolicySpend(ctx, id, deltaMicros)
	return nil
}

const ptuShareSelectCols = `id, org_id, deployment_id, team_id, reserved_rpm, reserved_tpm, created_at, updated_at`

func scanPTUShare(row rowScanner) (*domain.DeploymentPTUShare, error) {
	var s domain.DeploymentPTUShare
	if err := row.Scan(
		&s.ID, &s.OrgID, &s.DeploymentID, &s.TeamID,
		&s.ReservedRPM, &s.ReservedTPM, &s.CreatedAt, &s.UpdatedAt,
	); err != nil {
		return nil, err
	}
	return &s, nil
}

func (p *PostgresRepository) syncPTUShareMem(share *domain.DeploymentPTUShare) {
	if p == nil || p.mem == nil || share == nil {
		return
	}
	p.mem.mu.Lock()
	tupleKey := ptuShareTupleKey(share.DeploymentID, share.TeamID)
	if oldID, ok := p.mem.ptuSharesByTuple[tupleKey]; ok && oldID != share.ID {
		delete(p.mem.ptuShares, oldID)
	}
	if existing, ok := p.mem.ptuShares[share.ID]; ok {
		delete(p.mem.ptuSharesByTuple, ptuShareTupleKey(existing.DeploymentID, existing.TeamID))
	}
	cp := share.Clone()
	p.mem.ptuShares[cp.ID] = cp
	p.mem.ptuSharesByTuple[tupleKey] = cp.ID
	p.mem.mu.Unlock()
}

func (p *PostgresRepository) UpsertDeploymentPTUShare(ctx context.Context, share *domain.DeploymentPTUShare) error {
	if p.pool == nil {
		return p.mem.UpsertDeploymentPTUShare(ctx, share)
	}
	now := time.Now().UTC()
	if err := normalizePTUShare(share, now); err != nil {
		return err
	}
	if share.ID == "" {
		share.ID = uuid.NewString()
	}
	const q = `
		INSERT INTO deployment_ptu_shares (
			id, org_id, deployment_id, team_id, reserved_rpm, reserved_tpm
		) VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (deployment_id, team_id) DO UPDATE SET
			reserved_rpm = EXCLUDED.reserved_rpm,
			reserved_tpm = EXCLUDED.reserved_tpm,
			updated_at = NOW()
		RETURNING id, created_at, updated_at`
	if err := p.pool.QueryRow(ctx, q,
		share.ID, share.OrgID, share.DeploymentID, share.TeamID,
		share.ReservedRPM, share.ReservedTPM,
	).Scan(&share.ID, &share.CreatedAt, &share.UpdatedAt); err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return fmt.Errorf("deployment PTU share conflict: %w", ErrConflict)
		}
		return err
	}
	p.syncPTUShareMem(share)
	return nil
}

func (p *PostgresRepository) ListDeploymentPTUShares(ctx context.Context, deploymentID string) ([]*domain.DeploymentPTUShare, error) {
	if p.pool == nil {
		return p.mem.ListDeploymentPTUShares(ctx, deploymentID)
	}
	deploymentID = strings.TrimSpace(deploymentID)
	q := `SELECT ` + ptuShareSelectCols + ` FROM deployment_ptu_shares`
	var args []any
	if deploymentID != "" {
		args = append(args, deploymentID)
		q += ` WHERE deployment_id = $1`
	}
	q += ` ORDER BY deployment_id ASC, team_id ASC, id ASC`

	rows, err := p.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*domain.DeploymentPTUShare
	for rows.Next() {
		s, scanErr := scanPTUShare(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

func (p *PostgresRepository) DeleteDeploymentPTUShare(ctx context.Context, deploymentID, teamID string) error {
	if p.pool == nil {
		return p.mem.DeleteDeploymentPTUShare(ctx, deploymentID, teamID)
	}
	deploymentID = strings.TrimSpace(deploymentID)
	teamID = strings.TrimSpace(teamID)
	tag, err := p.pool.Exec(ctx,
		`DELETE FROM deployment_ptu_shares WHERE deployment_id = $1 AND team_id = $2`,
		deploymentID, teamID,
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("deployment PTU share (%s, %s) %w", deploymentID, teamID, ErrNotFound)
	}
	_ = p.mem.DeleteDeploymentPTUShare(ctx, deploymentID, teamID)
	return nil
}

func (p *PostgresRepository) HasTeamPTUShares(ctx context.Context, teamID string) (bool, error) {
	if p.pool == nil {
		return p.mem.HasTeamPTUShares(ctx, teamID)
	}
	teamID = strings.TrimSpace(teamID)
	if teamID == "" {
		return false, nil
	}
	var exists bool
	if err := p.pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM deployment_ptu_shares WHERE team_id = $1)`,
		teamID,
	).Scan(&exists); err != nil {
		return false, err
	}
	return exists, nil
}

const budgetWindowSelectCols = `id, org_id, scope_type, scope_id, window_type, max_budget_micros, spent_micros, window_reset_at, created_at, updated_at`

func scanBudgetWindowLimit(row rowScanner) (*domain.BudgetWindowLimit, error) {
	var bw domain.BudgetWindowLimit
	var scopeType, windowType string
	if err := row.Scan(
		&bw.ID, &bw.OrgID, &scopeType, &bw.ScopeID, &windowType,
		&bw.MaxBudgetMicros, &bw.SpentMicros, &bw.WindowResetAt,
		&bw.CreatedAt, &bw.UpdatedAt,
	); err != nil {
		return nil, err
	}
	bw.ScopeType = domain.QuotaScopeType(scopeType)
	bw.WindowType = domain.BudgetWindowType(windowType)
	return &bw, nil
}

func (p *PostgresRepository) syncBudgetWindowMem(bw *domain.BudgetWindowLimit) {
	if p == nil || p.mem == nil || bw == nil {
		return
	}
	tupleKey := budgetWindowTupleKey(bw.OrgID, bw.ScopeType, bw.ScopeID, bw.WindowType)
	p.mem.mu.Lock()
	if existingID, ok := p.mem.budgetWindowsByTuple[tupleKey]; ok && existingID != bw.ID {
		delete(p.mem.budgetWindows, existingID)
	}
	cp := bw.Clone()
	p.mem.budgetWindows[cp.ID] = cp
	p.mem.budgetWindowsByTuple[tupleKey] = cp.ID
	p.mem.mu.Unlock()
}

func (p *PostgresRepository) UpsertBudgetWindowLimit(ctx context.Context, limit *domain.BudgetWindowLimit) error {
	if p.pool == nil {
		return p.mem.UpsertBudgetWindowLimit(ctx, limit)
	}
	now := time.Now().UTC()
	hasExplicitReset := limit != nil && !limit.WindowResetAt.IsZero()
	if err := normalizeBudgetWindowLimit(limit, now); err != nil {
		return err
	}
	if limit.ID == "" {
		limit.ID = uuid.NewString()
	}
	const q = `
		INSERT INTO budget_window_limits (
			id, org_id, scope_type, scope_id, window_type,
			max_budget_micros, spent_micros, window_reset_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		ON CONFLICT (org_id, scope_type, scope_id, window_type) DO UPDATE SET
			max_budget_micros = EXCLUDED.max_budget_micros,
			spent_micros = GREATEST(budget_window_limits.spent_micros, EXCLUDED.spent_micros),
			window_reset_at = CASE WHEN $9 THEN EXCLUDED.window_reset_at ELSE budget_window_limits.window_reset_at END,
			updated_at = NOW()
		RETURNING id, spent_micros, window_reset_at, created_at, updated_at`

	if err := p.pool.QueryRow(ctx, q,
		limit.ID, limit.OrgID, string(limit.ScopeType), limit.ScopeID, string(limit.WindowType),
		limit.MaxBudgetMicros, limit.SpentMicros, limit.WindowResetAt, hasExplicitReset,
	).Scan(&limit.ID, &limit.SpentMicros, &limit.WindowResetAt, &limit.CreatedAt, &limit.UpdatedAt); err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return fmt.Errorf("budget window limit conflict: %w", ErrConflict)
		}
		return err
	}
	p.syncBudgetWindowMem(limit)
	return nil
}

func (p *PostgresRepository) ListBudgetWindowLimits(ctx context.Context, filter BudgetWindowFilter) ([]*domain.BudgetWindowLimit, error) {
	if p.pool == nil {
		return p.mem.ListBudgetWindowLimits(ctx, filter)
	}
	var conds []string
	var args []any
	addCond := func(col string, val any) {
		args = append(args, val)
		conds = append(conds, fmt.Sprintf("%s = $%d", col, len(args)))
	}
	if v := strings.TrimSpace(filter.OrgID); v != "" {
		addCond("org_id", v)
	}
	if v := strings.ToLower(strings.TrimSpace(string(filter.ScopeType))); v != "" {
		addCond("scope_type", v)
	}
	if v := strings.TrimSpace(filter.ScopeID); v != "" {
		addCond("scope_id", v)
	}
	if v := strings.ToLower(strings.TrimSpace(string(filter.WindowType))); v != "" {
		addCond("window_type", v)
	}

	q := `SELECT ` + budgetWindowSelectCols + ` FROM budget_window_limits`
	if len(conds) > 0 {
		q += ` WHERE ` + strings.Join(conds, " AND ")
	}
	q += ` ORDER BY org_id ASC, scope_type ASC, scope_id ASC, window_type ASC, id ASC`

	rows, err := p.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*domain.BudgetWindowLimit
	for rows.Next() {
		bw, scanErr := scanBudgetWindowLimit(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		out = append(out, bw)
	}
	return out, rows.Err()
}

func (p *PostgresRepository) IncrementBudgetWindowSpend(ctx context.Context, orgID string, scopeType domain.QuotaScopeType, scopeID string, deltaMicros int64) error {
	orgID = strings.TrimSpace(orgID)
	scopeType = domain.QuotaScopeType(strings.ToLower(strings.TrimSpace(string(scopeType))))
	scopeID = strings.TrimSpace(scopeID)
	if orgID == "" || !scopeType.IsValid() || scopeID == "" {
		return fmt.Errorf("org_id, valid scope_type, and scope_id are required")
	}
	if deltaMicros < 0 {
		return fmt.Errorf("delta_micros must be non-negative")
	}
	if deltaMicros == 0 {
		return nil
	}
	if p.pool == nil {
		return p.mem.IncrementBudgetWindowSpend(ctx, orgID, scopeType, scopeID, deltaMicros)
	}
	if _, err := p.pool.Exec(ctx,
		`UPDATE budget_window_limits SET spent_micros = spent_micros + $4, updated_at = NOW() WHERE org_id = $1 AND scope_type = $2 AND scope_id = $3`,
		orgID, string(scopeType), scopeID, deltaMicros,
	); err != nil {
		return err
	}
	_ = p.mem.IncrementBudgetWindowSpend(ctx, orgID, scopeType, scopeID, deltaMicros)
	return nil
}

func (p *PostgresRepository) ResetExpiredBudgetWindows(ctx context.Context, now time.Time) (int, error) {
	reset, err := p.ResetExpiredBudgetWindowsWithResults(ctx, now)
	return len(reset), err
}

func (p *PostgresRepository) ResetExpiredBudgetWindowsWithResults(ctx context.Context, now time.Time) ([]*domain.BudgetWindowLimit, error) {
	if p.pool == nil {
		return p.mem.ResetExpiredBudgetWindowsWithResults(ctx, now)
	}
	nowUTC := now.UTC()
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin reset budget windows tx: %w", err)
	}
	defer tx.Rollback(ctx)

	rows, err := tx.Query(ctx,
		`SELECT `+budgetWindowSelectCols+` FROM budget_window_limits WHERE window_reset_at <= $1 FOR UPDATE`,
		nowUTC,
	)
	if err != nil {
		return nil, err
	}
	var expired []*domain.BudgetWindowLimit
	for rows.Next() {
		bw, scanErr := scanBudgetWindowLimit(rows)
		if scanErr != nil {
			rows.Close()
			return nil, scanErr
		}
		expired = append(expired, bw)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()

	for _, bw := range expired {
		nextReset := advanceBudgetWindowResetAt(bw.WindowType, bw.WindowResetAt, nowUTC)
		if _, err := tx.Exec(ctx,
			`UPDATE budget_window_limits SET spent_micros = 0, window_reset_at = $2, updated_at = NOW() WHERE id = $1`,
			bw.ID, nextReset,
		); err != nil {
			return nil, err
		}
		bw.SpentMicros = 0
		bw.WindowResetAt = nextReset
		bw.UpdatedAt = nowUTC
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit reset budget windows tx: %w", err)
	}
	for _, bw := range expired {
		p.syncBudgetWindowMem(bw)
	}
	sortBudgetWindowLimits(expired)
	return expired, nil
}

func (p *PostgresRepository) SetTempBudgetBoost(ctx context.Context, scopeType domain.QuotaScopeType, scopeID string, increaseMicros int64, expiresAt *time.Time) error {
	scopeType = domain.QuotaScopeType(strings.ToLower(strings.TrimSpace(string(scopeType))))
	scopeID = strings.TrimSpace(scopeID)
	if scopeID == "" {
		return fmt.Errorf("scope_id is required")
	}
	if increaseMicros < 0 {
		return fmt.Errorf("temp_budget_increase_micros must be non-negative")
	}
	if p.pool == nil {
		return p.mem.SetTempBudgetBoost(ctx, scopeType, scopeID, increaseMicros, expiresAt)
	}
	var table string
	switch scopeType {
	case domain.QuotaScopeKey:
		table = "virtual_keys"
	case domain.QuotaScopeTeam:
		table = "teams"
	case domain.QuotaScopeUser:
		table = "users"
	case domain.QuotaScopeOrg:
		table = "organizations"
	default:
		return fmt.Errorf("unsupported temp budget scope_type %q", scopeType)
	}
	var exp *time.Time
	if expiresAt != nil {
		u := expiresAt.UTC()
		exp = &u
	}
	tag, err := p.pool.Exec(ctx,
		`UPDATE `+table+` SET temp_budget_increase_micros = $2, temp_budget_expires_at = $3, updated_at = NOW() WHERE id = $1`,
		scopeID, increaseMicros, exp,
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("%s %q %w", scopeType, scopeID, ErrNotFound)
	}
	_ = p.mem.SetTempBudgetBoost(ctx, scopeType, scopeID, increaseMicros, exp)
	return nil
}

const priorityClassSelectCols = `id, org_id, name, weight, priority_rank, max_borrow_multiple, created_at`

func scanPriorityClass(row rowScanner) (*domain.PriorityClass, error) {
	var pc domain.PriorityClass
	if err := row.Scan(
		&pc.ID, &pc.OrgID, &pc.Name, &pc.Weight,
		&pc.PriorityRank, &pc.MaxBorrowMultiple, &pc.CreatedAt,
	); err != nil {
		return nil, err
	}
	return &pc, nil
}

func (p *PostgresRepository) syncPriorityClassMem(pc *domain.PriorityClass) {
	if p == nil || p.mem == nil || pc == nil {
		return
	}
	p.mem.mu.Lock()
	tupleKey := priorityClassTupleKey(pc.OrgID, pc.Name)
	if oldID, ok := p.mem.priorityClassesByTuple[tupleKey]; ok && oldID != pc.ID {
		delete(p.mem.priorityClasses, oldID)
	}
	if existing, ok := p.mem.priorityClasses[pc.ID]; ok {
		delete(p.mem.priorityClassesByTuple, priorityClassTupleKey(existing.OrgID, existing.Name))
	}
	cp := pc.Clone()
	p.mem.priorityClasses[cp.ID] = cp
	p.mem.priorityClassesByTuple[tupleKey] = cp.ID
	p.mem.mu.Unlock()
}

func (p *PostgresRepository) UpsertPriorityClass(ctx context.Context, pc *domain.PriorityClass) error {
	if p.pool == nil {
		return p.mem.UpsertPriorityClass(ctx, pc)
	}
	now := time.Now().UTC()
	if err := normalizePriorityClass(pc, now); err != nil {
		return err
	}
	if pc.ID == "" {
		pc.ID = uuid.NewString()
	}
	const q = `
		INSERT INTO priority_classes (
			id, org_id, name, weight, priority_rank, max_borrow_multiple
		) VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (org_id, name) DO UPDATE SET
			weight = EXCLUDED.weight,
			priority_rank = EXCLUDED.priority_rank,
			max_borrow_multiple = EXCLUDED.max_borrow_multiple
		RETURNING id, created_at`
	if err := p.pool.QueryRow(ctx, q,
		pc.ID, pc.OrgID, pc.Name, pc.Weight, pc.PriorityRank, pc.MaxBorrowMultiple,
	).Scan(&pc.ID, &pc.CreatedAt); err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return fmt.Errorf("priority class conflict: %w", ErrConflict)
		}
		return err
	}
	p.syncPriorityClassMem(pc)
	return nil
}

func (p *PostgresRepository) ListPriorityClasses(ctx context.Context, orgID string) ([]*domain.PriorityClass, error) {
	if p.pool == nil {
		return p.mem.ListPriorityClasses(ctx, orgID)
	}
	orgID = strings.TrimSpace(orgID)
	q := `SELECT ` + priorityClassSelectCols + ` FROM priority_classes`
	var args []any
	if orgID != "" {
		args = append(args, orgID)
		q += ` WHERE org_id = $1`
	}
	q += ` ORDER BY priority_rank ASC, name ASC, id ASC`

	rows, err := p.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*domain.PriorityClass
	for rows.Next() {
		pc, scanErr := scanPriorityClass(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		out = append(out, pc)
	}
	return out, rows.Err()
}

const accessGroupRuleSelectCols = `id, org_id, name, attribute, operator, value, COALESCE(allowed_models, '{}'), COALESCE(access_group_id, ''), priority, is_active, created_at, updated_at`

func scanAccessGroupRule(row rowScanner) (*domain.AccessGroupRule, error) {
	var r domain.AccessGroupRule
	var op string
	if err := row.Scan(
		&r.ID, &r.OrgID, &r.Name, &r.Attribute, &op, &r.Value,
		&r.AllowedModels, &r.AccessGroupID, &r.Priority, &r.IsActive, &r.CreatedAt, &r.UpdatedAt,
	); err != nil {
		return nil, err
	}
	r.Operator = domain.AccessRuleOperator(op)
	if r.AllowedModels == nil {
		r.AllowedModels = []string{}
	}
	return &r, nil
}

func (p *PostgresRepository) CreateAccessGroupRule(ctx context.Context, rule *domain.AccessGroupRule) error {
	if rule == nil {
		return fmt.Errorf("access group rule is required")
	}
	if strings.TrimSpace(rule.OrgID) == "" ||
		strings.TrimSpace(rule.Name) == "" ||
		strings.TrimSpace(rule.Attribute) == "" ||
		strings.TrimSpace(string(rule.Operator)) == "" ||
		strings.TrimSpace(rule.Value) == "" {
		return fmt.Errorf("org_id, name, attribute, operator, and value are required")
	}
	if p.pool == nil {
		return p.mem.CreateAccessGroupRule(ctx, rule)
	}
	if rule.ID == "" {
		rule.ID = uuid.NewString()
	}
	allowedModels := rule.AllowedModels
	if allowedModels == nil {
		allowedModels = []string{}
	}
	const q = `
		INSERT INTO access_group_rules (id, org_id, name, attribute, operator, value, allowed_models, access_group_id, priority, is_active)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		RETURNING created_at, updated_at`
	if err := p.pool.QueryRow(ctx, q,
		rule.ID, rule.OrgID, rule.Name, rule.Attribute, string(rule.Operator), rule.Value,
		allowedModels, rule.AccessGroupID, rule.Priority, rule.IsActive,
	).Scan(&rule.CreatedAt, &rule.UpdatedAt); err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return fmt.Errorf("access group rule already exists: %w", ErrConflict)
		}
		return err
	}
	rule.AllowedModels = allowedModels
	_ = p.mem.CreateAccessGroupRule(ctx, rule)
	return nil
}

func (p *PostgresRepository) GetAccessGroupRule(ctx context.Context, id string) (*domain.AccessGroupRule, error) {
	if p.pool == nil {
		return p.mem.GetAccessGroupRule(ctx, id)
	}
	r, err := scanAccessGroupRule(p.pool.QueryRow(ctx, `SELECT `+accessGroupRuleSelectCols+` FROM access_group_rules WHERE id = $1`, id))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("access group rule %q %w", id, ErrNotFound)
		}
		return nil, err
	}
	return r, nil
}

func (p *PostgresRepository) ListAccessGroupRules(ctx context.Context, orgID string, activeOnly bool) ([]*domain.AccessGroupRule, error) {
	if p.pool == nil {
		return p.mem.ListAccessGroupRules(ctx, orgID, activeOnly)
	}
	var (
		clauses []string
		args    []any
	)
	if orgID != "" {
		args = append(args, orgID)
		clauses = append(clauses, fmt.Sprintf("org_id = $%d", len(args)))
	}
	if activeOnly {
		clauses = append(clauses, "is_active = TRUE")
	}
	q := `SELECT ` + accessGroupRuleSelectCols + ` FROM access_group_rules`
	if len(clauses) > 0 {
		q += ` WHERE ` + strings.Join(clauses, " AND ")
	}
	q += ` ORDER BY priority DESC, created_at ASC, id ASC`

	rows, err := p.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*domain.AccessGroupRule
	for rows.Next() {
		r, scanErr := scanAccessGroupRule(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (p *PostgresRepository) DeleteAccessGroupRule(ctx context.Context, id string) error {
	if p.pool == nil {
		return p.mem.DeleteAccessGroupRule(ctx, id)
	}
	tag, err := p.pool.Exec(ctx, `DELETE FROM access_group_rules WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("access group rule %q %w", id, ErrNotFound)
	}
	_ = p.mem.DeleteAccessGroupRule(ctx, id)
	return nil
}

const virtualKeySelectCols = `id, key_prefix, key_hash, name, org_id, COALESCE(team_id, ''), COALESCE(user_id, ''), role, allowed_models, allowed_endpoints, allowed_mcp_servers, allowed_a2a_agents, allowed_client_apps, max_budget_micros, temp_budget_increase_micros, temp_budget_expires_at, soft_budget_micros, throttle_on_budget_exceeded, COALESCE(budget_fallbacks, '{}'::jsonb), spent_micros, budget_reset_period, budget_reset_at, rpm_limit, tpm_limit, mcp_rpm_limit, max_concurrent_requests, batch_enqueued_token_limit, max_iterations, max_budget_per_session_micros, expires_at, is_active, rotation_interval_sec, key_rotation_at, last_rotated_at, rotation_count, revoked_at, COALESCE(revoked_by, ''), COALESCE(expiry_alert_sent_days, '{}'), COALESCE(NULLIF(key_type, ''), 'default'), COALESCE(project_id, ''), can_impersonate, COALESCE(tags, '{}'), COALESCE(metadata, '{}'::jsonb)`

const virtualKeySelectColsAliased = `vk.id, vk.key_prefix, vk.key_hash, vk.name, vk.org_id, COALESCE(vk.team_id, ''), COALESCE(vk.user_id, ''), vk.role, vk.allowed_models, vk.allowed_endpoints, vk.allowed_mcp_servers, vk.allowed_a2a_agents, vk.allowed_client_apps, vk.max_budget_micros, vk.temp_budget_increase_micros, vk.temp_budget_expires_at, vk.soft_budget_micros, vk.throttle_on_budget_exceeded, COALESCE(vk.budget_fallbacks, '{}'::jsonb), vk.spent_micros, vk.budget_reset_period, vk.budget_reset_at, vk.rpm_limit, vk.tpm_limit, vk.mcp_rpm_limit, vk.max_concurrent_requests, vk.batch_enqueued_token_limit, vk.max_iterations, vk.max_budget_per_session_micros, vk.expires_at, vk.is_active, vk.rotation_interval_sec, vk.key_rotation_at, vk.last_rotated_at, vk.rotation_count, vk.revoked_at, COALESCE(vk.revoked_by, ''), COALESCE(vk.expiry_alert_sent_days, '{}'), COALESCE(NULLIF(vk.key_type, ''), 'default'), COALESCE(vk.project_id, ''), vk.can_impersonate, COALESCE(vk.tags, '{}'), COALESCE(vk.metadata, '{}'::jsonb)`

func scanVirtualKey(row rowScanner) (*domain.VirtualKey, error) {
	var k domain.VirtualKey
	var role, period, keyType string
	var rawFallbacks, rawMeta []byte
	var sentDays []int32
	if err := row.Scan(
		&k.ID, &k.KeyPrefix, &k.KeyHash, &k.Name, &k.OrgID, &k.TeamID, &k.UserID, &role,
		&k.AllowedModels, &k.AllowedEndpoints,
		&k.AllowedMCPServers, &k.AllowedA2AAgents, &k.AllowedClientApps,
		&k.MaxBudgetMicros, &k.TempBudgetIncreaseMicros, &k.TempBudgetExpiresAt, &k.SoftBudgetMicros, &k.ThrottleOnBudgetExceeded, &rawFallbacks, &k.SpentMicros, &period, &k.BudgetResetAt,
		&k.RPMLimit, &k.TPMLimit, &k.MCPRPMLimit, &k.MaxConcurrentRequests, &k.BatchEnqueuedTokenLimit, &k.MaxIterations, &k.MaxBudgetPerSessionMicros, &k.ExpiresAt, &k.IsActive,
		&k.RotationIntervalSec, &k.KeyRotationAt, &k.LastRotatedAt, &k.RotationCount, &k.RevokedAt, &k.RevokedBy, &sentDays,
		&keyType, &k.ProjectID, &k.CanImpersonate, &k.Tags, &rawMeta,
	); err != nil {
		return nil, err
	}
	k.Role = domain.Role(role)
	k.BudgetResetPeriod = domain.BudgetResetPeriod(period)
	k.BudgetFallbacks = unmarshalBudgetFallbacks(rawFallbacks)
	k.Metadata = unmarshalStringMapJSON(rawMeta)
	k.ExpiryAlertSentDays = int32sToInts(sentDays)
	k.KeyType = domain.KeyType(keyType)
	if k.KeyType == "" {
		k.KeyType = domain.KeyTypeDefault
	}
	return &k, nil
}

func scanDeprecatedVirtualKey(row rowScanner) (*domain.VirtualKey, time.Time, error) {
	var k domain.VirtualKey
	var role, period, keyType string
	var rawFallbacks, rawMeta []byte
	var sentDays []int32
	var revokeAt time.Time
	if err := row.Scan(
		&k.ID, &k.KeyPrefix, &k.KeyHash, &k.Name, &k.OrgID, &k.TeamID, &k.UserID, &role,
		&k.AllowedModels, &k.AllowedEndpoints,
		&k.AllowedMCPServers, &k.AllowedA2AAgents, &k.AllowedClientApps,
		&k.MaxBudgetMicros, &k.TempBudgetIncreaseMicros, &k.TempBudgetExpiresAt, &k.SoftBudgetMicros, &k.ThrottleOnBudgetExceeded, &rawFallbacks, &k.SpentMicros, &period, &k.BudgetResetAt,
		&k.RPMLimit, &k.TPMLimit, &k.MCPRPMLimit, &k.MaxConcurrentRequests, &k.BatchEnqueuedTokenLimit, &k.MaxIterations, &k.MaxBudgetPerSessionMicros, &k.ExpiresAt, &k.IsActive,
		&k.RotationIntervalSec, &k.KeyRotationAt, &k.LastRotatedAt, &k.RotationCount, &k.RevokedAt, &k.RevokedBy, &sentDays,
		&keyType, &k.ProjectID, &k.CanImpersonate, &k.Tags, &rawMeta,
		&revokeAt,
	); err != nil {
		return nil, time.Time{}, err
	}
	k.Role = domain.Role(role)
	k.BudgetResetPeriod = domain.BudgetResetPeriod(period)
	k.BudgetFallbacks = unmarshalBudgetFallbacks(rawFallbacks)
	k.Metadata = unmarshalStringMapJSON(rawMeta)
	k.ExpiryAlertSentDays = int32sToInts(sentDays)
	k.KeyType = domain.KeyType(keyType)
	if k.KeyType == "" {
		k.KeyType = domain.KeyTypeDefault
	}
	return &k, revokeAt.UTC(), nil
}

func (p *PostgresRepository) CreateVirtualKey(ctx context.Context, vk *domain.VirtualKey) error {
	if vk.ID == "" {
		vk.ID = uuid.NewString()
	}
	if vk.AllowedModels == nil {
		vk.AllowedModels = []string{}
	}
	if vk.AllowedEndpoints == nil {
		vk.AllowedEndpoints = append([]string(nil), domain.DefaultAllowedEndpoints...)
	}
	tags := vk.Tags
	if tags == nil {
		tags = []string{}
	}
	if vk.Role == "" {
		vk.Role = domain.RoleServiceAccount
	}
	if vk.KeyType == "" {
		vk.KeyType = domain.KeyTypeDefault
	}
	vk.BudgetResetPeriod, vk.BudgetResetAt = resolveBudgetResetSchedule(vk.BudgetResetPeriod, vk.BudgetResetAt, time.Now().UTC())
	if p.pool == nil {
		return p.mem.CreateVirtualKey(ctx, vk)
	}
	const q = `
		INSERT INTO virtual_keys (
			id, key_prefix, key_hash, name, org_id, team_id, user_id, role, allowed_models, allowed_endpoints,
			allowed_mcp_servers, allowed_a2a_agents, allowed_client_apps,
			max_budget_micros, temp_budget_increase_micros, temp_budget_expires_at, soft_budget_micros, throttle_on_budget_exceeded, budget_fallbacks, spent_micros, budget_reset_period, budget_reset_at,
			rpm_limit, tpm_limit, mcp_rpm_limit, max_concurrent_requests, batch_enqueued_token_limit, max_iterations, max_budget_per_session_micros, expires_at, is_active,
			rotation_interval_sec, key_rotation_at, key_type, project_id, can_impersonate, tags, metadata
		) VALUES ($1,$2,$3,$4,$5,NULLIF($6,''),NULLIF($7,''),$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28,$29,$30,$31,$32,$33,$34,NULLIF($35,''),$36,$37,$38)`
	if _, err := p.pool.Exec(ctx, q,
		vk.ID, vk.KeyPrefix, vk.KeyHash, vk.Name, vk.OrgID, vk.TeamID, vk.UserID, string(vk.Role),
		vk.AllowedModels, vk.AllowedEndpoints,
		vk.AllowedMCPServers, vk.AllowedA2AAgents, vk.AllowedClientApps,
		vk.MaxBudgetMicros, vk.TempBudgetIncreaseMicros, vk.TempBudgetExpiresAt, vk.SoftBudgetMicros, vk.ThrottleOnBudgetExceeded, marshalBudgetFallbacks(vk.BudgetFallbacks), vk.SpentMicros, string(vk.BudgetResetPeriod), vk.BudgetResetAt,
		vk.RPMLimit, vk.TPMLimit, vk.MCPRPMLimit, vk.MaxConcurrentRequests, vk.BatchEnqueuedTokenLimit, vk.MaxIterations, vk.MaxBudgetPerSessionMicros, vk.ExpiresAt, vk.IsActive,
		vk.RotationIntervalSec, vk.KeyRotationAt, string(vk.KeyType), vk.ProjectID, vk.CanImpersonate, tags, marshalStringMapJSON(vk.Metadata),
	); err != nil {
		return err
	}
	return p.mem.CreateVirtualKey(ctx, vk)
}

func (p *PostgresRepository) UpdateVirtualKey(ctx context.Context, vk *domain.VirtualKey) error {
	if vk == nil || vk.ID == "" {
		return fmt.Errorf("virtual key id is required")
	}
	if vk.AllowedModels == nil {
		vk.AllowedModels = []string{}
	}
	if vk.AllowedEndpoints == nil {
		vk.AllowedEndpoints = append([]string(nil), domain.DefaultAllowedEndpoints...)
	}
	tags := vk.Tags
	if tags == nil {
		tags = []string{}
	}
	if vk.Role == "" {
		vk.Role = domain.RoleServiceAccount
	}
	vk.BudgetResetPeriod, vk.BudgetResetAt = resolveBudgetResetSchedule(vk.BudgetResetPeriod, vk.BudgetResetAt, time.Now().UTC())
	const q = `
		UPDATE virtual_keys SET
			key_prefix = COALESCE(NULLIF($2, ''), key_prefix),
			key_hash = COALESCE(NULLIF($3, ''), key_hash),
			name = $4,
			team_id = NULLIF($5, ''),
			user_id = NULLIF($6, ''),
			role = $7,
			allowed_models = $8,
			allowed_endpoints = $9,
			allowed_mcp_servers = $10,
			allowed_a2a_agents = $11,
			allowed_client_apps = $12,
			max_budget_micros = $13,
			temp_budget_increase_micros = $14,
			temp_budget_expires_at = $15,
			soft_budget_micros = $16,
			throttle_on_budget_exceeded = $17,
			budget_fallbacks = $18,
			spent_micros = $19,
			budget_reset_period = $20,
			budget_reset_at = $21,
			rpm_limit = $22,
			tpm_limit = $23,
			mcp_rpm_limit = $24,
			max_concurrent_requests = $25,
			batch_enqueued_token_limit = $26,
			max_iterations = $27,
			max_budget_per_session_micros = $28,
			expires_at = $29,
			is_active = $30,
			rotation_interval_sec = $31,
			key_rotation_at = $32,
			key_type = COALESCE(NULLIF($33, ''), key_type),
			project_id = NULLIF($34, ''),
			can_impersonate = $35,
			tags = $36,
			metadata = $37,
			updated_at = NOW()
		WHERE id = $1`
	if p.pool != nil {
		tag, err := p.pool.Exec(ctx, q,
			vk.ID, vk.KeyPrefix, vk.KeyHash, vk.Name, vk.TeamID, vk.UserID, string(vk.Role),
			vk.AllowedModels, vk.AllowedEndpoints,
			vk.AllowedMCPServers, vk.AllowedA2AAgents, vk.AllowedClientApps,
			vk.MaxBudgetMicros, vk.TempBudgetIncreaseMicros, vk.TempBudgetExpiresAt, vk.SoftBudgetMicros, vk.ThrottleOnBudgetExceeded, marshalBudgetFallbacks(vk.BudgetFallbacks), vk.SpentMicros, string(vk.BudgetResetPeriod), vk.BudgetResetAt,
			vk.RPMLimit, vk.TPMLimit, vk.MCPRPMLimit, vk.MaxConcurrentRequests, vk.BatchEnqueuedTokenLimit, vk.MaxIterations, vk.MaxBudgetPerSessionMicros, vk.ExpiresAt, vk.IsActive,
			vk.RotationIntervalSec, vk.KeyRotationAt, string(vk.KeyType), vk.ProjectID, vk.CanImpersonate, tags, marshalStringMapJSON(vk.Metadata),
		)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return fmt.Errorf("virtual key %q %w", vk.ID, ErrNotFound)
		}
	}
	if err := p.mem.UpdateVirtualKey(ctx, vk); err != nil {
		if p.pool == nil {
			return err
		}
		_ = p.mem.CreateVirtualKey(ctx, vk)
	}
	return nil
}

func (p *PostgresRepository) GetVirtualKeyByHash(ctx context.Context, keyHash string) (*domain.VirtualKey, error) {
	if p.pool == nil {
		return p.mem.GetVirtualKeyByHash(ctx, keyHash)
	}
	k, err := scanVirtualKey(p.pool.QueryRow(ctx, `SELECT `+virtualKeySelectCols+` FROM virtual_keys WHERE key_hash = $1`, keyHash))
	if err != nil {
		return nil, fmt.Errorf("virtual key not found: %w", err)
	}
	return k, nil
}

func (p *PostgresRepository) GetVirtualKeyByID(ctx context.Context, id string) (*domain.VirtualKey, error) {
	if p.pool == nil {
		return p.mem.GetVirtualKeyByID(ctx, id)
	}
	k, err := scanVirtualKey(p.pool.QueryRow(ctx, `SELECT `+virtualKeySelectCols+` FROM virtual_keys WHERE id = $1`, id))
	if err != nil {
		return nil, fmt.Errorf("virtual key not found: %w", err)
	}
	return k, nil
}

func (p *PostgresRepository) ListVirtualKeys(ctx context.Context, orgID string) ([]*domain.VirtualKey, error) {
	if p.pool == nil {
		return p.mem.ListVirtualKeys(ctx, orgID)
	}
	rows, err := p.pool.Query(ctx, `SELECT `+virtualKeySelectCols+` FROM virtual_keys WHERE org_id = $1 ORDER BY created_at DESC`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var list []*domain.VirtualKey
	for rows.Next() {
		k, err := scanVirtualKey(rows)
		if err != nil {
			return nil, err
		}
		list = append(list, k)
	}
	return list, rows.Err()
}

func (p *PostgresRepository) ListVirtualKeysByUserID(ctx context.Context, orgID, userID string) ([]*domain.VirtualKey, error) {
	orgID = strings.TrimSpace(orgID)
	userID = strings.TrimSpace(userID)
	if userID == "" {
		return nil, nil
	}
	if p.pool == nil {
		return p.mem.ListVirtualKeysByUserID(ctx, orgID, userID)
	}
	var (
		rows pgx.Rows
		err  error
	)
	if orgID != "" {
		rows, err = p.pool.Query(ctx, `SELECT `+virtualKeySelectCols+` FROM virtual_keys WHERE org_id = $1 AND user_id = $2 ORDER BY created_at DESC`, orgID, userID)
	} else {
		rows, err = p.pool.Query(ctx, `SELECT `+virtualKeySelectCols+` FROM virtual_keys WHERE user_id = $1 ORDER BY created_at DESC`, userID)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var list []*domain.VirtualKey
	for rows.Next() {
		k, err := scanVirtualKey(rows)
		if err != nil {
			return nil, err
		}
		list = append(list, k)
	}
	return list, rows.Err()
}

func (p *PostgresRepository) RevokeVirtualKey(ctx context.Context, id string) error {
	return p.RevokeVirtualKeyWithActor(ctx, id, "")
}

func (p *PostgresRepository) RevokeVirtualKeyWithActor(ctx context.Context, id, revokedBy string) error {
	if p.pool == nil {
		return p.mem.RevokeVirtualKeyWithActor(ctx, id, revokedBy)
	}
	var keyHash, orgID string
	err := p.pool.QueryRow(ctx,
		`UPDATE virtual_keys SET is_active = FALSE, revoked_at = COALESCE(revoked_at, NOW()), revoked_by = $2, updated_at = NOW() WHERE id = $1 RETURNING key_hash, org_id`,
		id, strings.TrimSpace(revokedBy),
	).Scan(&keyHash, &orgID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("virtual key %q %w", id, ErrNotFound)
		}
		return err
	}
	_ = p.mem.RevokeVirtualKeyWithActor(ctx, id, revokedBy)
	return nil
}

func (p *PostgresRepository) UnblockVirtualKey(ctx context.Context, id string) error {
	if p.pool == nil {
		return p.mem.UnblockVirtualKey(ctx, id)
	}
	tag, err := p.pool.Exec(ctx,
		`UPDATE virtual_keys SET is_active = TRUE, revoked_at = NULL, revoked_by = '', updated_at = NOW() WHERE id = $1`,
		id,
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("virtual key %q %w", id, ErrNotFound)
	}
	_ = p.mem.UnblockVirtualKey(ctx, id)
	return nil
}

func (p *PostgresRepository) GetVirtualKeyAuthBundleByHash(ctx context.Context, keyHash string, now time.Time) (*VirtualKeyAuthBundle, error) {
	keyHash = strings.TrimSpace(keyHash)
	if keyHash == "" {
		return nil, fmt.Errorf("virtual key %w", ErrNotFound)
	}
	if p.pool == nil {
		return p.mem.GetVirtualKeyAuthBundleByHash(ctx, keyHash, now)
	}
	const q = `
		WITH matched AS (
			SELECT id AS vk_id, FALSE AS is_deprecated, NULL::timestamptz AS revoke_at
			FROM virtual_keys
			WHERE key_hash = $1
			UNION ALL
			SELECT d.virtual_key_id AS vk_id, TRUE AS is_deprecated, d.revoke_at
			FROM virtual_key_deprecated_hashes d
			WHERE d.key_hash = $1
			  AND d.revoke_at > $2
			  AND NOT EXISTS (SELECT 1 FROM virtual_keys WHERE key_hash = $1)
			LIMIT 1
		)
		SELECT
			` + virtualKeySelectColsAliased + `,
			m.is_deprecated,
			m.revoke_at,
			(o.id IS NOT NULL) AS has_org,
			COALESCE(o.id, ''), COALESCE(o.name, ''), COALESCE(o.slug, ''),
			COALESCE(o.max_budget_micros, 0), COALESCE(o.temp_budget_increase_micros, 0), o.temp_budget_expires_at,
			COALESCE(NULLIF(o.self_serve_budget_policy, ''), 'disabled'),
			COALESCE(o.soft_budget_micros, 0), COALESCE(o.throttle_on_budget_exceeded, FALSE), COALESCE(o.budget_fallbacks, '{}'::jsonb),
			COALESCE(o.spent_micros, 0), COALESCE(NULLIF(o.budget_reset_period, ''), 'monthly'), o.budget_reset_at,
			COALESCE(o.rpm_limit, 0), COALESCE(o.tpm_limit, 0), COALESCE(o.max_concurrent_requests, 0),
			COALESCE(o.batch_enqueued_token_limit, 0), COALESCE(o.max_iterations, 0), COALESCE(o.max_budget_per_session_micros, 0),
			COALESCE(o.enforce_guaranteed_throughput, FALSE), COALESCE(o.developer_self_serve_keys, FALSE),
			COALESCE(o.key_expiry_alert_days, '{7,1}'), COALESCE(o.lifecycle_webhook_url, ''), COALESCE(o.is_active, FALSE),
			(t.id IS NOT NULL) AS has_team,
			COALESCE(t.id, ''), COALESCE(t.org_id, ''), COALESCE(t.name, ''),
			COALESCE(t.max_budget_micros, 0), COALESCE(t.temp_budget_increase_micros, 0), t.temp_budget_expires_at,
			COALESCE(t.soft_budget_micros, 0), COALESCE(t.throttle_on_budget_exceeded, FALSE), COALESCE(t.budget_fallbacks, '{}'::jsonb),
			COALESCE(t.spent_micros, 0), COALESCE(NULLIF(t.budget_reset_period, ''), 'monthly'), t.budget_reset_at,
			COALESCE(t.rpm_limit, 0), COALESCE(t.tpm_limit, 0), COALESCE(t.mcp_rpm_limit, 0), COALESCE(t.max_concurrent_requests, 0),
			COALESCE(t.batch_enqueued_token_limit, 0), COALESCE(t.max_iterations, 0), COALESCE(t.max_budget_per_session_micros, 0),
			COALESCE(t.enforce_guaranteed_throughput, FALSE), COALESCE(t.default_member_max_budget_micros, 0),
			COALESCE(t.default_member_rpm_limit, 0), COALESCE(t.default_member_tpm_limit, 0),
			COALESCE(t.default_member_allowed_models, '{}'), COALESCE(t.team_member_permissions, '{}'),
			COALESCE(t.allowed_models, '{}'), t.allowed_mcp_servers, t.allowed_a2a_agents, t.allowed_client_apps,
			COALESCE(t.is_active, FALSE),
			(pr.id IS NOT NULL) AS has_project,
			COALESCE(pr.id, ''), COALESCE(pr.org_id, ''), COALESCE(pr.team_id, ''), COALESCE(pr.name, ''), COALESCE(pr.description, ''),
			COALESCE(pr.max_budget_micros, 0), COALESCE(pr.spent_micros, 0), COALESCE(pr.rpm_limit, 0), COALESCE(pr.tpm_limit, 0),
			COALESCE(pr.allowed_models, '{}'), COALESCE(pr.enforce_project_model_quota, FALSE), COALESCE(pr.is_active, FALSE),
			(u.id IS NOT NULL) AS has_user,
			COALESCE(u.id, ''), COALESCE(u.org_id, ''), COALESCE(u.team_id, ''), COALESCE(u.email, ''), COALESCE(u.name, ''), COALESCE(u.role, ''),
			COALESCE(u.oidc_subject, ''), COALESCE(u.scim_external_id, ''), COALESCE(u.scim_active, TRUE),
			COALESCE(u.max_budget_micros, 0), COALESCE(u.temp_budget_increase_micros, 0), u.temp_budget_expires_at,
			COALESCE(u.soft_budget_micros, 0), COALESCE(u.throttle_on_budget_exceeded, FALSE), COALESCE(u.budget_fallbacks, '{}'::jsonb),
			COALESCE(u.spent_micros, 0), COALESCE(NULLIF(u.budget_reset_period, ''), 'monthly'), u.budget_reset_at,
			COALESCE(u.rpm_limit, 0), COALESCE(u.tpm_limit, 0), COALESCE(u.max_concurrent_requests, 0), COALESCE(u.batch_enqueued_token_limit, 0),
			COALESCE(u.is_active, FALSE),
			(tm.id IS NOT NULL) AS has_tm,
			COALESCE(tm.id, ''), COALESCE(tm.org_id, ''), COALESCE(tm.team_id, ''), COALESCE(tm.user_id, ''), COALESCE(tm.role, ''),
			COALESCE(tm.max_budget_micros, 0), COALESCE(tm.spent_micros, 0), COALESCE(tm.rpm_limit, 0), COALESCE(tm.tpm_limit, 0), COALESCE(tm.allowed_models, '{}')
		FROM matched m
		JOIN virtual_keys vk ON vk.id = m.vk_id
		LEFT JOIN organizations o ON o.id = vk.org_id
		LEFT JOIN teams t ON t.id = vk.team_id
		LEFT JOIN projects pr ON pr.id = vk.project_id
		LEFT JOIN users u ON u.id = vk.user_id
		LEFT JOIN team_memberships tm ON tm.team_id = vk.team_id AND tm.user_id = vk.user_id`

	var (
		k                         domain.VirtualKey
		vkRole, vkPeriod, keyType string
		vkFallbacks, vkMeta       []byte
		vkSentDays                []int32
		deprecated                bool
		revokeAt                  *time.Time

		hasOrg              bool
		o                   domain.Organization
		oPeriod, oSelfServe string
		oFallbacks          []byte
		oAlertDays          []int32

		hasTeam    bool
		t          domain.Team
		tPeriod    string
		tFallbacks []byte

		hasProj bool
		pr      domain.Project

		hasUser        bool
		u              domain.User
		uRole, uPeriod string
		uFallbacks     []byte

		hasTM  bool
		tm     domain.TeamMembership
		tmRole string
	)

	err := p.pool.QueryRow(ctx, q, keyHash, now.UTC()).Scan(
		&k.ID, &k.KeyPrefix, &k.KeyHash, &k.Name, &k.OrgID, &k.TeamID, &k.UserID, &vkRole,
		&k.AllowedModels, &k.AllowedEndpoints,
		&k.AllowedMCPServers, &k.AllowedA2AAgents, &k.AllowedClientApps,
		&k.MaxBudgetMicros, &k.TempBudgetIncreaseMicros, &k.TempBudgetExpiresAt, &k.SoftBudgetMicros, &k.ThrottleOnBudgetExceeded, &vkFallbacks, &k.SpentMicros, &vkPeriod, &k.BudgetResetAt,
		&k.RPMLimit, &k.TPMLimit, &k.MCPRPMLimit, &k.MaxConcurrentRequests, &k.BatchEnqueuedTokenLimit, &k.MaxIterations, &k.MaxBudgetPerSessionMicros, &k.ExpiresAt, &k.IsActive,
		&k.RotationIntervalSec, &k.KeyRotationAt, &k.LastRotatedAt, &k.RotationCount, &k.RevokedAt, &k.RevokedBy, &vkSentDays,
		&keyType, &k.ProjectID, &k.CanImpersonate, &k.Tags, &vkMeta,
		&deprecated, &revokeAt,
		&hasOrg,
		&o.ID, &o.Name, &o.Slug, &o.MaxBudgetMicros, &o.TempBudgetIncreaseMicros, &o.TempBudgetExpiresAt, &oSelfServe,
		&o.SoftBudgetMicros, &o.ThrottleOnBudgetExceeded, &oFallbacks, &o.SpentMicros, &oPeriod, &o.BudgetResetAt,
		&o.RPMLimit, &o.TPMLimit, &o.MaxConcurrentRequests, &o.BatchEnqueuedTokenLimit, &o.MaxIterations, &o.MaxBudgetPerSessionMicros,
		&o.EnforceGuaranteedThroughput, &o.DeveloperSelfServeKeys, &oAlertDays, &o.LifecycleWebhookURL, &o.IsActive,
		&hasTeam,
		&t.ID, &t.OrgID, &t.Name, &t.MaxBudgetMicros, &t.TempBudgetIncreaseMicros, &t.TempBudgetExpiresAt,
		&t.SoftBudgetMicros, &t.ThrottleOnBudgetExceeded, &tFallbacks, &t.SpentMicros, &tPeriod, &t.BudgetResetAt,
		&t.RPMLimit, &t.TPMLimit, &t.MCPRPMLimit, &t.MaxConcurrentRequests, &t.BatchEnqueuedTokenLimit, &t.MaxIterations, &t.MaxBudgetPerSessionMicros,
		&t.EnforceGuaranteedThroughput, &t.DefaultMemberMaxBudgetMicros, &t.DefaultMemberRPMLimit, &t.DefaultMemberTPMLimit,
		&t.DefaultMemberAllowedModels, &t.TeamMemberPermissions,
		&t.AllowedModels, &t.AllowedMCPServers, &t.AllowedA2AAgents, &t.AllowedClientApps, &t.IsActive,
		&hasProj,
		&pr.ID, &pr.OrgID, &pr.TeamID, &pr.Name, &pr.Description, &pr.MaxBudgetMicros, &pr.SpentMicros, &pr.RPMLimit, &pr.TPMLimit,
		&pr.AllowedModels, &pr.EnforceProjectModelQuota, &pr.IsActive,
		&hasUser,
		&u.ID, &u.OrgID, &u.TeamID, &u.Email, &u.Name, &uRole, &u.OIDCSubject, &u.SCIMExternalID, &u.SCIMActive,
		&u.MaxBudgetMicros, &u.TempBudgetIncreaseMicros, &u.TempBudgetExpiresAt,
		&u.SoftBudgetMicros, &u.ThrottleOnBudgetExceeded, &uFallbacks, &u.SpentMicros, &uPeriod, &u.BudgetResetAt,
		&u.RPMLimit, &u.TPMLimit, &u.MaxConcurrentRequests, &u.BatchEnqueuedTokenLimit, &u.IsActive,
		&hasTM,
		&tm.ID, &tm.OrgID, &tm.TeamID, &tm.UserID, &tmRole, &tm.MaxBudgetMicros, &tm.SpentMicros, &tm.RPMLimit, &tm.TPMLimit, &tm.AllowedModels,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("virtual key %w", ErrNotFound)
		}
		return nil, err
	}

	k.Role = domain.Role(vkRole)
	k.BudgetResetPeriod = domain.BudgetResetPeriod(vkPeriod)
	k.BudgetFallbacks = unmarshalBudgetFallbacks(vkFallbacks)
	k.Metadata = unmarshalStringMapJSON(vkMeta)
	k.ExpiryAlertSentDays = int32sToInts(vkSentDays)
	k.KeyType = domain.KeyType(keyType)
	if k.KeyType == "" {
		k.KeyType = domain.KeyTypeDefault
	}

	bundle := &VirtualKeyAuthBundle{
		Key:        &k,
		Deprecated: deprecated,
	}
	if revokeAt != nil {
		bundle.DeprecatedKeyRevokeAt = revokeAt.UTC()
	}
	if hasOrg {
		o.BudgetResetPeriod = domain.BudgetResetPeriod(oPeriod)
		o.SelfServeBudgetPolicy = domain.SelfServeBudgetPolicy(oSelfServe)
		o.BudgetFallbacks = unmarshalBudgetFallbacks(oFallbacks)
		o.KeyExpiryAlertDays = int32sToInts(oAlertDays)
		bundle.Org = &o
	}
	if hasTeam {
		t.BudgetResetPeriod = domain.BudgetResetPeriod(tPeriod)
		t.BudgetFallbacks = unmarshalBudgetFallbacks(tFallbacks)
		bundle.Team = &t
	}
	if hasProj {
		bundle.Project = &pr
	}
	if hasUser {
		u.Role = domain.Role(uRole)
		u.BudgetResetPeriod = domain.BudgetResetPeriod(uPeriod)
		u.BudgetFallbacks = unmarshalBudgetFallbacks(uFallbacks)
		bundle.User = &u
	}
	if hasTM {
		tm.Role = domain.Role(tmRole)
		bundle.TeamMembership = &tm
	}
	return bundle, nil
}

func (p *PostgresRepository) ListVirtualKeysFiltered(ctx context.Context, filter VirtualKeyFilter) ([]*domain.VirtualKey, int, error) {
	if p.pool == nil {
		return p.mem.ListVirtualKeysFiltered(ctx, filter)
	}
	var conds []string
	var args []any
	addEq := func(col, val string) {
		if v := strings.TrimSpace(val); v != "" {
			args = append(args, v)
			conds = append(conds, fmt.Sprintf("%s = $%d", col, len(args)))
		}
	}
	addEq("org_id", filter.OrgID)
	addEq("team_id", filter.TeamID)
	addEq("user_id", filter.UserID)
	addEq("project_id", filter.ProjectID)
	switch strings.ToLower(strings.TrimSpace(filter.Status)) {
	case "active":
		conds = append(conds, "is_active = TRUE AND (expires_at IS NULL OR expires_at > NOW())")
	case "revoked":
		conds = append(conds, "is_active = FALSE")
	case "expired":
		conds = append(conds, "expires_at IS NOT NULL AND expires_at <= NOW()")
	}
	if qStr := strings.TrimSpace(filter.Search); qStr != "" {
		args = append(args, "%"+qStr+"%")
		conds = append(conds, fmt.Sprintf("(id ILIKE $%d OR key_prefix ILIKE $%d OR name ILIKE $%d)", len(args), len(args), len(args)))
	}
	where := ""
	if len(conds) > 0 {
		where = " WHERE " + strings.Join(conds, " AND ")
	}
	var total int
	if err := p.pool.QueryRow(ctx, `SELECT COUNT(*) FROM virtual_keys`+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	q := `SELECT ` + virtualKeySelectCols + ` FROM virtual_keys` + where + ` ORDER BY created_at DESC, id ASC`
	if filter.Limit > 0 {
		args = append(args, filter.Limit)
		q += fmt.Sprintf(" LIMIT $%d", len(args))
	}
	if filter.Offset > 0 {
		args = append(args, filter.Offset)
		q += fmt.Sprintf(" OFFSET $%d", len(args))
	}
	rows, err := p.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var list []*domain.VirtualKey
	for rows.Next() {
		k, scanErr := scanVirtualKey(rows)
		if scanErr != nil {
			return nil, 0, scanErr
		}
		list = append(list, k)
	}
	return list, total, rows.Err()
}

func (p *PostgresRepository) BulkUpdateVirtualKeys(ctx context.Context, orgID string, ids []string, patch VirtualKeyBulkPatch) ([]*domain.VirtualKey, error) {
	if p.pool == nil {
		return p.mem.BulkUpdateVirtualKeys(ctx, orgID, ids, patch)
	}
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var updated []*domain.VirtualKey
	for _, id := range ids {
		var sets []string
		args := []any{id}
		addSet := func(expr string, val any) {
			args = append(args, val)
			sets = append(sets, fmt.Sprintf("%s = $%d", expr, len(args)))
		}
		if patch.IsActive != nil {
			addSet("is_active", *patch.IsActive)
			if !*patch.IsActive {
				sets = append(sets, "revoked_at = COALESCE(revoked_at, NOW())")
				addSet("revoked_by", strings.TrimSpace(patch.RevokedBy))
			} else {
				sets = append(sets, "revoked_at = NULL", "revoked_by = ''")
			}
		}
		if patch.MaxBudgetMicros != nil {
			addSet("max_budget_micros", *patch.MaxBudgetMicros)
		}
		if patch.RPMLimit != nil {
			addSet("rpm_limit", *patch.RPMLimit)
		}
		if patch.TPMLimit != nil {
			addSet("tpm_limit", *patch.TPMLimit)
		}
		if patch.AllowedModels != nil {
			addSet("allowed_models", patch.AllowedModels)
		}
		sets = append(sets, "updated_at = NOW()")
		where := "id = $1"
		if strings.TrimSpace(orgID) != "" {
			args = append(args, strings.TrimSpace(orgID))
			where += fmt.Sprintf(" AND org_id = $%d", len(args))
		}
		q := `UPDATE virtual_keys SET ` + strings.Join(sets, ", ") + ` WHERE ` + where + ` RETURNING ` + virtualKeySelectCols
		k, scanErr := scanVirtualKey(tx.QueryRow(ctx, q, args...))
		if scanErr != nil {
			if errors.Is(scanErr, pgx.ErrNoRows) {
				return nil, fmt.Errorf("virtual key %q %w", id, ErrNotFound)
			}
			return nil, scanErr
		}
		if patch.IsActive != nil && !*patch.IsActive {
			if _, delErr := tx.Exec(ctx, `DELETE FROM virtual_key_deprecated_hashes WHERE virtual_key_id = $1`, k.ID); delErr != nil {
				return nil, delErr
			}
		}
		updated = append(updated, k)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	_, _ = p.mem.BulkUpdateVirtualKeys(ctx, orgID, ids, patch)
	return updated, nil
}

func (p *PostgresRepository) ResetEntitySpend(ctx context.Context, scope EntitySpendScope, orgID, entityID, secondaryID string) error {
	if p.pool == nil {
		return p.mem.ResetEntitySpend(ctx, scope, orgID, entityID, secondaryID)
	}
	switch scope {
	case EntitySpendScopeKey:
		tag, err := p.pool.Exec(ctx, `UPDATE virtual_keys SET spent_micros = 0, updated_at = NOW() WHERE id = $1 AND ($2 = '' OR org_id = $2)`, entityID, strings.TrimSpace(orgID))
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return fmt.Errorf("virtual key %q %w", entityID, ErrNotFound)
		}
	case EntitySpendScopeTeamMember:
		tag, err := p.pool.Exec(ctx, `UPDATE team_memberships SET spent_micros = 0, updated_at = NOW() WHERE team_id = $1 AND user_id = $2 AND ($3 = '' OR org_id = $3)`, entityID, secondaryID, strings.TrimSpace(orgID))
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return fmt.Errorf("team membership (%q, %q) %w", entityID, secondaryID, ErrNotFound)
		}
	default:
		return fmt.Errorf("unsupported spend reset scope %q", scope)
	}
	_ = p.mem.ResetEntitySpend(ctx, scope, orgID, entityID, secondaryID)
	return nil
}

func (p *PostgresRepository) SumChildKeyThroughput(ctx context.Context, orgID, teamID, excludeKeyID string) (int, int, error) {
	if p.pool == nil {
		return p.mem.SumChildKeyThroughput(ctx, orgID, teamID, excludeKeyID)
	}
	var rpmSum, tpmSum int
	var q string
	var args []any
	if strings.TrimSpace(teamID) != "" {
		q = `SELECT COALESCE(SUM(rpm_limit), 0), COALESCE(SUM(tpm_limit), 0) FROM virtual_keys WHERE org_id = $1 AND team_id = $2 AND is_active = TRUE AND ($3 = '' OR id <> $3)`
		args = []any{orgID, teamID, excludeKeyID}
	} else {
		q = `SELECT COALESCE(SUM(rpm_limit), 0), COALESCE(SUM(tpm_limit), 0) FROM virtual_keys WHERE org_id = $1 AND is_active = TRUE AND ($2 = '' OR id <> $2)`
		args = []any{orgID, excludeKeyID}
	}
	if err := p.pool.QueryRow(ctx, q, args...).Scan(&rpmSum, &tpmSum); err != nil {
		return 0, 0, err
	}
	return rpmSum, tpmSum, nil
}

func (p *PostgresRepository) ListVirtualKeysExpiringBefore(ctx context.Context, cutoff time.Time, limit int) ([]*domain.VirtualKey, error) {
	if p.pool == nil {
		return p.mem.ListVirtualKeysExpiringBefore(ctx, cutoff, limit)
	}
	if limit <= 0 {
		limit = 200
	}
	const q = `
		SELECT ` + virtualKeySelectCols + `
		FROM virtual_keys
		WHERE is_active = TRUE
		  AND expires_at IS NOT NULL
		  AND expires_at > NOW()
		  AND expires_at <= $1
		ORDER BY expires_at ASC, id ASC
		LIMIT $2`
	rows, err := p.pool.Query(ctx, q, cutoff.UTC(), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var list []*domain.VirtualKey
	for rows.Next() {
		k, scanErr := scanVirtualKey(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		list = append(list, k)
	}
	return list, rows.Err()
}

func (p *PostgresRepository) MarkVirtualKeyExpiryAlertSent(ctx context.Context, keyID string, alertDay int) error {
	if p.pool == nil {
		return p.mem.MarkVirtualKeyExpiryAlertSent(ctx, keyID, alertDay)
	}
	const q = `
		UPDATE virtual_keys
		SET expiry_alert_sent_days = CASE
			WHEN $2 = ANY(COALESCE(expiry_alert_sent_days, '{}')) THEN COALESCE(expiry_alert_sent_days, '{}')
			ELSE array_append(COALESCE(expiry_alert_sent_days, '{}'), $2)
		END
		WHERE id = $1`
	tag, err := p.pool.Exec(ctx, q, keyID, int32(alertDay))
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("virtual key %q %w", keyID, ErrNotFound)
	}
	_ = p.mem.MarkVirtualKeyExpiryAlertSent(ctx, keyID, alertDay)
	return nil
}

func (p *PostgresRepository) MarkVirtualKeyRotated(ctx context.Context, keyID string, rotatedAt time.Time) error {
	if p.pool == nil {
		return p.mem.MarkVirtualKeyRotated(ctx, keyID, rotatedAt)
	}
	ts := rotatedAt.UTC()
	tag, err := p.pool.Exec(ctx, `UPDATE virtual_keys SET last_rotated_at = $2, rotation_count = rotation_count + 1, updated_at = $2 WHERE id = $1`, keyID, ts)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("virtual key %q %w", keyID, ErrNotFound)
	}
	_ = p.mem.MarkVirtualKeyRotated(ctx, keyID, ts)
	return nil
}

func (p *PostgresRepository) AddDeprecatedVirtualKeyHash(ctx context.Context, keyHash, virtualKeyID string, revokeAt time.Time) error {
	keyHash = strings.TrimSpace(keyHash)
	virtualKeyID = strings.TrimSpace(virtualKeyID)
	if keyHash == "" || virtualKeyID == "" {
		return fmt.Errorf("key_hash and virtual_key_id are required")
	}
	revUTC := revokeAt.UTC()
	if p.pool == nil {
		return p.mem.AddDeprecatedVirtualKeyHash(ctx, keyHash, virtualKeyID, revUTC)
	}
	const q = `
		INSERT INTO virtual_key_deprecated_hashes (key_hash, virtual_key_id, revoke_at, created_at)
		VALUES ($1, $2, $3, NOW())
		ON CONFLICT (key_hash) DO UPDATE SET
			virtual_key_id = EXCLUDED.virtual_key_id,
			revoke_at = EXCLUDED.revoke_at`
	if _, err := p.pool.Exec(ctx, q, keyHash, virtualKeyID, revUTC); err != nil {
		return err
	}
	_ = p.mem.AddDeprecatedVirtualKeyHash(ctx, keyHash, virtualKeyID, revUTC)
	return nil
}

func (p *PostgresRepository) GetActiveDeprecatedVirtualKey(ctx context.Context, keyHash string, now time.Time) (*domain.VirtualKey, time.Time, error) {
	keyHash = strings.TrimSpace(keyHash)
	if keyHash == "" {
		return nil, time.Time{}, fmt.Errorf("deprecated virtual key %w", ErrNotFound)
	}
	nowUTC := now.UTC()
	if p.pool == nil {
		return p.mem.GetActiveDeprecatedVirtualKey(ctx, keyHash, nowUTC)
	}
	const q = `
		SELECT ` + virtualKeySelectColsAliased + `, d.revoke_at
		FROM virtual_key_deprecated_hashes d
		JOIN virtual_keys vk ON vk.id = d.virtual_key_id
		WHERE d.key_hash = $1 AND d.revoke_at > $2`
	vk, revokeAt, err := scanDeprecatedVirtualKey(p.pool.QueryRow(ctx, q, keyHash, nowUTC))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, time.Time{}, fmt.Errorf("deprecated virtual key %w", ErrNotFound)
		}
		return nil, time.Time{}, err
	}
	return vk, revokeAt, nil
}

func (p *PostgresRepository) DeleteExpiredDeprecatedVirtualKeyHashes(ctx context.Context, now time.Time) (int64, error) {
	nowUTC := now.UTC()
	if p.pool == nil {
		return p.mem.DeleteExpiredDeprecatedVirtualKeyHashes(ctx, nowUTC)
	}
	tag, err := p.pool.Exec(ctx, `DELETE FROM virtual_key_deprecated_hashes WHERE revoke_at <= $1`, nowUTC)
	if err != nil {
		return 0, err
	}
	_, _ = p.mem.DeleteExpiredDeprecatedVirtualKeyHashes(ctx, nowUTC)
	return tag.RowsAffected(), nil
}

func (p *PostgresRepository) ListDeprecatedVirtualKeyHashesByKeyID(ctx context.Context, virtualKeyID string) ([]string, error) {
	virtualKeyID = strings.TrimSpace(virtualKeyID)
	if virtualKeyID == "" {
		return nil, nil
	}
	if p.pool == nil {
		return p.mem.ListDeprecatedVirtualKeyHashesByKeyID(ctx, virtualKeyID)
	}
	rows, err := p.pool.Query(ctx, `SELECT TRIM(key_hash) FROM virtual_key_deprecated_hashes WHERE virtual_key_id = $1 ORDER BY key_hash ASC`, virtualKeyID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var hashes []string
	for rows.Next() {
		var h string
		if err := rows.Scan(&h); err != nil {
			return nil, err
		}
		if h != "" {
			hashes = append(hashes, h)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return hashes, nil
}

func (p *PostgresRepository) DeleteDeprecatedVirtualKeyHashesByKeyID(ctx context.Context, virtualKeyID string) ([]string, error) {
	virtualKeyID = strings.TrimSpace(virtualKeyID)
	if virtualKeyID == "" {
		return nil, nil
	}
	if p.pool == nil {
		return p.mem.DeleteDeprecatedVirtualKeyHashesByKeyID(ctx, virtualKeyID)
	}
	rows, err := p.pool.Query(ctx, `DELETE FROM virtual_key_deprecated_hashes WHERE virtual_key_id = $1 RETURNING TRIM(key_hash)`, virtualKeyID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var hashes []string
	for rows.Next() {
		var h string
		if err := rows.Scan(&h); err != nil {
			return nil, err
		}
		if h != "" {
			hashes = append(hashes, h)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	_, _ = p.mem.DeleteDeprecatedVirtualKeyHashesByKeyID(ctx, virtualKeyID)
	return hashes, nil
}

func (p *PostgresRepository) ListVirtualKeysDueForRotation(ctx context.Context, now time.Time, limit int) ([]*domain.VirtualKey, error) {
	nowUTC := now.UTC()
	if p.pool == nil {
		return p.mem.ListVirtualKeysDueForRotation(ctx, nowUTC, limit)
	}
	if limit <= 0 {
		limit = 100
	}
	const q = `
		SELECT ` + virtualKeySelectCols + `
		FROM virtual_keys
		WHERE is_active = TRUE
		  AND rotation_interval_sec > 0
		  AND key_rotation_at IS NOT NULL
		  AND key_rotation_at <= $1
		  AND (expires_at IS NULL OR expires_at > $1)
		ORDER BY key_rotation_at ASC, id ASC
		LIMIT $2`
	rows, err := p.pool.Query(ctx, q, nowUTC, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var list []*domain.VirtualKey
	for rows.Next() {
		k, err := scanVirtualKey(rows)
		if err != nil {
			return nil, err
		}
		list = append(list, k)
	}
	return list, rows.Err()
}

func (p *PostgresRepository) CreateProviderCredential(ctx context.Context, cred *domain.ProviderCredential) error {
	if p.pool == nil {
		return p.mem.CreateProviderCredential(ctx, cred)
	}
	if cred.ID == "" {
		cred.ID = uuid.NewString()
	}
	const q = `
		INSERT INTO provider_credentials (
			id, org_id, provider, name, base_url, azure_deployment_name, api_version,
			encrypted_api_key, data_nonce, encrypted_dek, dek_nonce, key_version,
			expires_at, last_rotated_at, last_validated_at, is_active
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)
		ON CONFLICT (org_id, name) DO UPDATE SET
			encrypted_api_key = EXCLUDED.encrypted_api_key,
			data_nonce = EXCLUDED.data_nonce,
			encrypted_dek = EXCLUDED.encrypted_dek,
			dek_nonce = EXCLUDED.dek_nonce,
			base_url = EXCLUDED.base_url,
			azure_deployment_name = EXCLUDED.azure_deployment_name,
			api_version = EXCLUDED.api_version,
			updated_at = NOW()
		RETURNING id`
	kv := cred.KeyVersion
	if kv <= 0 {
		kv = 1
	}
	if err := p.pool.QueryRow(ctx, q,
		cred.ID, cred.OrgID, string(cred.Provider), cred.Name, cred.BaseURL,
		cred.AzureDeploymentName, cred.APIVersion,
		cred.EncryptedAPIKey, cred.DataNonce, cred.EncryptedDEK, cred.DEKNonce,
		kv, cred.ExpiresAt, cred.LastRotatedAt, cred.LastValidatedAt, cred.IsActive,
	).Scan(&cred.ID); err != nil {
		return err
	}
	return p.mem.CreateProviderCredential(ctx, cred)
}

const providerCredentialSelectCols = `id, org_id, provider, name, base_url, COALESCE(azure_deployment_name, ''), COALESCE(api_version, ''), encrypted_api_key, data_nonce, encrypted_dek, dek_nonce, key_version, expires_at, last_rotated_at, last_validated_at, is_active`

func scanProviderCredential(row rowScanner) (*domain.ProviderCredential, error) {
	var c domain.ProviderCredential
	var prov string
	if err := row.Scan(
		&c.ID, &c.OrgID, &prov, &c.Name, &c.BaseURL, &c.AzureDeploymentName, &c.APIVersion,
		&c.EncryptedAPIKey, &c.DataNonce, &c.EncryptedDEK, &c.DEKNonce,
		&c.KeyVersion, &c.ExpiresAt, &c.LastRotatedAt, &c.LastValidatedAt, &c.IsActive,
	); err != nil {
		return nil, err
	}
	c.Provider = domain.ProviderType(prov)
	return &c, nil
}

func (p *PostgresRepository) GetProviderCredential(ctx context.Context, id string) (*domain.ProviderCredential, error) {
	if p.pool == nil {
		return p.mem.GetProviderCredential(ctx, id)
	}
	const q = `SELECT ` + providerCredentialSelectCols + ` FROM provider_credentials WHERE id = $1`
	c, err := scanProviderCredential(p.pool.QueryRow(ctx, q, id))
	if err != nil {
		return nil, fmt.Errorf("credential not found: %w", err)
	}
	_ = p.mem.CreateProviderCredential(ctx, c)
	return c, nil
}

func (p *PostgresRepository) hydrateProviderCredentials(ctx context.Context, ids []string) error {
	if len(ids) == 0 {
		return nil
	}
	const q = `SELECT ` + providerCredentialSelectCols + ` FROM provider_credentials WHERE id = ANY($1)`
	rows, err := p.pool.Query(ctx, q, ids)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		c, err := scanProviderCredential(rows)
		if err != nil {
			return err
		}
		_ = p.mem.CreateProviderCredential(ctx, c)
	}
	return rows.Err()
}

func (p *PostgresRepository) UpdateProviderCredential(ctx context.Context, cred *domain.ProviderCredential) error {
	if p.pool == nil {
		return p.mem.UpdateProviderCredential(ctx, cred)
	}
	kv := cred.KeyVersion
	if kv <= 0 {
		kv = 1
	}
	if _, err := p.pool.Exec(ctx, `
		UPDATE provider_credentials SET
			azure_deployment_name = $2,
			api_version = $3,
			encrypted_api_key = $4,
			data_nonce = $5,
			encrypted_dek = $6,
			dek_nonce = $7,
			key_version = $8,
			expires_at = $9,
			last_rotated_at = $10,
			last_validated_at = $11,
			is_active = $12,
			updated_at = NOW()
		WHERE id = $1`,
		cred.ID, cred.AzureDeploymentName, cred.APIVersion,
		cred.EncryptedAPIKey, cred.DataNonce, cred.EncryptedDEK, cred.DEKNonce,
		kv, cred.ExpiresAt, cred.LastRotatedAt, cred.LastValidatedAt, cred.IsActive,
	); err != nil {
		return err
	}
	if err := p.mem.UpdateProviderCredential(ctx, cred); err != nil {
		_ = p.mem.CreateProviderCredential(ctx, cred)
	}
	return nil
}

func (p *PostgresRepository) ListProviderCredentials(ctx context.Context, orgID string) ([]*domain.ProviderCredential, error) {
	if p.pool == nil {
		return p.mem.ListProviderCredentials(ctx, orgID)
	}
	const q = `SELECT ` + providerCredentialSelectCols + ` FROM provider_credentials WHERE ($1 = '' OR org_id = $1) ORDER BY name ASC`
	rows, err := p.pool.Query(ctx, q, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*domain.ProviderCredential
	for rows.Next() {
		c, err := scanProviderCredential(rows)
		if err != nil {
			return nil, err
		}
		_ = p.mem.CreateProviderCredential(ctx, c)
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func isJSONObjectNonEmpty(raw []byte) bool {
	trimmed := strings.TrimSpace(string(raw))
	return trimmed != "" && trimmed != "{}" && trimmed != "null"
}

const modelGroupSelectCols = `id, org_id, alias, description, routing_strategy, fallback_group_ids, COALESCE(context_window_fallbacks, '[]'::jsonb), COALESCE(content_policy_fallbacks, '[]'::jsonb), COALESCE(fallback_targets, '[]'::jsonb), COALESCE(retry_policy, '{}'::jsonb), COALESCE(cooldown_policy, '{}'::jsonb), max_retries, cooldown_seconds, failure_threshold, is_active`

func scanModelGroup(row rowScanner) (*domain.ModelGroup, error) {
	var g domain.ModelGroup
	var strat string
	var fbs []string
	var rawCtxFbs, rawContentFbs, rawTargets, rawRetry, rawCooldown []byte
	if err := row.Scan(
		&g.ID, &g.OrgID, &g.Alias, &g.Description, &strat, &fbs,
		&rawCtxFbs, &rawContentFbs, &rawTargets, &rawRetry, &rawCooldown,
		&g.MaxRetries, &g.CooldownSeconds, &g.FailureThreshold, &g.IsActive,
	); err != nil {
		return nil, err
	}
	g.RoutingStrategy = domain.RoutingStrategy(strat)
	g.FallbackGroupIDs = fbs
	if g.FallbackGroupIDs == nil {
		g.FallbackGroupIDs = []string{}
	}
	if len(rawCtxFbs) > 0 {
		_ = json.Unmarshal(rawCtxFbs, &g.ContextWindowFallbacks)
	}
	if len(rawContentFbs) > 0 {
		_ = json.Unmarshal(rawContentFbs, &g.ContentPolicyFallbacks)
	}
	if len(rawTargets) > 0 {
		_ = json.Unmarshal(rawTargets, &g.FallbackTargets)
	}
	if isJSONObjectNonEmpty(rawRetry) {
		var rp domain.RetryPolicy
		if err := json.Unmarshal(rawRetry, &rp); err == nil {
			g.RetryPolicy = &rp
		}
	}
	if isJSONObjectNonEmpty(rawCooldown) {
		var cp domain.CooldownPolicy
		if err := json.Unmarshal(rawCooldown, &cp); err == nil {
			g.CooldownPolicy = &cp
		}
	}
	return &g, nil
}

func (p *PostgresRepository) CreateModelGroup(ctx context.Context, mg *domain.ModelGroup) error {
	if mg.ID == "" {
		mg.ID = uuid.NewString()
	}
	if p.pool == nil {
		return p.mem.CreateModelGroup(ctx, mg)
	}
	fbs := mg.FallbackGroupIDs
	if fbs == nil {
		fbs = []string{}
	}
	ctxFbsJSON, err := marshalJSONOrDefault(mg.ContextWindowFallbacks, "[]")
	if err != nil {
		return fmt.Errorf("marshal context_window_fallbacks: %w", err)
	}
	contentFbsJSON, err := marshalJSONOrDefault(mg.ContentPolicyFallbacks, "[]")
	if err != nil {
		return fmt.Errorf("marshal content_policy_fallbacks: %w", err)
	}
	targetsJSON, err := marshalJSONOrDefault(mg.FallbackTargets, "[]")
	if err != nil {
		return fmt.Errorf("marshal fallback_targets: %w", err)
	}
	retryJSON, err := marshalJSONOrDefault(mg.RetryPolicy, "{}")
	if err != nil {
		return fmt.Errorf("marshal retry_policy: %w", err)
	}
	cooldownJSON, err := marshalJSONOrDefault(mg.CooldownPolicy, "{}")
	if err != nil {
		return fmt.Errorf("marshal cooldown_policy: %w", err)
	}
	const q = `
		INSERT INTO model_groups (
			id, org_id, alias, description, routing_strategy, fallback_group_ids,
			context_window_fallbacks, content_policy_fallbacks, fallback_targets,
			retry_policy, cooldown_policy, max_retries, cooldown_seconds, failure_threshold, is_active
		)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
		ON CONFLICT (org_id, alias) DO UPDATE SET
			routing_strategy = EXCLUDED.routing_strategy,
			fallback_group_ids = EXCLUDED.fallback_group_ids,
			context_window_fallbacks = EXCLUDED.context_window_fallbacks,
			content_policy_fallbacks = EXCLUDED.content_policy_fallbacks,
			fallback_targets = EXCLUDED.fallback_targets,
			retry_policy = EXCLUDED.retry_policy,
			cooldown_policy = EXCLUDED.cooldown_policy,
			updated_at = NOW()
		RETURNING id`
	if err := p.pool.QueryRow(ctx, q,
		mg.ID, mg.OrgID, mg.Alias, mg.Description, string(mg.RoutingStrategy), fbs,
		ctxFbsJSON, contentFbsJSON, targetsJSON, retryJSON, cooldownJSON,
		mg.MaxRetries, mg.CooldownSeconds, mg.FailureThreshold, mg.IsActive,
	).Scan(&mg.ID); err != nil {
		return err
	}
	return p.mem.CreateModelGroup(ctx, mg)
}

func (p *PostgresRepository) GetModelGroupByAlias(ctx context.Context, orgID, alias string) (*domain.ModelGroup, error) {
	if p.pool == nil {
		return p.mem.GetModelGroupByAlias(ctx, orgID, alias)
	}
	const q = `SELECT ` + modelGroupSelectCols + ` FROM model_groups WHERE org_id = $1 AND alias = $2`
	g, err := scanModelGroup(p.pool.QueryRow(ctx, q, orgID, alias))
	if err != nil {
		return nil, fmt.Errorf("model group not found: %w", err)
	}
	_ = p.mem.CreateModelGroup(ctx, g)
	return g, nil
}

func (p *PostgresRepository) GetModelGroupByID(ctx context.Context, id string) (*domain.ModelGroup, error) {
	if p.pool == nil {
		return p.mem.GetModelGroupByID(ctx, id)
	}
	const q = `SELECT ` + modelGroupSelectCols + ` FROM model_groups WHERE id = $1`
	g, err := scanModelGroup(p.pool.QueryRow(ctx, q, id))
	if err != nil {
		return nil, fmt.Errorf("model group not found: %w", err)
	}
	_ = p.mem.CreateModelGroup(ctx, g)
	return g, nil
}

func (p *PostgresRepository) ListModelGroups(ctx context.Context, orgID string) ([]*domain.ModelGroup, error) {
	if p.pool == nil {
		return p.mem.ListModelGroups(ctx, orgID)
	}
	const q = `SELECT ` + modelGroupSelectCols + ` FROM model_groups WHERE ($1 = '' OR org_id = $1) ORDER BY alias ASC`
	rows, err := p.pool.Query(ctx, q, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*domain.ModelGroup
	for rows.Next() {
		g, err := scanModelGroup(rows)
		if err != nil {
			return nil, err
		}
		_ = p.mem.CreateModelGroup(ctx, g)
		out = append(out, g)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

const deploymentSelectCols = `id, model_group_id, global_model_id, credential_id, deployment_name, region, weight, rpm_capacity, tpm_capacity, timeout_ms, priority, status, COALESCE(tags, '{}'), max_budget_micros, COALESCE(budget_reset_period, 'monthly')`

func (p *PostgresRepository) CreateDeployment(ctx context.Context, dep *domain.Deployment) error {
	if dep.ID == "" {
		dep.ID = uuid.NewString()
	}
	if dep.Status == "" {
		dep.Status = domain.DeploymentStatusActive
	}
	if dep.Weight <= 0 {
		dep.Weight = 100
	}
	if p.pool == nil {
		return p.mem.CreateDeployment(ctx, dep)
	}
	resetPeriod := dep.BudgetResetPeriod
	if resetPeriod == "" {
		resetPeriod = string(domain.BudgetResetMonthly)
	}
	tags := dep.Tags
	if tags == nil {
		tags = []string{}
	}
	const q = `
		INSERT INTO model_deployments (id, model_group_id, global_model_id, credential_id, deployment_name, region, weight, rpm_capacity, tpm_capacity, timeout_ms, priority, status, tags, max_budget_micros, budget_reset_period)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`
	if _, err := p.pool.Exec(ctx, q, dep.ID, dep.ModelGroupID, dep.GlobalModelID, dep.CredentialID, dep.DeploymentName, dep.Region, dep.Weight, dep.RPMCapacity, dep.TPMCapacity, dep.TimeoutMs, dep.Priority, string(dep.Status), tags, dep.MaxBudgetMicros, resetPeriod); err != nil {
		return err
	}
	if dep.GlobalModel == nil && dep.GlobalModelID != "" {
		dep.GlobalModel, _ = p.GetGlobalModel(ctx, dep.GlobalModelID)
	}
	if dep.Credential == nil && dep.CredentialID != "" {
		dep.Credential, _ = p.GetProviderCredential(ctx, dep.CredentialID)
	}
	return p.mem.CreateDeployment(ctx, dep)
}

func (p *PostgresRepository) loadAndHydrateDeployments(ctx context.Context, q string, args ...any) ([]*domain.Deployment, error) {
	rows, err := p.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	var deps []*domain.Deployment
	credSeen := make(map[string]struct{})
	modelSeen := make(map[string]struct{})
	var credIDs, modelIDs []string
	for rows.Next() {
		var d domain.Deployment
		var status string
		if err := rows.Scan(&d.ID, &d.ModelGroupID, &d.GlobalModelID, &d.CredentialID, &d.DeploymentName, &d.Region, &d.Weight, &d.RPMCapacity, &d.TPMCapacity, &d.TimeoutMs, &d.Priority, &status, &d.Tags, &d.MaxBudgetMicros, &d.BudgetResetPeriod); err != nil {
			continue
		}
		if d.Tags == nil {
			d.Tags = []string{}
		}
		if status == "" {
			d.Status = domain.DeploymentStatusActive
		} else {
			d.Status = domain.DeploymentStatus(status)
		}
		if d.CredentialID != "" {
			if _, ok := credSeen[d.CredentialID]; !ok {
				credSeen[d.CredentialID] = struct{}{}
				credIDs = append(credIDs, d.CredentialID)
			}
		}
		if d.GlobalModelID != "" {
			if _, ok := modelSeen[d.GlobalModelID]; !ok {
				modelSeen[d.GlobalModelID] = struct{}{}
				modelIDs = append(modelIDs, d.GlobalModelID)
			}
		}
		deps = append(deps, &d)
	}
	rowsErr := rows.Err()
	// Close rows before issuing batch hydration queries to prevent pool exhaustion/deadlocks.
	rows.Close()
	if rowsErr != nil {
		return nil, rowsErr
	}

	if len(credIDs) > 0 {
		_ = p.hydrateProviderCredentials(ctx, credIDs)
	}
	if len(modelIDs) > 0 {
		_ = p.hydrateGlobalModels(ctx, modelIDs)
	}
	for _, d := range deps {
		if d.CredentialID != "" {
			if c, err := p.mem.GetProviderCredential(ctx, d.CredentialID); err == nil {
				d.Credential = c
			}
		}
		if d.GlobalModelID != "" {
			if gm, err := p.mem.GetGlobalModel(ctx, d.GlobalModelID); err == nil {
				d.GlobalModel = gm
			}
		}
		_ = p.mem.CreateDeployment(ctx, d)
	}
	return deps, nil
}

func (p *PostgresRepository) ListDeploymentsByGroup(ctx context.Context, groupID string) ([]*domain.Deployment, error) {
	if p.pool == nil {
		return p.mem.ListDeploymentsByGroup(ctx, groupID)
	}
	const q = `SELECT ` + deploymentSelectCols + ` FROM model_deployments WHERE model_group_id = $1`
	return p.loadAndHydrateDeployments(ctx, q, groupID)
}

func (p *PostgresRepository) ListAllDeployments(ctx context.Context) ([]*domain.Deployment, error) {
	if p.pool == nil {
		return p.mem.ListAllDeployments(ctx)
	}
	const q = `SELECT ` + deploymentSelectCols + ` FROM model_deployments`
	return p.loadAndHydrateDeployments(ctx, q)
}

func (p *PostgresRepository) SetGuardrailPolicy(ctx context.Context, pol *domain.GuardrailPolicy) error {
	if err := p.mem.SetGuardrailPolicy(ctx, pol); err != nil {
		return err
	}
	if p.pool == nil {
		return nil
	}
	const q = `
		INSERT INTO guardrail_policies (
			org_id, mode, scan_all_roles, enable_prompt_injection, prompt_injection_action,
			enable_pii_detection, pii_action, enable_secret_detection,
			secret_action, blocked_keywords, redact_output_pii,
			enable_toxicity_filter, toxicity_action, toxicity_threshold,
			enabled_content_categories, content_exceptions, updated_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,NOW())
		ON CONFLICT (org_id) DO UPDATE SET
			mode = EXCLUDED.mode,
			scan_all_roles = EXCLUDED.scan_all_roles,
			enable_prompt_injection = EXCLUDED.enable_prompt_injection,
			prompt_injection_action = EXCLUDED.prompt_injection_action,
			enable_pii_detection = EXCLUDED.enable_pii_detection,
			pii_action = EXCLUDED.pii_action,
			enable_secret_detection = EXCLUDED.enable_secret_detection,
			secret_action = EXCLUDED.secret_action,
			blocked_keywords = EXCLUDED.blocked_keywords,
			redact_output_pii = EXCLUDED.redact_output_pii,
			enable_toxicity_filter = EXCLUDED.enable_toxicity_filter,
			toxicity_action = EXCLUDED.toxicity_action,
			toxicity_threshold = EXCLUDED.toxicity_threshold,
			enabled_content_categories = EXCLUDED.enabled_content_categories,
			content_exceptions = EXCLUDED.content_exceptions,
			updated_at = NOW()`
	mode := pol.EffectiveMode()
	act := pol.PromptInjectionAction
	if act == "" {
		act = domain.GuardrailActionBlock
	}
	piiAct := pol.PIIAction
	if piiAct == "" {
		piiAct = domain.GuardrailActionRedact
	}
	secAct := pol.SecretAction
	if secAct == "" {
		secAct = domain.GuardrailActionRedact
	}
	toxAct := pol.ToxicityAction
	if toxAct == "" {
		toxAct = domain.GuardrailActionBlock
	}
	toxThreshold := pol.ToxicityThreshold
	if toxThreshold == "" {
		toxThreshold = "medium"
	}
	blockedKeywords := pol.BlockedKeywords
	if blockedKeywords == nil {
		blockedKeywords = []string{}
	}
	enabledContentCategories := pol.EnabledContentCategories
	if enabledContentCategories == nil {
		enabledContentCategories = []string{}
	}
	contentExceptions := pol.ContentExceptions
	if contentExceptions == nil {
		contentExceptions = []string{}
	}
	_, err := p.pool.Exec(ctx, q,
		pol.OrgID, string(mode), pol.ScanAllRoles, pol.EnablePromptInjection, string(act),
		pol.EnablePIIDetection, string(piiAct), pol.EnableSecretDetection,
		string(secAct), blockedKeywords, pol.RedactOutputPII,
		pol.EnableToxicityFilter, string(toxAct), toxThreshold,
		enabledContentCategories, contentExceptions,
	)
	return err
}

func (p *PostgresRepository) GetGuardrailPolicy(ctx context.Context, orgID string) (*domain.GuardrailPolicy, error) {
	if p.pool == nil {
		return p.mem.GetGuardrailPolicy(ctx, orgID)
	}
	value, err := p.coalesceLookup(ctx, "guardrail:"+orgID, func(lookupCtx context.Context) (any, error) {
		p.guardrailQueries.Add(1)
		const q = `SELECT org_id, mode, scan_all_roles, enable_prompt_injection, prompt_injection_action, enable_pii_detection, pii_action, enable_secret_detection, secret_action, blocked_keywords, redact_output_pii, enable_toxicity_filter, toxicity_action, toxicity_threshold, enabled_content_categories, content_exceptions FROM guardrail_policies WHERE org_id = $1`
		var pol domain.GuardrailPolicy
		var modeStr, injAct, piiAct, secAct, toxAct string
		if scanErr := p.pool.QueryRow(lookupCtx, q, orgID).Scan(
			&pol.OrgID, &modeStr, &pol.ScanAllRoles, &pol.EnablePromptInjection, &injAct, &pol.EnablePIIDetection, &piiAct,
			&pol.EnableSecretDetection, &secAct, &pol.BlockedKeywords, &pol.RedactOutputPII,
			&pol.EnableToxicityFilter, &toxAct, &pol.ToxicityThreshold, &pol.EnabledContentCategories, &pol.ContentExceptions,
		); scanErr != nil {
			if errors.Is(scanErr, pgx.ErrNoRows) {
				p.missingGuardrailQueries.Add(1)
				return (*domain.GuardrailPolicy)(nil), nil
			}
			return nil, scanErr
		}
		pol.Mode = domain.GuardrailMode(modeStr)
		pol.PromptInjectionAction = domain.GuardrailAction(injAct)
		pol.PIIAction = domain.GuardrailAction(piiAct)
		pol.SecretAction = domain.GuardrailAction(secAct)
		pol.ToxicityAction = domain.GuardrailAction(toxAct)
		if pol.BlockedKeywords == nil {
			pol.BlockedKeywords = []string{}
		}
		if pol.EnabledContentCategories == nil {
			pol.EnabledContentCategories = []string{}
		}
		if pol.ContentExceptions == nil {
			pol.ContentExceptions = []string{}
		}
		if p.mem != nil {
			_ = p.mem.SetGuardrailPolicy(lookupCtx, &pol)
		}
		return &pol, nil
	})
	if err != nil {
		return nil, err
	}
	result, _ := value.(*domain.GuardrailPolicy)
	return result, nil
}

func (p *PostgresRepository) UpdateDeploymentStatus(ctx context.Context, depID string, status domain.DeploymentStatus) error {
	if p.pool == nil {
		return p.mem.UpdateDeploymentStatus(ctx, depID, status)
	}
	if _, err := p.pool.Exec(ctx, `UPDATE model_deployments SET status = $2, updated_at = NOW() WHERE id = $1`, depID, string(status)); err != nil {
		return err
	}
	_ = p.mem.UpdateDeploymentStatus(ctx, depID, status)
	return nil
}

func (p *PostgresRepository) EnqueueSpendEvent(ctx context.Context, ev domain.SpendEvent) error {
	if ev.ID == "" {
		ev.ID = uuid.NewString()
	}
	if ev.CreatedAt.IsZero() {
		ev.CreatedAt = time.Now().UTC()
	}
	if ev.PricingStatus == "" {
		ev.PricingStatus = domain.PricingStatusUnrecorded
	}
	payload, err := json.Marshal(ev)
	if err != nil {
		return fmt.Errorf("marshal spend event: %w", err)
	}
	_, err = p.pool.Exec(ctx, `INSERT INTO spend_event_outbox (id, payload_json) VALUES ($1, $2) ON CONFLICT (id) DO NOTHING`, ev.ID, payload)
	if err != nil {
		return fmt.Errorf("persist spend event outbox: %w", err)
	}
	return nil
}

func (p *PostgresRepository) ClaimSpendEvents(ctx context.Context, limit int, lease time.Duration) ([]domain.SpendEvent, error) {
	if limit <= 0 {
		limit = 100
	}
	if lease <= 0 {
		lease = time.Minute
	}
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	rows, err := tx.Query(ctx, `
		WITH candidates AS (
			SELECT id FROM spend_event_outbox
			WHERE (status = 'pending' AND next_attempt_at <= NOW())
			   OR (status = 'processing' AND locked_at < NOW() - ($2 * INTERVAL '1 second'))
			ORDER BY created_at
			LIMIT $1 FOR UPDATE SKIP LOCKED
		)
		UPDATE spend_event_outbox o SET status='processing', locked_at=NOW(), attempt_count=o.attempt_count+1, updated_at=NOW()
		FROM candidates c WHERE o.id=c.id RETURNING o.payload_json, o.attempt_count`, limit, lease.Seconds())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var events []domain.SpendEvent
	for rows.Next() {
		var raw []byte
		var attempt int
		if err := rows.Scan(&raw, &attempt); err != nil {
			return nil, err
		}
		var ev domain.SpendEvent
		if err := json.Unmarshal(raw, &ev); err != nil {
			return nil, fmt.Errorf("decode spend outbox payload: %w", err)
		}
		ev.OutboxAttempt = attempt
		events = append(events, ev)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	rows.Close()
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return events, nil
}

func (p *PostgresRepository) MarkSpendEventDelivered(ctx context.Context, id string) error {
	_, err := p.pool.Exec(ctx, `UPDATE spend_event_outbox SET status='delivered', locked_at=NULL, last_error=NULL, updated_at=NOW() WHERE id=$1`, id)
	return err
}

func (p *PostgresRepository) MarkSpendEventsDelivered(ctx context.Context, ids []string) error {
	if len(ids) == 0 {
		return nil
	}
	_, err := p.pool.Exec(ctx, `UPDATE spend_event_outbox SET status='delivered', locked_at=NULL, last_error=NULL, updated_at=NOW() WHERE id = ANY($1)`, ids)
	return err
}

func (p *PostgresRepository) CountPendingSpendEvents(ctx context.Context) (int64, error) {
	var count int64
	if err := p.pool.QueryRow(ctx, `SELECT COUNT(*) FROM spend_event_outbox WHERE status IN ('pending', 'processing')`).Scan(&count); err != nil {
		return 0, err
	}
	return count, nil
}

func (p *PostgresRepository) PruneDeliveredSpendEvents(ctx context.Context, olderThan time.Time, limit int) (int64, error) {
	if limit <= 0 {
		limit = 1000
	}
	tag, err := p.pool.Exec(ctx, `
		DELETE FROM spend_event_outbox
		WHERE id IN (
			SELECT id FROM spend_event_outbox
			WHERE status = 'delivered' AND updated_at < $1
			ORDER BY updated_at ASC
			LIMIT $2
		)`, olderThan.UTC(), limit)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

func (p *PostgresRepository) RetrySpendEvent(ctx context.Context, id string, cause error, retryAt time.Time, maxAttempts int) error {
	message := ""
	if cause != nil {
		message = cause.Error()
	}
	_, err := p.pool.Exec(ctx, `UPDATE spend_event_outbox SET status=CASE WHEN attempt_count >= $4 THEN 'dead_letter' ELSE 'pending' END, next_attempt_at=$3, locked_at=NULL, last_error=$2, updated_at=NOW() WHERE id=$1`, id, message, retryAt, maxAttempts)
	return err
}

type spendDelta struct {
	id         string
	costMicros int64
}

func sortedSpendDeltas(m map[string]int64) []spendDelta {
	if len(m) == 0 {
		return nil
	}
	keys := make([]string, 0, len(m))
	for k, v := range m {
		if k != "" && v > 0 {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	out := make([]spendDelta, 0, len(keys))
	for _, k := range keys {
		out = append(out, spendDelta{id: k, costMicros: m[k]})
	}
	return out
}

func (p *PostgresRepository) RecordSpendBatch(ctx context.Context, events []domain.SpendEvent) error {
	if len(events) == 0 {
		return nil
	}
	const insertQ = `
		INSERT INTO spend_logs (
			id, request_id, trace_id, org_id, team_id, user_id, virtual_key_id,
			end_user_id, tags, session_id,
			endpoint, modality, modality_units, requested_model, resolved_model, provider,
			prompt_tokens, completion_tokens, cached_tokens, reasoning_tokens, total_tokens,
			cost_micros, pricing_version, pricing_status, pricing_provenance_source,
			latency_ms, ttft_ms, status_code, is_stream, cache_hit, fallback_attempted, retry_count
		) VALUES (
			$1,$2,$3,$4,NULLIF($5,''),NULLIF($6,''),NULLIF($7,''),
			NULLIF($8,''),$9,NULLIF($10,''),
			$11,$12,$13,$14,$15,$16,
			$17,$18,$19,$20,$21,
			$22,$23,$24,$25,
			$26,$27,$28,$29,$30,$31,$32
		)
		ON CONFLICT (id) DO NOTHING
		RETURNING org_id, COALESCE(team_id, ''), COALESCE(user_id, ''), COALESCE(virtual_key_id, ''), cost_micros`

	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin spend batch tx: %w", err)
	}
	defer tx.Rollback(ctx)

	batch := &pgx.Batch{}
	for _, ev := range events {
		id := ev.ID
		if id == "" {
			id = uuid.NewString()
		}
		pv := ev.PricingVersion
		if pv <= 0 {
			pv = 1
		}
		pricingStatus := string(ev.PricingStatus)
		if pricingStatus == "" {
			pricingStatus = string(domain.PricingStatusUnrecorded)
		}
		orgID := ev.OrgID
		if orgID == "" {
			orgID = "00000000-0000-0000-0000-000000000000"
		}
		modality := string(ev.Modality)
		if modality == "" {
			modality = string(domain.ModalityChat)
		}
		modUnitsJSON, _ := json.Marshal(ev.ModalityUnits)
		if len(ev.ModalityUnits) == 0 {
			modUnitsJSON = []byte("{}")
		}
		evTags := ev.Tags
		if evTags == nil {
			evTags = []string{}
		}
		batch.Queue(insertQ,
			id, ev.RequestID, ev.TraceID, orgID, ev.TeamID, ev.UserID, ev.VirtualKeyID,
			ev.EndUserID, evTags, ev.SessionID,
			ev.Endpoint, modality, modUnitsJSON, ev.RequestedModel, ev.ResolvedModel, string(ev.Provider),
			ev.Usage.PromptTokens, ev.Usage.CompletionTokens, ev.Usage.CachedPromptTokens, ev.Usage.ReasoningTokens, ev.Usage.TotalTokens,
			ev.CostMicros, pv, pricingStatus, ev.PricingProvenanceSource,
			ev.LatencyMs, ev.TTFTMs, ev.StatusCode, ev.IsStream, ev.CacheHit, ev.FallbackAttempted, ev.RetryCount,
		)
	}
	orgTotals := make(map[string]int64)
	teamTotals := make(map[string]int64)
	userTotals := make(map[string]int64)
	keyTotals := make(map[string]int64)
	type orgTupleKey struct {
		orgID string
		id    string
	}
	endUserTotals := make(map[orgTupleKey]int64)
	tagTotals := make(map[orgTupleKey]int64)
	magTotals := make(map[string]int64)
	type bwSpendKey struct {
		orgID     string
		scopeType domain.QuotaScopeType
		scopeID   string
	}
	bwTotals := make(map[bwSpendKey]int64)

	br := tx.SendBatch(ctx, batch)
	for i := range events {
		var orgID, teamID, userID, keyID string
		var costMicros int64
		err := br.QueryRow().Scan(&orgID, &teamID, &userID, &keyID, &costMicros)
		if errors.Is(err, pgx.ErrNoRows) {
			continue
		}
		if err != nil {
			_ = br.Close()
			return fmt.Errorf("execute spend batch: %w", err)
		}
		if costMicros > 0 {
			ev := events[i]
			if orgID != "" {
				orgTotals[orgID] += costMicros
				bwTotals[bwSpendKey{orgID: orgID, scopeType: domain.QuotaScopeOrg, scopeID: orgID}] += costMicros
			}
			if teamID != "" {
				teamTotals[teamID] += costMicros
				if orgID != "" {
					bwTotals[bwSpendKey{orgID: orgID, scopeType: domain.QuotaScopeTeam, scopeID: teamID}] += costMicros
				}
			}
			if userID != "" {
				userTotals[userID] += costMicros
				if orgID != "" {
					bwTotals[bwSpendKey{orgID: orgID, scopeType: domain.QuotaScopeUser, scopeID: userID}] += costMicros
				}
			}
			if keyID != "" {
				keyTotals[keyID] += costMicros
				if orgID != "" {
					bwTotals[bwSpendKey{orgID: orgID, scopeType: domain.QuotaScopeKey, scopeID: keyID}] += costMicros
				}
			}
			if orgID != "" && teamID != "" && userID != "" {
				bwTotals[bwSpendKey{orgID: orgID, scopeType: domain.QuotaScopeTeamMember, scopeID: teamID + ":" + userID}] += costMicros
			}
			if orgID != "" && ev.EndUserID != "" {
				endUserTotals[orgTupleKey{orgID: orgID, id: ev.EndUserID}] += costMicros
				bwTotals[bwSpendKey{orgID: orgID, scopeType: domain.QuotaScopeEndUser, scopeID: ev.EndUserID}] += costMicros
			}
			for _, tagName := range ev.Tags {
				tagName = strings.TrimSpace(tagName)
				if tagName == "" || orgID == "" {
					continue
				}
				tagTotals[orgTupleKey{orgID: orgID, id: tagName}] += costMicros
				bwTotals[bwSpendKey{orgID: orgID, scopeType: domain.QuotaScopeTag, scopeID: tagName}] += costMicros
			}
			for _, magID := range ev.ModelAccessGroupIDs {
				magID = strings.TrimSpace(magID)
				if magID == "" {
					continue
				}
				magTotals[magID] += costMicros
				if orgID != "" {
					bwTotals[bwSpendKey{orgID: orgID, scopeType: domain.QuotaScopeModelAccessGroup, scopeID: magID}] += costMicros
				}
			}
		}
	}
	if err := br.Close(); err != nil {
		return fmt.Errorf("close spend batch: %w", err)
	}

	// Pre-aggregated updates in deterministic ID order prevent row-lock contention and deadlocks.
	updateBatch := &pgx.Batch{}
	updateCount := 0
	for _, d := range sortedSpendDeltas(orgTotals) {
		updateBatch.Queue(`UPDATE organizations SET spent_micros = spent_micros + $2, updated_at = NOW() WHERE id = $1`, d.id, d.costMicros)
		updateCount++
	}
	for _, d := range sortedSpendDeltas(teamTotals) {
		updateBatch.Queue(`UPDATE teams SET spent_micros = spent_micros + $2, updated_at = NOW() WHERE id = $1`, d.id, d.costMicros)
		updateCount++
	}
	for _, d := range sortedSpendDeltas(userTotals) {
		updateBatch.Queue(`UPDATE users SET spent_micros = spent_micros + $2, updated_at = NOW() WHERE id = $1`, d.id, d.costMicros)
		updateCount++
	}
	for _, d := range sortedSpendDeltas(keyTotals) {
		updateBatch.Queue(`UPDATE virtual_keys SET spent_micros = spent_micros + $2, updated_at = NOW() WHERE id = $1`, d.id, d.costMicros)
		updateCount++
	}
	if len(endUserTotals) > 0 {
		euKeys := make([]orgTupleKey, 0, len(endUserTotals))
		for k := range endUserTotals {
			euKeys = append(euKeys, k)
		}
		sort.Slice(euKeys, func(i, j int) bool {
			if euKeys[i].orgID != euKeys[j].orgID {
				return euKeys[i].orgID < euKeys[j].orgID
			}
			return euKeys[i].id < euKeys[j].id
		})
		for _, k := range euKeys {
			updateBatch.Queue(
				`UPDATE end_users SET spent_micros = spent_micros + $3, updated_at = NOW() WHERE org_id = $1 AND end_user_id = $2`,
				k.orgID, k.id, endUserTotals[k],
			)
			updateCount++
		}
	}
	if len(tagTotals) > 0 {
		tKeys := make([]orgTupleKey, 0, len(tagTotals))
		for k := range tagTotals {
			tKeys = append(tKeys, k)
		}
		sort.Slice(tKeys, func(i, j int) bool {
			if tKeys[i].orgID != tKeys[j].orgID {
				return tKeys[i].orgID < tKeys[j].orgID
			}
			return tKeys[i].id < tKeys[j].id
		})
		for _, k := range tKeys {
			updateBatch.Queue(
				`UPDATE tags SET spent_micros = spent_micros + $3, updated_at = NOW() WHERE org_id = $1 AND tag = $2`,
				k.orgID, k.id, tagTotals[k],
			)
			updateCount++
		}
	}
	for _, d := range sortedSpendDeltas(magTotals) {
		updateBatch.Queue(`UPDATE model_access_groups SET spent_micros = spent_micros + $2, updated_at = NOW() WHERE id = $1`, d.id, d.costMicros)
		updateCount++
	}
	if len(bwTotals) > 0 {
		bwKeys := make([]bwSpendKey, 0, len(bwTotals))
		for k := range bwTotals {
			bwKeys = append(bwKeys, k)
		}
		sort.Slice(bwKeys, func(i, j int) bool {
			if bwKeys[i].orgID != bwKeys[j].orgID {
				return bwKeys[i].orgID < bwKeys[j].orgID
			}
			if bwKeys[i].scopeType != bwKeys[j].scopeType {
				return bwKeys[i].scopeType < bwKeys[j].scopeType
			}
			return bwKeys[i].scopeID < bwKeys[j].scopeID
		})
		for _, k := range bwKeys {
			updateBatch.Queue(
				`UPDATE budget_window_limits SET spent_micros = spent_micros + $4, updated_at = NOW() WHERE org_id = $1 AND scope_type = $2 AND scope_id = $3`,
				k.orgID, string(k.scopeType), k.scopeID, bwTotals[k],
			)
			updateCount++
		}
	}
	if updateCount > 0 {
		ubr := tx.SendBatch(ctx, updateBatch)
		for i := 0; i < updateCount; i++ {
			if _, err := ubr.Exec(); err != nil {
				_ = ubr.Close()
				return fmt.Errorf("update aggregated spend: %w", err)
			}
		}
		if err := ubr.Close(); err != nil {
			return fmt.Errorf("close aggregated spend batch: %w", err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit spend batch: %w", err)
	}
	if err := p.mem.RecordSpendBatch(ctx, events); err != nil {
		return err
	}
	return nil
}

func (p *PostgresRepository) GetSpendSummary(ctx context.Context, orgID string) (*SpendSummary, error) {
	sum := &SpendSummary{
		SpendByProvider:   make(map[string]int64),
		SpendByModel:      make(map[string]int64),
		SpendByTeam:       make(map[string]int64),
		SpendByUser:       make(map[string]int64),
		SpendByVirtualKey: make(map[string]int64),
	}
	var whereClause string
	var args []any
	if orgID != "" {
		whereClause = "WHERE org_id = $1"
		args = append(args, orgID)
	}

	qTotals := `SELECT COUNT(*), COALESCE(SUM(total_tokens), 0), COALESCE(SUM(cost_micros), 0),
		COUNT(*) FILTER (WHERE pricing_status IN ('unknown', 'unrecorded')),
		COALESCE(SUM(total_tokens) FILTER (WHERE pricing_status IN ('unknown', 'unrecorded')), 0)
		FROM spend_logs ` + whereClause
	if err := p.pool.QueryRow(ctx, qTotals, args...).Scan(&sum.TotalRequests, &sum.TotalTokens, &sum.TotalCostMicros, &sum.UnpricedRequests, &sum.UnpricedTokens); err != nil {
		return p.mem.GetSpendSummary(ctx, orgID)
	}
	sum.TotalCostUSD = float64(sum.TotalCostMicros) / 1_000_000.0

	qBreakdown := `
		SELECT
			COALESCE(provider, ''),
			COALESCE(resolved_model, ''),
			COALESCE(team_id, ''),
			COALESCE(virtual_key_id, ''),
			COALESCE(user_id, ''),
			GROUPING(provider, resolved_model, team_id, virtual_key_id, user_id),
			COALESCE(SUM(cost_micros), 0)
		FROM spend_logs ` + whereClause + `
		GROUP BY GROUPING SETS (
			(provider),
			(resolved_model),
			(team_id),
			(virtual_key_id),
			(user_id)
		)`
	if rows, err := p.pool.Query(ctx, qBreakdown, args...); err == nil {
		defer rows.Close()
		for rows.Next() {
			var prov, model, teamID, vkID, userID string
			var grp int
			var cost int64
			if err := rows.Scan(&prov, &model, &teamID, &vkID, &userID, &grp, &cost); err != nil {
				continue
			}
			switch grp {
			case 15: // 0b01111 -> provider
				sum.SpendByProvider[prov] = cost
			case 23: // 0b10111 -> resolved_model
				sum.SpendByModel[model] = cost
			case 27: // 0b11011 -> team_id
				if teamID != "" {
					sum.SpendByTeam[teamID] = cost
				}
			case 29: // 0b11101 -> virtual_key_id
				if vkID != "" {
					sum.SpendByVirtualKey[vkID] = cost
				}
			case 30: // 0b11110 -> user_id
				if userID != "" {
					sum.SpendByUser[userID] = cost
				}
			}
		}
	}

	return sum, nil
}

func (p *PostgresRepository) ListSpendLogs(ctx context.Context, orgID string, limit int) ([]domain.SpendEvent, error) {
	if limit <= 0 {
		limit = 100
	}
	var q string
	var args []any
	if orgID != "" {
		q = `
			SELECT id, request_id, trace_id, org_id, endpoint, requested_model, resolved_model, provider,
				prompt_tokens, completion_tokens, cached_tokens, reasoning_tokens, total_tokens,
				cost_micros, pricing_version, latency_ms, ttft_ms, status_code, is_stream, cache_hit, fallback_attempted, retry_count, created_at
			FROM spend_logs WHERE org_id = $1 ORDER BY created_at DESC LIMIT $2`
		args = []any{orgID, limit}
	} else {
		q = `
			SELECT id, request_id, trace_id, org_id, endpoint, requested_model, resolved_model, provider,
				prompt_tokens, completion_tokens, cached_tokens, reasoning_tokens, total_tokens,
				cost_micros, pricing_version, latency_ms, ttft_ms, status_code, is_stream, cache_hit, fallback_attempted, retry_count, created_at
			FROM spend_logs ORDER BY created_at DESC LIMIT $1`
		args = []any{limit}
	}

	rows, err := p.pool.Query(ctx, q, args...)
	if err != nil {
		return p.mem.ListSpendLogs(ctx, orgID, limit)
	}
	defer rows.Close()

	var out []domain.SpendEvent
	for rows.Next() {
		var ev domain.SpendEvent
		var prov string
		if err := rows.Scan(
			&ev.ID, &ev.RequestID, &ev.TraceID, &ev.OrgID, &ev.Endpoint, &ev.RequestedModel, &ev.ResolvedModel, &prov,
			&ev.Usage.PromptTokens, &ev.Usage.CompletionTokens, &ev.Usage.CachedPromptTokens, &ev.Usage.ReasoningTokens, &ev.Usage.TotalTokens,
			&ev.CostMicros, &ev.PricingVersion, &ev.LatencyMs, &ev.TTFTMs, &ev.StatusCode, &ev.IsStream, &ev.CacheHit, &ev.FallbackAttempted, &ev.RetryCount, &ev.CreatedAt,
		); err != nil {
			return nil, err
		}
		ev.Provider = domain.ProviderType(prov)
		out = append(out, ev)
	}
	if len(out) == 0 {
		return p.mem.ListSpendLogs(ctx, orgID, limit)
	}
	return out, rows.Err()
}

func (p *PostgresRepository) GetTeamSpendSummary(ctx context.Context, orgID, teamID string) (*SpendSummary, error) {
	if p.pool == nil {
		return p.mem.GetTeamSpendSummary(ctx, orgID, teamID)
	}
	sum := &SpendSummary{
		SpendByProvider:   make(map[string]int64),
		SpendByModel:      make(map[string]int64),
		SpendByTeam:       make(map[string]int64),
		SpendByUser:       make(map[string]int64),
		SpendByVirtualKey: make(map[string]int64),
	}
	var whereClause string
	var args []any
	if orgID != "" {
		whereClause = "WHERE org_id = $1 AND team_id = $2"
		args = []any{orgID, teamID}
	} else {
		whereClause = "WHERE team_id = $1"
		args = []any{teamID}
	}

	qTotals := `SELECT COUNT(*), COALESCE(SUM(total_tokens), 0), COALESCE(SUM(cost_micros), 0),
		COUNT(*) FILTER (WHERE pricing_status IN ('unknown', 'unrecorded')),
		COALESCE(SUM(total_tokens) FILTER (WHERE pricing_status IN ('unknown', 'unrecorded')), 0)
		FROM spend_logs ` + whereClause
	if err := p.pool.QueryRow(ctx, qTotals, args...).Scan(&sum.TotalRequests, &sum.TotalTokens, &sum.TotalCostMicros, &sum.UnpricedRequests, &sum.UnpricedTokens); err != nil {
		return p.mem.GetTeamSpendSummary(ctx, orgID, teamID)
	}
	sum.TotalCostUSD = float64(sum.TotalCostMicros) / 1_000_000.0

	qBreakdown := `
		SELECT
			COALESCE(provider, ''),
			COALESCE(resolved_model, ''),
			COALESCE(team_id, ''),
			COALESCE(virtual_key_id, ''),
			COALESCE(user_id, ''),
			GROUPING(provider, resolved_model, team_id, virtual_key_id, user_id),
			COALESCE(SUM(cost_micros), 0)
		FROM spend_logs ` + whereClause + `
		GROUP BY GROUPING SETS (
			(provider),
			(resolved_model),
			(team_id),
			(virtual_key_id),
			(user_id)
		)`
	if rows, err := p.pool.Query(ctx, qBreakdown, args...); err == nil {
		defer rows.Close()
		for rows.Next() {
			var prov, model, tid, vkID, userID string
			var grp int
			var cost int64
			if err := rows.Scan(&prov, &model, &tid, &vkID, &userID, &grp, &cost); err != nil {
				continue
			}
			switch grp {
			case 15:
				sum.SpendByProvider[prov] = cost
			case 23:
				sum.SpendByModel[model] = cost
			case 27:
				if tid != "" {
					sum.SpendByTeam[tid] = cost
				}
			case 29:
				if vkID != "" {
					sum.SpendByVirtualKey[vkID] = cost
				}
			case 30:
				if userID != "" {
					sum.SpendByUser[userID] = cost
				}
			}
		}
	}
	return sum, nil
}

func (p *PostgresRepository) ListTeamSpendLogs(ctx context.Context, orgID, teamID string, limit int) ([]domain.SpendEvent, error) {
	if p.pool == nil {
		return p.mem.ListTeamSpendLogs(ctx, orgID, teamID, limit)
	}
	if limit <= 0 {
		limit = 100
	}
	var q string
	var args []any
	if orgID != "" {
		q = `
			SELECT id, request_id, trace_id, org_id, COALESCE(team_id, ''), COALESCE(user_id, ''), COALESCE(virtual_key_id, ''), endpoint, requested_model, resolved_model, provider,
				prompt_tokens, completion_tokens, cached_tokens, reasoning_tokens, total_tokens,
				cost_micros, pricing_version, latency_ms, ttft_ms, status_code, is_stream, cache_hit, fallback_attempted, retry_count, created_at
			FROM spend_logs WHERE org_id = $1 AND team_id = $2 ORDER BY created_at DESC LIMIT $3`
		args = []any{orgID, teamID, limit}
	} else {
		q = `
			SELECT id, request_id, trace_id, org_id, COALESCE(team_id, ''), COALESCE(user_id, ''), COALESCE(virtual_key_id, ''), endpoint, requested_model, resolved_model, provider,
				prompt_tokens, completion_tokens, cached_tokens, reasoning_tokens, total_tokens,
				cost_micros, pricing_version, latency_ms, ttft_ms, status_code, is_stream, cache_hit, fallback_attempted, retry_count, created_at
			FROM spend_logs WHERE team_id = $1 ORDER BY created_at DESC LIMIT $2`
		args = []any{teamID, limit}
	}

	rows, err := p.pool.Query(ctx, q, args...)
	if err != nil {
		return p.mem.ListTeamSpendLogs(ctx, orgID, teamID, limit)
	}
	defer rows.Close()

	out := make([]domain.SpendEvent, 0)
	for rows.Next() {
		var ev domain.SpendEvent
		var prov string
		if err := rows.Scan(
			&ev.ID, &ev.RequestID, &ev.TraceID, &ev.OrgID, &ev.TeamID, &ev.UserID, &ev.VirtualKeyID, &ev.Endpoint, &ev.RequestedModel, &ev.ResolvedModel, &prov,
			&ev.Usage.PromptTokens, &ev.Usage.CompletionTokens, &ev.Usage.CachedPromptTokens, &ev.Usage.ReasoningTokens, &ev.Usage.TotalTokens,
			&ev.CostMicros, &ev.PricingVersion, &ev.LatencyMs, &ev.TTFTMs, &ev.StatusCode, &ev.IsStream, &ev.CacheHit, &ev.FallbackAttempted, &ev.RetryCount, &ev.CreatedAt,
		); err != nil {
			return nil, err
		}
		ev.Provider = domain.ProviderType(prov)
		out = append(out, ev)
	}
	if len(out) == 0 {
		return p.mem.ListTeamSpendLogs(ctx, orgID, teamID, limit)
	}
	return out, rows.Err()
}

func (p *PostgresRepository) ResetExpiredBudgets(ctx context.Context, now time.Time) (int, error) {
	res, err := p.ResetExpiredBudgetsWithIDs(ctx, now)
	return res.Total(), err
}

func (p *PostgresRepository) ResetExpiredBudgetsWithIDs(ctx context.Context, now time.Time) (BudgetResetResult, error) {
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return BudgetResetResult{}, fmt.Errorf("begin reset budgets tx: %w", err)
	}
	defer tx.Rollback(ctx)

	var res BudgetResetResult
	queries := []struct {
		sql   string
		scope string
		dest  *[]string
	}{
		{
			sql: `UPDATE organizations
				SET spent_micros = 0,
				    budget_reset_at = CASE
				        WHEN budget_reset_period = 'daily' THEN budget_reset_at + INTERVAL '1 day'
				        WHEN budget_reset_period = 'monthly' THEN budget_reset_at + INTERVAL '1 month'
				        ELSE NULL
				    END,
				    updated_at = NOW()
				WHERE budget_reset_at IS NOT NULL AND budget_reset_at <= $1 AND budget_reset_period IN ('daily', 'monthly')
				RETURNING id, id`,
			scope: "org",
			dest:  &res.OrgIDs,
		},
		{
			sql: `UPDATE teams
				SET spent_micros = 0,
				    budget_reset_at = CASE
				        WHEN budget_reset_period = 'daily' THEN budget_reset_at + INTERVAL '1 day'
				        WHEN budget_reset_period = 'monthly' THEN budget_reset_at + INTERVAL '1 month'
				        ELSE NULL
				    END,
				    updated_at = NOW()
				WHERE budget_reset_at IS NOT NULL AND budget_reset_at <= $1 AND budget_reset_period IN ('daily', 'monthly')
				RETURNING id, org_id`,
			scope: "team",
			dest:  &res.TeamIDs,
		},
		{
			sql: `UPDATE users
				SET spent_micros = 0,
				    budget_reset_at = CASE
				        WHEN budget_reset_period = 'daily' THEN budget_reset_at + INTERVAL '1 day'
				        WHEN budget_reset_period = 'monthly' THEN budget_reset_at + INTERVAL '1 month'
				        ELSE NULL
				    END,
				    updated_at = NOW()
				WHERE budget_reset_at IS NOT NULL AND budget_reset_at <= $1 AND budget_reset_period IN ('daily', 'monthly')
				RETURNING id, org_id`,
			scope: "user",
			dest:  &res.UserIDs,
		},
		{
			sql: `UPDATE virtual_keys
				SET spent_micros = 0,
				    budget_reset_at = CASE
				        WHEN budget_reset_period = 'daily' THEN budget_reset_at + INTERVAL '1 day'
				        WHEN budget_reset_period = 'monthly' THEN budget_reset_at + INTERVAL '1 month'
				        ELSE NULL
				    END,
				    updated_at = NOW()
				WHERE budget_reset_at IS NOT NULL AND budget_reset_at <= $1 AND budget_reset_period IN ('daily', 'monthly')
				RETURNING id, org_id`,
			scope: "key",
			dest:  &res.VirtualKeyIDs,
		},
	}

	outboxBatch := &pgx.Batch{}
	outboxCount := 0
	for _, q := range queries {
		rows, err := tx.Query(ctx, q.sql, now)
		if err != nil {
			return BudgetResetResult{}, fmt.Errorf("reset expired budgets: %w", err)
		}
		for rows.Next() {
			var id, orgID string
			if err := rows.Scan(&id, &orgID); err != nil {
				rows.Close()
				return BudgetResetResult{}, fmt.Errorf("scan reset budget id: %w", err)
			}
			*q.dest = append(*q.dest, id)
			event := BudgetResetEvent{ID: uuid.NewString(), Scope: q.scope, EntityID: id, OrgID: orgID, ResetAt: now.UTC()}
			res.Events = append(res.Events, event)
			outboxBatch.Queue(`INSERT INTO budget_reset_outbox (id, scope, entity_id, org_id, reset_at) VALUES ($1,$2,$3,$4,$5)`, event.ID, event.Scope, event.EntityID, event.OrgID, event.ResetAt)
			outboxCount++
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return BudgetResetResult{}, fmt.Errorf("iterate reset budget ids: %w", err)
		}
		rows.Close()
	}

	if outboxCount > 0 {
		br := tx.SendBatch(ctx, outboxBatch)
		for i := 0; i < outboxCount; i++ {
			if _, err := br.Exec(); err != nil {
				_ = br.Close()
				return BudgetResetResult{}, fmt.Errorf("enqueue Redis budget reset: %w", err)
			}
		}
		if err := br.Close(); err != nil {
			return BudgetResetResult{}, fmt.Errorf("close budget reset outbox batch: %w", err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return BudgetResetResult{}, fmt.Errorf("commit reset budgets tx: %w", err)
	}

	memRes, _ := p.mem.ResetExpiredBudgetsWithIDs(ctx, now)
	if res.Total() == 0 {
		return memRes, nil
	}
	return res, nil
}

func (p *PostgresRepository) ListPendingBudgetResets(ctx context.Context, limit int) ([]BudgetResetEvent, error) {
	if limit <= 0 {
		limit = 250
	}
	rows, err := p.pool.Query(ctx, `SELECT id::text, scope, entity_id, org_id, reset_at FROM budget_reset_outbox WHERE delivered_at IS NULL ORDER BY created_at LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("list pending budget resets: %w", err)
	}
	defer rows.Close()
	var out []BudgetResetEvent
	for rows.Next() {
		var ev BudgetResetEvent
		if err := rows.Scan(&ev.ID, &ev.Scope, &ev.EntityID, &ev.OrgID, &ev.ResetAt); err != nil {
			return nil, fmt.Errorf("scan pending budget reset: %w", err)
		}
		out = append(out, ev)
	}
	return out, rows.Err()
}

func (p *PostgresRepository) MarkBudgetResetsDelivered(ctx context.Context, ids []string) error {
	if len(ids) == 0 {
		return nil
	}
	_, err := p.pool.Exec(ctx, `UPDATE budget_reset_outbox SET delivered_at = NOW() WHERE id::text = ANY($1) AND delivered_at IS NULL`, ids)
	if err != nil {
		return fmt.Errorf("mark budget resets delivered: %w", err)
	}
	return nil
}

func (p *PostgresRepository) RecordAuditLog(ctx context.Context, log *domain.AuditLog) error {
	if log.ID == "" {
		log.ID = uuid.NewString()
	}
	if p.pool == nil {
		return p.mem.RecordAuditLog(ctx, log)
	}
	detailsJSON, _ := json.Marshal(log.Details)
	if len(detailsJSON) == 0 || string(detailsJSON) == "null" {
		detailsJSON = []byte("{}")
	}
	var beforeJSON, afterJSON []byte
	if log.BeforeValue != nil {
		beforeJSON, _ = json.Marshal(log.BeforeValue)
	}
	if log.AfterValue != nil {
		afterJSON, _ = json.Marshal(log.AfterValue)
	}
	if _, err := p.pool.Exec(ctx, `INSERT INTO audit_logs (id, org_id, actor_id, action, resource, resource_id, details, before_value, after_value) VALUES ($1, NULLIF($2, ''), $3, $4, $5, $6, $7, $8, $9)`,
		log.ID, log.OrgID, log.ActorID, log.Action, log.Resource, log.ResourceID, detailsJSON, beforeJSON, afterJSON,
	); err != nil {
		return fmt.Errorf("insert audit log: %w", err)
	}
	return p.mem.RecordAuditLog(ctx, log)
}

func (p *PostgresRepository) ListAuditLogs(ctx context.Context, orgID string, limit int) ([]*domain.AuditLog, error) {
	if p.pool == nil {
		return p.mem.ListAuditLogs(ctx, orgID, limit)
	}
	if limit <= 0 {
		limit = 100
	}
	var q string
	var args []any
	if orgID != "" {
		q = `SELECT id, COALESCE(org_id, ''), actor_id, action, resource, resource_id, details, before_value, after_value, created_at FROM audit_logs WHERE org_id = $1 ORDER BY created_at DESC LIMIT $2`
		args = []any{orgID, limit}
	} else {
		q = `SELECT id, COALESCE(org_id, ''), actor_id, action, resource, resource_id, details, before_value, after_value, created_at FROM audit_logs ORDER BY created_at DESC LIMIT $1`
		args = []any{limit}
	}
	rows, err := p.pool.Query(ctx, q, args...)
	if err != nil {
		return p.mem.ListAuditLogs(ctx, orgID, limit)
	}
	defer rows.Close()

	var logs []*domain.AuditLog
	for rows.Next() {
		var a domain.AuditLog
		var detailsJSON, beforeJSON, afterJSON []byte
		if err := rows.Scan(&a.ID, &a.OrgID, &a.ActorID, &a.Action, &a.Resource, &a.ResourceID, &detailsJSON, &beforeJSON, &afterJSON, &a.CreatedAt); err != nil {
			return nil, err
		}
		if len(detailsJSON) > 0 {
			_ = json.Unmarshal(detailsJSON, &a.Details)
		}
		if len(beforeJSON) > 0 {
			_ = json.Unmarshal(beforeJSON, &a.BeforeValue)
		}
		if len(afterJSON) > 0 {
			_ = json.Unmarshal(afterJSON, &a.AfterValue)
		}
		logs = append(logs, &a)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(logs) == 0 {
		return p.mem.ListAuditLogs(ctx, orgID, limit)
	}
	return logs, nil
}

// -----------------------------------------------------------------------------
// MCP: Servers, Tools, Toolsets & BYOK Credentials
// -----------------------------------------------------------------------------

func (p *PostgresRepository) CreateMCPServer(ctx context.Context, server *domain.MCPServer) error {
	if server.ID == "" {
		server.ID = uuid.NewString()
	}
	if p.pool == nil {
		return p.mem.CreateMCPServer(ctx, server)
	}
	headersJSON, _ := json.Marshal(server.StaticHeaders)
	const q = `
		INSERT INTO mcp_servers (
			id, org_id, name, slug, protocol_version, transport_type, endpoint_url,
			config_version, auth_type, encrypted_auth_secret, encrypted_auth_dek,
			static_headers, oauth2_endpoint, oauth2_client_id, oauth2_scopes,
			pinned_tool_hash, rpm_limit, is_active
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)`
	if _, err := p.pool.Exec(ctx, q,
		server.ID, server.OrgID, server.Name, server.Slug, server.ProtocolVersion, server.TransportType, server.EndpointURL,
		server.ConfigVersion, server.AuthType, server.EncryptedAuthSecret, server.EncryptedAuthDEK,
		headersJSON, server.OAuth2Endpoint, server.OAuth2ClientID, server.OAuth2Scopes,
		server.PinnedToolHash, server.RPMLimit, server.IsActive,
	); err != nil {
		return err
	}
	return p.mem.CreateMCPServer(ctx, server)
}

func (p *PostgresRepository) UpdateMCPServer(ctx context.Context, server *domain.MCPServer) error {
	if p.pool == nil {
		return p.mem.UpdateMCPServer(ctx, server)
	}
	headersJSON, _ := json.Marshal(server.StaticHeaders)
	const q = `
		UPDATE mcp_servers SET
			name = $2, slug = $3, protocol_version = $4, transport_type = $5, endpoint_url = $6,
			config_version = config_version + 1, auth_type = $7, encrypted_auth_secret = $8, encrypted_auth_dek = $9,
			static_headers = $10, oauth2_endpoint = $11, oauth2_client_id = $12, oauth2_scopes = $13,
			pinned_tool_hash = $14, rpm_limit = $15, is_active = $16, updated_at = NOW()
		WHERE id = $1 RETURNING config_version`
	var newVersion int64
	if err := p.pool.QueryRow(ctx, q,
		server.ID, server.Name, server.Slug, server.ProtocolVersion, server.TransportType, server.EndpointURL,
		server.AuthType, server.EncryptedAuthSecret, server.EncryptedAuthDEK,
		headersJSON, server.OAuth2Endpoint, server.OAuth2ClientID, server.OAuth2Scopes,
		server.PinnedToolHash, server.RPMLimit, server.IsActive,
	).Scan(&newVersion); err != nil {
		return err
	}
	server.ConfigVersion = newVersion
	if err := p.mem.UpdateMCPServer(ctx, server); err != nil {
		_ = p.mem.CreateMCPServer(ctx, server)
	}
	return nil
}

func (p *PostgresRepository) GetMCPServer(ctx context.Context, id string) (*domain.MCPServer, error) {
	if p.pool == nil {
		return p.mem.GetMCPServer(ctx, id)
	}
	const q = `
		SELECT id, org_id, name, slug, protocol_version, transport_type, endpoint_url,
		       config_version, auth_type, encrypted_auth_secret, encrypted_auth_dek,
		       static_headers, oauth2_endpoint, oauth2_client_id, oauth2_scopes,
		       pinned_tool_hash, rpm_limit, is_active, created_at, updated_at
		FROM mcp_servers WHERE id = $1`
	var s domain.MCPServer
	var headersJSON []byte
	if err := p.pool.QueryRow(ctx, q, id).Scan(
		&s.ID, &s.OrgID, &s.Name, &s.Slug, &s.ProtocolVersion, &s.TransportType, &s.EndpointURL,
		&s.ConfigVersion, &s.AuthType, &s.EncryptedAuthSecret, &s.EncryptedAuthDEK,
		&headersJSON, &s.OAuth2Endpoint, &s.OAuth2ClientID, &s.OAuth2Scopes,
		&s.PinnedToolHash, &s.RPMLimit, &s.IsActive, &s.CreatedAt, &s.UpdatedAt,
	); err != nil {
		return nil, fmt.Errorf("mcp server %s not found: %w", id, err)
	}
	if len(headersJSON) > 0 {
		_ = json.Unmarshal(headersJSON, &s.StaticHeaders)
	}
	_ = p.mem.CreateMCPServer(ctx, &s)
	return &s, nil
}

func (p *PostgresRepository) GetMCPServerBySlug(ctx context.Context, orgID, slug string) (*domain.MCPServer, error) {
	if p.pool == nil {
		return p.mem.GetMCPServerBySlug(ctx, orgID, slug)
	}
	const q = `
		SELECT id, org_id, name, slug, protocol_version, transport_type, endpoint_url,
		       config_version, auth_type, encrypted_auth_secret, encrypted_auth_dek,
		       static_headers, oauth2_endpoint, oauth2_client_id, oauth2_scopes,
		       pinned_tool_hash, rpm_limit, is_active, created_at, updated_at
		FROM mcp_servers WHERE (org_id = $1 OR $1 = '') AND slug = $2 LIMIT 1`
	var s domain.MCPServer
	var headersJSON []byte
	if err := p.pool.QueryRow(ctx, q, orgID, slug).Scan(
		&s.ID, &s.OrgID, &s.Name, &s.Slug, &s.ProtocolVersion, &s.TransportType, &s.EndpointURL,
		&s.ConfigVersion, &s.AuthType, &s.EncryptedAuthSecret, &s.EncryptedAuthDEK,
		&headersJSON, &s.OAuth2Endpoint, &s.OAuth2ClientID, &s.OAuth2Scopes,
		&s.PinnedToolHash, &s.RPMLimit, &s.IsActive, &s.CreatedAt, &s.UpdatedAt,
	); err != nil {
		return nil, fmt.Errorf("mcp server %q not found: %w", slug, err)
	}
	if len(headersJSON) > 0 {
		_ = json.Unmarshal(headersJSON, &s.StaticHeaders)
	}
	_ = p.mem.CreateMCPServer(ctx, &s)
	return &s, nil
}

func (p *PostgresRepository) ListMCPServers(ctx context.Context, orgID string) ([]*domain.MCPServer, error) {
	if p.pool == nil {
		return p.mem.ListMCPServers(ctx, orgID)
	}
	const q = `
		SELECT id, org_id, name, slug, protocol_version, transport_type, endpoint_url,
		       config_version, auth_type, encrypted_auth_secret, encrypted_auth_dek,
		       static_headers, oauth2_endpoint, oauth2_client_id, oauth2_scopes,
		       pinned_tool_hash, rpm_limit, is_active, created_at, updated_at
		FROM mcp_servers WHERE org_id = $1 OR $1 = '' ORDER BY name ASC`
	rows, err := p.pool.Query(ctx, q, orgID)
	if err != nil {
		return p.mem.ListMCPServers(ctx, orgID)
	}
	defer rows.Close()

	var out []*domain.MCPServer
	for rows.Next() {
		var s domain.MCPServer
		var headersJSON []byte
		if err := rows.Scan(
			&s.ID, &s.OrgID, &s.Name, &s.Slug, &s.ProtocolVersion, &s.TransportType, &s.EndpointURL,
			&s.ConfigVersion, &s.AuthType, &s.EncryptedAuthSecret, &s.EncryptedAuthDEK,
			&headersJSON, &s.OAuth2Endpoint, &s.OAuth2ClientID, &s.OAuth2Scopes,
			&s.PinnedToolHash, &s.RPMLimit, &s.IsActive, &s.CreatedAt, &s.UpdatedAt,
		); err == nil {
			if len(headersJSON) > 0 {
				_ = json.Unmarshal(headersJSON, &s.StaticHeaders)
			}
			out = append(out, &s)
		}
	}
	return out, nil
}

func (p *PostgresRepository) DeleteMCPServer(ctx context.Context, id string) error {
	_, err := p.pool.Exec(ctx, `DELETE FROM mcp_servers WHERE id = $1`, id)
	_ = p.mem.DeleteMCPServer(ctx, id)
	return err
}

func (p *PostgresRepository) UpsertMCPTools(ctx context.Context, serverID, orgID string, tools []*domain.MCPTool) error {
	if len(tools) == 0 {
		return p.mem.UpsertMCPTools(ctx, serverID, orgID, tools)
	}
	const q = `
		INSERT INTO mcp_tools (id, server_id, org_id, name, description, input_schema, tool_def_hash, cost_per_call_micros, is_active, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW())
		ON CONFLICT (server_id, name) DO UPDATE SET
			description = EXCLUDED.description,
			input_schema = EXCLUDED.input_schema,
			tool_def_hash = EXCLUDED.tool_def_hash,
			cost_per_call_micros = EXCLUDED.cost_per_call_micros,
			is_active = EXCLUDED.is_active,
			updated_at = NOW()`
	batch := &pgx.Batch{}
	for _, t := range tools {
		if t.ID == "" {
			t.ID = uuid.NewString()
		}
		schemaJSON, _ := json.Marshal(t.InputSchema)
		batch.Queue(q, t.ID, serverID, orgID, t.Name, t.Description, schemaJSON, t.ToolDefHash, t.CostPerCallMicros, t.IsActive)
	}
	br := p.pool.SendBatch(ctx, batch)
	for range tools {
		if _, err := br.Exec(); err != nil {
			_ = br.Close()
			return err
		}
	}
	if err := br.Close(); err != nil {
		return err
	}
	return p.mem.UpsertMCPTools(ctx, serverID, orgID, tools)
}

func (p *PostgresRepository) ListMCPTools(ctx context.Context, serverID string) ([]*domain.MCPTool, error) {
	const q = `SELECT id, server_id, org_id, name, description, input_schema, tool_def_hash, cost_per_call_micros, is_active, created_at, updated_at FROM mcp_tools WHERE server_id = $1 AND is_active = TRUE ORDER BY name ASC`
	rows, err := p.pool.Query(ctx, q, serverID)
	if err != nil {
		return p.mem.ListMCPTools(ctx, serverID)
	}
	defer rows.Close()

	var out []*domain.MCPTool
	for rows.Next() {
		var t domain.MCPTool
		var schemaJSON []byte
		if err := rows.Scan(&t.ID, &t.ServerID, &t.OrgID, &t.Name, &t.Description, &schemaJSON, &t.ToolDefHash, &t.CostPerCallMicros, &t.IsActive, &t.CreatedAt, &t.UpdatedAt); err == nil {
			if len(schemaJSON) > 0 {
				_ = json.Unmarshal(schemaJSON, &t.InputSchema)
			}
			out = append(out, &t)
		}
	}
	return out, nil
}

func (p *PostgresRepository) GetMCPTool(ctx context.Context, id string) (*domain.MCPTool, error) {
	if p.pool == nil {
		return p.mem.GetMCPTool(ctx, id)
	}
	const q = `SELECT id, server_id, org_id, name, description, input_schema, tool_def_hash, cost_per_call_micros, is_active, created_at, updated_at FROM mcp_tools WHERE id = $1`
	var t domain.MCPTool
	var schemaJSON []byte
	if err := p.pool.QueryRow(ctx, q, id).Scan(&t.ID, &t.ServerID, &t.OrgID, &t.Name, &t.Description, &schemaJSON, &t.ToolDefHash, &t.CostPerCallMicros, &t.IsActive, &t.CreatedAt, &t.UpdatedAt); err != nil {
		return nil, fmt.Errorf("mcp tool %s not found: %w", id, err)
	}
	if len(schemaJSON) > 0 {
		_ = json.Unmarshal(schemaJSON, &t.InputSchema)
	}
	return &t, nil
}

func (p *PostgresRepository) CreateMCPToolset(ctx context.Context, toolset *domain.MCPToolset) error {
	if toolset.ID == "" {
		toolset.ID = uuid.NewString()
	}
	toolIDs := toolset.ToolIDs
	if toolIDs == nil {
		toolIDs = []string{}
	}
	const q = `INSERT INTO mcp_toolsets (id, org_id, name, slug, tool_ids, is_active) VALUES ($1,$2,$3,$4,$5,$6)`
	if _, err := p.pool.Exec(ctx, q, toolset.ID, toolset.OrgID, toolset.Name, toolset.Slug, toolIDs, toolset.IsActive); err != nil {
		return err
	}
	return p.mem.CreateMCPToolset(ctx, toolset)
}

func (p *PostgresRepository) GetMCPToolsetBySlug(ctx context.Context, orgID, slug string) (*domain.MCPToolset, error) {
	if ts, err := p.mem.GetMCPToolsetBySlug(ctx, orgID, slug); err == nil && ts != nil {
		return ts, nil
	}
	const q = `SELECT id, org_id, name, slug, tool_ids, is_active, created_at, updated_at FROM mcp_toolsets WHERE (org_id = $1 OR $1 = '') AND slug = $2 LIMIT 1`
	var ts domain.MCPToolset
	if err := p.pool.QueryRow(ctx, q, orgID, slug).Scan(&ts.ID, &ts.OrgID, &ts.Name, &ts.Slug, &ts.ToolIDs, &ts.IsActive, &ts.CreatedAt, &ts.UpdatedAt); err != nil {
		return nil, fmt.Errorf("mcp toolset %q not found: %w", slug, err)
	}
	_ = p.mem.CreateMCPToolset(ctx, &ts)
	return &ts, nil
}

func (p *PostgresRepository) ListMCPToolsets(ctx context.Context, orgID string) ([]*domain.MCPToolset, error) {
	const q = `SELECT id, org_id, name, slug, tool_ids, is_active, created_at, updated_at FROM mcp_toolsets WHERE org_id = $1 OR $1 = ''`
	rows, err := p.pool.Query(ctx, q, orgID)
	if err != nil {
		return p.mem.ListMCPToolsets(ctx, orgID)
	}
	defer rows.Close()

	var out []*domain.MCPToolset
	for rows.Next() {
		var ts domain.MCPToolset
		if err := rows.Scan(&ts.ID, &ts.OrgID, &ts.Name, &ts.Slug, &ts.ToolIDs, &ts.IsActive, &ts.CreatedAt, &ts.UpdatedAt); err == nil {
			out = append(out, &ts)
		}
	}
	return out, nil
}

func (p *PostgresRepository) SetMCPUserCredential(ctx context.Context, cred *domain.MCPUserCredential) error {
	if cred.ID == "" {
		cred.ID = uuid.NewString()
	}
	const q = `
		INSERT INTO mcp_user_credentials (id, server_id, user_id, org_id, encrypted_token, encrypted_dek, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, NOW())
		ON CONFLICT (server_id, user_id) DO UPDATE SET
			encrypted_token = EXCLUDED.encrypted_token,
			encrypted_dek = EXCLUDED.encrypted_dek,
			updated_at = NOW()`
	if _, err := p.pool.Exec(ctx, q, cred.ID, cred.ServerID, cred.UserID, cred.OrgID, cred.EncryptedToken, cred.EncryptedDEK); err != nil {
		return err
	}
	return p.mem.SetMCPUserCredential(ctx, cred)
}

func (p *PostgresRepository) GetMCPUserCredential(ctx context.Context, serverID, userID string) (*domain.MCPUserCredential, error) {
	if c, err := p.mem.GetMCPUserCredential(ctx, serverID, userID); err == nil && c != nil {
		return c, nil
	}
	const q = `SELECT id, server_id, user_id, org_id, encrypted_token, encrypted_dek, created_at, updated_at FROM mcp_user_credentials WHERE server_id = $1 AND user_id = $2`
	var c domain.MCPUserCredential
	if err := p.pool.QueryRow(ctx, q, serverID, userID).Scan(&c.ID, &c.ServerID, &c.UserID, &c.OrgID, &c.EncryptedToken, &c.EncryptedDEK, &c.CreatedAt, &c.UpdatedAt); err != nil {
		return nil, fmt.Errorf("credential for server %s user %s not found: %w", serverID, userID, err)
	}
	_ = p.mem.SetMCPUserCredential(ctx, &c)
	return &c, nil
}

// -----------------------------------------------------------------------------
// A2A: Agents, Tasks, Events, Publications & Outbox
// -----------------------------------------------------------------------------

func (p *PostgresRepository) CreateA2AAgent(ctx context.Context, agent *domain.A2AAgent) error {
	if agent.ID == "" {
		agent.ID = uuid.NewString()
	}
	const q = `
		INSERT INTO a2a_agents (
			id, org_id, name, slug, endpoint_url, agent_card_url, agent_card_json,
			task_visibility_mode, auth_type, encrypted_auth_secret, encrypted_auth_dek,
			max_task_iterations, max_task_budget_micros, is_active, is_killed
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`
	if _, err := p.pool.Exec(ctx, q,
		agent.ID, agent.OrgID, agent.Name, agent.Slug, agent.EndpointURL, agent.AgentCardURL, agent.AgentCardJSON,
		agent.TaskVisibilityMode, agent.AuthType, agent.EncryptedAuthSecret, agent.EncryptedAuthDEK,
		agent.MaxTaskIterations, agent.MaxTaskBudgetMicros, agent.IsActive, agent.IsKilled,
	); err != nil {
		return err
	}
	return p.mem.CreateA2AAgent(ctx, agent)
}

func (p *PostgresRepository) UpdateA2AAgent(ctx context.Context, agent *domain.A2AAgent) error {
	const q = `
		UPDATE a2a_agents SET
			name = $2, slug = $3, endpoint_url = $4, agent_card_url = $5, agent_card_json = $6,
			task_visibility_mode = $7, auth_type = $8, encrypted_auth_secret = $9, encrypted_auth_dek = $10,
			max_task_iterations = $11, max_task_budget_micros = $12, is_active = $13, is_killed = $14,
			updated_at = NOW()
		WHERE id = $1`
	if _, err := p.pool.Exec(ctx, q,
		agent.ID, agent.Name, agent.Slug, agent.EndpointURL, agent.AgentCardURL, agent.AgentCardJSON,
		agent.TaskVisibilityMode, agent.AuthType, agent.EncryptedAuthSecret, agent.EncryptedAuthDEK,
		agent.MaxTaskIterations, agent.MaxTaskBudgetMicros, agent.IsActive, agent.IsKilled,
	); err != nil {
		return err
	}
	if err := p.mem.UpdateA2AAgent(ctx, agent); err != nil {
		_ = p.mem.CreateA2AAgent(ctx, agent)
	}
	return nil
}

func (p *PostgresRepository) GetA2AAgent(ctx context.Context, id string) (*domain.A2AAgent, error) {
	if p.pool == nil {
		return p.mem.GetA2AAgent(ctx, id)
	}
	const q = `
		SELECT id, org_id, name, slug, endpoint_url, agent_card_url, agent_card_json,
		       task_visibility_mode, auth_type, encrypted_auth_secret, encrypted_auth_dek,
		       max_task_iterations, max_task_budget_micros, is_active, is_killed,
		       created_at, updated_at
		FROM a2a_agents WHERE id = $1`
	var a domain.A2AAgent
	if err := p.pool.QueryRow(ctx, q, id).Scan(
		&a.ID, &a.OrgID, &a.Name, &a.Slug, &a.EndpointURL, &a.AgentCardURL, &a.AgentCardJSON,
		&a.TaskVisibilityMode, &a.AuthType, &a.EncryptedAuthSecret, &a.EncryptedAuthDEK,
		&a.MaxTaskIterations, &a.MaxTaskBudgetMicros, &a.IsActive, &a.IsKilled,
		&a.CreatedAt, &a.UpdatedAt,
	); err != nil {
		return nil, fmt.Errorf("a2a agent %s not found: %w", id, err)
	}
	_ = p.mem.CreateA2AAgent(ctx, &a)
	return &a, nil
}

func (p *PostgresRepository) GetA2AAgentBySlug(ctx context.Context, orgID, slug string) (*domain.A2AAgent, error) {
	if p.pool == nil {
		return p.mem.GetA2AAgentBySlug(ctx, orgID, slug)
	}
	const q = `
		SELECT id, org_id, name, slug, endpoint_url, agent_card_url, agent_card_json,
		       task_visibility_mode, auth_type, encrypted_auth_secret, encrypted_auth_dek,
		       max_task_iterations, max_task_budget_micros, is_active, is_killed,
		       created_at, updated_at
		FROM a2a_agents WHERE (org_id = $1 OR $1 = '') AND slug = $2 LIMIT 1`
	var a domain.A2AAgent
	if err := p.pool.QueryRow(ctx, q, orgID, slug).Scan(
		&a.ID, &a.OrgID, &a.Name, &a.Slug, &a.EndpointURL, &a.AgentCardURL, &a.AgentCardJSON,
		&a.TaskVisibilityMode, &a.AuthType, &a.EncryptedAuthSecret, &a.EncryptedAuthDEK,
		&a.MaxTaskIterations, &a.MaxTaskBudgetMicros, &a.IsActive, &a.IsKilled,
		&a.CreatedAt, &a.UpdatedAt,
	); err != nil {
		return nil, fmt.Errorf("a2a agent %q not found: %w", slug, err)
	}
	_ = p.mem.CreateA2AAgent(ctx, &a)
	return &a, nil
}

func (p *PostgresRepository) ListA2AAgents(ctx context.Context, orgID string) ([]*domain.A2AAgent, error) {
	const q = `
		SELECT id, org_id, name, slug, endpoint_url, agent_card_url, agent_card_json,
		       task_visibility_mode, auth_type, encrypted_auth_secret, encrypted_auth_dek,
		       max_task_iterations, max_task_budget_micros, is_active, is_killed,
		       created_at, updated_at
		FROM a2a_agents WHERE org_id = $1 OR $1 = '' ORDER BY name ASC`
	rows, err := p.pool.Query(ctx, q, orgID)
	if err != nil {
		return p.mem.ListA2AAgents(ctx, orgID)
	}
	defer rows.Close()

	var out []*domain.A2AAgent
	for rows.Next() {
		var a domain.A2AAgent
		if err := rows.Scan(
			&a.ID, &a.OrgID, &a.Name, &a.Slug, &a.EndpointURL, &a.AgentCardURL, &a.AgentCardJSON,
			&a.TaskVisibilityMode, &a.AuthType, &a.EncryptedAuthSecret, &a.EncryptedAuthDEK,
			&a.MaxTaskIterations, &a.MaxTaskBudgetMicros, &a.IsActive, &a.IsKilled,
			&a.CreatedAt, &a.UpdatedAt,
		); err == nil {
			out = append(out, &a)
		}
	}
	return out, nil
}

func (p *PostgresRepository) SetA2AAgentKillSwitch(ctx context.Context, id string, killed bool) error {
	_, err := p.pool.Exec(ctx, `UPDATE a2a_agents SET is_killed = $2, updated_at = NOW() WHERE id = $1`, id, killed)
	_ = p.mem.SetA2AAgentKillSwitch(ctx, id, killed)
	return err
}

func (p *PostgresRepository) CreateA2ATask(ctx context.Context, task *domain.A2ATask) error {
	if task.ID == "" {
		task.ID = uuid.NewString()
	}
	const q = `
		INSERT INTO a2a_tasks (
			id, agent_id, org_id, team_id, virtual_key_id, user_id, client_task_id,
			state, last_event_seq, input_message_json, output_message_json, total_cost_micros
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`
	if _, err := p.pool.Exec(ctx, q,
		task.ID, task.AgentID, task.OrgID, task.TeamID, task.VirtualKeyID, task.UserID, task.ClientTaskID,
		task.State, task.LastEventSeq, task.InputMessageJSON, task.OutputMessageJSON, task.TotalCostMicros,
	); err != nil {
		return err
	}
	return p.mem.CreateA2ATask(ctx, task)
}

func (p *PostgresRepository) UpdateA2ATaskState(ctx context.Context, taskID, state string, outputJSON string, costMicros int64) error {
	var completedAt *time.Time
	if state == domain.A2ATaskStateCompleted || state == domain.A2ATaskStateFailed || state == domain.A2ATaskStateCanceled {
		now := time.Now().UTC()
		completedAt = &now
	}
	const q = `
		UPDATE a2a_tasks SET
			state = $2,
			output_message_json = CASE WHEN $3 <> '' THEN $3 ELSE output_message_json END,
			total_cost_micros = total_cost_micros + $4,
			completed_at = COALESCE($5, completed_at),
			updated_at = NOW()
		WHERE id = $1`
	if _, err := p.pool.Exec(ctx, q, taskID, state, outputJSON, costMicros, completedAt); err != nil {
		return err
	}
	_ = p.mem.UpdateA2ATaskState(ctx, taskID, state, outputJSON, costMicros)
	return nil
}

func (p *PostgresRepository) GetA2ATask(ctx context.Context, id string) (*domain.A2ATask, error) {
	if t, err := p.mem.GetA2ATask(ctx, id); err == nil && t != nil {
		return t, nil
	}
	const q = `
		SELECT id, agent_id, org_id, team_id, virtual_key_id, user_id, client_task_id,
		       state, last_event_seq, input_message_json, output_message_json, total_cost_micros,
		       created_at, updated_at, completed_at
		FROM a2a_tasks WHERE id = $1`
	var t domain.A2ATask
	if err := p.pool.QueryRow(ctx, q, id).Scan(
		&t.ID, &t.AgentID, &t.OrgID, &t.TeamID, &t.VirtualKeyID, &t.UserID, &t.ClientTaskID,
		&t.State, &t.LastEventSeq, &t.InputMessageJSON, &t.OutputMessageJSON, &t.TotalCostMicros,
		&t.CreatedAt, &t.UpdatedAt, &t.CompletedAt,
	); err != nil {
		return nil, fmt.Errorf("a2a task %s not found: %w", id, err)
	}
	_ = p.mem.CreateA2ATask(ctx, &t)
	return &t, nil
}

func (p *PostgresRepository) ListA2ATasks(ctx context.Context, agentID, virtualKeyID string, limit int) ([]*domain.A2ATask, error) {
	if limit <= 0 {
		limit = 50
	}
	const q = `
		SELECT id, agent_id, org_id, team_id, virtual_key_id, user_id, client_task_id,
		       state, last_event_seq, input_message_json, output_message_json, total_cost_micros,
		       created_at, updated_at, completed_at
		FROM a2a_tasks
		WHERE (agent_id = $1 OR $1 = '') AND (virtual_key_id = $2 OR $2 = '')
		ORDER BY created_at DESC LIMIT $3`
	rows, err := p.pool.Query(ctx, q, agentID, virtualKeyID, limit)
	if err != nil {
		return p.mem.ListA2ATasks(ctx, agentID, virtualKeyID, limit)
	}
	defer rows.Close()

	var out []*domain.A2ATask
	for rows.Next() {
		var t domain.A2ATask
		if err := rows.Scan(
			&t.ID, &t.AgentID, &t.OrgID, &t.TeamID, &t.VirtualKeyID, &t.UserID, &t.ClientTaskID,
			&t.State, &t.LastEventSeq, &t.InputMessageJSON, &t.OutputMessageJSON, &t.TotalCostMicros,
			&t.CreatedAt, &t.UpdatedAt, &t.CompletedAt,
		); err == nil {
			out = append(out, &t)
		}
	}
	return out, nil
}

func (p *PostgresRepository) AppendA2ATaskEvent(ctx context.Context, taskID, eventType, payloadJSON string) (*domain.A2ATaskEvent, error) {
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin task event tx: %w", err)
	}
	defer tx.Rollback(ctx)

	// Atomic sequence increment with row lock on task:
	var nextSeq int64
	err = tx.QueryRow(ctx, `
		UPDATE a2a_tasks 
		SET last_event_seq = last_event_seq + 1, updated_at = NOW() 
		WHERE id = $1 
		RETURNING last_event_seq
	`, taskID).Scan(&nextSeq)
	if err != nil {
		return nil, fmt.Errorf("increment task event sequence: %w", err)
	}

	eventID := uuid.NewString()
	now := time.Now().UTC()
	_, err = tx.Exec(ctx, `
		INSERT INTO a2a_task_events (id, task_id, event_seq, event_type, payload_json, created_at)
		VALUES ($1, $2, $3, $4, $5, $6)
	`, eventID, taskID, nextSeq, eventType, payloadJSON, now)
	if err != nil {
		return nil, fmt.Errorf("insert a2a task event: %w", err)
	}

	// Insert into stream publications for background Redis Pub/Sub broadcast
	pubID := uuid.NewString()
	_, err = tx.Exec(ctx, `
		INSERT INTO a2a_stream_publications (id, task_id, event_seq, payload_json, published, created_at)
		VALUES ($1, $2, $3, $4, FALSE, $5)
	`, pubID, taskID, nextSeq, payloadJSON, now)
	if err != nil {
		return nil, fmt.Errorf("insert a2a stream publication: %w", err)
	}

	// Enqueue webhook notification if push config is registered for this task
	var targetURL string
	_ = tx.QueryRow(ctx, `SELECT target_url FROM a2a_push_notification_configs WHERE task_id = $1`, taskID).Scan(&targetURL)
	if targetURL != "" {
		outboxID := uuid.NewString()
		_, _ = tx.Exec(ctx, `
			INSERT INTO a2a_outbox_events (id, task_id, event_type, target_url, payload_json, status, created_at)
			VALUES ($1, $2, $3, $4, $5, 'pending', $6)
		`, outboxID, taskID, eventType, targetURL, payloadJSON, now)
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit task event tx: %w", err)
	}

	event := &domain.A2ATaskEvent{
		ID:          eventID,
		TaskID:      taskID,
		EventSeq:    nextSeq,
		EventType:   eventType,
		PayloadJSON: payloadJSON,
		CreatedAt:   now,
	}
	_, _ = p.mem.AppendA2ATaskEvent(ctx, taskID, eventType, payloadJSON)
	return event, nil
}

func (p *PostgresRepository) ListA2ATaskEvents(ctx context.Context, taskID string, afterSeq int64, limit int) ([]*domain.A2ATaskEvent, error) {
	if limit <= 0 {
		limit = 100
	}
	const q = `
		SELECT id, task_id, event_seq, event_type, payload_json, created_at
		FROM a2a_task_events
		WHERE task_id = $1 AND event_seq > $2
		ORDER BY event_seq ASC LIMIT $3`
	rows, err := p.pool.Query(ctx, q, taskID, afterSeq, limit)
	if err != nil {
		return p.mem.ListA2ATaskEvents(ctx, taskID, afterSeq, limit)
	}
	defer rows.Close()

	var out []*domain.A2ATaskEvent
	for rows.Next() {
		var e domain.A2ATaskEvent
		if err := rows.Scan(&e.ID, &e.TaskID, &e.EventSeq, &e.EventType, &e.PayloadJSON, &e.CreatedAt); err == nil {
			out = append(out, &e)
		}
	}
	return out, nil
}

func (p *PostgresRepository) ClaimPendingA2AStreamPublications(ctx context.Context, batchSize int) ([]*domain.A2AStreamPublication, error) {
	if batchSize <= 0 {
		batchSize = 50
	}
	const q = `
		UPDATE a2a_stream_publications SET
			attempt_count = attempt_count + 1,
			next_attempt_at = NOW() + INTERVAL '5 seconds'
		WHERE id IN (
			SELECT id FROM a2a_stream_publications
			WHERE NOT published AND next_attempt_at <= NOW()
			ORDER BY next_attempt_at ASC
			LIMIT $1
			FOR UPDATE SKIP LOCKED
		)
		RETURNING id, task_id, event_seq, payload_json, published, attempt_count, next_attempt_at, created_at`
	rows, err := p.pool.Query(ctx, q, batchSize)
	if err != nil {
		return p.mem.ClaimPendingA2AStreamPublications(ctx, batchSize)
	}
	defer rows.Close()

	var out []*domain.A2AStreamPublication
	for rows.Next() {
		var pub domain.A2AStreamPublication
		if err := rows.Scan(&pub.ID, &pub.TaskID, &pub.EventSeq, &pub.PayloadJSON, &pub.Published, &pub.AttemptCount, &pub.NextAttemptAt, &pub.CreatedAt); err == nil {
			out = append(out, &pub)
		}
	}
	return out, nil
}

func (p *PostgresRepository) MarkA2AStreamPublicationSuccess(ctx context.Context, id string) error {
	_, err := p.pool.Exec(ctx, `UPDATE a2a_stream_publications SET published = TRUE WHERE id = $1`, id)
	_ = p.mem.MarkA2AStreamPublicationSuccess(ctx, id)
	return err
}

func (p *PostgresRepository) CreateA2AOutboxEvent(ctx context.Context, event *domain.A2AOutboxEvent) error {
	if event.ID == "" {
		event.ID = uuid.NewString()
	}
	const q = `
		INSERT INTO a2a_outbox_events (id, task_id, event_type, target_url, payload_json, status)
		VALUES ($1, $2, $3, $4, $5, $6)`
	if _, err := p.pool.Exec(ctx, q, event.ID, event.TaskID, event.EventType, event.TargetURL, event.PayloadJSON, event.Status); err != nil {
		return err
	}
	return p.mem.CreateA2AOutboxEvent(ctx, event)
}

func (p *PostgresRepository) ClaimPendingA2AOutboxEvents(ctx context.Context, batchSize int) ([]*domain.A2AOutboxEvent, error) {
	if batchSize <= 0 {
		batchSize = 25
	}
	const q = `
		UPDATE a2a_outbox_events SET
			attempt_count = attempt_count + 1,
			next_attempt_at = NOW() + INTERVAL '10 seconds'
		WHERE id IN (
			SELECT id FROM a2a_outbox_events
			WHERE status = 'pending' AND next_attempt_at <= NOW()
			ORDER BY next_attempt_at ASC
			LIMIT $1
			FOR UPDATE SKIP LOCKED
		)
		RETURNING id, task_id, event_type, target_url, payload_json, status, attempt_count, next_attempt_at, created_at`
	rows, err := p.pool.Query(ctx, q, batchSize)
	if err != nil {
		return p.mem.ClaimPendingA2AOutboxEvents(ctx, batchSize)
	}
	defer rows.Close()

	var out []*domain.A2AOutboxEvent
	for rows.Next() {
		var o domain.A2AOutboxEvent
		if err := rows.Scan(&o.ID, &o.TaskID, &o.EventType, &o.TargetURL, &o.PayloadJSON, &o.Status, &o.AttemptCount, &o.NextAttemptAt, &o.CreatedAt); err == nil {
			out = append(out, &o)
		}
	}
	return out, nil
}

func (p *PostgresRepository) UpdateA2AOutboxEventStatus(ctx context.Context, id, status string) error {
	_, err := p.pool.Exec(ctx, `UPDATE a2a_outbox_events SET status = $2 WHERE id = $1`, id, status)
	_ = p.mem.UpdateA2AOutboxEventStatus(ctx, id, status)
	return err
}

func (p *PostgresRepository) GetA2AOutboxEvent(ctx context.Context, id string) (*domain.A2AOutboxEvent, error) {
	if ev, err := p.mem.GetA2AOutboxEvent(ctx, id); err == nil && ev != nil {
		return ev, nil
	}
	const q = `SELECT id, task_id, event_type, target_url, payload_json, status, attempt_count, next_attempt_at, created_at FROM a2a_outbox_events WHERE id = $1`
	var o domain.A2AOutboxEvent
	if err := p.pool.QueryRow(ctx, q, id).Scan(&o.ID, &o.TaskID, &o.EventType, &o.TargetURL, &o.PayloadJSON, &o.Status, &o.AttemptCount, &o.NextAttemptAt, &o.CreatedAt); err != nil {
		return nil, fmt.Errorf("outbox event %s not found: %w", id, err)
	}
	return &o, nil
}

func (p *PostgresRepository) SetA2APushNotificationConfig(ctx context.Context, cfg *domain.A2APushNotificationConfig) error {
	if cfg.ID == "" {
		cfg.ID = uuid.NewString()
	}
	const q = `
		INSERT INTO a2a_push_notification_configs (id, task_id, target_url, auth_token)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (task_id) DO UPDATE SET
			target_url = EXCLUDED.target_url,
			auth_token = EXCLUDED.auth_token`
	if _, err := p.pool.Exec(ctx, q, cfg.ID, cfg.TaskID, cfg.TargetURL, cfg.AuthToken); err != nil {
		return err
	}
	return p.mem.SetA2APushNotificationConfig(ctx, cfg)
}

func (p *PostgresRepository) GetA2APushNotificationConfig(ctx context.Context, taskID string) (*domain.A2APushNotificationConfig, error) {
	if c, err := p.mem.GetA2APushNotificationConfig(ctx, taskID); err == nil && c != nil {
		return c, nil
	}
	const q = `SELECT id, task_id, target_url, auth_token, created_at FROM a2a_push_notification_configs WHERE task_id = $1`
	var cfg domain.A2APushNotificationConfig
	if err := p.pool.QueryRow(ctx, q, taskID).Scan(&cfg.ID, &cfg.TaskID, &cfg.TargetURL, &cfg.AuthToken, &cfg.CreatedAt); err != nil {
		return nil, fmt.Errorf("push notification config for task %s not found: %w", taskID, err)
	}
	_ = p.mem.SetA2APushNotificationConfig(ctx, &cfg)
	return &cfg, nil
}

// Files Management

func (p *PostgresRepository) CreateFile(ctx context.Context, file *domain.CanonicalFile) error {
	if file.ID == "" {
		file.ID = uuid.NewString()
	}
	if file.CreatedAt.IsZero() {
		file.CreatedAt = time.Now().UTC()
	}
	const q = `
		INSERT INTO files (id, org_id, team_id, user_id, bytes, created_at, filename, purpose, status, content_sha256, storage_path, upstream_provider, upstream_id, expires_at)
		VALUES ($1, $2, NULLIF($3, ''), NULLIF($4, ''), $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)`
	_, err := p.pool.Exec(ctx, q, file.ID, file.OrgID, file.TeamID, file.UserID, file.Bytes, file.CreatedAt, file.Filename, file.Purpose, file.Status, file.ContentSHA256, file.StoragePath, file.UpstreamProvider, file.UpstreamID, file.ExpiresAt)
	if err != nil {
		return err
	}
	return p.mem.CreateFile(ctx, file)
}

func (p *PostgresRepository) GetFile(ctx context.Context, orgID, fileID string) (*domain.CanonicalFile, error) {
	if f, err := p.mem.GetFile(ctx, orgID, fileID); err == nil && f != nil {
		return f, nil
	}
	const q = `
		SELECT id, org_id, COALESCE(team_id::text, ''), COALESCE(user_id::text, ''), bytes, created_at, filename, purpose, status, content_sha256, storage_path, COALESCE(upstream_provider, ''), COALESCE(upstream_id, ''), expires_at
		FROM files WHERE id = $1 AND ($2 = '' OR org_id = $2)`
	var f domain.CanonicalFile
	if err := p.pool.QueryRow(ctx, q, fileID, orgID).Scan(
		&f.ID, &f.OrgID, &f.TeamID, &f.UserID, &f.Bytes, &f.CreatedAt, &f.Filename, &f.Purpose, &f.Status, &f.ContentSHA256, &f.StoragePath, &f.UpstreamProvider, &f.UpstreamID, &f.ExpiresAt,
	); err != nil {
		return nil, fmt.Errorf("file %s not found: %w", fileID, err)
	}
	_ = p.mem.CreateFile(ctx, &f)
	return &f, nil
}

func (p *PostgresRepository) ListFiles(ctx context.Context, orgID string, purpose string) ([]*domain.CanonicalFile, error) {
	const q = `
		SELECT id, org_id, COALESCE(team_id::text, ''), COALESCE(user_id::text, ''), bytes, created_at, filename, purpose, status, content_sha256, storage_path, COALESCE(upstream_provider, ''), COALESCE(upstream_id, ''), expires_at
		FROM files WHERE ($1 = '' OR org_id = $1) AND ($2 = '' OR purpose = $2)
		ORDER BY created_at DESC`
	rows, err := p.pool.Query(ctx, q, orgID, purpose)
	if err != nil {
		return p.mem.ListFiles(ctx, orgID, purpose)
	}
	defer rows.Close()
	var out []*domain.CanonicalFile
	for rows.Next() {
		var f domain.CanonicalFile
		if err := rows.Scan(
			&f.ID, &f.OrgID, &f.TeamID, &f.UserID, &f.Bytes, &f.CreatedAt, &f.Filename, &f.Purpose, &f.Status, &f.ContentSHA256, &f.StoragePath, &f.UpstreamProvider, &f.UpstreamID, &f.ExpiresAt,
		); err == nil {
			out = append(out, &f)
			_ = p.mem.CreateFile(ctx, &f)
		}
	}
	return out, nil
}

func (p *PostgresRepository) DeleteFile(ctx context.Context, orgID, fileID string) error {
	const q = `DELETE FROM files WHERE id = $1 AND ($2 = '' OR org_id = $2)`
	if _, err := p.pool.Exec(ctx, q, fileID, orgID); err != nil {
		return err
	}
	_ = p.mem.DeleteFile(ctx, orgID, fileID)
	return nil
}

// Batches Management

func (p *PostgresRepository) CreateBatch(ctx context.Context, batch *domain.CanonicalBatch) error {
	if batch.ID == "" {
		batch.ID = uuid.NewString()
	}
	if batch.CreatedAt.IsZero() {
		batch.CreatedAt = time.Now().UTC()
	}
	metaJSON, _ := json.Marshal(batch.Metadata)
	countsJSON, _ := json.Marshal(batch.RequestCounts)
	const q = `
		INSERT INTO batches (id, org_id, team_id, input_file_id, output_file_id, error_file_id, endpoint, status, completion_window, created_at, completed_at, metadata, request_counts, estimated_tokens, reserved_cost_micros, upstream_provider, upstream_id)
		VALUES ($1, $2, NULLIF($3, '')::uuid, $4, NULLIF($5, ''), NULLIF($6, ''), $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)`
	_, err := p.pool.Exec(ctx, q, batch.ID, batch.OrgID, batch.TeamID, batch.InputFileID, batch.OutputFileID, batch.ErrorFileID, batch.Endpoint, batch.Status, batch.CompletionWindow, batch.CreatedAt, batch.CompletedAt, metaJSON, countsJSON, batch.EstimatedTokens, batch.ReservedCostMicros, batch.UpstreamProvider, batch.UpstreamID)
	if err != nil {
		return err
	}
	return p.mem.CreateBatch(ctx, batch)
}

func (p *PostgresRepository) GetBatch(ctx context.Context, orgID, batchID string) (*domain.CanonicalBatch, error) {
	if b, err := p.mem.GetBatch(ctx, orgID, batchID); err == nil && b != nil {
		return b, nil
	}
	const q = `
		SELECT id, org_id, COALESCE(team_id::text, ''), input_file_id, COALESCE(output_file_id, ''), COALESCE(error_file_id, ''), endpoint, status, completion_window, created_at, completed_at, metadata, request_counts, estimated_tokens, reserved_cost_micros, COALESCE(upstream_provider, ''), COALESCE(upstream_id, '')
		FROM batches WHERE id = $1 AND ($2 = '' OR org_id = $2::uuid)`
	var b domain.CanonicalBatch
	var metaJSON, countsJSON []byte
	if err := p.pool.QueryRow(ctx, q, batchID, orgID).Scan(
		&b.ID, &b.OrgID, &b.TeamID, &b.InputFileID, &b.OutputFileID, &b.ErrorFileID, &b.Endpoint, &b.Status, &b.CompletionWindow, &b.CreatedAt, &b.CompletedAt, &metaJSON, &countsJSON, &b.EstimatedTokens, &b.ReservedCostMicros, &b.UpstreamProvider, &b.UpstreamID,
	); err != nil {
		return nil, fmt.Errorf("batch %s not found: %w", batchID, err)
	}
	_ = json.Unmarshal(metaJSON, &b.Metadata)
	_ = json.Unmarshal(countsJSON, &b.RequestCounts)
	_ = p.mem.CreateBatch(ctx, &b)
	return &b, nil
}

func (p *PostgresRepository) ListBatches(ctx context.Context, orgID string, limit int) ([]*domain.CanonicalBatch, error) {
	if limit <= 0 {
		limit = 50
	}
	const q = `
		SELECT id, org_id, COALESCE(team_id::text, ''), input_file_id, COALESCE(output_file_id, ''), COALESCE(error_file_id, ''), endpoint, status, completion_window, created_at, completed_at, metadata, request_counts, estimated_tokens, reserved_cost_micros, COALESCE(upstream_provider, ''), COALESCE(upstream_id, '')
		FROM batches WHERE ($1 = '' OR org_id = $1::uuid)
		ORDER BY created_at DESC LIMIT $2`
	rows, err := p.pool.Query(ctx, q, orgID, limit)
	if err != nil {
		return p.mem.ListBatches(ctx, orgID, limit)
	}
	defer rows.Close()
	var out []*domain.CanonicalBatch
	for rows.Next() {
		var b domain.CanonicalBatch
		var metaJSON, countsJSON []byte
		if err := rows.Scan(
			&b.ID, &b.OrgID, &b.TeamID, &b.InputFileID, &b.OutputFileID, &b.ErrorFileID, &b.Endpoint, &b.Status, &b.CompletionWindow, &b.CreatedAt, &b.CompletedAt, &metaJSON, &countsJSON, &b.EstimatedTokens, &b.ReservedCostMicros, &b.UpstreamProvider, &b.UpstreamID,
		); err == nil {
			_ = json.Unmarshal(metaJSON, &b.Metadata)
			_ = json.Unmarshal(countsJSON, &b.RequestCounts)
			out = append(out, &b)
			_ = p.mem.CreateBatch(ctx, &b)
		}
	}
	return out, nil
}

func (p *PostgresRepository) UpdateBatchStatus(ctx context.Context, batchID string, status string, outputFileID string, counts domain.BatchCounts, completedAt *time.Time) error {
	countsJSON, _ := json.Marshal(counts)
	const q = `UPDATE batches SET status = $1, output_file_id = COALESCE(NULLIF($2, ''), output_file_id), request_counts = $3, completed_at = $4 WHERE id = $5`
	if _, err := p.pool.Exec(ctx, q, status, outputFileID, countsJSON, completedAt, batchID); err != nil {
		return err
	}
	_ = p.mem.UpdateBatchStatus(ctx, batchID, status, outputFileID, counts, completedAt)
	return nil
}

// -----------------------------------------------------------------------------
// Guardrail Definitions Registry & Hierarchical Bindings
// -----------------------------------------------------------------------------

type guardrailStreamScopeJSON struct {
	Scope  domain.StreamScope       `json:"scope,omitempty"`
	ByHook domain.StreamScopeByHook `json:"by_hook,omitempty"`
}

func marshalJSONOrDefault(v any, fallback string) ([]byte, error) {
	if v == nil {
		return []byte(fallback), nil
	}
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	if len(b) == 0 || string(b) == "null" {
		return []byte(fallback), nil
	}
	return b, nil
}

func marshalGuardrailDefinitionPayloads(def *domain.GuardrailDefinition) (hooksJSON, streamScopeJSON, modeRuleJSON, rolesJSON, configJSON, infoJSON []byte, err error) {
	hooksJSON, err = marshalJSONOrDefault(def.EventHooks, "[]")
	if err != nil {
		return nil, nil, nil, nil, nil, nil, fmt.Errorf("marshal guardrail hooks: %w", err)
	}
	streamScopeJSON, err = json.Marshal(guardrailStreamScopeJSON{
		Scope:  def.StreamScope,
		ByHook: def.StreamScopeByHook,
	})
	if err != nil {
		return nil, nil, nil, nil, nil, nil, fmt.Errorf("marshal guardrail stream_scope: %w", err)
	}
	modeRuleJSON, err = marshalJSONOrDefault(def.ModeRule, "{}")
	if err != nil {
		return nil, nil, nil, nil, nil, nil, fmt.Errorf("marshal guardrail mode_rule: %w", err)
	}
	rolesJSON, err = marshalJSONOrDefault(def.EnabledRoles, "[]")
	if err != nil {
		return nil, nil, nil, nil, nil, nil, fmt.Errorf("marshal guardrail enabled_roles: %w", err)
	}
	configJSON, err = marshalJSONOrDefault(def.Config, "{}")
	if err != nil {
		return nil, nil, nil, nil, nil, nil, fmt.Errorf("marshal guardrail config: %w", err)
	}
	infoJSON, err = marshalJSONOrDefault(def.GuardrailInfo, "{}")
	if err != nil {
		return nil, nil, nil, nil, nil, nil, fmt.Errorf("marshal guardrail info: %w", err)
	}
	return hooksJSON, streamScopeJSON, modeRuleJSON, rolesJSON, configJSON, infoJSON, nil
}

const guardrailDefinitionSelectCols = `id, org_id, name, provider, hooks, stream_scope, mode_rule, default_on, enabled_roles, timeout_ms, fail_open, precedence, config, encrypted_secrets, encrypted_dek, status, guardrail_info, weight, created_at, updated_at`

func scanGuardrailDefinition(row rowScanner) (*domain.GuardrailDefinition, error) {
	var def domain.GuardrailDefinition
	var statusStr string
	var hooksJSON, streamScopeJSON, modeRuleJSON, rolesJSON, configJSON, infoJSON []byte
	if err := row.Scan(
		&def.ID, &def.OrgID, &def.Name, &def.Provider,
		&hooksJSON, &streamScopeJSON, &modeRuleJSON,
		&def.DefaultOn, &rolesJSON, &def.TimeoutMs, &def.FailOpen, &def.Precedence,
		&configJSON, &def.EncryptedSecrets, &def.EncryptedDEK, &statusStr, &infoJSON, &def.Weight,
		&def.CreatedAt, &def.UpdatedAt,
	); err != nil {
		return nil, err
	}
	def.Status = domain.GuardrailStatus(statusStr)

	if len(hooksJSON) > 0 && string(hooksJSON) != "[]" && string(hooksJSON) != "null" {
		if err := json.Unmarshal(hooksJSON, &def.EventHooks); err != nil {
			return nil, fmt.Errorf("unmarshal guardrail hooks: %w", err)
		}
	}
	if len(streamScopeJSON) > 0 && string(streamScopeJSON) != "{}" && string(streamScopeJSON) != "null" {
		trimmed := strings.TrimSpace(string(streamScopeJSON))
		if strings.HasPrefix(trimmed, `"`) {
			var scope domain.StreamScope
			if err := json.Unmarshal(streamScopeJSON, &scope); err != nil {
				return nil, fmt.Errorf("unmarshal guardrail stream_scope: %w", err)
			}
			def.StreamScope = scope
		} else {
			var ss guardrailStreamScopeJSON
			if err := json.Unmarshal(streamScopeJSON, &ss); err != nil {
				return nil, fmt.Errorf("unmarshal guardrail stream_scope: %w", err)
			}
			if ss.Scope != "" || len(ss.ByHook) > 0 {
				def.StreamScope = ss.Scope
				def.StreamScopeByHook = ss.ByHook
			} else {
				var byHook domain.StreamScopeByHook
				if err := json.Unmarshal(streamScopeJSON, &byHook); err == nil && len(byHook) > 0 {
					def.StreamScopeByHook = byHook
				}
			}
		}
	}
	if len(modeRuleJSON) > 0 && string(modeRuleJSON) != "{}" && string(modeRuleJSON) != "null" {
		var mr domain.GuardrailModeRule
		if err := json.Unmarshal(modeRuleJSON, &mr); err != nil {
			return nil, fmt.Errorf("unmarshal guardrail mode_rule: %w", err)
		}
		if len(mr.Tags) > 0 || len(mr.Default) > 0 {
			def.ModeRule = &mr
		}
	}
	if len(rolesJSON) > 0 && string(rolesJSON) != "[]" && string(rolesJSON) != "null" {
		if err := json.Unmarshal(rolesJSON, &def.EnabledRoles); err != nil {
			return nil, fmt.Errorf("unmarshal guardrail enabled_roles: %w", err)
		}
	}
	if len(configJSON) > 0 && string(configJSON) != "{}" && string(configJSON) != "null" {
		if err := json.Unmarshal(configJSON, &def.Config); err != nil {
			return nil, fmt.Errorf("unmarshal guardrail config: %w", err)
		}
	}
	if len(infoJSON) > 0 && string(infoJSON) != "{}" && string(infoJSON) != "null" {
		if err := json.Unmarshal(infoJSON, &def.GuardrailInfo); err != nil {
			return nil, fmt.Errorf("unmarshal guardrail info: %w", err)
		}
	}
	return &def, nil
}

const guardrailBindingSelectCols = `id, org_id, guardrail_id, guardrail_name, COALESCE(team_id, ''), COALESCE(virtual_key_id, ''), COALESCE(end_user_id, ''), COALESCE(model_group_id, ''), COALESCE(tag, ''), overrides, is_locked, created_at, updated_at`

func scanGuardrailBinding(row rowScanner) (*domain.GuardrailBinding, error) {
	var b domain.GuardrailBinding
	var overridesJSON []byte
	if err := row.Scan(
		&b.ID, &b.OrgID, &b.GuardrailID, &b.GuardrailName,
		&b.TeamID, &b.VirtualKeyID, &b.EndUserID, &b.ModelGroupID, &b.Tag,
		&overridesJSON, &b.IsLocked, &b.CreatedAt, &b.UpdatedAt,
	); err != nil {
		return nil, err
	}
	if len(overridesJSON) > 0 && string(overridesJSON) != "{}" && string(overridesJSON) != "null" {
		if err := json.Unmarshal(overridesJSON, &b.ParamOverrides); err != nil {
			return nil, fmt.Errorf("unmarshal guardrail binding overrides: %w", err)
		}
	}
	return &b, nil
}

func (p *PostgresRepository) syncGuardrailDefinitionMem(def *domain.GuardrailDefinition) {
	if p.mem == nil || def == nil {
		return
	}
	p.mem.mu.Lock()
	p.mem.guardrailDefs[def.ID] = cloneGuardrailDefinition(def)
	p.mem.mu.Unlock()
}

func (p *PostgresRepository) syncGuardrailBindingMem(b *domain.GuardrailBinding) {
	if p.mem == nil || b == nil {
		return
	}
	p.mem.mu.Lock()
	p.mem.guardrailBindings[b.ID] = cloneGuardrailBinding(b)
	p.mem.mu.Unlock()
}

func (p *PostgresRepository) CreateGuardrailDefinition(ctx context.Context, def *domain.GuardrailDefinition) error {
	if p.pool == nil {
		return p.mem.CreateGuardrailDefinition(ctx, def)
	}
	if err := normalizeGuardrailDefinition(def); err != nil {
		return err
	}
	if def.ID == "" {
		def.ID = uuid.NewString()
	}
	hooksJSON, streamScopeJSON, modeRuleJSON, rolesJSON, configJSON, infoJSON, err := marshalGuardrailDefinitionPayloads(def)
	if err != nil {
		return err
	}
	const q = `
		INSERT INTO guardrail_definitions (
			id, org_id, name, provider, hooks, stream_scope, mode_rule,
			default_on, enabled_roles, timeout_ms, fail_open, precedence,
			config, encrypted_secrets, encrypted_dek, status, guardrail_info, weight
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)
		RETURNING created_at, updated_at`
	if err := p.pool.QueryRow(ctx, q,
		def.ID, def.OrgID, def.Name, def.Provider,
		hooksJSON, streamScopeJSON, modeRuleJSON,
		def.DefaultOn, rolesJSON, def.TimeoutMs, def.FailOpen, def.Precedence,
		configJSON, def.EncryptedSecrets, def.EncryptedDEK, string(def.Status), infoJSON, def.Weight,
	).Scan(&def.CreatedAt, &def.UpdatedAt); err != nil {
		return err
	}
	p.syncGuardrailDefinitionMem(def)
	return nil
}

func (p *PostgresRepository) GetGuardrailDefinition(ctx context.Context, id string) (*domain.GuardrailDefinition, error) {
	if p.pool == nil {
		return p.mem.GetGuardrailDefinition(ctx, id)
	}
	const q = `SELECT ` + guardrailDefinitionSelectCols + ` FROM guardrail_definitions WHERE id = $1`
	def, err := scanGuardrailDefinition(p.pool.QueryRow(ctx, q, id))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("guardrail definition %q %w", id, ErrNotFound)
		}
		return nil, err
	}
	p.syncGuardrailDefinitionMem(def)
	return def, nil
}

func (p *PostgresRepository) ListGuardrailDefinitions(ctx context.Context, orgID string, status domain.GuardrailStatus, name string) ([]*domain.GuardrailDefinition, error) {
	if p.pool == nil {
		return p.mem.ListGuardrailDefinitions(ctx, orgID, status, name)
	}
	const q = `
		SELECT ` + guardrailDefinitionSelectCols + `
		FROM guardrail_definitions
		WHERE ($1 = '' OR org_id = $1)
		  AND ($2 = '' OR status = $2)
		  AND ($3 = '' OR name = $3)
		ORDER BY precedence ASC, created_at ASC, id ASC`
	rows, err := p.pool.Query(ctx, q, orgID, string(status), name)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*domain.GuardrailDefinition
	for rows.Next() {
		def, err := scanGuardrailDefinition(rows)
		if err != nil {
			return nil, err
		}
		p.syncGuardrailDefinitionMem(def)
		out = append(out, def)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func (p *PostgresRepository) UpdateGuardrailDefinition(ctx context.Context, def *domain.GuardrailDefinition) error {
	if p.pool == nil {
		return p.mem.UpdateGuardrailDefinition(ctx, def)
	}
	if def == nil || def.ID == "" {
		return fmt.Errorf("guardrail definition id is required")
	}
	if err := normalizeGuardrailDefinition(def); err != nil {
		return err
	}
	hooksJSON, streamScopeJSON, modeRuleJSON, rolesJSON, configJSON, infoJSON, err := marshalGuardrailDefinitionPayloads(def)
	if err != nil {
		return err
	}
	const q = `
		UPDATE guardrail_definitions SET
			name = $3,
			provider = $4,
			hooks = $5,
			stream_scope = $6,
			mode_rule = $7,
			default_on = $8,
			enabled_roles = $9,
			timeout_ms = $10,
			fail_open = $11,
			precedence = $12,
			config = $13,
			encrypted_secrets = CASE WHEN $14 <> '' OR $15 <> '' THEN $14 ELSE encrypted_secrets END,
			encrypted_dek = CASE WHEN $14 <> '' OR $15 <> '' THEN $15 ELSE encrypted_dek END,
			status = $16,
			guardrail_info = $17,
			weight = $18,
			updated_at = NOW()
		WHERE id = $1 AND org_id = $2
		RETURNING created_at, updated_at, encrypted_secrets, encrypted_dek`
	var encSecrets, encDEK string
	if err := p.pool.QueryRow(ctx, q,
		def.ID, def.OrgID, def.Name, def.Provider,
		hooksJSON, streamScopeJSON, modeRuleJSON,
		def.DefaultOn, rolesJSON, def.TimeoutMs, def.FailOpen, def.Precedence,
		configJSON, def.EncryptedSecrets, def.EncryptedDEK, string(def.Status), infoJSON, def.Weight,
	).Scan(&def.CreatedAt, &def.UpdatedAt, &encSecrets, &encDEK); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("guardrail definition %q %w", def.ID, ErrNotFound)
		}
		return err
	}
	if _, err := p.pool.Exec(ctx,
		`UPDATE guardrail_bindings SET guardrail_name = $2, updated_at = NOW() WHERE guardrail_id = $1 AND guardrail_name <> $2`,
		def.ID, def.Name,
	); err != nil {
		return err
	}
	stored := cloneGuardrailDefinition(def)
	stored.EncryptedSecrets = encSecrets
	stored.EncryptedDEK = encDEK
	p.syncGuardrailDefinitionMem(stored)
	if p.mem != nil {
		p.mem.mu.Lock()
		for _, b := range p.mem.guardrailBindings {
			if b.GuardrailID == def.ID {
				b.GuardrailName = def.Name
			}
		}
		p.mem.mu.Unlock()
	}
	return nil
}

func (p *PostgresRepository) DeleteGuardrailDefinition(ctx context.Context, id string) error {
	if p.pool == nil {
		return p.mem.DeleteGuardrailDefinition(ctx, id)
	}
	tag, err := p.pool.Exec(ctx, `DELETE FROM guardrail_definitions WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("guardrail definition %q %w", id, ErrNotFound)
	}
	if p.mem != nil {
		_ = p.mem.DeleteGuardrailDefinition(ctx, id)
	}
	return nil
}

func (p *PostgresRepository) CreateGuardrailBinding(ctx context.Context, binding *domain.GuardrailBinding) error {
	if p.pool == nil {
		return p.mem.CreateGuardrailBinding(ctx, binding)
	}
	if binding == nil {
		return fmt.Errorf("guardrail binding is required")
	}
	if binding.OrgID == "" {
		return fmt.Errorf("org_id is required for guardrail binding")
	}
	if binding.GuardrailID == "" {
		return fmt.Errorf("guardrail_id is required for guardrail binding")
	}
	var defName string
	if err := p.pool.QueryRow(ctx, `SELECT name FROM guardrail_definitions WHERE id = $1 AND org_id = $2`, binding.GuardrailID, binding.OrgID).Scan(&defName); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("guardrail definition %q %w", binding.GuardrailID, ErrNotFound)
		}
		return err
	}
	if binding.GuardrailName == "" {
		binding.GuardrailName = defName
	}
	if binding.ID == "" {
		binding.ID = uuid.NewString()
	}
	overridesJSON, err := marshalJSONOrDefault(binding.ParamOverrides, "{}")
	if err != nil {
		return fmt.Errorf("marshal guardrail binding overrides: %w", err)
	}
	const q = `
		INSERT INTO guardrail_bindings (
			id, org_id, guardrail_id, guardrail_name,
			team_id, virtual_key_id, end_user_id, model_group_id, tag,
			overrides, is_locked
		) VALUES (
			$1, $2, $3, $4,
			NULLIF($5, ''), NULLIF($6, ''), NULLIF($7, ''), NULLIF($8, ''), NULLIF($9, ''),
			$10, $11
		)
		RETURNING created_at, updated_at`
	if err := p.pool.QueryRow(ctx, q,
		binding.ID, binding.OrgID, binding.GuardrailID, binding.GuardrailName,
		binding.TeamID, binding.VirtualKeyID, binding.EndUserID, binding.ModelGroupID, binding.Tag,
		overridesJSON, binding.IsLocked,
	).Scan(&binding.CreatedAt, &binding.UpdatedAt); err != nil {
		return err
	}
	p.syncGuardrailBindingMem(binding)
	return nil
}

func (p *PostgresRepository) GetGuardrailBinding(ctx context.Context, id string) (*domain.GuardrailBinding, error) {
	if p.pool == nil {
		return p.mem.GetGuardrailBinding(ctx, id)
	}
	const q = `SELECT ` + guardrailBindingSelectCols + ` FROM guardrail_bindings WHERE id = $1`
	b, err := scanGuardrailBinding(p.pool.QueryRow(ctx, q, id))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("guardrail binding %q %w", id, ErrNotFound)
		}
		return nil, err
	}
	p.syncGuardrailBindingMem(b)
	return b, nil
}

func (p *PostgresRepository) ListGuardrailBindings(ctx context.Context, filter GuardrailBindingFilter) ([]*domain.GuardrailBinding, error) {
	if p.pool == nil {
		return p.mem.ListGuardrailBindings(ctx, filter)
	}
	const q = `
		SELECT ` + guardrailBindingSelectCols + `
		FROM guardrail_bindings
		WHERE ($1 = '' OR org_id = $1)
		  AND ($2 = '' OR guardrail_id = $2)
		  AND ($3 = '' OR guardrail_name = $3)
		  AND ($4 = '' OR team_id = $4)
		  AND ($5 = '' OR virtual_key_id = $5)
		  AND ($6 = '' OR end_user_id = $6)
		  AND ($7 = '' OR model_group_id = $7)
		  AND ($8 = '' OR tag = $8)
		ORDER BY created_at ASC, id ASC`
	rows, err := p.pool.Query(ctx, q,
		filter.OrgID, filter.GuardrailID, filter.GuardrailName,
		filter.TeamID, filter.VirtualKeyID, filter.EndUserID, filter.ModelGroupID, filter.Tag,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*domain.GuardrailBinding
	for rows.Next() {
		b, err := scanGuardrailBinding(rows)
		if err != nil {
			return nil, err
		}
		p.syncGuardrailBindingMem(b)
		out = append(out, b)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func (p *PostgresRepository) UpdateGuardrailBinding(ctx context.Context, binding *domain.GuardrailBinding) error {
	if p.pool == nil {
		return p.mem.UpdateGuardrailBinding(ctx, binding)
	}
	if binding == nil || binding.ID == "" {
		return fmt.Errorf("guardrail binding id is required")
	}
	if binding.OrgID == "" {
		return fmt.Errorf("org_id is required for guardrail binding")
	}
	if binding.GuardrailID == "" {
		return fmt.Errorf("guardrail_id is required for guardrail binding")
	}
	var defName string
	if err := p.pool.QueryRow(ctx, `SELECT name FROM guardrail_definitions WHERE id = $1 AND org_id = $2`, binding.GuardrailID, binding.OrgID).Scan(&defName); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("guardrail definition %q %w", binding.GuardrailID, ErrNotFound)
		}
		return err
	}
	if binding.GuardrailName == "" {
		binding.GuardrailName = defName
	}
	overridesJSON, err := marshalJSONOrDefault(binding.ParamOverrides, "{}")
	if err != nil {
		return fmt.Errorf("marshal guardrail binding overrides: %w", err)
	}
	const q = `
		UPDATE guardrail_bindings SET
			guardrail_id = $3,
			guardrail_name = $4,
			team_id = NULLIF($5, ''),
			virtual_key_id = NULLIF($6, ''),
			end_user_id = NULLIF($7, ''),
			model_group_id = NULLIF($8, ''),
			tag = NULLIF($9, ''),
			overrides = $10,
			is_locked = $11,
			updated_at = NOW()
		WHERE id = $1 AND org_id = $2
		RETURNING created_at, updated_at`
	if err := p.pool.QueryRow(ctx, q,
		binding.ID, binding.OrgID, binding.GuardrailID, binding.GuardrailName,
		binding.TeamID, binding.VirtualKeyID, binding.EndUserID, binding.ModelGroupID, binding.Tag,
		overridesJSON, binding.IsLocked,
	).Scan(&binding.CreatedAt, &binding.UpdatedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("guardrail binding %q %w", binding.ID, ErrNotFound)
		}
		return err
	}
	p.syncGuardrailBindingMem(binding)
	return nil
}

func (p *PostgresRepository) DeleteGuardrailBinding(ctx context.Context, id string) error {
	if p.pool == nil {
		return p.mem.DeleteGuardrailBinding(ctx, id)
	}
	tag, err := p.pool.Exec(ctx, `DELETE FROM guardrail_bindings WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("guardrail binding %q %w", id, ErrNotFound)
	}
	if p.mem != nil {
		_ = p.mem.DeleteGuardrailBinding(ctx, id)
	}
	return nil
}

func (p *PostgresRepository) ListEffectiveGuardrailsForOrg(ctx context.Context, orgID string) (*EffectiveGuardrails, error) {
	if p.pool == nil {
		return p.mem.ListEffectiveGuardrailsForOrg(ctx, orgID)
	}
	value, err := p.coalesceLookup(ctx, "effective_guardrails:"+orgID, func(lookupCtx context.Context) (any, error) {
		const defsQ = `
			SELECT ` + guardrailDefinitionSelectCols + `
			FROM guardrail_definitions
			WHERE org_id = $1 AND status = $2
			ORDER BY precedence ASC, created_at ASC, id ASC`
		defRows, err := p.pool.Query(lookupCtx, defsQ, orgID, string(domain.GuardrailStatusActive))
		if err != nil {
			return nil, err
		}
		defer defRows.Close()

		var defs []*domain.GuardrailDefinition
		for defRows.Next() {
			def, err := scanGuardrailDefinition(defRows)
			if err != nil {
				return nil, err
			}
			p.syncGuardrailDefinitionMem(def)
			defs = append(defs, def)
		}
		if err := defRows.Err(); err != nil {
			return nil, err
		}

		const bindQ = `
			SELECT b.id, b.org_id, b.guardrail_id, b.guardrail_name,
			       COALESCE(b.team_id, ''), COALESCE(b.virtual_key_id, ''), COALESCE(b.end_user_id, ''), COALESCE(b.model_group_id, ''), COALESCE(b.tag, ''),
			       b.overrides, b.is_locked, b.created_at, b.updated_at
			FROM guardrail_bindings b
			INNER JOIN guardrail_definitions d ON d.id = b.guardrail_id
			WHERE b.org_id = $1 AND d.org_id = $1 AND d.status = $2
			ORDER BY b.created_at ASC, b.id ASC`
		bindRows, err := p.pool.Query(lookupCtx, bindQ, orgID, string(domain.GuardrailStatusActive))
		if err != nil {
			return nil, err
		}
		defer bindRows.Close()

		var bindings []*domain.GuardrailBinding
		for bindRows.Next() {
			b, err := scanGuardrailBinding(bindRows)
			if err != nil {
				return nil, err
			}
			p.syncGuardrailBindingMem(b)
			bindings = append(bindings, b)
		}
		if err := bindRows.Err(); err != nil {
			return nil, err
		}

		return &EffectiveGuardrails{
			Definitions: defs,
			Bindings:    bindings,
		}, nil
	})
	if err != nil {
		return nil, err
	}
	eff, _ := value.(*EffectiveGuardrails)
	if eff == nil {
		return &EffectiveGuardrails{}, nil
	}
	cloned := &EffectiveGuardrails{
		Definitions: make([]*domain.GuardrailDefinition, len(eff.Definitions)),
		Bindings:    make([]*domain.GuardrailBinding, len(eff.Bindings)),
	}
	for i, d := range eff.Definitions {
		cloned.Definitions[i] = cloneGuardrailDefinition(d)
	}
	for i, b := range eff.Bindings {
		cloned.Bindings[i] = cloneGuardrailBinding(b)
	}
	return cloned, nil
}

func (p *PostgresRepository) RotateGuardrailSecrets(ctx context.Context, orgID, id, encryptedSecrets, encryptedDEK string) error {
	if id == "" {
		return fmt.Errorf("guardrail definition id is required")
	}
	if p.pool == nil {
		return p.mem.RotateGuardrailSecrets(ctx, orgID, id, encryptedSecrets, encryptedDEK)
	}
	tag, err := p.pool.Exec(ctx, `
		UPDATE guardrail_definitions
		SET encrypted_secrets = $3, encrypted_dek = $4, updated_at = NOW()
		WHERE id = $1 AND ($2 = '' OR org_id = $2)`,
		id, orgID, encryptedSecrets, encryptedDEK,
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("guardrail definition %q %w", id, ErrNotFound)
	}
	if p.mem != nil {
		_ = p.mem.RotateGuardrailSecrets(ctx, orgID, id, encryptedSecrets, encryptedDEK)
	}
	return nil
}

func (p *PostgresRepository) UpsertUserPassword(ctx context.Context, userID, passwordHash string, resetRequired bool) error {
	userID = strings.TrimSpace(userID)
	passwordHash = strings.TrimSpace(passwordHash)
	if userID == "" {
		return fmt.Errorf("user_id is required")
	}
	if passwordHash == "" {
		return fmt.Errorf("password_hash is required")
	}
	if p.pool == nil {
		return p.mem.UpsertUserPassword(ctx, userID, passwordHash, resetRequired)
	}
	const q = `
		INSERT INTO user_credentials (user_id, password_hash, password_reset_required, failed_attempts, locked_until, updated_at)
		VALUES ($1, $2, $3, 0, NULL, NOW())
		ON CONFLICT (user_id) DO UPDATE SET
			password_hash = EXCLUDED.password_hash,
			password_reset_required = EXCLUDED.password_reset_required,
			failed_attempts = 0,
			locked_until = NULL,
			updated_at = NOW()`
	if _, err := p.pool.Exec(ctx, q, userID, passwordHash, resetRequired); err != nil {
		return err
	}
	if p.mem != nil {
		_ = p.mem.UpsertUserPassword(ctx, userID, passwordHash, resetRequired)
	}
	return nil
}

func (p *PostgresRepository) GetUserCredential(ctx context.Context, userID string) (*domain.UserCredential, error) {
	userID = strings.TrimSpace(userID)
	if userID == "" {
		return nil, fmt.Errorf("user credential for %q %w", userID, ErrNotFound)
	}
	if p.pool == nil {
		return p.mem.GetUserCredential(ctx, userID)
	}
	const q = `
		SELECT user_id, password_hash, password_reset_required, failed_attempts, locked_until, updated_at
		FROM user_credentials
		WHERE user_id = $1`
	var cred domain.UserCredential
	if err := p.pool.QueryRow(ctx, q, userID).Scan(
		&cred.UserID,
		&cred.PasswordHash,
		&cred.PasswordResetRequired,
		&cred.FailedAttempts,
		&cred.LockedUntil,
		&cred.UpdatedAt,
	); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("user credential for %q %w", userID, ErrNotFound)
		}
		return nil, err
	}
	return &cred, nil
}

func (p *PostgresRepository) UpdateUserLoginFailure(ctx context.Context, userID string, failedAttempts int, lockedUntil *time.Time) error {
	userID = strings.TrimSpace(userID)
	if userID == "" {
		return fmt.Errorf("user_id is required")
	}
	if p.pool == nil {
		return p.mem.UpdateUserLoginFailure(ctx, userID, failedAttempts, lockedUntil)
	}
	const q = `
		UPDATE user_credentials
		SET failed_attempts = $2, locked_until = $3, updated_at = NOW()
		WHERE user_id = $1`
	tag, err := p.pool.Exec(ctx, q, userID, failedAttempts, lockedUntil)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("user credential for %q %w", userID, ErrNotFound)
	}
	if p.mem != nil {
		_ = p.mem.UpdateUserLoginFailure(ctx, userID, failedAttempts, lockedUntil)
	}
	return nil
}

func (p *PostgresRepository) CreateOperatorSession(ctx context.Context, session *domain.OperatorSession) error {
	if session == nil {
		return fmt.Errorf("operator session is required")
	}
	if strings.TrimSpace(session.UserID) == "" ||
		strings.TrimSpace(session.OrgID) == "" ||
		strings.TrimSpace(session.Role) == "" ||
		strings.TrimSpace(session.CSRFToken) == "" ||
		session.ExpiresAt.IsZero() {
		return fmt.Errorf("user_id, org_id, role, csrf_token, and expires_at are required")
	}
	if p.pool == nil {
		return p.mem.CreateOperatorSession(ctx, session)
	}
	if strings.TrimSpace(session.ID) == "" {
		session.ID = uuid.NewString()
	}
	if session.CreatedAt.IsZero() {
		session.CreatedAt = time.Now().UTC()
	}
	const q = `
		INSERT INTO operator_sessions (id, user_id, org_id, role, csrf_token, expires_at, revoked_at, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`
	if _, err := p.pool.Exec(ctx, q,
		session.ID,
		session.UserID,
		session.OrgID,
		session.Role,
		session.CSRFToken,
		session.ExpiresAt.UTC(),
		session.RevokedAt,
		session.CreatedAt.UTC(),
	); err != nil {
		return err
	}
	if p.mem != nil {
		_ = p.mem.CreateOperatorSession(ctx, session)
	}
	return nil
}

func (p *PostgresRepository) GetOperatorSession(ctx context.Context, id string) (*domain.OperatorSession, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return nil, fmt.Errorf("operator session %q %w", id, ErrNotFound)
	}
	if p.pool == nil {
		return p.mem.GetOperatorSession(ctx, id)
	}
	const q = `
		SELECT id, user_id, org_id, role, csrf_token, expires_at, revoked_at, created_at
		FROM operator_sessions
		WHERE id = $1`
	var sess domain.OperatorSession
	if err := p.pool.QueryRow(ctx, q, id).Scan(
		&sess.ID,
		&sess.UserID,
		&sess.OrgID,
		&sess.Role,
		&sess.CSRFToken,
		&sess.ExpiresAt,
		&sess.RevokedAt,
		&sess.CreatedAt,
	); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("operator session %q %w", id, ErrNotFound)
		}
		return nil, err
	}
	return &sess, nil
}

func (p *PostgresRepository) RevokeOperatorSession(ctx context.Context, id string, revokedAt time.Time) error {
	id = strings.TrimSpace(id)
	if id == "" {
		return fmt.Errorf("operator session id is required")
	}
	if revokedAt.IsZero() {
		revokedAt = time.Now().UTC()
	} else {
		revokedAt = revokedAt.UTC()
	}
	if p.pool == nil {
		return p.mem.RevokeOperatorSession(ctx, id, revokedAt)
	}
	const q = `
		UPDATE operator_sessions
		SET revoked_at = COALESCE(revoked_at, $2)
		WHERE id = $1`
	tag, err := p.pool.Exec(ctx, q, id, revokedAt)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("operator session %q %w", id, ErrNotFound)
	}
	if p.mem != nil {
		_ = p.mem.RevokeOperatorSession(ctx, id, revokedAt)
	}
	return nil
}

func (p *PostgresRepository) RevokeAllUserSessions(ctx context.Context, userID string, revokedAt time.Time) error {
	userID = strings.TrimSpace(userID)
	if userID == "" {
		return fmt.Errorf("user_id is required")
	}
	if revokedAt.IsZero() {
		revokedAt = time.Now().UTC()
	} else {
		revokedAt = revokedAt.UTC()
	}
	if p.pool == nil {
		return p.mem.RevokeAllUserSessions(ctx, userID, revokedAt)
	}
	const q = `
		UPDATE operator_sessions
		SET revoked_at = $2
		WHERE user_id = $1 AND revoked_at IS NULL`
	if _, err := p.pool.Exec(ctx, q, userID, revokedAt); err != nil {
		return err
	}
	if p.mem != nil {
		_ = p.mem.RevokeAllUserSessions(ctx, userID, revokedAt)
	}
	return nil
}
