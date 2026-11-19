package storage

import (
	"context"
	"crypto/tls"
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
		if !postgresTLSVerifiesCertificate(cfg.ConnConfig.TLSConfig) {
			return nil, errRDSIAMVerifiedTLS
		}
		for _, fallback := range cfg.ConnConfig.Fallbacks {
			if !postgresTLSVerifiesCertificate(fallback.TLSConfig) {
				return nil, errRDSIAMVerifiedTLS
			}
		}
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

var errRDSIAMVerifiedTLS = errors.New("rds_iam: PostgreSQL requires certificate-verified TLS for every connection (use sslmode=verify-full or verify-ca)")

func postgresTLSVerifiesCertificate(cfg *tls.Config) bool {
	// pgx implements verify-ca with its own certificate chain verifier.
	return cfg != nil && (!cfg.InsecureSkipVerify || cfg.VerifyPeerCertificate != nil)
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

// HasPostgresPool reports whether the repository is backed by a live PostgreSQL connection pool.
func (p *PostgresRepository) HasPostgresPool() bool {
	return p != nil && p.pool != nil
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

// NewPostgresRepository wraps a pgxpool.Pool with Repository persistence and
// seeds the embedded global model catalog.
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
