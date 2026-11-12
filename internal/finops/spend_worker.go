package finops

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/logger"
	"github.com/goroute-ai/ai-gateway-go/internal/ratelimit"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
)

// SpendWorker processes inference SpendEvents asynchronously off the hot path.
// It updates Redis spend counters immediately and batches durable writes to the repository.
type SpendWorker struct {
	repo       storage.Repository
	limiter    *ratelimit.Limiter
	cfg        config.FinOpsConfig
	ch         chan domain.SpendEvent
	flushReqCh chan chan error
	wg         sync.WaitGroup
	stopOnce   sync.Once
	stopCh     chan struct{}
}

func NewSpendWorker(repo storage.Repository, limiter *ratelimit.Limiter, cfg config.FinOpsConfig) *SpendWorker {
	if cfg.ChannelBufferSize <= 0 {
		cfg.ChannelBufferSize = 16384
	}
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = 250
	}
	if cfg.FlushInterval <= 0 {
		cfg.FlushInterval = 500 * time.Millisecond
	}
	return &SpendWorker{
		repo:       repo,
		limiter:    limiter,
		cfg:        cfg,
		ch:         make(chan domain.SpendEvent, cfg.ChannelBufferSize),
		flushReqCh: make(chan chan error),
		stopCh:     make(chan struct{}),
	}
}

// Start launches the background batch writer and budget reset loop.
func (sw *SpendWorker) Start(ctx context.Context) {
	sw.wg.Add(1)
	go sw.runBatchLoop(ctx)
}

// Enqueue pushes a SpendEvent without blocking the HTTP response path.
func (sw *SpendWorker) Enqueue(ev domain.SpendEvent) {
	if sw.limiter != nil && ev.CostMicros > 0 {
		sw.limiter.RecordSpendIncrementForRequest(context.Background(), ev.RequestID, ev.VirtualKeyID, ev.TeamID, ev.OrgID, ev.CostMicros)
	} else if sw.limiter != nil && ev.RequestID != "" {
		// A zero-cost success (for example a cache hit) still releases its reservation.
		sw.limiter.RecordSpendIncrementForRequest(context.Background(), ev.RequestID, ev.VirtualKeyID, ev.TeamID, ev.OrgID, 0)
	}
	select {
	case sw.ch <- ev:
	default:
		// If channel is full under extreme backpressure, flush synchronously to prevent financial data loss
		logger.Warn("FinOps spend channel queue saturated; synchronous fallback write executed",
			slog.String("component", "finops"),
			slog.String("virtual_key_id", ev.VirtualKeyID),
			slog.String("org_id", ev.OrgID),
			slog.Int64("cost_micros", ev.CostMicros),
		)
		_ = sw.repo.RecordSpendBatch(context.Background(), []domain.SpendEvent{ev})
	}
}

// FlushNow signals the background batch loop to drain both the channel and its in-memory batch buffer synchronously.
func (sw *SpendWorker) FlushNow(ctx context.Context) error {
	done := make(chan error, 1)
	select {
	case sw.flushReqCh <- done:
		select {
		case err := <-done:
			return err
		case <-ctx.Done():
			return ctx.Err()
		}
	case <-sw.stopCh:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Stop signals the background worker to drain remaining events and wait for completion.
func (sw *SpendWorker) Stop(ctx context.Context) {
	sw.stopOnce.Do(func() {
		close(sw.stopCh)
	})
	sw.wg.Wait()
}

func (sw *SpendWorker) runBatchLoop(ctx context.Context) {
	defer sw.wg.Done()

	flushTicker := time.NewTicker(sw.cfg.FlushInterval)
	defer flushTicker.Stop()

	resetTicker := time.NewTicker(1 * time.Minute)
	defer resetTicker.Stop()

	batch := make([]domain.SpendEvent, 0, sw.cfg.BatchSize)

	drainAndFlush := func() error {
		for {
			select {
			case ev := <-sw.ch:
				batch = append(batch, ev)
			default:
				if len(batch) == 0 {
					return nil
				}
				err := sw.repo.RecordSpendBatch(context.Background(), batch)
				if err != nil {
					logger.Error("Failed to persist FinOps spend batch",
						slog.String("component", "finops"),
						slog.Int("batch_size", len(batch)),
						slog.String("error", err.Error()),
					)
				}
				batch = batch[:0]
				return err
			}
		}
	}

	for {
		select {
		case <-ctx.Done():
			_ = drainAndFlush()
			return
		case <-sw.stopCh:
			_ = drainAndFlush()
			return
		case done := <-sw.flushReqCh:
			done <- drainAndFlush()
		case ev := <-sw.ch:
			batch = append(batch, ev)
			if len(batch) >= sw.cfg.BatchSize {
				if err := sw.repo.RecordSpendBatch(context.Background(), batch); err != nil {
					logger.Error("Failed to persist FinOps spend batch",
						slog.String("component", "finops"),
						slog.Int("batch_size", len(batch)),
						slog.String("error", err.Error()),
					)
				}
				batch = batch[:0]
			}
		case <-flushTicker.C:
			if len(batch) > 0 {
				if err := sw.repo.RecordSpendBatch(context.Background(), batch); err != nil {
					logger.Error("Failed to persist FinOps spend batch",
						slog.String("component", "finops"),
						slog.Int("batch_size", len(batch)),
						slog.String("error", err.Error()),
					)
				}
				batch = batch[:0]
			}
		case <-resetTicker.C:
			if count, err := sw.repo.ResetExpiredBudgets(context.Background(), time.Now().UTC()); err != nil {
				logger.Error("FinOps budget reset cycle failed",
					slog.String("component", "finops"),
					slog.String("error", err.Error()),
				)
			} else if count > 0 {
				logger.Info("FinOps expired budgets reset",
					slog.String("component", "finops"),
					slog.Int("count", count),
				)
			}
		}
	}
}
