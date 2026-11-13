package finops

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/logger"
	"github.com/goroute-ai/ai-gateway-go/internal/observability"
	"github.com/goroute-ai/ai-gateway-go/internal/ratelimit"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
)

// SpendWorker commits events to the repository outbox before callers report success,
// then retries ledger delivery from that durable queue.
type SpendWorker struct {
	repo      storage.Repository
	limiter   *ratelimit.Limiter
	collector *observability.Collector
	cfg       config.FinOpsConfig
	notify    chan struct{}
	wg        sync.WaitGroup
	stopOnce  sync.Once
	stopCh    chan struct{}
}

func NewSpendWorker(repo storage.Repository, limiter *ratelimit.Limiter, cfg config.FinOpsConfig) *SpendWorker {
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = 250
	}
	if cfg.FlushInterval <= 0 {
		cfg.FlushInterval = 500 * time.Millisecond
	}
	return &SpendWorker{repo: repo, limiter: limiter, cfg: cfg, notify: make(chan struct{}, 1), stopCh: make(chan struct{})}
}

// SetCollector attaches an observability collector for reporting Redis spend drift metrics.
func (sw *SpendWorker) SetCollector(collector *observability.Collector) {
	sw.collector = collector
}

func (sw *SpendWorker) Start(ctx context.Context) { sw.wg.Add(1); go sw.runBatchLoop(ctx) }

// Record durably commits the event to the repository outbox before returning nil.
func (sw *SpendWorker) Record(ctx context.Context, ev domain.SpendEvent) error {
	if ev.ID == "" {
		ev.ID = uuid.NewString()
	}
	if ev.CreatedAt.IsZero() {
		ev.CreatedAt = time.Now().UTC()
	}
	if err := sw.repo.EnqueueSpendEvent(ctx, ev); err != nil {
		logger.Error("Failed to persist FinOps spend outbox event", slog.String("component", "finops"), slog.String("event_id", ev.ID), slog.String("error", err.Error()))
		return err
	}
	if sw.limiter != nil && ev.CostMicros > 0 {
		if err := sw.limiter.RecordSpendIncrementForEvent(context.Background(), ev.ID, ev.RequestID, ev.VirtualKeyID, ev.TeamID, ev.OrgID, ev.CostMicros); err != nil {
			logger.Warn("Immediate Redis spend increment failed; outbox will retry", slog.String("component", "finops"), slog.String("event_id", ev.ID), slog.String("error", err.Error()))
		}
	} else if sw.limiter != nil && ev.RequestID != "" {
		// A zero-cost success (for example a cache hit) still releases its reservation.
		if err := sw.limiter.RecordSpendIncrementForEvent(context.Background(), ev.ID, ev.RequestID, ev.VirtualKeyID, ev.TeamID, ev.OrgID, 0); err != nil {
			logger.Warn("Immediate Redis reservation release failed; outbox will retry", slog.String("component", "finops"), slog.String("event_id", ev.ID), slog.String("error", err.Error()))
		}
	}
	select {
	case sw.notify <- struct{}{}:
	default:
	}
	return nil
}

func (sw *SpendWorker) FlushNow(ctx context.Context) error { return sw.process(ctx) }

func (sw *SpendWorker) Stop(ctx context.Context) {
	sw.stopOnce.Do(func() { close(sw.stopCh) })
	done := make(chan struct{})
	go func() { sw.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-ctx.Done():
	}
}

func (sw *SpendWorker) runBatchLoop(ctx context.Context) {
	defer sw.wg.Done()
	ticker := time.NewTicker(sw.cfg.FlushInterval)
	defer ticker.Stop()
	resetTicker := time.NewTicker(time.Minute)
	defer resetTicker.Stop()
	for {
		select {
		case <-ctx.Done():
			_ = sw.process(context.Background())
			return
		case <-sw.stopCh:
			_ = sw.process(context.Background())
			return
		case <-sw.notify:
			if err := sw.process(ctx); err != nil {
				logger.Warn("FinOps outbox delivery will retry", slog.String("component", "finops"), slog.String("error", err.Error()))
			}
		case <-ticker.C:
			if err := sw.process(ctx); err != nil {
				logger.Warn("FinOps outbox delivery will retry", slog.String("component", "finops"), slog.String("error", err.Error()))
			}
		case <-resetTicker.C:
			if count, err := sw.ResetExpiredBudgetsNow(ctx, time.Now().UTC()); err != nil {
				logger.Error("FinOps budget reset cycle failed", slog.String("component", "finops"), slog.String("error", err.Error()))
			} else if count > 0 {
				logger.Info("FinOps expired budgets reset", slog.String("component", "finops"), slog.Int("count", count))
			}
		}
	}
}

// ResetExpiredBudgetsNow resets expired budgets in the repository and clears
// the corresponding live Redis spend counters when a limiter is configured.
func (sw *SpendWorker) ResetExpiredBudgetsNow(ctx context.Context, now time.Time) (int, error) {
	resetCount := 0
	if withIDs, ok := sw.repo.(storage.BudgetResetWithIDsRepository); ok {
		res, err := withIDs.ResetExpiredBudgetsWithIDs(ctx, now)
		if err != nil {
			return 0, err
		}
		resetCount = res.Total()
	} else {
		count, err := sw.repo.ResetExpiredBudgets(ctx, now)
		if err != nil {
			return 0, err
		}
		resetCount = count
	}
	if outbox, ok := sw.repo.(storage.BudgetResetOutboxRepository); ok {
		pending, err := outbox.ListPendingBudgetResets(ctx, sw.cfg.BatchSize)
		if err != nil {
			return resetCount, err
		}
		if sw.limiter != nil {
			if err := sw.limiter.ResetSpendCounters(ctx, pending); err != nil {
				logger.Warn("Redis budget counter reset remains pending", slog.String("component", "finops"), slog.String("error", err.Error()))
				return resetCount, err
			}
		}
		ids := make([]string, 0, len(pending))
		for _, event := range pending {
			ids = append(ids, event.ID)
		}
		if err := outbox.MarkBudgetResetsDelivered(ctx, ids); err != nil {
			return resetCount, err
		}
	}
	return resetCount, nil
}

func (sw *SpendWorker) process(ctx context.Context) error {
	var firstErr error
	for {
		events, err := sw.repo.ClaimSpendEvents(ctx, sw.cfg.BatchSize, time.Minute)
		if err != nil {
			return err
		}
		if len(events) == 0 {
			return firstErr
		}
		if err := sw.repo.RecordSpendBatch(ctx, events); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			for _, ev := range events {
				attempt := ev.OutboxAttempt
				delay := time.Second << min(attempt, 8)
				if retryErr := sw.repo.RetrySpendEvent(ctx, ev.ID, err, time.Now().Add(delay), 12); retryErr != nil && firstErr == nil {
					firstErr = retryErr
				}
				if attempt >= 12 {
					logger.Error("FinOps spend event moved to dead-letter state", slog.String("component", "finops"), slog.String("event_id", ev.ID), slog.Int("attempts", attempt), slog.String("error", err.Error()))
				}
			}
			return firstErr
		}
		for _, ev := range events {
			if sw.limiter != nil && (ev.CostMicros > 0 || ev.RequestID != "") {
				cost := ev.CostMicros
				if cost < 0 {
					cost = 0
				}
				if err := sw.limiter.RecordSpendIncrementForEvent(ctx, ev.ID, ev.RequestID, ev.VirtualKeyID, ev.TeamID, ev.OrgID, cost); err != nil {
					if firstErr == nil {
						firstErr = err
					}
					attempt := ev.OutboxAttempt
					delay := time.Second << min(attempt, 8)
					if retryErr := sw.repo.RetrySpendEvent(ctx, ev.ID, err, time.Now().Add(delay), 12); retryErr != nil && firstErr == nil {
						firstErr = retryErr
					}
					if attempt >= 12 {
						sw.collector.RecordSpendRedisDrift()
						logger.Error("FinOps Redis spend reconciliation moved to dead-letter state", slog.String("component", "finops"), slog.String("event_id", ev.ID), slog.Int("attempts", attempt), slog.String("error", err.Error()))
					}
					continue
				}
			}
			if err := sw.repo.MarkSpendEventDelivered(ctx, ev.ID); err != nil {
				if firstErr == nil {
					firstErr = err
				}
				logger.Error("Failed to acknowledge delivered FinOps event", slog.String("component", "finops"), slog.String("event_id", ev.ID), slog.String("error", err.Error()))
			}
		}
	}
}
