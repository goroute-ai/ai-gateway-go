package finops

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/logger"
	"github.com/goroute-ai/ai-gateway-go/internal/observability"
	"github.com/goroute-ai/ai-gateway-go/internal/ratelimit"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
)

const (
	defaultRedisSettleTimeout = 2 * time.Second
	defaultOutboxRetention    = 24 * time.Hour
	defaultRetentionInterval  = 10 * time.Minute
	defaultRetentionBatchSize = 1000
)

// ErrOutboxBackpressure is returned by Record when the pending spend outbox
// exceeds the configured high-watermark.
var ErrOutboxBackpressure = errors.New("finops spend outbox backpressure limit exceeded")

// DeploymentSpendRecorder settles per-deployment and per-provider spend
// alongside tenant-level FinOps accounting.
type DeploymentSpendRecorder interface {
	RecordSpend(ctx context.Context, orgID, depID, provider, period string, costMicros int64)
}

// DeploymentBudgetHook is an alias for DeploymentSpendRecorder.
type DeploymentBudgetHook = DeploymentSpendRecorder

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

	hookMu               sync.RWMutex
	deploymentBudgetHook DeploymentSpendRecorder
	softBudgetNotifier   *SoftBudgetNotifier

	maxOutboxDepth     int64
	pendingOutboxDepth atomic.Int64
	deadLetterCount    atomic.Int64
	backpressureCount  atomic.Int64
}

func NewSpendWorker(repo storage.Repository, limiter *ratelimit.Limiter, cfg config.FinOpsConfig) *SpendWorker {
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = 250
	}
	if cfg.FlushInterval <= 0 {
		cfg.FlushInterval = 500 * time.Millisecond
	}
	return &SpendWorker{
		repo:           repo,
		limiter:        limiter,
		cfg:            cfg,
		notify:         make(chan struct{}, 1),
		stopCh:         make(chan struct{}),
		maxOutboxDepth: int64(cfg.ChannelBufferSize),
	}
}

// SetCollector attaches an observability collector for reporting Redis spend drift metrics.
func (sw *SpendWorker) SetCollector(collector *observability.Collector) {
	sw.collector = collector
}

// SetDeploymentSpendRecorder attaches an optional hook that settles per-deployment
// and per-provider spend alongside tenant spend.
func (sw *SpendWorker) SetDeploymentSpendRecorder(recorder DeploymentSpendRecorder) {
	sw.hookMu.Lock()
	sw.deploymentBudgetHook = recorder
	sw.hookMu.Unlock()
}

// SetDeploymentBudgetHook attaches an optional DeploymentBudgetHook.
func (sw *SpendWorker) SetDeploymentBudgetHook(hook DeploymentBudgetHook) {
	sw.SetDeploymentSpendRecorder(hook)
}

// SetSoftBudgetNotifier attaches an optional SoftBudgetNotifier invoked after spend settlement.
func (sw *SpendWorker) SetSoftBudgetNotifier(notifier *SoftBudgetNotifier) {
	sw.hookMu.Lock()
	sw.softBudgetNotifier = notifier
	sw.hookMu.Unlock()
}

func (sw *SpendWorker) getSoftBudgetNotifier() *SoftBudgetNotifier {
	sw.hookMu.RLock()
	notifier := sw.softBudgetNotifier
	sw.hookMu.RUnlock()
	return notifier
}

// SetMaxOutboxDepth configures the pending outbox high-watermark for backpressure.
// A non-positive value disables backpressure rejection.
func (sw *SpendWorker) SetMaxOutboxDepth(limit int64) {
	sw.maxOutboxDepth = limit
}

// OutboxMetrics returns current pending outbox depth, cumulative dead-letter events,
// and cumulative backpressure rejections.
func (sw *SpendWorker) OutboxMetrics() (pendingDepth, deadLetterTotal, backpressureTotal int64) {
	return sw.pendingOutboxDepth.Load(), sw.deadLetterCount.Load(), sw.backpressureCount.Load()
}

func (sw *SpendWorker) Start(ctx context.Context) { sw.wg.Add(1); go sw.runBatchLoop(ctx) }

// Record durably commits the event to the repository outbox before returning nil.
func (sw *SpendWorker) Record(ctx context.Context, ev domain.SpendEvent) error {
	if sw.maxOutboxDepth > 0 && sw.pendingOutboxDepth.Load() >= sw.maxOutboxDepth {
		sw.backpressureCount.Add(1)
		select {
		case sw.notify <- struct{}{}:
		default:
		}
		return ErrOutboxBackpressure
	}
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
	sw.pendingOutboxDepth.Add(1)

	if sw.limiter != nil && (ev.CostMicros > 0 || ev.RequestID != "") {
		cost := ev.CostMicros
		if cost < 0 {
			cost = 0
		}
		redisCtx, cancel := context.WithTimeout(context.Background(), defaultRedisSettleTimeout)
		defer cancel()
		if err := sw.limiter.RecordSpendIncrementForUserEvent(redisCtx, ev.ID, ev.RequestID, ev.VirtualKeyID, ev.TeamID, ev.UserID, ev.OrgID, cost); err != nil {
			logger.Warn("Immediate Redis spend settlement failed; outbox will retry", slog.String("component", "finops"), slog.String("event_id", ev.ID), slog.String("error", err.Error()))
		}
	}
	sw.hookMu.RLock()
	hook := sw.deploymentBudgetHook
	sw.hookMu.RUnlock()
	if hook != nil && (ev.DeploymentID != "" || ev.Provider != "") {
		cost := ev.CostMicros
		if cost < 0 {
			cost = 0
		}
		hookCtx, cancel := context.WithTimeout(context.Background(), defaultRedisSettleTimeout)
		defer cancel()
		hook.RecordSpend(hookCtx, ev.OrgID, ev.DeploymentID, string(ev.Provider), "", cost)
	}
	select {
	case sw.notify <- struct{}{}:
	default:
	}
	return nil
}

func (sw *SpendWorker) FlushNow(ctx context.Context) error { return sw.process(ctx) }

// PruneDeliveredOutbox deletes delivered outbox rows older than olderThan.
func (sw *SpendWorker) PruneDeliveredOutbox(ctx context.Context, olderThan time.Time, limit int) (int64, error) {
	maint, ok := sw.repo.(storage.SpendOutboxMaintenanceRepository)
	if !ok {
		return 0, nil
	}
	return maint.PruneDeliveredSpendEvents(ctx, olderThan, limit)
}

func (sw *SpendWorker) Stop(ctx context.Context) {
	sw.stopOnce.Do(func() { close(sw.stopCh) })
	done := make(chan struct{})
	go func() { sw.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-ctx.Done():
	}
	if notifier := sw.getSoftBudgetNotifier(); notifier != nil {
		_ = notifier.Wait(ctx)
	}
}

func (sw *SpendWorker) runBatchLoop(ctx context.Context) {
	defer sw.wg.Done()
	ticker := time.NewTicker(sw.cfg.FlushInterval)
	defer ticker.Stop()
	resetTicker := time.NewTicker(time.Minute)
	defer resetTicker.Stop()
	retentionTicker := time.NewTicker(defaultRetentionInterval)
	defer retentionTicker.Stop()
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
		case <-retentionTicker.C:
			if pruned, err := sw.PruneDeliveredOutbox(ctx, time.Now().UTC().Add(-defaultOutboxRetention), defaultRetentionBatchSize); err != nil {
				logger.Warn("FinOps outbox retention cleanup failed", slog.String("component", "finops"), slog.String("error", err.Error()))
			} else if pruned > 0 {
				logger.Info("FinOps delivered outbox rows pruned", slog.String("component", "finops"), slog.Int64("pruned", pruned))
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
		notifier := sw.getSoftBudgetNotifier()
		for _, event := range pending {
			ids = append(ids, event.ID)
			if notifier != nil {
				notifier.ClearCooldown(ctx, event.OrgID, event.Scope, event.EntityID, string(domain.BudgetResetDaily))
				notifier.ClearCooldown(ctx, event.OrgID, event.Scope, event.EntityID, string(domain.BudgetResetMonthly))
			}
		}
		if err := outbox.MarkBudgetResetsDelivered(ctx, ids); err != nil {
			return resetCount, err
		}
	}
	return resetCount, nil
}

func (sw *SpendWorker) refreshOutboxDepth(ctx context.Context) {
	if maint, ok := sw.repo.(storage.SpendOutboxMaintenanceRepository); ok {
		if depth, err := maint.CountPendingSpendEvents(ctx); err == nil {
			sw.pendingOutboxDepth.Store(depth)
		}
	}
}

func (sw *SpendWorker) markDeliveredBatch(ctx context.Context, ids []string) error {
	if len(ids) == 0 {
		return nil
	}
	if batchAck, ok := sw.repo.(storage.BatchSpendEventAckRepository); ok {
		return batchAck.MarkSpendEventsDelivered(ctx, ids)
	}
	var firstErr error
	for _, id := range ids {
		if err := sw.repo.MarkSpendEventDelivered(ctx, id); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func (sw *SpendWorker) process(ctx context.Context) error {
	defer sw.refreshOutboxDepth(ctx)
	var firstErr error
	for {
		events, err := sw.repo.ClaimSpendEvents(ctx, sw.cfg.BatchSize, time.Minute)
		if err != nil {
			return err
		}
		if len(events) == 0 {
			return firstErr
		}
		if notifier := sw.getSoftBudgetNotifier(); notifier != nil {
			notifier.CheckAndNotifyForEvents(ctx, events)
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
					sw.deadLetterCount.Add(1)
					logger.Error("FinOps spend event moved to dead-letter state", slog.String("component", "finops"), slog.String("event_id", ev.ID), slog.Int("attempts", attempt), slog.String("error", err.Error()))
				}
			}
			return firstErr
		}
		if notifier := sw.getSoftBudgetNotifier(); notifier != nil {
			notifier.CheckAndNotifyForEvents(ctx, events)
		}

		var redisErrs []error
		if sw.limiter != nil {
			batch := make([]ratelimit.SpendIncrementEvent, len(events))
			for i, ev := range events {
				cost := ev.CostMicros
				if cost < 0 {
					cost = 0
				}
				batch[i] = ratelimit.SpendIncrementEvent{
					EventID:      ev.ID,
					RequestID:    ev.RequestID,
					VirtualKeyID: ev.VirtualKeyID,
					TeamID:       ev.TeamID,
					UserID:       ev.UserID,
					OrgID:        ev.OrgID,
					CostMicros:   cost,
				}
			}
			redisErrs = sw.limiter.RecordSpendIncrementsBatch(ctx, batch)
		}

		deliveredIDs := make([]string, 0, len(events))
		for i, ev := range events {
			if sw.limiter != nil && (ev.CostMicros > 0 || ev.RequestID != "") && i < len(redisErrs) && redisErrs[i] != nil {
				err := redisErrs[i]
				if firstErr == nil {
					firstErr = err
				}
				attempt := ev.OutboxAttempt
				delay := time.Second << min(attempt, 8)
				if retryErr := sw.repo.RetrySpendEvent(ctx, ev.ID, err, time.Now().Add(delay), 12); retryErr != nil && firstErr == nil {
					firstErr = retryErr
				}
				if attempt >= 12 {
					sw.deadLetterCount.Add(1)
					if sw.collector != nil {
						sw.collector.RecordSpendRedisDrift()
					}
					logger.Error("FinOps Redis spend reconciliation moved to dead-letter state", slog.String("component", "finops"), slog.String("event_id", ev.ID), slog.Int("attempts", attempt), slog.String("error", err.Error()))
				}
				continue
			}
			deliveredIDs = append(deliveredIDs, ev.ID)
		}

		if err := sw.markDeliveredBatch(ctx, deliveredIDs); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			logger.Error("Failed to acknowledge delivered FinOps events", slog.String("component", "finops"), slog.Int("count", len(deliveredIDs)), slog.String("error", err.Error()))
		}
	}
}
