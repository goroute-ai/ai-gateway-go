package finops_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/finops"
	"github.com/goroute-ai/ai-gateway-go/internal/ratelimit"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
)

type trackingBatchAckRepo struct {
	storage.Repository
	batchCalls  [][]string
	prunedCalls int
}

func (r *trackingBatchAckRepo) MarkSpendEventsDelivered(ctx context.Context, ids []string) error {
	cp := append([]string(nil), ids...)
	r.batchCalls = append(r.batchCalls, cp)
	if batchAck, ok := r.Repository.(storage.BatchSpendEventAckRepository); ok {
		return batchAck.MarkSpendEventsDelivered(ctx, ids)
	}
	return nil
}

func (r *trackingBatchAckRepo) CountPendingSpendEvents(ctx context.Context) (int64, error) {
	if m, ok := r.Repository.(storage.SpendOutboxMaintenanceRepository); ok {
		return m.CountPendingSpendEvents(ctx)
	}
	return 0, nil
}

func (r *trackingBatchAckRepo) PruneDeliveredSpendEvents(ctx context.Context, olderThan time.Time, limit int) (int64, error) {
	r.prunedCalls++
	return 5, nil
}

func TestSpendWorkerDeadLetterWithoutCollectorDoesNotPanic(t *testing.T) {
	mr := miniredis.RunT(t)
	deadFabric := storage.NewRedisFabric(mr.Addr(), "", 0)
	mr.Close() // force Redis failure
	deadLimiter := ratelimit.NewLimiter(deadFabric, 60, 300)

	repo := storage.NewMemoryRepository()
	ctx := context.Background()
	sw := finops.NewSpendWorker(repo, deadLimiter, config.FinOpsConfig{BatchSize: 10})
	// Intentionally do NOT call sw.SetCollector(...)

	if err := sw.Record(ctx, domain.SpendEvent{
		ID:           "ev-no-collector-1",
		RequestID:    "req-no-collector-1",
		OrgID:        "org-1",
		VirtualKeyID: "vk-1",
		CostMicros:   100,
	}); err != nil {
		t.Fatalf("Record: %v", err)
	}

	for attempt := 0; attempt < 13; attempt++ {
		_, err := repo.ClaimSpendEvents(ctx, 10, time.Minute)
		if err != nil {
			t.Fatalf("claim: %v", err)
		}
		if attempt < 12 {
			_ = repo.RetrySpendEvent(ctx, "ev-no-collector-1", errors.New("redis down"), time.Now().Add(-time.Second), 20)
		}
	}

	// Put it back to pending with attempt >= 12 so FlushNow triggers dead-letter path with collector == nil.
	_ = repo.RetrySpendEvent(ctx, "ev-no-collector-1", errors.New("redis down"), time.Now().Add(-time.Second), 20)
	_ = sw.FlushNow(ctx)

	_, deadLetters, _ := sw.OutboxMetrics()
	if deadLetters < 1 {
		t.Fatalf("expected deadLetterCount >= 1, got %d", deadLetters)
	}
}

func TestSpendWorkerBatchAckBackpressureAndRetention(t *testing.T) {
	base := storage.NewMemoryRepository()
	repo := &trackingBatchAckRepo{Repository: base}
	ctx := context.Background()

	sw := finops.NewSpendWorker(repo, nil, config.FinOpsConfig{BatchSize: 10})
	sw.SetMaxOutboxDepth(2)

	for i, id := range []string{"ev-1", "ev-2"} {
		if err := sw.Record(ctx, domain.SpendEvent{
			ID:           id,
			RequestID:    "req-" + id,
			OrgID:        "org-1",
			VirtualKeyID: "vk-1",
			CostMicros:   int64(10 * (i + 1)),
		}); err != nil {
			t.Fatalf("Record %s: %v", id, err)
		}
	}

	if err := sw.Record(ctx, domain.SpendEvent{
		ID:         "ev-3",
		RequestID:  "req-3",
		OrgID:      "org-1",
		CostMicros: 30,
	}); !errors.Is(err, finops.ErrOutboxBackpressure) {
		t.Fatalf("expected ErrOutboxBackpressure, got %v", err)
	}

	pending, _, backpressured := sw.OutboxMetrics()
	if pending != 2 || backpressured != 1 {
		t.Fatalf("unexpected metrics: pending=%d backpressured=%d", pending, backpressured)
	}

	if err := sw.FlushNow(ctx); err != nil {
		t.Fatalf("FlushNow: %v", err)
	}
	if len(repo.batchCalls) != 1 || len(repo.batchCalls[0]) != 2 {
		t.Fatalf("expected 1 batch ack call with 2 IDs, got %+v", repo.batchCalls)
	}

	pending, _, _ = sw.OutboxMetrics()
	if pending != 0 {
		t.Fatalf("expected pending=0 after flush, got %d", pending)
	}

	pruned, err := sw.PruneDeliveredOutbox(ctx, time.Now().Add(-time.Hour), 100)
	if err != nil || pruned != 5 || repo.prunedCalls != 1 {
		t.Fatalf("unexpected prune result: pruned=%d calls=%d err=%v", pruned, repo.prunedCalls, err)
	}
}
