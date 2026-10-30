package a2a

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"math"
	"net/http"
	"sync"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/logger"
	"github.com/goroute-ai/ai-gateway-go/internal/security/network"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
)

// OutboxWorker processes asynchronous webhook push notifications via the Transactional Outbox pattern.
type OutboxWorker struct {
	repo       storage.Repository
	httpClient *http.Client
	maxRetries int
	interval   time.Duration
	stopCh     chan struct{}
	wg         sync.WaitGroup
}

// NewOutboxWorker constructs a new OutboxWorker instance.
func NewOutboxWorker(
	repo storage.Repository,
	netPolicy *network.Policy,
	maxRetries int,
	interval time.Duration,
) *OutboxWorker {
	if maxRetries <= 0 {
		maxRetries = 5
	}
	if interval <= 0 {
		interval = 200 * time.Millisecond
	}

	client := network.NewHTTPClient(netPolicy)
	client.Timeout = 10 * time.Second

	return &OutboxWorker{
		repo:       repo,
		httpClient: client,
		maxRetries: maxRetries,
		interval:   interval,
		stopCh:     make(chan struct{}),
	}
}

// Start launches the outbox drain background daemon.
func (w *OutboxWorker) Start(ctx context.Context) {
	w.wg.Add(1)
	go w.run(ctx)
}

// Stop cleanly halts the background daemon.
func (w *OutboxWorker) Stop() {
	close(w.stopCh)
	w.wg.Wait()
}

func (w *OutboxWorker) run(ctx context.Context) {
	defer w.wg.Done()
	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-w.stopCh:
			return
		case <-ticker.C:
			w.ProcessPendingEvents(ctx)
		}
	}
}

// ProcessPendingEvents synchronously drains pending outbox events (useful for testing and deterministic batch runs).
func (w *OutboxWorker) ProcessPendingEvents(ctx context.Context) {
	events, err := w.repo.ClaimPendingA2AOutboxEvents(ctx, 50)
	if err != nil || len(events) == 0 {
		return
	}

	for _, ev := range events {
		success := w.deliverEvent(ctx, ev)
		if success {
			_ = w.repo.UpdateA2AOutboxEventStatus(ctx, ev.ID, domain.OutboxStatusSent)
		} else {
			ev.AttemptCount++
			if ev.AttemptCount >= w.maxRetries {
				logger.WarnContext(ctx, "outbox webhook dead-lettered after max retries",
					slog.String("event_id", ev.ID),
					slog.String("task_id", ev.TaskID),
					slog.String("target_url", ev.TargetURL),
					slog.Int("attempts", ev.AttemptCount),
				)
				_ = w.repo.UpdateA2AOutboxEventStatus(ctx, ev.ID, domain.OutboxStatusDeadLetter)
			} else {
				// Exponential backoff: base 100ms * 2^attempt
				backoff := time.Duration(math.Pow(2, float64(ev.AttemptCount))) * 100 * time.Millisecond
				ev.NextAttemptAt = time.Now().UTC().Add(backoff)
				_ = w.repo.UpdateA2AOutboxEventStatus(ctx, ev.ID, domain.OutboxStatusPending)
			}
		}
	}
}

func (w *OutboxWorker) deliverEvent(ctx context.Context, ev *domain.A2AOutboxEvent) bool {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ev.TargetURL, bytes.NewReader([]byte(ev.PayloadJSON)))
	if err != nil {
		return false
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Gateway-Event-Id", ev.ID)
	req.Header.Set("X-Gateway-Task-Id", ev.TaskID)
	req.Header.Set("X-Gateway-Delivery-Attempt", fmt.Sprintf("%d", ev.AttemptCount+1))
	req.Header.Set("Idempotency-Key", ev.ID)

	resp, err := w.httpClient.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	return resp.StatusCode >= 200 && resp.StatusCode < 300
}
