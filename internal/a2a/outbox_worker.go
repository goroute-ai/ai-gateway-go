package a2a

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	a2aspec "github.com/goroute-ai/ai-gateway-go/internal/a2a/spec"
	"github.com/goroute-ai/ai-gateway-go/internal/auth"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/logger"
	"github.com/goroute-ai/ai-gateway-go/internal/observability"
	"github.com/goroute-ai/ai-gateway-go/internal/security/network"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
)

// OutboxWorker processes asynchronous webhook push notifications via the Transactional Outbox pattern.
type OutboxWorker struct {
	repo       storage.Repository
	vault      *auth.Vault
	httpClient *http.Client
	maxRetries int
	interval   time.Duration
	stopCh     chan struct{}
	wg         sync.WaitGroup

	pubTTL    time.Duration
	outboxTTL time.Duration
	taskTTL   time.Duration

	deliveredTotal  atomic.Int64
	deadLetterTotal atomic.Int64
	prunedTotal     atomic.Int64
}

// NewOutboxWorker constructs an OutboxWorker with Vault decryption and SSRF-hardened HTTP delivery.
func NewOutboxWorker(
	repo storage.Repository,
	vault *auth.Vault,
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
		vault:      vault,
		httpClient: client,
		maxRetries: maxRetries,
		interval:   interval,
		stopCh:     make(chan struct{}),
		pubTTL:     1 * time.Hour,
		outboxTTL:  24 * time.Hour,
		taskTTL:    24 * time.Hour,
	}
}

// SetRetentionPolicy configures TTL thresholds for periodic pruning of published stream publications,
// terminal outbox events, and terminal tasks.
func (w *OutboxWorker) SetRetentionPolicy(pubTTL, outboxTTL, taskTTL time.Duration) {
	if w == nil {
		return
	}
	w.pubTTL = pubTTL
	w.outboxTTL = outboxTTL
	w.taskTTL = taskTTL
}

// Metrics returns point-in-time outbox delivery, dead-letter, and pruned record counters.
func (w *OutboxWorker) Metrics() (delivered, deadLetter, pruned int64) {
	if w == nil {
		return 0, 0, 0
	}
	return w.deliveredTotal.Load(), w.deadLetterTotal.Load(), w.prunedTotal.Load()
}

// PruneExpired invokes repository TTL cleanup for published stream rows, terminal outbox rows,
// and terminal tasks relative to `now`, updating the cumulative pruned counter.
func (w *OutboxWorker) PruneExpired(ctx context.Context, now time.Time) (int64, error) {
	if w == nil || w.repo == nil {
		return 0, nil
	}
	var pubBefore, outboxBefore, taskBefore time.Time
	if w.pubTTL > 0 {
		pubBefore = now.Add(-w.pubTTL)
	}
	if w.outboxTTL > 0 {
		outboxBefore = now.Add(-w.outboxTTL)
	}
	if w.taskTTL > 0 {
		taskBefore = now.Add(-w.taskTTL)
	}
	n, err := w.repo.PruneExpiredA2ARecords(ctx, pubBefore, outboxBefore, taskBefore)
	if n > 0 {
		w.prunedTotal.Add(n)
	}
	return n, err
}

// Start launches the outbox drain background daemon.
func (w *OutboxWorker) Start(ctx context.Context) {
	w.wg.Add(1)
	go w.run(ctx)
}

// Stop cleanly drains and halts the background daemon.
func (w *OutboxWorker) Stop() {
	close(w.stopCh)
	w.wg.Wait()
}

func (w *OutboxWorker) run(ctx context.Context) {
	defer w.wg.Done()
	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()

	var ticks int64
	for {
		select {
		case <-ctx.Done():
			return
		case <-w.stopCh:
			return
		case <-ticker.C:
			w.ProcessPendingEvents(ctx)
			ticks++
			if ticks%300 == 0 {
				_, _ = w.PruneExpired(ctx, time.Now().UTC())
			}
		}
	}
}

// ProcessPendingEvents synchronously drains pending outbox events with persisted exponential backoff & DLQ.
func (w *OutboxWorker) ProcessPendingEvents(ctx context.Context) {
	events, err := w.repo.ClaimPendingA2AOutboxEvents(ctx, 50)
	if err != nil || len(events) == 0 {
		return
	}

	for _, ev := range events {
		deliveryErr := w.deliverEvent(ctx, ev)
		if deliveryErr == nil {
			ev.Status = domain.OutboxStatusSent
			ev.LastError = ""
			_ = w.repo.UpdateA2AOutboxEvent(ctx, ev)
			w.deliveredTotal.Add(1)
			continue
		}

		if ev.AttemptCount == 0 {
			ev.AttemptCount = 1
		}
		ev.LastError = deliveryErr.Error()
		if ev.AttemptCount >= w.maxRetries {
			logger.WarnContext(ctx, "outbox webhook dead-lettered after max retries",
				slog.String("event_id", ev.ID),
				slog.String("task_id", ev.TaskID),
				slog.String("target_url", ev.TargetURL),
				slog.Int("attempts", ev.AttemptCount),
				slog.String("error", ev.LastError),
			)
			ev.Status = domain.OutboxStatusDeadLetter
			w.deadLetterTotal.Add(1)
		} else {
			// Exponential backoff: 100ms * 2^attempt (capped cleanly within reasonable bounds)
			shift := min(ev.AttemptCount, 10)
			backoff := time.Duration(1<<shift) * 100 * time.Millisecond
			ev.NextAttemptAt = time.Now().UTC().Add(backoff)
			ev.Status = domain.OutboxStatusPending
		}
		_ = w.repo.UpdateA2AOutboxEvent(ctx, ev)
	}
}

func (w *OutboxWorker) deliverEvent(ctx context.Context, ev *domain.A2AOutboxEvent) error {
	payload := strings.TrimSpace(ev.PayloadJSON)
	if !json.Valid([]byte(payload)) {
		b, _ := json.Marshal(payload)
		payload = string(b)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ev.TargetURL, strings.NewReader(payload))
	if err != nil {
		return fmt.Errorf("build webhook request: %w", err)
	}

	req.Header.Set("Content-Type", MediaTypeA2AJSON)
	req.Header.Set(HeaderA2AVersion, a2aspec.SupportedA2AVersion)
	req.Header.Set("X-Gateway-Event-Id", ev.ID)
	req.Header.Set("X-Gateway-Task-Id", ev.TaskID)
	req.Header.Set("X-Gateway-Delivery-Attempt", fmt.Sprintf("%d", ev.AttemptCount))
	req.Header.Set("Idempotency-Key", ev.ID)

	w.attachPushAuthHeaders(ctx, ev, req)
	observability.InjectTraceHeaders(ctx, req)

	resp, err := w.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned HTTP %d", resp.StatusCode)
	}
	return nil
}

func (w *OutboxWorker) attachPushAuthHeaders(ctx context.Context, ev *domain.A2AOutboxEvent, req *http.Request) {
	if w.repo == nil || ev == nil || ev.TaskID == "" {
		return
	}
	cfg, err := w.repo.GetA2APushNotificationConfig(ctx, ev.TaskID, ev.PushConfigID)
	if err != nil || cfg == nil {
		return
	}

	if tok := strings.TrimSpace(cfg.Token); tok != "" {
		req.Header.Set("X-A2A-Notification-Token", tok)
	}

	scheme := strings.TrimSpace(cfg.AuthScheme)
	if scheme == "" {
		scheme = "Bearer"
	}

	creds := ""
	if cfg.EncryptedAuthCreds != "" && cfg.EncryptedAuthDEK != "" && w.vault != nil {
		if plain, decErr := w.vault.DecryptString(cfg.EncryptedAuthCreds, cfg.EncryptedAuthDEK); decErr == nil {
			creds = strings.TrimSpace(plain)
		}
	}
	// Legacy packed format: "vault:<cipher>:<dek>"
	if creds == "" && strings.HasPrefix(cfg.AuthToken, "vault:") && w.vault != nil {
		parts := strings.SplitN(cfg.AuthToken, ":", 3)
		if len(parts) == 3 {
			if plain, decErr := w.vault.DecryptString(parts[1], parts[2]); decErr == nil {
				creds = strings.TrimSpace(plain)
			}
		}
	} else if creds == "" && cfg.AuthToken != "" && !strings.HasPrefix(cfg.AuthToken, "vault:") {
		creds = strings.TrimSpace(cfg.AuthToken)
	}

	if creds != "" {
		req.Header.Set("Authorization", scheme+" "+creds)
	}
}
