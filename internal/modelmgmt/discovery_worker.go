package modelmgmt

import (
	"context"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/goroute-ai/ai-gateway-go/internal/adapter"
	"github.com/goroute-ai/ai-gateway-go/internal/auth"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/logger"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
	"github.com/redis/go-redis/v9"
)

// SyncReport summarizes an Automated Model Discovery run.
type SyncReport struct {
	TotalDiscovered int       `json:"total_discovered"`
	NewModels       []string  `json:"new_models"`
	UpdatedModels   []string  `json:"updated_models"`
	Errors          []string  `json:"errors,omitempty"`
	SyncedAt        time.Time `json:"synced_at"`
}

// DiscoveryWorker periodically polls upstream provider `/models` endpoints, normalizes metadata,
// and updates Layer 1 (`global_models`) without coupling discovery to customer entitlements.
type DiscoveryWorker struct {
	repo        storage.Repository
	registry    *adapter.Registry
	vault       *auth.Vault
	redis       *storage.RedisFabric
	interval    time.Duration
	autoApprove bool
	stopCh      chan struct{}
}

func NewDiscoveryWorker(repo storage.Repository, registry *adapter.Registry, vault *auth.Vault, redisFabric *storage.RedisFabric, interval time.Duration, autoApprove bool) *DiscoveryWorker {
	if interval <= 0 {
		interval = 6 * time.Hour
	}
	return &DiscoveryWorker{
		repo:        repo,
		registry:    registry,
		vault:       vault,
		redis:       redisFabric,
		interval:    interval,
		autoApprove: autoApprove,
		stopCh:      make(chan struct{}),
	}
}

func (w *DiscoveryWorker) Start(ctx context.Context) {
	ticker := time.NewTicker(w.interval)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-w.stopCh:
				return
			case <-ticker.C:
				if w.acquireLeaderLock(ctx) {
					_, _ = w.SyncNow(ctx)
				}
			}
		}
	}()
}

func (w *DiscoveryWorker) Stop() {
	select {
	case <-w.stopCh:
	default:
		close(w.stopCh)
	}
}

func (w *DiscoveryWorker) acquireLeaderLock(ctx context.Context) bool {
	if w.redis == nil || w.redis.Client() == nil {
		return true
	}
	res, err := w.redis.Execute(func(rdb redis.UniversalClient) (any, error) {
		return rdb.SetNX(ctx, "gw:lock:discovery", uuid.NewString(), 60*time.Second).Result()
	})
	if err != nil {
		return true
	}
	ok, _ := res.(bool)
	return ok
}

// SyncNow executes an immediate discovery sweep across all active provider credentials.
func (w *DiscoveryWorker) SyncNow(ctx context.Context) (*SyncReport, error) {
	report := &SyncReport{SyncedAt: time.Now().UTC()}

	existingList, _ := w.repo.ListGlobalModels(ctx)
	existingMap := make(map[string]*domain.GlobalModel, len(existingList))
	for _, m := range existingList {
		existingMap[m.ID] = m
	}

	creds, err := w.repo.ListProviderCredentials(ctx, "")
	if err != nil {
		return report, err
	}

	// Deduplicate discovery per (provider, baseURL)
	seenProviderEndpoint := make(map[string]bool)

	for _, cred := range creds {
		if !cred.IsActive {
			continue
		}
		dedupKey := string(cred.Provider) + "|" + cred.BaseURL
		if seenProviderEndpoint[dedupKey] {
			continue
		}
		seenProviderEndpoint[dedupKey] = true

		adp, err := w.registry.Get(cred.Provider)
		if err != nil {
			continue
		}

		credCopy := *cred
		if w.vault != nil {
			if dec, err := w.vault.DecryptCredential(&credCopy); err == nil {
				credCopy.DecryptedAPIKey = dec
			}
		}

		discovered, err := adp.ListModels(ctx, &credCopy)
		if err != nil {
			if gwErr, ok := err.(*domain.GatewayError); ok && gwErr.Code == "list_models_unsupported" {
				logger.InfoContext(ctx, "Provider does not support /models discovery probe; skipping automated discovery",
					slog.String("component", "model_discovery"),
					slog.String("provider", string(cred.Provider)),
				)
				continue
			}
			report.Errors = append(report.Errors, err.Error())
			logger.WarnContext(ctx, "Provider model discovery failed",
				slog.String("component", "model_discovery"),
				slog.String("provider", string(cred.Provider)),
				slog.String("base_url", cred.BaseURL),
				slog.String("error", err.Error()),
			)
			continue
		}

		for _, dm := range discovered {
			report.TotalDiscovered++
			enriched := EnrichDiscoveredModel(dm, w.autoApprove)
			if prev, exists := existingMap[enriched.ID]; exists {
				// Preserve existing pricing if already customized
				if prev.InputCostMicrosPer1M > 0 {
					enriched.InputCostMicrosPer1M = prev.InputCostMicrosPer1M
				}
				if prev.OutputCostMicrosPer1M > 0 {
					enriched.OutputCostMicrosPer1M = prev.OutputCostMicrosPer1M
				}
				enriched.LifecycleStatus = prev.LifecycleStatus
				enriched.DiscoveredAt = prev.DiscoveredAt
				report.UpdatedModels = append(report.UpdatedModels, enriched.ID)
			} else {
				report.NewModels = append(report.NewModels, enriched.ID)
				_ = w.repo.RecordAuditLog(ctx, &domain.AuditLog{
					ActorID:    "model-discovery-worker",
					Action:     "model.discovered",
					Resource:   "global_model",
					ResourceID: enriched.ID,
					Details: map[string]any{
						"provider":   enriched.Provider,
						"model_name": enriched.ModelName,
						"status":     enriched.LifecycleStatus,
					},
				})
			}
			_ = w.repo.UpsertGlobalModel(ctx, enriched)
			existingMap[enriched.ID] = enriched
		}
	}

	logger.InfoContext(ctx, "Automated model discovery cycle complete",
		slog.String("component", "model_discovery"),
		slog.Int("total_discovered", report.TotalDiscovered),
		slog.Int("new_models_count", len(report.NewModels)),
		slog.Int("updated_models_count", len(report.UpdatedModels)),
		slog.Int("errors_count", len(report.Errors)),
	)

	return report, nil
}
