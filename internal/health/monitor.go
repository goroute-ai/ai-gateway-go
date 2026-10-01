package health

import (
	"context"
	"log/slog"
	"sort"
	"sync"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/adapter"
	"github.com/goroute-ai/ai-gateway-go/internal/auth"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/logger"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
)

// HealthState represents the active probe health of a deployment.
type HealthState string

const (
	StateHealthy   HealthState = "healthy"
	StateDegraded  HealthState = "degraded"
	StateUnhealthy HealthState = "unhealthy"
)

// DeploymentHealthReport captures the active health check status of a deployment.
type DeploymentHealthReport struct {
	DeploymentID        string      `json:"deployment_id"`
	DeploymentName      string      `json:"deployment_name"`
	Provider            string      `json:"provider"`
	Model               string      `json:"model"`
	Status              HealthState `json:"status"`
	ConsecutiveFailures int         `json:"consecutive_failures"`
	ProbeLatencyMs      int64       `json:"probe_latency_ms"`
	LastError           string      `json:"last_error,omitempty"`
	LastCheckedAt       time.Time   `json:"last_checked_at"`
}

// Monitor executes active background health probes against configured deployments
// so unhealthy upstreams are detected and isolated before receiving live inference traffic.
type Monitor struct {
	repo         storage.Repository
	registry     *adapter.Registry
	vault        *auth.Vault
	interval     time.Duration
	probeTimeout time.Duration
	mu           sync.RWMutex
	reports      map[string]*DeploymentHealthReport
	stopCh       chan struct{}
	stopOnce     sync.Once
}

func NewMonitor(repo storage.Repository, registry *adapter.Registry, vault *auth.Vault, interval, probeTimeout time.Duration) *Monitor {
	if interval <= 0 {
		interval = 30 * time.Second
	}
	if probeTimeout <= 0 {
		probeTimeout = 5 * time.Second
	}
	return &Monitor{
		repo:         repo,
		registry:     registry,
		vault:        vault,
		interval:     interval,
		probeTimeout: probeTimeout,
		reports:      make(map[string]*DeploymentHealthReport),
		stopCh:       make(chan struct{}),
	}
}

func (m *Monitor) Start(ctx context.Context) {
	ticker := time.NewTicker(m.interval)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-m.stopCh:
				return
			case <-ticker.C:
				_, _ = m.ProbeAllNow(ctx)
			}
		}
	}()
}

func (m *Monitor) Stop() {
	m.stopOnce.Do(func() {
		close(m.stopCh)
	})
}

// IsHealthy returns false if active background probing has marked the deployment unhealthy.
// Deployments that have not yet been probed default to healthy.
func (m *Monitor) IsHealthy(depID string) bool {
	if m == nil {
		return true
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	rep, ok := m.reports[depID]
	if !ok {
		return true
	}
	return rep.Status != StateUnhealthy
}

// GetReports returns all deployment health reports sorted by deployment ID.
func (m *Monitor) GetReports() []DeploymentHealthReport {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]DeploymentHealthReport, 0, len(m.reports))
	for _, r := range m.reports {
		out = append(out, *r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].DeploymentID < out[j].DeploymentID })
	return out
}

type credProbeOutcome struct {
	err       error
	latencyMs int64
}

// ProbeAllNow executes an immediate health check sweep across all active deployments.
func (m *Monitor) ProbeAllNow(ctx context.Context) ([]DeploymentHealthReport, error) {
	deps, err := m.repo.ListAllDeployments(ctx)
	if err != nil {
		return nil, err
	}

	credResults := make(map[string]credProbeOutcome)
	now := time.Now().UTC()

	for _, dep := range deps {
		if dep.Status == domain.DeploymentStatusDisabled || dep.GlobalModel == nil || dep.Credential == nil {
			continue
		}

		// Check if credential is expired
		if dep.Credential.ExpiresAt != nil && !now.Before(*dep.Credential.ExpiresAt) {
			m.recordOutcome(dep, 0, &domain.GatewayError{
				StatusCode: 401,
				Code:       "credential_expired",
				Message:    "provider credential has expired",
			})
			continue
		}

		outcome, cached := credResults[dep.CredentialID]
		if !cached {
			credCopy := *dep.Credential
			if m.vault != nil {
				if dec, err := m.vault.DecryptCredential(&credCopy); err == nil {
					credCopy.DecryptedAPIKey = dec
				}
			}
			adp, err := m.registry.Get(dep.GlobalModel.Provider)
			if err != nil {
				outcome = credProbeOutcome{err: err}
			} else {
				pCtx, cancel := context.WithTimeout(ctx, m.probeTimeout)
				start := time.Now()
				_, pErr := adp.ListModels(pCtx, &credCopy)
				lat := time.Since(start).Milliseconds()
				cancel()
				outcome = credProbeOutcome{err: pErr, latencyMs: lat}
			}
			credResults[dep.CredentialID] = outcome
		}

		m.recordOutcome(dep, outcome.latencyMs, outcome.err)
	}

	return m.GetReports(), nil
}

func (m *Monitor) recordOutcome(dep *domain.Deployment, latencyMs int64, probeErr error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	rep, exists := m.reports[dep.ID]
	if !exists {
		rep = &DeploymentHealthReport{
			DeploymentID:   dep.ID,
			DeploymentName: dep.DeploymentName,
			Provider:       string(dep.GlobalModel.Provider),
			Model:          dep.GlobalModel.ModelName,
			Status:         StateHealthy,
		}
		m.reports[dep.ID] = rep
	}

	rep.ProbeLatencyMs = latencyMs
	rep.LastCheckedAt = time.Now().UTC()
	prevStatus := rep.Status

	if probeErr == nil {
		rep.ConsecutiveFailures = 0
		rep.LastError = ""
		rep.Status = StateHealthy
		if prevStatus != StateHealthy {
			logger.Info("Deployment health probe recovered",
				slog.String("component", "health_monitor"),
				slog.String("deployment_id", dep.ID),
				slog.String("deployment_name", dep.DeploymentName),
				slog.Int64("probe_latency_ms", latencyMs),
			)
		}
		if dep.Status == domain.DeploymentStatusCooldown {
			_ = m.repo.UpdateDeploymentStatus(context.Background(), dep.ID, domain.DeploymentStatusActive)
		}
	} else {
		rep.ConsecutiveFailures++
		rep.LastError = probeErr.Error()
		rep.Status = StateUnhealthy
		if prevStatus != StateUnhealthy {
			logger.Warn("Deployment health probe failed",
				slog.String("component", "health_monitor"),
				slog.String("deployment_id", dep.ID),
				slog.String("deployment_name", dep.DeploymentName),
				slog.String("error", probeErr.Error()),
				slog.Int("consecutive_failures", rep.ConsecutiveFailures),
			)
		}
	}
}
