package auth

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/security/network"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
	"github.com/redis/go-redis/v9"
)

const (
	// KeyExpiryAlertLockKey is the Redis distributed pod lock key acquired by KeyExpiryAlertManager.
	KeyExpiryAlertLockKey = "gw:lock:key_expiry_alerts"

	// DefaultKeyExpiryAlertPollInterval is the default sweep cadence for proactive key expiry alerts.
	DefaultKeyExpiryAlertPollInterval = 5 * time.Minute

	// DefaultKeyExpiryAlertLockTTL is the distributed Redis lock TTL (55s).
	DefaultKeyExpiryAlertLockTTL = 55 * time.Second

	// DefaultKeyExpiryAlertBatchSize caps the number of expiring keys scanned per sweep.
	DefaultKeyExpiryAlertBatchSize = 200
)

var defaultExpiryAlertDays = []int{7, 1}

// KeyExpiryAlertConfig configures KeyExpiryAlertManager.
type KeyExpiryAlertConfig struct {
	PollInterval  time.Duration
	LockTTL       time.Duration
	BatchSize     int
	PodID         string
	NetworkPolicy *network.Policy
	HTTPClient    *http.Client
	Now           func() time.Time
}

// KeyExpiryAlertSweepResult summarizes a single expiry-alert scan cycle.
type KeyExpiryAlertSweepResult struct {
	LockAcquired   bool
	ScannedKeys    int
	AlertsRecorded int
	WebhooksSent   int
	Errors         int
}

// KeyExpiryAlertPayload is posted to Organization.LifecycleWebhookURL for expiring keys.
type KeyExpiryAlertPayload struct {
	Event         string    `json:"event"`
	OrgID         string    `json:"org_id"`
	VirtualKeyID  string    `json:"virtual_key_id"`
	KeyPrefix     string    `json:"key_prefix"`
	Name          string    `json:"name"`
	ThresholdDays int       `json:"threshold_days"`
	DaysRemaining int       `json:"days_remaining"`
	ExpiresAt     time.Time `json:"expires_at"`
	Timestamp     time.Time `json:"timestamp"`
}

// KeyExpiryAlertManager periodically scans for active virtual keys approaching expiration,
// emits once-per-threshold audit logs, and dispatches SSRF-checked webhook notifications.
type KeyExpiryAlertManager struct {
	repo         storage.Repository
	redis        *storage.RedisFabric
	pollInterval time.Duration
	lockTTL      time.Duration
	batchSize    int
	podID        string
	netPolicy    *network.Policy
	httpClient   *http.Client
	nowFn        func() time.Time

	mu      sync.Mutex
	running bool
	cancel  context.CancelFunc
	done    chan struct{}
}

// NewKeyExpiryAlertManager constructs a KeyExpiryAlertManager with SSRF-guarded outbound HTTP.
func NewKeyExpiryAlertManager(repo storage.Repository, redisFabric *storage.RedisFabric, cfg KeyExpiryAlertConfig) *KeyExpiryAlertManager {
	pollInterval := cfg.PollInterval
	if pollInterval <= 0 {
		pollInterval = DefaultKeyExpiryAlertPollInterval
	}
	lockTTL := cfg.LockTTL
	if lockTTL <= 0 {
		lockTTL = DefaultKeyExpiryAlertLockTTL
	}
	batchSize := cfg.BatchSize
	if batchSize <= 0 {
		batchSize = DefaultKeyExpiryAlertBatchSize
	}
	podID := strings.TrimSpace(cfg.PodID)
	if podID == "" {
		host, _ := os.Hostname()
		if host != "" {
			podID = host + "-" + uuid.NewString()
		} else {
			podID = uuid.NewString()
		}
	}
	nowFn := cfg.Now
	if nowFn == nil {
		nowFn = func() time.Time { return time.Now().UTC() }
	}
	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = network.NewHTTPClient(cfg.NetworkPolicy)
	}
	return &KeyExpiryAlertManager{
		repo:         repo,
		redis:        redisFabric,
		pollInterval: pollInterval,
		lockTTL:      lockTTL,
		batchSize:    batchSize,
		podID:        podID,
		netPolicy:    cfg.NetworkPolicy,
		httpClient:   httpClient,
		nowFn:        nowFn,
	}
}

// Start launches the periodic key-expiry alert sweep goroutine.
func (m *KeyExpiryAlertManager) Start(ctx context.Context) {
	if m == nil {
		return
	}
	m.mu.Lock()
	if m.running {
		m.mu.Unlock()
		return
	}
	loopCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	m.running = true
	m.cancel = cancel
	m.done = done
	m.mu.Unlock()

	go func() {
		defer close(done)
		ticker := time.NewTicker(m.pollInterval)
		defer ticker.Stop()

		for {
			select {
			case <-loopCtx.Done():
				return
			case <-ticker.C:
				_, _ = m.RunOnce(loopCtx)
			}
		}
	}()
}

// Stop halts the background expiry alert loop and waits for completion.
func (m *KeyExpiryAlertManager) Stop() {
	if m == nil {
		return
	}
	m.mu.Lock()
	cancel := m.cancel
	done := m.done
	m.running = false
	m.cancel = nil
	m.done = nil
	m.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	if done != nil {
		<-done
	}
}

// RunOnce executes a single cluster-coordinated scan and notification pass.
func (m *KeyExpiryAlertManager) RunOnce(ctx context.Context) (KeyExpiryAlertSweepResult, error) {
	var result KeyExpiryAlertSweepResult
	if m == nil || m.repo == nil {
		return result, nil
	}
	acquired, err := m.acquireLock(ctx)
	if err != nil {
		slog.WarnContext(ctx, "auth: failed to acquire key expiry alert lock", "pod_id", m.podID, "error", err)
		return result, err
	}
	if !acquired {
		return result, nil
	}
	result.LockAcquired = true
	defer m.releaseLock(context.WithoutCancel(ctx))

	govRepo, ok := m.repo.(storage.KeyGovernanceRepository)
	if !ok || govRepo == nil {
		return result, nil
	}

	orgs, err := m.repo.ListOrganizations(ctx)
	if err != nil {
		result.Errors++
		return result, err
	}
	orgMap := make(map[string]*domain.Organization, len(orgs))
	maxLookaheadDays := 7
	for _, org := range orgs {
		if org == nil || !org.IsActive {
			continue
		}
		orgMap[org.ID] = org
		for _, d := range orgAlertDays(org) {
			if d > maxLookaheadDays {
				maxLookaheadDays = d
			}
		}
	}

	now := m.nowFn().UTC()
	cutoff := now.Add(time.Duration(maxLookaheadDays) * 24 * time.Hour)
	expiring, err := govRepo.ListVirtualKeysExpiringBefore(ctx, cutoff, m.batchSize)
	if err != nil {
		result.Errors++
		return result, err
	}
	result.ScannedKeys = len(expiring)

	for _, vk := range expiring {
		if vk == nil || !vk.IsActive || vk.ExpiresAt == nil {
			continue
		}
		org := orgMap[vk.OrgID]
		if org == nil {
			continue
		}
		remaining := vk.ExpiresAt.UTC().Sub(now)
		if remaining <= 0 {
			continue
		}
		remainingDays := int(remaining.Hours() / 24)
		thresholds := orgAlertDays(org)
		sort.Ints(thresholds) // check smallest threshold first (e.g. 1 day before 7 day)
		for _, day := range thresholds {
			if day <= 0 {
				continue
			}
			if remaining > time.Duration(day)*24*time.Hour {
				continue
			}
			if slices.Contains(vk.ExpiryAlertSentDays, day) {
				break
			}
			if markErr := govRepo.MarkVirtualKeyExpiryAlertSent(ctx, vk.ID, day); markErr != nil {
				result.Errors++
				continue
			}
			_ = m.repo.RecordAuditLog(ctx, &domain.AuditLog{
				OrgID:      vk.OrgID,
				ActorID:    "key-expiry-alert-worker",
				Action:     "virtual_key.expiring_soon",
				Resource:   "virtual_key",
				ResourceID: vk.ID,
				Details: map[string]any{
					"key_prefix":     vk.KeyPrefix,
					"name":           vk.Name,
					"threshold_days": day,
					"days_remaining": remainingDays,
					"expires_at":     vk.ExpiresAt.UTC().Format(time.RFC3339),
				},
			})
			result.AlertsRecorded++
			if webhookURL := strings.TrimSpace(org.LifecycleWebhookURL); webhookURL != "" {
				if sendErr := m.dispatchWebhook(ctx, webhookURL, KeyExpiryAlertPayload{
					Event:         "virtual_key.expiring_soon",
					OrgID:         vk.OrgID,
					VirtualKeyID:  vk.ID,
					KeyPrefix:     vk.KeyPrefix,
					Name:          vk.Name,
					ThresholdDays: day,
					DaysRemaining: remainingDays,
					ExpiresAt:     vk.ExpiresAt.UTC(),
					Timestamp:     now,
				}); sendErr != nil {
					slog.WarnContext(ctx, "auth: failed to dispatch key expiry webhook",
						"org_id", vk.OrgID, "virtual_key_id", vk.ID, "error", sendErr)
					result.Errors++
				} else {
					result.WebhooksSent++
				}
			}
			break // notify only once per sweep even if crossing multiple thresholds
		}
	}

	return result, nil
}

func orgAlertDays(org *domain.Organization) []int {
	if org != nil && org.KeyExpiryAlertDays != nil {
		return slices.Clone(org.KeyExpiryAlertDays)
	}
	return slices.Clone(defaultExpiryAlertDays)
}

func (m *KeyExpiryAlertManager) dispatchWebhook(ctx context.Context, rawURL string, payload KeyExpiryAlertPayload) error {
	return dispatchLifecycleWebhook(ctx, m.httpClient, m.netPolicy, rawURL, payload)
}

func (m *KeyExpiryAlertManager) acquireLock(ctx context.Context) (bool, error) {
	if m.redis == nil || m.redis.Client() == nil {
		return true, nil
	}
	lockMillis := m.lockTTL.Milliseconds()
	if lockMillis <= 0 {
		lockMillis = DefaultKeyExpiryAlertLockTTL.Milliseconds()
	}
	res, err := m.redis.Execute(func(rdb redis.UniversalClient) (any, error) {
		return rdb.Do(ctx, "SET", KeyExpiryAlertLockKey, m.podID, "NX", "PX", lockMillis).Result()
	})
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return false, nil
		}
		return false, err
	}
	status, ok := res.(string)
	return ok && status == "OK", nil
}

func (m *KeyExpiryAlertManager) releaseLock(ctx context.Context) {
	if m.redis == nil || m.redis.Client() == nil {
		return
	}
	relCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	_, _ = m.redis.Execute(func(rdb redis.UniversalClient) (any, error) {
		return releaseKeyRotationLockScript.Run(relCtx, rdb, []string{KeyExpiryAlertLockKey}, m.podID).Result()
	})
}
