package auth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/security/network"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
	"github.com/redis/go-redis/v9"
)

const (
	// KeyRotationLockKey is the Redis distributed pod lock key acquired by KeyRotationManager.
	KeyRotationLockKey = "gw:lock:key_rotation"

	// DefaultKeyRotationPollInterval is the default polling cadence for scheduled key rotation.
	DefaultKeyRotationPollInterval = 1 * time.Minute

	// DefaultKeyRotationGracePeriod is the default dual-active grace window for automated key rotation.
	DefaultKeyRotationGracePeriod = 24 * time.Hour

	// DefaultKeyRotationLockTTL is the Redis pod lock TTL (55s = 55000ms).
	DefaultKeyRotationLockTTL = 55 * time.Second

	// DefaultKeyRotationBatchSize is the maximum number of due keys rotated per sweep.
	DefaultKeyRotationBatchSize = 100
)

// ManagementAllowedEndpoints restricts management virtual keys strictly to Control Plane routes.
var ManagementAllowedEndpoints = []string{
	"/admin/v1/*",
}

// ReadOnlyAllowedEndpoints restricts read-only virtual keys to GET/info routes on Data Plane and Control Plane.
var ReadOnlyAllowedEndpoints = []string{
	"/v1/models",
	"/models",
	"/v1/key/info",
	"/v1/files",
	"/v1/files/*",
	"/files",
	"/files/*",
	"/v1/batches",
	"/v1/batches/*",
	"/batches",
	"/batches/*",
	"/v1/goroute/mcp/registry",
	"/mcp-rest/tools/list",
	"/admin/v1/*",
}

var releaseKeyRotationLockScript = redis.NewScript(`
if redis.call("GET", KEYS[1]) == ARGV[1] then
	return redis.call("DEL", KEYS[1])
end
return 0
`)

// NormalizeKeyType canonicalizes a VirtualKey key_type, defaulting empty values to "default".
func NormalizeKeyType(kt domain.KeyType) domain.KeyType {
	norm := domain.KeyType(strings.ToLower(strings.TrimSpace(string(kt))))
	if norm == "" {
		return domain.KeyTypeDefault
	}
	return norm
}

// IsValidKeyType reports whether kt is empty or one of the supported key_type presets.
func IsValidKeyType(kt domain.KeyType) bool {
	switch NormalizeKeyType(kt) {
	case domain.KeyTypeDefault,
		domain.KeyTypeLLMAPI,
		domain.KeyTypeManagement,
		domain.KeyTypeReadOnly,
		domain.KeyTypeServiceAccount:
		return true
	default:
		return false
	}
}

// ApplyKeyTypePreset applies the capability preset for vk.KeyType to vk's AllowedEndpoints, Role, and UserID.
// Supported presets:
//   - llm_api: data-plane inference routes (domain.DefaultAllowedEndpoints) and non-admin role
//   - management: /admin/v1/* Control Plane routes and operator role (default org_admin)
//   - read_only: GET/info routes + viewer/org_viewer role
//   - service_account: RoleServiceAccount with UserID cleared
//   - default: preserves caller-supplied role and endpoints
func ApplyKeyTypePreset(vk *domain.VirtualKey) {
	if vk == nil {
		return
	}
	vk.KeyType = NormalizeKeyType(vk.KeyType)

	switch vk.KeyType {
	case domain.KeyTypeLLMAPI:
		if len(vk.AllowedEndpoints) == 0 || hasWildcardOrAdminEndpoint(vk.AllowedEndpoints) {
			vk.AllowedEndpoints = append([]string(nil), domain.DefaultAllowedEndpoints...)
		}
		if vk.Role == "" || isControlPlaneOperatorRole(vk.Role) {
			vk.Role = domain.RoleServiceAccount
		}
	case domain.KeyTypeManagement:
		if len(vk.AllowedEndpoints) == 0 || hasNonAdminEndpoint(vk.AllowedEndpoints) {
			vk.AllowedEndpoints = append([]string(nil), ManagementAllowedEndpoints...)
		}
		if vk.Role == "" || !isControlPlaneOperatorRole(vk.Role) {
			vk.Role = domain.RoleOrgAdmin
		}
	case domain.KeyTypeReadOnly:
		if len(vk.AllowedEndpoints) == 0 || hasNonReadOnlyEndpoint(vk.AllowedEndpoints) {
			vk.AllowedEndpoints = append([]string(nil), ReadOnlyAllowedEndpoints...)
		}
		if vk.Role != domain.RoleViewer && vk.Role != domain.RoleOrgViewer {
			vk.Role = domain.RoleOrgViewer
		}
	case domain.KeyTypeServiceAccount:
		vk.Role = domain.RoleServiceAccount
		vk.UserID = ""
	case domain.KeyTypeDefault:
		// Default preset preserves existing backward-compatible behavior.
	}
}

func isControlPlaneOperatorRole(role domain.Role) bool {
	_, ok := mapDomainRoleToOperatorRole(role)
	return ok
}

func hasWildcardOrAdminEndpoint(endpoints []string) bool {
	for _, ep := range endpoints {
		trimmed := strings.TrimSpace(ep)
		if trimmed == "*" || strings.HasPrefix(trimmed, "/admin") {
			return true
		}
	}
	return false
}

func hasNonAdminEndpoint(endpoints []string) bool {
	for _, ep := range endpoints {
		trimmed := strings.TrimSpace(ep)
		if trimmed == "*" || (!strings.HasPrefix(trimmed, "/admin/v1/") && trimmed != "/admin/v1") {
			return true
		}
	}
	return false
}

func hasNonReadOnlyEndpoint(endpoints []string) bool {
	for _, ep := range endpoints {
		trimmed := strings.TrimSpace(ep)
		if trimmed == "" || trimmed == "*" || !isAllowedReadOnlyPattern(trimmed) {
			return true
		}
	}
	return false
}

func isAllowedReadOnlyPattern(pattern string) bool {
	for _, allowed := range ReadOnlyAllowedEndpoints {
		if pattern == allowed {
			return true
		}
		if strings.HasSuffix(allowed, "*") {
			prefix := strings.TrimSuffix(allowed, "*")
			if strings.HasPrefix(pattern, prefix) {
				return true
			}
		}
	}
	return false
}

// RotateVirtualKeyWithGrace generates a new cryptographically random `sk-gw-...` key for an existing VirtualKey,
// optionally records the previous KeyHash in virtual_key_deprecated_hashes until now+gracePeriod for zero-downtime
// dual-active migration, advances KeyRotationAt when RotationIntervalSec > 0, invalidates cached L1/L2 entries for
// the previous hash so deprecation metadata (or immediate revocation) takes effect across all pods, and returns the
// updated VirtualKey with RawKey populated once.
func (s *Service) RotateVirtualKeyWithGrace(ctx context.Context, id string, gracePeriod time.Duration) (*domain.VirtualKey, error) {
	return s.rotateVirtualKeyWithGraceAt(ctx, id, gracePeriod, s.now(), nil)
}

type stagedRotationDelivery func(ctx context.Context, event KeyRotatedSecretEvent) error

func (s *Service) rotateVirtualKeyWithGraceAt(ctx context.Context, id string, gracePeriod time.Duration, now time.Time, deliver stagedRotationDelivery) (*domain.VirtualKey, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return nil, fmt.Errorf("virtual key id is required")
	}
	if gracePeriod < 0 {
		return nil, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "invalid_grace_period",
			Message:    "grace_period_seconds cannot be negative",
		}
	}

	existing, err := s.repo.GetVirtualKeyByID(ctx, id)
	if err != nil {
		return nil, err
	}

	now = now.UTC()

	var nextRotationPtr *time.Time
	if existing.RotationIntervalSec > 0 {
		nextRotation := now.Add(time.Duration(existing.RotationIntervalSec) * time.Second)
		nextRotationPtr = &nextRotation
	}
	var revokeAtPtr *time.Time
	if gracePeriod > 0 {
		revAt := now.Add(gracePeriod).UTC()
		revokeAtPtr = &revAt
	}

	var rawKey, nextPrefix, nextHash string
	if deliver != nil {
		if s.vault == nil {
			return nil, fmt.Errorf("vault is required to stage scheduled virtual key rotation")
		}
		if existing.StagedKeyHash != "" && existing.StagedEncryptedRawKey != "" && existing.StagedKeyDEK != "" {
			rawKey, err = s.vault.DecryptString(existing.StagedEncryptedRawKey, existing.StagedKeyDEK)
			if err != nil {
				return nil, fmt.Errorf("decrypt staged virtual key replacement: %w", err)
			}
			if HashKey(rawKey) != existing.StagedKeyHash {
				return nil, fmt.Errorf("staged virtual key replacement failed integrity verification")
			}
			nextPrefix = existing.StagedKeyPrefix
			nextHash = existing.StagedKeyHash
		} else {
			rawKey, nextPrefix, nextHash, err = generateVirtualKeyMaterial()
			if err != nil {
				return nil, err
			}
			encRaw, dekHex, encErr := s.vault.EncryptString(rawKey)
			if encErr != nil {
				return nil, fmt.Errorf("encrypt staged virtual key replacement: %w", encErr)
			}
			staged := *existing
			staged.StagedKeyHash = nextHash
			staged.StagedKeyPrefix = nextPrefix
			staged.StagedEncryptedRawKey = encRaw
			staged.StagedKeyDEK = dekHex
			stagedAt := now
			staged.StagedCreatedAt = &stagedAt
			if err := s.repo.UpdateVirtualKey(ctx, &staged); err != nil {
				return nil, fmt.Errorf("persist staged virtual key replacement: %w", err)
			}
			existing = &staged
		}
		ev := KeyRotatedSecretEvent{
			OrgID:                 existing.OrgID,
			TeamID:                existing.TeamID,
			UserID:                existing.UserID,
			VirtualKeyID:          existing.ID,
			Name:                  existing.Name,
			KeyPrefix:             nextPrefix,
			PreviousKeyPrefix:     existing.KeyPrefix,
			RawKey:                rawKey,
			DeprecatedKeyRevokeAt: revokeAtPtr,
			NextRotationAt:        nextRotationPtr,
			RotatedAt:             now,
		}
		if err := deliver(ctx, ev); err != nil {
			return nil, fmt.Errorf("deliver replacement credential: %w", err)
		}
	} else {
		rawKey, nextPrefix, nextHash, err = generateVirtualKeyMaterial()
		if err != nil {
			return nil, err
		}
	}

	oldHash := existing.KeyHash
	rotated := *existing
	rotated.KeyPrefix = nextPrefix
	rotated.KeyHash = nextHash
	rotated.StagedKeyHash = ""
	rotated.StagedKeyPrefix = ""
	rotated.StagedEncryptedRawKey = ""
	rotated.StagedKeyDEK = ""
	rotated.StagedCreatedAt = nil
	rotated.IsActive = true
	if nextRotationPtr != nil {
		rotated.KeyRotationAt = nextRotationPtr
	}

	// Store deprecated hash BEFORE swapping the primary hash so concurrent callers
	// never observe a transient 401 window during zero-downtime grace rotation.
	if revokeAtPtr != nil && oldHash != "" {
		rotRepo, ok := s.repo.(storage.KeyRotationRepository)
		if !ok || rotRepo == nil {
			return nil, fmt.Errorf("repository does not support deprecated key grace periods")
		}
		if err := rotRepo.AddDeprecatedVirtualKeyHash(ctx, oldHash, existing.ID, *revokeAtPtr); err != nil {
			return nil, fmt.Errorf("record deprecated virtual key hash: %w", err)
		}
	}

	if err := s.repo.UpdateVirtualKey(ctx, &rotated); err != nil {
		return nil, err
	}
	if govRepo, ok := s.repo.(storage.KeyGovernanceRepository); ok && govRepo != nil {
		_ = govRepo.MarkVirtualKeyRotated(ctx, rotated.ID, now)
	}
	rotated.LastRotatedAt = &now
	rotated.RotationCount = existing.RotationCount + 1
	if oldHash != "" {
		s.InvalidateKeyHash(ctx, oldHash)
	}
	rotated.RawKey = rawKey
	return &rotated, nil
}

func generateVirtualKeyMaterial() (rawKey, prefix, hash string, err error) {
	randBytes := make([]byte, 22)
	if _, err := rand.Read(randBytes); err != nil {
		return "", "", "", fmt.Errorf("generate random key bytes: %w", err)
	}
	randHex := hex.EncodeToString(randBytes)
	shortID := randHex[:8]
	secretPart := randHex[8:]
	rawKey = fmt.Sprintf("sk-gw-%s-%s", shortID, secretPart)
	prefix = fmt.Sprintf("sk-gw-%s", shortID)
	hash = HashKey(rawKey)
	return rawKey, prefix, hash, nil
}

// RotationDelivery acknowledges durable external receipt of a scheduled replacement credential.
type RotationDelivery func(ctx context.Context, orgID, keyID, replacement string) error

// KeyRotatedSecretEvent carries the newly minted raw key for out-of-band in-process delivery
// to a secret manager without logging or sending plaintext keys in webhooks or audit trails.
type KeyRotatedSecretEvent struct {
	OrgID                 string     `json:"org_id"`
	TeamID                string     `json:"team_id,omitempty"`
	UserID                string     `json:"user_id,omitempty"`
	VirtualKeyID          string     `json:"virtual_key_id"`
	Name                  string     `json:"name"`
	KeyPrefix             string     `json:"key_prefix"`
	PreviousKeyPrefix     string     `json:"previous_key_prefix,omitempty"`
	RawKey                string     `json:"raw_key"`
	DeprecatedKeyRevokeAt *time.Time `json:"deprecated_key_revoke_at,omitempty"`
	NextRotationAt        *time.Time `json:"next_rotation_at,omitempty"`
	RotatedAt             time.Time  `json:"rotated_at"`
}

// KeySecretSink receives newly minted virtual key secrets from automated rotation sweeps
// so embedders can push rotated credentials into external vaults (e.g., Secrets Manager, Vault).
type KeySecretSink interface {
	DeliverRotatedSecret(ctx context.Context, event KeyRotatedSecretEvent) error
}

// KeySecretSinkFunc adapts a Go function into a KeySecretSink.
type KeySecretSinkFunc func(ctx context.Context, event KeyRotatedSecretEvent) error

// DeliverRotatedSecret invokes f(ctx, event).
func (f KeySecretSinkFunc) DeliverRotatedSecret(ctx context.Context, event KeyRotatedSecretEvent) error {
	return f(ctx, event)
}

// KeyAutoRotatedWebhookPayload is posted to Organization.LifecycleWebhookURL without raw key material.
type KeyAutoRotatedWebhookPayload struct {
	Event                 string     `json:"event"`
	OrgID                 string     `json:"org_id"`
	VirtualKeyID          string     `json:"virtual_key_id"`
	Name                  string     `json:"name"`
	KeyPrefix             string     `json:"key_prefix"`
	PreviousKeyPrefix     string     `json:"previous_key_prefix,omitempty"`
	GracePeriodSeconds    int64      `json:"grace_period_seconds"`
	DeprecatedKeyRevokeAt *time.Time `json:"deprecated_key_revoke_at,omitempty"`
	NextRotationAt        *time.Time `json:"next_rotation_at,omitempty"`
	Timestamp             time.Time  `json:"timestamp"`
}

// KeyRotationConfig configures the background scheduled key rotation worker.
type KeyRotationConfig struct {
	Deliver            RotationDelivery
	PollInterval       time.Duration
	GracePeriod        time.Duration
	DisableGracePeriod bool
	LockTTL            time.Duration
	BatchSize          int
	PodID              string
	NetworkPolicy      *network.Policy
	HTTPClient         *http.Client
	SecretSink         KeySecretSink
	Now                func() time.Time
}

// KeyRotationSweepResult reports the outcome of a single KeyRotationManager sweep.
type KeyRotationSweepResult struct {
	LockAcquired  bool
	PurgedHashes  int64
	RotatedKeys   int
	RotatedKeyIDs []string
	WebhooksSent  int
	Errors        int
}

// KeyRotationManager periodically scans for virtual keys due for scheduled rotation
// (`key_rotation_at <= now`), rotates them with a configurable dual-active grace period
// under a Redis distributed pod lock (`SET gw:lock:key_rotation <podID> NX PX 55000` + Lua release),
// records audit logs, dispatches SSRF-checked webhooks, delivers new secrets to KeySecretSink, and purges expired deprecated key hashes.
type KeyRotationManager struct {
	deliver      RotationDelivery
	authSvc      *Service
	repo         storage.Repository
	redis        *storage.RedisFabric
	pollInterval time.Duration
	gracePeriod  time.Duration
	lockTTL      time.Duration
	batchSize    int
	podID        string
	netPolicy    *network.Policy
	httpClient   *http.Client
	secretSink   KeySecretSink
	nowFn        func() time.Time

	mu                    sync.Mutex
	running               bool
	cancel                context.CancelFunc
	done                  chan struct{}
	deliveriesTotal       atomic.Uint64
	deliveryFailuresTotal atomic.Uint64
}

// DeliveryStats returns cumulative succeeded and failed replacement credential deliveries.
func (m *KeyRotationManager) DeliveryStats() (deliveries, failures uint64) {
	if m == nil {
		return 0, 0
	}
	return m.deliveriesTotal.Load(), m.deliveryFailuresTotal.Load()
}

// NewKeyRotationManager constructs a KeyRotationManager with safe production defaults.
func NewKeyRotationManager(authSvc *Service, repo storage.Repository, redisFabric *storage.RedisFabric, cfg KeyRotationConfig) *KeyRotationManager {
	if repo == nil && authSvc != nil {
		repo = authSvc.Repo()
	}
	pollInterval := cfg.PollInterval
	if pollInterval <= 0 {
		pollInterval = DefaultKeyRotationPollInterval
	}
	gracePeriod := cfg.GracePeriod
	if cfg.DisableGracePeriod {
		gracePeriod = 0
	} else if gracePeriod <= 0 {
		gracePeriod = DefaultKeyRotationGracePeriod
	}
	lockTTL := cfg.LockTTL
	if lockTTL <= 0 {
		lockTTL = DefaultKeyRotationLockTTL
	}
	batchSize := cfg.BatchSize
	if batchSize <= 0 {
		batchSize = DefaultKeyRotationBatchSize
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
		if authSvc != nil {
			nowFn = authSvc.now
		} else {
			nowFn = func() time.Time { return time.Now().UTC() }
		}
	}
	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = network.NewHTTPClient(cfg.NetworkPolicy)
	}
	return &KeyRotationManager{
		deliver:      cfg.Deliver,
		authSvc:      authSvc,
		repo:         repo,
		redis:        redisFabric,
		pollInterval: pollInterval,
		gracePeriod:  gracePeriod,
		lockTTL:      lockTTL,
		batchSize:    batchSize,
		podID:        podID,
		netPolicy:    cfg.NetworkPolicy,
		httpClient:   httpClient,
		secretSink:   cfg.SecretSink,
		nowFn:        nowFn,
	}
}

// SetSecretSink updates the in-process KeySecretSink notified whenever automated rotation mints a new key.
func (m *KeyRotationManager) SetSecretSink(sink KeySecretSink) {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.secretSink = sink
	m.mu.Unlock()
}

func (m *KeyRotationManager) currentSecretSink() KeySecretSink {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	sink := m.secretSink
	m.mu.Unlock()
	return sink
}

// PodID returns this manager's unique distributed lock owner identifier.
func (m *KeyRotationManager) PodID() string {
	if m == nil {
		return ""
	}
	return m.podID
}

// Start launches the background rotation and expired-hash cleanup loop.
func (m *KeyRotationManager) Start(ctx context.Context) {
	if m == nil {
		return
	}
	m.mu.Lock()
	if m.running {
		m.mu.Unlock()
		return
	}
	runCtx, cancel := context.WithCancel(ctx)
	m.cancel = cancel
	m.done = make(chan struct{})
	m.running = true
	done := m.done
	m.mu.Unlock()

	go func() {
		defer close(done)
		ticker := time.NewTicker(m.pollInterval)
		defer ticker.Stop()
		for {
			select {
			case <-runCtx.Done():
				return
			case <-ticker.C:
				_, _ = m.RunOnce(runCtx)
			}
		}
	}()
}

// Stop stops the background worker and waits for its goroutine to exit cleanly.
func (m *KeyRotationManager) Stop() {
	if m == nil {
		return
	}
	m.mu.Lock()
	if !m.running {
		m.mu.Unlock()
		return
	}
	cancel := m.cancel
	done := m.done
	m.cancel = nil
	m.running = false
	m.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	if done != nil {
		<-done
	}
}

// RunOnce executes a single lock-guarded rotation and expired-hash purge sweep.
func (m *KeyRotationManager) RunOnce(ctx context.Context) (KeyRotationSweepResult, error) {
	var result KeyRotationSweepResult
	if m == nil || m.authSvc == nil || m.repo == nil {
		return result, nil
	}

	acquired, err := m.acquireLock(ctx)
	if err != nil {
		slog.WarnContext(ctx, "auth: failed to acquire key rotation pod lock", "pod_id", m.podID, "error", err)
		return result, err
	}
	if !acquired {
		return result, nil
	}
	result.LockAcquired = true
	defer m.releaseLock(context.WithoutCancel(ctx))

	rotRepo, ok := m.repo.(storage.KeyRotationRepository)
	if !ok || rotRepo == nil {
		return result, nil
	}

	now := m.nowFn().UTC()

	// 1. Purge expired deprecated hashes
	purged, err := rotRepo.DeleteExpiredDeprecatedVirtualKeyHashes(ctx, now)
	if err != nil {
		slog.WarnContext(ctx, "auth: failed to purge expired deprecated virtual key hashes", "error", err)
		result.Errors++
	} else {
		result.PurgedHashes = purged
	}

	secretSink := m.currentSecretSink()
	if m.deliver == nil && secretSink == nil {
		return result, nil
	}

	// 2. Rotate virtual keys due for scheduled rotation
	dueKeys, err := rotRepo.ListVirtualKeysDueForRotation(ctx, now, m.batchSize)
	if err != nil {
		slog.WarnContext(ctx, "auth: failed to list virtual keys due for rotation", "error", err)
		result.Errors++
		return result, err
	}

	for _, vk := range dueKeys {
		if vk == nil || !vk.IsActive || vk.RotationIntervalSec <= 0 || vk.KeyRotationAt == nil {
			continue
		}
		if vk.KeyRotationAt.UTC().After(now) {
			continue
		}
		alreadyStaged := vk.StagedKeyHash != "" && vk.StagedEncryptedRawKey != "" && vk.StagedKeyDEK != ""
		activeSink := m.currentSecretSink()
		usePreCommit := m.deliver != nil || (activeSink != nil && m.authSvc.vault != nil)
		var deliverFn stagedRotationDelivery
		if usePreCommit {
			deliverFn = func(dCtx context.Context, ev KeyRotatedSecretEvent) error {
				if m.deliver != nil {
					if err := m.deliver(dCtx, ev.OrgID, ev.VirtualKeyID, ev.RawKey); err != nil {
						m.deliveryFailuresTotal.Add(1)
						return err
					}
				}
				if activeSink != nil {
					if err := activeSink.DeliverRotatedSecret(dCtx, ev); err != nil {
						m.deliveryFailuresTotal.Add(1)
						return err
					}
				}
				m.deliveriesTotal.Add(1)
				return nil
			}
		}
		rotated, rotErr := m.authSvc.rotateVirtualKeyWithGraceAt(ctx, vk.ID, m.gracePeriod, now, deliverFn)
		if rotErr != nil {
			slog.WarnContext(ctx, "auth: scheduled virtual key auto-rotation failed",
				"virtual_key_id", vk.ID,
				"org_id", vk.OrgID,
				"error", rotErr,
			)
			// Record one sanitized failure event on initial staging so prolonged outages do not flood audit_logs.
			if !alreadyStaged {
				_ = m.repo.RecordAuditLog(ctx, &domain.AuditLog{
					OrgID:      vk.OrgID,
					ActorID:    "key-rotation-worker",
					Action:     "virtual_key.auto_rotation_failed",
					Resource:   "virtual_key",
					ResourceID: vk.ID,
					Details: map[string]any{
						"key_prefix": vk.KeyPrefix,
						"name":       vk.Name,
						"staged":     true,
						"pod_id":     m.podID,
						"error":      rotErr.Error(),
					},
				})
			}
			result.Errors++
			continue
		}

		details := map[string]any{
			"key_prefix":            rotated.KeyPrefix,
			"previous_key_prefix":   vk.KeyPrefix,
			"name":                  rotated.Name,
			"rotation_interval_sec": rotated.RotationIntervalSec,
			"grace_period_seconds":  int64(m.gracePeriod / time.Second),
			"automated":             true,
			"pod_id":                m.podID,
		}
		if rotated.KeyRotationAt != nil {
			details["next_rotation_at"] = rotated.KeyRotationAt.UTC().Format(time.RFC3339)
		}
		var revokeAtPtr *time.Time
		if m.gracePeriod > 0 {
			revAt := now.Add(m.gracePeriod).UTC()
			revokeAtPtr = &revAt
			details["deprecated_key_revoke_at"] = revAt.Format(time.RFC3339)
		}
		_ = m.repo.RecordAuditLog(ctx, &domain.AuditLog{
			OrgID:      rotated.OrgID,
			ActorID:    "key-rotation-worker",
			Action:     "virtual_key.auto_rotated",
			Resource:   "virtual_key",
			ResourceID: rotated.ID,
			Details:    details,
		})

		if !usePreCommit && activeSink != nil && rotated.RawKey != "" {
			if sinkErr := activeSink.DeliverRotatedSecret(ctx, KeyRotatedSecretEvent{
				OrgID:                 rotated.OrgID,
				TeamID:                rotated.TeamID,
				UserID:                rotated.UserID,
				VirtualKeyID:          rotated.ID,
				Name:                  rotated.Name,
				KeyPrefix:             rotated.KeyPrefix,
				PreviousKeyPrefix:     vk.KeyPrefix,
				RawKey:                rotated.RawKey,
				DeprecatedKeyRevokeAt: revokeAtPtr,
				NextRotationAt:        rotated.KeyRotationAt,
				RotatedAt:             now,
			}); sinkErr != nil {
				m.deliveryFailuresTotal.Add(1)
				slog.WarnContext(ctx, "auth: failed to deliver rotated key secret to sink",
					"org_id", rotated.OrgID, "virtual_key_id", rotated.ID, "error", sinkErr)
				result.Errors++
			} else {
				m.deliveriesTotal.Add(1)
			}
		}

		if org, orgErr := m.repo.GetOrganization(ctx, rotated.OrgID); orgErr == nil && org != nil && org.IsActive {
			if webhookURL := strings.TrimSpace(org.LifecycleWebhookURL); webhookURL != "" {
				if sendErr := dispatchLifecycleWebhook(ctx, m.httpClient, m.netPolicy, webhookURL, KeyAutoRotatedWebhookPayload{
					Event:                 "virtual_key.auto_rotated",
					OrgID:                 rotated.OrgID,
					VirtualKeyID:          rotated.ID,
					Name:                  rotated.Name,
					KeyPrefix:             rotated.KeyPrefix,
					PreviousKeyPrefix:     vk.KeyPrefix,
					GracePeriodSeconds:    int64(m.gracePeriod / time.Second),
					DeprecatedKeyRevokeAt: revokeAtPtr,
					NextRotationAt:        rotated.KeyRotationAt,
					Timestamp:             now,
				}); sendErr != nil {
					slog.WarnContext(ctx, "auth: failed to dispatch key auto-rotation webhook",
						"org_id", rotated.OrgID, "virtual_key_id", rotated.ID, "error", sendErr)
					result.Errors++
				} else {
					result.WebhooksSent++
				}
			}
		}

		result.RotatedKeys++
		result.RotatedKeyIDs = append(result.RotatedKeyIDs, rotated.ID)
	}

	return result, nil
}

func (m *KeyRotationManager) acquireLock(ctx context.Context) (bool, error) {
	if m.redis == nil || m.redis.Client() == nil {
		return true, nil
	}
	lockMillis := m.lockTTL.Milliseconds()
	if lockMillis <= 0 {
		lockMillis = DefaultKeyRotationLockTTL.Milliseconds()
	}
	res, err := m.redis.Execute(func(rdb redis.UniversalClient) (any, error) {
		return rdb.Do(ctx, "SET", KeyRotationLockKey, m.podID, "NX", "PX", lockMillis).Result()
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

func (m *KeyRotationManager) releaseLock(ctx context.Context) {
	if m.redis == nil || m.redis.Client() == nil {
		return
	}
	relCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	_, _ = m.redis.Execute(func(rdb redis.UniversalClient) (any, error) {
		return releaseKeyRotationLockScript.Run(relCtx, rdb, []string{KeyRotationLockKey}, m.podID).Result()
	})
}
