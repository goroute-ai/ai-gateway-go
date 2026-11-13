package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
	"github.com/redis/go-redis/v9"
)

type l1CacheEntry struct {
	identity     *domain.IdentityContext
	expiresAt    time.Time
	keyExpiresAt *time.Time
}

type cachedIdentity struct {
	Identity     domain.IdentityContext `json:"identity"`
	KeyExpiresAt *time.Time             `json:"key_expires_at,omitempty"`
}

// Service manages Boundary 1 authentication (Virtual API Keys, L1/L2 caching, and Admin authentication).
type Service struct {
	repo                storage.Repository
	redis               *storage.RedisFabric
	masterAdminKey      string
	masterEncryptionKey string
	l1TTL               time.Duration
	l2TTL               time.Duration
	l1Cache             sync.Map // keyHash -> l1CacheEntry
	invalidationMu      sync.Mutex
	invalidationCancel  context.CancelFunc
}

func NewService(repo storage.Repository, redisFabric *storage.RedisFabric, masterAdminKey string, l1TTL, l2TTL time.Duration) *Service {
	if l1TTL <= 0 {
		l1TTL = 15 * time.Second
	}
	if l2TTL <= 0 {
		l2TTL = 5 * time.Minute
	}
	return &Service{
		repo:           repo,
		redis:          redisFabric,
		masterAdminKey: masterAdminKey,
		l1TTL:          l1TTL,
		l2TTL:          l2TTL,
	}
}

// SetMasterEncryptionKey configures the master encryption key used for secret isolation and self-credential checks.
func (s *Service) SetMasterEncryptionKey(key string) {
	s.masterEncryptionKey = strings.TrimSpace(key)
}

// HashKey computes the hex-encoded SHA-256 digest of a raw Virtual API Key.
func HashKey(rawKey string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(rawKey)))
	return hex.EncodeToString(sum[:])
}

// IssueVirtualKey generates a cryptographically random Virtual Key (`sk-gw-<8char>-<36char>`),
// stores only its SHA-256 hash in the repository, and returns the VirtualKey with `RawKey` populated once.
func (s *Service) IssueVirtualKey(ctx context.Context, req *domain.VirtualKey) (*domain.VirtualKey, error) {
	if req.OrgID == "" {
		return nil, fmt.Errorf("org_id is required to issue a virtual key")
	}
	if _, err := s.repo.GetOrganization(ctx, req.OrgID); err != nil {
		return nil, err
	}

	randBytes := make([]byte, 22)
	if _, err := rand.Read(randBytes); err != nil {
		return nil, fmt.Errorf("generate random key bytes: %w", err)
	}
	randHex := hex.EncodeToString(randBytes)
	shortID := randHex[:8]
	secretPart := randHex[8:]
	rawKey := fmt.Sprintf("sk-gw-%s-%s", shortID, secretPart)

	vk := *req
	if vk.ID == "" {
		vk.ID = uuid.NewString()
	}
	vk.KeyPrefix = fmt.Sprintf("sk-gw-%s", shortID)
	vk.KeyHash = HashKey(rawKey)
	vk.IsActive = true
	if vk.Role == "" {
		vk.Role = domain.RoleServiceAccount
	}
	if vk.BudgetResetPeriod == "" {
		vk.BudgetResetPeriod = domain.BudgetResetMonthly
	}
	if len(vk.AllowedEndpoints) == 0 {
		vk.AllowedEndpoints = append([]string(nil), domain.DefaultAllowedEndpoints...)
	}
	// Confirmed Default: newly provisioned keys default to DenyAll ([]string{}) for MCP and A2A
	if vk.AllowedMCPServers == nil {
		vk.AllowedMCPServers = []string{}
	}
	if vk.AllowedA2AAgents == nil {
		vk.AllowedA2AAgents = []string{}
	}
	if vk.AllowedClientApps == nil {
		vk.AllowedClientApps = []string{}
	}

	if err := s.repo.CreateVirtualKey(ctx, &vk); err != nil {
		return nil, err
	}
	vk.RawKey = rawKey
	return &vk, nil
}

// RevokeKey marks a Virtual Key inactive and immediately evicts it from L1 and L2 caches across all pods.
func (s *Service) RevokeKey(ctx context.Context, id string) error {
	vk, err := s.repo.GetVirtualKeyByID(ctx, id)
	if err != nil {
		return err
	}
	if err := s.repo.RevokeVirtualKey(ctx, id); err != nil {
		return err
	}
	s.InvalidateKeyHash(ctx, vk.KeyHash)
	return nil
}

// InvalidateKeyHash evicts a key from local L1 cache, deletes its L2 Redis key, and broadcasts Pub/Sub eviction.
func (s *Service) InvalidateKeyHash(ctx context.Context, keyHash string) {
	s.l1Cache.Delete(keyHash)
	if s.redis != nil {
		_, _ = s.redis.Execute(func(rdb *redis.Client) (any, error) {
			return rdb.Del(ctx, authCacheKey(keyHash), "gw:auth:key:"+keyHash).Result()
		})
		s.redis.PublishInvalidation(ctx, storage.InvalidationEvent{
			Type:    "key",
			KeyHash: keyHash,
		})
	}
}

func authCacheKey(keyHash string) string {
	return "gw:auth:key:v2:" + keyHash
}

func (s *Service) handleInvalidation(ev storage.InvalidationEvent) {
	if ev.Type == "key" && ev.KeyHash != "" {
		s.l1Cache.Delete(ev.KeyHash)
	}
}

// StartInvalidationListener removes revoked-key identities from this process cache when another replica publishes an event.
func (s *Service) StartInvalidationListener(ctx context.Context) {
	if s.redis == nil || s.redis.Client() == nil {
		return
	}
	s.invalidationMu.Lock()
	if s.invalidationCancel != nil {
		s.invalidationMu.Unlock()
		return
	}
	listenerCtx, cancel := context.WithCancel(ctx)
	s.invalidationCancel = cancel
	s.invalidationMu.Unlock()
	go func() {
		pubsub := s.redis.Client().Subscribe(listenerCtx, storage.InvalidationChannel)
		defer pubsub.Close()
		if _, err := pubsub.Receive(listenerCtx); err != nil {
			return
		}
		messages := pubsub.Channel()
		for {
			select {
			case <-listenerCtx.Done():
				return
			case msg, ok := <-messages:
				if !ok {
					return
				}
				var ev storage.InvalidationEvent
				if err := json.Unmarshal([]byte(msg.Payload), &ev); err == nil {
					s.handleInvalidation(ev)
				}
			}
		}
	}()
}

func (s *Service) StopInvalidationListener() {
	s.invalidationMu.Lock()
	defer s.invalidationMu.Unlock()
	if s.invalidationCancel != nil {
		s.invalidationCancel()
		s.invalidationCancel = nil
	}
}

// InvalidateKeyID invalidates a virtual key by its entity ID, looking up its key hash when available.
func (s *Service) InvalidateKeyID(ctx context.Context, id string) {
	if s.repo != nil {
		if vk, err := s.repo.GetVirtualKeyByID(ctx, id); err == nil && vk != nil && vk.KeyHash != "" {
			s.InvalidateKeyHash(ctx, vk.KeyHash)
			return
		}
	}
	s.l1Cache.Delete(id)
}

// AuthenticateVirtualKey validates a Bearer `sk-gw-...` token using the L1 Memory -> L2 Redis -> Repository hierarchy.
func (s *Service) AuthenticateVirtualKey(ctx context.Context, rawToken string) (*domain.IdentityContext, error) {
	rawToken = strings.TrimSpace(rawToken)
	if rawToken == "" {
		return nil, &domain.GatewayError{
			StatusCode: http.StatusUnauthorized,
			Type:       domain.ErrorTypeAuthentication,
			Code:       "missing_api_key",
			Message:    "Missing Authorization Bearer token (expected virtual key starting with sk-gw-)",
		}
	}

	keyHash := HashKey(rawToken)
	now := time.Now().UTC()

	// 1. Check L1 In-Memory Cache
	if val, ok := s.l1Cache.Load(keyHash); ok {
		entry := val.(l1CacheEntry)
		if now.Before(entry.expiresAt) {
			if isKeyExpired(entry.keyExpiresAt, now) {
				s.l1Cache.Delete(keyHash)
				return nil, expiredVirtualKeyError()
			}
			return entry.identity, nil
		}
		s.l1Cache.Delete(keyHash)
	}

	// 2. Check L2 Redis Cache
	if s.redis != nil {
		res, err := s.redis.Execute(func(rdb *redis.Client) (any, error) {
			return rdb.Get(ctx, authCacheKey(keyHash)).Result()
		})
		if err == nil {
			if jsonStr, ok := res.(string); ok && jsonStr != "" {
				var cached cachedIdentity
				if json.Unmarshal([]byte(jsonStr), &cached) == nil && cached.Identity.VirtualKeyID != "" {
					if isKeyExpired(cached.KeyExpiresAt, now) {
						s.l1Cache.Delete(keyHash)
						return nil, expiredVirtualKeyError()
					}
					idCtx := cached.Identity
					s.l1Cache.Store(keyHash, l1CacheEntry{
						identity:     &idCtx,
						expiresAt:    now.Add(s.l1TTL),
						keyExpiresAt: cached.KeyExpiresAt,
					})
					return &idCtx, nil
				}
			}
		}
	}

	// 3. Query Durable Repository
	vk, err := s.repo.GetVirtualKeyByHash(ctx, keyHash)
	if err != nil || !vk.IsActive {
		// Admin convenience: allow MasterAdminKey on /v1/* Data Plane if an active Organization exists
		if err != nil && s.ValidateAdminKey(rawToken) {
			if org := s.resolveDefaultActiveOrg(ctx); org != nil {
				idCtx := &domain.IdentityContext{
					VirtualKeyID:         "vk_master_admin",
					KeyPrefix:            "master-admin",
					OrgID:                org.ID,
					Role:                 domain.RoleOrgAdmin,
					AllowedEndpoints:     []string{"*"},
					KeyAllowedMCPServers: []string{"*"},
					KeyAllowedA2AAgents:  []string{"*"},
					OrgRPMLimit:          org.RPMLimit,
					OrgTPMLimit:          org.TPMLimit,
					OrgMaxBudgetMicros:   org.MaxBudgetMicros,
					OrgSpentMicros:       org.SpentMicros,
				}
				return idCtx, nil
			}
		}
		return nil, &domain.GatewayError{
			StatusCode: http.StatusUnauthorized,
			Type:       domain.ErrorTypeAuthentication,
			Code:       "invalid_api_key",
			Message:    "Invalid or revoked virtual API key",
		}
	}
	if vk.ExpiresAt != nil && !now.Before(*vk.ExpiresAt) {
		return nil, expiredVirtualKeyError()
	}

	org, err := s.repo.GetOrganization(ctx, vk.OrgID)
	if err != nil || !org.IsActive {
		return nil, &domain.GatewayError{
			StatusCode: http.StatusForbidden,
			Type:       domain.ErrorTypePermission,
			Code:       "organization_inactive",
			Message:    "Organization associated with this virtual key is inactive",
		}
	}

	idCtx := &domain.IdentityContext{
		VirtualKeyID:         vk.ID,
		KeyPrefix:            vk.KeyPrefix,
		OrgID:                vk.OrgID,
		TeamID:               vk.TeamID,
		UserID:               vk.UserID,
		Role:                 vk.Role,
		KeyAllowedModels:     vk.AllowedModels,
		AllowedEndpoints:     vk.AllowedEndpoints,
		KeyAllowedMCPServers: vk.AllowedMCPServers,
		KeyAllowedA2AAgents:  vk.AllowedA2AAgents,
		KeyAllowedClientApps: vk.AllowedClientApps,
		KeyRPMLimit:          vk.RPMLimit,
		KeyTPMLimit:          vk.TPMLimit,
		KeyMaxConcurrent:     vk.MaxConcurrentRequests,
		KeyMaxBudgetMicros:   vk.MaxBudgetMicros,
		KeySpentMicros:       vk.SpentMicros,
		OrgRPMLimit:          org.RPMLimit,
		OrgTPMLimit:          org.TPMLimit,
		OrgMaxBudgetMicros:   org.MaxBudgetMicros,
		OrgSpentMicros:       org.SpentMicros,
	}

	if vk.TeamID != "" {
		team, err := s.repo.GetTeam(ctx, vk.TeamID)
		if err != nil {
			if errors.Is(err, storage.ErrNotFound) {
				return nil, &domain.GatewayError{
					StatusCode: http.StatusForbidden,
					Type:       domain.ErrorTypePermission,
					Code:       "team_not_found",
					Message:    "Team associated with this virtual key was not found",
				}
			}
			return nil, &domain.GatewayError{
				StatusCode: http.StatusServiceUnavailable,
				Type:       domain.ErrorTypeServer,
				Code:       "team_policy_unavailable",
				Message:    "Unable to resolve team policy for this virtual key",
				Retryable:  true,
			}
		}
		if !team.IsActive {
			return nil, &domain.GatewayError{
				StatusCode: http.StatusForbidden,
				Type:       domain.ErrorTypePermission,
				Code:       "team_inactive",
				Message:    "Team associated with this virtual key is inactive",
			}
		}
		idCtx.TeamAllowedModels = team.AllowedModels
		idCtx.TeamAllowedMCPServers = team.AllowedMCPServers
		idCtx.TeamAllowedA2AAgents = team.AllowedA2AAgents
		idCtx.TeamAllowedClientApps = team.AllowedClientApps
		idCtx.TeamRPMLimit = team.RPMLimit
		idCtx.TeamTPMLimit = team.TPMLimit
		idCtx.TeamMaxBudgetMicros = team.MaxBudgetMicros
		idCtx.TeamSpentMicros = team.SpentMicros
	}

	// Hydrate L2 Redis + L1 Memory
	var keyExpiresAt *time.Time
	if vk.ExpiresAt != nil {
		expiresAt := vk.ExpiresAt.UTC()
		keyExpiresAt = &expiresAt
	}
	cacheEntry := cachedIdentity{Identity: *idCtx, KeyExpiresAt: keyExpiresAt}
	if s.redis != nil {
		if b, err := json.Marshal(cacheEntry); err == nil {
			_, _ = s.redis.Execute(func(rdb *redis.Client) (any, error) {
				return rdb.Set(ctx, authCacheKey(keyHash), b, s.l2TTL).Result()
			})
		}
	}
	s.l1Cache.Store(keyHash, l1CacheEntry{
		identity:     idCtx,
		expiresAt:    now.Add(s.l1TTL),
		keyExpiresAt: keyExpiresAt,
	})

	return idCtx, nil
}

func isKeyExpired(expiresAt *time.Time, now time.Time) bool {
	return expiresAt != nil && !now.Before(*expiresAt)
}

func expiredVirtualKeyError() *domain.GatewayError {
	return &domain.GatewayError{
		StatusCode: http.StatusUnauthorized,
		Type:       domain.ErrorTypeAuthentication,
		Code:       "expired_api_key",
		Message:    "Virtual API key has expired",
	}
}

// ValidateAdminKey performs constant-time verification of the Control Plane Master Admin Key.
func (s *Service) ValidateAdminKey(rawToken string) bool {
	rawToken = strings.TrimSpace(rawToken)
	if rawToken == "" || s.masterAdminKey == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(rawToken), []byte(s.masterAdminKey)) == 1
}

// IsMasterCredential performs constant-time detection of any Gateway master credential (admin key or encryption key).
func (s *Service) IsMasterCredential(rawToken string) bool {
	rawToken = strings.TrimSpace(rawToken)
	if rawToken == "" {
		return false
	}
	tokenBytes := []byte(rawToken)
	if s.masterAdminKey != "" && subtle.ConstantTimeCompare(tokenBytes, []byte(s.masterAdminKey)) == 1 {
		return true
	}
	if s.masterEncryptionKey != "" && subtle.ConstantTimeCompare(tokenBytes, []byte(s.masterEncryptionKey)) == 1 {
		return true
	}
	return false
}

func (s *Service) resolveDefaultActiveOrg(ctx context.Context) *domain.Organization {
	if org, err := s.repo.GetOrganization(ctx, "org_default"); err == nil && org != nil && org.IsActive {
		return org
	}
	orgs, err := s.repo.ListOrganizations(ctx)
	if err != nil {
		return nil
	}
	for _, o := range orgs {
		if o != nil && o.IsActive {
			return o
		}
	}
	return nil
}
