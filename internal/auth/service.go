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
	"log/slog"
	"net/http"
	"strconv"
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
	OrgEpoch     int64                  `json:"org_epoch,omitempty"`
	TeamEpoch    int64                  `json:"team_epoch,omitempty"`
}

// Service manages Boundary 1 authentication (Virtual API Keys, L1/L2 caching, and Admin authentication).
type Service struct {
	repo                    storage.Repository
	redis                   *storage.RedisFabric
	masterAdminKey          string
	masterEncryptionKey     string
	allowMasterKeyDataPlane bool
	customAPIKeyHeader      string
	jwtVerifier             *JWTVerifier
	dataPlaneResolver       *AuthResolver
	l1TTL                   time.Duration
	l2TTL                   time.Duration
	l1Cache                 sync.Map // keyHash -> l1CacheEntry
	invalidationMu          sync.Mutex
	invalidationCancel      context.CancelFunc
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

// SetAllowMasterKeyDataPlane controls whether MasterAdminKey can synthesize a fallback identity on data-plane endpoints.
func (s *Service) SetAllowMasterKeyDataPlane(allow bool) {
	s.allowMasterKeyDataPlane = allow
}

// SetJWTVerifier configures inbound JWT/OIDC verification for Control Plane authentication.
func (s *Service) SetJWTVerifier(v *JWTVerifier) {
	s.jwtVerifier = v
}

// JWTVerifier returns the configured JWTVerifier.
func (s *Service) JWTVerifier() *JWTVerifier {
	if s == nil {
		return nil
	}
	return s.jwtVerifier
}

// SetDataPlaneResolver attaches a unified AuthResolver for DataPlaneMiddleware.
func (s *Service) SetDataPlaneResolver(r *AuthResolver) {
	if s != nil {
		s.dataPlaneResolver = r
	}
}

// DataPlaneResolver returns the configured Data Plane AuthResolver, if any.
func (s *Service) DataPlaneResolver() *AuthResolver {
	if s == nil {
		return nil
	}
	return s.dataPlaneResolver
}

// Repo returns the underlying storage.Repository.
func (s *Service) Repo() storage.Repository {
	if s == nil {
		return nil
	}
	return s.repo
}

// AllowMasterKeyDataPlane reports whether MasterAdminKey is allowed on data-plane routes.
func (s *Service) AllowMasterKeyDataPlane() bool {
	return s != nil && s.allowMasterKeyDataPlane
}

// SetCustomAPIKeyHeader configures an optional custom HTTP header name used to extract inbound gateway API keys.
func (s *Service) SetCustomAPIKeyHeader(name string) {
	s.customAPIKeyHeader = strings.TrimSpace(name)
}

// ExtractorOptions returns the inbound credential extraction options configured for this service.
func (s *Service) ExtractorOptions() ExtractorOptions {
	if s == nil {
		return ExtractorOptions{}
	}
	return ExtractorOptions{
		CustomHeaderName: s.customAPIKeyHeader,
	}
}

// HashKey computes the hex-encoded SHA-256 lookup digest for a high-entropy (176-bit)
// gateway Virtual API Key (`sk-gw-...`). Deterministic SHA-256 is required for O(1) indexed
// DB/cache lookup on every inference request and is not used for low-entropy passwords.
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
	if req.TeamID != "" {
		team, err := s.repo.GetTeam(ctx, req.TeamID)
		if err != nil {
			return nil, fmt.Errorf("verify team %q: %w", req.TeamID, err)
		}
		if team.OrgID != req.OrgID {
			return nil, fmt.Errorf("team %q does not belong to organization %q", req.TeamID, req.OrgID)
		}
	}
	if req.UserID != "" {
		user, err := s.lookupUser(ctx, req.OrgID, req.UserID)
		if err != nil {
			if errors.Is(err, storage.ErrNotFound) {
				return nil, fmt.Errorf("user %q does not belong to organization %q", req.UserID, req.OrgID)
			}
			return nil, fmt.Errorf("verify user %q: %w", req.UserID, err)
		}
		if user == nil || user.OrgID != req.OrgID {
			return nil, fmt.Errorf("user %q does not belong to organization %q", req.UserID, req.OrgID)
		}
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
		vk.AllowedEndpoints = []string{"*"}
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

// UpdateVirtualKey updates an existing Virtual Key's metadata/scopes/limits and invalidates its cached identity.
func (s *Service) UpdateVirtualKey(ctx context.Context, vk *domain.VirtualKey) error {
	if vk == nil || strings.TrimSpace(vk.ID) == "" {
		return fmt.Errorf("virtual key id is required")
	}
	existing, err := s.repo.GetVirtualKeyByID(ctx, vk.ID)
	if err != nil {
		return err
	}
	if vk.OrgID == "" {
		vk.OrgID = existing.OrgID
	}
	if vk.KeyHash == "" {
		vk.KeyHash = existing.KeyHash
	}
	if vk.KeyPrefix == "" {
		vk.KeyPrefix = existing.KeyPrefix
	}
	if vk.Role == "" {
		vk.Role = existing.Role
	}
	if vk.BudgetResetPeriod == "" {
		vk.BudgetResetPeriod = existing.BudgetResetPeriod
	}
	if vk.AllowedEndpoints == nil {
		vk.AllowedEndpoints = existing.AllowedEndpoints
	}
	if vk.CreatedAt.IsZero() {
		vk.CreatedAt = existing.CreatedAt
	}
	if vk.TeamID != "" {
		team, err := s.repo.GetTeam(ctx, vk.TeamID)
		if err != nil {
			return fmt.Errorf("verify team %q: %w", vk.TeamID, err)
		}
		if team.OrgID != vk.OrgID {
			return fmt.Errorf("team %q does not belong to organization %q", vk.TeamID, vk.OrgID)
		}
	}
	if vk.UserID != "" {
		user, err := s.lookupUser(ctx, vk.OrgID, vk.UserID)
		if err != nil {
			if errors.Is(err, storage.ErrNotFound) {
				return fmt.Errorf("user %q does not belong to organization %q", vk.UserID, vk.OrgID)
			}
			return fmt.Errorf("verify user %q: %w", vk.UserID, err)
		}
		if user == nil || user.OrgID != vk.OrgID {
			return fmt.Errorf("user %q does not belong to organization %q", vk.UserID, vk.OrgID)
		}
	}
	if err := s.repo.UpdateVirtualKey(ctx, vk); err != nil {
		return err
	}
	if existing.KeyHash != "" {
		s.InvalidateKeyHash(ctx, existing.KeyHash)
	}
	if vk.KeyHash != "" && vk.KeyHash != existing.KeyHash {
		s.InvalidateKeyHash(ctx, vk.KeyHash)
	}
	return nil
}

// RotateVirtualKey generates a new cryptographically random `sk-gw-...` key for an existing VirtualKey,
// updates its key hash and prefix in storage, invalidates the old key hash across L1/L2/PubSub,
// and returns the updated VirtualKey with RawKey populated once.
func (s *Service) RotateVirtualKey(ctx context.Context, id string) (*domain.VirtualKey, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return nil, fmt.Errorf("virtual key id is required")
	}
	existing, err := s.repo.GetVirtualKeyByID(ctx, id)
	if err != nil {
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

	oldHash := existing.KeyHash
	rotated := *existing
	rotated.KeyPrefix = fmt.Sprintf("sk-gw-%s", shortID)
	rotated.KeyHash = HashKey(rawKey)
	rotated.IsActive = true

	if err := s.repo.UpdateVirtualKey(ctx, &rotated); err != nil {
		return nil, err
	}
	if oldHash != "" {
		s.InvalidateKeyHash(ctx, oldHash)
	}
	rotated.RawKey = rawKey
	return &rotated, nil
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
		if _, err := s.redis.Execute(func(rdb redis.UniversalClient) (any, error) {
			return rdb.Del(ctx, authCacheKey(keyHash), "gw:auth:key:"+keyHash).Result()
		}); err != nil {
			slog.WarnContext(ctx, "auth: failed to delete cached key from redis", "error", err)
		}
		s.redis.PublishInvalidation(ctx, storage.InvalidationEvent{
			Type:    "key",
			KeyHash: keyHash,
		})
	}
}

// InvalidateOrg evicts all L1 cached identities for orgID, bumps the L2 org epoch, and broadcasts Pub/Sub eviction.
func (s *Service) InvalidateOrg(ctx context.Context, orgID string) {
	if orgID == "" {
		return
	}
	s.evictL1ByOrg(orgID)
	if s.redis != nil {
		if _, err := s.redis.Execute(func(rdb redis.UniversalClient) (any, error) {
			return rdb.Incr(ctx, orgEpochKey(orgID)).Result()
		}); err != nil {
			slog.WarnContext(ctx, "auth: failed to increment org invalidation epoch", "org_id", orgID, "error", err)
		}
		s.redis.PublishInvalidation(ctx, storage.InvalidationEvent{
			Type:  "org",
			OrgID: orgID,
		})
	}
}

// InvalidateTeam evicts all L1 cached identities for teamID, bumps the L2 team epoch, and broadcasts Pub/Sub eviction.
func (s *Service) InvalidateTeam(ctx context.Context, teamID string) {
	if teamID == "" {
		return
	}
	s.evictL1ByTeam(teamID)
	if s.redis != nil {
		if _, err := s.redis.Execute(func(rdb redis.UniversalClient) (any, error) {
			return rdb.Incr(ctx, teamEpochKey(teamID)).Result()
		}); err != nil {
			slog.WarnContext(ctx, "auth: failed to increment team invalidation epoch", "team_id", teamID, "error", err)
		}
		s.redis.PublishInvalidation(ctx, storage.InvalidationEvent{
			Type:       "team",
			EntityType: "team",
			EntityID:   teamID,
		})
	}
}

func (s *Service) evictL1ByOrg(orgID string) {
	s.l1Cache.Range(func(k, v any) bool {
		if entry, ok := v.(l1CacheEntry); ok && entry.identity != nil && entry.identity.OrgID == orgID {
			s.l1Cache.Delete(k)
		}
		return true
	})
}

func (s *Service) evictL1ByTeam(teamID string) {
	s.l1Cache.Range(func(k, v any) bool {
		if entry, ok := v.(l1CacheEntry); ok && entry.identity != nil && entry.identity.TeamID == teamID {
			s.l1Cache.Delete(k)
		}
		return true
	})
}

func authCacheKey(keyHash string) string {
	return "gw:auth:key:v2:" + keyHash
}

func orgEpochKey(orgID string) string {
	return "gw:auth:org_epoch:" + orgID
}

func teamEpochKey(teamID string) string {
	return "gw:auth:team_epoch:" + teamID
}

func (s *Service) handleInvalidation(ev storage.InvalidationEvent) {
	switch ev.Type {
	case "key":
		if ev.KeyHash != "" {
			s.l1Cache.Delete(ev.KeyHash)
		}
	case "org":
		if ev.OrgID != "" {
			s.evictL1ByOrg(ev.OrgID)
		}
	case "team":
		if ev.EntityID != "" {
			s.evictL1ByTeam(ev.EntityID)
		}
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
		res, err := s.redis.Execute(func(rdb redis.UniversalClient) (any, error) {
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
					orgEpoch, teamEpoch := s.fetchEpochs(ctx, cached.Identity.OrgID, cached.Identity.TeamID)
					if orgEpoch == cached.OrgEpoch && teamEpoch == cached.TeamEpoch {
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
	}

	// 3. Query Durable Repository
	vk, err := s.repo.GetVirtualKeyByHash(ctx, keyHash)
	if err != nil || !vk.IsActive {
		// Admin convenience: allow MasterAdminKey on /v1/* Data Plane only when explicitly enabled
		if err != nil && s.allowMasterKeyDataPlane && s.ValidateAdminKey(rawToken) {
			if org := s.resolveDefaultActiveOrg(ctx); org != nil {
				idCtx := &domain.IdentityContext{
					VirtualKeyID:                "vk_master_admin",
					KeyPrefix:                   "master-admin",
					OrgID:                       org.ID,
					Role:                        domain.RoleOrgAdmin,
					AllowedEndpoints:            []string{"*"},
					KeyAllowedMCPServers:        []string{"*"},
					KeyAllowedA2AAgents:         []string{"*"},
					OrgRPMLimit:                 org.RPMLimit,
					OrgTPMLimit:                 org.TPMLimit,
					OrgMaxConcurrent:            org.MaxConcurrentRequests,
					OrgBatchEnqueuedTokenLimit:  org.BatchEnqueuedTokenLimit,
					OrgMaxBudgetMicros:          org.MaxBudgetMicros,
					OrgSoftBudgetMicros:         org.SoftBudgetMicros,
					OrgThrottleOnBudgetExceeded: org.ThrottleOnBudgetExceeded,
					OrgBudgetFallbacks:          domain.CloneBudgetFallbacks(org.BudgetFallbacks),
					OrgSpentMicros:              org.SpentMicros,
				}
				s.l1Cache.Store(keyHash, l1CacheEntry{
					identity:  idCtx,
					expiresAt: now.Add(s.l1TTL),
				})
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

	idCtx, err := s.resolveVirtualKeyIdentity(ctx, vk)
	if err != nil {
		return nil, err
	}

	// Hydrate L2 Redis + L1 Memory
	var keyExpiresAt *time.Time
	if vk.ExpiresAt != nil {
		expiresAt := vk.ExpiresAt.UTC()
		keyExpiresAt = &expiresAt
	}
	orgEpoch, teamEpoch := s.fetchEpochs(ctx, idCtx.OrgID, idCtx.TeamID)
	cacheEntry := cachedIdentity{
		Identity:     *idCtx,
		KeyExpiresAt: keyExpiresAt,
		OrgEpoch:     orgEpoch,
		TeamEpoch:    teamEpoch,
	}
	if s.redis != nil {
		if b, err := json.Marshal(cacheEntry); err == nil {
			_, _ = s.redis.Execute(func(rdb redis.UniversalClient) (any, error) {
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

// AuthenticateVirtualKeyByID resolves a VirtualKey's full IdentityContext by ID (e.g. from a JWT-to-key mapping).
func (s *Service) AuthenticateVirtualKeyByID(ctx context.Context, id string) (*domain.IdentityContext, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return nil, &domain.GatewayError{
			StatusCode: http.StatusUnauthorized,
			Type:       domain.ErrorTypeAuthentication,
			Code:       "invalid_api_key",
			Message:    "Mapped virtual API key id is empty",
		}
	}
	vk, err := s.repo.GetVirtualKeyByID(ctx, id)
	if err != nil || vk == nil || !vk.IsActive {
		return nil, &domain.GatewayError{
			StatusCode: http.StatusUnauthorized,
			Type:       domain.ErrorTypeAuthentication,
			Code:       "invalid_api_key",
			Message:    "Mapped virtual API key is invalid or revoked",
		}
	}
	if isKeyExpired(vk.ExpiresAt, time.Now().UTC()) {
		return nil, expiredVirtualKeyError()
	}
	return s.resolveVirtualKeyIdentity(ctx, vk)
}

func (s *Service) resolveVirtualKeyIdentity(ctx context.Context, vk *domain.VirtualKey) (*domain.IdentityContext, error) {
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
		VirtualKeyID:                vk.ID,
		KeyPrefix:                   vk.KeyPrefix,
		OrgID:                       vk.OrgID,
		TeamID:                      vk.TeamID,
		UserID:                      vk.UserID,
		Role:                        vk.Role,
		KeyAllowedModels:            vk.AllowedModels,
		AllowedEndpoints:            vk.AllowedEndpoints,
		KeyAllowedMCPServers:        vk.AllowedMCPServers,
		KeyAllowedA2AAgents:         vk.AllowedA2AAgents,
		KeyAllowedClientApps:        vk.AllowedClientApps,
		KeyRPMLimit:                 vk.RPMLimit,
		KeyTPMLimit:                 vk.TPMLimit,
		KeyMaxConcurrent:            vk.MaxConcurrentRequests,
		KeyBatchEnqueuedTokenLimit:  vk.BatchEnqueuedTokenLimit,
		KeyMaxBudgetMicros:          vk.MaxBudgetMicros,
		KeySoftBudgetMicros:         vk.SoftBudgetMicros,
		KeyThrottleOnBudgetExceeded: vk.ThrottleOnBudgetExceeded,
		KeyBudgetFallbacks:          domain.CloneBudgetFallbacks(vk.BudgetFallbacks),
		KeySpentMicros:              vk.SpentMicros,
		OrgRPMLimit:                 org.RPMLimit,
		OrgTPMLimit:                 org.TPMLimit,
		OrgMaxConcurrent:            org.MaxConcurrentRequests,
		OrgBatchEnqueuedTokenLimit:  org.BatchEnqueuedTokenLimit,
		OrgMaxBudgetMicros:          org.MaxBudgetMicros,
		OrgSoftBudgetMicros:         org.SoftBudgetMicros,
		OrgThrottleOnBudgetExceeded: org.ThrottleOnBudgetExceeded,
		OrgBudgetFallbacks:          domain.CloneBudgetFallbacks(org.BudgetFallbacks),
		OrgSpentMicros:              org.SpentMicros,
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
		if team.OrgID != vk.OrgID {
			return nil, &domain.GatewayError{
				StatusCode: http.StatusForbidden,
				Type:       domain.ErrorTypePermission,
				Code:       "team_org_mismatch",
				Message:    "Team associated with this virtual key does not belong to its organization",
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
		idCtx.TeamMaxConcurrent = team.MaxConcurrentRequests
		idCtx.TeamBatchEnqueuedTokenLimit = team.BatchEnqueuedTokenLimit
		idCtx.TeamMaxBudgetMicros = team.MaxBudgetMicros
		idCtx.TeamSoftBudgetMicros = team.SoftBudgetMicros
		idCtx.TeamThrottleOnBudgetExceeded = team.ThrottleOnBudgetExceeded
		idCtx.TeamBudgetFallbacks = domain.CloneBudgetFallbacks(team.BudgetFallbacks)
		idCtx.TeamSpentMicros = team.SpentMicros
	}

	if vk.UserID != "" {
		user, err := s.lookupUser(ctx, vk.OrgID, vk.UserID)
		if err != nil {
			if errors.Is(err, storage.ErrNotFound) || strings.Contains(strings.ToLower(err.Error()), "not found") {
				return nil, &domain.GatewayError{
					StatusCode: http.StatusForbidden,
					Type:       domain.ErrorTypePermission,
					Code:       "user_not_found",
					Message:    "User associated with this virtual key was not found in organization",
				}
			}
			return nil, &domain.GatewayError{
				StatusCode: http.StatusServiceUnavailable,
				Type:       domain.ErrorTypeServer,
				Code:       "user_policy_unavailable",
				Message:    "Unable to resolve user status for this virtual key",
				Retryable:  true,
			}
		}
		if user == nil || user.OrgID != vk.OrgID {
			return nil, &domain.GatewayError{
				StatusCode: http.StatusForbidden,
				Type:       domain.ErrorTypePermission,
				Code:       "user_not_found",
				Message:    "User associated with this virtual key was not found in organization",
			}
		}
		if !user.IsActive {
			return nil, &domain.GatewayError{
				StatusCode: http.StatusForbidden,
				Type:       domain.ErrorTypePermission,
				Code:       "user_inactive",
				Message:    "User associated with this virtual key is inactive",
			}
		}
		idCtx.UserRPMLimit = user.RPMLimit
		idCtx.UserTPMLimit = user.TPMLimit
		idCtx.UserMaxConcurrent = user.MaxConcurrentRequests
		idCtx.UserBatchEnqueuedTokenLimit = user.BatchEnqueuedTokenLimit
		idCtx.UserMaxBudgetMicros = user.MaxBudgetMicros
		idCtx.UserSoftBudgetMicros = user.SoftBudgetMicros
		idCtx.UserThrottleOnBudgetExceeded = user.ThrottleOnBudgetExceeded
		idCtx.UserBudgetFallbacks = domain.CloneBudgetFallbacks(user.BudgetFallbacks)
		idCtx.UserSpentMicros = user.SpentMicros
	}

	return idCtx, nil
}

func (s *Service) lookupUser(ctx context.Context, orgID, userID string) (*domain.User, error) {
	if ul, ok := s.repo.(storage.UserLookupRepository); ok {
		user, err := ul.GetUser(ctx, userID)
		if err != nil {
			return nil, err
		}
		if user == nil || user.OrgID != orgID {
			return nil, storage.ErrNotFound
		}
		return user, nil
	}
	users, err := s.repo.ListUsers(ctx, orgID)
	if err != nil {
		return nil, err
	}
	for _, u := range users {
		if u != nil && u.ID == userID && u.OrgID == orgID {
			return u, nil
		}
	}
	return nil, storage.ErrNotFound
}

func (s *Service) fetchEpochs(ctx context.Context, orgID, teamID string) (int64, int64) {
	if s.redis == nil || orgID == "" {
		return 0, 0
	}
	keys := []string{orgEpochKey(orgID)}
	if teamID != "" {
		keys = append(keys, teamEpochKey(teamID))
	}
	res, err := s.redis.Execute(func(rdb redis.UniversalClient) (any, error) {
		return rdb.MGet(ctx, keys...).Result()
	})
	if err != nil {
		return 0, 0
	}
	vals, ok := res.([]any)
	if !ok || len(vals) == 0 {
		return 0, 0
	}
	var orgEpoch, teamEpoch int64
	if vals[0] != nil {
		if str, ok := vals[0].(string); ok {
			orgEpoch, _ = strconv.ParseInt(str, 10, 64)
		}
	}
	if len(vals) > 1 && vals[1] != nil {
		if str, ok := vals[1].(string); ok {
			teamEpoch, _ = strconv.ParseInt(str, 10, 64)
		}
	}
	return orgEpoch, teamEpoch
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

// AuthenticateOperator resolves an OperatorContext for Control Plane (/admin/v1/*) requests from:
// (a) MasterAdminKey (platform_admin), (b) admin-role VirtualKey, or (c) validated inbound JWT mapped to an active User.
func (s *Service) AuthenticateOperator(ctx context.Context, rawToken string) (*domain.OperatorContext, error) {
	return s.AuthenticateOperatorWithSource(ctx, ExtractedCredentials{
		Token:  rawToken,
		Source: CredentialSourceBearer,
	})
}

// AuthenticateOperatorWithSource resolves an OperatorContext while restricting OIDC/JWT
// verification strictly to Authorization Bearer credentials (never x-api-key headers).
func (s *Service) AuthenticateOperatorWithSource(ctx context.Context, cred ExtractedCredentials) (*domain.OperatorContext, error) {
	rawToken := strings.TrimSpace(cred.Token)
	if rawToken == "" {
		return nil, &domain.GatewayError{
			StatusCode: http.StatusUnauthorized,
			Type:       domain.ErrorTypeAuthentication,
			Code:       "invalid_admin_key",
			Message:    "Valid Master Admin Key, admin Virtual Key, or operator JWT is required to access /admin/v1/* endpoints",
		}
	}

	if s.ValidateAdminKey(rawToken) {
		return &domain.OperatorContext{
			ActorID:    "master_admin",
			Role:       domain.OperatorRolePlatformAdmin,
			AuthMethod: "master_key",
		}, nil
	}

	if strings.HasPrefix(rawToken, "sk-gw-") {
		idCtx, err := s.AuthenticateVirtualKey(ctx, rawToken)
		if err != nil {
			return nil, err
		}
		opRole, ok := mapDomainRoleToOperatorRole(idCtx.Role)
		if !ok {
			return nil, &domain.GatewayError{
				StatusCode: http.StatusForbidden,
				Type:       domain.ErrorTypePermission,
				Code:       "insufficient_permissions",
				Message:    fmt.Sprintf("Virtual key role %q is not authorized for control plane access", idCtx.Role),
			}
		}
		actorID := idCtx.VirtualKeyID
		if idCtx.UserID != "" {
			actorID = idCtx.UserID
		}
		return &domain.OperatorContext{
			ActorID:    actorID,
			Role:       opRole,
			OrgID:      idCtx.OrgID,
			AuthMethod: "virtual_key",
		}, nil
	}

	if cred.Source == CredentialSourceBearer && s.jwtVerifier != nil && s.jwtVerifier.Enabled() && strings.Count(rawToken, ".") == 2 {
		claims, err := s.jwtVerifier.Verify(ctx, rawToken)
		if err != nil {
			return nil, &domain.GatewayError{
				StatusCode: http.StatusUnauthorized,
				Type:       domain.ErrorTypeAuthentication,
				Code:       "invalid_token",
				Message:    "Invalid or expired JWT: " + err.Error(),
			}
		}
		user, err := s.repo.GetUserByOIDCSubject(ctx, claims.Subject)
		if err != nil || user == nil {
			return nil, &domain.GatewayError{
				StatusCode: http.StatusUnauthorized,
				Type:       domain.ErrorTypeAuthentication,
				Code:       "unknown_operator",
				Message:    "No user mapped to JWT subject",
			}
		}
		if !user.IsActive {
			return nil, &domain.GatewayError{
				StatusCode: http.StatusForbidden,
				Type:       domain.ErrorTypePermission,
				Code:       "user_inactive",
				Message:    "Operator user account is inactive",
			}
		}
		org, err := s.repo.GetOrganization(ctx, user.OrgID)
		if err != nil || !org.IsActive {
			return nil, &domain.GatewayError{
				StatusCode: http.StatusForbidden,
				Type:       domain.ErrorTypePermission,
				Code:       "organization_inactive",
				Message:    "Organization associated with this operator is inactive",
			}
		}
		opRole, ok := mapDomainRoleToOperatorRole(user.Role)
		if !ok {
			return nil, &domain.GatewayError{
				StatusCode: http.StatusForbidden,
				Type:       domain.ErrorTypePermission,
				Code:       "insufficient_permissions",
				Message:    fmt.Sprintf("User role %q is not authorized for control plane access", user.Role),
			}
		}
		return &domain.OperatorContext{
			ActorID:    user.ID,
			Role:       opRole,
			OrgID:      user.OrgID,
			AuthMethod: "jwt",
		}, nil
	}

	return nil, &domain.GatewayError{
		StatusCode: http.StatusUnauthorized,
		Type:       domain.ErrorTypeAuthentication,
		Code:       "invalid_admin_key",
		Message:    "Valid Master Admin Key, admin Virtual Key, or operator JWT is required to access /admin/v1/* endpoints",
	}
}

func mapDomainRoleToOperatorRole(role domain.Role) (domain.OperatorRole, bool) {
	switch role {
	case domain.RolePlatformAdmin:
		return domain.OperatorRolePlatformAdmin, true
	case domain.RoleOrgAdmin:
		return domain.OperatorRoleOrgAdmin, true
	case domain.RoleViewer, domain.RoleOrgViewer:
		return domain.OperatorRoleOrgViewer, true
	default:
		return "", false
	}
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
