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
	"maps"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
	"github.com/redis/go-redis/v9"
	"golang.org/x/sync/singleflight"
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
	vault                   *Vault
	allowMasterKeyDataPlane bool
	customAPIKeyHeader      string
	jwtVerifier             *JWTVerifier
	sessionManager          *SessionManager
	loginThrottle           *LoginThrottle
	dataPlaneResolver       *AuthResolver
	l1TTL                   time.Duration
	l2TTL                   time.Duration
	l1Cache                 sync.Map // keyHash -> l1CacheEntry
	authFlight              singleflight.Group
	invalidationSeq         atomic.Uint64
	invalidationMu          sync.Mutex
	invalidationCancel      context.CancelFunc
	nowFn                   func() time.Time
	invalidationHandlers    []func(storage.InvalidationEvent)
}

// NewService creates a virtual-key and identity authentication Service with L1/L2 caching.
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

// SetNowFunc overrides the clock used by Service (intended for deterministic tests).
func (s *Service) SetNowFunc(fn func() time.Time) {
	if s != nil {
		s.nowFn = fn
	}
}

func (s *Service) now() time.Time {
	if s != nil && s.nowFn != nil {
		return s.nowFn().UTC()
	}
	return time.Now().UTC()
}

// SetMasterEncryptionKey configures the master encryption key used for secret isolation and self-credential checks.
func (s *Service) SetMasterEncryptionKey(key string) {
	s.masterEncryptionKey = strings.TrimSpace(key)
	if s.vault == nil && len(s.masterEncryptionKey) >= 32 {
		if v, err := NewVault(s.masterEncryptionKey); err == nil {
			s.vault = v
		}
	}
}

// SetVault attaches the envelope encryption Vault used to encrypt staged replacement credentials.
func (s *Service) SetVault(v *Vault) {
	if s != nil {
		s.vault = v
	}
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

// SetSessionManager configures Control Plane operator session issuance and verification.
func (s *Service) SetSessionManager(sm *SessionManager) {
	if s != nil {
		s.sessionManager = sm
	}
}

// SessionManager returns the configured SessionManager, if any.
func (s *Service) SessionManager() *SessionManager {
	if s == nil {
		return nil
	}
	return s.sessionManager
}

// SetLoginThrottle configures brute-force login throttling.
func (s *Service) SetLoginThrottle(t *LoginThrottle) {
	if s != nil {
		s.loginThrottle = t
	}
}

// LoginThrottle returns the configured LoginThrottle, if any.
func (s *Service) LoginThrottle() *LoginThrottle {
	if s == nil {
		return nil
	}
	return s.loginThrottle
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
	if req == nil || req.OrgID == "" {
		return nil, fmt.Errorf("org_id is required to issue a virtual key")
	}
	if !IsValidKeyType(req.KeyType) {
		return nil, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "invalid_key_type",
			Message:    fmt.Sprintf("unsupported key_type %q", req.KeyType),
		}
	}
	if req.RotationIntervalSec < 0 {
		return nil, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "invalid_rotation_interval",
			Message:    "rotation_interval_sec cannot be negative",
		}
	}
	if _, err := s.repo.GetOrganization(ctx, req.OrgID); err != nil {
		return nil, err
	}

	vk := *req
	vk.TeamID = strings.TrimSpace(vk.TeamID)
	vk.ProjectID = strings.TrimSpace(vk.ProjectID)
	vk.UserID = strings.TrimSpace(vk.UserID)
	ApplyKeyTypePreset(&vk)

	if vk.ProjectID != "" {
		pmRepo, ok := s.repo.(storage.ProjectAndMembershipRepository)
		if !ok || pmRepo == nil {
			return nil, fmt.Errorf("repository does not support projects")
		}
		proj, err := pmRepo.GetProject(ctx, vk.ProjectID)
		if err != nil {
			return nil, fmt.Errorf("verify project %q: %w", vk.ProjectID, err)
		}
		if proj.OrgID != vk.OrgID {
			return nil, fmt.Errorf("project %q does not belong to organization %q", vk.ProjectID, vk.OrgID)
		}
		if vk.TeamID == "" {
			vk.TeamID = proj.TeamID
		} else if proj.TeamID != vk.TeamID {
			return nil, fmt.Errorf("project %q does not belong to team %q", vk.ProjectID, vk.TeamID)
		}
	}
	if vk.TeamID != "" {
		team, err := s.repo.GetTeam(ctx, vk.TeamID)
		if err != nil {
			return nil, fmt.Errorf("verify team %q: %w", vk.TeamID, err)
		}
		if team.OrgID != vk.OrgID {
			return nil, fmt.Errorf("team %q does not belong to organization %q", vk.TeamID, vk.OrgID)
		}
	}
	if vk.UserID != "" {
		user, err := s.lookupUser(ctx, vk.OrgID, vk.UserID)
		if err != nil {
			if errors.Is(err, storage.ErrNotFound) {
				return nil, fmt.Errorf("user %q does not belong to organization %q", vk.UserID, vk.OrgID)
			}
			return nil, fmt.Errorf("verify user %q: %w", vk.UserID, err)
		}
		if user == nil || user.OrgID != vk.OrgID {
			return nil, fmt.Errorf("user %q does not belong to organization %q", vk.UserID, vk.OrgID)
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
	if vk.RotationIntervalSec > 0 && vk.KeyRotationAt == nil {
		nextRotation := s.now().Add(time.Duration(vk.RotationIntervalSec) * time.Second)
		vk.KeyRotationAt = &nextRotation
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
	if vk.KeyType != "" && !IsValidKeyType(vk.KeyType) {
		return &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "invalid_key_type",
			Message:    fmt.Sprintf("unsupported key_type %q", vk.KeyType),
		}
	}
	if vk.RotationIntervalSec < 0 {
		return &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "invalid_rotation_interval",
			Message:    "rotation_interval_sec cannot be negative",
		}
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
	if vk.KeyType == "" {
		vk.KeyType = NormalizeKeyType(existing.KeyType)
	} else {
		vk.KeyType = NormalizeKeyType(vk.KeyType)
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
	if vk.StagedKeyHash == "" {
		vk.StagedKeyHash = existing.StagedKeyHash
		vk.StagedKeyPrefix = existing.StagedKeyPrefix
		vk.StagedEncryptedRawKey = existing.StagedEncryptedRawKey
		vk.StagedKeyDEK = existing.StagedKeyDEK
		if vk.StagedCreatedAt == nil {
			vk.StagedCreatedAt = existing.StagedCreatedAt
		}
	}
	vk.TeamID = strings.TrimSpace(vk.TeamID)
	vk.ProjectID = strings.TrimSpace(vk.ProjectID)
	vk.UserID = strings.TrimSpace(vk.UserID)
	if vk.ProjectID != "" {
		pmRepo, ok := s.repo.(storage.ProjectAndMembershipRepository)
		if !ok || pmRepo == nil {
			return fmt.Errorf("repository does not support projects")
		}
		proj, err := pmRepo.GetProject(ctx, vk.ProjectID)
		if err != nil {
			return fmt.Errorf("verify project %q: %w", vk.ProjectID, err)
		}
		if proj.OrgID != vk.OrgID {
			return fmt.Errorf("project %q does not belong to organization %q", vk.ProjectID, vk.OrgID)
		}
		if vk.TeamID == "" {
			vk.TeamID = proj.TeamID
		} else if proj.TeamID != vk.TeamID {
			return fmt.Errorf("project %q does not belong to team %q", vk.ProjectID, vk.TeamID)
		}
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
	s.invalidateDeprecatedKeyHashes(ctx, vk.ID, existing.KeyHash, vk.KeyHash, !vk.IsActive)
	return nil
}

// RotateVirtualKey generates a new cryptographically random `sk-gw-...` key for an existing VirtualKey,
// updates its key hash and prefix in storage, immediately invalidates the old key hash across L1/L2/PubSub,
// and returns the updated VirtualKey with RawKey populated once.
func (s *Service) RotateVirtualKey(ctx context.Context, id string) (*domain.VirtualKey, error) {
	return s.RotateVirtualKeyWithGrace(ctx, id, 0)
}

// RevokeKey marks a Virtual Key inactive and immediately evicts it (and any deprecated grace hashes)
// from L1 and L2 caches across all pods.
func (s *Service) RevokeKey(ctx context.Context, id string) error {
	return s.RevokeKeyWithActor(ctx, id, "")
}

// RevokeKeyWithActor marks a Virtual Key inactive with actor attribution and immediately evicts caches.
func (s *Service) RevokeKeyWithActor(ctx context.Context, id, revokedBy string) error {
	vk, err := s.repo.GetVirtualKeyByID(ctx, id)
	if err != nil {
		return err
	}
	if govRepo, ok := s.repo.(storage.KeyGovernanceRepository); ok && govRepo != nil {
		if err := govRepo.RevokeVirtualKeyWithActor(ctx, id, revokedBy); err != nil {
			return err
		}
	} else if err := s.repo.RevokeVirtualKey(ctx, id); err != nil {
		return err
	}
	s.InvalidateKeyHash(ctx, vk.KeyHash)
	s.invalidateDeprecatedKeyHashes(ctx, id, vk.KeyHash, "", true)
	return nil
}

func (s *Service) invalidateDeprecatedKeyHashes(ctx context.Context, keyID, skipHashA, skipHashB string, deleteRows bool) {
	if s == nil || s.repo == nil || strings.TrimSpace(keyID) == "" {
		return
	}
	var hashes []string
	if deleteRows {
		if depRev, ok := s.repo.(storage.DeprecatedKeyRevocationRepository); ok && depRev != nil {
			hashes, _ = depRev.DeleteDeprecatedVirtualKeyHashesByKeyID(ctx, keyID)
		}
	} else {
		if depLookup, ok := s.repo.(storage.DeprecatedKeyLookupRepository); ok && depLookup != nil {
			hashes, _ = depLookup.ListDeprecatedVirtualKeyHashesByKeyID(ctx, keyID)
		}
	}
	for _, h := range hashes {
		if h != "" && h != skipHashA && h != skipHashB {
			s.InvalidateKeyHash(ctx, h)
		}
	}
}

// InvalidateKeyHash evicts a key from local L1 cache, deletes its L2 Redis key, and broadcasts Pub/Sub eviction.
func (s *Service) InvalidateKeyHash(ctx context.Context, keyHash string) {
	s.invalidationSeq.Add(1)
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
	s.invalidationSeq.Add(1)
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
	s.invalidationSeq.Add(1)
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

// AddInvalidationHandler registers an additional handler (such as RBACEngine.HandleInvalidation)
// to receive Redis Pub/Sub invalidation events observed by StartInvalidationListener.
func (s *Service) AddInvalidationHandler(fn func(storage.InvalidationEvent)) {
	if s == nil || fn == nil {
		return
	}
	s.invalidationMu.Lock()
	defer s.invalidationMu.Unlock()
	s.invalidationHandlers = append(s.invalidationHandlers, fn)
}

func (s *Service) handleInvalidation(ev storage.InvalidationEvent) {
	s.invalidationSeq.Add(1)
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
	case "vault_kek_rotated":
		slog.Warn("auth: master KEK rotated by peer gateway instance; roll peer instances with the updated master encryption key",
			"source_pod", ev.EntityID)
	}

	s.invalidationMu.Lock()
	handlers := make([]func(storage.InvalidationEvent), len(s.invalidationHandlers))
	copy(handlers, s.invalidationHandlers)
	s.invalidationMu.Unlock()
	for _, h := range handlers {
		h(ev)
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

// StopInvalidationListener terminates the background Redis Pub/Sub invalidation listener.
func (s *Service) StopInvalidationListener() {
	s.invalidationMu.Lock()
	defer s.invalidationMu.Unlock()
	if s.invalidationCancel != nil {
		s.invalidationCancel()
		s.invalidationCancel = nil
	}
}

// InvalidateKeyID invalidates a virtual key (and any deprecated grace hashes) by its entity ID.
func (s *Service) InvalidateKeyID(ctx context.Context, id string) {
	var activeHash string
	if s.repo != nil {
		if vk, err := s.repo.GetVirtualKeyByID(ctx, id); err == nil && vk != nil && vk.KeyHash != "" {
			activeHash = vk.KeyHash
			s.InvalidateKeyHash(ctx, activeHash)
		}
	}
	s.invalidateDeprecatedKeyHashes(ctx, id, activeHash, "", false)
	if activeHash == "" {
		s.l1Cache.Delete(id)
	}
}

// InvalidateUserKeys immediately evicts all virtual keys belonging to userID from L1,
// L2 Redis, and Pub/Sub across pods, and bumps the organization invalidation epoch.
func (s *Service) InvalidateUserKeys(ctx context.Context, orgID, userID string) {
	if s == nil {
		return
	}
	userID = strings.TrimSpace(userID)
	orgID = strings.TrimSpace(orgID)
	if s.repo != nil && userID != "" {
		var keys []*domain.VirtualKey
		if scimRepo, ok := s.repo.(storage.SCIMRepository); ok && scimRepo != nil {
			keys, _ = scimRepo.ListVirtualKeysByUserID(ctx, orgID, userID)
		} else if orgID != "" {
			if allKeys, err := s.repo.ListVirtualKeys(ctx, orgID); err == nil {
				for _, k := range allKeys {
					if k != nil && k.UserID == userID {
						keys = append(keys, k)
					}
				}
			}
		}
		for _, vk := range keys {
			if vk == nil {
				continue
			}
			if vk.KeyHash != "" {
				s.InvalidateKeyHash(ctx, vk.KeyHash)
			}
			s.invalidateDeprecatedKeyHashes(ctx, vk.ID, vk.KeyHash, "", false)
		}
	}
	if userID != "" {
		s.l1Cache.Range(func(k, v any) bool {
			if entry, ok := v.(l1CacheEntry); ok && entry.identity != nil && entry.identity.UserID == userID && (orgID == "" || entry.identity.OrgID == orgID) {
				s.l1Cache.Delete(k)
			}
			return true
		})
	}
	if orgID != "" {
		s.InvalidateOrg(ctx, orgID)
	}
}

// AuthenticateVirtualKey validates a Bearer `sk-gw-...` token using the L1 Memory -> L2 Redis -> Repository hierarchy.
// Concurrent misses for the same keyHash are collapsed via singleflight and guarded by a pre-read invalidation lease
// so stale DB reads never overwrite concurrent revocations or rotations.
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
	now := s.now()

	// 1. Check L1 In-Memory Cache (lock-free fast path)
	if idCtx, err, hit := s.loadL1Identity(keyHash, now); hit {
		return idCtx, err
	}

	if ctxErr := ctx.Err(); ctxErr != nil {
		return nil, ctxErr
	}

	// 2. Collapse concurrent L2/DB misses per keyHash via singleflight.
	lookupCtx := context.WithoutCancel(ctx)
	if _, hasDeadline := lookupCtx.Deadline(); !hasDeadline {
		var cancel context.CancelFunc
		lookupCtx, cancel = context.WithTimeout(lookupCtx, 10*time.Second)
		defer cancel()
	}

	val, err, _ := s.authFlight.Do(keyHash, func() (any, error) {
		now := s.now()
		if idCtx, l1Err, hit := s.loadL1Identity(keyHash, now); hit {
			if l1Err != nil {
				return nil, l1Err
			}
			return idCtx, nil
		}

		// Check L2 Redis Cache
		if s.redis != nil {
			res, rErr := s.redis.Execute(func(rdb redis.UniversalClient) (any, error) {
				return rdb.Get(lookupCtx, authCacheKey(keyHash)).Result()
			})
			if rErr == nil {
				if jsonStr, ok := res.(string); ok && jsonStr != "" {
					var cached cachedIdentity
					if json.Unmarshal([]byte(jsonStr), &cached) == nil && cached.Identity.VirtualKeyID != "" {
						if isKeyExpired(cached.KeyExpiresAt, now) {
							s.l1Cache.Delete(keyHash)
							return nil, expiredVirtualKeyError()
						}
						deprecatedExpired := cached.Identity.DeprecatedKeyRevokeAt != nil && !now.Before(*cached.Identity.DeprecatedKeyRevokeAt)
						if !deprecatedExpired {
							orgEpoch, teamEpoch := s.fetchEpochs(lookupCtx, cached.Identity.OrgID, cached.Identity.TeamID)
							if orgEpoch == cached.OrgEpoch && teamEpoch == cached.TeamEpoch {
								idCtx := cached.Identity
								l1Exp := now.Add(s.l1TTL)
								if idCtx.DeprecatedKeyRevokeAt != nil && idCtx.DeprecatedKeyRevokeAt.Before(l1Exp) {
									l1Exp = *idCtx.DeprecatedKeyRevokeAt
								}
								s.l1Cache.Store(keyHash, l1CacheEntry{
									identity:     &idCtx,
									expiresAt:    l1Exp,
									keyExpiresAt: cached.KeyExpiresAt,
								})
								return &idCtx, nil
							}
						}
					}
				}
			}
		}

		// Capture pre-read invalidation lease before hitting durable storage.
		preSeq := s.invalidationSeq.Load()

		var (
			vk                 *domain.VirtualKey
			idCtx              *domain.IdentityContext
			deprecatedRevokeAt *time.Time
			lookupErr          error
		)
		if bundleRepo, ok := s.repo.(storage.VirtualKeyBundleLookup); ok && bundleRepo != nil {
			var bundle *storage.VirtualKeyAuthBundle
			bundle, lookupErr = bundleRepo.GetVirtualKeyAuthBundleByHash(lookupCtx, keyHash, now)
			if lookupErr == nil && bundle != nil && bundle.Key != nil {
				vk = bundle.Key
				if bundle.Deprecated && !bundle.DeprecatedKeyRevokeAt.IsZero() {
					revUTC := bundle.DeprecatedKeyRevokeAt.UTC()
					deprecatedRevokeAt = &revUTC
				}
				if vk.IsActive {
					if vk.ExpiresAt != nil && !now.Before(*vk.ExpiresAt) {
						return nil, expiredVirtualKeyError()
					}
					idCtx, lookupErr = s.identityFromAuthBundle(vk, bundle)
					if lookupErr == nil && deprecatedRevokeAt != nil {
						idCtx.DeprecatedKeyRevokeAt = deprecatedRevokeAt
					}
				}
			}
		} else {
			vk, lookupErr = s.repo.GetVirtualKeyByHash(lookupCtx, keyHash)
			if lookupErr != nil {
				if rotRepo, ok := s.repo.(storage.KeyRotationRepository); ok && rotRepo != nil {
					if depVK, revokeAt, depErr := rotRepo.GetActiveDeprecatedVirtualKey(lookupCtx, keyHash, now); depErr == nil && depVK != nil && now.Before(revokeAt) {
						vk = depVK
						lookupErr = nil
						revUTC := revokeAt.UTC()
						deprecatedRevokeAt = &revUTC
					}
				}
			}
			if lookupErr == nil && vk != nil && vk.IsActive {
				if vk.ExpiresAt != nil && !now.Before(*vk.ExpiresAt) {
					return nil, expiredVirtualKeyError()
				}
				idCtx, lookupErr = s.resolveVirtualKeyIdentity(lookupCtx, vk)
				if lookupErr == nil && deprecatedRevokeAt != nil {
					idCtx.DeprecatedKeyRevokeAt = deprecatedRevokeAt
				}
			}
		}

		if lookupErr != nil && idCtx == nil {
			// Preserve explicit permission/availability GatewayErrors from bundle resolution (e.g. org inactive).
			var gwErr *domain.GatewayError
			if errors.As(lookupErr, &gwErr) {
				return nil, gwErr
			}
			// Admin convenience: allow MasterAdminKey on /v1/* Data Plane only when explicitly enabled
			if s.allowMasterKeyDataPlane && s.ValidateAdminKey(rawToken) {
				if org := s.resolveDefaultActiveOrg(lookupCtx); org != nil {
					masterCtx := &domain.IdentityContext{
						VirtualKeyID:                "vk_master_admin",
						KeyPrefix:                   "master-admin",
						OrgID:                       org.ID,
						Role:                        domain.RoleOrgAdmin,
						KeyType:                     domain.KeyTypeDefault,
						SCIMActive:                  true,
						CanImpersonate:              true,
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
					if s.invalidationSeq.Load() == preSeq {
						s.l1Cache.Store(keyHash, l1CacheEntry{
							identity:  masterCtx,
							expiresAt: now.Add(s.l1TTL),
						})
					}
					return masterCtx, nil
				}
			}
			return nil, &domain.GatewayError{
				StatusCode: http.StatusUnauthorized,
				Type:       domain.ErrorTypeAuthentication,
				Code:       "invalid_api_key",
				Message:    "Invalid or revoked virtual API key",
			}
		}

		if vk == nil || !vk.IsActive || idCtx == nil {
			return nil, &domain.GatewayError{
				StatusCode: http.StatusUnauthorized,
				Type:       domain.ErrorTypeAuthentication,
				Code:       "invalid_api_key",
				Message:    "Invalid or revoked virtual API key",
			}
		}

		var keyExpiresAt *time.Time
		if vk.ExpiresAt != nil {
			expiresAt := vk.ExpiresAt.UTC()
			keyExpiresAt = &expiresAt
		}
		l1ExpiresAt := now.Add(s.l1TTL)
		l2TTL := s.l2TTL
		if deprecatedRevokeAt != nil {
			remaining := deprecatedRevokeAt.Sub(now)
			if remaining <= 0 {
				return nil, &domain.GatewayError{
					StatusCode: http.StatusUnauthorized,
					Type:       domain.ErrorTypeAuthentication,
					Code:       "invalid_api_key",
					Message:    "Invalid or revoked virtual API key",
				}
			}
			if deprecatedRevokeAt.Before(l1ExpiresAt) {
				l1ExpiresAt = *deprecatedRevokeAt
			}
			if remaining < l2TTL {
				l2TTL = remaining
			}
		}

		// Anti-stampede lease guard: skip cache write if an invalidation landed during the DB read.
		if s.invalidationSeq.Load() == preSeq {
			orgEpoch, teamEpoch := s.fetchEpochs(lookupCtx, idCtx.OrgID, idCtx.TeamID)
			cacheEntry := cachedIdentity{
				Identity:     *idCtx,
				KeyExpiresAt: keyExpiresAt,
				OrgEpoch:     orgEpoch,
				TeamEpoch:    teamEpoch,
			}
			if s.redis != nil && l2TTL > 0 {
				if b, mErr := json.Marshal(cacheEntry); mErr == nil {
					_, _ = s.redis.Execute(func(rdb redis.UniversalClient) (any, error) {
						return rdb.Set(lookupCtx, authCacheKey(keyHash), b, l2TTL).Result()
					})
				}
			}
			s.l1Cache.Store(keyHash, l1CacheEntry{
				identity:     idCtx,
				expiresAt:    l1ExpiresAt,
				keyExpiresAt: keyExpiresAt,
			})
		}

		return idCtx, nil
	})
	if err != nil {
		return nil, err
	}
	idCtx, ok := val.(*domain.IdentityContext)
	if !ok || idCtx == nil {
		return nil, &domain.GatewayError{
			StatusCode: http.StatusUnauthorized,
			Type:       domain.ErrorTypeAuthentication,
			Code:       "invalid_api_key",
			Message:    "Invalid or revoked virtual API key",
		}
	}
	return idCtx, nil
}

func (s *Service) loadL1Identity(keyHash string, now time.Time) (*domain.IdentityContext, error, bool) {
	val, ok := s.l1Cache.Load(keyHash)
	if !ok {
		return nil, nil, false
	}
	entry := val.(l1CacheEntry)
	if !now.Before(entry.expiresAt) {
		s.l1Cache.Delete(keyHash)
		return nil, nil, false
	}
	if isKeyExpired(entry.keyExpiresAt, now) {
		s.l1Cache.Delete(keyHash)
		return nil, expiredVirtualKeyError(), true
	}
	if entry.identity != nil && entry.identity.DeprecatedKeyRevokeAt != nil && !now.Before(*entry.identity.DeprecatedKeyRevokeAt) {
		s.l1Cache.Delete(keyHash)
		return nil, nil, false
	}
	return entry.identity, nil, true
}

func (s *Service) identityFromAuthBundle(vk *domain.VirtualKey, bundle *storage.VirtualKeyAuthBundle) (*domain.IdentityContext, error) {
	if bundle == nil || bundle.Org == nil || !bundle.Org.IsActive {
		return nil, &domain.GatewayError{
			StatusCode: http.StatusForbidden,
			Type:       domain.ErrorTypePermission,
			Code:       "organization_inactive",
			Message:    "Organization associated with this virtual key is inactive",
		}
	}
	org := bundle.Org
	var keyRotationAt *time.Time
	if vk.KeyRotationAt != nil {
		t := vk.KeyRotationAt.UTC()
		keyRotationAt = &t
	}
	idCtx := &domain.IdentityContext{
		VirtualKeyID:                 vk.ID,
		KeyPrefix:                    vk.KeyPrefix,
		OrgID:                        vk.OrgID,
		TeamID:                       vk.TeamID,
		ProjectID:                    vk.ProjectID,
		UserID:                       vk.UserID,
		Role:                         vk.Role,
		KeyType:                      NormalizeKeyType(vk.KeyType),
		SCIMActive:                   true,
		CanImpersonate:               vk.CanImpersonate,
		RotationIntervalSec:          vk.RotationIntervalSec,
		KeyRotationAt:                keyRotationAt,
		KeyAllowedModels:             vk.AllowedModels,
		AllowedEndpoints:             vk.AllowedEndpoints,
		KeyAllowedMCPServers:         vk.AllowedMCPServers,
		KeyAllowedA2AAgents:          vk.AllowedA2AAgents,
		KeyAllowedClientApps:         vk.AllowedClientApps,
		KeyRPMLimit:                  vk.RPMLimit,
		KeyTPMLimit:                  vk.TPMLimit,
		KeyMCPRPMLimit:               vk.MCPRPMLimit,
		KeyMaxConcurrent:             vk.MaxConcurrentRequests,
		KeyBatchEnqueuedTokenLimit:   vk.BatchEnqueuedTokenLimit,
		KeyMaxIterations:             vk.MaxIterations,
		KeyMaxBudgetPerSessionMicros: vk.MaxBudgetPerSessionMicros,
		KeyMinPriorityRank:           vk.MinPriorityRank,
		KeyAllowedRoutingTags:        slices.Clone(vk.AllowedRoutingTags),
		KeyTags:                      slices.Clone(vk.Tags),
		KeyMetadata:                  maps.Clone(vk.Metadata),
		KeyMaxBudgetMicros:           vk.MaxBudgetMicros,
		KeyTempBudgetIncreaseMicros:  vk.TempBudgetIncreaseMicros,
		KeyTempBudgetExpiresAt:       vk.TempBudgetExpiresAt,
		KeySoftBudgetMicros:          vk.SoftBudgetMicros,
		KeyThrottleOnBudgetExceeded:  vk.ThrottleOnBudgetExceeded,
		KeyBudgetFallbacks:           domain.CloneBudgetFallbacks(vk.BudgetFallbacks),
		KeySpentMicros:               vk.SpentMicros,
		OrgRPMLimit:                  org.RPMLimit,
		OrgTPMLimit:                  org.TPMLimit,
		OrgMaxConcurrent:             org.MaxConcurrentRequests,
		OrgBatchEnqueuedTokenLimit:   org.BatchEnqueuedTokenLimit,
		OrgMaxIterations:             org.MaxIterations,
		OrgMaxBudgetPerSessionMicros: org.MaxBudgetPerSessionMicros,
		OrgMaxBudgetMicros:           org.MaxBudgetMicros,
		OrgTempBudgetIncreaseMicros:  org.TempBudgetIncreaseMicros,
		OrgTempBudgetExpiresAt:       org.TempBudgetExpiresAt,
		OrgSoftBudgetMicros:          org.SoftBudgetMicros,
		OrgThrottleOnBudgetExceeded:  org.ThrottleOnBudgetExceeded,
		OrgBudgetFallbacks:           domain.CloneBudgetFallbacks(org.BudgetFallbacks),
		OrgSpentMicros:               org.SpentMicros,
	}

	if vk.ProjectID != "" {
		proj := bundle.Project
		if proj == nil {
			return nil, &domain.GatewayError{
				StatusCode: http.StatusForbidden,
				Type:       domain.ErrorTypePermission,
				Code:       "project_not_found",
				Message:    "Project associated with this virtual key was not found",
			}
		}
		if proj.OrgID != vk.OrgID {
			return nil, &domain.GatewayError{
				StatusCode: http.StatusForbidden,
				Type:       domain.ErrorTypePermission,
				Code:       "project_org_mismatch",
				Message:    "Project associated with this virtual key does not belong to its organization",
			}
		}
		if vk.TeamID != "" && proj.TeamID != vk.TeamID {
			return nil, &domain.GatewayError{
				StatusCode: http.StatusForbidden,
				Type:       domain.ErrorTypePermission,
				Code:       "project_team_mismatch",
				Message:    "Project associated with this virtual key does not belong to its team",
			}
		}
		if !proj.IsActive {
			return nil, &domain.GatewayError{
				StatusCode: http.StatusForbidden,
				Type:       domain.ErrorTypePermission,
				Code:       "project_inactive",
				Message:    "Project associated with this virtual key is inactive",
			}
		}
		if idCtx.TeamID == "" {
			idCtx.TeamID = proj.TeamID
		}
		idCtx.ProjectAllowedModels = slices.Clone(proj.AllowedModels)
		idCtx.ProjectMaxBudgetMicros = proj.MaxBudgetMicros
		idCtx.ProjectSpentMicros = proj.SpentMicros
		idCtx.ProjectRPMLimit = proj.RPMLimit
		idCtx.ProjectTPMLimit = proj.TPMLimit
		idCtx.ProjectEnforceModelQuota = proj.EnforceProjectModelQuota
	}

	if idCtx.TeamID != "" {
		team := bundle.Team
		if team == nil && idCtx.TeamID != vk.TeamID {
			if t, err := s.repo.GetTeam(context.Background(), idCtx.TeamID); err == nil {
				team = t
			}
		}
		if team == nil {
			return nil, &domain.GatewayError{
				StatusCode: http.StatusForbidden,
				Type:       domain.ErrorTypePermission,
				Code:       "team_not_found",
				Message:    "Team associated with this virtual key was not found",
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
		idCtx.TeamMinPriorityRank = team.MinPriorityRank
		idCtx.TeamAllowedRoutingTags = slices.Clone(team.AllowedRoutingTags)
		idCtx.TeamRPMLimit = team.RPMLimit
		idCtx.TeamTPMLimit = team.TPMLimit
		idCtx.TeamMCPRPMLimit = team.MCPRPMLimit
		idCtx.TeamMaxConcurrent = team.MaxConcurrentRequests
		idCtx.TeamBatchEnqueuedTokenLimit = team.BatchEnqueuedTokenLimit
		idCtx.TeamMaxIterations = team.MaxIterations
		idCtx.TeamMaxBudgetPerSessionMicros = team.MaxBudgetPerSessionMicros
		idCtx.TeamMaxBudgetMicros = team.MaxBudgetMicros
		idCtx.TeamTempBudgetIncreaseMicros = team.TempBudgetIncreaseMicros
		idCtx.TeamTempBudgetExpiresAt = team.TempBudgetExpiresAt
		idCtx.TeamSoftBudgetMicros = team.SoftBudgetMicros
		idCtx.TeamThrottleOnBudgetExceeded = team.ThrottleOnBudgetExceeded
		idCtx.TeamBudgetFallbacks = domain.CloneBudgetFallbacks(team.BudgetFallbacks)
		idCtx.TeamSpentMicros = team.SpentMicros
	}

	if vk.UserID != "" {
		user := bundle.User
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
		if !user.SCIMActive {
			return nil, &domain.GatewayError{
				StatusCode: http.StatusForbidden,
				Type:       domain.ErrorTypePermission,
				Code:       "scim_deprovisioned",
				Message:    "User associated with this virtual key has been deprovisioned via SCIM",
			}
		}
		idCtx.SCIMActive = user.SCIMActive
		idCtx.UserRPMLimit = user.RPMLimit
		idCtx.UserTPMLimit = user.TPMLimit
		idCtx.UserMaxConcurrent = user.MaxConcurrentRequests
		idCtx.UserBatchEnqueuedTokenLimit = user.BatchEnqueuedTokenLimit
		idCtx.UserMaxBudgetMicros = user.MaxBudgetMicros
		idCtx.UserTempBudgetIncreaseMicros = user.TempBudgetIncreaseMicros
		idCtx.UserTempBudgetExpiresAt = user.TempBudgetExpiresAt
		idCtx.UserSoftBudgetMicros = user.SoftBudgetMicros
		idCtx.UserThrottleOnBudgetExceeded = user.ThrottleOnBudgetExceeded
		idCtx.UserBudgetFallbacks = domain.CloneBudgetFallbacks(user.BudgetFallbacks)
		idCtx.UserSpentMicros = user.SpentMicros

		if idCtx.TeamID != "" && bundle.TeamMembership != nil {
			m := bundle.TeamMembership
			if m.OrgID == vk.OrgID && m.TeamID == idCtx.TeamID {
				idCtx.TeamMemberAllowedModels = slices.Clone(m.AllowedModels)
				idCtx.TeamMemberMaxBudgetMicros = m.MaxBudgetMicros
				idCtx.TeamMemberSpentMicros = m.SpentMicros
				idCtx.TeamMemberRPMLimit = m.RPMLimit
				idCtx.TeamMemberTPMLimit = m.TPMLimit
			}
		}
	}
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
	if isKeyExpired(vk.ExpiresAt, s.now()) {
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

	var keyRotationAt *time.Time
	if vk.KeyRotationAt != nil {
		t := vk.KeyRotationAt.UTC()
		keyRotationAt = &t
	}

	idCtx := &domain.IdentityContext{
		VirtualKeyID:                 vk.ID,
		KeyPrefix:                    vk.KeyPrefix,
		OrgID:                        vk.OrgID,
		TeamID:                       vk.TeamID,
		ProjectID:                    vk.ProjectID,
		UserID:                       vk.UserID,
		Role:                         vk.Role,
		KeyType:                      NormalizeKeyType(vk.KeyType),
		SCIMActive:                   true,
		CanImpersonate:               vk.CanImpersonate,
		RotationIntervalSec:          vk.RotationIntervalSec,
		KeyRotationAt:                keyRotationAt,
		KeyAllowedModels:             vk.AllowedModels,
		AllowedEndpoints:             vk.AllowedEndpoints,
		KeyAllowedMCPServers:         vk.AllowedMCPServers,
		KeyAllowedA2AAgents:          vk.AllowedA2AAgents,
		KeyAllowedClientApps:         vk.AllowedClientApps,
		KeyRPMLimit:                  vk.RPMLimit,
		KeyTPMLimit:                  vk.TPMLimit,
		KeyMCPRPMLimit:               vk.MCPRPMLimit,
		KeyMaxConcurrent:             vk.MaxConcurrentRequests,
		KeyBatchEnqueuedTokenLimit:   vk.BatchEnqueuedTokenLimit,
		KeyMaxIterations:             vk.MaxIterations,
		KeyMaxBudgetPerSessionMicros: vk.MaxBudgetPerSessionMicros,
		KeyMinPriorityRank:           vk.MinPriorityRank,
		KeyAllowedRoutingTags:        slices.Clone(vk.AllowedRoutingTags),
		KeyTags:                      slices.Clone(vk.Tags),
		KeyMetadata:                  maps.Clone(vk.Metadata),
		KeyMaxBudgetMicros:           vk.MaxBudgetMicros,
		KeyTempBudgetIncreaseMicros:  vk.TempBudgetIncreaseMicros,
		KeyTempBudgetExpiresAt:       vk.TempBudgetExpiresAt,
		KeySoftBudgetMicros:          vk.SoftBudgetMicros,
		KeyThrottleOnBudgetExceeded:  vk.ThrottleOnBudgetExceeded,
		KeyBudgetFallbacks:           domain.CloneBudgetFallbacks(vk.BudgetFallbacks),
		KeySpentMicros:               vk.SpentMicros,
		OrgRPMLimit:                  org.RPMLimit,
		OrgTPMLimit:                  org.TPMLimit,
		OrgMaxConcurrent:             org.MaxConcurrentRequests,
		OrgBatchEnqueuedTokenLimit:   org.BatchEnqueuedTokenLimit,
		OrgMaxIterations:             org.MaxIterations,
		OrgMaxBudgetPerSessionMicros: org.MaxBudgetPerSessionMicros,
		OrgMaxBudgetMicros:           org.MaxBudgetMicros,
		OrgTempBudgetIncreaseMicros:  org.TempBudgetIncreaseMicros,
		OrgTempBudgetExpiresAt:       org.TempBudgetExpiresAt,
		OrgSoftBudgetMicros:          org.SoftBudgetMicros,
		OrgThrottleOnBudgetExceeded:  org.ThrottleOnBudgetExceeded,
		OrgBudgetFallbacks:           domain.CloneBudgetFallbacks(org.BudgetFallbacks),
		OrgSpentMicros:               org.SpentMicros,
	}

	if vk.ProjectID != "" {
		if pmRepo, ok := s.repo.(storage.ProjectAndMembershipRepository); ok && pmRepo != nil {
			proj, err := pmRepo.GetProject(ctx, vk.ProjectID)
			if err != nil {
				if errors.Is(err, storage.ErrNotFound) {
					return nil, &domain.GatewayError{
						StatusCode: http.StatusForbidden,
						Type:       domain.ErrorTypePermission,
						Code:       "project_not_found",
						Message:    "Project associated with this virtual key was not found",
					}
				}
				return nil, &domain.GatewayError{
					StatusCode: http.StatusServiceUnavailable,
					Type:       domain.ErrorTypeServer,
					Code:       "project_policy_unavailable",
					Message:    "Unable to resolve project policy for this virtual key",
					Retryable:  true,
				}
			}
			if proj.OrgID != vk.OrgID {
				return nil, &domain.GatewayError{
					StatusCode: http.StatusForbidden,
					Type:       domain.ErrorTypePermission,
					Code:       "project_org_mismatch",
					Message:    "Project associated with this virtual key does not belong to its organization",
				}
			}
			if vk.TeamID != "" && proj.TeamID != vk.TeamID {
				return nil, &domain.GatewayError{
					StatusCode: http.StatusForbidden,
					Type:       domain.ErrorTypePermission,
					Code:       "project_team_mismatch",
					Message:    "Project associated with this virtual key does not belong to its team",
				}
			}
			if !proj.IsActive {
				return nil, &domain.GatewayError{
					StatusCode: http.StatusForbidden,
					Type:       domain.ErrorTypePermission,
					Code:       "project_inactive",
					Message:    "Project associated with this virtual key is inactive",
				}
			}
			if idCtx.TeamID == "" {
				idCtx.TeamID = proj.TeamID
			}
			idCtx.ProjectAllowedModels = slices.Clone(proj.AllowedModels)
			idCtx.ProjectMaxBudgetMicros = proj.MaxBudgetMicros
			idCtx.ProjectSpentMicros = proj.SpentMicros
			idCtx.ProjectRPMLimit = proj.RPMLimit
			idCtx.ProjectTPMLimit = proj.TPMLimit
			idCtx.ProjectEnforceModelQuota = proj.EnforceProjectModelQuota
		}
	}

	if idCtx.TeamID != "" {
		team, err := s.repo.GetTeam(ctx, idCtx.TeamID)
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
		idCtx.TeamMinPriorityRank = team.MinPriorityRank
		idCtx.TeamAllowedRoutingTags = slices.Clone(team.AllowedRoutingTags)
		idCtx.TeamRPMLimit = team.RPMLimit
		idCtx.TeamTPMLimit = team.TPMLimit
		idCtx.TeamMCPRPMLimit = team.MCPRPMLimit
		idCtx.TeamMaxConcurrent = team.MaxConcurrentRequests
		idCtx.TeamBatchEnqueuedTokenLimit = team.BatchEnqueuedTokenLimit
		idCtx.TeamMaxIterations = team.MaxIterations
		idCtx.TeamMaxBudgetPerSessionMicros = team.MaxBudgetPerSessionMicros
		idCtx.TeamMaxBudgetMicros = team.MaxBudgetMicros
		idCtx.TeamTempBudgetIncreaseMicros = team.TempBudgetIncreaseMicros
		idCtx.TeamTempBudgetExpiresAt = team.TempBudgetExpiresAt
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
		if !user.SCIMActive {
			return nil, &domain.GatewayError{
				StatusCode: http.StatusForbidden,
				Type:       domain.ErrorTypePermission,
				Code:       "scim_deprovisioned",
				Message:    "User associated with this virtual key has been deprovisioned via SCIM",
			}
		}
		idCtx.SCIMActive = user.SCIMActive
		idCtx.UserRPMLimit = user.RPMLimit
		idCtx.UserTPMLimit = user.TPMLimit
		idCtx.UserMaxConcurrent = user.MaxConcurrentRequests
		idCtx.UserBatchEnqueuedTokenLimit = user.BatchEnqueuedTokenLimit
		idCtx.UserMaxBudgetMicros = user.MaxBudgetMicros
		idCtx.UserTempBudgetIncreaseMicros = user.TempBudgetIncreaseMicros
		idCtx.UserTempBudgetExpiresAt = user.TempBudgetExpiresAt
		idCtx.UserSoftBudgetMicros = user.SoftBudgetMicros
		idCtx.UserThrottleOnBudgetExceeded = user.ThrottleOnBudgetExceeded
		idCtx.UserBudgetFallbacks = domain.CloneBudgetFallbacks(user.BudgetFallbacks)
		idCtx.UserSpentMicros = user.SpentMicros

		if idCtx.TeamID != "" {
			if pmRepo, ok := s.repo.(storage.ProjectAndMembershipRepository); ok && pmRepo != nil {
				membership, memErr := pmRepo.GetTeamMembership(ctx, idCtx.TeamID, vk.UserID)
				if memErr == nil && membership != nil {
					if membership.OrgID == vk.OrgID && membership.TeamID == idCtx.TeamID {
						idCtx.TeamMemberAllowedModels = slices.Clone(membership.AllowedModels)
						idCtx.TeamMemberMaxBudgetMicros = membership.MaxBudgetMicros
						idCtx.TeamMemberSpentMicros = membership.SpentMicros
						idCtx.TeamMemberRPMLimit = membership.RPMLimit
						idCtx.TeamMemberTPMLimit = membership.TPMLimit
					}
				} else if memErr != nil && !errors.Is(memErr, storage.ErrNotFound) {
					return nil, &domain.GatewayError{
						StatusCode: http.StatusServiceUnavailable,
						Type:       domain.ErrorTypeServer,
						Code:       "team_membership_unavailable",
						Message:    "Unable to resolve team membership policy for this virtual key",
						Retryable:  true,
					}
				}
			}
		}
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
			Message:    "Valid Master Admin Key, admin Virtual Key, operator JWT, or session is required to access /admin/v1/* endpoints",
		}
	}

	if cred.Source == CredentialSourceCookie {
		if s.sessionManager == nil {
			return nil, &domain.GatewayError{
				StatusCode: http.StatusUnauthorized,
				Type:       domain.ErrorTypeAuthentication,
				Code:       "invalid_session",
				Message:    "Operator session authentication is not configured",
			}
		}
		return s.authenticateSessionToken(ctx, rawToken)
	}

	if s.ValidateAdminKey(rawToken) {
		return &domain.OperatorContext{
			ActorID:        "master_admin",
			Role:           domain.OperatorRolePlatformAdmin,
			AuthMethod:     "master_key",
			CanImpersonate: true,
		}, nil
	}

	if strings.HasPrefix(rawToken, "sk-gw-") {
		idCtx, err := s.AuthenticateVirtualKey(ctx, rawToken)
		if err != nil {
			return nil, err
		}
		if idCtx.KeyType == domain.KeyTypeLLMAPI {
			return nil, &domain.GatewayError{
				StatusCode: http.StatusForbidden,
				Type:       domain.ErrorTypePermission,
				Code:       "key_type_not_allowed",
				Message:    "Virtual keys with key_type \"llm_api\" are restricted to data-plane inference endpoints",
			}
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
		teamID := idCtx.TeamID
		if teamID == "" && idCtx.UserID != "" {
			if user, uErr := s.lookupUser(ctx, idCtx.OrgID, idCtx.UserID); uErr == nil && user != nil {
				teamID = user.TeamID
			}
		}
		return &domain.OperatorContext{
			ActorID:               actorID,
			Role:                  opRole,
			OrgID:                 idCtx.OrgID,
			TeamID:                teamID,
			AuthMethod:            "virtual_key",
			CanImpersonate:        idCtx.CanImpersonate,
			DeprecatedKeyRevokeAt: idCtx.DeprecatedKeyRevokeAt,
		}, nil
	}

	if cred.Source == CredentialSourceBearer && s.sessionManager != nil && strings.Count(rawToken, ".") == 2 && IsSessionTokenAudience(rawToken) {
		return s.authenticateSessionToken(ctx, rawToken)
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
		user, err := s.resolveOIDCUserForClaims(ctx, claims, "unknown_operator")
		if err != nil {
			return nil, err
		}
		if !user.IsActive {
			return nil, &domain.GatewayError{
				StatusCode: http.StatusForbidden,
				Type:       domain.ErrorTypePermission,
				Code:       "user_inactive",
				Message:    "Operator user account is inactive",
			}
		}
		if !user.SCIMActive {
			return nil, &domain.GatewayError{
				StatusCode: http.StatusForbidden,
				Type:       domain.ErrorTypePermission,
				Code:       "scim_deprovisioned",
				Message:    "Operator user account has been deprovisioned via SCIM",
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
		teamID := user.TeamID
		if !ok || (opRole == domain.OperatorRoleTeamAdmin && teamID == "") {
			if pmRepo, pmOK := s.repo.(storage.ProjectAndMembershipRepository); pmOK && pmRepo != nil {
				if memberships, mErr := pmRepo.ListTeamMemberships(ctx, user.OrgID, "", user.ID); mErr == nil {
					for _, m := range memberships {
						if m != nil && m.Role == domain.RoleTeamAdmin {
							opRole = domain.OperatorRoleTeamAdmin
							teamID = m.TeamID
							ok = true
							break
						}
					}
				}
			}
		}
		if !ok {
			return nil, &domain.GatewayError{
				StatusCode: http.StatusForbidden,
				Type:       domain.ErrorTypePermission,
				Code:       "insufficient_permissions",
				Message:    fmt.Sprintf("User role %q is not authorized for control plane access", user.Role),
			}
		}
		if opRole == domain.OperatorRoleTeamAdmin && teamID != "" {
			if team, teamErr := s.repo.GetTeam(ctx, teamID); teamErr == nil && team != nil {
				if team.OrgID != user.OrgID {
					return nil, &domain.GatewayError{
						StatusCode: http.StatusForbidden,
						Type:       domain.ErrorTypePermission,
						Code:       "team_org_mismatch",
						Message:    "Team associated with this operator does not belong to its organization",
					}
				}
				if !team.IsActive {
					return nil, &domain.GatewayError{
						StatusCode: http.StatusForbidden,
						Type:       domain.ErrorTypePermission,
						Code:       "team_inactive",
						Message:    "Team associated with this operator is inactive",
					}
				}
			}
		}
		return &domain.OperatorContext{
			ActorID:    user.ID,
			Role:       opRole,
			OrgID:      user.OrgID,
			TeamID:     teamID,
			AuthMethod: "jwt",
		}, nil
	}

	return nil, &domain.GatewayError{
		StatusCode: http.StatusUnauthorized,
		Type:       domain.ErrorTypeAuthentication,
		Code:       "invalid_admin_key",
		Message:    "Valid Master Admin Key, admin Virtual Key, operator JWT, or session is required to access /admin/v1/* endpoints",
	}
}

func (s *Service) resolveOIDCUserForClaims(ctx context.Context, claims *JWTClaims, notFoundCode string) (*domain.User, error) {
	if claims == nil || strings.TrimSpace(claims.Subject) == "" {
		return nil, &domain.GatewayError{
			StatusCode: http.StatusUnauthorized,
			Type:       domain.ErrorTypeAuthentication,
			Code:       notFoundCode,
			Message:    "No user mapped to JWT subject",
		}
	}

	ov := s.jwtVerifier.VerifierForIssuer(claims.Issuer)
	effectiveIssuer := strings.TrimSpace(claims.Issuer)
	if ov != nil && strings.TrimSpace(ov.Issuer()) != "" {
		effectiveIssuer = strings.TrimSpace(ov.Issuer())
	}
	pinnedOrgID := ""
	if ov != nil {
		pinnedOrgID = strings.TrimSpace(ov.DefaultOrgID())
	}
	claimOrgID := strings.TrimSpace(claims.OrgID)
	if pinnedOrgID != "" && claimOrgID != "" && claimOrgID != pinnedOrgID {
		return nil, &domain.GatewayError{
			StatusCode: http.StatusForbidden,
			Type:       domain.ErrorTypePermission,
			Code:       "cross_org_access_denied",
			Message:    "JWT org_id claim does not match issuer organization scope",
		}
	}
	orgID := pinnedOrgID
	if orgID == "" {
		orgID = claimOrgID
	}

	singleIssuer := s.jwtVerifier.SingleIdentityIssuer()
	if oidcRepo, ok := s.repo.(storage.OIDCUserRepository); ok && oidcRepo != nil && orgID != "" {
		if effectiveIssuer != "" {
			user, err := oidcRepo.GetUserByOIDCIdentity(ctx, orgID, effectiveIssuer, claims.Subject)
			if err == nil && user != nil {
				return user, nil
			}
			if err != nil && !errors.Is(err, storage.ErrNotFound) {
				return nil, &domain.GatewayError{
					StatusCode: http.StatusUnauthorized,
					Type:       domain.ErrorTypeAuthentication,
					Code:       notFoundCode,
					Message:    "No user mapped to JWT subject",
				}
			}
		}
		if singleIssuer {
			user, err := oidcRepo.GetUserByOIDCIdentity(ctx, orgID, "", claims.Subject)
			if err == nil && user != nil {
				return user, nil
			}
		}
		return nil, &domain.GatewayError{
			StatusCode: http.StatusUnauthorized,
			Type:       domain.ErrorTypeAuthentication,
			Code:       notFoundCode,
			Message:    "No user mapped to JWT subject",
		}
	}

	user, err := s.repo.GetUserByOIDCSubject(ctx, claims.Subject)
	if err != nil || user == nil {
		return nil, &domain.GatewayError{
			StatusCode: http.StatusUnauthorized,
			Type:       domain.ErrorTypeAuthentication,
			Code:       notFoundCode,
			Message:    "No user mapped to JWT subject",
		}
	}
	if orgID != "" && user.OrgID != orgID {
		return nil, &domain.GatewayError{
			StatusCode: http.StatusUnauthorized,
			Type:       domain.ErrorTypeAuthentication,
			Code:       notFoundCode,
			Message:    "No user mapped to JWT subject",
		}
	}
	if user.OIDCIssuer != "" {
		if effectiveIssuer == "" || user.OIDCIssuer != effectiveIssuer {
			return nil, &domain.GatewayError{
				StatusCode: http.StatusUnauthorized,
				Type:       domain.ErrorTypeAuthentication,
				Code:       notFoundCode,
				Message:    "No user mapped to JWT subject",
			}
		}
	} else if !singleIssuer {
		return nil, &domain.GatewayError{
			StatusCode: http.StatusUnauthorized,
			Type:       domain.ErrorTypeAuthentication,
			Code:       notFoundCode,
			Message:    "No user mapped to JWT subject",
		}
	}
	return user, nil
}

func (s *Service) authenticateSessionToken(ctx context.Context, rawToken string) (*domain.OperatorContext, error) {
	claims, sess, err := s.sessionManager.VerifySession(ctx, rawToken)
	if err != nil {
		return nil, err
	}
	op := &domain.OperatorContext{
		ActorID:    claims.Subject,
		Role:       domain.OperatorRole(claims.Role),
		OrgID:      claims.OrgID,
		TeamID:     claims.TeamID,
		AuthMethod: "session",
		SessionID:  claims.JTI,
		CSRFToken:  claims.CSRFToken,
	}
	if sess != nil && op.CSRFToken == "" {
		op.CSRFToken = sess.CSRFToken
	}
	if claims.Synthetic || claims.Subject == UIAdminActorID {
		return op, nil
	}
	if ul, ok := s.repo.(storage.UserLookupRepository); ok && ul != nil {
		user, uErr := ul.GetUser(ctx, claims.Subject)
		if uErr != nil || user == nil {
			return nil, &domain.GatewayError{
				StatusCode: http.StatusUnauthorized,
				Type:       domain.ErrorTypeAuthentication,
				Code:       "session_user_not_found",
				Message:    "Operator user account no longer exists",
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
		if !user.SCIMActive {
			return nil, &domain.GatewayError{
				StatusCode: http.StatusForbidden,
				Type:       domain.ErrorTypePermission,
				Code:       "scim_deprovisioned",
				Message:    "Operator user account has been deprovisioned via SCIM",
			}
		}
		org, oErr := s.repo.GetOrganization(ctx, user.OrgID)
		if oErr != nil || !org.IsActive {
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
		if opRole == domain.OperatorRoleTeamAdmin && user.TeamID != "" {
			if team, teamErr := s.repo.GetTeam(ctx, user.TeamID); teamErr == nil && team != nil {
				if team.OrgID != user.OrgID {
					return nil, &domain.GatewayError{
						StatusCode: http.StatusForbidden,
						Type:       domain.ErrorTypePermission,
						Code:       "team_org_mismatch",
						Message:    "Team associated with this operator does not belong to its organization",
					}
				}
				if !team.IsActive {
					return nil, &domain.GatewayError{
						StatusCode: http.StatusForbidden,
						Type:       domain.ErrorTypePermission,
						Code:       "team_inactive",
						Message:    "Team associated with this operator is inactive",
					}
				}
			}
		}
		op.Role = opRole
		op.OrgID = user.OrgID
		op.TeamID = user.TeamID
	}
	return op, nil
}

func mapDomainRoleToOperatorRole(role domain.Role) (domain.OperatorRole, bool) {
	switch role {
	case domain.RolePlatformAdmin:
		return domain.OperatorRolePlatformAdmin, true
	case domain.RoleOrgAdmin:
		return domain.OperatorRoleOrgAdmin, true
	case domain.RoleViewer, domain.RoleOrgViewer:
		return domain.OperatorRoleOrgViewer, true
	case domain.RoleTeamAdmin:
		return domain.OperatorRoleTeamAdmin, true
	default:
		return "", false
	}
}

// AuthenticateSelfServiceUser resolves an active authenticated user and corresponding
// non-elevated OperatorContext for governed developer self-service endpoints (`/v1/self/*`).
// Master admin keys and inference-only (`llm_api`) keys are explicitly rejected.
func (s *Service) AuthenticateSelfServiceUser(ctx context.Context, cred ExtractedCredentials) (*domain.User, *domain.OperatorContext, error) {
	rawToken := strings.TrimSpace(cred.Token)
	if rawToken == "" {
		return nil, nil, &domain.GatewayError{
			StatusCode: http.StatusUnauthorized,
			Type:       domain.ErrorTypeAuthentication,
			Code:       "invalid_credentials",
			Message:    "Valid user session, JWT, or non-inference user virtual key is required",
		}
	}

	resolveUser := func(userID, orgID string) (*domain.User, error) {
		var (
			user *domain.User
			err  error
		)
		if orgID != "" {
			user, err = s.lookupUser(ctx, orgID, userID)
		} else if ul, ok := s.repo.(storage.UserLookupRepository); ok {
			user, err = ul.GetUser(ctx, userID)
		} else {
			err = storage.ErrNotFound
		}
		if err != nil || user == nil {
			return nil, &domain.GatewayError{
				StatusCode: http.StatusUnauthorized,
				Type:       domain.ErrorTypeAuthentication,
				Code:       "unknown_user",
				Message:    "Authenticated principal is not bound to an active user",
			}
		}
		if !user.IsActive {
			return nil, &domain.GatewayError{
				StatusCode: http.StatusForbidden,
				Type:       domain.ErrorTypePermission,
				Code:       "user_inactive",
				Message:    "User account is inactive",
			}
		}
		if !user.SCIMActive {
			return nil, &domain.GatewayError{
				StatusCode: http.StatusForbidden,
				Type:       domain.ErrorTypePermission,
				Code:       "scim_deprovisioned",
				Message:    "User account has been deprovisioned",
			}
		}
		if user.OrgID != "" {
			org, oErr := s.repo.GetOrganization(ctx, user.OrgID)
			if oErr != nil || org == nil || !org.IsActive {
				return nil, &domain.GatewayError{
					StatusCode: http.StatusForbidden,
					Type:       domain.ErrorTypePermission,
					Code:       "organization_inactive",
					Message:    "Organization associated with this user is inactive",
				}
			}
		}
		return user, nil
	}

	if cred.Source == CredentialSourceCookie || (cred.Source == CredentialSourceBearer && s.sessionManager != nil && strings.Count(rawToken, ".") == 2 && IsSessionTokenAudience(rawToken)) {
		if s.sessionManager == nil {
			return nil, nil, &domain.GatewayError{
				StatusCode: http.StatusUnauthorized,
				Type:       domain.ErrorTypeAuthentication,
				Code:       "invalid_session",
				Message:    "User session authentication is not configured",
			}
		}
		op, err := s.authenticateSessionToken(ctx, rawToken)
		if err != nil {
			return nil, nil, err
		}
		if op == nil || op.ActorID == "" || op.ActorID == "master_admin" {
			return nil, nil, &domain.GatewayError{
				StatusCode: http.StatusForbidden,
				Type:       domain.ErrorTypePermission,
				Code:       "user_identity_required",
				Message:    "Self-service developer key endpoints require an authenticated user identity",
			}
		}
		user, uErr := resolveUser(op.ActorID, op.OrgID)
		if uErr != nil {
			return nil, nil, uErr
		}
		return user, op, nil
	}

	if strings.HasPrefix(rawToken, "sk-gw-") {
		idCtx, err := s.AuthenticateVirtualKey(ctx, rawToken)
		if err != nil {
			return nil, nil, err
		}
		if idCtx.KeyType == domain.KeyTypeLLMAPI || idCtx.KeyType == domain.KeyTypeReadOnly {
			return nil, nil, &domain.GatewayError{
				StatusCode: http.StatusForbidden,
				Type:       domain.ErrorTypePermission,
				Code:       "key_type_not_allowed",
				Message:    fmt.Sprintf("Virtual keys with key_type %q cannot mutate self-service keys", idCtx.KeyType),
			}
		}
		if strings.TrimSpace(idCtx.UserID) == "" {
			return nil, nil, &domain.GatewayError{
				StatusCode: http.StatusForbidden,
				Type:       domain.ErrorTypePermission,
				Code:       "user_identity_required",
				Message:    "Virtual key must be bound to a user_id for self-service access",
			}
		}
		user, uErr := resolveUser(idCtx.UserID, idCtx.OrgID)
		if uErr != nil {
			return nil, nil, uErr
		}
		opRole, ok := mapDomainRoleToOperatorRole(user.Role)
		if !ok {
			opRole = domain.OperatorRole(user.Role)
		}
		teamID := idCtx.TeamID
		if teamID == "" {
			teamID = user.TeamID
		}
		return user, &domain.OperatorContext{
			ActorID:               user.ID,
			Role:                  opRole,
			OrgID:                 user.OrgID,
			TeamID:                teamID,
			AuthMethod:            "virtual_key",
			DeprecatedKeyRevokeAt: idCtx.DeprecatedKeyRevokeAt,
		}, nil
	}

	if cred.Source == CredentialSourceBearer && s.jwtVerifier != nil && s.jwtVerifier.Enabled() && strings.Count(rawToken, ".") == 2 {
		claims, err := s.jwtVerifier.Verify(ctx, rawToken)
		if err != nil {
			return nil, nil, &domain.GatewayError{
				StatusCode: http.StatusUnauthorized,
				Type:       domain.ErrorTypeAuthentication,
				Code:       "invalid_token",
				Message:    "Invalid or expired JWT: " + err.Error(),
			}
		}
		user, err := s.resolveOIDCUserForClaims(ctx, claims, "unknown_user")
		if err != nil {
			return nil, nil, err
		}
		checkedUser, uErr := resolveUser(user.ID, user.OrgID)
		if uErr != nil {
			return nil, nil, uErr
		}
		opRole, ok := mapDomainRoleToOperatorRole(checkedUser.Role)
		if !ok {
			opRole = domain.OperatorRole(checkedUser.Role)
		}
		return checkedUser, &domain.OperatorContext{
			ActorID:    checkedUser.ID,
			Role:       opRole,
			OrgID:      checkedUser.OrgID,
			TeamID:     checkedUser.TeamID,
			AuthMethod: "jwt",
		}, nil
	}

	return nil, nil, &domain.GatewayError{
		StatusCode: http.StatusUnauthorized,
		Type:       domain.ErrorTypeAuthentication,
		Code:       "invalid_credentials",
		Message:    "Valid user session, JWT, or non-inference user virtual key is required",
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
