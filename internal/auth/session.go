package auth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
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

const (
	// SESSION_AUDIENCE is the required JWT audience claim for Control Plane operator sessions.
	SESSION_AUDIENCE = "goroute-control-plane-session"
	// SessionAudience aliases SESSION_AUDIENCE.
	SessionAudience = SESSION_AUDIENCE
	// SessionIssuer is the issuer claim for Control Plane operator session JWTs.
	SessionIssuer = "goroute-control-plane"
	// SessionCookieName is the HTTP cookie name used to carry Control Plane session JWTs.
	SessionCookieName = "goroute_session"
	// CSRFHeaderName is the HTTP header required on mutating cookie-authenticated requests.
	CSRFHeaderName = "X-CSRF-Token"
	// DefaultSessionTTL is the default lifetime for Control Plane operator sessions.
	DefaultSessionTTL = 24 * time.Hour
	// UIAdminActorID is the synthetic actor ID used when authenticating via config UIUsername/UIPassword.
	UIAdminActorID = "ui_admin"
)

// SessionClaims represents the signed payload of a Control Plane operator session JWT.
type SessionClaims struct {
	Subject   string        `json:"sub"`
	Issuer    string        `json:"iss,omitempty"`
	Audience  AudienceClaim `json:"aud,omitempty"`
	JTI       string        `json:"jti"`
	OrgID     string        `json:"org_id,omitempty"`
	TeamID    string        `json:"team_id,omitempty"`
	Role      string        `json:"role"`
	CSRFToken string        `json:"csrf_token,omitempty"`
	Synthetic bool          `json:"synthetic,omitempty"`
	IssuedAt  int64         `json:"iat"`
	ExpiresAt int64         `json:"exp"`
}

// IssuedSession holds the signed session token, CSRF token, expiration, and session metadata.
type IssuedSession struct {
	Token     string                  `json:"token"`
	CSRFToken string                  `json:"csrf_token"`
	ExpiresAt time.Time               `json:"expires_at"`
	Session   *domain.OperatorSession `json:"session"`
}

// SessionManager issues, validates, and revokes HS256-signed Control Plane operator sessions
// backed by OperatorSessionRepository and Redis revocation caches.
type SessionManager struct {
	repo   storage.Repository
	redis  *storage.RedisFabric
	secret []byte
	ttl    time.Duration
	now    func() time.Time

	mu                sync.RWMutex
	syntheticSessions map[string]*domain.OperatorSession
	revokedSessions   map[string]time.Time
}

// DeriveSessionSecret derives a 32-byte HMAC-SHA256 signing key from the configured session secret
// or falls back to domain-separated derivation from master secrets so raw master keys are never reused directly.
func DeriveSessionSecret(sessionSecret, masterEncryptionKey, jwtSecret, masterAdminKey string) []byte {
	if trimmed := strings.TrimSpace(sessionSecret); trimmed != "" {
		return []byte(trimmed)
	}
	seed := strings.TrimSpace(masterEncryptionKey)
	if seed == "" {
		seed = strings.TrimSpace(jwtSecret)
	}
	if seed == "" {
		seed = strings.TrimSpace(masterAdminKey)
	}
	if seed == "" {
		randomSeed := make([]byte, 32)
		_, _ = rand.Read(randomSeed)
		return randomSeed
	}
	sum := sha256.Sum256([]byte("goroute-control-plane-session-key:" + seed))
	return sum[:]
}

// NewSessionManager constructs a SessionManager for Control Plane operator sessions.
func NewSessionManager(repo storage.Repository, redisFabric *storage.RedisFabric, secret []byte, ttl time.Duration) *SessionManager {
	if ttl <= 0 {
		ttl = DefaultSessionTTL
	}
	key := make([]byte, len(secret))
	copy(key, secret)
	if len(key) == 0 {
		key = DeriveSessionSecret("", "", "", "")
	}
	return &SessionManager{
		repo:              repo,
		redis:             redisFabric,
		secret:            key,
		ttl:               ttl,
		now:               time.Now,
		syntheticSessions: make(map[string]*domain.OperatorSession),
		revokedSessions:   make(map[string]time.Time),
	}
}

// SetNowFunc overrides the clock function for deterministic session expiration and revocation tests.
func (m *SessionManager) SetNowFunc(fn func() time.Time) {
	if m == nil || fn == nil {
		return
	}
	m.mu.Lock()
	m.now = fn
	m.mu.Unlock()
}

func (m *SessionManager) currentTime() time.Time {
	m.mu.RLock()
	fn := m.now
	m.mu.RUnlock()
	if fn == nil {
		return time.Now().UTC()
	}
	return fn().UTC()
}

// TTL returns the configured session lifetime.
func (m *SessionManager) TTL() time.Duration {
	if m == nil || m.ttl <= 0 {
		return DefaultSessionTTL
	}
	return m.ttl
}

func sessionRevokedRedisKey(jti string) string {
	return "gw:auth:session:revoked:" + jti
}

func sessionActiveRedisKey(jti string) string {
	return "gw:auth:session:active:" + jti
}

// IssueSession creates a new persisted operator session and returns an HS256-signed JWT + CSRF token.
func (m *SessionManager) IssueSession(ctx context.Context, userID, orgID, teamID string, role domain.OperatorRole) (*IssuedSession, error) {
	return m.issueSession(ctx, userID, orgID, teamID, role, false)
}

// IssueSyntheticSession creates a revocable operator session for config-backed admin login (e.g., UIUsername/UIPassword)
// without requiring a foreign-key row in the SQL users table.
func (m *SessionManager) IssueSyntheticSession(ctx context.Context, actorID, orgID string, role domain.OperatorRole) (*IssuedSession, error) {
	return m.issueSession(ctx, actorID, orgID, "", role, true)
}

func (m *SessionManager) issueSession(ctx context.Context, userID, orgID, teamID string, role domain.OperatorRole, synthetic bool) (*IssuedSession, error) {
	if m == nil {
		return nil, errors.New("session manager is nil")
	}
	userID = strings.TrimSpace(userID)
	orgID = strings.TrimSpace(orgID)
	teamID = strings.TrimSpace(teamID)
	if userID == "" {
		return nil, errors.New("user_id is required to issue session")
	}
	if role == "" {
		role = domain.OperatorRoleOrgViewer
	}

	now := m.currentTime()
	expiresAt := now.Add(m.TTL())
	jti := uuid.NewString()

	csrfBytes := make([]byte, 32)
	if _, err := rand.Read(csrfBytes); err != nil {
		return nil, fmt.Errorf("generate csrf token: %w", err)
	}
	csrfToken := hex.EncodeToString(csrfBytes)

	sess := &domain.OperatorSession{
		ID:        jti,
		UserID:    userID,
		OrgID:     orgID,
		Role:      string(role),
		CSRFToken: csrfToken,
		ExpiresAt: expiresAt,
		CreatedAt: now,
	}

	if synthetic {
		m.mu.Lock()
		m.syntheticSessions[jti] = cloneSession(sess)
		m.mu.Unlock()
	} else if sessRepo, ok := m.repo.(storage.OperatorSessionRepository); ok && sessRepo != nil {
		if err := sessRepo.CreateOperatorSession(ctx, sess); err != nil {
			return nil, fmt.Errorf("persist operator session: %w", err)
		}
	} else {
		m.mu.Lock()
		m.syntheticSessions[jti] = cloneSession(sess)
		m.mu.Unlock()
	}

	if m.redis != nil {
		if b, err := json.Marshal(sess); err == nil {
			_, _ = m.redis.Execute(func(rdb redis.UniversalClient) (any, error) {
				return rdb.Set(ctx, sessionActiveRedisKey(jti), b, m.TTL()).Result()
			})
		}
	}

	claims := SessionClaims{
		Subject:   userID,
		Issuer:    SessionIssuer,
		Audience:  AudienceClaim{SESSION_AUDIENCE},
		JTI:       jti,
		OrgID:     orgID,
		TeamID:    teamID,
		Role:      string(role),
		CSRFToken: csrfToken,
		Synthetic: synthetic,
		IssuedAt:  now.Unix(),
		ExpiresAt: expiresAt.Unix(),
	}

	token, err := m.signJWT(claims)
	if err != nil {
		return nil, err
	}

	return &IssuedSession{
		Token:     token,
		CSRFToken: csrfToken,
		ExpiresAt: expiresAt,
		Session:   sess,
	}, nil
}

func (m *SessionManager) signJWT(claims SessionClaims) (string, error) {
	hdrBytes, err := json.Marshal(jwtHeader{
		Alg: "HS256",
		Typ: "JWT",
	})
	if err != nil {
		return "", fmt.Errorf("marshal session jwt header: %w", err)
	}
	payloadBytes, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("marshal session jwt claims: %w", err)
	}
	signingInput := base64.RawURLEncoding.EncodeToString(hdrBytes) + "." + base64.RawURLEncoding.EncodeToString(payloadBytes)
	mac := hmac.New(sha256.New, m.secret)
	mac.Write([]byte(signingInput))
	sig := mac.Sum(nil)
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// IsSessionTokenAudience checks if a 3-part JWT carries SESSION_AUDIENCE without trusting its signature yet.
func IsSessionTokenAudience(rawToken string) bool {
	parts := strings.Split(strings.TrimSpace(rawToken), ".")
	if len(parts) != 3 {
		return false
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return false
	}
	var peek struct {
		Audience AudienceClaim `json:"aud"`
	}
	if err := json.Unmarshal(payloadBytes, &peek); err != nil {
		return false
	}
	return peek.Audience.Contains(SESSION_AUDIENCE)
}

// VerifySession validates an HS256-signed session JWT, checks revocation in Redis + DB,
// and ensures the session has not expired.
func (m *SessionManager) VerifySession(ctx context.Context, rawToken string) (*SessionClaims, *domain.OperatorSession, error) {
	if m == nil {
		return nil, nil, sessionUnauthorized("session_unavailable", "Operator session manager is not configured")
	}
	parts, hdr, payloadBytes, sigBytes, err := parseJWTEnvelope(rawToken)
	if err != nil {
		return nil, nil, sessionUnauthorized("invalid_session", "Invalid session token format")
	}
	if hdr.Alg != "HS256" {
		return nil, nil, sessionUnauthorized("invalid_session", "Unsupported session token algorithm")
	}

	signingInput := parts[0] + "." + parts[1]
	mac := hmac.New(sha256.New, m.secret)
	mac.Write([]byte(signingInput))
	expectedSig := mac.Sum(nil)
	if !hmac.Equal(sigBytes, expectedSig) {
		return nil, nil, sessionUnauthorized("invalid_session", "Invalid session token signature")
	}

	var claims SessionClaims
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return nil, nil, sessionUnauthorized("invalid_session", "Invalid session token claims")
	}
	if !claims.Audience.Contains(SESSION_AUDIENCE) {
		return nil, nil, sessionUnauthorized("invalid_session", "Invalid session token audience")
	}
	if strings.TrimSpace(claims.Subject) == "" || strings.TrimSpace(claims.JTI) == "" {
		return nil, nil, sessionUnauthorized("invalid_session", "Session token missing subject or jti")
	}

	now := m.currentTime()
	if claims.ExpiresAt <= 0 || now.Unix() >= claims.ExpiresAt {
		return nil, nil, sessionUnauthorized("session_expired", "Operator session has expired")
	}

	// Check local revocation cache first
	m.mu.RLock()
	_, locallyRevoked := m.revokedSessions[claims.JTI]
	m.mu.RUnlock()
	if locallyRevoked {
		return nil, nil, sessionUnauthorized("session_revoked", "Operator session has been revoked")
	}

	// Check Redis revocation cache
	if m.redis != nil {
		res, err := m.redis.Execute(func(rdb redis.UniversalClient) (any, error) {
			return rdb.Exists(ctx, sessionRevokedRedisKey(claims.JTI)).Result()
		})
		if err == nil {
			if cnt, ok := res.(int64); ok && cnt > 0 {
				return nil, nil, sessionUnauthorized("session_revoked", "Operator session has been revoked")
			}
		}
	}

	// Resolve session record from durable storage (or synthetic/Redis store)
	var sess *domain.OperatorSession
	if !claims.Synthetic {
		if sessRepo, ok := m.repo.(storage.OperatorSessionRepository); ok && sessRepo != nil {
			dbSess, err := sessRepo.GetOperatorSession(ctx, claims.JTI)
			if err != nil {
				if errors.Is(err, storage.ErrNotFound) {
					return nil, nil, sessionUnauthorized("session_revoked", "Operator session not found or revoked")
				}
				return nil, nil, &domain.GatewayError{
					StatusCode: http.StatusServiceUnavailable,
					Type:       domain.ErrorTypeServer,
					Code:       "session_store_unavailable",
					Message:    "Unable to verify operator session state",
					Retryable:  true,
				}
			}
			sess = dbSess
		}
	}
	if sess == nil {
		m.mu.RLock()
		if syn, ok := m.syntheticSessions[claims.JTI]; ok && syn != nil {
			sess = cloneSession(syn)
		}
		m.mu.RUnlock()
	}
	if sess == nil && m.redis != nil {
		res, err := m.redis.Execute(func(rdb redis.UniversalClient) (any, error) {
			return rdb.Get(ctx, sessionActiveRedisKey(claims.JTI)).Result()
		})
		if err == nil {
			if raw, ok := res.(string); ok && raw != "" {
				var cached domain.OperatorSession
				if json.Unmarshal([]byte(raw), &cached) == nil && cached.ID == claims.JTI {
					sess = &cached
				}
			}
		}
	}
	if sess == nil {
		return nil, nil, sessionUnauthorized("session_revoked", "Operator session not found or revoked")
	}
	if sess.RevokedAt != nil {
		return nil, nil, sessionUnauthorized("session_revoked", "Operator session has been revoked")
	}
	if !now.Before(sess.ExpiresAt) {
		return nil, nil, sessionUnauthorized("session_expired", "Operator session has expired")
	}
	if claims.CSRFToken == "" {
		claims.CSRFToken = sess.CSRFToken
	}

	return &claims, sess, nil
}

// RevokeSession immediately revokes a session by jti in DB, Redis, and local cache.
func (m *SessionManager) RevokeSession(ctx context.Context, jti string, expiresAt time.Time) error {
	if m == nil {
		return nil
	}
	jti = strings.TrimSpace(jti)
	if jti == "" {
		return errors.New("session jti is required")
	}
	now := m.currentTime()

	m.mu.Lock()
	m.revokedSessions[jti] = now
	if syn, ok := m.syntheticSessions[jti]; ok && syn != nil {
		t := now
		syn.RevokedAt = &t
	}
	m.mu.Unlock()

	ttl := time.Until(expiresAt)
	if ttl <= 0 {
		ttl = m.TTL()
	}
	if m.redis != nil {
		_, _ = m.redis.Execute(func(rdb redis.UniversalClient) (any, error) {
			if err := rdb.Set(ctx, sessionRevokedRedisKey(jti), "1", ttl).Err(); err != nil {
				return nil, err
			}
			return rdb.Del(ctx, sessionActiveRedisKey(jti)).Result()
		})
	}

	if sessRepo, ok := m.repo.(storage.OperatorSessionRepository); ok && sessRepo != nil {
		if err := sessRepo.RevokeOperatorSession(ctx, jti, now); err != nil && !errors.Is(err, storage.ErrNotFound) {
			return err
		}
	}
	return nil
}

// RevokeAllUserSessions revokes every active session belonging to userID across DB, Redis, and local cache.
func (m *SessionManager) RevokeAllUserSessions(ctx context.Context, userID string) error {
	if m == nil {
		return nil
	}
	userID = strings.TrimSpace(userID)
	if userID == "" {
		return errors.New("user_id is required")
	}
	now := m.currentTime()

	m.mu.Lock()
	var revokedJTIs []string
	for jti, syn := range m.syntheticSessions {
		if syn != nil && syn.UserID == userID && syn.RevokedAt == nil {
			t := now
			syn.RevokedAt = &t
			m.revokedSessions[jti] = now
			revokedJTIs = append(revokedJTIs, jti)
		}
	}
	m.mu.Unlock()

	if m.redis != nil && len(revokedJTIs) > 0 {
		for _, jti := range revokedJTIs {
			_, _ = m.redis.Execute(func(rdb redis.UniversalClient) (any, error) {
				if err := rdb.Set(ctx, sessionRevokedRedisKey(jti), "1", m.TTL()).Err(); err != nil {
					return nil, err
				}
				return rdb.Del(ctx, sessionActiveRedisKey(jti)).Result()
			})
		}
	}

	if sessRepo, ok := m.repo.(storage.OperatorSessionRepository); ok && sessRepo != nil {
		return sessRepo.RevokeAllUserSessions(ctx, userID, now)
	}
	return nil
}

// SetSessionCookie writes the HttpOnly; Secure; SameSite=Lax Control Plane session cookie.
func SetSessionCookie(w http.ResponseWriter, token string, expiresAt time.Time) {
	if w == nil {
		return
	}
	maxAge := int(time.Until(expiresAt).Seconds())
	if maxAge < 0 {
		maxAge = 0
	}
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    token,
		Path:     "/",
		Expires:  expiresAt.UTC(),
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
}

// ClearSessionCookie expires and clears the Control Plane session cookie.
func ClearSessionCookie(w http.ResponseWriter) {
	if w == nil {
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(0, 0).UTC(),
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
}

// IsMutatingHTTPMethod reports whether method is a state-changing HTTP method subject to CSRF enforcement.
func IsMutatingHTTPMethod(method string) bool {
	switch strings.ToUpper(strings.TrimSpace(method)) {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	default:
		return false
	}
}

// ValidateCSRF checks the X-CSRF-Token header against the session's bound CSRF token.
func ValidateCSRF(r *http.Request, op *domain.OperatorContext) error {
	if r == nil || op == nil {
		return &domain.GatewayError{
			StatusCode: http.StatusForbidden,
			Type:       domain.ErrorTypePermission,
			Code:       "invalid_csrf_token",
			Message:    "Missing or invalid X-CSRF-Token header",
		}
	}
	headerToken := strings.TrimSpace(r.Header.Get(CSRFHeaderName))
	if headerToken == "" || op.CSRFToken == "" ||
		subtle.ConstantTimeCompare([]byte(headerToken), []byte(op.CSRFToken)) != 1 {
		return &domain.GatewayError{
			StatusCode: http.StatusForbidden,
			Type:       domain.ErrorTypePermission,
			Code:       "invalid_csrf_token",
			Message:    "Missing or invalid X-CSRF-Token header for cookie-authenticated request",
		}
	}
	return nil
}

func cloneSession(s *domain.OperatorSession) *domain.OperatorSession {
	if s == nil {
		return nil
	}
	cp := *s
	if s.RevokedAt != nil {
		t := *s.RevokedAt
		cp.RevokedAt = &t
	}
	return &cp
}

func sessionUnauthorized(code, msg string) *domain.GatewayError {
	return &domain.GatewayError{
		StatusCode: http.StatusUnauthorized,
		Type:       domain.ErrorTypeAuthentication,
		Code:       code,
		Message:    msg,
	}
}
