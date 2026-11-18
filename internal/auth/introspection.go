package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/security/network"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
	"github.com/redis/go-redis/v9"
	"golang.org/x/sync/singleflight"
)

const (
	// IntrospectionModeAuto selects RFC 7662 POST introspection when the endpoint
	// contains "introspect" or ClientID is set, and falls back to GET UserInfo otherwise.
	IntrospectionModeAuto = "auto"
	// IntrospectionModeIntrospect forces OAuth 2.0 RFC 7662 POST introspection.
	IntrospectionModeIntrospect = "introspect"
	// IntrospectionModeUserInfo forces OIDC GET UserInfo verification.
	IntrospectionModeUserInfo = "userinfo"

	defaultIntrospectionCacheTTL = 5 * time.Minute
	maxIntrospectionResponseSize = 1 << 20 // 1 MiB
	introspectionRequestTimeout  = 15 * time.Second
	introspectRedisKeyPrefix     = "gw:auth:introspect:"
)

// IntrospectionConfig configures OAuth 2.0 RFC 7662 token introspection and OIDC UserInfo verification.
type IntrospectionConfig struct {
	TokenInfoEndpoint string
	ClientID          string
	ClientSecret      string
	Mode              string // "auto", "introspect", "userinfo"
	UserIDField       string
	EmailField        string
	RoleField         string
	OrgIDField        string
	TeamIDField       string
	CacheTTL          time.Duration
	NetworkPolicy     *network.Policy
	HTTPClient        *http.Client
	Redis             *storage.RedisFabric
}

// IntrospectionResult contains verified claims extracted from an RFC 7662 introspection
// response or an OIDC UserInfo endpoint response.
type IntrospectionResult struct {
	Active    bool           `json:"active"`
	Subject   string         `json:"sub,omitempty"`
	UserID    string         `json:"user_id,omitempty"`
	Email     string         `json:"email,omitempty"`
	Role      string         `json:"role,omitempty"`
	OrgID     string         `json:"org_id,omitempty"`
	TeamID    string         `json:"team_id,omitempty"`
	Scope     string         `json:"scope,omitempty"`
	ClientID  string         `json:"client_id,omitempty"`
	TokenType string         `json:"token_type,omitempty"`
	Username  string         `json:"username,omitempty"`
	Issuer    string         `json:"iss,omitempty"`
	Audience  AudienceClaim  `json:"aud,omitempty"`
	ExpiresAt int64          `json:"exp,omitempty"`
	IssuedAt  int64          `json:"iat,omitempty"`
	NotBefore int64          `json:"nbf,omitempty"`
	Groups    []string       `json:"groups,omitempty"`
	Claims    map[string]any `json:"claims,omitempty"`
}

type l1IntrospectionEntry struct {
	result    *IntrospectionResult
	expiresAt time.Time
}

type l2IntrospectionEntry struct {
	Result         IntrospectionResult `json:"result"`
	CacheExpiresAt time.Time           `json:"cache_expires_at"`
}

// OAuthIntrospector verifies opaque or non-JWT bearer tokens via OAuth 2.0 RFC 7662
// token introspection or generic OIDC UserInfo endpoints with SHA-256-keyed L1/L2 caching.
type OAuthIntrospector struct {
	endpoint     string
	clientID     string
	clientSecret string
	mode         string
	userIDField  string
	emailField   string
	roleField    string
	orgIDField   string
	teamIDField  string
	cacheTTL     time.Duration
	httpClient   *http.Client
	redis        *storage.RedisFabric
	now          func() time.Time

	l1Cache sync.Map // sha256(token) -> l1IntrospectionEntry
	sfGroup singleflight.Group
}

// NewOAuthIntrospector constructs an OAuthIntrospector. When cfg.HTTPClient is nil,
// outbound HTTP calls always use an SSRF-protected client from network.NewHTTPClient.
func NewOAuthIntrospector(cfg IntrospectionConfig) *OAuthIntrospector {
	client := cfg.HTTPClient
	if client == nil {
		client = network.NewHTTPClient(cfg.NetworkPolicy)
	}

	mode := strings.ToLower(strings.TrimSpace(cfg.Mode))
	if mode == "" {
		mode = IntrospectionModeAuto
	}

	userIDField := strings.TrimSpace(cfg.UserIDField)
	if userIDField == "" {
		userIDField = "sub"
	}
	emailField := strings.TrimSpace(cfg.EmailField)
	if emailField == "" {
		emailField = "email"
	}
	roleField := strings.TrimSpace(cfg.RoleField)
	if roleField == "" {
		roleField = "role"
	}
	orgIDField := strings.TrimSpace(cfg.OrgIDField)
	if orgIDField == "" {
		orgIDField = "org_id"
	}
	teamIDField := strings.TrimSpace(cfg.TeamIDField)
	if teamIDField == "" {
		teamIDField = "team_id"
	}

	cacheTTL := cfg.CacheTTL
	if cacheTTL <= 0 {
		cacheTTL = defaultIntrospectionCacheTTL
	}

	return &OAuthIntrospector{
		endpoint:     strings.TrimSpace(cfg.TokenInfoEndpoint),
		clientID:     strings.TrimSpace(cfg.ClientID),
		clientSecret: cfg.ClientSecret,
		mode:         mode,
		userIDField:  userIDField,
		emailField:   emailField,
		roleField:    roleField,
		orgIDField:   orgIDField,
		teamIDField:  teamIDField,
		cacheTTL:     cacheTTL,
		httpClient:   client,
		redis:        cfg.Redis,
		now:          time.Now,
	}
}

// Enabled reports whether an introspection or UserInfo endpoint is configured.
func (o *OAuthIntrospector) Enabled() bool {
	return o != nil && o.endpoint != ""
}

// ResolvedMode returns the effective verification mode ("introspect" or "userinfo"),
// or an error if the configured mode is unrecognized.
func (o *OAuthIntrospector) ResolvedMode() (string, error) {
	if o == nil {
		return "", errors.New("oauth introspector is nil")
	}
	switch o.mode {
	case "", IntrospectionModeAuto:
		if strings.Contains(strings.ToLower(o.endpoint), "introspect") || o.clientID != "" {
			return IntrospectionModeIntrospect, nil
		}
		return IntrospectionModeUserInfo, nil
	case IntrospectionModeIntrospect, IntrospectionModeUserInfo:
		return o.mode, nil
	default:
		return "", fmt.Errorf("unsupported introspection mode %q", o.mode)
	}
}

// Introspect verifies rawToken via L1/L2 cache or the configured introspection/UserInfo endpoint.
// Concurrent cache misses for the same token digest are deduplicated via singleflight.
func (o *OAuthIntrospector) Introspect(ctx context.Context, rawToken string) (*IntrospectionResult, error) {
	if !o.Enabled() {
		return nil, &domain.GatewayError{
			StatusCode: http.StatusUnauthorized,
			Type:       domain.ErrorTypeAuthentication,
			Code:       "introspection_not_configured",
			Message:    "OAuth token introspection is not configured",
		}
	}
	mode, err := o.ResolvedMode()
	if err != nil {
		return nil, &domain.GatewayError{
			StatusCode: http.StatusServiceUnavailable,
			Type:       domain.ErrorTypeServer,
			Code:       "introspection_misconfigured",
			Message:    err.Error(),
		}
	}

	token := strings.TrimSpace(rawToken)
	if token == "" {
		return nil, invalidIntrospectionTokenError("Bearer token is required")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	tokenHash := HashKey(token)
	now := o.now().UTC()

	if res, ok := o.lookupL1(tokenHash, now); ok {
		return res, nil
	}
	if res, ok := o.lookupL2(ctx, tokenHash, now); ok {
		return res, nil
	}

	ch := o.sfGroup.DoChan(tokenHash, func() (any, error) {
		now := o.now().UTC()
		if res, ok := o.lookupL1(tokenHash, now); ok {
			return res, nil
		}
		fetchCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), introspectionRequestTimeout)
		defer cancel()

		if res, ok := o.lookupL2(fetchCtx, tokenHash, now); ok {
			return res, nil
		}

		res, err := o.fetchAndVerify(fetchCtx, mode, token, now)
		if err != nil {
			return nil, err
		}

		o.storeCaches(fetchCtx, tokenHash, res, o.now().UTC())
		return res, nil
	})

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case sfRes := <-ch:
		if sfRes.Err != nil {
			return nil, sfRes.Err
		}
		res, ok := sfRes.Val.(*IntrospectionResult)
		if !ok || res == nil {
			return nil, invalidIntrospectionTokenError("Token verification returned empty result")
		}
		return cloneIntrospectionResult(res), nil
	}
}

// InvalidateToken removes a token digest from local L1 and L2 Redis caches.
func (o *OAuthIntrospector) InvalidateToken(ctx context.Context, rawToken string) {
	if o == nil {
		return
	}
	token := strings.TrimSpace(rawToken)
	if token == "" {
		return
	}
	tokenHash := HashKey(token)
	o.l1Cache.Delete(tokenHash)
	if o.redis != nil {
		_, _ = o.redis.Execute(func(rdb redis.UniversalClient) (any, error) {
			return rdb.Del(ctx, introspectRedisKey(tokenHash)).Result()
		})
	}
}

func (o *OAuthIntrospector) lookupL1(tokenHash string, now time.Time) (*IntrospectionResult, bool) {
	val, ok := o.l1Cache.Load(tokenHash)
	if !ok {
		return nil, false
	}
	entry, ok := val.(l1IntrospectionEntry)
	if !ok || entry.result == nil {
		o.l1Cache.Delete(tokenHash)
		return nil, false
	}
	if !now.Before(entry.expiresAt) || isIntrospectionTokenExpired(entry.result.ExpiresAt, now) {
		o.l1Cache.Delete(tokenHash)
		return nil, false
	}
	return cloneIntrospectionResult(entry.result), true
}

func (o *OAuthIntrospector) lookupL2(ctx context.Context, tokenHash string, now time.Time) (*IntrospectionResult, bool) {
	if o.redis == nil {
		return nil, false
	}
	raw, err := o.redis.Execute(func(rdb redis.UniversalClient) (any, error) {
		return rdb.Get(ctx, introspectRedisKey(tokenHash)).Result()
	})
	if err != nil {
		return nil, false
	}
	jsonStr, ok := raw.(string)
	if !ok || jsonStr == "" {
		return nil, false
	}

	var cached l2IntrospectionEntry
	if err := json.Unmarshal([]byte(jsonStr), &cached); err != nil || !cached.Result.Active {
		return nil, false
	}
	if isIntrospectionTokenExpired(cached.Result.ExpiresAt, now) {
		return nil, false
	}
	ttl := o.effectiveTTL(cached.Result.ExpiresAt, now)
	if !cached.CacheExpiresAt.IsZero() {
		remaining := cached.CacheExpiresAt.Sub(now)
		if remaining <= 0 {
			return nil, false
		}
		if remaining < ttl {
			ttl = remaining
		}
	}
	if ttl <= 0 {
		return nil, false
	}

	res := cloneIntrospectionResult(&cached.Result)
	o.l1Cache.Store(tokenHash, l1IntrospectionEntry{
		result:    res,
		expiresAt: now.Add(ttl),
	})
	return cloneIntrospectionResult(res), true
}

func (o *OAuthIntrospector) storeCaches(ctx context.Context, tokenHash string, res *IntrospectionResult, now time.Time) {
	if res == nil || !res.Active {
		return
	}
	ttl := o.effectiveTTL(res.ExpiresAt, now)
	if ttl <= 0 {
		return
	}

	stored := cloneIntrospectionResult(res)
	expiresAt := now.Add(ttl)
	o.l1Cache.Store(tokenHash, l1IntrospectionEntry{
		result:    stored,
		expiresAt: expiresAt,
	})

	if o.redis != nil {
		payload, err := json.Marshal(l2IntrospectionEntry{
			Result:         *stored,
			CacheExpiresAt: expiresAt,
		})
		if err != nil {
			return
		}
		_, _ = o.redis.Execute(func(rdb redis.UniversalClient) (any, error) {
			return rdb.Set(ctx, introspectRedisKey(tokenHash), string(payload), ttl).Result()
		})
	}
}

func (o *OAuthIntrospector) effectiveTTL(expUnix int64, now time.Time) time.Duration {
	ttl := o.cacheTTL
	if ttl <= 0 {
		return 0
	}
	if expUnix > 0 {
		remaining := time.Unix(expUnix, 0).UTC().Sub(now)
		if remaining <= 0 {
			return 0
		}
		if remaining < ttl {
			ttl = remaining
		}
	}
	return ttl
}

func (o *OAuthIntrospector) fetchAndVerify(ctx context.Context, mode, token string, now time.Time) (*IntrospectionResult, error) {
	if o.httpClient == nil {
		return nil, &domain.GatewayError{
			StatusCode: http.StatusServiceUnavailable,
			Type:       domain.ErrorTypeServer,
			Code:       "introspection_unavailable",
			Message:    "Introspection HTTP client is not initialized",
		}
	}

	req, err := o.buildRequest(ctx, mode, token)
	if err != nil {
		return nil, fmt.Errorf("build introspection request: %w", err)
	}

	resp, err := o.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("introspection request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusBadRequest {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return nil, invalidIntrospectionTokenError(fmt.Sprintf("Token rejected by introspection endpoint (HTTP %d)", resp.StatusCode))
	}
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return nil, &domain.GatewayError{
			StatusCode: http.StatusServiceUnavailable,
			Type:       domain.ErrorTypeServer,
			Code:       "introspection_unavailable",
			Message:    fmt.Sprintf("Introspection endpoint returned unexpected HTTP %d", resp.StatusCode),
			Retryable:  true,
		}
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxIntrospectionResponseSize+1))
	if err != nil {
		return nil, fmt.Errorf("read introspection response: %w", err)
	}
	if len(body) > maxIntrospectionResponseSize {
		return nil, &domain.GatewayError{
			StatusCode: http.StatusServiceUnavailable,
			Type:       domain.ErrorTypeServer,
			Code:       "introspection_response_too_large",
			Message:    "Introspection response exceeded maximum allowed size",
		}
	}

	var claims map[string]any
	if err := json.Unmarshal(body, &claims); err != nil {
		return nil, &domain.GatewayError{
			StatusCode: http.StatusServiceUnavailable,
			Type:       domain.ErrorTypeServer,
			Code:       "introspection_invalid_response",
			Message:    "Introspection endpoint returned invalid JSON",
		}
	}

	return o.parseAndValidateClaims(mode, claims, now)
}

func (o *OAuthIntrospector) buildRequest(ctx context.Context, mode, token string) (*http.Request, error) {
	if mode == IntrospectionModeIntrospect {
		form := url.Values{}
		form.Set("token", token)
		if o.clientID != "" && o.clientSecret == "" {
			form.Set("client_id", o.clientID)
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, o.endpoint, strings.NewReader(form.Encode()))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Accept", "application/json")
		if o.clientID != "" && o.clientSecret != "" {
			req.SetBasicAuth(o.clientID, o.clientSecret)
		}
		return req, nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, o.endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	return req, nil
}

func (o *OAuthIntrospector) parseAndValidateClaims(mode string, claims map[string]any, now time.Time) (*IntrospectionResult, error) {
	if claims == nil {
		return nil, invalidIntrospectionTokenError("Introspection response contained no claims")
	}

	nowUnix := now.Unix()
	var exp int64
	if rawExp, hasExp := claims["exp"]; hasExp && rawExp != nil {
		parsedExp, ok := parseInt64Claim(rawExp)
		if !ok {
			return nil, invalidIntrospectionTokenError("Token exp claim is invalid")
		}
		exp = parsedExp
		if exp <= nowUnix {
			return nil, &domain.GatewayError{
				StatusCode:  http.StatusUnauthorized,
				Type:        domain.ErrorTypeAuthentication,
				Code:        "token_expired",
				Message:     "Token is expired",
				AuthFailure: true,
			}
		}
	}

	var nbf int64
	if rawNbf, hasNbf := claims["nbf"]; hasNbf && rawNbf != nil {
		parsedNbf, ok := parseInt64Claim(rawNbf)
		if !ok {
			return nil, invalidIntrospectionTokenError("Token nbf claim is invalid")
		}
		nbf = parsedNbf
		if nbf > nowUnix {
			return nil, invalidIntrospectionTokenError("Token is not yet valid")
		}
	}

	var iat int64
	if rawIat, hasIat := claims["iat"]; hasIat && rawIat != nil {
		if parsedIat, ok := parseInt64Claim(rawIat); ok {
			iat = parsedIat
		}
	}

	active := true
	if mode == IntrospectionModeIntrospect {
		rawActive, hasActive := claims["active"]
		if !hasActive {
			return nil, invalidIntrospectionTokenError("Introspection response missing active claim")
		}
		isActive, ok := rawActive.(bool)
		if !ok || !isActive {
			return nil, invalidIntrospectionTokenError("Token is not active")
		}
		active = true
	} else if rawActive, hasActive := claims["active"]; hasActive && rawActive != nil {
		if isActive, ok := rawActive.(bool); ok && !isActive {
			return nil, invalidIntrospectionTokenError("Token is not active")
		}
	}

	sub := extractStringClaim(claims, "sub")
	userID := extractStringClaim(claims, o.userIDField)
	if userID == "" && o.userIDField == "sub" {
		userID = sub
	}
	if mode == IntrospectionModeUserInfo && userID == "" && sub == "" {
		return nil, invalidIntrospectionTokenError("UserInfo response missing subject claim")
	}

	res := &IntrospectionResult{
		Active:    active,
		Subject:   sub,
		UserID:    userID,
		Email:     extractStringClaim(claims, o.emailField),
		Role:      extractRoleClaim(claims, o.roleField),
		OrgID:     extractStringClaim(claims, o.orgIDField),
		TeamID:    extractStringClaim(claims, o.teamIDField),
		Scope:     extractStringClaim(claims, "scope"),
		ClientID:  extractStringClaim(claims, "client_id"),
		TokenType: extractStringClaim(claims, "token_type"),
		Username:  extractStringClaim(claims, "username"),
		Issuer:    extractStringClaim(claims, "iss"),
		Audience:  extractAudienceClaim(claims["aud"]),
		ExpiresAt: exp,
		IssuedAt:  iat,
		NotBefore: nbf,
		Groups:    extractStringSliceClaim(claims, "groups"),
		Claims:    cloneClaimsMap(claims),
	}
	return res, nil
}

func invalidIntrospectionTokenError(msg string) *domain.GatewayError {
	return &domain.GatewayError{
		StatusCode:  http.StatusUnauthorized,
		Type:        domain.ErrorTypeAuthentication,
		Code:        "invalid_token",
		Message:     msg,
		AuthFailure: true,
	}
}

func introspectRedisKey(tokenHash string) string {
	return introspectRedisKeyPrefix + tokenHash
}

func isIntrospectionTokenExpired(expUnix int64, now time.Time) bool {
	return expUnix > 0 && now.Unix() >= expUnix
}

func extractStringClaim(claims map[string]any, field string) string {
	if field == "" {
		return ""
	}
	raw, ok := claims[field]
	if !ok || raw == nil {
		return ""
	}
	switch v := raw.(type) {
	case string:
		return strings.TrimSpace(v)
	case json.Number:
		return strings.TrimSpace(v.String())
	case float64:
		if v == float64(int64(v)) {
			return strconv.FormatInt(int64(v), 10)
		}
		return strconv.FormatFloat(v, 'f', -1, 64)
	case int64:
		return strconv.FormatInt(v, 10)
	case int:
		return strconv.Itoa(v)
	default:
		return ""
	}
}

func extractRoleClaim(claims map[string]any, field string) string {
	if s := extractStringClaim(claims, field); s != "" {
		return s
	}
	vals := extractStringSliceClaim(claims, field)
	if len(vals) > 0 {
		return vals[0]
	}
	return ""
}

func extractStringSliceClaim(claims map[string]any, field string) []string {
	if field == "" {
		return nil
	}
	raw, ok := claims[field]
	if !ok || raw == nil {
		return nil
	}
	switch v := raw.(type) {
	case []string:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if trimmed := strings.TrimSpace(item); trimmed != "" {
				out = append(out, trimmed)
			}
		}
		return out
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok {
				if trimmed := strings.TrimSpace(s); trimmed != "" {
					out = append(out, trimmed)
				}
			}
		}
		return out
	default:
		return nil
	}
}

func extractAudienceClaim(raw any) AudienceClaim {
	if raw == nil {
		return nil
	}
	switch v := raw.(type) {
	case string:
		if trimmed := strings.TrimSpace(v); trimmed != "" {
			return AudienceClaim{trimmed}
		}
	case []string:
		return AudienceClaim(append([]string(nil), v...))
	case []any:
		out := make(AudienceClaim, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok && strings.TrimSpace(s) != "" {
				out = append(out, strings.TrimSpace(s))
			}
		}
		return out
	}
	return nil
}

func parseInt64Claim(raw any) (int64, bool) {
	switch v := raw.(type) {
	case float64:
		return int64(v), true
	case int64:
		return v, true
	case int:
		return int64(v), true
	case json.Number:
		n, err := v.Int64()
		if err != nil {
			f, fErr := v.Float64()
			if fErr != nil {
				return 0, false
			}
			return int64(f), true
		}
		return n, true
	default:
		return 0, false
	}
}

func cloneIntrospectionResult(src *IntrospectionResult) *IntrospectionResult {
	if src == nil {
		return nil
	}
	cp := *src
	if src.Audience != nil {
		cp.Audience = append(AudienceClaim(nil), src.Audience...)
	}
	if src.Groups != nil {
		cp.Groups = append([]string(nil), src.Groups...)
	}
	if src.Claims != nil {
		cp.Claims = cloneClaimsMap(src.Claims)
	}
	return &cp
}

func cloneClaimsMap(src map[string]any) map[string]any {
	if src == nil {
		return nil
	}
	cp := make(map[string]any, len(src))
	for k, v := range src {
		cp[k] = cloneClaimValue(v)
	}
	return cp
}

func cloneClaimValue(v any) any {
	switch tv := v.(type) {
	case map[string]any:
		return cloneClaimsMap(tv)
	case []any:
		cp := make([]any, len(tv))
		for idx, item := range tv {
			cp[idx] = cloneClaimValue(item)
		}
		return cp
	case []string:
		return append([]string(nil), tv...)
	default:
		return v
	}
}
