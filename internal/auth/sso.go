package auth

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/auth/upstream"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/security/network"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
	"github.com/redis/go-redis/v9"
	"golang.org/x/sync/singleflight"
)

const (
	// DefaultSSOStateTTL is the lifetime of transient OIDC PKCE/state/nonce records.
	DefaultSSOStateTTL = 10 * time.Minute
	// DefaultCLILoginTTL is the lifetime of pending and completed CLI browser login sessions.
	DefaultCLILoginTTL = 10 * time.Minute
	// DefaultCLIPollInterval is the minimum interval between CLI poll requests.
	DefaultCLIPollInterval = 5 * time.Second
	// maxOIDCTokenResponseBytes bounds upstream IdP token endpoint responses.
	maxOIDCTokenResponseBytes = 1 << 20
)

var (
	// ErrSSOProviderNotFound indicates the requested SSO provider ID is not configured.
	ErrSSOProviderNotFound = errors.New("sso provider not found")
	// ErrSSOStateNotFound indicates the OIDC state token is missing, expired, or already consumed.
	ErrSSOStateNotFound = errors.New("sso state not found or expired")
	// ErrCLILoginNotFound indicates the CLI login session does not exist or has expired.
	ErrCLILoginNotFound = errors.New("cli login session not found or expired")
	// ErrCLILoginAlreadyCompleted indicates the CLI login session was already approved.
	ErrCLILoginAlreadyCompleted = errors.New("cli login session is already completed")
	// ErrCLIPollRateLimited indicates the CLI polled faster than the allowed interval.
	ErrCLIPollRateLimited = errors.New("cli poll rate limit exceeded")
)

var consumeAndDeleteLua = redis.NewScript(`
local val = redis.call('GET', KEYS[1])
if val then
	redis.call('DEL', KEYS[1])
end
return val
`)

var cliPollRateLimitLua = redis.NewScript(`
if redis.call('EXISTS', KEYS[1]) == 1 then
	local ttl = redis.call('PTTL', KEYS[1])
	if ttl < 1 then
		ttl = tonumber(ARGV[1])
	end
	return ttl
end
redis.call('SET', KEYS[1], '1', 'PX', ARGV[1])
return 0
`)

// SSOProviderConfig configures an interactive OIDC SSO identity provider.
type SSOProviderConfig struct {
	ID                    string
	Name                  string
	Type                  string
	DisplayName           string
	ClientID              string
	ClientSecret          string
	Issuer                string
	AuthorizationEndpoint string
	TokenEndpoint         string
	JWKSURL               string
	DiscoveryURL          string
	Scopes                []string
	RedirectURL           string
	AllowedEmailDomains   []string
	AutoRegister          bool
	DefaultOrgID          string
	DefaultTeamID         string
	DefaultRole           string
	TenantID              string
	Algorithms            []string
	ClaimMapping          OIDCClaimMapping
}

// SSOProviderPublicInfo exposes non-sensitive SSO provider metadata for login UI discovery.
type SSOProviderPublicInfo struct {
	ID          string `json:"id"`
	DisplayName string `json:"display_name"`
	Type        string `json:"type"`
}

// SSOEndpoints holds resolved OAuth 2.0 / OIDC endpoints for an SSO provider.
type SSOEndpoints struct {
	Issuer                string
	AuthorizationEndpoint string
	TokenEndpoint         string
	JWKSURL               string
}

// SSOIDTokenClaims represents verified identity claims extracted from an OIDC ID token.
type SSOIDTokenClaims struct {
	Subject     string
	Issuer      string
	Email       string
	DisplayName string
	OrgID       string
	TeamIDs     []string
	Role        string
	RawClaims   map[string]any
}

// SSOError wraps an SSO failure with an HTTP status code and machine-readable GatewayError code.
type SSOError struct {
	StatusCode int
	Type       domain.ErrorType
	Code       string
	Message    string
	RetryAfter time.Duration
	Err        error
}

func (e *SSOError) Error() string {
	if e == nil {
		return ""
	}
	if e.Err != nil {
		return fmt.Sprintf("%s: %v", e.Message, e.Err)
	}
	return e.Message
}

func (e *SSOError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

// GatewayError converts the SSOError into a domain.GatewayError for HTTP serialization.
func (e *SSOError) GatewayError() *domain.GatewayError {
	if e == nil {
		return nil
	}
	errType := e.Type
	if errType == "" {
		errType = domain.ErrorTypeAuthentication
	}
	return &domain.GatewayError{
		StatusCode:  e.StatusCode,
		Type:        errType,
		Code:        e.Code,
		Message:     e.Message,
		AuthFailure: e.StatusCode == http.StatusUnauthorized,
		Retryable:   e.StatusCode == http.StatusTooManyRequests || e.StatusCode >= 500,
	}
}

// SSOProvider represents a normalized, runtime-ready OIDC SSO provider.
type SSOProvider struct {
	id                    string
	providerType          string
	displayName           string
	clientID              string
	clientSecret          string
	issuer                string
	authorizationEndpoint string
	tokenEndpoint         string
	jwksURL               string
	discoveryURL          string
	scopes                []string
	redirectURL           string
	allowedEmailDomains   []string
	autoRegister          bool
	defaultOrgID          string
	defaultTeamID         string
	defaultRole           string
	tenantID              string
	algorithms            []string
	claimMapping          OIDCClaimMapping

	httpClient *http.Client
	netPolicy  *network.Policy
	now        func() time.Time

	mu             sync.RWMutex
	discovered     *SSOEndpoints
	discoveredAt   time.Time
	discoveryTTL   time.Duration
	discoveryGroup singleflight.Group
	verifier       *OIDCVerifier
}

// ID returns the normalized provider identifier.
func (p *SSOProvider) ID() string { return p.id }

// Type returns the provider type ("google", "microsoft", or "oidc").
func (p *SSOProvider) Type() string { return p.providerType }

// DisplayName returns the user-facing display label for the provider.
func (p *SSOProvider) DisplayName() string { return p.displayName }

// RedirectURL returns the configured static callback redirect URL, if any.
func (p *SSOProvider) RedirectURL() string { return p.redirectURL }

// AutoRegister reports whether JIT user creation is enabled for this provider.
func (p *SSOProvider) AutoRegister() bool { return p.autoRegister }

// DefaultOrgID returns the fallback organization ID configured for this provider.
func (p *SSOProvider) DefaultOrgID() string { return p.defaultOrgID }

// DefaultTeamID returns the fallback team ID configured for this provider.
func (p *SSOProvider) DefaultTeamID() string { return p.defaultTeamID }

// DefaultRole returns the fallback role configured for this provider.
func (p *SSOProvider) DefaultRole() string { return p.defaultRole }

// PublicInfo returns non-sensitive provider metadata safe for unauthenticated exposure.
func (p *SSOProvider) PublicInfo() SSOProviderPublicInfo {
	return SSOProviderPublicInfo{
		ID:          p.id,
		DisplayName: p.displayName,
		Type:        p.providerType,
	}
}

// SSOProviderManager manages configured OIDC SSO providers, discovery caching,
// authorization URL construction, PKCE token exchange, and ID token verification.
type SSOProviderManager struct {
	httpClient *http.Client
	netPolicy  *network.Policy
	providers  map[string]*SSOProvider
	ordered    []*SSOProvider

	mu  sync.RWMutex
	now func() time.Time
}

// NewSSOProviderManager constructs an SSOProviderManager backed by an SSRF-enforcing HTTP client.
func NewSSOProviderManager(configs []SSOProviderConfig, netPolicy *network.Policy) (*SSOProviderManager, error) {
	httpClient := network.NewHTTPClient(netPolicy)
	httpClient.Timeout = 15 * time.Second

	mgr := &SSOProviderManager{
		httpClient: httpClient,
		netPolicy:  netPolicy,
		providers:  make(map[string]*SSOProvider, len(configs)),
		ordered:    make([]*SSOProvider, 0, len(configs)),
		now:        time.Now,
	}

	for _, cfg := range configs {
		p, err := mgr.buildProvider(cfg)
		if err != nil {
			return nil, err
		}
		if _, dup := mgr.providers[p.id]; dup {
			return nil, fmt.Errorf("duplicate sso provider id %q", p.id)
		}
		mgr.providers[p.id] = p
		mgr.ordered = append(mgr.ordered, p)
	}
	return mgr, nil
}

// SetNowFunc overrides the clock function for deterministic OIDC discovery and token verification tests.
func (m *SSOProviderManager) SetNowFunc(fn func() time.Time) {
	if m == nil || fn == nil {
		return
	}
	m.mu.Lock()
	m.now = fn
	for _, p := range m.ordered {
		p.mu.Lock()
		p.now = fn
		if p.verifier != nil {
			p.verifier.SetNowFunc(fn)
		}
		p.mu.Unlock()
	}
	m.mu.Unlock()
}

func (m *SSOProviderManager) currentTime() time.Time {
	if m == nil {
		return time.Now().UTC()
	}
	m.mu.RLock()
	fn := m.now
	m.mu.RUnlock()
	if fn == nil {
		return time.Now().UTC()
	}
	return fn().UTC()
}

func (m *SSOProviderManager) buildProvider(cfg SSOProviderConfig) (*SSOProvider, error) {
	id := strings.ToLower(strings.TrimSpace(cfg.ID))
	if id == "" {
		id = strings.ToLower(strings.TrimSpace(cfg.Name))
	}
	if id == "" {
		return nil, errors.New("sso provider id or name is required")
	}

	clientID := strings.TrimSpace(cfg.ClientID)
	if clientID == "" {
		return nil, fmt.Errorf("sso provider %q: client_id is required", id)
	}

	ptype := strings.ToLower(strings.TrimSpace(cfg.Type))
	if ptype == "" {
		switch {
		case id == "google":
			ptype = "google"
		case id == "microsoft" || id == "entra" || id == "azure_ad" || strings.TrimSpace(cfg.TenantID) != "":
			ptype = "microsoft"
		default:
			ptype = "oidc"
		}
	}

	displayName := strings.TrimSpace(cfg.DisplayName)
	if displayName == "" {
		switch ptype {
		case "google":
			displayName = "Google"
		case "microsoft":
			displayName = "Microsoft"
		default:
			if name := strings.TrimSpace(cfg.Name); name != "" {
				displayName = name
			} else {
				displayName = id
			}
		}
	}

	issuer := strings.TrimSpace(cfg.Issuer)
	authEndpoint := strings.TrimSpace(cfg.AuthorizationEndpoint)
	tokenEndpoint := strings.TrimSpace(cfg.TokenEndpoint)
	jwksURL := strings.TrimSpace(cfg.JWKSURL)
	discoveryURL := strings.TrimSpace(cfg.DiscoveryURL)
	tenantID := strings.TrimSpace(cfg.TenantID)

	switch ptype {
	case "google":
		if issuer == "" && discoveryURL == "" && authEndpoint == "" && tokenEndpoint == "" {
			issuer = "https://accounts.google.com"
		}
	case "microsoft":
		if tenantID == "" {
			tenantID = "common"
		}
		if issuer == "" && discoveryURL == "" && authEndpoint == "" && tokenEndpoint == "" {
			issuer = fmt.Sprintf("https://login.microsoftonline.com/%s/v2.0", tenantID)
		}
	}

	if discoveryURL == "" && issuer != "" && (authEndpoint == "" || tokenEndpoint == "" || jwksURL == "") {
		if u, err := url.Parse(issuer); err == nil && (u.Scheme == "https" || u.Scheme == "http") && u.Host != "" {
			discoveryURL = strings.TrimRight(issuer, "/") + "/.well-known/openid-configuration"
		}
	}

	scopes := normalizeOIDCScopes(cfg.Scopes)

	var allowedDomains []string
	for _, d := range cfg.AllowedEmailDomains {
		norm := strings.ToLower(strings.TrimPrefix(strings.TrimSpace(d), "@"))
		if norm != "" {
			allowedDomains = append(allowedDomains, norm)
		}
	}

	return &SSOProvider{
		id:                    id,
		providerType:          ptype,
		displayName:           displayName,
		clientID:              clientID,
		clientSecret:          strings.TrimSpace(cfg.ClientSecret),
		issuer:                issuer,
		authorizationEndpoint: authEndpoint,
		tokenEndpoint:         tokenEndpoint,
		jwksURL:               jwksURL,
		discoveryURL:          discoveryURL,
		scopes:                scopes,
		redirectURL:           strings.TrimSpace(cfg.RedirectURL),
		allowedEmailDomains:   allowedDomains,
		autoRegister:          cfg.AutoRegister,
		defaultOrgID:          strings.TrimSpace(cfg.DefaultOrgID),
		defaultTeamID:         strings.TrimSpace(cfg.DefaultTeamID),
		defaultRole:           strings.TrimSpace(cfg.DefaultRole),
		tenantID:              tenantID,
		algorithms:            append([]string(nil), cfg.Algorithms...),
		claimMapping:          cfg.ClaimMapping,
		httpClient:            m.httpClient,
		netPolicy:             m.netPolicy,
		now:                   m.currentTime,
		discoveryTTL:          defaultDiscoveryCacheTTL,
	}, nil
}

func normalizeOIDCScopes(raw []string) []string {
	var out []string
	seen := make(map[string]struct{})
	add := func(s string) {
		trimmed := strings.TrimSpace(s)
		if trimmed == "" {
			return
		}
		if _, ok := seen[trimmed]; ok {
			return
		}
		seen[trimmed] = struct{}{}
		out = append(out, trimmed)
	}
	if len(raw) == 0 {
		return []string{"openid", "email", "profile"}
	}
	add("openid")
	for _, s := range raw {
		add(s)
	}
	return out
}

// ListProviders returns the non-sensitive public descriptors of all configured SSO providers.
func (m *SSOProviderManager) ListProviders() []SSOProviderPublicInfo {
	if m == nil || len(m.ordered) == 0 {
		return []SSOProviderPublicInfo{}
	}
	out := make([]SSOProviderPublicInfo, 0, len(m.ordered))
	for _, p := range m.ordered {
		if p != nil {
			out = append(out, p.PublicInfo())
		}
	}
	return out
}

// GetProvider looks up a configured SSO provider by normalized ID.
func (m *SSOProviderManager) GetProvider(id string) (*SSOProvider, bool) {
	if m == nil {
		return nil, false
	}
	norm := strings.ToLower(strings.TrimSpace(id))
	if norm == "" {
		return nil, false
	}
	p, ok := m.providers[norm]
	return p, ok && p != nil
}

// ResolveEndpoints resolves authorization, token, JWKS, and issuer metadata for provider p,
// fetching and caching the OIDC discovery document when needed.
func (p *SSOProvider) ResolveEndpoints(ctx context.Context) (SSOEndpoints, error) {
	if p == nil {
		return SSOEndpoints{}, ErrSSOProviderNotFound
	}
	ep := SSOEndpoints{
		Issuer:                p.issuer,
		AuthorizationEndpoint: p.authorizationEndpoint,
		TokenEndpoint:         p.tokenEndpoint,
		JWKSURL:               p.jwksURL,
	}
	if ep.AuthorizationEndpoint != "" && ep.TokenEndpoint != "" && ep.JWKSURL != "" && ep.Issuer != "" {
		return ep, nil
	}
	if p.discoveryURL == "" {
		return ep, nil
	}

	now := p.currentTime()
	p.mu.RLock()
	cached := p.discovered
	fresh := cached != nil && !p.discoveredAt.IsZero() && now.Sub(p.discoveredAt) < p.discoveryTTL
	p.mu.RUnlock()

	if !fresh {
		res, err, _ := p.discoveryGroup.Do("discovery", func() (any, error) {
			now := p.currentTime()
			p.mu.RLock()
			stillCached := p.discovered
			stillFresh := stillCached != nil && !p.discoveredAt.IsZero() && now.Sub(p.discoveredAt) < p.discoveryTTL
			p.mu.RUnlock()
			if stillFresh {
				return *stillCached, nil
			}
			fetched, fetchErr := p.fetchDiscovery(ctx)
			if fetchErr != nil {
				return SSOEndpoints{}, fetchErr
			}
			discoveredAt := p.currentTime()
			p.mu.Lock()
			p.discovered = &fetched
			p.discoveredAt = discoveredAt
			p.mu.Unlock()
			return fetched, nil
		})
		if err != nil {
			return SSOEndpoints{}, err
		}
		d := res.(SSOEndpoints)
		cached = &d
	}

	if cached != nil {
		if ep.Issuer == "" {
			ep.Issuer = cached.Issuer
		}
		if ep.AuthorizationEndpoint == "" {
			ep.AuthorizationEndpoint = cached.AuthorizationEndpoint
		}
		if ep.TokenEndpoint == "" {
			ep.TokenEndpoint = cached.TokenEndpoint
		}
		if ep.JWKSURL == "" {
			ep.JWKSURL = cached.JWKSURL
		}
	}
	return ep, nil
}

func (p *SSOProvider) currentTime() time.Time {
	p.mu.RLock()
	fn := p.now
	p.mu.RUnlock()
	if fn == nil {
		return time.Now().UTC()
	}
	return fn().UTC()
}

type ssoDiscoveryDoc struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
}

func (p *SSOProvider) fetchDiscovery(ctx context.Context) (SSOEndpoints, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.discoveryURL, nil)
	if err != nil {
		return SSOEndpoints{}, &SSOError{
			StatusCode: http.StatusBadGateway,
			Type:       domain.ErrorTypeServer,
			Code:       "sso_discovery_failed",
			Message:    "Failed to build OIDC discovery request",
			Err:        err,
		}
	}
	req.Header.Set("Accept", "application/json")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return SSOEndpoints{}, &SSOError{
			StatusCode: http.StatusBadGateway,
			Type:       domain.ErrorTypeServer,
			Code:       "sso_discovery_unreachable",
			Message:    "Failed to fetch OIDC discovery document",
			Err:        err,
		}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return SSOEndpoints{}, &SSOError{
			StatusCode: http.StatusBadGateway,
			Type:       domain.ErrorTypeServer,
			Code:       "sso_discovery_failed",
			Message:    fmt.Sprintf("OIDC discovery endpoint returned HTTP %d", resp.StatusCode),
		}
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxJWTDocumentBytes))
	if err != nil {
		return SSOEndpoints{}, &SSOError{
			StatusCode: http.StatusBadGateway,
			Type:       domain.ErrorTypeServer,
			Code:       "sso_discovery_failed",
			Message:    "Failed to read OIDC discovery document",
			Err:        err,
		}
	}

	var doc ssoDiscoveryDoc
	if err := json.Unmarshal(body, &doc); err != nil {
		return SSOEndpoints{}, &SSOError{
			StatusCode: http.StatusBadGateway,
			Type:       domain.ErrorTypeServer,
			Code:       "sso_discovery_invalid",
			Message:    "Invalid OIDC discovery JSON",
			Err:        err,
		}
	}

	docIss := strings.TrimSpace(doc.Issuer)
	if p.issuer != "" && docIss != "" && !strings.Contains(docIss, "{tenantid}") && docIss != p.issuer {
		return SSOEndpoints{}, &SSOError{
			StatusCode: http.StatusBadGateway,
			Type:       domain.ErrorTypeServer,
			Code:       "sso_discovery_issuer_mismatch",
			Message:    fmt.Sprintf("OIDC discovery issuer %q does not match configured issuer %q", docIss, p.issuer),
		}
	}

	return SSOEndpoints{
		Issuer:                docIss,
		AuthorizationEndpoint: strings.TrimSpace(doc.AuthorizationEndpoint),
		TokenEndpoint:         strings.TrimSpace(doc.TokenEndpoint),
		JWKSURL:               strings.TrimSpace(doc.JWKSURI),
	}, nil
}

// BuildAuthorizationURL generates PKCE S256 + state + nonce, persists state in stateStore,
// and returns the IdP authorization URL and opaque state parameter.
func (m *SSOProviderManager) BuildAuthorizationURL(
	ctx context.Context,
	providerID, redirectURI, redirectAfter, cliLoginID string,
	stateStore *SSOStateStore,
) (authURL string, state string, err error) {
	if m == nil {
		return "", "", &SSOError{
			StatusCode: http.StatusServiceUnavailable,
			Type:       domain.ErrorTypeServer,
			Code:       "sso_unavailable",
			Message:    "SSO provider manager is not initialized",
		}
	}
	if stateStore == nil {
		return "", "", &SSOError{
			StatusCode: http.StatusServiceUnavailable,
			Type:       domain.ErrorTypeServer,
			Code:       "sso_state_unavailable",
			Message:    "SSO state store is not initialized",
		}
	}

	p, ok := m.GetProvider(providerID)
	if !ok {
		return "", "", &SSOError{
			StatusCode: http.StatusNotFound,
			Type:       domain.ErrorTypeNotFound,
			Code:       "sso_provider_not_found",
			Message:    fmt.Sprintf("SSO provider %q is not configured", providerID),
			Err:        ErrSSOProviderNotFound,
		}
	}

	ep, err := p.ResolveEndpoints(ctx)
	if err != nil {
		return "", "", err
	}
	if ep.AuthorizationEndpoint == "" {
		return "", "", &SSOError{
			StatusCode: http.StatusBadGateway,
			Type:       domain.ErrorTypeServer,
			Code:       "sso_missing_authorization_endpoint",
			Message:    fmt.Sprintf("SSO provider %q has no authorization_endpoint", p.id),
		}
	}

	parsedAuth, err := url.Parse(ep.AuthorizationEndpoint)
	if err != nil || (parsedAuth.Scheme != "http" && parsedAuth.Scheme != "https") || parsedAuth.Host == "" {
		return "", "", &SSOError{
			StatusCode: http.StatusBadGateway,
			Type:       domain.ErrorTypeServer,
			Code:       "sso_invalid_authorization_endpoint",
			Message:    fmt.Sprintf("SSO provider %q has invalid authorization_endpoint", p.id),
		}
	}

	pkce, err := upstream.GeneratePKCE()
	if err != nil {
		return "", "", &SSOError{
			StatusCode: http.StatusInternalServerError,
			Type:       domain.ErrorTypeServer,
			Code:       "pkce_generation_failed",
			Message:    "Failed to generate PKCE challenge",
			Err:        err,
		}
	}

	state, err = randomBase64URL(32)
	if err != nil {
		return "", "", &SSOError{
			StatusCode: http.StatusInternalServerError,
			Type:       domain.ErrorTypeServer,
			Code:       "sso_state_generation_failed",
			Message:    "Failed to generate SSO state",
			Err:        err,
		}
	}

	nonce, err := randomBase64URL(32)
	if err != nil {
		return "", "", &SSOError{
			StatusCode: http.StatusInternalServerError,
			Type:       domain.ErrorTypeServer,
			Code:       "sso_nonce_generation_failed",
			Message:    "Failed to generate SSO nonce",
			Err:        err,
		}
	}

	effectiveRedirectURI := strings.TrimSpace(p.redirectURL)
	if effectiveRedirectURI == "" {
		effectiveRedirectURI = strings.TrimSpace(redirectURI)
	}

	if err := stateStore.Save(ctx, &SSOAuthState{
		State:         state,
		Provider:      p.id,
		CodeVerifier:  pkce.CodeVerifier,
		Nonce:         nonce,
		RedirectAfter: strings.TrimSpace(redirectAfter),
		RedirectURI:   effectiveRedirectURI,
		CLILoginID:    strings.TrimSpace(cliLoginID),
	}); err != nil {
		return "", "", &SSOError{
			StatusCode: http.StatusServiceUnavailable,
			Type:       domain.ErrorTypeServer,
			Code:       "sso_state_persist_failed",
			Message:    "Failed to persist SSO state",
			Err:        err,
		}
	}

	q := parsedAuth.Query()
	q.Set("response_type", "code")
	q.Set("client_id", p.clientID)
	if effectiveRedirectURI != "" {
		q.Set("redirect_uri", effectiveRedirectURI)
	}
	q.Set("scope", strings.Join(p.scopes, " "))
	q.Set("state", state)
	q.Set("nonce", nonce)
	q.Set("code_challenge", pkce.CodeChallenge)
	q.Set("code_challenge_method", pkce.CodeChallengeMethod)
	parsedAuth.RawQuery = q.Encode()

	return parsedAuth.String(), state, nil
}

type oidcTokenExchangeResponse struct {
	AccessToken      string `json:"access_token"`
	IDToken          string `json:"id_token"`
	TokenType        string `json:"token_type"`
	ExpiresIn        int64  `json:"expires_in"`
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

// ExchangeAndVerify exchanges the authorization code with PKCE code_verifier at the IdP token endpoint,
// verifies the returned ID token signature, issuer, audience, nonce, and allowed email domains.
func (m *SSOProviderManager) ExchangeAndVerify(
	ctx context.Context,
	providerID, code, redirectURI, codeVerifier, expectedNonce string,
) (*SSOIDTokenClaims, error) {
	if m == nil {
		return nil, &SSOError{
			StatusCode: http.StatusServiceUnavailable,
			Type:       domain.ErrorTypeServer,
			Code:       "sso_unavailable",
			Message:    "SSO provider manager is not initialized",
		}
	}
	p, ok := m.GetProvider(providerID)
	if !ok {
		return nil, &SSOError{
			StatusCode: http.StatusNotFound,
			Type:       domain.ErrorTypeNotFound,
			Code:       "sso_provider_not_found",
			Message:    fmt.Sprintf("SSO provider %q is not configured", providerID),
			Err:        ErrSSOProviderNotFound,
		}
	}

	ep, err := p.ResolveEndpoints(ctx)
	if err != nil {
		return nil, err
	}
	if ep.TokenEndpoint == "" {
		return nil, &SSOError{
			StatusCode: http.StatusBadGateway,
			Type:       domain.ErrorTypeServer,
			Code:       "sso_missing_token_endpoint",
			Message:    fmt.Sprintf("SSO provider %q has no token_endpoint", p.id),
		}
	}

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	if strings.TrimSpace(redirectURI) != "" {
		form.Set("redirect_uri", strings.TrimSpace(redirectURI))
	}
	form.Set("client_id", p.clientID)
	form.Set("code_verifier", codeVerifier)
	if p.clientSecret != "" {
		form.Set("client_secret", p.clientSecret)
	}

	tokenReq, err := http.NewRequestWithContext(ctx, http.MethodPost, ep.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, &SSOError{
			StatusCode: http.StatusBadGateway,
			Type:       domain.ErrorTypeServer,
			Code:       "sso_token_exchange_failed",
			Message:    "Failed to construct token exchange request",
			Err:        err,
		}
	}
	tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokenReq.Header.Set("Accept", "application/json")

	resp, err := p.httpClient.Do(tokenReq)
	if err != nil {
		return nil, &SSOError{
			StatusCode: http.StatusBadGateway,
			Type:       domain.ErrorTypeServer,
			Code:       "sso_token_endpoint_unreachable",
			Message:    "Failed to reach SSO token endpoint",
			Err:        err,
		}
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxOIDCTokenResponseBytes))
	if err != nil {
		return nil, &SSOError{
			StatusCode: http.StatusBadGateway,
			Type:       domain.ErrorTypeServer,
			Code:       "sso_token_exchange_failed",
			Message:    "Failed to read SSO token response",
			Err:        err,
		}
	}

	var tokenResp oidcTokenExchangeResponse
	_ = json.Unmarshal(body, &tokenResp)
	if resp.StatusCode != http.StatusOK {
		msg := "SSO token exchange failed"
		if tokenResp.Error != "" {
			msg = fmt.Sprintf("SSO token exchange failed (%s: %s)", tokenResp.Error, tokenResp.ErrorDescription)
		}
		status := http.StatusUnauthorized
		if resp.StatusCode >= 500 {
			status = http.StatusBadGateway
		}
		return nil, &SSOError{
			StatusCode: status,
			Type:       domain.ErrorTypeAuthentication,
			Code:       "sso_token_exchange_failed",
			Message:    msg,
		}
	}

	rawIDToken := strings.TrimSpace(tokenResp.IDToken)
	if rawIDToken == "" {
		return nil, &SSOError{
			StatusCode: http.StatusUnauthorized,
			Type:       domain.ErrorTypeAuthentication,
			Code:       "sso_missing_id_token",
			Message:    "SSO token response did not include an id_token",
		}
	}

	return p.verifyIDToken(ctx, ep, rawIDToken, expectedNonce)
}

func (p *SSOProvider) getOrInitVerifier(ep SSOEndpoints) (*OIDCVerifier, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.verifier != nil {
		return p.verifier, nil
	}

	jwksURL := ep.JWKSURL
	discoveryURL := p.discoveryURL
	if jwksURL == "" && discoveryURL == "" {
		return nil, &SSOError{
			StatusCode: http.StatusBadGateway,
			Type:       domain.ErrorTypeServer,
			Code:       "sso_missing_jwks",
			Message:    fmt.Sprintf("SSO provider %q has neither jwks_url nor discovery_url", p.id),
		}
	}

	// Microsoft multi-tenant endpoints return issuer templates containing "{tenantid}";
	// handle template matching explicitly after signature verification.
	verifierIssuer := ep.Issuer
	if strings.Contains(verifierIssuer, "{tenantid}") {
		verifierIssuer = ""
	}

	v := NewOIDCVerifier(OIDCIssuerConfig{
		Issuer:        verifierIssuer,
		Audience:      p.clientID,
		JWKSURL:       jwksURL,
		DiscoveryURL:  discoveryURL,
		Algorithms:    p.algorithms,
		ClaimMapping:  p.claimMapping,
		AutoRegister:  p.autoRegister,
		DefaultOrgID:  p.defaultOrgID,
		DefaultTeamID: p.defaultTeamID,
		DefaultRole:   p.defaultRole,
		NetworkPolicy: p.netPolicy,
		HTTPClient:    p.httpClient,
		Now:           p.now,
	})
	p.verifier = v
	return v, nil
}

func (p *SSOProvider) verifyIDToken(ctx context.Context, ep SSOEndpoints, rawIDToken, expectedNonce string) (*SSOIDTokenClaims, error) {
	verifier, err := p.getOrInitVerifier(ep)
	if err != nil {
		return nil, err
	}

	claims, err := verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, &SSOError{
			StatusCode: http.StatusUnauthorized,
			Type:       domain.ErrorTypeAuthentication,
			Code:       "invalid_id_token",
			Message:    "ID token verification failed: " + err.Error(),
			Err:        err,
		}
	}

	// Enforce Microsoft Entra ID templated multi-tenant issuer if applicable.
	if strings.Contains(ep.Issuer, "{tenantid}") {
		tid, _ := extractStringClaim(claims.RawClaims, "tid")
		if tid == "" {
			return nil, &SSOError{
				StatusCode: http.StatusUnauthorized,
				Type:       domain.ErrorTypeAuthentication,
				Code:       "invalid_id_token",
				Message:    "ID token missing tid claim for multi-tenant issuer validation",
			}
		}
		wantIss := strings.ReplaceAll(ep.Issuer, "{tenantid}", tid)
		if claims.Issuer != wantIss {
			return nil, &SSOError{
				StatusCode: http.StatusUnauthorized,
				Type:       domain.ErrorTypeAuthentication,
				Code:       "invalid_id_token",
				Message:    fmt.Sprintf("ID token issuer mismatch: got %q, want %q", claims.Issuer, wantIss),
			}
		}
	}

	// OIDC Core Section 3.1.3.7: validate azp when multiple audiences are present.
	if len(claims.Audience) > 1 {
		if azp, hasAZP := extractStringClaim(claims.RawClaims, "azp"); hasAZP && azp != p.clientID {
			return nil, &SSOError{
				StatusCode: http.StatusUnauthorized,
				Type:       domain.ErrorTypeAuthentication,
				Code:       "invalid_id_token",
				Message:    "ID token azp claim does not match client_id",
			}
		}
	}

	// OIDC Core Section 3.1.3.7: validate nonce against bound auth state.
	if strings.TrimSpace(expectedNonce) == "" {
		return nil, &SSOError{
			StatusCode: http.StatusUnauthorized,
			Type:       domain.ErrorTypeAuthentication,
			Code:       "invalid_sso_nonce",
			Message:    "Expected SSO nonce is missing",
		}
	}
	tokenNonce, hasNonce := extractStringClaim(claims.RawClaims, "nonce")
	if !hasNonce || subtle.ConstantTimeCompare([]byte(tokenNonce), []byte(expectedNonce)) != 1 {
		return nil, &SSOError{
			StatusCode: http.StatusUnauthorized,
			Type:       domain.ErrorTypeAuthentication,
			Code:       "invalid_sso_nonce",
			Message:    "ID token nonce does not match SSO session",
		}
	}

	email := strings.TrimSpace(claims.Email)
	if email == "" && p.providerType == "microsoft" && strings.TrimSpace(p.claimMapping.Email) == "" {
		if v, ok := extractStringClaim(claims.RawClaims, "preferred_username"); ok {
			email = v
		} else if v, ok := extractStringClaim(claims.RawClaims, "upn"); ok {
			email = v
		}
	}

	if err := p.enforceAllowedEmailDomain(email); err != nil {
		return nil, &SSOError{
			StatusCode: http.StatusForbidden,
			Type:       domain.ErrorTypePermission,
			Code:       "email_domain_not_allowed",
			Message:    err.Error(),
			Err:        err,
		}
	}

	displayName := extractSSODisplayName(claims.RawClaims, email, claims.Subject)

	return &SSOIDTokenClaims{
		Subject:     claims.Subject,
		Issuer:      claims.Issuer,
		Email:       email,
		DisplayName: displayName,
		OrgID:       claims.OrgID,
		TeamIDs:     claims.TeamIDs,
		Role:        claims.Role,
		RawClaims:   claims.RawClaims,
	}, nil
}

func (p *SSOProvider) enforceAllowedEmailDomain(email string) error {
	if len(p.allowedEmailDomains) == 0 {
		return nil
	}
	trimmed := strings.TrimSpace(email)
	atIdx := strings.LastIndex(trimmed, "@")
	if atIdx < 0 || atIdx == len(trimmed)-1 {
		return errors.New("id token missing valid email claim required by allowed_email_domains")
	}
	domainPart := strings.ToLower(strings.TrimSpace(trimmed[atIdx+1:]))
	for _, allowed := range p.allowedEmailDomains {
		if domainPart == allowed {
			return nil
		}
	}
	return fmt.Errorf("email domain %q is not in allowed_email_domains", domainPart)
}

func extractSSODisplayName(raw map[string]any, fallbacks ...string) string {
	if raw != nil {
		if v, ok := extractStringClaim(raw, "name"); ok {
			return v
		}
		given, _ := extractStringClaim(raw, "given_name")
		family, _ := extractStringClaim(raw, "family_name")
		full := strings.TrimSpace(given + " " + family)
		if full != "" {
			return full
		}
	}
	return firstNonEmpty(fallbacks...)
}

// SSOAuthState stores transient PKCE, nonce, and optional CLI link state for an in-flight OIDC flow.
type SSOAuthState struct {
	State         string    `json:"state"`
	Provider      string    `json:"provider"`
	CodeVerifier  string    `json:"code_verifier"`
	Nonce         string    `json:"nonce"`
	RedirectAfter string    `json:"redirect_after,omitempty"`
	RedirectURI   string    `json:"redirect_uri,omitempty"`
	CLILoginID    string    `json:"cli_login_id,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
	ExpiresAt     time.Time `json:"expires_at"`
}

// SSOStateStore persists short-lived OIDC PKCE/state/nonce records in Redis (10m TTL) with in-memory fallback.
type SSOStateStore struct {
	redis *storage.RedisFabric
	ttl   time.Duration

	mu     sync.Mutex
	states map[string]*SSOAuthState
	now    func() time.Time
}

// NewSSOStateStore constructs an SSOStateStore with a 10-minute default TTL.
func NewSSOStateStore(redisFabric *storage.RedisFabric) *SSOStateStore {
	return &SSOStateStore{
		redis:  redisFabric,
		ttl:    DefaultSSOStateTTL,
		states: make(map[string]*SSOAuthState),
		now:    time.Now,
	}
}

// SetNowFunc overrides the clock function for deterministic state expiration tests.
func (s *SSOStateStore) SetNowFunc(fn func() time.Time) {
	if s == nil || fn == nil {
		return
	}
	s.mu.Lock()
	s.now = fn
	s.mu.Unlock()
}

func (s *SSOStateStore) currentTime() time.Time {
	s.mu.Lock()
	fn := s.now
	s.mu.Unlock()
	if fn == nil {
		return time.Now().UTC()
	}
	return fn().UTC()
}

func ssoStateRedisKey(state string) string {
	return "gw:sso:state:" + state
}

// Save stores an SSOAuthState for single-use callback verification.
func (s *SSOStateStore) Save(ctx context.Context, st *SSOAuthState) error {
	if s == nil || st == nil || strings.TrimSpace(st.State) == "" {
		return errors.New("sso state is required")
	}
	now := s.currentTime()
	cp := *st
	if cp.CreatedAt.IsZero() {
		cp.CreatedAt = now
	}
	if cp.ExpiresAt.IsZero() {
		cp.ExpiresAt = cp.CreatedAt.Add(s.ttl)
	}
	ttl := cp.ExpiresAt.Sub(now)
	if ttl <= 0 {
		ttl = s.ttl
	}

	if s.redis != nil {
		raw, err := json.Marshal(&cp)
		if err != nil {
			return err
		}
		_, err = s.redis.Execute(func(rdb redis.UniversalClient) (any, error) {
			return rdb.Set(ctx, ssoStateRedisKey(cp.State), raw, ttl).Result()
		})
		if err == nil {
			return nil
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	for k, existing := range s.states {
		if existing == nil || !now.Before(existing.ExpiresAt) {
			delete(s.states, k)
		}
	}
	s.states[cp.State] = &cp
	return nil
}

// Consume atomically retrieves and deletes an SSOAuthState so state tokens cannot be replayed.
func (s *SSOStateStore) Consume(ctx context.Context, state string) (*SSOAuthState, error) {
	if s == nil {
		return nil, ErrSSOStateNotFound
	}
	state = strings.TrimSpace(state)
	if state == "" {
		return nil, ErrSSOStateNotFound
	}
	now := s.currentTime()

	if s.redis != nil {
		res, err := s.redis.Execute(func(rdb redis.UniversalClient) (any, error) {
			return consumeAndDeleteLua.Run(ctx, rdb, []string{ssoStateRedisKey(state)}).Result()
		})
		if err == nil {
			if raw, ok := res.(string); ok && raw != "" {
				var st SSOAuthState
				if jsonErr := json.Unmarshal([]byte(raw), &st); jsonErr != nil {
					return nil, ErrSSOStateNotFound
				}
				if !now.Before(st.ExpiresAt) {
					return nil, ErrSSOStateNotFound
				}
				return &st, nil
			}
			// If Redis returned nil, still check local fallback in case Save fell back during a transient blip.
		}
	}

	s.mu.Lock()
	st, ok := s.states[state]
	if ok {
		delete(s.states, state)
	}
	s.mu.Unlock()

	if !ok || st == nil || !now.Before(st.ExpiresAt) {
		return nil, ErrSSOStateNotFound
	}
	return st, nil
}

// CLILoginStatus represents the lifecycle state of a CLI browser/device SSO login request.
type CLILoginStatus string

// Supported CLI SSO login session lifecycle states.
const (
	CLILoginStatusPending   CLILoginStatus = "pending"
	CLILoginStatusCompleted CLILoginStatus = "completed"
)

// CLILoginSession stores the state and transiently encrypted Virtual Key for a CLI SSO login.
type CLILoginSession struct {
	LoginID      string         `json:"login_id"`
	UserCode     string         `json:"user_code"`
	Provider     string         `json:"provider,omitempty"`
	Status       CLILoginStatus `json:"status"`
	OrgID        string         `json:"org_id,omitempty"`
	TeamID       string         `json:"team_id,omitempty"`
	UserID       string         `json:"user_id,omitempty"`
	KeyID        string         `json:"key_id,omitempty"`
	KeyPrefix    string         `json:"key_prefix,omitempty"`
	EncryptedKey string         `json:"encrypted_key,omitempty"`
	EncryptedDEK string         `json:"encrypted_dek,omitempty"`
	CreatedAt    time.Time      `json:"created_at"`
	ExpiresAt    time.Time      `json:"expires_at"`
	CompletedAt  *time.Time     `json:"completed_at,omitempty"`
}

// CLILoginPollResult represents the outcome of polling GET /auth/cli/poll/{login_id}.
type CLILoginPollResult struct {
	Status    CLILoginStatus
	LoginID   string
	ExpiresIn int
	Interval  int
	APIKey    string
	KeyID     string
	KeyPrefix string
	OrgID     string
	TeamID    string
}

// CLILoginStore manages CLI browser/device login sessions in Redis (`gw:cli:login:<login_id>`,
// `gw:cli:poll:<login_id>`) with 10m TTL, poll rate limiting, and AES-256-GCM encrypted key storage.
type CLILoginStore struct {
	redis        *storage.RedisFabric
	vault        *Vault
	ttl          time.Duration
	pollInterval time.Duration

	mu       sync.Mutex
	sessions map[string]*CLILoginSession
	lastPoll map[string]time.Time
	now      func() time.Time
}

// NewCLILoginStore constructs a CLILoginStore using vault for transient AES-256-GCM Virtual Key encryption.
func NewCLILoginStore(redisFabric *storage.RedisFabric, vault *Vault) *CLILoginStore {
	return &CLILoginStore{
		redis:        redisFabric,
		vault:        vault,
		ttl:          DefaultCLILoginTTL,
		pollInterval: DefaultCLIPollInterval,
		sessions:     make(map[string]*CLILoginSession),
		lastPoll:     make(map[string]time.Time),
		now:          time.Now,
	}
}

// SetNowFunc overrides the clock function for deterministic CLI expiration and poll rate-limit tests.
func (s *CLILoginStore) SetNowFunc(fn func() time.Time) {
	if s == nil || fn == nil {
		return
	}
	s.mu.Lock()
	s.now = fn
	s.mu.Unlock()
}

// SetPollInterval overrides the minimum poll interval (for testing or configuration).
func (s *CLILoginStore) SetPollInterval(d time.Duration) {
	if s == nil || d <= 0 {
		return
	}
	s.mu.Lock()
	s.pollInterval = d
	s.mu.Unlock()
}

// PollInterval returns the configured minimum CLI poll interval.
func (s *CLILoginStore) PollInterval() time.Duration {
	if s == nil {
		return DefaultCLIPollInterval
	}
	s.mu.Lock()
	d := s.pollInterval
	s.mu.Unlock()
	if d <= 0 {
		return DefaultCLIPollInterval
	}
	return d
}

// TTL returns the CLI login session lifetime.
func (s *CLILoginStore) TTL() time.Duration {
	if s == nil || s.ttl <= 0 {
		return DefaultCLILoginTTL
	}
	return s.ttl
}

func (s *CLILoginStore) currentTime() time.Time {
	s.mu.Lock()
	fn := s.now
	s.mu.Unlock()
	if fn == nil {
		return time.Now().UTC()
	}
	return fn().UTC()
}

func cliLoginRedisKey(loginID string) string {
	return "gw:cli:login:" + loginID
}

func cliPollRedisKey(loginID string) string {
	return "gw:cli:poll:" + loginID
}

// Start creates a new pending CLI login session with a random login_id and human-readable user_code.
func (s *CLILoginStore) Start(ctx context.Context, provider string) (*CLILoginSession, error) {
	if s == nil {
		return nil, errors.New("cli login store is nil")
	}
	idBytes := make([]byte, 16)
	if _, err := rand.Read(idBytes); err != nil {
		return nil, fmt.Errorf("generate cli login id: %w", err)
	}
	loginID := "cli_" + hex.EncodeToString(idBytes)

	userCode, err := generateCLIUserCode()
	if err != nil {
		return nil, fmt.Errorf("generate cli user code: %w", err)
	}

	now := s.currentTime()
	sess := &CLILoginSession{
		LoginID:   loginID,
		UserCode:  userCode,
		Provider:  strings.ToLower(strings.TrimSpace(provider)),
		Status:    CLILoginStatusPending,
		CreatedAt: now,
		ExpiresAt: now.Add(s.TTL()),
	}

	if err := s.saveSession(ctx, sess, now); err != nil {
		return nil, err
	}
	cp := *sess
	return &cp, nil
}

func (s *CLILoginStore) saveSession(ctx context.Context, sess *CLILoginSession, now time.Time) error {
	ttl := sess.ExpiresAt.Sub(now)
	if ttl <= 0 {
		return ErrCLILoginNotFound
	}
	if s.redis != nil {
		raw, err := json.Marshal(sess)
		if err != nil {
			return err
		}
		_, err = s.redis.Execute(func(rdb redis.UniversalClient) (any, error) {
			return rdb.Set(ctx, cliLoginRedisKey(sess.LoginID), raw, ttl).Result()
		})
		if err == nil {
			return nil
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	for k, existing := range s.sessions {
		if existing == nil || !now.Before(existing.ExpiresAt) {
			delete(s.sessions, k)
			delete(s.lastPoll, k)
		}
	}
	cp := *sess
	s.sessions[sess.LoginID] = &cp
	return nil
}

// Get retrieves a CLI login session if it exists and has not expired.
func (s *CLILoginStore) Get(ctx context.Context, loginID string) (*CLILoginSession, error) {
	if s == nil {
		return nil, ErrCLILoginNotFound
	}
	loginID = strings.TrimSpace(loginID)
	if loginID == "" {
		return nil, ErrCLILoginNotFound
	}
	now := s.currentTime()

	if s.redis != nil {
		res, err := s.redis.Execute(func(rdb redis.UniversalClient) (any, error) {
			return rdb.Get(ctx, cliLoginRedisKey(loginID)).Result()
		})
		if err == nil {
			if raw, ok := res.(string); ok && raw != "" {
				var sess CLILoginSession
				if jsonErr := json.Unmarshal([]byte(raw), &sess); jsonErr != nil {
					return nil, ErrCLILoginNotFound
				}
				if !now.Before(sess.ExpiresAt) {
					return nil, ErrCLILoginNotFound
				}
				return &sess, nil
			}
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[loginID]
	if !ok || sess == nil || !now.Before(sess.ExpiresAt) {
		delete(s.sessions, loginID)
		delete(s.lastPoll, loginID)
		return nil, ErrCLILoginNotFound
	}
	cp := *sess
	return &cp, nil
}

// Complete marks a pending CLI login session as completed and stores the encrypted Virtual Key
// transiently until the single-use CLI poll retrieves and deletes it.
func (s *CLILoginStore) Complete(ctx context.Context, loginID, orgID, teamID, userID, keyID, keyPrefix, rawKey string) (*CLILoginSession, error) {
	if s == nil {
		return nil, ErrCLILoginNotFound
	}
	if s.vault == nil {
		return nil, errors.New("cli login store requires vault encryption for transient virtual keys")
	}
	loginID = strings.TrimSpace(loginID)
	if loginID == "" || strings.TrimSpace(rawKey) == "" {
		return nil, ErrCLILoginNotFound
	}

	sess, err := s.Get(ctx, loginID)
	if err != nil {
		return nil, err
	}
	if sess.Status == CLILoginStatusCompleted {
		return nil, ErrCLILoginAlreadyCompleted
	}

	encKey, encDEK, err := s.vault.EncryptString(rawKey)
	if err != nil {
		return nil, fmt.Errorf("encrypt transient cli virtual key: %w", err)
	}

	now := s.currentTime()
	sess.Status = CLILoginStatusCompleted
	sess.OrgID = strings.TrimSpace(orgID)
	sess.TeamID = strings.TrimSpace(teamID)
	sess.UserID = strings.TrimSpace(userID)
	sess.KeyID = strings.TrimSpace(keyID)
	sess.KeyPrefix = strings.TrimSpace(keyPrefix)
	sess.EncryptedKey = encKey
	sess.EncryptedDEK = encDEK
	sess.CompletedAt = &now

	if err := s.saveSession(ctx, sess, now); err != nil {
		return nil, err
	}
	cp := *sess
	return &cp, nil
}

// Poll enforces poll interval rate-limiting (`ErrCLIPollRateLimited`) and performs single-use
// pickup of a completed CLI login session, deleting the session immediately after retrieval.
func (s *CLILoginStore) Poll(ctx context.Context, loginID string) (*CLILoginPollResult, error) {
	if s == nil {
		return nil, ErrCLILoginNotFound
	}
	loginID = strings.TrimSpace(loginID)
	if loginID == "" {
		return nil, ErrCLILoginNotFound
	}
	now := s.currentTime()

	sess, err := s.Get(ctx, loginID)
	if err != nil {
		return nil, err
	}

	interval := s.PollInterval()
	if err := s.checkAndRecordPoll(ctx, loginID, now, interval); err != nil {
		return nil, err
	}

	if sess.Status != CLILoginStatusCompleted {
		remSec := int(sess.ExpiresAt.Sub(now).Seconds())
		if remSec < 0 {
			remSec = 0
		}
		intervalSec := int(interval.Seconds())
		if intervalSec < 1 {
			intervalSec = 1
		}
		return &CLILoginPollResult{
			Status:    CLILoginStatusPending,
			LoginID:   loginID,
			ExpiresIn: remSec,
			Interval:  intervalSec,
		}, nil
	}

	consumed, err := s.consumeSession(ctx, loginID, now)
	if err != nil {
		return nil, err
	}
	if s.vault == nil {
		return nil, errors.New("cli login store vault is unavailable")
	}
	rawKey, err := s.vault.DecryptString(consumed.EncryptedKey, consumed.EncryptedDEK)
	if err != nil || rawKey == "" {
		return nil, fmt.Errorf("decrypt transient cli virtual key: %w", err)
	}

	return &CLILoginPollResult{
		Status:    CLILoginStatusCompleted,
		LoginID:   loginID,
		APIKey:    rawKey,
		KeyID:     consumed.KeyID,
		KeyPrefix: consumed.KeyPrefix,
		OrgID:     consumed.OrgID,
		TeamID:    consumed.TeamID,
	}, nil
}

func (s *CLILoginStore) checkAndRecordPoll(ctx context.Context, loginID string, now time.Time, interval time.Duration) error {
	if s.redis != nil {
		intervalMs := interval.Milliseconds()
		if intervalMs <= 0 {
			intervalMs = 1
		}
		res, err := s.redis.Execute(func(rdb redis.UniversalClient) (any, error) {
			return cliPollRateLimitLua.Run(ctx, rdb, []string{cliPollRedisKey(loginID)}, intervalMs).Result()
		})
		if err == nil {
			if ttlMs, ok := res.(int64); ok {
				if ttlMs > 0 {
					return &SSOError{
						StatusCode: http.StatusTooManyRequests,
						Type:       domain.ErrorTypeRateLimit,
						Code:       "slow_down",
						Message:    "CLI polling too frequently; slow down and retry after interval",
						RetryAfter: time.Duration(ttlMs) * time.Millisecond,
						Err:        ErrCLIPollRateLimited,
					}
				}
				return nil
			}
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if last, ok := s.lastPoll[loginID]; ok && now.Sub(last) < interval {
		retryAfter := interval - now.Sub(last)
		return &SSOError{
			StatusCode: http.StatusTooManyRequests,
			Type:       domain.ErrorTypeRateLimit,
			Code:       "slow_down",
			Message:    "CLI polling too frequently; slow down and retry after interval",
			RetryAfter: retryAfter,
			Err:        ErrCLIPollRateLimited,
		}
	}
	s.lastPoll[loginID] = now
	return nil
}

func (s *CLILoginStore) consumeSession(ctx context.Context, loginID string, now time.Time) (*CLILoginSession, error) {
	if s.redis != nil {
		res, err := s.redis.Execute(func(rdb redis.UniversalClient) (any, error) {
			val, luaErr := consumeAndDeleteLua.Run(ctx, rdb, []string{cliLoginRedisKey(loginID)}).Result()
			_, _ = rdb.Del(ctx, cliPollRedisKey(loginID)).Result()
			return val, luaErr
		})
		if err == nil {
			if raw, ok := res.(string); ok && raw != "" {
				var sess CLILoginSession
				if jsonErr := json.Unmarshal([]byte(raw), &sess); jsonErr != nil {
					return nil, ErrCLILoginNotFound
				}
				if !now.Before(sess.ExpiresAt) {
					return nil, ErrCLILoginNotFound
				}
				return &sess, nil
			}
		}
	}

	s.mu.Lock()
	sess, ok := s.sessions[loginID]
	if ok {
		delete(s.sessions, loginID)
		delete(s.lastPoll, loginID)
	}
	s.mu.Unlock()

	if !ok || sess == nil || !now.Before(sess.ExpiresAt) {
		return nil, ErrCLILoginNotFound
	}
	cp := *sess
	return &cp, nil
}

func randomBase64URL(numBytes int) (string, error) {
	buf := make([]byte, numBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

const cliUserCodeAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"

func generateCLIUserCode() (string, error) {
	raw := make([]byte, 8)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	var b strings.Builder
	b.Grow(9)
	for i, v := range raw {
		if i == 4 {
			b.WriteByte('-')
		}
		b.WriteByte(cliUserCodeAlphabet[int(v)%len(cliUserCodeAlphabet)])
	}
	return b.String(), nil
}
