package auth

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/security/network"
	"golang.org/x/sync/singleflight"
)

const (
	defaultJWKSCacheTTL        = 5 * time.Minute
	defaultDiscoveryCacheTTL   = 1 * time.Hour
	defaultStaleJWKSCacheTTL   = 24 * time.Hour
	defaultMinRefreshInterval  = 10 * time.Second
	defaultUnreachableCooldown = 30 * time.Second
	defaultOIDCRefreshAttempts = 3
	defaultRetryBaseDelay      = 100 * time.Millisecond
	// DefaultJWTClockSkew is the bounded clock-skew leeway honored for exp/nbf validation.
	DefaultJWTClockSkew = 30 * time.Second
	maxJWTDocumentBytes = 1 << 20 // 1 MiB cap for discovery & JWKS payloads
)

// AudienceClaim supports RFC 7519 `aud` values encoded as either a single string or a string array.
type AudienceClaim []string

// UnmarshalJSON decodes a string or []string JSON value into AudienceClaim.
func (a *AudienceClaim) UnmarshalJSON(data []byte) error {
	var single string
	if err := json.Unmarshal(data, &single); err == nil {
		if single != "" {
			*a = AudienceClaim{single}
		}
		return nil
	}
	var multi []string
	if err := json.Unmarshal(data, &multi); err != nil {
		return err
	}
	*a = AudienceClaim(multi)
	return nil
}

// Contains returns true if the audience list contains target.
func (a AudienceClaim) Contains(target string) bool {
	for _, item := range a {
		if item == target {
			return true
		}
	}
	return false
}

// JWTClaims represents validated inbound JWT claims for Control Plane and Data Plane authentication.
type JWTClaims struct {
	Subject       string         `json:"sub"`
	Issuer        string         `json:"iss,omitempty"`
	Audience      AudienceClaim  `json:"aud,omitempty"`
	ExpiresAt     int64          `json:"exp,omitempty"`
	NotBefore     int64          `json:"nbf,omitempty"`
	IssuedAt      int64          `json:"iat,omitempty"`
	Email         string         `json:"email,omitempty"`
	EmailVerified bool           `json:"email_verified,omitempty"`
	Role          string         `json:"role,omitempty"`
	Groups        []string       `json:"groups,omitempty"`
	OrgID         string         `json:"org_id,omitempty"`
	TeamIDs       []string       `json:"team_ids,omitempty"`
	EndUserID     string         `json:"end_user_id,omitempty"`
	RawClaims     map[string]any `json:"-"`
}

// OIDCClaimMapping configures custom JWT claim paths (supporting both literal top-level keys
// and dot-separated nested JSON paths) for identity extraction.
type OIDCClaimMapping struct {
	UserID  string
	Email   string
	OrgID   string
	TeamIDs string
	Role    string
	Groups  string
	EndUser string
}

// OIDCIssuerConfig configures a single OIDC issuer verified via asymmetric JWKS/Discovery.
type OIDCIssuerConfig struct {
	Issuer                    string
	Audience                  string
	JWKSURL                   string
	DiscoveryURL              string
	Algorithms                []string
	AllowedEmailDomains       []string
	AllowUnverifiedEmail      bool
	AllowPrivilegedRoleClaims bool
	ClaimMapping              OIDCClaimMapping
	GroupRoleMappings         []GroupRoleMappingRule
	RoleMappingStrategy       string
	GroupTeamMappings         map[string]string
	AutoRegister              bool
	DefaultOrgID              string
	DefaultTeamID             string
	DefaultRole               string
	CacheTTL                  time.Duration
	DiscoveryTTL              time.Duration
	StaleCacheTTL             time.Duration
	UnreachableCooldown       time.Duration
	RefreshAttempts           int
	RetryBaseDelay            time.Duration
	ClockSkew                 time.Duration
	NetworkPolicy             *network.Policy
	HTTPClient                *http.Client
	Now                       func() time.Time
}

// MultiIssuerConfig configures multi-issuer OIDC verification with shared transport settings.
type MultiIssuerConfig struct {
	Issuers             []OIDCIssuerConfig
	NetworkPolicy       *network.Policy
	HTTPClient          *http.Client
	CacheTTL            time.Duration
	DiscoveryTTL        time.Duration
	StaleCacheTTL       time.Duration
	UnreachableCooldown time.Duration
	RefreshAttempts     int
	RetryBaseDelay      time.Duration
	ClockSkew           time.Duration
	Now                 func() time.Time
}

// JWTConfig configures inbound OIDC JWKS verification (single-issuer and/or multi-issuer).
type JWTConfig struct {
	Issuer              string
	Audience            string
	OIDCJWKSURL         string
	DiscoveryURL        string
	Algorithms          []string
	AllowedEmailDomains []string
	ClaimMapping        OIDCClaimMapping
	AutoRegister        bool
	DefaultOrgID        string
	DefaultTeamID       string
	DefaultRole         string
	Issuers             []OIDCIssuerConfig
	NetworkPolicy       *network.Policy
	HTTPClient          *http.Client
	CacheTTL            time.Duration
	DiscoveryTTL        time.Duration
	StaleCacheTTL       time.Duration
	UnreachableCooldown time.Duration
	RefreshAttempts     int
	RetryBaseDelay      time.Duration
	ClockSkew           time.Duration
	Now                 func() time.Time
}

type cachedJWK struct {
	key any
	alg string
}

// OIDCVerifier validates inbound asymmetric OIDC JWTs for a single configured issuer with
// OIDC Discovery / RFC 8414 metadata, bounded retry/cooldown, and stale-JWKS grace caching.
type OIDCVerifier struct {
	issuer                    string
	audience                  string
	staticJWKSURL             string
	discoveryURL              string
	derivedDiscovery          bool
	allowedAlgs               map[string]struct{}
	allowedEmailDomains       []string
	allowUnverifiedEmail      bool
	allowPrivilegedRoleClaims bool
	claimMapping              OIDCClaimMapping
	groupRoleMappings         []GroupRoleMappingRule
	roleMappingStrategy       string
	groupTeamMappings         map[string]string
	autoRegister              bool
	defaultOrgID              string
	defaultTeamID             string
	defaultRole               string
	httpClient                *http.Client
	now                       func() time.Time

	mu                  sync.RWMutex
	discoveredJWKSURL   string
	discoveredAt        time.Time
	keys                map[string]cachedJWK
	fetchedAt           time.Time
	staleUntil          time.Time
	lastAttempt         time.Time
	cooldownUntil       time.Time
	cacheTTL            time.Duration
	discoveryTTL        time.Duration
	staleCacheTTL       time.Duration
	minRefreshInterval  time.Duration
	unreachableCooldown time.Duration
	refreshAttempts     int
	retryBaseDelay      time.Duration
	clockSkew           time.Duration
	refreshGroup        singleflight.Group
}

// NewOIDCVerifier constructs an OIDCVerifier for a single issuer using network.NewHTTPClient
// when HTTPClient is not explicitly supplied.
func NewOIDCVerifier(cfg OIDCIssuerConfig) *OIDCVerifier {
	return newOIDCVerifier(cfg, defaultOIDCRefreshAttempts)
}

func newOIDCVerifier(cfg OIDCIssuerConfig, defaultAttempts int) *OIDCVerifier {
	issuer := strings.TrimSpace(cfg.Issuer)
	jwksURL := strings.TrimSpace(cfg.JWKSURL)
	discoveryURL := strings.TrimSpace(cfg.DiscoveryURL)
	derivedDiscovery := false

	// Automatically derive standard OIDC discovery URL when neither jwks_url nor discovery_url
	// is set and issuer is an HTTP(S) URL.
	if jwksURL == "" && discoveryURL == "" && issuer != "" {
		if u, err := url.Parse(issuer); err == nil && (u.Scheme == "https" || u.Scheme == "http") && u.Host != "" {
			discoveryURL = strings.TrimRight(issuer, "/") + "/.well-known/openid-configuration"
			derivedDiscovery = true
		}
	}

	client := cfg.HTTPClient
	if client == nil && (jwksURL != "" || discoveryURL != "") {
		client = network.NewHTTPClient(cfg.NetworkPolicy)
	}

	nowFn := cfg.Now
	if nowFn == nil {
		nowFn = time.Now
	}

	cacheTTL := cfg.CacheTTL
	if cacheTTL <= 0 {
		cacheTTL = defaultJWKSCacheTTL
	}
	discoveryTTL := cfg.DiscoveryTTL
	if discoveryTTL <= 0 {
		discoveryTTL = defaultDiscoveryCacheTTL
	}
	staleCacheTTL := cfg.StaleCacheTTL
	if staleCacheTTL <= 0 {
		staleCacheTTL = defaultStaleJWKSCacheTTL
	}
	cooldown := cfg.UnreachableCooldown
	if cooldown <= 0 {
		cooldown = defaultUnreachableCooldown
	}
	attempts := cfg.RefreshAttempts
	if attempts <= 0 {
		attempts = defaultAttempts
	}
	if attempts <= 0 {
		attempts = 1
	}
	retryBaseDelay := cfg.RetryBaseDelay
	if retryBaseDelay <= 0 {
		retryBaseDelay = defaultRetryBaseDelay
	}
	clockSkew := cfg.ClockSkew
	if clockSkew == 0 {
		clockSkew = DefaultJWTClockSkew
	} else if clockSkew < 0 {
		clockSkew = 0
	}

	var allowedAlgs map[string]struct{}
	if len(cfg.Algorithms) > 0 {
		allowedAlgs = make(map[string]struct{}, len(cfg.Algorithms))
		for _, a := range cfg.Algorithms {
			trimmed := strings.TrimSpace(a)
			if trimmed != "" {
				allowedAlgs[trimmed] = struct{}{}
			}
		}
	}

	var allowedDomains []string
	for _, d := range cfg.AllowedEmailDomains {
		norm := strings.ToLower(strings.TrimPrefix(strings.TrimSpace(d), "@"))
		if norm != "" {
			allowedDomains = append(allowedDomains, norm)
		}
	}

	return &OIDCVerifier{
		issuer:                    issuer,
		audience:                  strings.TrimSpace(cfg.Audience),
		staticJWKSURL:             jwksURL,
		discoveryURL:              discoveryURL,
		derivedDiscovery:          derivedDiscovery,
		allowedAlgs:               allowedAlgs,
		allowedEmailDomains:       allowedDomains,
		allowUnverifiedEmail:      cfg.AllowUnverifiedEmail,
		allowPrivilegedRoleClaims: cfg.AllowPrivilegedRoleClaims,
		claimMapping:              cfg.ClaimMapping,
		groupRoleMappings:         slices.Clone(cfg.GroupRoleMappings),
		roleMappingStrategy:       strings.TrimSpace(cfg.RoleMappingStrategy),
		groupTeamMappings:         cloneStringMap(cfg.GroupTeamMappings),
		autoRegister:              cfg.AutoRegister,
		defaultOrgID:              strings.TrimSpace(cfg.DefaultOrgID),
		defaultTeamID:             strings.TrimSpace(cfg.DefaultTeamID),
		defaultRole:               strings.TrimSpace(cfg.DefaultRole),
		httpClient:                client,
		now:                       nowFn,
		keys:                      make(map[string]cachedJWK),
		cacheTTL:                  cacheTTL,
		discoveryTTL:              discoveryTTL,
		staleCacheTTL:             staleCacheTTL,
		minRefreshInterval:        defaultMinRefreshInterval,
		unreachableCooldown:       cooldown,
		refreshAttempts:           attempts,
		retryBaseDelay:            retryBaseDelay,
		clockSkew:                 clockSkew,
	}
}

// SetNowFunc overrides the clock function used for expiration, cooldown, and cache TTL checks.
func (o *OIDCVerifier) SetNowFunc(fn func() time.Time) {
	if o == nil || fn == nil {
		return
	}
	o.mu.Lock()
	o.now = fn
	o.mu.Unlock()
}

func (o *OIDCVerifier) currentTime() time.Time {
	o.mu.RLock()
	fn := o.now
	o.mu.RUnlock()
	if fn == nil {
		return time.Now()
	}
	return fn()
}

// GroupRoleMappings returns the configured IdP group-to-GoRoute role mappings.
func (o *OIDCVerifier) GroupRoleMappings() []GroupRoleMappingRule {
	if o == nil {
		return nil
	}
	return slices.Clone(o.groupRoleMappings)
}

// RoleMappingStrategy returns the configured role mapping precedence strategy.
func (o *OIDCVerifier) RoleMappingStrategy() string {
	if o == nil {
		return ""
	}
	return o.roleMappingStrategy
}

// GroupTeamMappings returns the configured IdP group-to-team mappings.
func (o *OIDCVerifier) GroupTeamMappings() map[string]string {
	if o == nil {
		return nil
	}
	return cloneStringMap(o.groupTeamMappings)
}

func cloneStringMap(src map[string]string) map[string]string {
	if len(src) == 0 {
		return nil
	}
	dst := make(map[string]string, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

// Enabled reports whether this issuer verifier has a static JWKS URL or OIDC discovery URL configured.
func (o *OIDCVerifier) Enabled() bool {
	return o != nil && (o.staticJWKSURL != "" || o.discoveryURL != "")
}

// Issuer returns the configured issuer string.
func (o *OIDCVerifier) Issuer() string {
	if o == nil {
		return ""
	}
	return o.issuer
}

// AutoRegister reports whether JIT user provisioning is enabled for this issuer.
func (o *OIDCVerifier) AutoRegister() bool {
	return o != nil && o.autoRegister
}

// DefaultOrgID returns the fallback organization ID configured for this issuer.
func (o *OIDCVerifier) DefaultOrgID() string {
	if o == nil {
		return ""
	}
	return o.defaultOrgID
}

// DefaultTeamID returns the fallback team ID configured for this issuer.
func (o *OIDCVerifier) DefaultTeamID() string {
	if o == nil {
		return ""
	}
	return o.defaultTeamID
}

// DefaultRole returns the fallback role configured for this issuer.
func (o *OIDCVerifier) DefaultRole() string {
	if o == nil {
		return ""
	}
	return o.defaultRole
}

// AllowUnverifiedEmail reports whether unverified email claims are permitted for this issuer.
func (o *OIDCVerifier) AllowUnverifiedEmail() bool {
	return o != nil && o.allowUnverifiedEmail
}

// AllowPrivilegedRoleClaims reports whether IdP role claims may JIT-provision platform_admin.
func (o *OIDCVerifier) AllowPrivilegedRoleClaims() bool {
	return o != nil && o.allowPrivilegedRoleClaims
}

// JWTVerifier validates inbound asymmetric OIDC JWTs across one or more configured issuers.
type JWTVerifier struct {
	defaultVerifier *OIDCVerifier
	issuers         map[string]*OIDCVerifier
}

// NewJWTVerifier constructs a JWTVerifier supporting single-issuer as well as
// multi-issuer OIDC configs using the outbound network policy HTTP client for discovery and JWKS fetches.
func NewJWTVerifier(cfg JWTConfig) *JWTVerifier {
	issuers := make(map[string]*OIDCVerifier, len(cfg.Issuers)+1)

	var defaultVerifier *OIDCVerifier
	if strings.TrimSpace(cfg.OIDCJWKSURL) != "" || strings.TrimSpace(cfg.DiscoveryURL) != "" {
		// Preserve single-attempt + cooldown semantics on legacy single-issuer JWTConfig
		// unless RefreshAttempts is explicitly configured.
		legacyCfg := OIDCIssuerConfig{
			Issuer:              cfg.Issuer,
			Audience:            cfg.Audience,
			JWKSURL:             cfg.OIDCJWKSURL,
			DiscoveryURL:        cfg.DiscoveryURL,
			Algorithms:          cfg.Algorithms,
			AllowedEmailDomains: cfg.AllowedEmailDomains,
			ClaimMapping:        cfg.ClaimMapping,
			AutoRegister:        cfg.AutoRegister,
			DefaultOrgID:        cfg.DefaultOrgID,
			DefaultTeamID:       cfg.DefaultTeamID,
			DefaultRole:         cfg.DefaultRole,
			CacheTTL:            cfg.CacheTTL,
			DiscoveryTTL:        cfg.DiscoveryTTL,
			StaleCacheTTL:       cfg.StaleCacheTTL,
			UnreachableCooldown: cfg.UnreachableCooldown,
			RefreshAttempts:     cfg.RefreshAttempts,
			RetryBaseDelay:      cfg.RetryBaseDelay,
			ClockSkew:           cfg.ClockSkew,
			NetworkPolicy:       cfg.NetworkPolicy,
			HTTPClient:          cfg.HTTPClient,
			Now:                 cfg.Now,
		}
		defaultVerifier = newOIDCVerifier(legacyCfg, 1)
		if defaultVerifier.issuer != "" {
			issuers[defaultVerifier.issuer] = defaultVerifier
		}
	}

	for _, issCfg := range cfg.Issuers {
		merged := inheritMultiIssuerDefaults(issCfg, cfg.NetworkPolicy, cfg.HTTPClient, cfg.CacheTTL, cfg.DiscoveryTTL, cfg.StaleCacheTTL, cfg.UnreachableCooldown, cfg.RefreshAttempts, cfg.RetryBaseDelay, cfg.ClockSkew, cfg.Now)
		ov := NewOIDCVerifier(merged)
		if ov.issuer != "" {
			issuers[ov.issuer] = ov
		}
	}

	return &JWTVerifier{
		defaultVerifier: defaultVerifier,
		issuers:         issuers,
	}
}

// NewMultiIssuerJWTVerifier constructs a multi-issuer JWTVerifier from a MultiIssuerConfig.
func NewMultiIssuerJWTVerifier(cfg MultiIssuerConfig) *JWTVerifier {
	return NewJWTVerifier(JWTConfig{
		Issuers:             cfg.Issuers,
		NetworkPolicy:       cfg.NetworkPolicy,
		HTTPClient:          cfg.HTTPClient,
		CacheTTL:            cfg.CacheTTL,
		DiscoveryTTL:        cfg.DiscoveryTTL,
		StaleCacheTTL:       cfg.StaleCacheTTL,
		UnreachableCooldown: cfg.UnreachableCooldown,
		RefreshAttempts:     cfg.RefreshAttempts,
		RetryBaseDelay:      cfg.RetryBaseDelay,
		ClockSkew:           cfg.ClockSkew,
		Now:                 cfg.Now,
	})
}

func inheritMultiIssuerDefaults(
	iss OIDCIssuerConfig,
	netPolicy *network.Policy,
	httpClient *http.Client,
	cacheTTL, discoveryTTL, staleCacheTTL, cooldown time.Duration,
	refreshAttempts int,
	retryBaseDelay, clockSkew time.Duration,
	nowFn func() time.Time,
) OIDCIssuerConfig {
	if iss.NetworkPolicy == nil {
		iss.NetworkPolicy = netPolicy
	}
	if iss.HTTPClient == nil {
		iss.HTTPClient = httpClient
	}
	if iss.CacheTTL <= 0 {
		iss.CacheTTL = cacheTTL
	}
	if iss.DiscoveryTTL <= 0 {
		iss.DiscoveryTTL = discoveryTTL
	}
	if iss.StaleCacheTTL <= 0 {
		iss.StaleCacheTTL = staleCacheTTL
	}
	if iss.UnreachableCooldown <= 0 {
		iss.UnreachableCooldown = cooldown
	}
	if iss.RefreshAttempts <= 0 {
		iss.RefreshAttempts = refreshAttempts
	}
	if iss.RetryBaseDelay <= 0 {
		iss.RetryBaseDelay = retryBaseDelay
	}
	if iss.ClockSkew == 0 {
		iss.ClockSkew = clockSkew
	}
	if iss.Now == nil {
		iss.Now = nowFn
	}
	return iss
}

// SetNowFunc overrides the clock function on the verifier and all configured issuer verifiers.
func (v *JWTVerifier) SetNowFunc(fn func() time.Time) {
	if v == nil || fn == nil {
		return
	}
	if v.defaultVerifier != nil {
		v.defaultVerifier.SetNowFunc(fn)
	}
	for _, ov := range v.issuers {
		if ov != nil {
			ov.SetNowFunc(fn)
		}
	}
}

// VerifierForIssuer returns the configured OIDCVerifier for issuer, falling back to the default verifier.
func (v *JWTVerifier) VerifierForIssuer(issuer string) *OIDCVerifier {
	if v == nil {
		return nil
	}
	if iss := strings.TrimSpace(issuer); iss != "" {
		if ov, ok := v.issuers[iss]; ok && ov != nil {
			return ov
		}
	}
	return v.defaultVerifier
}

// SingleIdentityIssuer reports whether pre-existing subject-only accounts can
// be resolved without choosing between distinct configured identity providers.
func (v *JWTVerifier) SingleIdentityIssuer() bool {
	if v == nil {
		return false
	}
	count := 0
	for _, verifier := range v.issuers {
		if verifier.Enabled() {
			count++
		}
	}
	if v.defaultVerifier != nil && v.defaultVerifier.issuer == "" && v.defaultVerifier.Enabled() {
		count++
	}
	return count == 1
}

// Enabled reports whether at least one static JWKS URL or OIDC discovery issuer is configured.
func (v *JWTVerifier) Enabled() bool {
	if v == nil {
		return false
	}
	if v.defaultVerifier != nil && v.defaultVerifier.Enabled() {
		return true
	}
	for _, ov := range v.issuers {
		if ov != nil && ov.Enabled() {
			return true
		}
	}
	return false
}

type jwtHeader struct {
	Alg string `json:"alg"`
	Kid string `json:"kid,omitempty"`
	Typ string `json:"typ,omitempty"`
}

func isDisallowedTokenType(typ string) bool {
	normalized := strings.ToLower(strings.TrimSpace(typ))
	return normalized == "oauth-id-jag+jwt" || normalized == "application/oauth-id-jag+jwt"
}

func parseJWTEnvelope(rawToken string) (parts []string, hdr jwtHeader, payloadBytes []byte, sigBytes []byte, err error) {
	parts = strings.Split(strings.TrimSpace(rawToken), ".")
	if len(parts) != 3 {
		return nil, jwtHeader{}, nil, nil, errors.New("invalid jwt format")
	}

	hdrBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, jwtHeader{}, nil, nil, fmt.Errorf("decode jwt header: %w", err)
	}
	if err := json.Unmarshal(hdrBytes, &hdr); err != nil {
		return nil, jwtHeader{}, nil, nil, fmt.Errorf("parse jwt header: %w", err)
	}
	if hdr.Alg == "" || strings.EqualFold(hdr.Alg, "none") {
		return nil, jwtHeader{}, nil, nil, errors.New("jwt algorithm is missing or none")
	}
	if isDisallowedTokenType(hdr.Typ) {
		return nil, jwtHeader{}, nil, nil, errors.New("oauth-id-jag+jwt tokens cannot be used directly as bearer tokens")
	}

	payloadBytes, err = base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, jwtHeader{}, nil, nil, fmt.Errorf("decode jwt payload: %w", err)
	}
	sigBytes, err = base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, jwtHeader{}, nil, nil, fmt.Errorf("decode jwt signature: %w", err)
	}
	return parts, hdr, payloadBytes, sigBytes, nil
}

// Verify parses, routes by issuer, cryptographically verifies, and validates an inbound JWT.
func (v *JWTVerifier) Verify(ctx context.Context, rawToken string) (*JWTClaims, error) {
	if !v.Enabled() {
		return nil, errors.New("jwt verification is not configured")
	}

	parts, hdr, payloadBytes, sigBytes, err := parseJWTEnvelope(rawToken)
	if err != nil {
		return nil, err
	}

	var peek struct {
		Issuer string `json:"iss"`
	}
	_ = json.Unmarshal(payloadBytes, &peek)
	iss := strings.TrimSpace(peek.Issuer)

	var target *OIDCVerifier
	if iss != "" {
		if ov, ok := v.issuers[iss]; ok && ov != nil {
			target = ov
		}
	}
	if target == nil {
		target = v.defaultVerifier
	}
	if target == nil {
		if iss == "" {
			return nil, errors.New("jwt missing iss claim")
		}
		return nil, fmt.Errorf("unknown jwt issuer %q", iss)
	}

	return target.verifyParsed(ctx, parts, hdr, payloadBytes, sigBytes)
}

// Verify parses and cryptographically verifies an inbound JWT against this issuer's configuration.
func (o *OIDCVerifier) Verify(ctx context.Context, rawToken string) (*JWTClaims, error) {
	if !o.Enabled() {
		return nil, errors.New("jwt verification is not configured")
	}
	parts, hdr, payloadBytes, sigBytes, err := parseJWTEnvelope(rawToken)
	if err != nil {
		return nil, err
	}
	return o.verifyParsed(ctx, parts, hdr, payloadBytes, sigBytes)
}

func (o *OIDCVerifier) verifyParsed(ctx context.Context, parts []string, hdr jwtHeader, payloadBytes, sigBytes []byte) (*JWTClaims, error) {
	if strings.HasPrefix(strings.ToUpper(strings.TrimSpace(hdr.Alg)), "HS") {
		return nil, fmt.Errorf("symmetric jwt algorithm %q is disallowed for OIDC verification", hdr.Alg)
	}
	if len(o.allowedAlgs) > 0 {
		if _, allowed := o.allowedAlgs[hdr.Alg]; !allowed {
			return nil, fmt.Errorf("jwt signing algorithm %q is not allowed for issuer %q", hdr.Alg, o.issuer)
		}
	}

	signingInput := parts[0] + "." + parts[1]
	if err := o.verifySignature(ctx, hdr, signingInput, sigBytes); err != nil {
		return nil, err
	}

	var base struct {
		Subject   string        `json:"sub"`
		Issuer    string        `json:"iss,omitempty"`
		Audience  AudienceClaim `json:"aud,omitempty"`
		ExpiresAt int64         `json:"exp,omitempty"`
		NotBefore int64         `json:"nbf,omitempty"`
		IssuedAt  int64         `json:"iat,omitempty"`
	}
	if err := json.Unmarshal(payloadBytes, &base); err != nil {
		return nil, fmt.Errorf("parse jwt claims: %w", err)
	}

	var rawClaims map[string]any
	if err := json.Unmarshal(payloadBytes, &rawClaims); err != nil {
		return nil, fmt.Errorf("parse jwt raw claims: %w", err)
	}

	nowUnix := o.currentTime().UTC().Unix()
	skewSec := int64(o.clockSkew / time.Second)
	if base.ExpiresAt <= 0 {
		return nil, errors.New("jwt missing exp claim")
	}
	if nowUnix >= base.ExpiresAt+skewSec {
		return nil, errors.New("jwt token is expired")
	}
	if base.NotBefore > 0 && nowUnix+skewSec < base.NotBefore {
		return nil, errors.New("jwt token is not yet valid")
	}
	if o.issuer != "" && base.Issuer != o.issuer {
		return nil, fmt.Errorf("jwt issuer mismatch: got %q, want %q", base.Issuer, o.issuer)
	}
	if o.audience != "" && !base.Audience.Contains(o.audience) {
		return nil, fmt.Errorf("jwt audience %q not present", o.audience)
	}

	claims := &JWTClaims{
		Subject:   base.Subject,
		Issuer:    base.Issuer,
		Audience:  base.Audience,
		ExpiresAt: base.ExpiresAt,
		NotBefore: base.NotBefore,
		IssuedAt:  base.IssuedAt,
		RawClaims: rawClaims,
	}
	o.applyClaimMappings(claims, rawClaims)

	if strings.TrimSpace(claims.Subject) == "" {
		return nil, errors.New("jwt missing sub claim")
	}

	if err := o.enforceEmailDomain(claims.Email, claims.EmailVerified); err != nil {
		return nil, err
	}

	return claims, nil
}

func extractBoolClaim(raw map[string]any, path string) (bool, bool) {
	val, ok := resolveClaimPath(raw, path)
	if !ok || val == nil {
		return false, false
	}
	b, ok := val.(bool)
	return b, ok
}

func (o *OIDCVerifier) applyClaimMappings(claims *JWTClaims, raw map[string]any) {
	if path := strings.TrimSpace(o.claimMapping.UserID); path != "" {
		if v, ok := extractStringClaim(raw, path); ok {
			claims.Subject = v
		}
	}

	emailPath := strings.TrimSpace(o.claimMapping.Email)
	if emailPath == "" {
		emailPath = "email"
	}
	if v, ok := extractStringClaim(raw, emailPath); ok {
		claims.Email = v
	}
	if verified, ok := extractBoolClaim(raw, "email_verified"); ok {
		claims.EmailVerified = verified
	}

	orgPath := strings.TrimSpace(o.claimMapping.OrgID)
	if orgPath == "" {
		orgPath = "org_id"
	}
	if v, ok := extractStringClaim(raw, orgPath); ok {
		claims.OrgID = v
	} else if o.defaultOrgID != "" {
		claims.OrgID = o.defaultOrgID
	}

	teamPath := strings.TrimSpace(o.claimMapping.TeamIDs)
	if teamPath == "" {
		teamPath = "team_ids"
	}
	if v, ok := extractStringSliceClaim(raw, teamPath); ok {
		claims.TeamIDs = v
	} else if o.defaultTeamID != "" {
		claims.TeamIDs = []string{o.defaultTeamID}
	}

	rolePath := strings.TrimSpace(o.claimMapping.Role)
	if rolePath == "" {
		rolePath = "role"
	}
	if v, ok := extractStringClaim(raw, rolePath); ok {
		claims.Role = v
	} else if o.defaultRole != "" {
		claims.Role = o.defaultRole
	}

	groupsPath := strings.TrimSpace(o.claimMapping.Groups)
	if groupsPath == "" {
		groupsPath = "groups"
	}
	if v, ok := extractStringSliceClaim(raw, groupsPath); ok {
		claims.Groups = v
	}

	if endUserPath := strings.TrimSpace(o.claimMapping.EndUser); endUserPath != "" {
		if v, ok := extractStringClaim(raw, endUserPath); ok {
			claims.EndUserID = v
		}
	} else if v, ok := extractStringClaim(raw, "end_user_id"); ok {
		claims.EndUserID = v
	} else if v, ok := extractStringClaim(raw, "end_user"); ok {
		claims.EndUserID = v
	}
}

func (o *OIDCVerifier) enforceEmailDomain(email string, emailVerified bool) error {
	if len(o.allowedEmailDomains) == 0 {
		return nil
	}
	if !o.allowUnverifiedEmail && !emailVerified {
		return errors.New("jwt email_verified must be true when allowed_email_domains is enforced")
	}
	trimmed := strings.TrimSpace(email)
	atIdx := strings.LastIndex(trimmed, "@")
	if atIdx < 0 || atIdx == len(trimmed)-1 {
		return errors.New("jwt missing valid email claim required by allowed_email_domains")
	}
	domain := strings.ToLower(strings.TrimSpace(trimmed[atIdx+1:]))
	for _, allowed := range o.allowedEmailDomains {
		if domain == allowed {
			return nil
		}
	}
	return fmt.Errorf("jwt email domain %q is not in allowed_email_domains", domain)
}

func resolveClaimPath(raw map[string]any, path string) (any, bool) {
	if raw == nil || path == "" {
		return nil, false
	}
	if val, ok := raw[path]; ok {
		return val, true
	}
	segments := strings.Split(path, ".")
	var cur any = raw
	for _, seg := range segments {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		next, exists := m[seg]
		if !exists {
			return nil, false
		}
		cur = next
	}
	return cur, true
}

func extractStringClaim(raw map[string]any, path string) (string, bool) {
	val, ok := resolveClaimPath(raw, path)
	if !ok || val == nil {
		return "", false
	}
	switch v := val.(type) {
	case string:
		trimmed := strings.TrimSpace(v)
		return trimmed, trimmed != ""
	case []any:
		for _, item := range v {
			if s, ok := item.(string); ok {
				if trimmed := strings.TrimSpace(s); trimmed != "" {
					return trimmed, true
				}
			}
		}
		return "", false
	default:
		return "", false
	}
}

func extractStringSliceClaim(raw map[string]any, path string) ([]string, bool) {
	val, ok := resolveClaimPath(raw, path)
	if !ok {
		return nil, false
	}
	return extractStringSliceValue(val, true)
}

func extractStringSliceValue(raw any, splitComma bool) ([]string, bool) {
	if raw == nil {
		return nil, false
	}
	switch v := raw.(type) {
	case []string:
		out := trimNonEmptyStrings(v)
		return out, len(out) > 0
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok {
				if trimmed := strings.TrimSpace(s); trimmed != "" {
					out = append(out, trimmed)
				}
			}
		}
		return out, len(out) > 0
	case string:
		if !splitComma {
			return nil, false
		}
		out := trimNonEmptyStrings(strings.Split(v, ","))
		return out, len(out) > 0
	default:
		return nil, false
	}
}

func trimNonEmptyStrings(items []string) []string {
	out := make([]string, 0, len(items))
	for _, item := range items {
		if trimmed := strings.TrimSpace(item); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

func (o *OIDCVerifier) verifySignature(ctx context.Context, hdr jwtHeader, signingInput string, sigBytes []byte) error {
	switch hdr.Alg {
	case "RS256", "RS384", "RS512", "PS256", "PS384", "PS512":
		pubKey, err := o.resolveJWKSKey(ctx, hdr.Kid, hdr.Alg)
		if err != nil {
			return err
		}
		rsaKey, ok := pubKey.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("jwt key type mismatch for %s", hdr.Alg)
		}
		return verifyRSASignature(hdr.Alg, rsaKey, signingInput, sigBytes)

	case "ES256":
		pubKey, err := o.resolveJWKSKey(ctx, hdr.Kid, hdr.Alg)
		if err != nil {
			return err
		}
		ecKey, ok := pubKey.(*ecdsa.PublicKey)
		if !ok || ecKey.Curve != elliptic.P256() {
			return errors.New("jwt key type mismatch for ES256")
		}
		digest := sha256.Sum256([]byte(signingInput))
		return verifyECDSASignature("ES256", ecKey, digest[:], 32, sigBytes)

	case "ES384":
		pubKey, err := o.resolveJWKSKey(ctx, hdr.Kid, hdr.Alg)
		if err != nil {
			return err
		}
		ecKey, ok := pubKey.(*ecdsa.PublicKey)
		if !ok || ecKey.Curve != elliptic.P384() {
			return errors.New("jwt key type mismatch for ES384")
		}
		digest := sha512.Sum384([]byte(signingInput))
		return verifyECDSASignature("ES384", ecKey, digest[:], 48, sigBytes)

	case "ES512":
		pubKey, err := o.resolveJWKSKey(ctx, hdr.Kid, hdr.Alg)
		if err != nil {
			return err
		}
		ecKey, ok := pubKey.(*ecdsa.PublicKey)
		if !ok || ecKey.Curve != elliptic.P521() {
			return errors.New("jwt key type mismatch for ES512")
		}
		digest := sha512.Sum512([]byte(signingInput))
		return verifyECDSASignature("ES512", ecKey, digest[:], 66, sigBytes)

	case "EdDSA":
		pubKey, err := o.resolveJWKSKey(ctx, hdr.Kid, hdr.Alg)
		if err != nil {
			return err
		}
		edKey, ok := pubKey.(ed25519.PublicKey)
		if !ok {
			return errors.New("jwt key type mismatch for EdDSA")
		}
		if !ed25519.Verify(edKey, []byte(signingInput), sigBytes) {
			return errors.New("invalid EdDSA jwt signature")
		}
		return nil

	default:
		return fmt.Errorf("unsupported jwt signing algorithm %q", hdr.Alg)
	}
}

func verifyRSASignature(alg string, rsaKey *rsa.PublicKey, signingInput string, sigBytes []byte) error {
	switch alg {
	case "RS256":
		digest := sha256.Sum256([]byte(signingInput))
		if err := rsa.VerifyPKCS1v15(rsaKey, crypto.SHA256, digest[:], sigBytes); err != nil {
			return fmt.Errorf("invalid RS256 jwt signature: %w", err)
		}
		return nil
	case "RS384":
		digest := sha512.Sum384([]byte(signingInput))
		if err := rsa.VerifyPKCS1v15(rsaKey, crypto.SHA384, digest[:], sigBytes); err != nil {
			return fmt.Errorf("invalid RS384 jwt signature: %w", err)
		}
		return nil
	case "RS512":
		digest := sha512.Sum512([]byte(signingInput))
		if err := rsa.VerifyPKCS1v15(rsaKey, crypto.SHA512, digest[:], sigBytes); err != nil {
			return fmt.Errorf("invalid RS512 jwt signature: %w", err)
		}
		return nil
	case "PS256":
		digest := sha256.Sum256([]byte(signingInput))
		if err := rsa.VerifyPSS(rsaKey, crypto.SHA256, digest[:], sigBytes, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto}); err != nil {
			return fmt.Errorf("invalid PS256 jwt signature: %w", err)
		}
		return nil
	case "PS384":
		digest := sha512.Sum384([]byte(signingInput))
		if err := rsa.VerifyPSS(rsaKey, crypto.SHA384, digest[:], sigBytes, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto}); err != nil {
			return fmt.Errorf("invalid PS384 jwt signature: %w", err)
		}
		return nil
	case "PS512":
		digest := sha512.Sum512([]byte(signingInput))
		if err := rsa.VerifyPSS(rsaKey, crypto.SHA512, digest[:], sigBytes, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto}); err != nil {
			return fmt.Errorf("invalid PS512 jwt signature: %w", err)
		}
		return nil
	default:
		return fmt.Errorf("unsupported rsa algorithm %q", alg)
	}
}

func verifyECDSASignature(alg string, ecKey *ecdsa.PublicKey, digest []byte, coordSize int, sigBytes []byte) error {
	if len(sigBytes) != coordSize*2 {
		return fmt.Errorf("invalid %s jwt signature length", alg)
	}
	r := new(big.Int).SetBytes(sigBytes[:coordSize])
	s := new(big.Int).SetBytes(sigBytes[coordSize:])
	if !ecdsa.Verify(ecKey, digest, r, s) {
		return fmt.Errorf("invalid %s jwt signature", alg)
	}
	return nil
}

func (o *OIDCVerifier) resolveJWKSKey(ctx context.Context, kid, expectedAlg string) (any, error) {
	if o.staticJWKSURL == "" && o.discoveryURL == "" {
		return nil, errors.New("oidc jwks url is not configured")
	}

	now := o.currentTime().UTC()
	o.mu.RLock()
	cacheValid := !o.fetchedAt.IsZero() && now.Sub(o.fetchedAt) < o.cacheTTL
	entry, found := o.lookupKeyLocked(kid)
	o.mu.RUnlock()

	if cacheValid && found {
		if entry.alg != "" && entry.alg != expectedAlg {
			return nil, fmt.Errorf("jwks key %q algorithm mismatch: key alg %q != token alg %q", kid, entry.alg, expectedAlg)
		}
		return entry.key, nil
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	_, err, _ := o.refreshGroup.Do("jwks", func() (any, error) {
		now := o.currentTime().UTC()
		o.mu.RLock()
		stillCacheValid := !o.fetchedAt.IsZero() && now.Sub(o.fetchedAt) < o.cacheTTL
		_, stillFound := o.lookupKeyLocked(kid)
		inCooldown := !o.cooldownUntil.IsZero() && now.Before(o.cooldownUntil)
		rateLimited := !o.lastAttempt.IsZero() && now.Sub(o.lastAttempt) < o.minRefreshInterval
		staleValid := !o.staleUntil.IsZero() && now.Before(o.staleUntil)
		o.mu.RUnlock()

		if stillCacheValid && stillFound {
			return nil, nil
		}
		if inCooldown {
			if staleValid && stillFound {
				return nil, nil
			}
			return nil, fmt.Errorf("jwks endpoint in unreachable cooldown; key %q unavailable", kid)
		}
		if rateLimited {
			if staleValid && stillFound {
				return nil, nil
			}
			return nil, fmt.Errorf("jwks refresh rate-limited; key %q unavailable", kid)
		}

		fetchCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
		defer cancel()
		return nil, o.refreshWithRetry(fetchCtx, kid)
	})
	if err != nil {
		return nil, err
	}

	now = o.currentTime().UTC()
	o.mu.RLock()
	entry, found = o.lookupKeyLocked(kid)
	cacheValid = !o.fetchedAt.IsZero() && now.Sub(o.fetchedAt) < o.cacheTTL
	staleValid := !o.staleUntil.IsZero() && now.Before(o.staleUntil)
	o.mu.RUnlock()

	if found && (cacheValid || staleValid) {
		if entry.alg != "" && entry.alg != expectedAlg {
			return nil, fmt.Errorf("jwks key %q algorithm mismatch: key alg %q != token alg %q", kid, entry.alg, expectedAlg)
		}
		return entry.key, nil
	}

	return nil, fmt.Errorf("jwks key %q not found", kid)
}

func (o *OIDCVerifier) lookupKeyLocked(kid string) (cachedJWK, bool) {
	if kid != "" {
		k, ok := o.keys[kid]
		return k, ok && k.key != nil
	}
	if len(o.keys) == 1 {
		for _, k := range o.keys {
			return k, k.key != nil
		}
	}
	return cachedJWK{}, false
}

// OIDCDiscoveryMetadata holds standard OpenID Connect Discovery 1.0 and OAuth 2.0 AS Metadata (RFC 8414) fields.
type OIDCDiscoveryMetadata struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	UserInfoEndpoint                  string   `json:"userinfo_endpoint,omitempty"`
	JWKSURI                           string   `json:"jwks_uri"`
	RegistrationEndpoint              string   `json:"registration_endpoint,omitempty"`
	IntrospectionEndpoint             string   `json:"introspection_endpoint,omitempty"`
	RevocationEndpoint                string   `json:"revocation_endpoint,omitempty"`
	EndSessionEndpoint                string   `json:"end_session_endpoint,omitempty"`
	ScopesSupported                   []string `json:"scopes_supported,omitempty"`
	ResponseTypesSupported            []string `json:"response_types_supported,omitempty"`
	GrantTypesSupported               []string `json:"grant_types_supported,omitempty"`
	IDTokenSigningAlgValuesSupported  []string `json:"id_token_signing_alg_values_supported,omitempty"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported,omitempty"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported,omitempty"`
	ClaimsSupported                   []string `json:"claims_supported,omitempty"`
}

// BuildRFC8414DiscoveryURL constructs the RFC 8414 Section 3.1 Authorization Server Metadata URL
// for an issuer (inserting `/.well-known/oauth-authorization-server` before any issuer path).
func BuildRFC8414DiscoveryURL(issuer string) string {
	u, err := url.Parse(strings.TrimSpace(issuer))
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return ""
	}
	cleanPath := strings.TrimSuffix(u.Path, "/")
	u.Path = "/.well-known/oauth-authorization-server" + cleanPath
	u.RawQuery = ""
	u.Fragment = ""
	return u.String()
}

// FetchOIDCDiscoveryMetadata fetches and validates OIDC Discovery 1.0 metadata, optionally falling
// back to RFC 8414 (`/.well-known/oauth-authorization-server`) when the derived OIDC path returns 404.
func FetchOIDCDiscoveryMetadata(
	ctx context.Context,
	httpClient *http.Client,
	discoveryURL, configuredIssuer string,
	allowRFC8414Fallback bool,
) (*OIDCDiscoveryMetadata, error) {
	if httpClient == nil {
		return nil, errors.New("oidc discovery http client is not initialized")
	}

	fetchOnce := func(targetURL string) (*OIDCDiscoveryMetadata, int, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
		if err != nil {
			return nil, 0, fmt.Errorf("build oidc discovery request: %w", err)
		}
		req.Header.Set("Accept", "application/json")

		resp, err := httpClient.Do(req)
		if err != nil {
			return nil, 0, fmt.Errorf("fetch oidc discovery: %w", err)
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode != http.StatusOK {
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
			return nil, resp.StatusCode, fmt.Errorf("fetch oidc discovery: unexpected status %d", resp.StatusCode)
		}

		body, err := io.ReadAll(io.LimitReader(resp.Body, maxJWTDocumentBytes))
		if err != nil {
			return nil, resp.StatusCode, fmt.Errorf("read oidc discovery body: %w", err)
		}

		var doc OIDCDiscoveryMetadata
		if err := json.Unmarshal(body, &doc); err != nil {
			return nil, resp.StatusCode, fmt.Errorf("parse oidc discovery json: %w", err)
		}
		return &doc, resp.StatusCode, nil
	}

	doc, status, err := fetchOnce(discoveryURL)
	if err != nil && status == http.StatusNotFound && allowRFC8414Fallback && configuredIssuer != "" {
		candidates := []string{BuildRFC8414DiscoveryURL(configuredIssuer)}
		if suffixURL := strings.TrimRight(strings.TrimSpace(configuredIssuer), "/") + "/.well-known/oauth-authorization-server"; suffixURL != candidates[0] {
			candidates = append(candidates, suffixURL)
		}
		for _, rfcURL := range candidates {
			if rfcURL == "" || rfcURL == discoveryURL {
				continue
			}
			fallbackDoc, fallbackStatus, fallbackErr := fetchOnce(rfcURL)
			if fallbackErr == nil {
				doc = fallbackDoc
				err = nil
				break
			}
			if fallbackStatus != http.StatusNotFound {
				err = fallbackErr
				break
			}
		}
	}
	if err != nil {
		return nil, err
	}

	doc.Issuer = strings.TrimSpace(doc.Issuer)
	doc.AuthorizationEndpoint = strings.TrimSpace(doc.AuthorizationEndpoint)
	doc.TokenEndpoint = strings.TrimSpace(doc.TokenEndpoint)
	doc.UserInfoEndpoint = strings.TrimSpace(doc.UserInfoEndpoint)
	doc.JWKSURI = strings.TrimSpace(doc.JWKSURI)
	doc.RegistrationEndpoint = strings.TrimSpace(doc.RegistrationEndpoint)
	doc.IntrospectionEndpoint = strings.TrimSpace(doc.IntrospectionEndpoint)
	doc.RevocationEndpoint = strings.TrimSpace(doc.RevocationEndpoint)
	doc.EndSessionEndpoint = strings.TrimSpace(doc.EndSessionEndpoint)

	// OIDC Discovery 1.0 §4.3: issuer MUST be present and strictly equal to configuredIssuer.
	if configuredIssuer != "" && doc.Issuer != configuredIssuer {
		return nil, fmt.Errorf("oidc discovery issuer mismatch: got %q, want %q", doc.Issuer, configuredIssuer)
	}
	return doc, nil
}

type jwksDocument struct {
	Keys []jwkEntry `json:"keys"`
}

type jwkEntry struct {
	Kty    string   `json:"kty"`
	Kid    string   `json:"kid"`
	Use    string   `json:"use,omitempty"`
	KeyOps []string `json:"key_ops,omitempty"`
	Alg    string   `json:"alg,omitempty"`
	N      string   `json:"n,omitempty"`
	E      string   `json:"e,omitempty"`
	Crv    string   `json:"crv,omitempty"`
	X      string   `json:"x,omitempty"`
	Y      string   `json:"y,omitempty"`
}

func (o *OIDCVerifier) refreshWithRetry(ctx context.Context, kid string) error {
	if o.httpClient == nil {
		return errors.New("jwks http client is not initialized")
	}

	o.mu.Lock()
	o.lastAttempt = o.now().UTC()
	o.mu.Unlock()

	var lastErr error
	for attempt := 0; attempt < o.refreshAttempts; attempt++ {
		if attempt > 0 {
			backoff := o.retryBaseDelay << uint(attempt-1)
			timer := time.NewTimer(backoff)
			select {
			case <-ctx.Done():
				timer.Stop()
				lastErr = ctx.Err()
				break
			case <-timer.C:
			}
			if ctx.Err() != nil {
				break
			}
		}

		jwksURL, err := o.resolveJWKSURL(ctx, attempt > 0)
		if err != nil {
			lastErr = err
			continue
		}

		if err := o.refreshJWKS(ctx, jwksURL); err != nil {
			lastErr = err
			continue
		}
		return nil
	}

	now := o.currentTime().UTC()
	o.mu.Lock()
	o.cooldownUntil = now.Add(o.unreachableCooldown)
	_, staleFound := o.lookupKeyLocked(kid)
	staleValid := !o.staleUntil.IsZero() && now.Before(o.staleUntil)
	o.mu.Unlock()

	if staleValid && staleFound {
		return nil
	}
	if lastErr == nil {
		lastErr = errors.New("jwks refresh failed")
	}
	return lastErr
}

func (o *OIDCVerifier) resolveJWKSURL(ctx context.Context, forceRediscover bool) (string, error) {
	if o.staticJWKSURL != "" {
		return o.staticJWKSURL, nil
	}

	now := o.currentTime().UTC()
	if !forceRediscover {
		o.mu.RLock()
		cached := o.discoveredJWKSURL
		fresh := !o.discoveredAt.IsZero() && now.Sub(o.discoveredAt) < o.discoveryTTL
		o.mu.RUnlock()
		if cached != "" && fresh {
			return cached, nil
		}
	}

	if o.discoveryURL == "" {
		return "", errors.New("oidc discovery url is not configured")
	}

	doc, err := FetchOIDCDiscoveryMetadata(ctx, o.httpClient, o.discoveryURL, o.issuer, o.derivedDiscovery)
	if err != nil {
		return "", err
	}
	if doc.JWKSURI == "" {
		return "", errors.New("oidc discovery document missing jwks_uri")
	}

	o.mu.Lock()
	o.discoveredJWKSURL = doc.JWKSURI
	o.discoveredAt = o.now().UTC()
	o.mu.Unlock()
	return doc.JWKSURI, nil
}

func (o *OIDCVerifier) refreshJWKS(ctx context.Context, jwksURL string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksURL, nil)
	if err != nil {
		return fmt.Errorf("build jwks request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := o.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("fetch jwks: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("fetch jwks: unexpected status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxJWTDocumentBytes))
	if err != nil {
		return fmt.Errorf("read jwks body: %w", err)
	}

	var doc jwksDocument
	if err := json.Unmarshal(body, &doc); err != nil {
		return fmt.Errorf("parse jwks json: %w", err)
	}

	parsed := make(map[string]cachedJWK, len(doc.Keys))
	for _, entry := range doc.Keys {
		if entry.Use != "" && entry.Use != "sig" {
			continue
		}
		if len(entry.KeyOps) > 0 && !slices.Contains(entry.KeyOps, "verify") {
			continue
		}
		pub, err := parseJWKPublicKey(entry)
		if err != nil {
			continue
		}
		kid := entry.Kid
		if kid == "" {
			kid = fmt.Sprintf("_default_%d", len(parsed))
		}
		parsed[kid] = cachedJWK{
			key: pub,
			alg: strings.TrimSpace(entry.Alg),
		}
	}
	if len(parsed) == 0 {
		return errors.New("jwks contained no usable signing keys")
	}

	now := o.currentTime().UTC()
	o.mu.Lock()
	o.keys = parsed
	o.fetchedAt = now
	o.staleUntil = now.Add(o.staleCacheTTL)
	o.cooldownUntil = time.Time{}
	o.mu.Unlock()
	return nil
}

func parseJWKPublicKey(entry jwkEntry) (any, error) {
	switch entry.Kty {
	case "RSA":
		nBytes, err := base64.RawURLEncoding.DecodeString(entry.N)
		if err != nil || len(nBytes) == 0 {
			return nil, errors.New("invalid RSA modulus")
		}
		modulus := new(big.Int).SetBytes(nBytes)
		// RFC 7518 §3.3 requires RSA keys of at least 2048 bits for RS*/PS* signatures.
		if modulus.BitLen() < 2048 {
			return nil, fmt.Errorf("RSA key modulus too small: %d bits (minimum 2048)", modulus.BitLen())
		}
		eBytes, err := base64.RawURLEncoding.DecodeString(entry.E)
		if err != nil || len(eBytes) == 0 {
			return nil, errors.New("invalid RSA exponent")
		}
		eBig := new(big.Int).SetBytes(eBytes)
		if !eBig.IsInt64() {
			return nil, errors.New("invalid RSA exponent value")
		}
		eInt := eBig.Int64()
		if eInt < 3 || eInt%2 == 0 {
			return nil, errors.New("invalid RSA exponent value")
		}
		return &rsa.PublicKey{
			N: modulus,
			E: int(eInt),
		}, nil

	case "EC":
		var curve elliptic.Curve
		switch entry.Crv {
		case "P-256":
			curve = elliptic.P256()
		case "P-384":
			curve = elliptic.P384()
		case "P-521":
			curve = elliptic.P521()
		default:
			return nil, fmt.Errorf("unsupported EC curve %q", entry.Crv)
		}
		xBytes, err := base64.RawURLEncoding.DecodeString(entry.X)
		if err != nil || len(xBytes) == 0 {
			return nil, errors.New("invalid EC x coordinate")
		}
		yBytes, err := base64.RawURLEncoding.DecodeString(entry.Y)
		if err != nil || len(yBytes) == 0 {
			return nil, errors.New("invalid EC y coordinate")
		}
		pub := &ecdsa.PublicKey{
			Curve: curve,
			X:     new(big.Int).SetBytes(xBytes),
			Y:     new(big.Int).SetBytes(yBytes),
		}
		if _, err := pub.ECDH(); err != nil {
			return nil, errors.New("EC public key is not on curve")
		}
		return pub, nil

	case "OKP":
		if entry.Crv != "Ed25519" {
			return nil, fmt.Errorf("unsupported OKP curve %q", entry.Crv)
		}
		xBytes, err := base64.RawURLEncoding.DecodeString(entry.X)
		if err != nil || len(xBytes) != ed25519.PublicKeySize {
			return nil, errors.New("invalid Ed25519 public key")
		}
		return ed25519.PublicKey(xBytes), nil

	default:
		return nil, fmt.Errorf("unsupported jwk key type %q", entry.Kty)
	}
}
