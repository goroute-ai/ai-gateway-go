package mcp

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"hash"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/goroute-ai/ai-gateway-go/internal/auth"
	"github.com/goroute-ai/ai-gateway-go/internal/auth/upstream"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/security/network"
	"golang.org/x/sync/singleflight"
)

// AuthResolver resolves the appropriate upstream authentication strategy for an MCP server call.
type AuthResolver struct {
	vault      *auth.Vault
	netPolicy  *network.Policy
	tokenCache *upstream.DistributedTokenCache
}

// NewAuthResolver constructs an AuthResolver.
func NewAuthResolver(vault *auth.Vault, netPolicy *network.Policy) *AuthResolver {
	return &AuthResolver{
		vault:     vault,
		netPolicy: netPolicy,
	}
}

// SetTokenCache attaches an optional DistributedTokenCache shared across MCP upstream OAuth2 strategies.
func (r *AuthResolver) SetTokenCache(cache *upstream.DistributedTokenCache) {
	r.tokenCache = cache
}

// ResolveStrategy determines the upstream authentication strategy for the given server.
func (r *AuthResolver) ResolveStrategy(
	ctx context.Context,
	server *domain.MCPServer,
	userCred *domain.MCPUserCredential,
	clientHeaders http.Header,
) (upstream.Strategy, map[string]string) {
	extraHeaders := make(map[string]string)

	// 1. Process server static headers
	for k, v := range server.StaticHeaders {
		extraHeaders[k] = v
	}

	// 2. Process x-mcp-{slug}-{header} overrides from client
	slugPrefix := "x-mcp-" + strings.ToLower(server.Slug) + "-"
	for k, v := range clientHeaders {
		lower := strings.ToLower(k)
		// Mask / filter out debug headers
		if strings.HasPrefix(lower, "x-mcp-debug-") {
			continue
		}
		if strings.HasPrefix(lower, slugPrefix) && len(v) > 0 {
			targetHeader := k[len(slugPrefix):]
			extraHeaders[targetHeader] = v[0]
		}
	}

	// 3. Resolve BYOK credential if provided
	if userCred != nil && userCred.EncryptedToken != "" && r.vault != nil {
		// Decrypt user credential
		decrypted, err := r.vault.DecryptString(userCred.EncryptedToken, userCred.EncryptedDEK)
		if err == nil && decrypted != "" {
			return upstream.NewStaticStrategy("Authorization", decrypted, extraHeaders), extraHeaders
		}
	}

	// 4. Resolve server-level authentication
	var secret string
	if server.EncryptedAuthSecret != "" && r.vault != nil {
		decrypted, err := r.vault.DecryptString(server.EncryptedAuthSecret, server.EncryptedAuthDEK)
		if err == nil {
			secret = decrypted
		}
	}

	switch server.AuthType {
	case "static":
		return upstream.NewStaticStrategy("Authorization", secret, extraHeaders), extraHeaders
	case "oauth2":
		return upstream.NewOAuth2StrategyWithCache(server.OAuth2Endpoint, server.OAuth2ClientID, secret, server.OAuth2Scopes, r.netPolicy, r.tokenCache), extraHeaders
	case "delegation":
		return upstream.NewDelegationStrategy("Authorization", true), extraHeaders
	case domain.MCPAuthVaultJWT:
		signer, err := r.resolveVaultJWTSigner(server, secret)
		if err == nil {
			return signer, extraHeaders
		}
		if strings.HasPrefix(strings.TrimSpace(secret), "{") {
			return &failingStrategy{authType: domain.MCPAuthVaultJWT, err: err}, extraHeaders
		}
	case "aws_sigv4":
		var sigCfg upstream.SigV4Config
		if err := json.Unmarshal([]byte(secret), &sigCfg); err != nil {
			parts := strings.Split(secret, ":")
			if len(parts) >= 2 {
				sigCfg.AccessKeyID = parts[0]
				sigCfg.SecretAccessKey = parts[1]
			}
		}
		if sigCfg.Region == "" {
			sigCfg.Region = server.StaticHeaders["x-amz-region"]
			if sigCfg.Region == "" {
				sigCfg.Region = "us-east-1"
			}
		}
		if sigCfg.Service == "" {
			sigCfg.Service = server.StaticHeaders["x-amz-service"]
			if sigCfg.Service == "" {
				sigCfg.Service = "bedrock"
			}
		}
		if s, err := upstream.NewSigV4Strategy(sigCfg); err == nil {
			return s, extraHeaders
		}
	case "token_exchange", "rfc8693":
		if s, err := upstream.NewTokenExchangeStrategy(upstream.TokenExchangeConfig{
			TokenEndpoint: server.OAuth2Endpoint,
			ClientID:      server.OAuth2ClientID,
			ClientSecret:  secret,
			Resource:      server.EndpointURL,
			Scope:         strings.Join(server.OAuth2Scopes, " "),
			NetPolicy:     r.netPolicy,
			TokenCache:    r.tokenCache,
		}); err == nil {
			return s, extraHeaders
		}
	}

	// Default: static strategy with whatever extra headers exist
	return upstream.NewStaticStrategy("Authorization", secret, extraHeaders), extraHeaders
}

func (r *AuthResolver) resolveVaultJWTSigner(server *domain.MCPServer, secret string) (*MCPJWTSigner, error) {
	trimmed := strings.TrimSpace(secret)
	var cfg MCPJWTSignerConfig
	if strings.HasPrefix(trimmed, "{") {
		if err := json.Unmarshal([]byte(trimmed), &cfg); err != nil {
			return nil, fmt.Errorf("parse vault_jwt config: %w", err)
		}
	} else {
		cfg.SigningKey = secret
	}
	if cfg.KeyID == "" {
		cfg.KeyID = "gw-mcp-key"
	}
	if cfg.Issuer == "" {
		cfg.Issuer = "goroute-ai-gateway"
	}
	if len(cfg.TrustedAudiences) == 0 && server != nil && server.EndpointURL != "" {
		cfg.TrustedAudiences = []string{server.EndpointURL}
	}
	cfg.NetPolicy = r.netPolicy
	return NewMCPJWTSigner(cfg)
}

type failingStrategy struct {
	authType string
	err      error
}

func (s *failingStrategy) Type() string { return s.authType }
func (s *failingStrategy) Apply(_ context.Context, _ *http.Request, _ *upstream.UpstreamAuthContext) error {
	return s.err
}

const (
	defaultVaultJWTTTL = 5 * time.Minute
	maxJWKSBodyBytes   = 1 << 20
)

// RequiredClaimsSpec supports unmarshaling required_claims from either []string (claim presence)
// or map[string]any (exact/slice claim value expectations).
type RequiredClaimsSpec map[string]any

// UnmarshalJSON decodes either []string or map[string]any into RequiredClaimsSpec.
func (r *RequiredClaimsSpec) UnmarshalJSON(data []byte) error {
	var list []string
	if err := json.Unmarshal(data, &list); err == nil {
		out := make(RequiredClaimsSpec, len(list))
		for _, k := range list {
			if trimmed := strings.TrimSpace(k); trimmed != "" {
				out[trimmed] = true
			}
		}
		*r = out
		return nil
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		return err
	}
	*r = RequiredClaimsSpec(m)
	return nil
}

// MCPJWTSignerConfig configures incoming bearer verification, claim validation/transforms,
// end-user sub/email mapping, and short-lived Vault JWT signing per upstream MCP hop.
type MCPJWTSignerConfig struct {
	KeyID               string        `json:"key_id,omitempty"`
	SigningKey          string        `json:"signing_key,omitempty"`
	SigningAlgorithm    string        `json:"signing_algorithm,omitempty"` // "HS256" (default), "RS256", "ES256"
	Issuer              string        `json:"issuer,omitempty"`
	TrustedAudiences    []string      `json:"trusted_audiences,omitempty"`
	TokenTTL            time.Duration `json:"-"`
	TTLSeconds          int           `json:"ttl_seconds,omitempty"`
	HeaderName          string        `json:"header_name,omitempty"`
	IncludeBearerPrefix *bool         `json:"bearer_prefix,omitempty"`

	// Optional incoming bearer token verification
	VerifyIncoming        bool   `json:"verify_incoming,omitempty"`
	RequireIncomingToken  bool   `json:"require_incoming_token,omitempty"`
	AllowMissingExp       bool   `json:"allow_missing_exp,omitempty"`
	VerificationKey       string `json:"verification_key,omitempty"`
	VerificationJWKSURL   string `json:"verification_jwks_url,omitempty"`
	VerificationIssuer    string `json:"verification_issuer,omitempty"`
	VerificationAudience  string `json:"verification_audience,omitempty"`
	ForwardIncomingClaims *bool  `json:"forward_incoming_claims,omitempty"`

	// Claim validation & transforms
	RequiredClaims    RequiredClaimsSpec `json:"required_claims,omitempty"`
	OptionalClaims    []string           `json:"optional_claims,omitempty"`
	AddClaims         map[string]any     `json:"add_claims,omitempty"`
	SetClaims         map[string]any     `json:"set_claims,omitempty"`
	RemoveClaims      []string           `json:"remove_claims,omitempty"`
	ForwardEndUserSub *bool              `json:"forward_sub,omitempty"`
	SubClaimSource    string             `json:"sub_source,omitempty"` // "", "auto", "incoming_sub", "end_user_id", "user_id", "virtual_key"
	ForwardEmail      *bool              `json:"forward_email,omitempty"`
	DefaultEmail      string             `json:"default_email,omitempty"`

	NetPolicy  *network.Policy  `json:"-"`
	HTTPClient *http.Client     `json:"-"`
	Now        func() time.Time `json:"-"`
}

type signerCachedJWK struct {
	key any
	alg string
}

// MCPJWTSigner implements upstream.Strategy for MCPAuthVaultJWT ("vault_jwt"), performing
// incoming bearer token verification, claim validation/transformation, and short-lived
// Vault JWT signing per upstream MCP hop.
type MCPJWTSigner struct {
	cfg           MCPJWTSignerConfig
	signingAlg    string
	hmacKey       []byte
	rsaPriv       *rsa.PrivateKey
	ecPriv        *ecdsa.PrivateKey
	verifyHMACKey []byte
	verifyPubKey  any
	httpClient    *http.Client
	now           func() time.Time

	mu           sync.RWMutex
	jwksKeys     map[string]signerCachedJWK
	fetchedAt    time.Time
	lastAttempt  time.Time
	cacheTTL     time.Duration
	refreshGroup singleflight.Group
}

// NewMCPJWTSigner validates cfg and constructs an MCPJWTSigner.
func NewMCPJWTSigner(cfg MCPJWTSignerConfig) (*MCPJWTSigner, error) {
	if strings.TrimSpace(cfg.SigningKey) == "" {
		return nil, upstream.ErrMissingSigningKey
	}
	if cfg.TokenTTL <= 0 && cfg.TTLSeconds > 0 {
		cfg.TokenTTL = time.Duration(cfg.TTLSeconds) * time.Second
	}
	if cfg.TokenTTL <= 0 {
		cfg.TokenTTL = defaultVaultJWTTTL
	}
	if strings.TrimSpace(cfg.Issuer) == "" {
		cfg.Issuer = "goroute-ai-gateway"
	}
	if strings.TrimSpace(cfg.HeaderName) == "" {
		cfg.HeaderName = "Authorization"
	}

	alg := strings.ToUpper(strings.TrimSpace(cfg.SigningAlgorithm))
	if alg == "" {
		alg = "HS256"
	}

	s := &MCPJWTSigner{
		cfg:        cfg,
		signingAlg: alg,
		now:        cfg.Now,
		jwksKeys:   make(map[string]signerCachedJWK),
		cacheTTL:   5 * time.Minute,
	}
	if s.now == nil {
		s.now = time.Now
	}

	switch alg {
	case "HS256":
		s.hmacKey = []byte(cfg.SigningKey)
	case "RS256":
		priv, err := parseRSAPrivateKeyPEM(cfg.SigningKey)
		if err != nil {
			return nil, fmt.Errorf("mcp_jwt_signer: parse RS256 signing key: %w", err)
		}
		s.rsaPriv = priv
	case "ES256":
		priv, err := parseECPrivateKeyPEM(cfg.SigningKey)
		if err != nil {
			return nil, fmt.Errorf("mcp_jwt_signer: parse ES256 signing key: %w", err)
		}
		s.ecPriv = priv
	default:
		return nil, fmt.Errorf("mcp_jwt_signer: unsupported signing algorithm %q", alg)
	}

	if vKey := strings.TrimSpace(cfg.VerificationKey); vKey != "" {
		if strings.Contains(vKey, "-----BEGIN ") {
			pub, err := parsePublicKeyPEM(vKey)
			if err != nil {
				return nil, fmt.Errorf("mcp_jwt_signer: parse verification public key: %w", err)
			}
			s.verifyPubKey = pub
		} else {
			s.verifyHMACKey = []byte(vKey)
		}
	}

	if cfg.HTTPClient != nil {
		s.httpClient = cfg.HTTPClient
	} else if strings.TrimSpace(cfg.VerificationJWKSURL) != "" {
		s.httpClient = network.NewHTTPClient(cfg.NetPolicy)
	}

	return s, nil
}

// Type returns the upstream authentication strategy identifier ("vault_jwt").
func (s *MCPJWTSigner) Type() string {
	return domain.MCPAuthVaultJWT
}

// Apply verifies optional incoming bearer tokens, validates required/optional claims,
// applies configured claim transforms, and signs a short-lived Vault JWT on req.
func (s *MCPJWTSigner) Apply(ctx context.Context, req *http.Request, authCtx *upstream.UpstreamAuthContext) error {
	if req == nil {
		return errors.New("mcp_jwt_signer: nil request")
	}

	audience := resolveTargetAudience(req, authCtx)
	incomingToken := extractIncomingBearerToken(req, authCtx)
	token, _, err := s.SignAndVerifyClaims(ctx, incomingToken, authCtx, audience)
	if err != nil {
		return err
	}

	headerName := s.cfg.HeaderName
	if headerName == "" {
		headerName = "Authorization"
	}
	if s.cfg.IncludeBearerPrefix != nil && !*s.cfg.IncludeBearerPrefix {
		req.Header.Set(headerName, token)
	} else {
		req.Header.Set(headerName, "Bearer "+token)
	}
	return nil
}

// SignAndVerifyClaims verifies incomingToken (if configured/present), validates required & optional
// claims, applies transforms, and signs a short-lived JWT returning the token string and claims.
func (s *MCPJWTSigner) SignAndVerifyClaims(
	ctx context.Context,
	incomingToken string,
	authCtx *upstream.UpstreamAuthContext,
	audience string,
) (string, map[string]any, error) {
	if err := s.validateAudience(audience); err != nil {
		return "", nil, err
	}

	incomingToken = stripBearerPrefix(incomingToken)
	shouldVerify := s.cfg.VerifyIncoming || s.cfg.RequireIncomingToken || len(s.verifyHMACKey) > 0 || s.verifyPubKey != nil || strings.TrimSpace(s.cfg.VerificationJWKSURL) != ""

	var verifiedClaims map[string]any
	if incomingToken != "" && shouldVerify {
		var err error
		verifiedClaims, err = s.verifyIncomingToken(ctx, incomingToken)
		if err != nil {
			return "", nil, err
		}
	} else if incomingToken == "" && s.cfg.RequireIncomingToken {
		return "", nil, errors.New("mcp_jwt_signer: incoming bearer token is required")
	}

	// Build baseline context claims for validation when no incoming token was supplied.
	availableClaims := make(map[string]any)
	for k, v := range verifiedClaims {
		availableClaims[k] = v
	}
	if authCtx != nil {
		if authCtx.CallingOrgID != "" && availableClaims["org_id"] == nil {
			availableClaims["org_id"] = authCtx.CallingOrgID
		}
		if authCtx.CallingTeamID != "" && availableClaims["team_id"] == nil {
			availableClaims["team_id"] = authCtx.CallingTeamID
		}
		if authCtx.CallingUserID != "" && availableClaims["user_id"] == nil {
			availableClaims["user_id"] = authCtx.CallingUserID
		}
		if authCtx.CallingVirtualKey != "" && availableClaims["virtual_key_id"] == nil {
			availableClaims["virtual_key_id"] = authCtx.CallingVirtualKey
		}
		if authCtx.CallingAgentID != "" && availableClaims["agent_id"] == nil {
			availableClaims["agent_id"] = authCtx.CallingAgentID
		}
	}

	// Validate required_claims.
	if err := validateSignerRequiredClaims(s.cfg.RequiredClaims, availableClaims); err != nil {
		return "", nil, err
	}

	// Assemble outbound claims.
	outbound := make(map[string]any)
	forwardAllIncoming := true
	if s.cfg.ForwardIncomingClaims != nil {
		forwardAllIncoming = *s.cfg.ForwardIncomingClaims
	}

	if len(verifiedClaims) > 0 {
		if len(s.cfg.OptionalClaims) > 0 || len(s.cfg.RequiredClaims) > 0 {
			for k := range s.cfg.RequiredClaims {
				if isReservedJWTEnvelopeClaim(k) {
					continue
				}
				if val, ok := verifiedClaims[k]; ok {
					outbound[k] = val
				}
			}
			for _, optKey := range s.cfg.OptionalClaims {
				k := strings.TrimSpace(optKey)
				if k == "" || isReservedJWTEnvelopeClaim(k) {
					continue
				}
				if val, ok := verifiedClaims[k]; ok {
					outbound[k] = val
				}
			}
			if forwardAllIncoming && len(s.cfg.OptionalClaims) == 0 {
				for k, v := range verifiedClaims {
					if !isReservedJWTEnvelopeClaim(k) && k != "sub" && k != "email" {
						outbound[k] = v
					}
				}
			}
		} else if forwardAllIncoming {
			for k, v := range verifiedClaims {
				if !isReservedJWTEnvelopeClaim(k) && k != "sub" && k != "email" {
					outbound[k] = v
				}
			}
		}
	}

	if authCtx != nil {
		if authCtx.CallingOrgID != "" {
			outbound["org_id"] = authCtx.CallingOrgID
		}
		if authCtx.CallingTeamID != "" {
			outbound["team_id"] = authCtx.CallingTeamID
		}
		if authCtx.CallingUserID != "" {
			outbound["user_id"] = authCtx.CallingUserID
		}
		if authCtx.CallingVirtualKey != "" {
			outbound["virtual_key_id"] = authCtx.CallingVirtualKey
		}
		if authCtx.CallingAgentID != "" {
			outbound["agent_id"] = authCtx.CallingAgentID
		}
	}

	// End-user sub & email mapping.
	forwardSub := true
	if s.cfg.ForwardEndUserSub != nil {
		forwardSub = *s.cfg.ForwardEndUserSub
	}
	if forwardSub {
		if sub := resolveEndUserSub(s.cfg.SubClaimSource, verifiedClaims, authCtx); sub != "" {
			outbound["sub"] = sub
		} else {
			outbound["sub"] = "goroute-ai-gateway"
		}
	} else {
		outbound["sub"] = "goroute-ai-gateway"
	}

	forwardEmail := true
	if s.cfg.ForwardEmail != nil {
		forwardEmail = *s.cfg.ForwardEmail
	}
	if forwardEmail {
		if email := resolveEndUserEmail(s.cfg.DefaultEmail, verifiedClaims, authCtx); email != "" {
			outbound["email"] = email
		}
	}

	now := s.now().UTC()
	outbound["iss"] = s.cfg.Issuer
	if audience != "" {
		outbound["aud"] = audience
	}
	outbound["iat"] = now.Unix()
	outbound["exp"] = now.Add(s.cfg.TokenTTL).Unix()
	outbound["jti"] = uuid.NewString()

	// Claim transforms: add_claims (only if absent) -> set_claims (overwrite) -> remove_claims.
	for k, v := range s.cfg.AddClaims {
		if _, exists := outbound[k]; !exists {
			outbound[k] = v
		}
	}
	for k, v := range s.cfg.SetClaims {
		outbound[k] = v
	}
	for _, k := range s.cfg.RemoveClaims {
		delete(outbound, k)
	}

	signed, err := s.signClaims(outbound)
	if err != nil {
		return "", nil, err
	}
	return signed, outbound, nil
}

func (s *MCPJWTSigner) validateAudience(audience string) error {
	if len(s.cfg.TrustedAudiences) == 0 {
		return nil
	}
	for _, ta := range s.cfg.TrustedAudiences {
		if ta == "*" || ta == audience || (ta != "" && strings.HasPrefix(audience, ta)) {
			return nil
		}
	}
	return fmt.Errorf("%w: %q (allowed: %v)", upstream.ErrUntrustedAudience, audience, s.cfg.TrustedAudiences)
}

func (s *MCPJWTSigner) signClaims(claims map[string]any) (string, error) {
	hdr := map[string]string{
		"alg": s.signingAlg,
		"typ": "JWT",
	}
	if s.cfg.KeyID != "" {
		hdr["kid"] = s.cfg.KeyID
	}
	hdrBytes, err := json.Marshal(hdr)
	if err != nil {
		return "", fmt.Errorf("mcp_jwt_signer: marshal header: %w", err)
	}
	claimsBytes, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("mcp_jwt_signer: marshal claims: %w", err)
	}

	signingInput := base64.RawURLEncoding.EncodeToString(hdrBytes) + "." + base64.RawURLEncoding.EncodeToString(claimsBytes)

	var sig []byte
	switch s.signingAlg {
	case "HS256":
		mac := hmac.New(sha256.New, s.hmacKey)
		_, _ = mac.Write([]byte(signingInput))
		sig = mac.Sum(nil)
	case "RS256":
		digest := sha256.Sum256([]byte(signingInput))
		sig, err = rsa.SignPKCS1v15(rand.Reader, s.rsaPriv, crypto.SHA256, digest[:])
		if err != nil {
			return "", fmt.Errorf("mcp_jwt_signer: RS256 sign: %w", err)
		}
	case "ES256":
		digest := sha256.Sum256([]byte(signingInput))
		r, sv, signErr := ecdsa.Sign(rand.Reader, s.ecPriv, digest[:])
		if signErr != nil {
			return "", fmt.Errorf("mcp_jwt_signer: ES256 sign: %w", signErr)
		}
		sig = make([]byte, 64)
		r.FillBytes(sig[:32])
		sv.FillBytes(sig[32:])
	default:
		return "", fmt.Errorf("mcp_jwt_signer: unsupported signing algorithm %q", s.signingAlg)
	}

	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

func (s *MCPJWTSigner) verifyIncomingToken(ctx context.Context, rawToken string) (map[string]any, error) {
	parts := strings.Split(strings.TrimSpace(rawToken), ".")
	if len(parts) != 3 {
		return nil, errors.New("mcp_jwt_signer: invalid incoming jwt format")
	}

	hdrBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("mcp_jwt_signer: decode incoming jwt header: %w", err)
	}
	var hdr struct {
		Alg string `json:"alg"`
		Kid string `json:"kid,omitempty"`
	}
	if err := json.Unmarshal(hdrBytes, &hdr); err != nil {
		return nil, fmt.Errorf("mcp_jwt_signer: parse incoming jwt header: %w", err)
	}
	if hdr.Alg == "" || strings.EqualFold(hdr.Alg, "none") {
		return nil, errors.New("mcp_jwt_signer: incoming jwt algorithm is missing or disallowed")
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("mcp_jwt_signer: decode incoming jwt payload: %w", err)
	}
	sigBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("mcp_jwt_signer: decode incoming jwt signature: %w", err)
	}

	signingInput := parts[0] + "." + parts[1]
	if err := s.verifyIncomingSignature(ctx, hdr.Alg, hdr.Kid, signingInput, sigBytes); err != nil {
		return nil, err
	}

	var claims map[string]any
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return nil, fmt.Errorf("mcp_jwt_signer: parse incoming jwt claims: %w", err)
	}

	nowUnix := s.now().UTC().Unix()
	if expVal, hasExp := numericClaimInt64(claims["exp"]); hasExp {
		if nowUnix >= expVal {
			return nil, errors.New("mcp_jwt_signer: incoming jwt token is expired")
		}
	} else if !s.cfg.AllowMissingExp {
		return nil, errors.New("mcp_jwt_signer: incoming jwt missing exp claim")
	}

	if nbfVal, hasNbf := numericClaimInt64(claims["nbf"]); hasNbf && nowUnix < nbfVal {
		return nil, errors.New("mcp_jwt_signer: incoming jwt token is not yet valid")
	}

	if s.cfg.VerificationIssuer != "" {
		iss, _ := claims["iss"].(string)
		if iss != s.cfg.VerificationIssuer {
			return nil, fmt.Errorf("mcp_jwt_signer: incoming jwt issuer mismatch: got %q, want %q", iss, s.cfg.VerificationIssuer)
		}
	}
	if s.cfg.VerificationAudience != "" && !claimAudienceContains(claims["aud"], s.cfg.VerificationAudience) {
		return nil, fmt.Errorf("mcp_jwt_signer: incoming jwt audience %q not present", s.cfg.VerificationAudience)
	}

	return claims, nil
}

func (s *MCPJWTSigner) verifyIncomingSignature(ctx context.Context, alg, kid, signingInput string, sigBytes []byte) error {
	switch alg {
	case "HS256", "HS384", "HS512":
		if len(s.verifyHMACKey) == 0 {
			return fmt.Errorf("mcp_jwt_signer: %s verification key is not configured", alg)
		}
		var hashFn func() hash.Hash
		switch alg {
		case "HS256":
			hashFn = sha256.New
		case "HS384":
			hashFn = sha512.New384
		case "HS512":
			hashFn = sha512.New
		}
		mac := hmac.New(hashFn, s.verifyHMACKey)
		_, _ = mac.Write([]byte(signingInput))
		if !hmac.Equal(sigBytes, mac.Sum(nil)) {
			return fmt.Errorf("mcp_jwt_signer: invalid %s incoming jwt signature", alg)
		}
		return nil

	case "RS256", "RS384", "RS512":
		pub, err := s.resolveVerificationKey(ctx, kid, alg)
		if err != nil {
			return err
		}
		rsaPub, ok := pub.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("mcp_jwt_signer: key type mismatch for %s", alg)
		}
		cHash, digest := hashForJWTAlg(alg, []byte(signingInput))
		if err := rsa.VerifyPKCS1v15(rsaPub, cHash, digest, sigBytes); err != nil {
			return fmt.Errorf("mcp_jwt_signer: invalid %s incoming jwt signature: %w", alg, err)
		}
		return nil

	case "ES256", "ES384", "ES512":
		pub, err := s.resolveVerificationKey(ctx, kid, alg)
		if err != nil {
			return err
		}
		ecPub, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			return fmt.Errorf("mcp_jwt_signer: key type mismatch for %s", alg)
		}
		_, digest := hashForJWTAlg(alg, []byte(signingInput))
		coordSize := (ecPub.Curve.Params().BitSize + 7) / 8
		if len(sigBytes) == 2*coordSize {
			r := new(big.Int).SetBytes(sigBytes[:coordSize])
			sv := new(big.Int).SetBytes(sigBytes[coordSize:])
			if !ecdsa.Verify(ecPub, digest, r, sv) {
				return fmt.Errorf("mcp_jwt_signer: invalid %s incoming jwt signature", alg)
			}
			return nil
		}
		if !ecdsa.VerifyASN1(ecPub, digest, sigBytes) {
			return fmt.Errorf("mcp_jwt_signer: invalid %s incoming jwt signature", alg)
		}
		return nil

	default:
		return fmt.Errorf("mcp_jwt_signer: unsupported incoming jwt signing algorithm %q", alg)
	}
}

func (s *MCPJWTSigner) resolveVerificationKey(ctx context.Context, kid, expectedAlg string) (any, error) {
	if s.verifyPubKey != nil {
		return s.verifyPubKey, nil
	}
	if strings.TrimSpace(s.cfg.VerificationJWKSURL) == "" {
		return nil, fmt.Errorf("mcp_jwt_signer: no public key or JWKS URL configured for %s", expectedAlg)
	}

	now := s.now().UTC()
	s.mu.RLock()
	cacheValid := !s.fetchedAt.IsZero() && now.Sub(s.fetchedAt) < s.cacheTTL
	entry, found := s.lookupJWKSKeyLocked(kid)
	s.mu.RUnlock()

	if cacheValid && found {
		if entry.alg != "" && entry.alg != expectedAlg {
			return nil, fmt.Errorf("mcp_jwt_signer: jwks key %q algorithm mismatch: %q != %q", kid, entry.alg, expectedAlg)
		}
		return entry.key, nil
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}
	_, err, _ := s.refreshGroup.Do("jwks", func() (any, error) {
		s.mu.RLock()
		now := s.now().UTC()
		stillValid := !s.fetchedAt.IsZero() && now.Sub(s.fetchedAt) < s.cacheTTL
		_, stillFound := s.lookupJWKSKeyLocked(kid)
		canRefresh := s.lastAttempt.IsZero() || now.Sub(s.lastAttempt) >= 10*time.Second
		s.mu.RUnlock()
		if stillValid && stillFound {
			return nil, nil
		}
		if !canRefresh {
			return nil, fmt.Errorf("mcp_jwt_signer: jwks refresh rate-limited; key %q unavailable", kid)
		}
		fetchCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
		defer cancel()
		return nil, s.refreshJWKS(fetchCtx)
	})
	if err != nil {
		return nil, err
	}

	s.mu.RLock()
	entry, found = s.lookupJWKSKeyLocked(kid)
	s.mu.RUnlock()
	if !found {
		return nil, fmt.Errorf("mcp_jwt_signer: jwks key %q not found", kid)
	}
	if entry.alg != "" && entry.alg != expectedAlg {
		return nil, fmt.Errorf("mcp_jwt_signer: jwks key %q algorithm mismatch: %q != %q", kid, entry.alg, expectedAlg)
	}
	return entry.key, nil
}

func (s *MCPJWTSigner) lookupJWKSKeyLocked(kid string) (signerCachedJWK, bool) {
	if kid != "" {
		k, ok := s.jwksKeys[kid]
		return k, ok && k.key != nil
	}
	if len(s.jwksKeys) == 1 {
		for _, k := range s.jwksKeys {
			return k, k.key != nil
		}
	}
	return signerCachedJWK{}, false
}

func (s *MCPJWTSigner) refreshJWKS(ctx context.Context) error {
	if s.httpClient == nil {
		return errors.New("mcp_jwt_signer: jwks http client is not initialized")
	}

	s.mu.Lock()
	s.lastAttempt = s.now().UTC()
	s.mu.Unlock()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.cfg.VerificationJWKSURL, nil)
	if err != nil {
		return fmt.Errorf("mcp_jwt_signer: build jwks request: %w", err)
	}
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("mcp_jwt_signer: fetch jwks: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("mcp_jwt_signer: fetch jwks unexpected status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxJWKSBodyBytes))
	if err != nil {
		return fmt.Errorf("mcp_jwt_signer: read jwks body: %w", err)
	}

	var doc struct {
		Keys []struct {
			Kty string `json:"kty"`
			Kid string `json:"kid"`
			Use string `json:"use,omitempty"`
			Alg string `json:"alg,omitempty"`
			N   string `json:"n,omitempty"`
			E   string `json:"e,omitempty"`
			Crv string `json:"crv,omitempty"`
			X   string `json:"x,omitempty"`
			Y   string `json:"y,omitempty"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return fmt.Errorf("mcp_jwt_signer: parse jwks json: %w", err)
	}

	parsed := make(map[string]signerCachedJWK, len(doc.Keys))
	for _, entry := range doc.Keys {
		if entry.Use != "" && entry.Use != "sig" {
			continue
		}
		var pub any
		switch entry.Kty {
		case "RSA":
			nBytes, nErr := base64.RawURLEncoding.DecodeString(entry.N)
			eBytes, eErr := base64.RawURLEncoding.DecodeString(entry.E)
			if nErr != nil || eErr != nil || len(nBytes) == 0 || len(eBytes) == 0 {
				continue
			}
			eInt := new(big.Int).SetBytes(eBytes).Int64()
			if eInt <= 0 {
				continue
			}
			pub = &rsa.PublicKey{N: new(big.Int).SetBytes(nBytes), E: int(eInt)}
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
				continue
			}
			xBytes, xErr := base64.RawURLEncoding.DecodeString(entry.X)
			yBytes, yErr := base64.RawURLEncoding.DecodeString(entry.Y)
			if xErr != nil || yErr != nil || len(xBytes) == 0 || len(yBytes) == 0 {
				continue
			}
			pub = &ecdsa.PublicKey{
				Curve: curve,
				X:     new(big.Int).SetBytes(xBytes),
				Y:     new(big.Int).SetBytes(yBytes),
			}
		default:
			continue
		}
		kid := entry.Kid
		if kid == "" {
			kid = fmt.Sprintf("_default_%d", len(parsed))
		}
		parsed[kid] = signerCachedJWK{key: pub, alg: strings.TrimSpace(entry.Alg)}
	}
	if len(parsed) == 0 {
		return errors.New("mcp_jwt_signer: jwks contained no usable signing keys")
	}

	s.mu.Lock()
	s.jwksKeys = parsed
	s.fetchedAt = s.now().UTC()
	s.mu.Unlock()
	return nil
}

func resolveTargetAudience(req *http.Request, authCtx *upstream.UpstreamAuthContext) string {
	if authCtx != nil {
		if authCtx.TargetURL != "" {
			return authCtx.TargetURL
		}
		if authCtx.ServerSlug != "" {
			return authCtx.ServerSlug
		}
	}
	if req != nil && req.URL != nil {
		return req.URL.String()
	}
	return ""
}

func extractIncomingBearerToken(req *http.Request, authCtx *upstream.UpstreamAuthContext) string {
	if authCtx != nil && strings.TrimSpace(authCtx.DelegatedToken) != "" {
		return authCtx.DelegatedToken
	}
	if authCtx != nil && len(authCtx.ExtraHeaders) > 0 {
		for k, v := range authCtx.ExtraHeaders {
			lk := strings.ToLower(k)
			if (lk == "x-goroute-end-user-token" || lk == "x-end-user-token") && strings.TrimSpace(v) != "" {
				return v
			}
		}
	}
	if req != nil {
		for _, hdr := range []string{"X-GoRoute-End-User-Token", "X-End-User-Token"} {
			if val := strings.TrimSpace(req.Header.Get(hdr)); val != "" {
				return val
			}
		}
		if authHdr := strings.TrimSpace(req.Header.Get("Authorization")); authHdr != "" {
			tok := stripBearerPrefix(authHdr)
			if strings.Count(tok, ".") == 2 && !strings.HasPrefix(tok, "sk-gw-") {
				return tok
			}
		}
	}
	return ""
}

func stripBearerPrefix(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if len(trimmed) > 7 && strings.EqualFold(trimmed[:7], "Bearer ") {
		return strings.TrimSpace(trimmed[7:])
	}
	return trimmed
}

func validateSignerRequiredClaims(required RequiredClaimsSpec, actual map[string]any) error {
	for k, want := range required {
		got, exists := actual[k]
		if !exists || got == nil {
			return fmt.Errorf("mcp_jwt_signer: missing required claim %q", k)
		}
		if b, ok := want.(bool); ok && b {
			if s, ok := got.(string); ok && strings.TrimSpace(s) == "" {
				return fmt.Errorf("mcp_jwt_signer: required claim %q is empty", k)
			}
			continue
		}
		if !signerClaimMatches(k, want, got) {
			return fmt.Errorf("mcp_jwt_signer: required claim %q does not match expected policy", k)
		}
	}
	return nil
}

func signerClaimMatches(claimKey string, want, got any) bool {
	if wantSlice, ok := toStringSlice(want); ok {
		gotSlice, _ := toStringSlice(got)
		if len(gotSlice) == 1 && (claimKey == "scope" || claimKey == "scp") && strings.Contains(gotSlice[0], " ") {
			gotSlice = strings.Fields(gotSlice[0])
		}
		for _, w := range wantSlice {
			for _, g := range gotSlice {
				if w == g {
					return true
				}
			}
		}
		return false
	}
	if wantStr, ok := want.(string); ok {
		gotSlice, ok := toStringSlice(got)
		if ok {
			if len(gotSlice) == 1 && (claimKey == "scope" || claimKey == "scp") && strings.Contains(gotSlice[0], " ") {
				gotSlice = strings.Fields(gotSlice[0])
			}
			for _, g := range gotSlice {
				if g == wantStr {
					return true
				}
			}
			return false
		}
	}
	return fmt.Sprint(want) == fmt.Sprint(got)
}

func toStringSlice(v any) ([]string, bool) {
	switch typed := v.(type) {
	case []string:
		return typed, true
	case []any:
		out := make([]string, 0, len(typed))
		for _, item := range typed {
			out = append(out, fmt.Sprint(item))
		}
		return out, true
	case string:
		return []string{typed}, true
	default:
		return nil, false
	}
}

func resolveEndUserSub(source string, verifiedClaims map[string]any, authCtx *upstream.UpstreamAuthContext) string {
	incomingSub, _ := verifiedClaims["sub"].(string)
	incomingSub = strings.TrimSpace(incomingSub)

	userID := ""
	vkID := ""
	if authCtx != nil {
		userID = strings.TrimSpace(authCtx.CallingUserID)
		vkID = strings.TrimSpace(authCtx.CallingVirtualKey)
	}

	switch strings.ToLower(strings.TrimSpace(source)) {
	case "incoming_sub":
		return incomingSub
	case "end_user_id", "user_id":
		if userID != "" {
			return userID
		}
		return incomingSub
	case "virtual_key":
		return vkID
	default:
		if incomingSub != "" {
			return incomingSub
		}
		return userID
	}
}

func resolveEndUserEmail(defaultEmail string, verifiedClaims map[string]any, authCtx *upstream.UpstreamAuthContext) string {
	if email, ok := verifiedClaims["email"].(string); ok && strings.TrimSpace(email) != "" {
		return strings.TrimSpace(email)
	}
	if authCtx != nil {
		for k, v := range authCtx.ExtraHeaders {
			if strings.EqualFold(k, "X-GoRoute-User-Email") && strings.TrimSpace(v) != "" {
				return strings.TrimSpace(v)
			}
		}
	}
	return strings.TrimSpace(defaultEmail)
}

func isReservedJWTEnvelopeClaim(k string) bool {
	switch k {
	case "iss", "aud", "exp", "iat", "nbf", "jti":
		return true
	default:
		return false
	}
}

func numericClaimInt64(v any) (int64, bool) {
	switch n := v.(type) {
	case float64:
		return int64(n), true
	case int64:
		return n, true
	case json.Number:
		parsed, err := n.Int64()
		return parsed, err == nil
	default:
		return 0, false
	}
}

func claimAudienceContains(audClaim any, expected string) bool {
	switch v := audClaim.(type) {
	case string:
		return v == expected
	case []any:
		for _, item := range v {
			if s, ok := item.(string); ok && s == expected {
				return true
			}
		}
	case []string:
		for _, s := range v {
			if s == expected {
				return true
			}
		}
	}
	return false
}

func hashForJWTAlg(alg string, data []byte) (crypto.Hash, []byte) {
	switch alg {
	case "RS384", "ES384":
		sum := sha512.Sum384(data)
		return crypto.SHA384, sum[:]
	case "RS512", "ES512":
		sum := sha512.Sum512(data)
		return crypto.SHA512, sum[:]
	default:
		sum := sha256.Sum256(data)
		return crypto.SHA256, sum[:]
	}
}

func parseRSAPrivateKeyPEM(pemStr string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, errors.New("invalid PEM block")
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	rsaKey, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("PEM key is not RSA private key")
	}
	return rsaKey, nil
}

func parseECPrivateKeyPEM(pemStr string) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, errors.New("invalid PEM block")
	}
	if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	ecKey, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("PEM key is not ECDSA private key")
	}
	return ecKey, nil
}

func parsePublicKeyPEM(pemStr string) (any, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, errors.New("invalid PEM block")
	}
	if pub, err := x509.ParsePKIXPublicKey(block.Bytes); err == nil {
		return pub, nil
	}
	if rsaPub, err := x509.ParsePKCS1PublicKey(block.Bytes); err == nil {
		return rsaPub, nil
	}
	if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
		return cert.PublicKey, nil
	}
	return nil, errors.New("unsupported PEM public key format")
}
