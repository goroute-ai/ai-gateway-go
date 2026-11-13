package auth

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/security/network"
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

// JWTClaims represents validated inbound JWT claims for Control Plane operator authentication.
type JWTClaims struct {
	Subject   string        `json:"sub"`
	Issuer    string        `json:"iss,omitempty"`
	Audience  AudienceClaim `json:"aud,omitempty"`
	ExpiresAt int64         `json:"exp,omitempty"`
	NotBefore int64         `json:"nbf,omitempty"`
	IssuedAt  int64         `json:"iat,omitempty"`
	Email     string        `json:"email,omitempty"`
	Role      string        `json:"role,omitempty"`
	OrgID     string        `json:"org_id,omitempty"`
}

// JWTConfig configures inbound JWT and OIDC JWKS verification.
type JWTConfig struct {
	Secret        string
	Issuer        string
	Audience      string
	OIDCJWKSURL   string
	NetworkPolicy *network.Policy
	HTTPClient    *http.Client
}

// JWTVerifier validates inbound HS256 and OIDC RS256/ES256 JWTs.
type JWTVerifier struct {
	secret     []byte
	issuer     string
	audience   string
	jwksURL    string
	httpClient *http.Client
	now        func() time.Time

	mu          sync.RWMutex
	keys        map[string]any
	fetchedAt   time.Time
	lastAttempt time.Time
	cacheTTL    time.Duration
}

// NewJWTVerifier constructs a JWTVerifier using the outbound network policy HTTP client for JWKS fetches.
func NewJWTVerifier(cfg JWTConfig) *JWTVerifier {
	client := cfg.HTTPClient
	if client == nil && cfg.OIDCJWKSURL != "" {
		client = network.NewHTTPClient(cfg.NetworkPolicy)
	}
	return &JWTVerifier{
		secret:     []byte(strings.TrimSpace(cfg.Secret)),
		issuer:     strings.TrimSpace(cfg.Issuer),
		audience:   strings.TrimSpace(cfg.Audience),
		jwksURL:    strings.TrimSpace(cfg.OIDCJWKSURL),
		httpClient: client,
		now:        time.Now,
		keys:       make(map[string]any),
		cacheTTL:   5 * time.Minute,
	}
}

// Enabled reports whether either HMAC secret or OIDC JWKS verification is configured.
func (v *JWTVerifier) Enabled() bool {
	return v != nil && (len(v.secret) > 0 || v.jwksURL != "")
}

type jwtHeader struct {
	Alg string `json:"alg"`
	Kid string `json:"kid,omitempty"`
	Typ string `json:"typ,omitempty"`
}

// Verify parses and cryptographically verifies an inbound JWT and validates standard claims.
func (v *JWTVerifier) Verify(ctx context.Context, rawToken string) (*JWTClaims, error) {
	if !v.Enabled() {
		return nil, errors.New("jwt verification is not configured")
	}

	parts := strings.Split(strings.TrimSpace(rawToken), ".")
	if len(parts) != 3 {
		return nil, errors.New("invalid jwt format")
	}

	hdrBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("decode jwt header: %w", err)
	}
	var hdr jwtHeader
	if err := json.Unmarshal(hdrBytes, &hdr); err != nil {
		return nil, fmt.Errorf("parse jwt header: %w", err)
	}
	if hdr.Alg == "" || strings.EqualFold(hdr.Alg, "none") {
		return nil, errors.New("jwt algorithm is missing or disallowed")
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decode jwt payload: %w", err)
	}
	sigBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("decode jwt signature: %w", err)
	}

	signingInput := parts[0] + "." + parts[1]
	if err := v.verifySignature(ctx, hdr, signingInput, sigBytes); err != nil {
		return nil, err
	}

	var claims JWTClaims
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return nil, fmt.Errorf("parse jwt claims: %w", err)
	}

	nowUnix := v.now().UTC().Unix()
	if claims.ExpiresAt <= 0 {
		return nil, errors.New("jwt missing exp claim")
	}
	if nowUnix >= claims.ExpiresAt {
		return nil, errors.New("jwt token is expired")
	}
	if claims.NotBefore > 0 && nowUnix < claims.NotBefore {
		return nil, errors.New("jwt token is not yet valid")
	}
	if v.issuer != "" && claims.Issuer != v.issuer {
		return nil, fmt.Errorf("jwt issuer mismatch: got %q, want %q", claims.Issuer, v.issuer)
	}
	if v.audience != "" && !claims.Audience.Contains(v.audience) {
		return nil, fmt.Errorf("jwt audience %q not present", v.audience)
	}
	if strings.TrimSpace(claims.Subject) == "" {
		return nil, errors.New("jwt missing sub claim")
	}

	return &claims, nil
}

func (v *JWTVerifier) verifySignature(ctx context.Context, hdr jwtHeader, signingInput string, sigBytes []byte) error {
	digest := sha256.Sum256([]byte(signingInput))

	switch hdr.Alg {
	case "HS256":
		if len(v.secret) == 0 {
			return errors.New("HS256 jwt secret is not configured")
		}
		mac := hmac.New(sha256.New, v.secret)
		_, _ = mac.Write([]byte(signingInput))
		expected := mac.Sum(nil)
		if !hmac.Equal(sigBytes, expected) {
			return errors.New("invalid HS256 jwt signature")
		}
		return nil

	case "RS256":
		pubKey, err := v.resolveJWKSKey(ctx, hdr.Kid)
		if err != nil {
			return err
		}
		rsaKey, ok := pubKey.(*rsa.PublicKey)
		if !ok {
			return errors.New("jwt key type mismatch for RS256")
		}
		if err := rsa.VerifyPKCS1v15(rsaKey, crypto.SHA256, digest[:], sigBytes); err != nil {
			return fmt.Errorf("invalid RS256 jwt signature: %w", err)
		}
		return nil

	case "ES256":
		pubKey, err := v.resolveJWKSKey(ctx, hdr.Kid)
		if err != nil {
			return err
		}
		ecKey, ok := pubKey.(*ecdsa.PublicKey)
		if !ok {
			return errors.New("jwt key type mismatch for ES256")
		}
		if len(sigBytes) == 64 {
			r := new(big.Int).SetBytes(sigBytes[:32])
			s := new(big.Int).SetBytes(sigBytes[32:])
			if !ecdsa.Verify(ecKey, digest[:], r, s) {
				return errors.New("invalid ES256 jwt signature")
			}
			return nil
		}
		if !ecdsa.VerifyASN1(ecKey, digest[:], sigBytes) {
			return errors.New("invalid ES256 jwt signature")
		}
		return nil

	default:
		return fmt.Errorf("unsupported jwt signing algorithm %q", hdr.Alg)
	}
}

func (v *JWTVerifier) resolveJWKSKey(ctx context.Context, kid string) (any, error) {
	if v.jwksURL == "" {
		return nil, errors.New("oidc jwks url is not configured")
	}

	now := v.now().UTC()
	v.mu.RLock()
	cacheValid := !v.fetchedAt.IsZero() && now.Sub(v.fetchedAt) < v.cacheTTL
	key, found := v.lookupKeyLocked(kid)
	canRefresh := v.lastAttempt.IsZero() || now.Sub(v.lastAttempt) >= 10*time.Second
	v.mu.RUnlock()

	if cacheValid && found {
		return key, nil
	}
	if !cacheValid || (!found && canRefresh) {
		if err := v.refreshJWKS(ctx); err != nil {
			return nil, err
		}
		v.mu.RLock()
		key, found = v.lookupKeyLocked(kid)
		v.mu.RUnlock()
		if found {
			return key, nil
		}
	}

	return nil, fmt.Errorf("jwks key %q not found", kid)
}

func (v *JWTVerifier) lookupKeyLocked(kid string) (any, bool) {
	if kid != "" {
		k, ok := v.keys[kid]
		return k, ok && k != nil
	}
	if len(v.keys) == 1 {
		for _, k := range v.keys {
			return k, k != nil
		}
	}
	return nil, false
}

type jwksDocument struct {
	Keys []jwkEntry `json:"keys"`
}

type jwkEntry struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use,omitempty"`
	Alg string `json:"alg,omitempty"`
	N   string `json:"n,omitempty"`
	E   string `json:"e,omitempty"`
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
}

func (v *JWTVerifier) refreshJWKS(ctx context.Context) error {
	if v.httpClient == nil {
		return errors.New("jwks http client is not initialized")
	}

	v.mu.Lock()
	v.lastAttempt = v.now().UTC()
	v.mu.Unlock()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.jwksURL, nil)
	if err != nil {
		return fmt.Errorf("build jwks request: %w", err)
	}
	resp, err := v.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("fetch jwks: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("fetch jwks: unexpected status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("read jwks body: %w", err)
	}

	var doc jwksDocument
	if err := json.Unmarshal(body, &doc); err != nil {
		return fmt.Errorf("parse jwks json: %w", err)
	}

	parsed := make(map[string]any, len(doc.Keys))
	for _, entry := range doc.Keys {
		if entry.Use != "" && entry.Use != "sig" {
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
		parsed[kid] = pub
	}
	if len(parsed) == 0 {
		return errors.New("jwks contained no usable signing keys")
	}

	v.mu.Lock()
	v.keys = parsed
	v.fetchedAt = v.now().UTC()
	v.mu.Unlock()
	return nil
}

func parseJWKPublicKey(entry jwkEntry) (any, error) {
	switch entry.Kty {
	case "RSA":
		nBytes, err := base64.RawURLEncoding.DecodeString(entry.N)
		if err != nil || len(nBytes) == 0 {
			return nil, errors.New("invalid RSA modulus")
		}
		eBytes, err := base64.RawURLEncoding.DecodeString(entry.E)
		if err != nil || len(eBytes) == 0 {
			return nil, errors.New("invalid RSA exponent")
		}
		eInt := new(big.Int).SetBytes(eBytes).Int64()
		if eInt <= 0 {
			return nil, errors.New("invalid RSA exponent value")
		}
		return &rsa.PublicKey{
			N: new(big.Int).SetBytes(nBytes),
			E: int(eInt),
		}, nil

	case "EC":
		if entry.Crv != "P-256" {
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
		return &ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     new(big.Int).SetBytes(xBytes),
			Y:     new(big.Int).SetBytes(yBytes),
		}, nil

	default:
		return nil, fmt.Errorf("unsupported jwk key type %q", entry.Kty)
	}
}

// SignHS256 signs a JWTClaims payload with HS256 using the given secret.
func SignHS256(secret string, claims *JWTClaims) (string, error) {
	if strings.TrimSpace(secret) == "" {
		return "", errors.New("jwt secret is required")
	}
	hdrJSON, err := json.Marshal(map[string]string{
		"alg": "HS256",
		"typ": "JWT",
	})
	if err != nil {
		return "", err
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	signingInput := base64.RawURLEncoding.EncodeToString(hdrJSON) + "." + base64.RawURLEncoding.EncodeToString(claimsJSON)
	mac := hmac.New(sha256.New, []byte(strings.TrimSpace(secret)))
	_, _ = mac.Write([]byte(signingInput))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return signingInput + "." + sig, nil
}
