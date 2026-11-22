package a2a

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	a2aspec "github.com/goroute-ai/ai-gateway-go/internal/a2a/spec"
	"github.com/goroute-ai/ai-gateway-go/internal/auth"
	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/security/network"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
)

// CanonicalizeJCS serializes any JSON-compatible object into RFC 8785 JSON Canonicalization Scheme (JCS).
func CanonicalizeJCS(v any) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var parsed any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&parsed); err != nil {
		return nil, err
	}
	return canonicalizeValue(parsed)
}

func canonicalizeValue(v any) ([]byte, error) {
	switch val := v.(type) {
	case nil:
		return []byte("null"), nil
	case bool:
		if val {
			return []byte("true"), nil
		}
		return []byte("false"), nil
	case json.Number:
		return []byte(val.String()), nil
	case string:
		return json.Marshal(val)
	case []any:
		var buf bytes.Buffer
		buf.WriteByte('[')
		for i, item := range val {
			if i > 0 {
				buf.WriteByte(',')
			}
			b, err := canonicalizeValue(item)
			if err != nil {
				return nil, err
			}
			buf.Write(b)
		}
		buf.WriteByte(']')
		return buf.Bytes(), nil
	case map[string]any:
		keys := make([]string, 0, len(val))
		for k := range val {
			keys = append(keys, k)
		}
		sort.Strings(keys)

		var buf bytes.Buffer
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			kb, _ := json.Marshal(k)
			buf.Write(kb)
			buf.WriteByte(':')
			vb, err := canonicalizeValue(val[k])
			if err != nil {
				return nil, err
			}
			buf.Write(vb)
		}
		buf.WriteByte('}')
		return buf.Bytes(), nil
	default:
		return json.Marshal(val)
	}
}

// UpstreamCardVerifier validates upstream AgentCard JWS signatures against trusted keys / JWKS URLs.
type UpstreamCardVerifier struct {
	mu                sync.RWMutex
	trustedPublicKeys map[string]any // kid -> *ecdsa.PublicKey, *rsa.PublicKey, or ed25519.PublicKey
	trustedCardJWKS   map[string]string
	jwksLastRefresh   map[string]time.Time
	lastJWKSURL       string
	refreshCooldown   time.Duration
	allowedAlgs       []string
	netPolicy         *network.Policy
	httpClient        *http.Client
}

// NewUpstreamCardVerifier creates a verifier with an initial map of trusted public keys.
func NewUpstreamCardVerifier(trustedKeys map[string]any, opts ...CardVerifierOption) *UpstreamCardVerifier {
	keysCopy := make(map[string]any)
	for k, v := range trustedKeys {
		keysCopy[k] = v
	}
	defaultPolicy, _ := network.NewPolicy(config.OutboundSSRFConfig{})
	defaultClient := network.NewHTTPClient(defaultPolicy)
	defaultClient.Timeout = 10 * time.Second
	v := &UpstreamCardVerifier{
		trustedPublicKeys: keysCopy,
		trustedCardJWKS:   make(map[string]string),
		jwksLastRefresh:   make(map[string]time.Time),
		refreshCooldown:   1 * time.Minute,
		allowedAlgs:       []string{"ES256", "RS256", "EdDSA"},
		netPolicy:         defaultPolicy,
		httpClient:        defaultClient,
	}
	for _, opt := range opts {
		if opt != nil {
			opt(v)
		}
	}
	return v
}

// CardVerifierOption customizes an UpstreamCardVerifier.
type CardVerifierOption func(*UpstreamCardVerifier)

// WithVerifierNetworkPolicy attaches an SSRF-hardened network policy for fetching upstream JWKS & cards.
func WithVerifierNetworkPolicy(policy *network.Policy) CardVerifierOption {
	return func(v *UpstreamCardVerifier) {
		v.netPolicy = policy
		client := network.NewHTTPClient(policy)
		client.Timeout = 10 * time.Second
		v.httpClient = client
	}
}

func containsUnsafeCardURLChars(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] == 0x7f || s[i] == '\\' {
			return true
		}
	}
	return false
}

// ValidateAndSanitizeCardURL validates an upstream AgentCard or JWKS URL against URL syntax
// invariants (HTTP/HTTPS scheme, non-empty canonical host, no userinfo, no trailing-dot host,
// no path traversal, no ASCII control characters or backslashes) and the active outbound network
// SSRF policy (defaulting to strict public-HTTPS enforcement when policy is nil).
func ValidateAndSanitizeCardURL(rawURL string, policy *network.Policy) (string, error) {
	if containsUnsafeCardURLChars(rawURL) {
		return "", errors.New("a2a: URL must not contain control characters or backslashes")
	}
	trimmed := strings.TrimSpace(rawURL)
	if trimmed == "" {
		return "", errors.New("a2a: URL is empty")
	}
	u, err := url.Parse(trimmed)
	if err != nil {
		return "", fmt.Errorf("a2a: invalid URL: %w", err)
	}
	scheme := strings.ToLower(strings.TrimSpace(u.Scheme))
	if scheme != "https" && scheme != "http" {
		return "", errors.New("a2a: URL must use http or https scheme")
	}
	if u.User != nil {
		return "", errors.New("a2a: URL must not include embedded credentials")
	}
	rawHost := strings.TrimSpace(u.Hostname())
	if rawHost == "" {
		return "", errors.New("a2a: URL must include a hostname")
	}
	if strings.HasSuffix(rawHost, ".") {
		return "", errors.New("a2a: URL hostname must not end with a trailing dot")
	}
	if containsUnsafeCardURLChars(u.Host) || containsUnsafeCardURLChars(u.Path) {
		return "", errors.New("a2a: URL must not contain control characters or backslashes")
	}
	for _, seg := range strings.Split(u.Path, "/") {
		if seg == ".." {
			return "", errors.New("a2a: URL must not contain path traversal segments")
		}
	}
	if policy == nil {
		strictPol, polErr := network.NewPolicy(config.OutboundSSRFConfig{})
		if polErr != nil {
			return "", fmt.Errorf("a2a: default outbound network policy: %w", polErr)
		}
		policy = strictPol
	}
	if err := policy.ValidateURL(u); err != nil {
		return "", fmt.Errorf("a2a: URL blocked by outbound SSRF policy: %w", err)
	}
	host := strings.ToLower(rawHost)
	if port := u.Port(); port != "" {
		host = net.JoinHostPort(host, port)
	} else if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	return (&url.URL{
		Scheme:   scheme,
		Host:     host,
		Path:     u.Path,
		RawPath:  u.RawPath,
		RawQuery: u.RawQuery,
	}).String(), nil
}

// WithVerifierAllowedAlgs overrides allowed JWS algorithms (e.g. ["ES256", "RS256", "EdDSA"]).
func WithVerifierAllowedAlgs(algs []string) CardVerifierOption {
	return func(v *UpstreamCardVerifier) {
		if len(algs) > 0 {
			v.allowedAlgs = slices.Clone(algs)
		}
	}
}

// WithVerifierTrustedJWKS configures agent-slug -> JWKS URL mappings from A2AConfig.TrustedCardJWKS.
func WithVerifierTrustedJWKS(jwksMap map[string]string) CardVerifierOption {
	return func(v *UpstreamCardVerifier) {
		for k, u := range jwksMap {
			v.trustedCardJWKS[k] = u
		}
	}
}

// WithVerifierRefreshCooldown configures the minimum cooldown between automatic JWKS refreshes on unknown kid.
func WithVerifierRefreshCooldown(cooldown time.Duration) CardVerifierOption {
	return func(v *UpstreamCardVerifier) {
		if cooldown >= 0 {
			v.refreshCooldown = cooldown
		}
	}
}

// AddTrustedKey registers a trusted public key for a key ID.
func (v *UpstreamCardVerifier) AddTrustedKey(kid string, pubKey any) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.trustedPublicKeys[kid] = pubKey
}

// VerifyAgentCard verifies a compact or detached JWS string over the RFC 8785 canonicalized card.
func (v *UpstreamCardVerifier) VerifyAgentCard(card *a2aspec.AgentCard, rawJWS string) error {
	if card == nil {
		return errors.New("a2a: nil agent card")
	}
	parts := strings.Split(rawJWS, ".")
	if len(parts) != 3 {
		return errors.New("a2a: invalid jws compact serialization format")
	}
	return v.verifyDetachedJWS(card, parts[0], parts[1], parts[2])
}

// VerifyCardSignatures validates embedded AgentCardSignature entries on card per A2A v1.0 Section 8.4.
func (v *UpstreamCardVerifier) VerifyCardSignatures(card *a2aspec.AgentCard) error {
	if card == nil {
		return errors.New("a2a: nil agent card")
	}
	if card.Signatures == nil || len(*card.Signatures) == 0 {
		return errors.New("a2a: agent card contains no signatures")
	}
	var lastErr error
	for _, sig := range *card.Signatures {
		if sig.Protected == "" || sig.Signature == "" {
			lastErr = errors.New("a2a: signature missing required protected or signature field")
			continue
		}
		if err := v.verifyDetachedJWS(card, sig.Protected, "", sig.Signature); err == nil {
			return nil
		} else {
			lastErr = err
		}
	}
	return lastErr
}

// FetchAndVerifyCard fetches an upstream AgentCard JSON document, validates it against the OpenAPI schema,
// and optionally verifies its JWS signatures if a JWKS URL is provided (or configured for agentSlug).
func (v *UpstreamCardVerifier) FetchAndVerifyCard(ctx context.Context, agentSlug, cardURL, jwksURL string) (*a2aspec.AgentCard, error) {
	if strings.TrimSpace(cardURL) == "" {
		return nil, errors.New("a2a: agent_card_url is empty")
	}
	cleanCardURL, err := ValidateAndSanitizeCardURL(cardURL, v.netPolicy)
	if err != nil {
		return nil, fmt.Errorf("a2a: invalid agent_card_url: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, cleanCardURL, nil)
	if err != nil {
		return nil, fmt.Errorf("a2a: build card request: %w", err)
	}
	req.Header.Set("Accept", MediaTypeA2AJSON+", "+MediaTypeJSON)
	resp, err := v.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("a2a: fetch agent card: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("a2a: agent_card_url returned HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024))
	if err != nil {
		return nil, fmt.Errorf("a2a: read agent card body: %w", err)
	}
	card, err := a2aspec.DecodeStrict[a2aspec.AgentCard]("AgentCard", body)
	if err != nil {
		return nil, fmt.Errorf("a2a: upstream agent card failed schema validation: %w", err)
	}

	effectiveJWKS := strings.TrimSpace(jwksURL)
	if effectiveJWKS == "" && agentSlug != "" {
		v.mu.RLock()
		effectiveJWKS = v.trustedCardJWKS[agentSlug]
		v.mu.RUnlock()
	}
	if effectiveJWKS != "" {
		if err := v.LoadJWKS(ctx, effectiveJWKS); err != nil {
			return nil, fmt.Errorf("a2a: load trusted JWKS %q: %w", effectiveJWKS, err)
		}
		if err := v.VerifyCardSignatures(card); err != nil {
			return nil, fmt.Errorf("a2a: verify upstream agent card signatures: %w", err)
		}
	}
	return card, nil
}

// LoadJWKS fetches an RFC 7517 JWK Set from jwksURL and registers supported EC/RSA/OKP verification keys.
func (v *UpstreamCardVerifier) LoadJWKS(ctx context.Context, jwksURL string) error {
	cleanJWKSURL, err := ValidateAndSanitizeCardURL(jwksURL, v.netPolicy)
	if err != nil {
		return fmt.Errorf("a2a: invalid jwks_url: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, cleanJWKSURL, nil)
	if err != nil {
		return err
	}
	resp, err := v.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("jwks endpoint returned HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	if err != nil {
		return err
	}
	var set struct {
		Keys []struct {
			Kid string `json:"kid"`
			Kty string `json:"kty"`
			Crv string `json:"crv"`
			X   string `json:"x"`
			Y   string `json:"y"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(body, &set); err != nil {
		return fmt.Errorf("parse jwks: %w", err)
	}
	for _, k := range set.Keys {
		if k.Kid == "" {
			continue
		}
		switch k.Kty {
		case "EC":
			if k.Crv != "P-256" {
				continue
			}
			xb, err1 := base64.RawURLEncoding.DecodeString(k.X)
			yb, err2 := base64.RawURLEncoding.DecodeString(k.Y)
			if err1 != nil || err2 != nil {
				continue
			}
			v.AddTrustedKey(k.Kid, &ecdsa.PublicKey{
				Curve: elliptic.P256(),
				X:     new(big.Int).SetBytes(xb),
				Y:     new(big.Int).SetBytes(yb),
			})
		case "RSA":
			nb, err1 := base64.RawURLEncoding.DecodeString(k.N)
			eb, err2 := base64.RawURLEncoding.DecodeString(k.E)
			if err1 != nil || err2 != nil || len(nb) == 0 {
				continue
			}
			exp := int(new(big.Int).SetBytes(eb).Int64())
			if exp <= 1 {
				continue
			}
			v.AddTrustedKey(k.Kid, &rsa.PublicKey{
				N: new(big.Int).SetBytes(nb),
				E: exp,
			})
		case "OKP":
			if k.Crv != "Ed25519" {
				continue
			}
			xb, err := base64.RawURLEncoding.DecodeString(k.X)
			if err == nil && len(xb) == ed25519.PublicKeySize {
				v.AddTrustedKey(k.Kid, ed25519.PublicKey(xb))
			}
		}
	}
	v.mu.Lock()
	v.lastJWKSURL = jwksURL
	if v.jwksLastRefresh == nil {
		v.jwksLastRefresh = make(map[string]time.Time)
	}
	v.jwksLastRefresh[jwksURL] = time.Now().UTC()
	v.mu.Unlock()
	return nil
}

func (v *UpstreamCardVerifier) tryAutoRefreshJWKS() {
	v.mu.Lock()
	now := time.Now().UTC()
	cooldown := v.refreshCooldown
	if cooldown < 0 {
		cooldown = 1 * time.Minute
	}
	if v.jwksLastRefresh == nil {
		v.jwksLastRefresh = make(map[string]time.Time)
	}

	candidates := make([]string, 0, len(v.trustedCardJWKS)+1)
	seen := make(map[string]bool)
	addCandidate := func(u string) {
		u = strings.TrimSpace(u)
		if u == "" || seen[u] {
			return
		}
		seen[u] = true
		if last, ok := v.jwksLastRefresh[u]; ok && cooldown > 0 && now.Sub(last) < cooldown {
			return
		}
		v.jwksLastRefresh[u] = now
		candidates = append(candidates, u)
	}
	if v.lastJWKSURL != "" {
		addCandidate(v.lastJWKSURL)
	}
	for _, u := range v.trustedCardJWKS {
		addCandidate(u)
	}
	v.mu.Unlock()

	for _, u := range candidates {
		rCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_ = v.LoadJWKS(rCtx, u)
		cancel()
	}
}

func (v *UpstreamCardVerifier) isAlgAllowed(alg string) bool {
	if len(v.allowedAlgs) == 0 {
		return alg == "ES256" || alg == "RS256" || alg == "EdDSA"
	}
	for _, allowed := range v.allowedAlgs {
		if strings.EqualFold(strings.TrimSpace(allowed), alg) {
			return true
		}
	}
	return false
}

func (v *UpstreamCardVerifier) verifyDetachedJWS(card *a2aspec.AgentCard, headerB64, explicitPayloadB64, sigB64 string) error {
	headerBytes, err := base64.RawURLEncoding.DecodeString(headerB64)
	if err != nil {
		return fmt.Errorf("a2a: decode jws header: %w", err)
	}
	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return fmt.Errorf("a2a: parse jws header: %w", err)
	}
	if header.Kid == "" {
		return errors.New("a2a: jws header missing mandatory kid")
	}
	if !v.isAlgAllowed(header.Alg) {
		return fmt.Errorf("a2a: signature algorithm %q is not permitted by policy", header.Alg)
	}

	v.mu.RLock()
	pubKey, ok := v.trustedPublicKeys[header.Kid]
	v.mu.RUnlock()
	if !ok || pubKey == nil {
		v.tryAutoRefreshJWKS()
		v.mu.RLock()
		pubKey, ok = v.trustedPublicKeys[header.Kid]
		v.mu.RUnlock()
	}
	if !ok || pubKey == nil {
		return fmt.Errorf("a2a: untrusted signing key id %q", header.Kid)
	}

	cardJSON, err := json.Marshal(card)
	if err != nil {
		return fmt.Errorf("a2a: marshal agent card: %w", err)
	}
	var cardMap map[string]any
	if err := json.Unmarshal(cardJSON, &cardMap); err != nil {
		return fmt.Errorf("a2a: decode agent card map: %w", err)
	}
	delete(cardMap, "signatures")

	canonicalCard, err := CanonicalizeJCS(cardMap)
	if err != nil {
		return fmt.Errorf("a2a: canonicalize card: %w", err)
	}

	expectedPayloadB64 := base64.RawURLEncoding.EncodeToString(canonicalCard)
	if explicitPayloadB64 != "" && explicitPayloadB64 != expectedPayloadB64 {
		return errors.New("a2a: jws payload does not match canonical agent card")
	}

	sigInput := headerB64 + "." + expectedPayloadB64
	sigBytes, err := base64.RawURLEncoding.DecodeString(sigB64)
	if err != nil {
		return fmt.Errorf("a2a: decode signature: %w", err)
	}

	h := sha256.Sum256([]byte(sigInput))

	switch header.Alg {
	case "ES256":
		ecKey, ok := pubKey.(*ecdsa.PublicKey)
		if !ok {
			return errors.New("a2a: key type mismatch for ES256")
		}
		// Support both RFC 7515 Section 3.4 64-byte raw (R || S) and ASN.1 DER signatures.
		valid := false
		if len(sigBytes) == 64 {
			r := new(big.Int).SetBytes(sigBytes[:32])
			s := new(big.Int).SetBytes(sigBytes[32:])
			valid = ecdsa.Verify(ecKey, h[:], r, s)
		}
		if !valid && !ecdsa.VerifyASN1(ecKey, h[:], sigBytes) {
			return errors.New("a2a: ES256 signature verification failed")
		}
	case "RS256":
		rsaKey, ok := pubKey.(*rsa.PublicKey)
		if !ok {
			return errors.New("a2a: key type mismatch for RS256")
		}
		// Fix H8: pass crypto.SHA256 so PKCS#1 v1.5 DigestInfo ASN.1 prefix matches standard RS256 signatures.
		if err := rsa.VerifyPKCS1v15(rsaKey, crypto.SHA256, h[:], sigBytes); err != nil {
			return fmt.Errorf("a2a: RS256 signature verification failed: %w", err)
		}
	case "EdDSA":
		edKey, ok := pubKey.(ed25519.PublicKey)
		if !ok {
			return errors.New("a2a: key type mismatch for EdDSA")
		}
		if !ed25519.Verify(edKey, []byte(sigInput), sigBytes) {
			return errors.New("a2a: EdDSA signature verification failed")
		}
	default:
		return fmt.Errorf("a2a: unsupported signature algorithm %q", header.Alg)
	}
	return nil
}

// GatewayCardSigner signs rewritten AgentCards using deterministic Vault-derived or injected Gateway keys.
type GatewayCardSigner struct {
	mu         sync.Mutex
	keyID      string
	alg        string
	privateKey any // *ecdsa.PrivateKey, *rsa.PrivateKey, or ed25519.PrivateKey
	vault      *auth.Vault
}

// NewGatewayCardSigner initializes a thread-safe GatewayCardSigner.
func NewGatewayCardSigner(keyID, alg string, privKey any, vault *auth.Vault) *GatewayCardSigner {
	if keyID == "" {
		keyID = "gw-a2a-v1"
	}
	if alg == "" {
		alg = "ES256"
	}
	return &GatewayCardSigner{
		keyID:      keyID,
		alg:        alg,
		privateKey: privKey,
		vault:      vault,
	}
}

// PublicKey returns the active verification public key (initializing from Vault or generating if needed).
func (s *GatewayCardSigner) PublicKey() (any, error) {
	key, err := s.ensureSigningKey()
	if err != nil {
		return nil, err
	}
	switch k := key.(type) {
	case *ecdsa.PrivateKey:
		return &k.PublicKey, nil
	case *rsa.PrivateKey:
		return &k.PublicKey, nil
	case ed25519.PrivateKey:
		return k.Public(), nil
	default:
		return nil, errors.New("a2a: unsupported private key type")
	}
}

// KeyID returns the configured JWS signing key ID (`kid`).
func (s *GatewayCardSigner) KeyID() string {
	return s.keyID
}

// RewriteAndSignAgentCard strips upstream signatures, rewrites HTTP/JSON-RPC interface URLs
// to the gateway namespace (preserving GRPC interfaces), canonicalizes via RFC 8785 JCS,
// and populates a compliant AgentCardSignature (including the REQUIRED `protected` field).
func (s *GatewayCardSigner) RewriteAndSignAgentCard(
	card *a2aspec.AgentCard,
	gatewayBaseURL string,
	agentSlug string,
) (*a2aspec.AgentCard, string, error) {
	if card == nil {
		return nil, "", errors.New("a2a: nil agent card")
	}

	raw, err := json.Marshal(card)
	if err != nil {
		return nil, "", err
	}
	var cloned a2aspec.AgentCard
	if err := json.Unmarshal(raw, &cloned); err != nil {
		return nil, "", err
	}
	cloned.Signatures = nil

	if agentSlug != "" {
		namespacedBase := fmt.Sprintf("%s/a2a/v1/agents/%s", strings.TrimRight(gatewayBaseURL, "/"), agentSlug)
		if len(cloned.SupportedInterfaces) == 0 {
			cloned.SupportedInterfaces = []a2aspec.AgentInterface{
				{
					ProtocolBinding: domain.A2AProtocolBindingHTTPJSON,
					ProtocolVersion: a2aspec.SupportedA2AVersion,
					Url:             namespacedBase,
				},
			}
		} else {
			for i := range cloned.SupportedInterfaces {
				iface := &cloned.SupportedInterfaces[i]
				if strings.EqualFold(iface.ProtocolBinding, domain.A2AProtocolBindingGRPC) {
					continue // Preserve native gRPC authority host:port
				}
				iface.Url = namespacedBase
				if iface.ProtocolVersion == "" {
					iface.ProtocolVersion = a2aspec.SupportedA2AVersion
				}
			}
		}
	}

	cardBytes, err := json.Marshal(&cloned)
	if err != nil {
		return nil, "", err
	}
	var cardMap map[string]any
	if err := json.Unmarshal(cardBytes, &cardMap); err != nil {
		return nil, "", err
	}
	delete(cardMap, "signatures")

	canonicalBytes, err := CanonicalizeJCS(cardMap)
	if err != nil {
		return nil, "", fmt.Errorf("a2a: canonicalize rewritten card: %w", err)
	}

	headerMap := map[string]string{
		"alg": s.alg,
		"kid": s.keyID,
		"typ": "JWS",
	}
	headerJSON, _ := json.Marshal(headerMap)
	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	payloadB64 := base64.RawURLEncoding.EncodeToString(canonicalBytes)
	sigInput := headerB64 + "." + payloadB64

	sigBytes, err := s.signDigest(sigInput)
	if err != nil {
		return nil, "", fmt.Errorf("a2a: sign card: %w", err)
	}
	sigB64 := base64.RawURLEncoding.EncodeToString(sigBytes)
	jwsCompact := headerB64 + "." + payloadB64 + "." + sigB64

	metaHeader := a2aspec.Metadata{
		"alg": s.alg,
		"kid": s.keyID,
		"typ": "JWS",
	}
	cloned.Signatures = &[]a2aspec.AgentCardSignature{
		{
			Protected: headerB64,
			Signature: sigB64,
			Header:    &metaHeader,
		},
	}

	return &cloned, jwsCompact, nil
}

// MintVaultJWT mints a short-lived signed HS256/ES256 JWT assertion for upstream `vault_jwt` authentication.
func (s *GatewayCardSigner) MintVaultJWT(orgID, agentSlug string) (string, error) {
	now := time.Now().UTC()
	headerJSON, _ := json.Marshal(map[string]string{
		"alg": "HS256",
		"kid": s.keyID,
		"typ": "JWT",
	})
	claimsJSON, _ := json.Marshal(map[string]any{
		"iss":        "goroute-ai-gateway",
		"sub":        "goroute-a2a-proxy",
		"aud":        agentSlug,
		"org_id":     orgID,
		"agent_slug": agentSlug,
		"iat":        now.Unix(),
		"exp":        now.Add(5 * time.Minute).Unix(),
	})
	unsigned := base64.RawURLEncoding.EncodeToString(headerJSON) + "." + base64.RawURLEncoding.EncodeToString(claimsJSON)

	var secret []byte
	if s != nil && s.vault != nil {
		derived, err := s.vault.DeriveSubkey("a2a-upstream-jwt:" + s.keyID)
		if err == nil && len(derived) >= 32 {
			secret = derived
		}
	}
	if len(secret) == 0 {
		key, err := s.ensureSigningKey()
		if err != nil {
			return "", err
		}
		sum := sha256.Sum256([]byte(fmt.Sprintf("%T:%s", key, s.keyID)))
		secret = sum[:]
	}

	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(unsigned))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return unsigned + "." + sig, nil
}

func (s *GatewayCardSigner) ensureSigningKey() (any, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.privateKey != nil {
		return s.privateKey, nil
	}

	// Derive a stable ECDSA P-256 or Ed25519 key from Vault when available so multi-pod
	// deployments produce consistent signatures for gateway-hosted AgentCards.
	if s.vault != nil {
		if seed, err := s.vault.DeriveSubkey("a2a-card-signer:" + s.keyID); err == nil && len(seed) == 32 {
			switch s.alg {
			case "EdDSA":
				key := ed25519.NewKeyFromSeed(seed)
				s.privateKey = key
				return key, nil
			default:
				curve := elliptic.P256()
				n := curve.Params().N
				d := new(big.Int).SetBytes(seed)
				d.Mod(d, new(big.Int).Sub(n, big.NewInt(1)))
				d.Add(d, big.NewInt(1))
				x, y := curve.ScalarBaseMult(d.Bytes())
				key := &ecdsa.PrivateKey{
					PublicKey: ecdsa.PublicKey{Curve: curve, X: x, Y: y},
					D:         d,
				}
				s.alg = "ES256"
				s.privateKey = key
				return key, nil
			}
		}
	}

	if s.alg == "EdDSA" {
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		s.privateKey = priv
		return priv, nil
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	s.privateKey = key
	return key, nil
}

func (s *GatewayCardSigner) signDigest(sigInput string) ([]byte, error) {
	key, err := s.ensureSigningKey()
	if err != nil {
		return nil, err
	}
	h := sha256.Sum256([]byte(sigInput))

	switch k := key.(type) {
	case *ecdsa.PrivateKey:
		return ecdsa.SignASN1(rand.Reader, k, h[:])
	case *rsa.PrivateKey:
		return rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, h[:])
	case ed25519.PrivateKey:
		return ed25519.Sign(k, []byte(sigInput)), nil
	default:
		return nil, errors.New("a2a: unsupported private key type for signing")
	}
}

// ServeWellKnownAgentCard serves `GET /.well-known/agent-card.json` (and optional legacy discovery path).
// Enforces C2 tenant isolation:
//   - Authenticated callers are strictly scoped to idCtx.OrgID + RBAC AuthorizeA2AAgent.
//   - Unauthenticated callers can only discover agents with IsPublicCard == true.
//   - When no matching agent exists or none is selected, serves a JWS-signed Gateway Hub AgentCard.
func ServeWellKnownAgentCard(
	w http.ResponseWriter,
	r *http.Request,
	repo storage.Repository,
	signer *GatewayCardSigner,
	rbac *auth.RBACEngine,
	idCtx *domain.IdentityContext,
	gatewayBaseURL string,
	defaultAgentSlug string,
) {
	agentSlug := strings.TrimSpace(r.URL.Query().Get("agent"))
	if agentSlug == "" {
		agentSlug = strings.TrimSpace(r.URL.Query().Get("slug"))
	}
	if agentSlug == "" {
		agentSlug = defaultAgentSlug
	}

	var matchedAgent *domain.A2AAgent
	if idCtx != nil {
		// Authenticated discovery: strictly scoped to caller organization + RBAC.
		if agentSlug != "" {
			if rbac != nil {
				if err := rbac.AuthorizeA2AAgent(idCtx, agentSlug); err != nil {
					WriteHTTPError(w, ErrTaskNotFound(fmt.Sprintf("A2A agent %q not found", agentSlug), ""))
					return
				}
			}
			ag, err := repo.GetA2AAgentBySlug(r.Context(), idCtx.OrgID, agentSlug)
			if err != nil || ag == nil || !ag.IsActive {
				WriteHTTPError(w, ErrTaskNotFound(fmt.Sprintf("A2A agent %q not found", agentSlug), ""))
				return
			}
			matchedAgent = ag
		} else {
			agents, _ := repo.ListA2AAgents(r.Context(), idCtx.OrgID)
			for _, ag := range agents {
				if ag == nil || !ag.IsActive {
					continue
				}
				if rbac == nil || rbac.AuthorizeA2AAgent(idCtx, ag.Slug) == nil {
					matchedAgent = ag
					break
				}
			}
		}
	} else {
		// Unauthenticated discovery: fail-closed to explicitly public cards only (`IsPublicCard == true`).
		agents, _ := repo.ListA2AAgents(r.Context(), "")
		for _, ag := range agents {
			if ag == nil || !ag.IsActive || !ag.IsPublicCard {
				continue
			}
			if agentSlug == "" || ag.Slug == agentSlug {
				matchedAgent = ag
				break
			}
		}
		if agentSlug != "" && matchedAgent == nil {
			WriteHTTPError(w, ErrTaskNotFound(fmt.Sprintf("A2A agent %q not found", agentSlug), ""))
			return
		}
	}

	if matchedAgent == nil {
		base := strings.TrimRight(gatewayBaseURL, "/")
		hubCard := &a2aspec.AgentCard{
			Name:        "GoRoute AI Gateway Agent Service",
			Description: "Enterprise Linux Foundation A2A v1.0 Gateway Hub",
			Version:     "1.0.0",
			Capabilities: a2aspec.AgentCapabilities{
				Streaming:         ptrBool(true),
				PushNotifications: ptrBool(true),
				ExtendedAgentCard: ptrBool(true),
			},
			DefaultInputModes:  []string{"text/plain", "application/json"},
			DefaultOutputModes: []string{"text/plain", "application/json"},
			Skills:             []a2aspec.AgentSkill{},
			SupportedInterfaces: []a2aspec.AgentInterface{
				{
					ProtocolBinding: domain.A2AProtocolBindingHTTPJSON,
					ProtocolVersion: a2aspec.SupportedA2AVersion,
					Url:             base + "/a2a/v1/agents/{agentSlug}",
				},
				{
					ProtocolBinding: domain.A2AProtocolBindingJSONRPC,
					ProtocolVersion: a2aspec.SupportedA2AVersion,
					Url:             base + "/a2a/v1/agents/{agentSlug}",
				},
			},
		}
		signedHub, _, err := signer.RewriteAndSignAgentCard(hubCard, gatewayBaseURL, "")
		if err != nil {
			WriteHTTPError(w, ErrInternal(fmt.Sprintf("failed to sign gateway agent card: %v", err)))
			return
		}
		_ = WriteJSONResponse(w, r, http.StatusOK, signedHub)
		return
	}

	card := decodeAgentCardOrDefault(matchedAgent)
	signedCard, _, err := signer.RewriteAndSignAgentCard(card, gatewayBaseURL, matchedAgent.Slug)
	if err != nil {
		WriteHTTPError(w, ErrInternal(fmt.Sprintf("failed to sign agent card: %v", err)))
		return
	}
	_ = WriteJSONResponse(w, r, http.StatusOK, signedCard)
}

func decodeAgentCardOrDefault(agent *domain.A2AAgent) *a2aspec.AgentCard {
	if agent != nil && strings.TrimSpace(agent.AgentCardJSON) != "" {
		var card a2aspec.AgentCard
		if err := json.Unmarshal([]byte(agent.AgentCardJSON), &card); err == nil {
			if card.DefaultInputModes == nil {
				card.DefaultInputModes = []string{"text/plain"}
			}
			if card.DefaultOutputModes == nil {
				card.DefaultOutputModes = []string{"text/plain"}
			}
			if card.Skills == nil {
				card.Skills = []a2aspec.AgentSkill{}
			}
			return &card
		}
	}
	name := "A2A Agent"
	if agent != nil && agent.Name != "" {
		name = agent.Name
	}
	return &a2aspec.AgentCard{
		Name:        name,
		Description: "A2A v1.0 Agent managed by GoRoute AI Gateway",
		Version:     "1.0.0",
		Capabilities: a2aspec.AgentCapabilities{
			Streaming:         ptrBool(true),
			PushNotifications: ptrBool(true),
		},
		DefaultInputModes:  []string{"text/plain"},
		DefaultOutputModes: []string{"text/plain"},
		Skills:             []a2aspec.AgentSkill{},
	}
}

func ptrBool(v bool) *bool { return &v }
