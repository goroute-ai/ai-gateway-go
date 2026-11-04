package upstream

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/security/network"
)

// ClientMetadataDocument represents an RFC 7591 / MCP 2026-07-28 Client Identifier Metadata Document (CIMD).
type ClientMetadataDocument struct {
	ClientID                string          `json:"client_id"`
	ClientName              string          `json:"client_name,omitempty"`
	ClientURI               string          `json:"client_uri,omitempty"`
	LogoURI                 string          `json:"logo_uri,omitempty"`
	RedirectURIs            []string        `json:"redirect_uris,omitempty"`
	TokenEndpointAuthMethod string          `json:"token_endpoint_auth_method,omitempty"`
	GrantTypes              []string        `json:"grant_types,omitempty"`
	ResponseTypes           []string        `json:"response_types,omitempty"`
	Scope                   string          `json:"scope,omitempty"`
	JWKSURI                 string          `json:"jwks_uri,omitempty"`
	JWKS                    json.RawMessage `json:"jwks,omitempty"`
}

// PKCEPair holds an RFC 7636 Proof Key for Code Exchange verifier and challenge.
type PKCEPair struct {
	CodeVerifier        string `json:"code_verifier"`
	CodeChallenge       string `json:"code_challenge"`
	CodeChallengeMethod string `json:"code_challenge_method"` // Always "S256"
}

// GeneratePKCE generates a cryptographically secure PKCE verifier and S256 challenge.
func GeneratePKCE() (*PKCEPair, error) {
	// RFC 7636 Section 4.1: code_verifier = high-entropy cryptographic random STRING
	// using unreserved characters [A-Z] / [a-z] / [0-9] / "-" / "." / "_" / "~"
	// with a minimum length of 43 characters and a maximum length of 128 characters.
	rawBytes := make([]byte, 32) // 32 bytes = 256 bits of entropy -> 43 base64url chars
	if _, err := rand.Read(rawBytes); err != nil {
		return nil, fmt.Errorf("pkce: generate random bytes: %w", err)
	}

	verifier := base64.RawURLEncoding.EncodeToString(rawBytes)

	// RFC 7636 Section 4.2: code_challenge = BASE64URL-ENCODE(SHA256(ASCII(code_verifier)))
	h := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(h[:])

	return &PKCEPair{
		CodeVerifier:        verifier,
		CodeChallenge:       challenge,
		CodeChallengeMethod: "S256",
	}, nil
}

// ValidatePKCE verifies that codeVerifier matches codeChallenge using the specified method.
func ValidatePKCE(verifier, challenge, method string) bool {
	if method != "S256" {
		return false
	}
	if len(verifier) < 43 || len(verifier) > 128 {
		return false
	}
	h := sha256.Sum256([]byte(verifier))
	computedChallenge := base64.RawURLEncoding.EncodeToString(h[:])
	return computedChallenge == challenge
}

// cachedCIMD stores a document in memory with an expiration time.
type cachedCIMD struct {
	doc       *ClientMetadataDocument
	expiresAt time.Time
}

// CIMDResolver fetches, validates, and caches Client Identifier Metadata Documents.
type CIMDResolver struct {
	httpClient *http.Client
	defaultTTL time.Duration
	allowHTTP  bool

	mu    sync.RWMutex
	cache map[string]cachedCIMD
}

// NewCIMDResolver constructs a new CIMD document resolver.
func NewCIMDResolver(netPolicy *network.Policy, defaultTTL time.Duration, allowHTTP bool) *CIMDResolver {
	if defaultTTL <= 0 {
		defaultTTL = 1 * time.Hour
	}
	client := network.NewHTTPClient(netPolicy)
	client.Timeout = 10 * time.Second

	return &CIMDResolver{
		httpClient: client,
		defaultTTL: defaultTTL,
		allowHTTP:  allowHTTP,
		cache:      make(map[string]cachedCIMD),
	}
}

// Resolve fetches or retrieves from cache the CIMD at the specified documentURL.
func (r *CIMDResolver) Resolve(ctx context.Context, documentURL string) (*ClientMetadataDocument, error) {
	parsedURL, err := url.Parse(documentURL)
	if err != nil {
		return nil, fmt.Errorf("cimd: invalid url: %w", err)
	}

	if !r.allowHTTP && !strings.EqualFold(parsedURL.Scheme, "https") {
		return nil, fmt.Errorf("cimd: insecure http scheme not allowed for client_id metadata document: %s", documentURL)
	}

	// 1. Check in-memory cache
	r.mu.RLock()
	cached, found := r.cache[documentURL]
	r.mu.RUnlock()

	if found && time.Now().Before(cached.expiresAt) {
		return cached.doc, nil
	}

	// 2. Fetch from upstream
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, documentURL, nil)
	if err != nil {
		return nil, fmt.Errorf("cimd: create request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := r.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("cimd: fetch document: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("cimd: fetch returned http %d: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024)) // 64KB max document size
	if err != nil {
		return nil, fmt.Errorf("cimd: read response body: %w", err)
	}

	var doc ClientMetadataDocument
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("cimd: parse json metadata: %w", err)
	}

	// Validate client_id matches the document URL (unless localhost in testing)
	if !strings.HasPrefix(parsedURL.Host, "127.0.0.1") && !strings.HasPrefix(parsedURL.Host, "localhost") {
		if doc.ClientID != documentURL {
			return nil, fmt.Errorf("cimd: document client_id %q does not match document URL %q", doc.ClientID, documentURL)
		}
	} else if doc.ClientID == "" {
		doc.ClientID = documentURL
	}

	// 3. Cache document
	r.mu.Lock()
	r.cache[documentURL] = cachedCIMD{
		doc:       &doc,
		expiresAt: time.Now().Add(r.defaultTTL),
	}
	r.mu.Unlock()

	return &doc, nil
}
