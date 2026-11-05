package upstream

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
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

	"github.com/google/uuid"
	"github.com/goroute-ai/ai-gateway-go/internal/security/network"
)

const (
	GrantTypeJWTBearer = "urn:ietf:params:oauth:grant-type:jwt-bearer"
)

// OktaIDJAGConfig configures the Okta Identity Assertion JWT Authorization Grant strategy.
type OktaIDJAGConfig struct {
	TokenEndpoint string
	ClientID      string
	Audience      string
	Scopes        []string
	KeyID         string
	SigningKey    string
	CustomSigner  func(claims map[string]any) (string, error)
	HeaderName    string
	NetPolicy     *network.Policy
}

// OktaIDJAGStrategy implements Okta ID-JAG (Identity Assertion JWT Authorization Grant).
type OktaIDJAGStrategy struct {
	tokenEndpoint string
	clientID      string
	audience      string
	scopes        []string
	keyID         string
	signingKey    string
	customSigner  func(claims map[string]any) (string, error)
	headerName    string
	httpClient    *http.Client

	mu    sync.RWMutex
	cache map[string]cachedToken
}

type cachedToken struct {
	accessToken string
	expiresAt   time.Time
}

// NewOktaIDJAGStrategy constructs a new Okta ID-JAG strategy.
func NewOktaIDJAGStrategy(cfg OktaIDJAGConfig) (*OktaIDJAGStrategy, error) {
	if strings.TrimSpace(cfg.TokenEndpoint) == "" {
		return nil, errors.New("okta_id_jag: token_endpoint is required")
	}
	if strings.TrimSpace(cfg.ClientID) == "" {
		return nil, errors.New("okta_id_jag: client_id is required")
	}
	if strings.TrimSpace(cfg.Audience) == "" {
		return nil, errors.New("okta_id_jag: audience is required")
	}
	if cfg.CustomSigner == nil && strings.TrimSpace(cfg.SigningKey) == "" {
		return nil, errors.New("okta_id_jag: signing_key or custom_signer is required")
	}

	headerName := cfg.HeaderName
	if headerName == "" {
		headerName = "Authorization"
	}

	client := network.NewHTTPClient(cfg.NetPolicy)
	client.Timeout = 15 * time.Second

	return &OktaIDJAGStrategy{
		tokenEndpoint: cfg.TokenEndpoint,
		clientID:      cfg.ClientID,
		audience:      cfg.Audience,
		scopes:        cfg.Scopes,
		keyID:         cfg.KeyID,
		signingKey:    cfg.SigningKey,
		customSigner:  cfg.CustomSigner,
		headerName:    headerName,
		httpClient:    client,
		cache:         make(map[string]cachedToken),
	}, nil
}

func (s *OktaIDJAGStrategy) Type() string {
	return "okta_id_jag"
}

func (s *OktaIDJAGStrategy) signAssertion(sub string) (string, error) {
	now := time.Now().UTC()
	claims := map[string]any{
		"iss": s.clientID,
		"sub": sub,
		"aud": s.audience,
		"jti": uuid.NewString(),
		"iat": now.Unix(),
		"exp": now.Add(5 * time.Minute).Unix(),
	}

	if s.customSigner != nil {
		return s.customSigner(claims)
	}

	// Default HS256 signer
	header := map[string]string{
		"alg": "HS256",
		"typ": "JWT",
	}
	if s.keyID != "" {
		header["kid"] = s.keyID
	}

	hdrBytes, _ := json.Marshal(header)
	claimsBytes, _ := json.Marshal(claims)

	encodedHdr := base64.RawURLEncoding.EncodeToString(hdrBytes)
	encodedClaims := base64.RawURLEncoding.EncodeToString(claimsBytes)
	signingInput := encodedHdr + "." + encodedClaims

	mac := hmac.New(sha256.New, []byte(s.signingKey))
	mac.Write([]byte(signingInput))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	return signingInput + "." + sig, nil
}

func (s *OktaIDJAGStrategy) Apply(ctx context.Context, req *http.Request, authCtx *UpstreamAuthContext) error {
	if req == nil {
		return errors.New("okta_id_jag: nil request")
	}

	// Resolve subject from caller context
	sub := s.clientID
	if authCtx != nil {
		if authCtx.CallingUserID != "" {
			sub = authCtx.CallingUserID
		} else if authCtx.CallingVirtualKey != "" {
			sub = authCtx.CallingVirtualKey
		} else if authCtx.CallingOrgID != "" {
			sub = authCtx.CallingOrgID
		}
	}

	cacheKeyHash := sha256.Sum256([]byte(fmt.Sprintf("%s|%s|%s", sub, s.tokenEndpoint, strings.Join(s.scopes, " "))))
	cacheKey := hex.EncodeToString(cacheKeyHash[:])

	// 1. Check cached token
	s.mu.RLock()
	cached, found := s.cache[cacheKey]
	s.mu.RUnlock()

	if found && time.Now().Before(cached.expiresAt) {
		req.Header.Set(s.headerName, "Bearer "+cached.accessToken)
		return nil
	}

	// 2. Mint Assertion JWT
	assertion, err := s.signAssertion(sub)
	if err != nil {
		return fmt.Errorf("okta_id_jag: sign assertion: %w", err)
	}

	// 3. Post to Token Endpoint
	form := url.Values{}
	form.Set("grant_type", GrantTypeJWTBearer)
	form.Set("assertion", assertion)
	if len(s.scopes) > 0 {
		form.Set("scope", strings.Join(s.scopes, " "))
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, s.tokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return fmt.Errorf("okta_id_jag: create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	httpReq.Header.Set("Accept", "application/json")

	resp, err := s.httpClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("okta_id_jag: post assertion: %w", err)
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return fmt.Errorf("okta_id_jag: read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("okta_id_jag: token endpoint returned HTTP %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var tokResp tokenResponse
	if err := json.Unmarshal(bodyBytes, &tokResp); err != nil {
		return fmt.Errorf("okta_id_jag: decode json: %w", err)
	}

	if tokResp.AccessToken == "" {
		return fmt.Errorf("okta_id_jag: missing access_token in response: %s", string(bodyBytes))
	}

	ttl := 3600 * time.Second
	if tokResp.ExpiresIn > 0 {
		ttl = time.Duration(tokResp.ExpiresIn) * time.Second
	}
	if ttl > 45*time.Second {
		ttl -= 30 * time.Second
	}

	s.mu.Lock()
	s.cache[cacheKey] = cachedToken{
		accessToken: tokResp.AccessToken,
		expiresAt:   time.Now().Add(ttl),
	}
	s.mu.Unlock()

	req.Header.Set(s.headerName, "Bearer "+tokResp.AccessToken)
	return nil
}
