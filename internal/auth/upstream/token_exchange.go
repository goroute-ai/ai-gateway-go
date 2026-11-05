package upstream

import (
	"context"
	"crypto/sha256"
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

	"github.com/goroute-ai/ai-gateway-go/internal/security/network"
)

const (
	GrantTypeTokenExchange = "urn:ietf:params:oauth:grant-type:token-exchange"
	TokenTypeAccessToken   = "urn:ietf:params:oauth:token-type:access_token"
	TokenTypeIDToken       = "urn:ietf:params:oauth:token-type:id_token"
	TokenTypeJWT           = "urn:ietf:params:oauth:token-type:jwt"
)

// TokenExchangeConfig configures an RFC 8693 Token Exchange strategy.
type TokenExchangeConfig struct {
	TokenEndpoint    string
	ClientID         string
	ClientSecret     string
	Resource         string // RFC 8707 target resource URI
	Audience         string
	Scope            string
	SubjectTokenType string
	HeaderName       string
	NetPolicy        *network.Policy
}

type cachedExchangedToken struct {
	accessToken string
	expiresAt   time.Time
}

// TokenExchangeStrategy implements RFC 8693 On-Behalf-Of (OBO) token exchange.
type TokenExchangeStrategy struct {
	tokenEndpoint    string
	clientID         string
	clientSecret     string
	resource         string
	audience         string
	scope            string
	subjectTokenType string
	headerName       string
	httpClient       *http.Client

	mu    sync.RWMutex
	cache map[string]cachedExchangedToken
}

// NewTokenExchangeStrategy creates a new TokenExchangeStrategy.
func NewTokenExchangeStrategy(cfg TokenExchangeConfig) (*TokenExchangeStrategy, error) {
	if strings.TrimSpace(cfg.TokenEndpoint) == "" {
		return nil, errors.New("token_exchange: token_endpoint is required")
	}

	subType := cfg.SubjectTokenType
	if subType == "" {
		subType = TokenTypeAccessToken
	}

	headerName := cfg.HeaderName
	if headerName == "" {
		headerName = "Authorization"
	}

	if cfg.Resource != "" {
		if err := ValidateRFC8707ResourceURI(cfg.Resource); err != nil {
			return nil, err
		}
	}

	client := network.NewHTTPClient(cfg.NetPolicy)
	client.Timeout = 15 * time.Second

	return &TokenExchangeStrategy{
		tokenEndpoint:    cfg.TokenEndpoint,
		clientID:         cfg.ClientID,
		clientSecret:     cfg.ClientSecret,
		resource:         cfg.Resource,
		audience:         cfg.Audience,
		scope:            cfg.Scope,
		subjectTokenType: subType,
		headerName:       headerName,
		httpClient:       client,
		cache:            make(map[string]cachedExchangedToken),
	}, nil
}

func (s *TokenExchangeStrategy) Type() string {
	return "rfc8693_token_exchange"
}

type tokenExchangeResponse struct {
	AccessToken     string `json:"access_token"`
	IssuedTokenType string `json:"issued_token_type"`
	TokenType       string `json:"token_type"`
	ExpiresIn       int64  `json:"expires_in"`
	Error           string `json:"error,omitempty"`
	ErrorDesc       string `json:"error_description,omitempty"`
}

func (s *TokenExchangeStrategy) Apply(ctx context.Context, req *http.Request, authCtx *UpstreamAuthContext) error {
	if req == nil {
		return errors.New("token_exchange: nil request")
	}
	if authCtx == nil || strings.TrimSpace(authCtx.DelegatedToken) == "" {
		return errors.New("token_exchange: delegated subject token is missing in caller context")
	}

	subjectToken := strings.TrimSpace(authCtx.DelegatedToken)

	// Compute deterministic cache key
	cacheKeyHash := sha256.Sum256([]byte(fmt.Sprintf("%s|%s|%s|%s", subjectToken, s.resource, s.audience, s.scope)))
	cacheKey := hex.EncodeToString(cacheKeyHash[:])

	// 1. Check cached exchange token
	s.mu.RLock()
	cached, found := s.cache[cacheKey]
	s.mu.RUnlock()

	if found && time.Now().Before(cached.expiresAt) {
		req.Header.Set(s.headerName, "Bearer "+cached.accessToken)
		return nil
	}

	// 2. Perform RFC 8693 Token Exchange POST
	form := url.Values{}
	form.Set("grant_type", GrantTypeTokenExchange)
	form.Set("subject_token", subjectToken)
	form.Set("subject_token_type", s.subjectTokenType)

	if s.resource != "" {
		form.Set("resource", s.resource)
	}
	if s.audience != "" {
		form.Set("audience", s.audience)
	}
	if s.scope != "" {
		form.Set("scope", s.scope)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, s.tokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return fmt.Errorf("token_exchange: create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	httpReq.Header.Set("Accept", "application/json")

	if s.clientID != "" && s.clientSecret != "" {
		httpReq.SetBasicAuth(s.clientID, s.clientSecret)
	} else if s.clientID != "" {
		form.Set("client_id", s.clientID)
	}

	resp, err := s.httpClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("token_exchange: post to token endpoint: %w", err)
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return fmt.Errorf("token_exchange: read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("token_exchange: endpoint returned HTTP %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var exResp tokenExchangeResponse
	if err := json.Unmarshal(bodyBytes, &exResp); err != nil {
		return fmt.Errorf("token_exchange: decode json response: %w", err)
	}

	if exResp.AccessToken == "" {
		return fmt.Errorf("token_exchange: missing access_token in response: %s", string(bodyBytes))
	}

	// Cache with TTL
	ttl := 3600 * time.Second
	if exResp.ExpiresIn > 0 {
		ttl = time.Duration(exResp.ExpiresIn) * time.Second
	}
	// Buffer 30 seconds before expiration
	if ttl > 45*time.Second {
		ttl -= 30 * time.Second
	}

	s.mu.Lock()
	s.cache[cacheKey] = cachedExchangedToken{
		accessToken: exResp.AccessToken,
		expiresAt:   time.Now().Add(ttl),
	}
	s.mu.Unlock()

	req.Header.Set(s.headerName, "Bearer "+exResp.AccessToken)
	return nil
}
