package upstream

import (
	"context"
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

// OAuth2Strategy handles M2M OAuth 2.0 Client Credentials Grant with thread-safe token caching.
type OAuth2Strategy struct {
	TokenEndpoint string   `json:"token_endpoint"`
	ClientID      string   `json:"client_id"`
	ClientSecret  string   `json:"-"` // Redacted from logs
	Scopes        []string `json:"scopes,omitempty"`
	HeaderName    string   `json:"header_name,omitempty"`

	httpClient *http.Client
	mu         sync.RWMutex
	tokenCache *DistributedTokenCache
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int64  `json:"expires_in"`
}

// NewOAuth2Strategy creates a new OAuth2Strategy with security policy applied to the token endpoint.
func NewOAuth2Strategy(endpoint, clientID, clientSecret string, scopes []string, netPolicy *network.Policy) *OAuth2Strategy {
	return NewOAuth2StrategyWithCache(endpoint, clientID, clientSecret, scopes, netPolicy, nil)
}

// NewOAuth2StrategyWithCache creates a new OAuth2Strategy backed by an optional DistributedTokenCache.
func NewOAuth2StrategyWithCache(endpoint, clientID, clientSecret string, scopes []string, netPolicy *network.Policy, cache *DistributedTokenCache) *OAuth2Strategy {
	client := network.NewHTTPClient(netPolicy)
	if cache == nil {
		cache = NewDistributedTokenCache(nil, DistributedTokenCacheConfig{})
	}
	return &OAuth2Strategy{
		TokenEndpoint: endpoint,
		ClientID:      clientID,
		ClientSecret:  clientSecret,
		Scopes:        scopes,
		HeaderName:    "Authorization",
		httpClient:    client,
		tokenCache:    cache,
	}
}

// SetTokenCache configures the DistributedTokenCache used by this strategy.
func (s *OAuth2Strategy) SetTokenCache(cache *DistributedTokenCache) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokenCache = cache
}

func (s *OAuth2Strategy) getOrInitTokenCache() *DistributedTokenCache {
	s.mu.RLock()
	cache := s.tokenCache
	s.mu.RUnlock()
	if cache != nil {
		return cache
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.tokenCache == nil {
		s.tokenCache = NewDistributedTokenCache(nil, DistributedTokenCacheConfig{})
	}
	return s.tokenCache
}

func (s *OAuth2Strategy) Type() string {
	return "oauth2_client_credentials"
}

func (s *OAuth2Strategy) Apply(ctx context.Context, req *http.Request, authCtx *UpstreamAuthContext) error {
	token, err := s.getToken(ctx)
	if err != nil {
		return fmt.Errorf("oauth2 client credentials: %w", err)
	}

	headerName := s.HeaderName
	if headerName == "" {
		headerName = "Authorization"
	}

	val := token
	if strings.EqualFold(headerName, "Authorization") && !strings.HasPrefix(strings.ToLower(val), "bearer ") {
		val = "Bearer " + val
	}
	req.Header.Set(headerName, val)
	return nil
}

func (s *OAuth2Strategy) getToken(ctx context.Context) (string, error) {
	cacheKey := fmt.Sprintf("oauth2|%s|%s|%s", s.TokenEndpoint, s.ClientID, strings.Join(s.Scopes, " "))
	return s.getOrInitTokenCache().GetOrRefresh(ctx, cacheKey, func(refreshCtx context.Context) (string, time.Duration, error) {
		form := url.Values{
			"grant_type":    {"client_credentials"},
			"client_id":     {s.ClientID},
			"client_secret": {s.ClientSecret},
		}
		if len(s.Scopes) > 0 {
			form.Set("scope", strings.Join(s.Scopes, " "))
		}

		req, err := http.NewRequestWithContext(refreshCtx, http.MethodPost, s.TokenEndpoint, strings.NewReader(form.Encode()))
		if err != nil {
			return "", 0, fmt.Errorf("create token request: %w", err)
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		client := s.httpClient
		if client == nil {
			client = network.NewHTTPClient(nil)
		}
		resp, err := client.Do(req)
		if err != nil {
			return "", 0, fmt.Errorf("execute token request: %w", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
			return "", 0, fmt.Errorf("token endpoint returned HTTP %d: %s", resp.StatusCode, string(body))
		}

		var tr tokenResponse
		if err := json.NewDecoder(resp.Body).Decode(&tr); err != nil {
			return "", 0, fmt.Errorf("decode token response: %w", err)
		}
		if tr.AccessToken == "" {
			return "", 0, fmt.Errorf("empty access_token received from token endpoint")
		}

		ttl := time.Duration(tr.ExpiresIn) * time.Second
		if ttl <= 0 {
			ttl = 1 * time.Hour
		}

		return tr.AccessToken, ttl, nil
	})
}
