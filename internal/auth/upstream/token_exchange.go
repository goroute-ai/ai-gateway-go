package upstream

import (
	"context"
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

// OAuth 2.0 Token Exchange (RFC 8693) grant and token-type URNs.
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
	TokenCache       *DistributedTokenCache
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

	mu         sync.RWMutex
	tokenCache *DistributedTokenCache
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

	cache := cfg.TokenCache
	if cache == nil {
		cache = NewDistributedTokenCache(nil, DistributedTokenCacheConfig{})
	}

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
		tokenCache:       cache,
	}, nil
}

// SetTokenCache configures the DistributedTokenCache used by this strategy.
func (s *TokenExchangeStrategy) SetTokenCache(cache *DistributedTokenCache) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokenCache = cache
}

func (s *TokenExchangeStrategy) getOrInitTokenCache() *DistributedTokenCache {
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

	cacheKey := tokenCacheKey(authCtx, "rfc8693", s.tokenEndpoint, s.clientID, s.clientSecret,
		subjectToken, s.subjectTokenType, s.resource, s.audience, s.scope)

	accessToken, err := s.getOrInitTokenCache().GetOrRefresh(ctx, cacheKey, func(refreshCtx context.Context) (string, time.Duration, error) {
		// Perform RFC 8693 Token Exchange POST
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
		if s.clientID != "" && s.clientSecret == "" {
			form.Set("client_id", s.clientID)
		}

		httpReq, err := http.NewRequestWithContext(refreshCtx, http.MethodPost, s.tokenEndpoint, strings.NewReader(form.Encode()))
		if err != nil {
			return "", 0, fmt.Errorf("token_exchange: create request: %w", err)
		}
		httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		httpReq.Header.Set("Accept", "application/json")

		if s.clientID != "" && s.clientSecret != "" {
			httpReq.SetBasicAuth(s.clientID, s.clientSecret)
		}

		resp, err := s.httpClient.Do(httpReq)
		if err != nil {
			return "", 0, fmt.Errorf("token_exchange: post to token endpoint: %w", err)
		}
		defer resp.Body.Close()

		bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
		if err != nil {
			return "", 0, fmt.Errorf("token_exchange: read response: %w", err)
		}

		if resp.StatusCode != http.StatusOK {
			return "", 0, fmt.Errorf("token_exchange: endpoint returned HTTP %d: %s", resp.StatusCode, string(bodyBytes))
		}

		var exResp tokenExchangeResponse
		if err := json.Unmarshal(bodyBytes, &exResp); err != nil {
			return "", 0, fmt.Errorf("token_exchange: decode json response: %w", err)
		}

		if exResp.AccessToken == "" {
			return "", 0, fmt.Errorf("token_exchange: missing access_token in response: %s", string(bodyBytes))
		}

		ttl := 3600 * time.Second
		if exResp.ExpiresIn > 0 {
			ttl = time.Duration(exResp.ExpiresIn) * time.Second
		}
		return exResp.AccessToken, ttl, nil
	})
	if err != nil {
		return err
	}

	req.Header.Set(s.headerName, "Bearer "+accessToken)
	return nil
}
