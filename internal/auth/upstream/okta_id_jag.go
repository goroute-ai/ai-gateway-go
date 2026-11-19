package upstream

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
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
	TokenCache    *DistributedTokenCache
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

	mu         sync.RWMutex
	tokenCache *DistributedTokenCache
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

	cache := cfg.TokenCache
	if cache == nil {
		cache = NewDistributedTokenCache(nil, DistributedTokenCacheConfig{})
	}

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
		tokenCache:    cache,
	}, nil
}

// SetTokenCache configures the DistributedTokenCache used by this strategy.
func (s *OktaIDJAGStrategy) SetTokenCache(cache *DistributedTokenCache) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokenCache = cache
}

func (s *OktaIDJAGStrategy) getOrInitTokenCache() *DistributedTokenCache {
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

	cacheKey := tokenCacheKey(authCtx, "okta_id_jag", sub, s.tokenEndpoint, s.clientID,
		s.signingKey, s.audience, strings.Join(s.scopes, " "))

	accessToken, err := s.getOrInitTokenCache().GetOrRefresh(ctx, cacheKey, func(refreshCtx context.Context) (string, time.Duration, error) {
		// Mint Assertion JWT
		assertion, err := s.signAssertion(sub)
		if err != nil {
			return "", 0, fmt.Errorf("okta_id_jag: sign assertion: %w", err)
		}

		// Post to Token Endpoint
		form := url.Values{}
		form.Set("grant_type", GrantTypeJWTBearer)
		form.Set("assertion", assertion)
		if len(s.scopes) > 0 {
			form.Set("scope", strings.Join(s.scopes, " "))
		}

		httpReq, err := http.NewRequestWithContext(refreshCtx, http.MethodPost, s.tokenEndpoint, strings.NewReader(form.Encode()))
		if err != nil {
			return "", 0, fmt.Errorf("okta_id_jag: create request: %w", err)
		}
		httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		httpReq.Header.Set("Accept", "application/json")

		resp, err := s.httpClient.Do(httpReq)
		if err != nil {
			return "", 0, fmt.Errorf("okta_id_jag: post assertion: %w", err)
		}
		defer resp.Body.Close()

		bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
		if err != nil {
			return "", 0, fmt.Errorf("okta_id_jag: read response: %w", err)
		}

		if resp.StatusCode != http.StatusOK {
			return "", 0, fmt.Errorf("okta_id_jag: token endpoint returned HTTP %d: %s", resp.StatusCode, string(bodyBytes))
		}

		var tokResp tokenResponse
		if err := json.Unmarshal(bodyBytes, &tokResp); err != nil {
			return "", 0, fmt.Errorf("okta_id_jag: decode json: %w", err)
		}

		if tokResp.AccessToken == "" {
			return "", 0, fmt.Errorf("okta_id_jag: missing access_token in response: %s", string(bodyBytes))
		}

		ttl := 3600 * time.Second
		if tokResp.ExpiresIn > 0 {
			ttl = time.Duration(tokResp.ExpiresIn) * time.Second
		}
		return tokResp.AccessToken, ttl, nil
	})
	if err != nil {
		return err
	}

	req.Header.Set(s.headerName, "Bearer "+accessToken)
	return nil
}
