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
	token      string
	expiresAt  time.Time
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int64  `json:"expires_in"`
}

// NewOAuth2Strategy creates a new OAuth2Strategy with security policy applied to the token endpoint.
func NewOAuth2Strategy(endpoint, clientID, clientSecret string, scopes []string, netPolicy *network.Policy) *OAuth2Strategy {
	client := network.NewHTTPClient(netPolicy)
	return &OAuth2Strategy{
		TokenEndpoint: endpoint,
		ClientID:      clientID,
		ClientSecret:  clientSecret,
		Scopes:        scopes,
		HeaderName:    "Authorization",
		httpClient:    client,
	}
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
	s.mu.RLock()
	// Early refresh 30 seconds before expiration
	if s.token != "" && time.Now().UTC().Add(30*time.Second).Before(s.expiresAt) {
		token := s.token
		s.mu.RUnlock()
		return token, nil
	}
	s.mu.RUnlock()

	s.mu.Lock()
	defer s.mu.Unlock()

	// Double check after acquiring write lock
	if s.token != "" && time.Now().UTC().Add(30*time.Second).Before(s.expiresAt) {
		return s.token, nil
	}

	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {s.ClientID},
		"client_secret": {s.ClientSecret},
	}
	if len(s.Scopes) > 0 {
		form.Set("scope", strings.Join(s.Scopes, " "))
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("create token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("execute token request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return "", fmt.Errorf("token endpoint returned HTTP %d: %s", resp.StatusCode, string(body))
	}

	var tr tokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tr); err != nil {
		return "", fmt.Errorf("decode token response: %w", err)
	}
	if tr.AccessToken == "" {
		return "", fmt.Errorf("empty access_token received from token endpoint")
	}

	ttl := time.Duration(tr.ExpiresIn) * time.Second
	if ttl <= 0 {
		ttl = 1 * time.Hour
	}

	s.token = tr.AccessToken
	s.expiresAt = time.Now().UTC().Add(ttl)

	return s.token, nil
}
