package azure

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/security/network"
	"golang.org/x/sync/singleflight"
)

const (
	defaultAzureCognitiveResource = "https://cognitiveservices.azure.com/"
	defaultAzureIMDSMSIURL        = "http://169.254.169.254/metadata/identity/oauth2/token"
	defaultMSITokenRefreshSkew    = 5 * time.Minute
	defaultMSIMaxRetries          = 3
	defaultMSIRetryBaseDelay      = 50 * time.Millisecond
)

// ErrAmbientIAMDisabled is returned when Azure Managed Identity resolution is attempted
// while AllowAmbientCloudIAM is false (the secure default).
var ErrAmbientIAMDisabled = errors.New("azure: ambient cloud IAM is disabled (allow_ambient_cloud_iam=false)")

// ManagedIdentityConfig configures opt-in Azure Managed Identity (IDENTITY_ENDPOINT / MSI / IMDS)
// token resolution with caching and bounded retries.
type ManagedIdentityConfig struct {
	AllowAmbientCloudIAM bool
	Resource             string
	ClientID             string
	IdentityEndpoint     string
	IdentityHeader       string
	SSRFPolicy           *network.Policy
	MaxRetries           int
	RetryBaseDelay       time.Duration
	Now                  func() time.Time
}

// ManagedIdentityTokenSource resolves and caches Entra ID access tokens from Azure Managed Identity.
type ManagedIdentityTokenSource struct {
	cfg        ManagedIdentityConfig
	maxRetries int
	baseDelay  time.Duration
	now        func() time.Time

	mu        sync.RWMutex
	cached    string
	refreshAt time.Time
	expiresAt time.Time
	sfGroup   singleflight.Group
}

// NewManagedIdentityTokenSource constructs a ManagedIdentityTokenSource.
func NewManagedIdentityTokenSource(cfg ManagedIdentityConfig) *ManagedIdentityTokenSource {
	maxRetries := cfg.MaxRetries
	if maxRetries <= 0 {
		maxRetries = defaultMSIMaxRetries
	}
	baseDelay := cfg.RetryBaseDelay
	if baseDelay <= 0 {
		baseDelay = defaultMSIRetryBaseDelay
	}
	nowFn := cfg.Now
	if nowFn == nil {
		nowFn = time.Now
	}
	return &ManagedIdentityTokenSource{
		cfg:        cfg,
		maxRetries: maxRetries,
		baseDelay:  baseDelay,
		now:        nowFn,
	}
}

// GetToken returns a cached or freshly acquired Azure Managed Identity Bearer token.
func (ts *ManagedIdentityTokenSource) GetToken(ctx context.Context) (string, error) {
	if !ts.cfg.AllowAmbientCloudIAM {
		return "", ErrAmbientIAMDisabled
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}

	now := ts.now().UTC()
	ts.mu.RLock()
	if ts.cached != "" && now.Before(ts.refreshAt) && now.Before(ts.expiresAt) {
		tok := ts.cached
		ts.mu.RUnlock()
		return tok, nil
	}
	ts.mu.RUnlock()

	ch := ts.sfGroup.DoChan("azure-msi-token", func() (any, error) {
		refreshCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 20*time.Second)
		defer cancel()
		return ts.refresh(refreshCtx)
	})

	select {
	case <-ctx.Done():
		return "", ctx.Err()
	case res := <-ch:
		if res.Err != nil {
			return "", res.Err
		}
		tok, _ := res.Val.(string)
		return tok, nil
	}
}

func (ts *ManagedIdentityTokenSource) refresh(ctx context.Context) (string, error) {
	now := ts.now().UTC()
	ts.mu.RLock()
	if ts.cached != "" && now.Before(ts.refreshAt) && now.Before(ts.expiresAt) {
		tok := ts.cached
		ts.mu.RUnlock()
		return tok, nil
	}
	ts.mu.RUnlock()

	client, err := network.NewAmbientIAMHTTPClient(ts.cfg.SSRFPolicy, ts.cfg.AllowAmbientCloudIAM)
	if err != nil {
		return "", err
	}

	reqURL, headers, err := ts.buildMSIRequestParams()
	if err != nil {
		return "", err
	}

	var lastErr error
	for attempt := 0; attempt < ts.maxRetries; attempt++ {
		if attempt > 0 {
			backoff := ts.baseDelay << (attempt - 1)
			timer := time.NewTimer(backoff)
			select {
			case <-ctx.Done():
				timer.Stop()
				return "", ctx.Err()
			case <-timer.C:
			}
		}

		tok, ttl, retryable, callErr := ts.doTokenRequest(ctx, client, reqURL, headers)
		if callErr == nil {
			now = ts.now().UTC()
			if ttl <= 0 {
				ttl = 1 * time.Hour
			}
			expiresAt := now.Add(ttl)
			skew := defaultMSITokenRefreshSkew
			if ttl <= skew*3/2 {
				skew = ttl / 4
			}
			refreshAt := expiresAt.Add(-skew)

			ts.mu.Lock()
			ts.cached = tok
			ts.expiresAt = expiresAt
			ts.refreshAt = refreshAt
			ts.mu.Unlock()
			return tok, nil
		}
		lastErr = callErr
		if !retryable {
			break
		}
	}

	return "", lastErr
}

func (ts *ManagedIdentityTokenSource) buildMSIRequestParams() (string, http.Header, error) {
	resource := strings.TrimSpace(ts.cfg.Resource)
	if resource == "" {
		resource = defaultAzureCognitiveResource
	}
	clientID := strings.TrimSpace(ts.cfg.ClientID)
	if clientID == "" {
		clientID = strings.TrimSpace(os.Getenv("AZURE_CLIENT_ID"))
	}

	headers := make(http.Header)

	// 1. Modern App Service / Functions / Container Apps: IDENTITY_ENDPOINT (+ IDENTITY_HEADER)
	idEndpoint := strings.TrimSpace(ts.cfg.IdentityEndpoint)
	idHeader := strings.TrimSpace(ts.cfg.IdentityHeader)
	if idEndpoint == "" {
		idEndpoint = strings.TrimSpace(os.Getenv("IDENTITY_ENDPOINT"))
		if idHeader == "" {
			idHeader = strings.TrimSpace(os.Getenv("IDENTITY_HEADER"))
		}
	}
	if idEndpoint != "" {
		u, err := url.Parse(idEndpoint)
		if err != nil {
			return "", nil, fmt.Errorf("azure msi: parse IDENTITY_ENDPOINT: %w", err)
		}
		q := u.Query()
		if q.Get("api-version") == "" {
			q.Set("api-version", "2019-08-01")
		}
		q.Set("resource", resource)
		if clientID != "" {
			q.Set("client_id", clientID)
		}
		u.RawQuery = q.Encode()
		if idHeader != "" {
			headers.Set("X-IDENTITY-HEADER", idHeader)
		}
		return u.String(), headers, nil
	}

	// 2. Legacy MSI_ENDPOINT (+ MSI_SECRET)
	if msiEndpoint := strings.TrimSpace(os.Getenv("MSI_ENDPOINT")); msiEndpoint != "" {
		u, err := url.Parse(msiEndpoint)
		if err != nil {
			return "", nil, fmt.Errorf("azure msi: parse MSI_ENDPOINT: %w", err)
		}
		q := u.Query()
		if q.Get("api-version") == "" {
			q.Set("api-version", "2017-09-01")
		}
		q.Set("resource", resource)
		if clientID != "" {
			q.Set("clientid", clientID)
		}
		u.RawQuery = q.Encode()
		if secret := strings.TrimSpace(os.Getenv("MSI_SECRET")); secret != "" {
			headers.Set("Secret", secret)
		}
		return u.String(), headers, nil
	}

	// 3. Azure VM / AKS IMDS endpoint
	u, _ := url.Parse(defaultAzureIMDSMSIURL)
	q := u.Query()
	q.Set("api-version", "2018-02-01")
	q.Set("resource", resource)
	if clientID != "" {
		q.Set("client_id", clientID)
	}
	u.RawQuery = q.Encode()
	headers.Set("Metadata", "true")
	return u.String(), headers, nil
}

type azureMSIResponse struct {
	AccessToken string          `json:"access_token"`
	ExpiresIn   json.RawMessage `json:"expires_in"`
	ExpiresOn   json.RawMessage `json:"expires_on"`
	TokenType   string          `json:"token_type"`
}

func (ts *ManagedIdentityTokenSource) doTokenRequest(ctx context.Context, client *http.Client, reqURL string, headers http.Header) (string, time.Duration, bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return "", 0, false, fmt.Errorf("azure msi: create request: %w", err)
	}
	for k, vals := range headers {
		for _, v := range vals {
			req.Header.Add(k, v)
		}
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", 0, true, fmt.Errorf("azure msi: request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 128*1024))
	if err != nil {
		return "", 0, true, fmt.Errorf("azure msi: read response: %w", err)
	}

	if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
		return "", 0, true, fmt.Errorf("azure msi: transient HTTP %d: %s", resp.StatusCode, string(body))
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", 0, false, fmt.Errorf("azure msi: HTTP %d: %s", resp.StatusCode, string(body))
	}

	var parsed azureMSIResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return "", 0, false, fmt.Errorf("azure msi: decode response: %w", err)
	}
	if strings.TrimSpace(parsed.AccessToken) == "" {
		return "", 0, false, errors.New("azure msi: empty access_token in response")
	}

	ttl := ts.parseTTL(parsed.ExpiresIn, parsed.ExpiresOn)
	return parsed.AccessToken, ttl, false, nil
}

func (ts *ManagedIdentityTokenSource) parseTTL(expiresInRaw, expiresOnRaw json.RawMessage) time.Duration {
	if sec, ok := parseFlexibleInt64(expiresInRaw); ok && sec > 0 {
		return time.Duration(sec) * time.Second
	}
	if tsVal, ok := parseFlexibleInt64(expiresOnRaw); ok && tsVal > 0 {
		exp := time.Unix(tsVal, 0).UTC()
		if d := exp.Sub(ts.now().UTC()); d > 0 {
			return d
		}
	}
	if len(expiresOnRaw) > 2 {
		var s string
		if err := json.Unmarshal(expiresOnRaw, &s); err == nil {
			if t, err := time.Parse(time.RFC3339, s); err == nil {
				if d := t.UTC().Sub(ts.now().UTC()); d > 0 {
					return d
				}
			}
		}
	}
	return 1 * time.Hour
}

func parseFlexibleInt64(raw json.RawMessage) (int64, bool) {
	if len(raw) == 0 {
		return 0, false
	}
	var n int64
	if err := json.Unmarshal(raw, &n); err == nil {
		return n, true
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		if parsed, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64); err == nil {
			return parsed, true
		}
	}
	return 0, false
}
