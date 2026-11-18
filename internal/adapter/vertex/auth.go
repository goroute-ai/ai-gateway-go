package vertex

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/adapter"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/security/network"
	"golang.org/x/sync/singleflight"
)

const (
	defaultGCPMetadataHost = "metadata.google.internal"
	defaultGoogleTokenURI  = "https://oauth2.googleapis.com/token"
)

// ErrAmbientIAMDisabled is returned when GCP ADC / Metadata Server resolution is attempted
// while AllowAmbientCloudIAM is false (the secure default).
var ErrAmbientIAMDisabled = errors.New("vertex: ambient cloud IAM is disabled (allow_ambient_cloud_iam=false)")

// AmbientADCConfig configures opt-in GCP Application Default Credentials (ADC)
// and Compute Metadata Server token resolution.
type AmbientADCConfig struct {
	AllowAmbientCloudIAM bool
	MetadataHost         string
	CredentialsFile      string
	Scopes               []string
	TokenURI             string
	SSRFPolicy           *network.Policy
	Now                  func() time.Time
}

type authorizedUserCredentials struct {
	Type           string `json:"type"`
	ClientID       string `json:"client_id"`
	ClientSecret   string `json:"client_secret"`
	RefreshToken   string `json:"refresh_token"`
	QuotaProjectID string `json:"quota_project_id"`
	TokenURI       string `json:"token_uri"`
}

// ServiceAccountKey represents a Google Cloud IAM Service Account JSON key.
type ServiceAccountKey struct {
	Type                    string `json:"type"`
	ProjectID               string `json:"project_id"`
	PrivateKeyID            string `json:"private_key_id"`
	PrivateKey              string `json:"private_key"`
	ClientEmail             string `json:"client_email"`
	ClientID                string `json:"client_id"`
	AuthURI                 string `json:"auth_uri"`
	TokenURI                string `json:"token_uri"`
	AuthProviderX509CertURL string `json:"auth_provider_x509_cert_url"`
	ClientX509CertURL       string `json:"client_x509_cert_url"`
}

// TokenSource provides OAuth2 Bearer access tokens with background caching.
type TokenSource struct {
	mu             sync.RWMutex
	client         *http.Client
	saKey          *ServiceAccountKey
	parsedKey      *rsa.PrivateKey
	authorizedUser *authorizedUserCredentials
	metadataURL    string
	cachedToken    string
	expiresAt      time.Time
	directBearer   string
	now            func() time.Time
	sfGroup        singleflight.Group
}

// NewTokenSource creates a token source from a raw credential string (either JSON service account key or Bearer token).
func NewTokenSource(client *http.Client, rawCred string) (*TokenSource, error) {
	if client == nil {
		client = network.NewHTTPClient(nil)
	}
	rawCred = strings.TrimSpace(rawCred)
	if rawCred == "" {
		return nil, fmt.Errorf("empty credentials")
	}

	ts := &TokenSource{
		client: client,
		now:    time.Now,
	}

	// If starts with '{', try parsing as Service Account JSON
	if strings.HasPrefix(rawCred, "{") {
		var sa ServiceAccountKey
		if err := json.Unmarshal([]byte(rawCred), &sa); err == nil && sa.ClientEmail != "" && sa.PrivateKey != "" {
			block, _ := pem.Decode([]byte(sa.PrivateKey))
			if block == nil {
				return nil, fmt.Errorf("failed to decode private key PEM")
			}
			parsedKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				// Fallback to PKCS1
				parsedKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
				if err != nil {
					return nil, fmt.Errorf("parse rsa private key: %w", err)
				}
			}
			rsaKey, ok := parsedKey.(*rsa.PrivateKey)
			if !ok {
				return nil, fmt.Errorf("private key is not RSA")
			}
			ts.saKey = &sa
			ts.parsedKey = rsaKey
			if ts.saKey.TokenURI == "" {
				ts.saKey.TokenURI = "https://oauth2.googleapis.com/token"
			}
			return ts, nil
		}
	}

	// Otherwise treat as direct pre-minted Bearer token
	ts.directBearer = rawCred
	return ts, nil
}

// NewAmbientTokenSource constructs a TokenSource backed by GCP Application Default Credentials
// (GOOGLE_APPLICATION_CREDENTIALS service_account or authorized_user JSON) or the GCP Compute
// Metadata Server when cfg.AllowAmbientCloudIAM is explicitly true.
func NewAmbientTokenSource(cfg AmbientADCConfig) (*TokenSource, error) {
	if !cfg.AllowAmbientCloudIAM {
		return nil, ErrAmbientIAMDisabled
	}

	nowFn := cfg.Now
	if nowFn == nil {
		nowFn = time.Now
	}

	// 1. Check explicit CredentialsFile or GOOGLE_APPLICATION_CREDENTIALS.
	credFile := strings.TrimSpace(cfg.CredentialsFile)
	if credFile == "" {
		credFile = strings.TrimSpace(os.Getenv("GOOGLE_APPLICATION_CREDENTIALS"))
	}
	if credFile != "" {
		rawBytes, err := os.ReadFile(credFile)
		if err != nil {
			return nil, fmt.Errorf("vertex adc: read credentials file: %w", err)
		}
		var header struct {
			Type string `json:"type"`
		}
		if err := json.Unmarshal(rawBytes, &header); err != nil {
			return nil, fmt.Errorf("vertex adc: parse credentials json: %w", err)
		}

		client := network.NewHTTPClient(cfg.SSRFPolicy)
		switch header.Type {
		case "service_account", "":
			ts, err := NewTokenSource(client, string(rawBytes))
			if err != nil {
				return nil, fmt.Errorf("vertex adc service_account: %w", err)
			}
			ts.now = nowFn
			if cfg.TokenURI != "" && ts.saKey != nil {
				ts.saKey.TokenURI = cfg.TokenURI
			}
			return ts, nil
		case "authorized_user":
			var au authorizedUserCredentials
			if err := json.Unmarshal(rawBytes, &au); err != nil {
				return nil, fmt.Errorf("vertex adc authorized_user: %w", err)
			}
			if au.ClientID == "" || au.ClientSecret == "" || au.RefreshToken == "" {
				return nil, errors.New("vertex adc authorized_user: missing client_id, client_secret, or refresh_token")
			}
			if cfg.TokenURI != "" {
				au.TokenURI = cfg.TokenURI
			} else if au.TokenURI == "" {
				au.TokenURI = defaultGoogleTokenURI
			}
			return &TokenSource{
				client:         client,
				authorizedUser: &au,
				now:            nowFn,
			}, nil
		default:
			return nil, fmt.Errorf("vertex adc: unsupported credential type %q", header.Type)
		}
	}

	// 2. Fallback to GCP Compute Metadata Server using opted-in metadata HTTP client.
	metaClient, err := network.NewAmbientIAMHTTPClient(cfg.SSRFPolicy, cfg.AllowAmbientCloudIAM)
	if err != nil {
		return nil, err
	}

	host := strings.TrimSpace(cfg.MetadataHost)
	if host == "" {
		host = strings.TrimSpace(os.Getenv("GCE_METADATA_HOST"))
	}
	if host == "" {
		host = defaultGCPMetadataHost
	}
	baseURL := host
	if !strings.HasPrefix(baseURL, "http://") && !strings.HasPrefix(baseURL, "https://") {
		baseURL = "http://" + baseURL
	}
	baseURL = strings.TrimRight(baseURL, "/")

	metaURL := baseURL + "/computeMetadata/v1/instance/service-accounts/default/token"
	if len(cfg.Scopes) > 0 {
		metaURL += "?scopes=" + url.QueryEscape(strings.Join(cfg.Scopes, ","))
	}

	return &TokenSource{
		client:      metaClient,
		metadataURL: metaURL,
		now:         nowFn,
	}, nil
}

// GetToken returns a valid OAuth2 Bearer token, refreshing via SA JWT, ADC refresh token, or Metadata Server.
func (ts *TokenSource) GetToken(ctx context.Context) (string, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}

	nowFn := ts.now
	if nowFn == nil {
		nowFn = time.Now
	}

	ts.mu.RLock()
	if ts.directBearer != "" {
		token := ts.directBearer
		ts.mu.RUnlock()
		return token, nil
	}
	now := nowFn()
	if ts.cachedToken != "" && now.Before(ts.expiresAt.Add(-60*time.Second)) {
		token := ts.cachedToken
		ts.mu.RUnlock()
		return token, nil
	}
	ts.mu.RUnlock()

	ch := ts.sfGroup.DoChan("vertex-token", func() (any, error) {
		refreshCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
		defer cancel()
		return ts.refreshLocked(refreshCtx)
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

func (ts *TokenSource) refreshLocked(ctx context.Context) (string, error) {
	nowFn := ts.now
	if nowFn == nil {
		nowFn = time.Now
	}

	ts.mu.Lock()
	defer ts.mu.Unlock()

	now := nowFn()
	if ts.cachedToken != "" && now.Before(ts.expiresAt.Add(-60*time.Second)) {
		return ts.cachedToken, nil
	}

	var (
		tok       string
		expiresIn int
		err       error
	)

	switch {
	case ts.parsedKey != nil && ts.saKey != nil:
		tok, expiresIn, err = ts.fetchServiceAccountToken(ctx, now)
	case ts.authorizedUser != nil:
		tok, expiresIn, err = ts.fetchAuthorizedUserToken(ctx)
	case ts.metadataURL != "":
		tok, expiresIn, err = ts.fetchMetadataToken(ctx)
	default:
		return "", fmt.Errorf("service account key not initialized")
	}
	if err != nil {
		return "", err
	}

	if expiresIn <= 0 {
		expiresIn = 3600
	}
	ts.cachedToken = tok
	ts.expiresAt = now.Add(time.Duration(expiresIn) * time.Second)
	return ts.cachedToken, nil
}

func (ts *TokenSource) fetchServiceAccountToken(ctx context.Context, now time.Time) (string, int, error) {
	headerBytes, _ := json.Marshal(map[string]string{
		"alg": "RS256",
		"typ": "JWT",
	})
	claimsBytes, _ := json.Marshal(map[string]any{
		"iss":   ts.saKey.ClientEmail,
		"scope": "https://www.googleapis.com/auth/cloud-platform",
		"aud":   ts.saKey.TokenURI,
		"exp":   now.Add(1 * time.Hour).Unix(),
		"iat":   now.Unix(),
	})

	seg1 := base64.RawURLEncoding.EncodeToString(headerBytes)
	seg2 := base64.RawURLEncoding.EncodeToString(claimsBytes)
	signingInput := seg1 + "." + seg2

	h := sha256.New()
	h.Write([]byte(signingInput))
	hashed := h.Sum(nil)

	sig, err := rsa.SignPKCS1v15(rand.Reader, ts.parsedKey, crypto.SHA256, hashed)
	if err != nil {
		return "", 0, fmt.Errorf("sign jwt: %w", err)
	}
	assertion := signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)

	form := url.Values{}
	form.Set("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer")
	form.Set("assertion", assertion)

	return ts.postOAuthTokenForm(ctx, ts.saKey.TokenURI, form)
}

func (ts *TokenSource) fetchAuthorizedUserToken(ctx context.Context) (string, int, error) {
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("client_id", ts.authorizedUser.ClientID)
	form.Set("client_secret", ts.authorizedUser.ClientSecret)
	form.Set("refresh_token", ts.authorizedUser.RefreshToken)
	return ts.postOAuthTokenForm(ctx, ts.authorizedUser.TokenURI, form)
}

func (ts *TokenSource) postOAuthTokenForm(ctx context.Context, endpoint string, form url.Values) (string, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", 0, fmt.Errorf("create token exchange request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := ts.client.Do(req)
	if err != nil {
		return "", 0, fmt.Errorf("token exchange failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := adapter.ReadBoundedBody(resp.Body, adapter.DefaultMaxResponseBytes, domain.ProviderVertex)
	if err != nil {
		return "", 0, err
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", 0, fmt.Errorf("token exchange http %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
		TokenType   string `json:"token_type"`
	}
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return "", 0, fmt.Errorf("decode token response: %w", err)
	}
	if tokenResp.AccessToken == "" {
		return "", 0, fmt.Errorf("no access token in response")
	}
	return tokenResp.AccessToken, tokenResp.ExpiresIn, nil
}

func (ts *TokenSource) fetchMetadataToken(ctx context.Context) (string, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ts.metadataURL, nil)
	if err != nil {
		return "", 0, fmt.Errorf("vertex metadata: create request: %w", err)
	}
	req.Header.Set("Metadata-Flavor", "Google")

	resp, err := ts.client.Do(req)
	if err != nil {
		return "", 0, fmt.Errorf("vertex metadata: request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := adapter.ReadBoundedBody(resp.Body, adapter.DefaultMaxResponseBytes, domain.ProviderVertex)
	if err != nil {
		return "", 0, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", 0, fmt.Errorf("vertex metadata http %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
		TokenType   string `json:"token_type"`
	}
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return "", 0, fmt.Errorf("vertex metadata: decode token response: %w", err)
	}
	if tokenResp.AccessToken == "" {
		return "", 0, errors.New("vertex metadata: empty access_token in response")
	}
	return tokenResp.AccessToken, tokenResp.ExpiresIn, nil
}
