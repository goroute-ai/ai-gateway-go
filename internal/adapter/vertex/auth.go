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
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

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
	mu           sync.RWMutex
	client       *http.Client
	saKey        *ServiceAccountKey
	parsedKey    *rsa.PrivateKey
	cachedToken  string
	expiresAt    time.Time
	directBearer string
}

// NewTokenSource creates a token source from a raw credential string (either JSON service account key or Bearer token).
func NewTokenSource(client *http.Client, rawCred string) (*TokenSource, error) {
	if client == nil {
		client = http.DefaultClient
	}
	rawCred = strings.TrimSpace(rawCred)
	if rawCred == "" {
		return nil, fmt.Errorf("empty credentials")
	}

	ts := &TokenSource{
		client: client,
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

// GetToken returns a valid OAuth2 Bearer token, exchanging JWT assertion if necessary.
func (ts *TokenSource) GetToken(ctx context.Context) (string, error) {
	ts.mu.RLock()
	if ts.directBearer != "" {
		token := ts.directBearer
		ts.mu.RUnlock()
		return token, nil
	}
	if ts.cachedToken != "" && time.Now().Before(ts.expiresAt.Add(-60*time.Second)) {
		token := ts.cachedToken
		ts.mu.RUnlock()
		return token, nil
	}
	ts.mu.RUnlock()

	ts.mu.Lock()
	defer ts.mu.Unlock()

	// Double check under write lock
	if ts.cachedToken != "" && time.Now().Before(ts.expiresAt.Add(-60*time.Second)) {
		return ts.cachedToken, nil
	}

	if ts.parsedKey == nil || ts.saKey == nil {
		return "", fmt.Errorf("service account key not initialized")
	}

	// Create JWT assertion
	now := time.Now()
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
		return "", fmt.Errorf("sign jwt: %w", err)
	}
	seg3 := base64.RawURLEncoding.EncodeToString(sig)
	assertion := signingInput + "." + seg3

	// Exchange assertion with Google OAuth2 Token URI
	form := url.Values{}
	form.Set("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer")
	form.Set("assertion", assertion)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ts.saKey.TokenURI, strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("create token exchange request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := ts.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("token exchange failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read token exchange response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("token exchange http %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
		TokenType   string `json:"token_type"`
	}
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return "", fmt.Errorf("decode token response: %w", err)
	}

	if tokenResp.AccessToken == "" {
		return "", fmt.Errorf("no access token in response")
	}

	ts.cachedToken = tokenResp.AccessToken
	if tokenResp.ExpiresIn <= 0 {
		tokenResp.ExpiresIn = 3600
	}
	ts.expiresAt = now.Add(time.Duration(tokenResp.ExpiresIn) * time.Second)

	return ts.cachedToken, nil
}
