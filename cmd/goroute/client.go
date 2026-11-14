package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"
)

type apiClient struct {
	baseURL string
	apiKey  string
	http    *http.Client
}

func newAPIClient(baseURL, apiKey string) *apiClient {
	return &apiClient{
		baseURL: strings.TrimRight(strings.TrimSpace(baseURL), "/"),
		apiKey:  strings.TrimSpace(apiKey),
		http:    buildCLIHTTPClient(),
	}
}

func buildCLIHTTPClient() *http.Client {
	client := &http.Client{Timeout: 30 * time.Second}
	caPath := strings.TrimSpace(os.Getenv("GOROUTE_CA_CERT"))
	if caPath == "" {
		caPath = strings.TrimSpace(os.Getenv("SSL_CERT_FILE"))
	}
	if caPath == "" {
		return client
	}
	pemBytes, err := os.ReadFile(caPath)
	if err != nil {
		return client
	}
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if !pool.AppendCertsFromPEM(pemBytes) {
		return client
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{
		RootCAs:    pool,
		MinVersion: tls.VersionTLS12,
	}
	client.Transport = tr
	return client
}

func (c *apiClient) doJSON(ctx context.Context, method, path string, body any, out any) (int, http.Header, error) {
	var reader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return 0, nil, err
		}
		reader = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, reader)
	if err != nil {
		return 0, nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	if c.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return resp.StatusCode, resp.Header, err
	}
	if resp.StatusCode >= 400 {
		return resp.StatusCode, resp.Header, fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	if out != nil && len(raw) > 0 {
		if err := json.Unmarshal(raw, out); err != nil {
			return resp.StatusCode, resp.Header, fmt.Errorf("decode response: %w", err)
		}
	}
	return resp.StatusCode, resp.Header, nil
}

type cliStartResponse struct {
	LoginID         string `json:"login_id"`
	UserCode        string `json:"user_code"`
	VerificationURL string `json:"verification_url"`
	ExpiresIn       int    `json:"expires_in"`
	Interval        int    `json:"interval"`
}

type cliPollResponse struct {
	Status    string `json:"status"`
	LoginID   string `json:"login_id"`
	APIKey    string `json:"api_key"`
	KeyID     string `json:"key_id"`
	KeyPrefix string `json:"key_prefix"`
	OrgID     string `json:"org_id"`
	TeamID    string `json:"team_id"`
	Interval  int    `json:"interval"`
}

func runDeviceLogin(ctx context.Context, client *apiClient, provider string, openBrowser bool, out io.Writer) (*Credentials, error) {
	reqBody := map[string]any{}
	if strings.TrimSpace(provider) != "" {
		reqBody["provider"] = strings.TrimSpace(provider)
	}
	var started cliStartResponse
	if _, _, err := client.doJSON(ctx, http.MethodPost, "/auth/cli/start", reqBody, &started); err != nil {
		return nil, fmt.Errorf("start CLI login: %w", err)
	}
	_, _ = fmt.Fprintf(out, "Open the verification URL in your browser to authorize this CLI:\n  %s\n", started.VerificationURL)
	if started.UserCode != "" {
		_, _ = fmt.Fprintf(out, "User Code: %s\n", started.UserCode)
	}
	if openBrowser && started.VerificationURL != "" {
		_ = tryOpenBrowser(started.VerificationURL)
	}

	interval := time.Duration(started.Interval) * time.Second
	if interval <= 0 {
		interval = 5 * time.Second
	}
	deadline := time.Now().Add(time.Duration(started.ExpiresIn) * time.Second)
	if started.ExpiresIn <= 0 {
		deadline = time.Now().Add(10 * time.Minute)
	}

	for {
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("CLI login timed out before browser approval")
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(interval):
		}

		var polled cliPollResponse
		status, hdr, err := client.doJSON(ctx, http.MethodGet, "/auth/cli/poll/"+started.LoginID, nil, &polled)
		if status == http.StatusTooManyRequests {
			if ra := strings.TrimSpace(hdr.Get("Retry-After")); ra != "" {
				if sec, pErr := strconv.Atoi(ra); pErr == nil && sec > 0 {
					interval = time.Duration(sec) * time.Second
				}
			}
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("poll CLI login: %w", err)
		}
		if status == http.StatusAccepted || polled.Status == "pending" {
			if polled.Interval > 0 {
				interval = time.Duration(polled.Interval) * time.Second
			}
			continue
		}
		if polled.Status == "completed" && polled.APIKey != "" {
			return &Credentials{
				GatewayURL: client.baseURL,
				APIKey:     polled.APIKey,
				KeyID:      polled.KeyID,
				KeyPrefix:  polled.KeyPrefix,
				OrgID:      polled.OrgID,
				TeamID:     polled.TeamID,
				SavedAt:    time.Now().UTC(),
			}, nil
		}
	}
}

func tryOpenBrowser(targetURL string) error {
	parsed, err := url.Parse(strings.TrimSpace(targetURL))
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		return fmt.Errorf("refusing to open non-HTTP(S) URL in browser")
	}
	safeURL := parsed.String()
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", safeURL) // #nosec G204 -- safeURL is validated to http/https scheme
	case "linux":
		cmd = exec.Command("xdg-open", safeURL) // #nosec G204 -- safeURL is validated to http/https scheme
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", safeURL) // #nosec G204 -- safeURL is validated to http/https scheme
	default:
		return nil
	}
	return cmd.Start()
}
