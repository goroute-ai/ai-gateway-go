package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/auth"
	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/security/network"
)

func newKeyRotationDelivery(cfg config.AuthConfig, policy *network.Policy) (auth.RotationDelivery, error) {
	endpoint := config.ResolveEnvValue(cfg.KeyRotationDeliveryURL)
	if endpoint == "" {
		return nil, nil
	}
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, errors.New("key rotation delivery requires an HTTPS URL without credentials, a query, or a fragment")
	}
	token := config.ResolveEnvValue(cfg.KeyRotationDeliveryToken)
	if token == "" {
		return nil, errors.New("key rotation delivery token is required")
	}

	client := network.NewHTTPClient(policy)
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return func(ctx context.Context, orgID, keyID, replacement string) error {
		ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		body, err := json.Marshal(map[string]string{
			"org_id":  orgID,
			"key_id":  keyID,
			"raw_key": replacement,
		})
		if err != nil {
			return errors.New("encode rotation delivery")
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
		if err != nil {
			return errors.New("create rotation delivery request")
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			return fmt.Errorf("rotation delivery endpoint unavailable: %w", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return fmt.Errorf("rotation delivery rejected with HTTP %d", resp.StatusCode)
		}
		return nil
	}, nil
}
