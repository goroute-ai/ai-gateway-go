package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/auth"
	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/security/network"
)

func validateStrictRotationHTTPSURL(raw, errPrefix string) (string, error) {
	return config.ValidateStrictHTTPSURL(raw, errPrefix)
}

func newRotationHTTPClient(policy *network.Policy) *http.Client {
	client := network.NewHTTPClient(policy)
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return client
}

func newKeyRotationSecretSink(cfg config.AuthConfig, policy *network.Policy) (auth.KeySecretSink, error) {
	return newKeyRotationSecretSinkWithClient(cfg, newRotationHTTPClient(policy), policy)
}

func newKeyRotationSecretSinkWithClient(cfg config.AuthConfig, client *http.Client, policy *network.Policy) (auth.KeySecretSink, error) {
	sinkCfg := cfg.KeyRotationSink
	driver := strings.ToLower(strings.TrimSpace(sinkCfg.Driver))
	if driver == "" {
		return nil, nil
	}
	if client == nil {
		client = newRotationHTTPClient(policy)
	}

	prefix := strings.Trim(strings.TrimSpace(sinkCfg.PathPrefix), "/")
	if prefix == "" {
		prefix = "goroute/virtual-keys"
	}

	switch driver {
	case "webhook":
		if strings.TrimSpace(sinkCfg.Address) == "" {
			if strings.TrimSpace(cfg.KeyRotationDeliveryURL) != "" {
				// Configured via legacy key_rotation_delivery_url; avoid duplicate posts.
				return nil, nil
			}
			return nil, errors.New("auth.key_rotation_sink.address is required for webhook driver")
		}
		endpoint, err := validateStrictRotationHTTPSURL(config.ResolveEnvValue(sinkCfg.Address), "key rotation sink webhook")
		if err != nil {
			return nil, err
		}
		token := config.ResolveEnvValue(sinkCfg.Token)
		if token == "" {
			token = config.ResolveEnvValue(cfg.KeyRotationDeliveryToken)
		}
		if token == "" {
			return nil, errors.New("auth.key_rotation_sink.token is required for webhook driver")
		}
		return auth.KeySecretSinkFunc(func(ctx context.Context, event auth.KeyRotatedSecretEvent) error {
			return postRotationJSON(ctx, client, endpoint, map[string]string{
				"Authorization": "Bearer " + token,
				"Content-Type":  "application/json",
			}, event, "webhook sink")
		}), nil

	case "vault_kv2":
		addr, err := validateStrictRotationHTTPSURL(config.ResolveEnvValue(sinkCfg.Address), "key rotation Vault KV v2 sink")
		if err != nil || addr == "" {
			if err == nil {
				err = errors.New("auth.key_rotation_sink.address is required for vault_kv2 driver")
			}
			return nil, err
		}
		token := config.ResolveEnvValue(sinkCfg.Token)
		if token == "" {
			return nil, errors.New("auth.key_rotation_sink.token is required for vault_kv2 driver")
		}
		mount := strings.Trim(strings.TrimSpace(sinkCfg.Mount), "/")
		if mount == "" {
			mount = "secret"
		}
		namespace := strings.TrimSpace(config.ResolveEnvValue(sinkCfg.Namespace))
		return auth.KeySecretSinkFunc(func(ctx context.Context, event auth.KeyRotatedSecretEvent) error {
			secretPath := fmt.Sprintf("%s/v1/%s/data/%s/%s/%s",
				addr,
				url.PathEscape(mount),
				escapeSlashPath(prefix),
				url.PathEscape(event.OrgID),
				url.PathEscape(event.VirtualKeyID),
			)
			headers := map[string]string{
				"X-Vault-Token": token,
				"Content-Type":  "application/json",
			}
			if namespace != "" {
				headers["X-Vault-Namespace"] = namespace
			}
			return postRotationJSON(ctx, client, secretPath, headers, map[string]any{
				"data": event,
			}, "vault_kv2 sink")
		}), nil

	default:
		return nil, fmt.Errorf("unsupported auth.key_rotation_sink.driver %q", sinkCfg.Driver)
	}
}

func escapeSlashPath(p string) string {
	parts := strings.Split(strings.Trim(p, "/"), "/")
	escaped := make([]string, 0, len(parts))
	for _, part := range parts {
		if part != "" {
			escaped = append(escaped, url.PathEscape(part))
		}
	}
	return strings.Join(escaped, "/")
}

func postRotationJSON(ctx context.Context, client *http.Client, endpoint string, headers map[string]string, payload any, label string) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("%s encode payload: %w", label, err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("%s build request: %w", label, err)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("%s unavailable: %w", label, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("%s rejected with HTTP %d", label, resp.StatusCode)
	}
	return nil
}
