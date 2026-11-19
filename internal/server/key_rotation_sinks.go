package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/adapter/bedrock"
	"github.com/goroute-ai/ai-gateway-go/internal/auth"
	"github.com/goroute-ai/ai-gateway-go/internal/auth/upstream"
	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/security/network"
)

func validateStrictRotationHTTPSURL(raw, errPrefix string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", nil
	}
	parsed, err := url.Parse(trimmed)
	if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", fmt.Errorf("%s requires an HTTPS URL without credentials, a query, or a fragment", errPrefix)
	}
	return strings.TrimRight(trimmed, "/"), nil
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

	case "aws_secrets_manager":
		region := strings.TrimSpace(config.ResolveEnvValue(sinkCfg.Region))
		accessKey := strings.TrimSpace(config.ResolveEnvValue(sinkCfg.AWSAccessKeyID))
		secretKey := strings.TrimSpace(config.ResolveEnvValue(sinkCfg.AWSSecretAccessKey))
		sessionToken := strings.TrimSpace(config.ResolveEnvValue(sinkCfg.AWSSessionToken))
		var ambient *bedrock.AmbientCredentialProvider
		if accessKey == "" || secretKey == "" {
			if !cfg.AllowAmbientCloudIAM {
				return nil, errors.New("aws_secrets_manager sink requires static AWS credentials when auth.allow_ambient_cloud_iam is false")
			}
			ambient = bedrock.NewAmbientCredentialProvider(bedrock.AmbientIAMConfig{
				AllowAmbientCloudIAM: true,
				Region:               region,
				SSRFPolicy:           policy,
			})
		}
		if region == "" {
			if r := strings.TrimSpace(os.Getenv("AWS_REGION")); r != "" {
				region = r
			} else if r := strings.TrimSpace(os.Getenv("AWS_DEFAULT_REGION")); r != "" {
				region = r
			}
		}
		if region == "" && strings.TrimSpace(sinkCfg.Address) == "" {
			return nil, errors.New("auth.key_rotation_sink.region is required for aws_secrets_manager driver")
		}
		if region == "" {
			region = "us-east-1"
		}
		endpoint := fmt.Sprintf("https://secretsmanager.%s.amazonaws.com", region)
		if rawAddr := config.ResolveEnvValue(sinkCfg.Address); strings.TrimSpace(rawAddr) != "" {
			var err error
			endpoint, err = validateStrictRotationHTTPSURL(rawAddr, "AWS Secrets Manager sink")
			if err != nil {
				return nil, err
			}
		}
		return auth.KeySecretSinkFunc(func(ctx context.Context, event auth.KeyRotatedSecretEvent) error {
			return deliverAWSSecretsManager(ctx, client, endpoint, region, prefix, accessKey, secretKey, sessionToken, ambient, event)
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

func deliverAWSSecretsManager(
	ctx context.Context,
	client *http.Client,
	endpoint, region, prefix, accessKey, secretKey, sessionToken string,
	ambient *bedrock.AmbientCredentialProvider,
	event auth.KeyRotatedSecretEvent,
) error {
	if (accessKey == "" || secretKey == "") && ambient != nil {
		creds, err := ambient.GetCredentials(ctx)
		if err != nil {
			return fmt.Errorf("aws_secrets_manager resolve ambient credentials: %w", err)
		}
		accessKey = creds.AccessKeyID
		secretKey = creds.SecretAccessKey
		sessionToken = creds.SessionToken
	}
	signer, err := upstream.NewSigV4Strategy(upstream.SigV4Config{
		AccessKeyID:     accessKey,
		SecretAccessKey: secretKey,
		SessionToken:    sessionToken,
		Region:          region,
		Service:         "secretsmanager",
	})
	if err != nil {
		return fmt.Errorf("aws_secrets_manager signer init: %w", err)
	}

	secretBytes, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("aws_secrets_manager encode secret: %w", err)
	}
	secretName := fmt.Sprintf("%s/%s/%s", prefix, event.OrgID, event.VirtualKeyID)
	putBody := map[string]any{
		"SecretId":     secretName,
		"SecretString": string(secretBytes),
	}
	status, respBody, err := callAWSSecretsManager(ctx, client, signer, endpoint, "secretsmanager.PutSecretValue", putBody)
	if err != nil {
		return err
	}
	if status >= 200 && status < 300 {
		return nil
	}
	if status == http.StatusBadRequest && strings.Contains(respBody, "ResourceNotFoundException") {
		createBody := map[string]any{
			"Name":         secretName,
			"SecretString": string(secretBytes),
		}
		cStatus, _, cErr := callAWSSecretsManager(ctx, client, signer, endpoint, "secretsmanager.CreateSecret", createBody)
		if cErr != nil {
			return cErr
		}
		if cStatus >= 200 && cStatus < 300 {
			return nil
		}
		return fmt.Errorf("aws_secrets_manager CreateSecret rejected with HTTP %d", cStatus)
	}
	return fmt.Errorf("aws_secrets_manager PutSecretValue rejected with HTTP %d", status)
}

func callAWSSecretsManager(
	ctx context.Context,
	client *http.Client,
	signer *upstream.SigV4Strategy,
	endpoint, target string,
	payload map[string]any,
) (int, string, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	body, err := json.Marshal(payload)
	if err != nil {
		return 0, "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return 0, "", err
	}
	req.Header.Set("Content-Type", "application/x-amz-json-1.1")
	req.Header.Set("X-Amz-Target", target)
	if err := signer.Apply(ctx, req, nil); err != nil {
		return 0, "", fmt.Errorf("aws_secrets_manager sign request: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, "", fmt.Errorf("aws_secrets_manager unavailable: %w", err)
	}
	defer resp.Body.Close()
	respBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	return resp.StatusCode, string(respBytes), nil
}
