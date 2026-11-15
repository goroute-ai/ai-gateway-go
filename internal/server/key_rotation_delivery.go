package server

import (
	"context"
	"errors"

	"github.com/goroute-ai/ai-gateway-go/internal/auth"
	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/security/network"
)

func newKeyRotationDelivery(cfg config.AuthConfig, policy *network.Policy) (auth.RotationDelivery, error) {
	endpoint, err := validateStrictRotationHTTPSURL(config.ResolveEnvValue(cfg.KeyRotationDeliveryURL), "key rotation delivery")
	if err != nil {
		return nil, err
	}
	if endpoint == "" {
		return nil, nil
	}
	token := config.ResolveEnvValue(cfg.KeyRotationDeliveryToken)
	if token == "" {
		return nil, errors.New("key rotation delivery token is required")
	}

	client := newRotationHTTPClient(policy)
	return func(ctx context.Context, orgID, keyID, replacement string) error {
		return postRotationJSON(ctx, client, endpoint, map[string]string{
			"Authorization": "Bearer " + token,
			"Content-Type":  "application/json",
		}, map[string]string{
			"org_id":  orgID,
			"key_id":  keyID,
			"raw_key": replacement,
		}, "rotation delivery")
	}, nil
}
