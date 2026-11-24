package gateway_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/pkg/gateway"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSDKWithCustomAuthenticatorAndCustomAuthorizer(t *testing.T) {
	mockUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id":      "chatcmpl-sdk-authz-1",
			"object":  "chat.completion",
			"created": 1700000000,
			"model":   "gpt-4o-mini",
			"choices": []map[string]any{{
				"index":         0,
				"message":       map[string]any{"role": "assistant", "content": "sdk-authz-ok"},
				"finish_reason": "stop",
			}},
			"usage": map[string]any{"prompt_tokens": 5, "completion_tokens": 3, "total_tokens": 8},
		})
	}))
	defer mockUpstream.Close()

	var authzMode string
	gw, err := gateway.New(
		gateway.WithAllowPrivateNetworks(),
		gateway.WithModelList(gateway.ModelEntry{
			ModelName: "sdk-mini",
			Model:     "openai/gpt-4o-mini",
			APIKey:    "sk-sdk-mock",
			APIBase:   mockUpstream.URL,
		}),
		gateway.WithCustomAuthenticator(gateway.CustomAuthModeOn, gateway.CustomAuthenticatorFunc(func(_ context.Context, r *http.Request) (*gateway.AuthDecision, error) {
			if r.Header.Get("X-Custom-Token") != "valid-enterprise-token" {
				return nil, &domain.GatewayError{
					StatusCode: http.StatusUnauthorized,
					Type:       domain.ErrorTypeAuthentication,
					Code:       "invalid_custom_token",
					Message:    "Custom token invalid",
				}
			}
			return &gateway.AuthDecision{
				Identity: &domain.IdentityContext{
					OrgID:            "org_default",
					UserID:           "usr_custom_1",
					KeyPrefix:        "custom-token",
					AllowedEndpoints: []string{"*"},
					KeyAllowedModels: []string{"*"},
				},
				RunPostChecks: true,
			}, nil
		})),
		gateway.WithCustomAuthorizer(gateway.CustomAuthorizerFunc(func(_ context.Context, req *gateway.AuthzRequest) (*gateway.AuthzDecision, error) {
			switch authzMode {
			case "deny":
				return &gateway.AuthzDecision{Allow: false, Reason: "blocked by sdk policy", ErrorCode: "sdk_policy_denied"}, nil
			case "error":
				return nil, errors.New("sdk policy backend offline")
			default:
				return &gateway.AuthzDecision{Allow: true}, nil
			}
		})),
	)
	require.NoError(t, err)
	defer gw.Close()

	postChat := func(token string) (int, string) {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, gw.BaseURL()+"/v1/chat/completions", bytes.NewBufferString(`{
			"model": "sdk-mini",
			"messages": [{"role": "user", "content": "hi"}]
		}`))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/json")
		if token != "" {
			req.Header.Set("X-Custom-Token", token)
		}
		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(body)
	}

	// 1. Missing/invalid custom token fails closed with 401
	code, _ := postChat("wrong")
	assert.Equal(t, http.StatusUnauthorized, code)

	// 2. Valid custom token + CustomAuthorizer allow -> 200
	authzMode = "allow"
	code, body := postChat("valid-enterprise-token")
	assert.Equal(t, http.StatusOK, code, "body=%s", body)
	assert.Contains(t, body, "sdk-authz-ok")

	// 3. Valid custom token + CustomAuthorizer deny -> 403 sdk_policy_denied
	authzMode = "deny"
	code, body = postChat("valid-enterprise-token")
	assert.Equal(t, http.StatusForbidden, code, "body=%s", body)
	assert.Contains(t, body, "sdk_policy_denied")

	// 4. Valid custom token + CustomAuthorizer error -> 503 fail-closed
	authzMode = "error"
	code, body = postChat("valid-enterprise-token")
	assert.Equal(t, http.StatusServiceUnavailable, code, "body=%s", body)
	assert.Contains(t, body, "authorizer_unavailable")
}
