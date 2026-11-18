package bedrock_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/adapter/bedrock"
	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/security/network"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBedrockAmbientIAM_DisabledByDefault(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIA_SHOULD_NOT_LEAK")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "SECRET_SHOULD_NOT_LEAK")

	p := bedrock.NewAmbientCredentialProvider(bedrock.AmbientIAMConfig{})
	_, err := p.GetCredentials(context.Background())
	require.Error(t, err)
	assert.True(t, errors.Is(err, bedrock.ErrAmbientIAMDisabled))

	adp := bedrock.NewAdapter(nil, nil)
	err = adp.ValidateCredential(context.Background(), &domain.ProviderCredential{DecryptedAPIKey: ""})
	require.Error(t, err)
	err = adp.ValidateCredential(context.Background(), &domain.ProviderCredential{DecryptedAPIKey: "ambient"})
	require.Error(t, err)
}

func TestBedrockAmbientIAM_IMDSv2AndAdapterConverse(t *testing.T) {
	var tokenPuts, credGets atomic.Int32

	imdsSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPut && r.URL.Path == "/latest/api/token":
			tokenPuts.Add(1)
			assert.NotEmpty(t, r.Header.Get("X-aws-ec2-metadata-token-ttl-seconds"))
			_, _ = w.Write([]byte("imds-v2-session-token"))
		case r.Method == http.MethodGet && r.URL.Path == "/latest/meta-data/iam/security-credentials/":
			assert.Equal(t, "imds-v2-session-token", r.Header.Get("X-aws-ec2-metadata-token"))
			_, _ = w.Write([]byte("bedrock-runtime-role\n"))
		case r.Method == http.MethodGet && r.URL.Path == "/latest/meta-data/iam/security-credentials/bedrock-runtime-role":
			credGets.Add(1)
			assert.Equal(t, "imds-v2-session-token", r.Header.Get("X-aws-ec2-metadata-token"))
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"Code":            "Success",
				"AccessKeyId":     "ASIAIMDSV2KEY",
				"SecretAccessKey": "imdsV2SecretKey",
				"Token":           "imdsV2SessionToken",
				"Expiration":      time.Now().UTC().Add(1 * time.Hour).Format(time.RFC3339),
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer imdsSrv.Close()

	// Ensure env static creds don't short-circuit IMDSv2.
	t.Setenv("AWS_ACCESS_KEY_ID", "")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "")
	t.Setenv("AWS_WEB_IDENTITY_TOKEN_FILE", "")
	t.Setenv("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "")
	t.Setenv("AWS_CONTAINER_CREDENTIALS_FULL_URI", "")

	var bedrockAuth, bedrockSecTok string
	bedrockSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bedrockAuth = r.Header.Get("Authorization")
		bedrockSecTok = r.Header.Get("x-amz-security-token")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"output":{"message":{"role":"assistant","content":[{"text":"ok"}]}},"usage":{"inputTokens":1,"outputTokens":1}}`))
	}))
	defer bedrockSrv.Close()

	adp := bedrock.NewAdapter(bedrockSrv.Client(), loopbackTestPolicy(t))
	adp.SetAmbientIAMConfig(bedrock.AmbientIAMConfig{
		AllowAmbientCloudIAM: true,
		Region:               "us-west-2",
		IMDSEndpoint:         imdsSrv.URL,
		SSRFPolicy:           loopbackTestPolicy(t),
	})

	dep := &domain.Deployment{
		ID: "dep-imds",
		GlobalModel: &domain.GlobalModel{
			ID:        "bedrock/anthropic.claude-3-5-sonnet-20241022-v2:0",
			Provider:  domain.ProviderBedrock,
			ModelName: "anthropic.claude-3-5-sonnet-20241022-v2:0",
		},
		Credential: &domain.ProviderCredential{
			BaseURL:         bedrockSrv.URL,
			DecryptedAPIKey: "ambient",
		},
	}
	req := &domain.CanonicalChatRequest{
		Model:    "anthropic.claude-3-5-sonnet-20241022-v2:0",
		Messages: []domain.CanonicalMessage{{Role: "user", Content: "hi"}},
	}

	resp, err := adp.ChatCompletion(context.Background(), dep, req)
	require.NoError(t, err)
	assert.Equal(t, "ok", resp.Choices[0].Message.Content)
	assert.True(t, strings.HasPrefix(bedrockAuth, "AWS4-HMAC-SHA256 Credential=ASIAIMDSV2KEY/"))
	assert.Contains(t, bedrockAuth, "/us-west-2/bedrock/aws4_request")
	assert.Equal(t, "imdsV2SessionToken", bedrockSecTok)

	// Second call reuses cached IMDSv2 credentials.
	_, err = adp.ChatCompletion(context.Background(), dep, req)
	require.NoError(t, err)
	assert.Equal(t, int32(1), tokenPuts.Load())
	assert.Equal(t, int32(1), credGets.Load())
}

func TestBedrockAmbientIAM_ECSAndIRSA(t *testing.T) {
	t.Run("ECS relative URI", func(t *testing.T) {
		ecsSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "/v2/credentials/task-123", r.URL.Path)
			assert.Equal(t, "ecs-auth-secret", r.Header.Get("Authorization"))
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"AccessKeyId":     "ASIAECSKEY",
				"SecretAccessKey": "ecsSecret",
				"Token":           "ecsToken",
				"Expiration":      time.Now().UTC().Add(30 * time.Minute).Format(time.RFC3339),
			})
		}))
		defer ecsSrv.Close()

		t.Setenv("AWS_ACCESS_KEY_ID", "")
		t.Setenv("AWS_SECRET_ACCESS_KEY", "")
		t.Setenv("AWS_WEB_IDENTITY_TOKEN_FILE", "")
		t.Setenv("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "/v2/credentials/task-123")
		t.Setenv("AWS_CONTAINER_AUTHORIZATION_TOKEN", "ecs-auth-secret")

		p := bedrock.NewAmbientCredentialProvider(bedrock.AmbientIAMConfig{
			AllowAmbientCloudIAM: true,
			Region:               "eu-central-1",
			ECSEndpoint:          ecsSrv.URL,
			SSRFPolicy:           loopbackTestPolicy(t),
		})
		creds, err := p.GetCredentials(context.Background())
		require.NoError(t, err)
		assert.Equal(t, "ASIAECSKEY", creds.AccessKeyID)
		assert.Equal(t, "ecsToken", creds.SessionToken)
		assert.Equal(t, "eu-central-1", creds.Region)
	})

	t.Run("IRSA web identity", func(t *testing.T) {
		tokenFile := filepath.Join(t.TempDir(), "token")
		require.NoError(t, os.WriteFile(tokenFile, []byte("jwt-irsa-token"), 0o600))

		stsSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_ = r.ParseForm()
			assert.Equal(t, "AssumeRoleWithWebIdentity", r.Form.Get("Action"))
			assert.Equal(t, "jwt-irsa-token", r.Form.Get("WebIdentityToken"))
			assert.Equal(t, "arn:aws:iam::123456789012:role/bedrock-role", r.Form.Get("RoleArn"))
			w.Header().Set("Content-Type", "text/xml")
			_, _ = w.Write([]byte(`
<AssumeRoleWithWebIdentityResponse>
  <AssumeRoleWithWebIdentityResult>
    <Credentials>
      <AccessKeyId>ASIAIRSA_BEDROCK</AccessKeyId>
      <SecretAccessKey>irsaSecret</SecretAccessKey>
      <SessionToken>irsaSession</SessionToken>
      <Expiration>` + time.Now().UTC().Add(1*time.Hour).Format(time.RFC3339) + `</Expiration>
    </Credentials>
  </AssumeRoleWithWebIdentityResult>
</AssumeRoleWithWebIdentityResponse>`))
		}))
		defer stsSrv.Close()

		t.Setenv("AWS_ACCESS_KEY_ID", "")
		t.Setenv("AWS_SECRET_ACCESS_KEY", "")
		t.Setenv("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "")
		t.Setenv("AWS_WEB_IDENTITY_TOKEN_FILE", tokenFile)
		t.Setenv("AWS_ROLE_ARN", "arn:aws:iam::123456789012:role/bedrock-role")

		pol, err := network.NewPolicy(config.OutboundSSRFConfig{
			AllowPrivateNetworks: true,
			AllowInsecureHTTP:    true,
		})
		require.NoError(t, err)

		p := bedrock.NewAmbientCredentialProvider(bedrock.AmbientIAMConfig{
			AllowAmbientCloudIAM: true,
			Region:               "us-east-1",
			STSEndpoint:          stsSrv.URL,
			SSRFPolicy:           pol,
		})
		creds, err := p.GetCredentials(context.Background())
		require.NoError(t, err)
		assert.Equal(t, "ASIAIRSA_BEDROCK", creds.AccessKeyID)
		assert.Equal(t, "irsaSession", creds.SessionToken)
	})
}
