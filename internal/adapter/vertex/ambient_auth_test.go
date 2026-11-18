package vertex_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/goroute-ai/ai-gateway-go/internal/adapter/vertex"
	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/security/network"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVertexAmbientIAM_DisabledByDefault(t *testing.T) {
	_, err := vertex.NewAmbientTokenSource(vertex.AmbientADCConfig{})
	require.Error(t, err)
	assert.True(t, errors.Is(err, vertex.ErrAmbientIAMDisabled))

	adp := vertex.NewAdapter(nil, nil)
	_, err = adp.ChatCompletion(context.Background(), &domain.Deployment{
		ID: "dep-vertex-empty",
		GlobalModel: &domain.GlobalModel{
			ID:        "vertex/gemini-2.5-flash",
			Provider:  domain.ProviderVertex,
			ModelName: "gemini-2.5-flash",
		},
		Credential: &domain.ProviderCredential{DecryptedAPIKey: ""},
	}, &domain.CanonicalChatRequest{
		Model:    "gemini-2.5-flash",
		Messages: []domain.CanonicalMessage{{Role: "user", Content: "hi"}},
	})
	require.Error(t, err)
}

func TestVertexAmbientIAM_MetadataServerAndAdapter(t *testing.T) {
	var metaCalls atomic.Int32
	metaSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		metaCalls.Add(1)
		assert.Equal(t, "Google", r.Header.Get("Metadata-Flavor"))
		assert.Equal(t, "/computeMetadata/v1/instance/service-accounts/default/token", r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "ya29.gcp-metadata-token",
			"expires_in":   3600,
			"token_type":   "Bearer",
		})
	}))
	defer metaSrv.Close()

	var vertexAuth string
	vertexSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		vertexAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"candidates":[{"content":{"role":"model","parts":[{"text":"vertex ok"}]}}],"usageMetadata":{"promptTokenCount":2,"candidatesTokenCount":2,"totalTokenCount":4}}`))
	}))
	defer vertexSrv.Close()

	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "")
	t.Setenv("VERTEX_PROJECT_ID", "gcp-proj-1")

	pol, err := network.NewPolicy(config.OutboundSSRFConfig{
		AllowPrivateNetworks: true,
		AllowInsecureHTTP:    true,
	})
	require.NoError(t, err)

	adp := vertex.NewAdapter(vertexSrv.Client(), pol)
	adp.SetAmbientADCConfig(vertex.AmbientADCConfig{
		AllowAmbientCloudIAM: true,
		MetadataHost:         metaSrv.URL,
		SSRFPolicy:           pol,
	})

	dep := &domain.Deployment{
		ID:     "dep-vertex-meta",
		Region: "us-central1",
		GlobalModel: &domain.GlobalModel{
			ID:        "vertex/gemini-2.5-flash",
			Provider:  domain.ProviderVertex,
			ModelName: "gemini-2.5-flash",
		},
		Credential: &domain.ProviderCredential{
			BaseURL:         vertexSrv.URL,
			DecryptedAPIKey: "ambient",
		},
	}
	req := &domain.CanonicalChatRequest{
		Model:    "gemini-2.5-flash",
		Messages: []domain.CanonicalMessage{{Role: "user", Content: "hi"}},
	}

	resp, err := adp.ChatCompletion(context.Background(), dep, req)
	require.NoError(t, err)
	assert.Equal(t, "vertex ok", resp.Choices[0].Message.Content)
	assert.Equal(t, "Bearer ya29.gcp-metadata-token", vertexAuth)

	// Second call hits cached token without hitting metadata server again.
	_, err = adp.ChatCompletion(context.Background(), dep, req)
	require.NoError(t, err)
	assert.Equal(t, int32(1), metaCalls.Load())
}

func TestVertexAmbientIAM_ADCFiles(t *testing.T) {
	pol, err := network.NewPolicy(config.OutboundSSRFConfig{
		AllowPrivateNetworks: true,
		AllowInsecureHTTP:    true,
	})
	require.NoError(t, err)

	t.Run("ADC authorized_user refresh token", func(t *testing.T) {
		oauthSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_ = r.ParseForm()
			assert.Equal(t, "refresh_token", r.Form.Get("grant_type"))
			assert.Equal(t, "adc-client-id", r.Form.Get("client_id"))
			assert.Equal(t, "adc-client-secret", r.Form.Get("client_secret"))
			assert.Equal(t, "adc-refresh-tok", r.Form.Get("refresh_token"))
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token": "ya29.adc-user-token",
				"expires_in":   3600,
			})
		}))
		defer oauthSrv.Close()

		adcPath := filepath.Join(t.TempDir(), "adc.json")
		require.NoError(t, os.WriteFile(adcPath, []byte(`{
			"type": "authorized_user",
			"client_id": "adc-client-id",
			"client_secret": "adc-client-secret",
			"refresh_token": "adc-refresh-tok",
			"quota_project_id": "quota-proj"
		}`), 0o600))

		ts, err := vertex.NewAmbientTokenSource(vertex.AmbientADCConfig{
			AllowAmbientCloudIAM: true,
			CredentialsFile:      adcPath,
			TokenURI:             oauthSrv.URL,
			SSRFPolicy:           pol,
		})
		require.NoError(t, err)
		tok, err := ts.GetToken(context.Background())
		require.NoError(t, err)
		assert.Equal(t, "ya29.adc-user-token", tok)
	})

	t.Run("ADC service_account file", func(t *testing.T) {
		oauthSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_ = r.ParseForm()
			assert.Equal(t, "urn:ietf:params:oauth:grant-type:jwt-bearer", r.Form.Get("grant_type"))
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token": "ya29.adc-sa-token",
				"expires_in":   3600,
			})
		}))
		defer oauthSrv.Close()

		saJSON := generateTestServiceAccountKey(t, oauthSrv.URL)
		saPath := filepath.Join(t.TempDir(), "sa.json")
		require.NoError(t, os.WriteFile(saPath, []byte(saJSON), 0o600))

		t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", saPath)
		ts, err := vertex.NewAmbientTokenSource(vertex.AmbientADCConfig{
			AllowAmbientCloudIAM: true,
			SSRFPolicy:           pol,
		})
		require.NoError(t, err)
		tok, err := ts.GetToken(context.Background())
		require.NoError(t, err)
		assert.Equal(t, "ya29.adc-sa-token", tok)
	})
}
