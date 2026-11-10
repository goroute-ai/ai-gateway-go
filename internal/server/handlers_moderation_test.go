package server_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/server"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestModerationEndpoints(t *testing.T) {
	ctx := context.Background()
	repo := storage.NewMemoryRepository()
	cfg := config.Default()
	cfg.Auth.MasterAdminKey = "admin_secret_key"
	cfg.Security.Network.OutboundSSRF.AllowPrivateNetworks = true
	cfg.Security.Network.OutboundSSRF.AllowInsecureHTTP = true

	// Mock OpenAI upstream server for moderations
	oaiSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/v1/moderations", r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{
			"id": "modr-test-id",
			"model": "omni-moderation-latest",
			"results": [
				{
					"flagged": true,
					"categories": {
						"hate": true,
						"violence": false
					},
					"category_scores": {
						"hate": 0.98,
						"violence": 0.02
					}
				}
			]
		}`)
	}))
	defer oaiSrv.Close()

	gw, err := server.New(cfg, repo, nil, oaiSrv.Client())
	require.NoError(t, err)
	handler := gw.Handler()

	org := &domain.Organization{ID: "org-modr", Name: "Modr Org", Slug: "modr-org", IsActive: true}
	require.NoError(t, repo.CreateOrganization(ctx, org))

	// Issue Virtual Key
	var issuedKey domain.VirtualKey
	keyBody, _ := json.Marshal(map[string]any{
		"org_id": org.ID,
		"name":   "modr-key",
	})
	keyReq, _ := http.NewRequest(http.MethodPost, "/admin/v1/keys", bytes.NewReader(keyBody))
	keyReq.Header.Set("Authorization", "Bearer admin_secret_key")
	keyReq.Header.Set("Content-Type", "application/json")
	keyRec := httptest.NewRecorder()
	handler.ServeHTTP(keyRec, keyReq)
	require.Equal(t, http.StatusCreated, keyRec.Code)
	_ = json.Unmarshal(keyRec.Body.Bytes(), &issuedKey)
	require.NotEmpty(t, issuedKey.RawKey)

	// Create Global Model with Moderation capability
	gm := &domain.GlobalModel{
		ID:                "openai/omni-moderation-latest",
		Provider:          domain.ProviderOpenAI,
		ModelName:         "omni-moderation-latest",
		DisplayName:       "Omni Moderation Latest",
		SupportsInference: true,
		LifecycleStatus:   domain.ModelStatusActive,
		PricingStatus:     domain.PricingStatusVerified,
		Capabilities: domain.ModelCapabilities{
			Moderation: domain.CapabilitySupported,
		},
	}
	require.NoError(t, repo.UpsertGlobalModel(ctx, gm))

	// Create Credential via admin API
	var cred domain.ProviderCredential
	credBody, _ := json.Marshal(map[string]any{
		"org_id":   org.ID,
		"provider": "openai",
		"name":     "openai-cred",
		"base_url": oaiSrv.URL + "/v1",
		"api_key":  "sk-openai",
	})
	credReq, _ := http.NewRequest(http.MethodPost, "/admin/v1/credentials", bytes.NewReader(credBody))
	credReq.Header.Set("Authorization", "Bearer admin_secret_key")
	credReq.Header.Set("Content-Type", "application/json")
	credRec := httptest.NewRecorder()
	handler.ServeHTTP(credRec, credReq)
	require.Equal(t, http.StatusCreated, credRec.Code)
	_ = json.Unmarshal(credRec.Body.Bytes(), &cred)

	mg := &domain.ModelGroup{
		ID:              "mg-openai-modr",
		OrgID:           org.ID,
		Alias:           "omni-moderation-latest",
		RoutingStrategy: domain.StrategyWeightedShuffle,
		IsActive:        true,
	}
	require.NoError(t, repo.CreateModelGroup(ctx, mg))

	dep := &domain.Deployment{
		ID:             "dep-openai-modr",
		ModelGroupID:   mg.ID,
		GlobalModelID:  gm.ID,
		CredentialID:   cred.ID,
		DeploymentName: "openai-modr-1",
		Status:         domain.DeploymentStatusActive,
		GlobalModel:    gm,
		Credential:     &cred,
	}
	require.NoError(t, repo.CreateDeployment(ctx, dep))

	// Test endpoints: /v1/moderations and /moderations
	endpoints := []string{"/v1/moderations", "/moderations"}

	for _, ep := range endpoints {
		t.Run(ep, func(t *testing.T) {
			reqPayload := map[string]any{
				"model": "omni-moderation-latest",
				"input": "test prompt for moderation analysis",
			}
			reqBytes, _ := json.Marshal(reqPayload)
			httpReq, _ := http.NewRequest(http.MethodPost, ep, bytes.NewReader(reqBytes))
			httpReq.Header.Set("Authorization", "Bearer "+issuedKey.RawKey)
			httpReq.Header.Set("Content-Type", "application/json")

			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, httpReq)

			require.Equal(t, http.StatusOK, rec.Code, "Response: %s", rec.Body.String())
			assert.Equal(t, "openai", rec.Header().Get("X-Gateway-Provider"))

			var resp domain.CanonicalModerationResponse
			err = json.Unmarshal(rec.Body.Bytes(), &resp)
			require.NoError(t, err)
			assert.Equal(t, "modr-test-id", resp.ID)
			assert.Len(t, resp.Results, 1)
			assert.True(t, resp.Results[0].Flagged)
			assert.True(t, resp.Results[0].Categories["hate"])
			assert.Equal(t, 0.98, resp.Results[0].CategoryScores["hate"])
		})
	}
}
