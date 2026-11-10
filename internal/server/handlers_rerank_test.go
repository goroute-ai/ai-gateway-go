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

func TestRerankEndpoints(t *testing.T) {
	ctx := context.Background()
	repo := storage.NewMemoryRepository()
	cfg := config.Default()
	cfg.Auth.MasterAdminKey = "admin_secret_key"
	cfg.Security.Network.OutboundSSRF.AllowPrivateNetworks = true
	cfg.Security.Network.OutboundSSRF.AllowInsecureHTTP = true

	// Mock Cohere upstream server
	cohereSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/v2/rerank", r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{
			"id": "rerank-test-id",
			"results": [
				{"index": 0, "relevance_score": 0.99},
				{"index": 1, "relevance_score": 0.45}
			],
			"meta": {
				"billed_units": {"search_units": 1}
			}
		}`)
	}))
	defer cohereSrv.Close()

	gw, err := server.New(cfg, repo, nil, cohereSrv.Client())
	require.NoError(t, err)
	handler := gw.Handler()

	org := &domain.Organization{ID: "org-rerank", Name: "Rerank Org", Slug: "rerank-org", IsActive: true}
	require.NoError(t, repo.CreateOrganization(ctx, org))

	// Issue Virtual Key
	var issuedKey domain.VirtualKey
	keyBody, _ := json.Marshal(map[string]any{
		"org_id": org.ID,
		"name":   "rerank-key",
	})
	keyReq, _ := http.NewRequest(http.MethodPost, "/admin/v1/keys", bytes.NewReader(keyBody))
	keyReq.Header.Set("Authorization", "Bearer admin_secret_key")
	keyReq.Header.Set("Content-Type", "application/json")
	keyRec := httptest.NewRecorder()
	handler.ServeHTTP(keyRec, keyReq)
	require.Equal(t, http.StatusCreated, keyRec.Code)
	_ = json.Unmarshal(keyRec.Body.Bytes(), &issuedKey)
	require.NotEmpty(t, issuedKey.RawKey)

	// Create Global Model with Rerank capability and search unit pricing
	gm := &domain.GlobalModel{
		ID:                            "cohere/rerank-v3.5",
		Provider:                      domain.ProviderCohere,
		ModelName:                     "rerank-v3.5",
		DisplayName:                   "Cohere Rerank v3.5",
		SupportsInference:             true,
		LifecycleStatus:               domain.ModelStatusActive,
		PricingStatus:                 domain.PricingStatusVerified,
		RerankCostMicrosPerSearchUnit: 2000, // 0.002 per search unit = 2000 micros
		Capabilities: domain.ModelCapabilities{
			Rerank: domain.CapabilitySupported,
		},
	}
	require.NoError(t, repo.UpsertGlobalModel(ctx, gm))

	// Create Credential via admin API
	var cred domain.ProviderCredential
	credBody, _ := json.Marshal(map[string]any{
		"org_id":   org.ID,
		"provider": "cohere",
		"name":     "cohere-cred",
		"base_url": cohereSrv.URL,
		"api_key":  "cohere-test-key",
	})
	credReq, _ := http.NewRequest(http.MethodPost, "/admin/v1/credentials", bytes.NewReader(credBody))
	credReq.Header.Set("Authorization", "Bearer admin_secret_key")
	credReq.Header.Set("Content-Type", "application/json")
	credRec := httptest.NewRecorder()
	handler.ServeHTTP(credRec, credReq)
	require.Equal(t, http.StatusCreated, credRec.Code)
	_ = json.Unmarshal(credRec.Body.Bytes(), &cred)

	mg := &domain.ModelGroup{
		ID:              "mg-cohere-rerank",
		OrgID:           org.ID,
		Alias:           "rerank-v3.5",
		RoutingStrategy: domain.StrategyWeightedShuffle,
		IsActive:        true,
	}
	require.NoError(t, repo.CreateModelGroup(ctx, mg))

	dep := &domain.Deployment{
		ID:             "dep-cohere-rerank",
		ModelGroupID:   mg.ID,
		GlobalModelID:  gm.ID,
		CredentialID:   cred.ID,
		DeploymentName: "cohere-rerank-1",
		Status:         domain.DeploymentStatusActive,
		GlobalModel:    gm,
		Credential:     &cred,
	}
	require.NoError(t, repo.CreateDeployment(ctx, dep))

	// Test endpoints: /v1/rerank, /rerank, and /v2/rerank
	endpoints := []string{"/v1/rerank", "/rerank", "/v2/rerank"}

	for _, ep := range endpoints {
		t.Run(ep, func(t *testing.T) {
			reqPayload := map[string]any{
				"model": "rerank-v3.5",
				"query": "machine learning in medicine",
				"documents": []string{
					"Deep learning models diagnose disease from radiology images.",
					"The history of Roman architecture.",
				},
				"top_n": 2,
			}
			reqBytes, _ := json.Marshal(reqPayload)
			httpReq, _ := http.NewRequest(http.MethodPost, ep, bytes.NewReader(reqBytes))
			httpReq.Header.Set("Authorization", "Bearer "+issuedKey.RawKey)
			httpReq.Header.Set("Content-Type", "application/json")

			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, httpReq)

			require.Equal(t, http.StatusOK, rec.Code, "Response: %s", rec.Body.String())
			assert.Equal(t, "cohere", rec.Header().Get("X-Gateway-Provider"))
			assert.Equal(t, "2000", rec.Header().Get("X-Gateway-Cost-Micros"))

			var resp domain.CanonicalRerankResponse
			err = json.Unmarshal(rec.Body.Bytes(), &resp)
			require.NoError(t, err)
			assert.Equal(t, "rerank-test-id", resp.ID)
			assert.Len(t, resp.Results, 2)
			assert.Equal(t, 0.99, resp.Results[0].RelevanceScore)
			assert.Equal(t, 1, resp.Usage.SearchUnits)
		})
	}
}
