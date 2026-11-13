package server_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/server"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAdminPricing_PromotionUnblocksBudgetRestrictedCallers(t *testing.T) {
	ctx := context.Background()
	repo := storage.NewMemoryRepository()
	cfg := config.Default()
	cfg.Auth.MasterAdminKey = "admin_secret_key"
	cfg.Security.Network.OutboundSSRF.AllowPrivateNetworks = true
	cfg.Security.Network.OutboundSSRF.AllowInsecureHTTP = true
	redisServer := miniredis.RunT(t)

	// Mock upstream server for Cerebras
	upstreamSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{
			"id": "chatcmpl-cerebras",
			"model": "llama-3.3-70b",
			"choices": [{
				"index": 0,
				"message": {
					"role": "assistant",
					"content": "Cerebras fast response"
				},
				"finish_reason": "stop"
			}],
			"usage": {
				"prompt_tokens": 10,
				"completion_tokens": 15,
				"total_tokens": 25
			}
		}`))
	}))
	defer upstreamSrv.Close()

	redisFabric := storage.NewRedisFabric(redisServer.Addr(), "", 0)
	defer redisFabric.Client().Close()
	gw, err := server.New(cfg, repo, redisFabric, upstreamSrv.Client())
	require.NoError(t, err)

	router := gw.Handler()

	// 1. Admin imports Cerebras models from embedded catalogue
	importReq, _ := http.NewRequest(http.MethodPost, "/admin/v1/catalogue/import?provider=cerebras", nil)
	importReq.Header.Set("Authorization", "Bearer admin_secret_key")
	importRec := httptest.NewRecorder()
	router.ServeHTTP(importRec, importReq)
	require.Equal(t, http.StatusOK, importRec.Code)

	var importResp map[string]any
	_ = json.Unmarshal(importRec.Body.Bytes(), &importResp)
	importedCount, _ := importResp["imported"].(float64)
	assert.Greater(t, importedCount, 0.0)

	// Check that the imported model has pricing_status: "unknown"
	gm, err := repo.GetGlobalModel(ctx, "cerebras/llama-3.3-70b")
	require.NoError(t, err)
	require.NotNil(t, gm)
	assert.Equal(t, domain.PricingStatusUnknown, gm.PricingStatus)
	assert.Equal(t, "upstream-model-catalog-v1.1", gm.PricingProvenanceSource)

	// 2. Set up tenant organization and deployment
	org := &domain.Organization{ID: "org-pricing-test", Name: "Pricing Org", Slug: "pricing-org", IsActive: true}
	_ = repo.CreateOrganization(ctx, org)

	// Issue Virtual Key with a hard max spend budget (budget-restricted caller)
	var issuedKey domain.VirtualKey
	keyBody, _ := json.Marshal(map[string]any{
		"org_id":            org.ID,
		"name":              "budgeted-key",
		"max_budget_micros": 10_000_000, // $10.00
	})
	keyReq, _ := http.NewRequest(http.MethodPost, "/admin/v1/keys", bytes.NewReader(keyBody))
	keyReq.Header.Set("Authorization", "Bearer admin_secret_key")
	keyReq.Header.Set("Content-Type", "application/json")
	keyRec := httptest.NewRecorder()
	router.ServeHTTP(keyRec, keyReq)
	require.Equal(t, http.StatusCreated, keyRec.Code)
	_ = json.Unmarshal(keyRec.Body.Bytes(), &issuedKey)
	require.NotEmpty(t, issuedKey.RawKey)

	cred := &domain.ProviderCredential{
		ID:              "cred-cerebras-test",
		OrgID:           org.ID,
		Provider:        domain.ProviderCerebras,
		Name:            "cerebras-cred",
		BaseURL:         upstreamSrv.URL,
		DecryptedAPIKey: "csk_test_key",
		IsActive:        true,
	}
	_ = repo.CreateProviderCredential(ctx, cred)

	mg := &domain.ModelGroup{
		ID:              "mg-cerebras-llama",
		OrgID:           org.ID,
		Alias:           "cerebras-llama",
		RoutingStrategy: domain.StrategyWeightedShuffle,
		IsActive:        true,
	}
	_ = repo.CreateModelGroup(ctx, mg)

	dep := &domain.Deployment{
		ID:             "dep-cerebras-llama",
		ModelGroupID:   mg.ID,
		GlobalModelID:  gm.ID,
		CredentialID:   cred.ID,
		DeploymentName: "cerebras-llama-dep",
		Status:         domain.DeploymentStatusActive,
		Weight:         100,
	}
	_ = repo.CreateDeployment(ctx, dep)

	// Try inference from budgeted caller while pricing_status is UNKNOWN -> rejected!
	chatBody, _ := json.Marshal(map[string]any{
		"model": "cerebras-llama",
		"messages": []map[string]string{
			{"role": "user", "content": "Hello"},
		},
	})
	chatReq, _ := http.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(chatBody))
	chatReq.Header.Set("Content-Type", "application/json")
	chatReq.Header.Set("Authorization", "Bearer "+issuedKey.RawKey)
	chatRec := httptest.NewRecorder()
	router.ServeHTTP(chatRec, chatReq)
	// Must fail closed because all deployments have unverified pricing
	assert.Equal(t, http.StatusForbidden, chatRec.Code)
	assert.Contains(t, chatRec.Body.String(), "pricing_unknown_budget_restricted")

	// 3. Admin promotes pricing to "verified" via POST /admin/v1/catalogue/pricing
	updatePricingBody, _ := json.Marshal(map[string]any{
		"global_model_id":                 gm.ID,
		"input_cost_micros_per_1m":        200,
		"output_cost_micros_per_1m":       400,
		"cached_input_cost_micros_per_1m": 100,
		"reasoning_cost_micros_per_1m":    0,
		"pricing_status":                  "verified",
		"pricing_provenance_source":       "admin-verified-nov-2026",
		"pricing_effective_date":          time.Now().Format("2006-01-02"),
		"changed_by":                      "admin_qaadir",
	})
	updatePricingReq, _ := http.NewRequest(http.MethodPost, "/admin/v1/catalogue/pricing", bytes.NewReader(updatePricingBody))
	updatePricingReq.Header.Set("Authorization", "Bearer admin_secret_key")
	updatePricingReq.Header.Set("Content-Type", "application/json")
	updatePricingRec := httptest.NewRecorder()
	router.ServeHTTP(updatePricingRec, updatePricingReq)
	require.Equal(t, http.StatusOK, updatePricingRec.Code)

	// Verify model pricing in repo
	gmUpdated, err := repo.GetGlobalModel(ctx, gm.ID)
	require.NoError(t, err)
	assert.Equal(t, domain.PricingStatusVerified, gmUpdated.PricingStatus)
	assert.Equal(t, "admin-verified-nov-2026", gmUpdated.PricingProvenanceSource)
	assert.Equal(t, 2, gmUpdated.PricingVersion)

	// Verify audit history record in repo
	history, err := repo.ListModelPricingHistory(ctx, gm.ID)
	require.NoError(t, err)
	require.Len(t, history, 2)
	latestHist := history[len(history)-1]
	assert.Equal(t, domain.PricingStatusVerified, latestHist.PricingStatus)
	assert.Equal(t, "admin-verified-nov-2026", latestHist.PricingProvenanceSource)

	// 4. Budget-restricted caller immediately succeeds!
	chatReq2, _ := http.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(chatBody))
	chatReq2.Header.Set("Content-Type", "application/json")
	chatReq2.Header.Set("Authorization", "Bearer "+issuedKey.RawKey)
	chatRec2 := httptest.NewRecorder()
	router.ServeHTTP(chatRec2, chatReq2)
	assert.Equal(t, http.StatusOK, chatRec2.Code)
	assert.Contains(t, chatRec2.Body.String(), "Cerebras fast response")
}
