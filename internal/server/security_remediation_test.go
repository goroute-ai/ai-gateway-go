package server_test

import (
	"bytes"
	"context"
	"encoding/json"
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

func TestAdminCredentialBaseURL_SSRFAndSyntaxValidation(t *testing.T) {
	ctx := context.Background()
	repo := storage.NewMemoryRepository()
	cfg := config.Default()
	cfg.Auth.MasterAdminKey = "admin_master_secret"
	// Keep strict defaults: AllowPrivateNetworks=false, AllowInsecureHTTP=false

	gw, err := server.New(cfg, repo, nil, nil)
	require.NoError(t, err)
	h := gw.Handler()

	org := &domain.Organization{ID: "org-ssrf", Name: "SSRF Org", Slug: "ssrf-org", IsActive: true}
	require.NoError(t, repo.CreateOrganization(ctx, org))

	badURLs := []string{
		"http://169.254.169.254/latest/meta-data",
		"http://127.0.0.1:8080/v1",
		"https://user:pass@api.openai.com/v1",
		"https://api.openai.com/v1?token=leak",
	}

	for _, bad := range badURLs {
		t.Run("create_rejects_"+bad, func(t *testing.T) {
			body, _ := json.Marshal(map[string]any{
				"org_id":   org.ID,
				"provider": "openai",
				"name":     "bad-cred",
				"base_url": bad,
				"api_key":  "sk-test",
			})
			req := httptest.NewRequest(http.MethodPost, "/admin/v1/credentials", bytes.NewReader(body))
			req.Header.Set("Authorization", "Bearer admin_master_secret")
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			assert.Equal(t, http.StatusBadRequest, rec.Code)
			assert.Contains(t, rec.Body.String(), "invalid_base_url")
		})

		t.Run("preflight_rejects_"+bad, func(t *testing.T) {
			body, _ := json.Marshal(map[string]any{
				"org_id":   org.ID,
				"provider": "openai",
				"base_url": bad,
				"api_key":  "sk-test",
			})
			req := httptest.NewRequest(http.MethodPost, "/admin/v1/credentials/validate", bytes.NewReader(body))
			req.Header.Set("Authorization", "Bearer admin_master_secret")
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			assert.Equal(t, http.StatusBadRequest, rec.Code)
			assert.Contains(t, rec.Body.String(), "invalid_base_url")
		})
	}

	// Valid public HTTPS credential succeeds, then rotate with bad BaseURL fails without overwriting.
	createBody, _ := json.Marshal(map[string]any{
		"org_id":   org.ID,
		"provider": "openai",
		"name":     "good-cred",
		"base_url": "https://api.openai.com/v1",
		"api_key":  "sk-good-1",
	})
	createReq := httptest.NewRequest(http.MethodPost, "/admin/v1/credentials", bytes.NewReader(createBody))
	createReq.Header.Set("Authorization", "Bearer admin_master_secret")
	createReq.Header.Set("Content-Type", "application/json")
	createRec := httptest.NewRecorder()
	h.ServeHTTP(createRec, createReq)
	require.Equal(t, http.StatusCreated, createRec.Code)

	var created domain.ProviderCredential
	require.NoError(t, json.Unmarshal(createRec.Body.Bytes(), &created))

	rotBody, _ := json.Marshal(map[string]any{
		"api_key":  "sk-good-2",
		"base_url": "http://169.254.169.254",
	})
	rotReq := httptest.NewRequest(http.MethodPost, "/admin/v1/credentials/"+created.ID+"/rotate", bytes.NewReader(rotBody))
	rotReq.Header.Set("Authorization", "Bearer admin_master_secret")
	rotReq.Header.Set("Content-Type", "application/json")
	rotRec := httptest.NewRecorder()
	h.ServeHTTP(rotRec, rotReq)
	assert.Equal(t, http.StatusBadRequest, rotRec.Code)
	assert.Contains(t, rotRec.Body.String(), "invalid_base_url")

	stored, err := repo.GetProviderCredential(ctx, created.ID)
	require.NoError(t, err)
	assert.Equal(t, "https://api.openai.com/v1", stored.BaseURL)
}

func TestAdminPreflightValidate_PrivateNetworkRequiresPlatformAdmin(t *testing.T) {
	ctx := context.Background()
	repo := storage.NewMemoryRepository()
	cfg := config.Default()
	cfg.Auth.MasterAdminKey = "admin_master_secret"
	cfg.Security.Network.OutboundSSRF.AllowPrivateNetworks = true
	cfg.Security.Network.OutboundSSRF.AllowInsecureHTTP = true

	upstreamSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"data":[{"id":"gpt-4o"}]}`))
	}))
	defer upstreamSrv.Close()

	gw, err := server.New(cfg, repo, nil, upstreamSrv.Client())
	require.NoError(t, err)
	h := gw.Handler()

	org := &domain.Organization{ID: "org-rbac-ssrf", Name: "RBAC SSRF Org", Slug: "rbac-ssrf", IsActive: true}
	require.NoError(t, repo.CreateOrganization(ctx, org))

	// Create org_admin virtual key
	keyBody, _ := json.Marshal(map[string]any{
		"org_id": org.ID,
		"name":   "org-admin-vk",
		"role":   domain.RoleOrgAdmin,
	})
	keyReq := httptest.NewRequest(http.MethodPost, "/admin/v1/keys", bytes.NewReader(keyBody))
	keyReq.Header.Set("Authorization", "Bearer admin_master_secret")
	keyReq.Header.Set("Content-Type", "application/json")
	keyRec := httptest.NewRecorder()
	h.ServeHTTP(keyRec, keyReq)
	require.Equal(t, http.StatusCreated, keyRec.Code)

	var orgAdminVK domain.VirtualKey
	require.NoError(t, json.Unmarshal(keyRec.Body.Bytes(), &orgAdminVK))
	require.NotEmpty(t, orgAdminVK.RawKey)

	// org_admin cannot probe arbitrary private base_url via preflight validate
	preflightBody, _ := json.Marshal(map[string]any{
		"org_id":   org.ID,
		"provider": "openai",
		"api_key":  "sk-test",
		"base_url": upstreamSrv.URL,
	})
	req := httptest.NewRequest(http.MethodPost, "/admin/v1/credentials/validate", bytes.NewReader(preflightBody))
	req.Header.Set("Authorization", "Bearer "+orgAdminVK.RawKey)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Contains(t, rec.Body.String(), "platform_admin_required")

	// platform_admin can still validate private upstream URLs
	adminReq := httptest.NewRequest(http.MethodPost, "/admin/v1/credentials/validate", bytes.NewReader(preflightBody))
	adminReq.Header.Set("Authorization", "Bearer admin_master_secret")
	adminReq.Header.Set("Content-Type", "application/json")
	adminRec := httptest.NewRecorder()
	h.ServeHTTP(adminRec, adminReq)
	assert.Equal(t, http.StatusOK, adminRec.Code)

	// org_admin cannot create a credential pointing to a private base_url either.
	createPrivateBody, _ := json.Marshal(map[string]any{
		"org_id":   org.ID,
		"provider": "openai",
		"name":     "org-admin-private-cred",
		"api_key":  "sk-test",
		"base_url": upstreamSrv.URL,
	})
	createReq := httptest.NewRequest(http.MethodPost, "/admin/v1/credentials", bytes.NewReader(createPrivateBody))
	createReq.Header.Set("Authorization", "Bearer "+orgAdminVK.RawKey)
	createReq.Header.Set("Content-Type", "application/json")
	createRec := httptest.NewRecorder()
	h.ServeHTTP(createRec, createReq)
	assert.Equal(t, http.StatusForbidden, createRec.Code)
	assert.Contains(t, createRec.Body.String(), "platform_admin_required")

	// platform_admin creates a private-URL credential; org_admin must still be blocked from validating or rotating it to a private base_url.
	adminCreateReq := httptest.NewRequest(http.MethodPost, "/admin/v1/credentials", bytes.NewReader(createPrivateBody))
	adminCreateReq.Header.Set("Authorization", "Bearer admin_master_secret")
	adminCreateReq.Header.Set("Content-Type", "application/json")
	adminCreateRec := httptest.NewRecorder()
	h.ServeHTTP(adminCreateRec, adminCreateReq)
	require.Equal(t, http.StatusCreated, adminCreateRec.Code)

	var createdPriv domain.ProviderCredential
	require.NoError(t, json.Unmarshal(adminCreateRec.Body.Bytes(), &createdPriv))

	validateStoredReq := httptest.NewRequest(http.MethodPost, "/admin/v1/credentials/"+createdPriv.ID+"/validate", nil)
	validateStoredReq.Header.Set("Authorization", "Bearer "+orgAdminVK.RawKey)
	validateStoredRec := httptest.NewRecorder()
	h.ServeHTTP(validateStoredRec, validateStoredReq)
	assert.Equal(t, http.StatusForbidden, validateStoredRec.Code)
	assert.Contains(t, validateStoredRec.Body.String(), "platform_admin_required")

	rotateBody, _ := json.Marshal(map[string]any{
		"api_key":  "sk-rotated",
		"base_url": upstreamSrv.URL,
	})
	rotateReq := httptest.NewRequest(http.MethodPost, "/admin/v1/credentials/"+createdPriv.ID+"/rotate", bytes.NewReader(rotateBody))
	rotateReq.Header.Set("Authorization", "Bearer "+orgAdminVK.RawKey)
	rotateReq.Header.Set("Content-Type", "application/json")
	rotateRec := httptest.NewRecorder()
	h.ServeHTTP(rotateRec, rotateReq)
	assert.Equal(t, http.StatusForbidden, rotateRec.Code)
	assert.Contains(t, rotateRec.Body.String(), "platform_admin_required")

	// platform_admin validation of stored private credential succeeds.
	adminValidateStoredReq := httptest.NewRequest(http.MethodPost, "/admin/v1/credentials/"+createdPriv.ID+"/validate", nil)
	adminValidateStoredReq.Header.Set("Authorization", "Bearer admin_master_secret")
	adminValidateStoredRec := httptest.NewRecorder()
	h.ServeHTTP(adminValidateStoredRec, adminValidateStoredReq)
	assert.Equal(t, http.StatusOK, adminValidateStoredRec.Code)
}

func TestGenerateSpeech_ContentTypeSanitization(t *testing.T) {
	ctx := context.Background()
	repo := storage.NewMemoryRepository()
	cfg := config.Default()
	cfg.Auth.MasterAdminKey = "admin_master_secret"
	cfg.Security.Network.OutboundSSRF.AllowPrivateNetworks = true
	cfg.Security.Network.OutboundSSRF.AllowInsecureHTTP = true

	upstreamContentType := "text/html; charset=utf-8"
	audioSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", upstreamContentType)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("fake-audio-payload"))
	}))
	defer audioSrv.Close()

	gw, err := server.New(cfg, repo, nil, audioSrv.Client())
	require.NoError(t, err)
	h := gw.Handler()

	org := &domain.Organization{ID: "org-tts-ct", Name: "TTS CT Org", Slug: "tts-ct-org", IsActive: true}
	require.NoError(t, repo.CreateOrganization(ctx, org))

	keyBody, _ := json.Marshal(map[string]any{"org_id": org.ID, "name": "tts-vk"})
	keyReq := httptest.NewRequest(http.MethodPost, "/admin/v1/keys", bytes.NewReader(keyBody))
	keyReq.Header.Set("Authorization", "Bearer admin_master_secret")
	keyReq.Header.Set("Content-Type", "application/json")
	keyRec := httptest.NewRecorder()
	h.ServeHTTP(keyRec, keyReq)
	require.Equal(t, http.StatusCreated, keyRec.Code)
	var issuedKey domain.VirtualKey
	require.NoError(t, json.Unmarshal(keyRec.Body.Bytes(), &issuedKey))

	credBody, _ := json.Marshal(map[string]any{
		"org_id":   org.ID,
		"provider": "openai",
		"name":     "openai-tts",
		"base_url": audioSrv.URL + "/v1",
		"api_key":  "sk-tts",
	})
	credReq := httptest.NewRequest(http.MethodPost, "/admin/v1/credentials", bytes.NewReader(credBody))
	credReq.Header.Set("Authorization", "Bearer admin_master_secret")
	credReq.Header.Set("Content-Type", "application/json")
	credRec := httptest.NewRecorder()
	h.ServeHTTP(credRec, credReq)
	require.Equal(t, http.StatusCreated, credRec.Code)
	var cred domain.ProviderCredential
	require.NoError(t, json.Unmarshal(credRec.Body.Bytes(), &cred))

	ttsGM := &domain.GlobalModel{
		ID:                           "openai/tts-1",
		Provider:                     domain.ProviderOpenAI,
		ModelName:                    "tts-1",
		DisplayName:                  "TTS 1",
		SupportsInference:            true,
		LifecycleStatus:              domain.ModelStatusActive,
		PricingStatus:                domain.PricingStatusVerified,
		AudioTTSCostMicrosPer1KChars: 15,
		Capabilities:                 domain.ModelCapabilities{AudioTTS: domain.CapabilitySupported},
	}
	require.NoError(t, repo.UpsertGlobalModel(ctx, ttsGM))
	require.NoError(t, repo.CreateModelGroup(ctx, &domain.ModelGroup{
		ID:              "mg-tts-ct",
		OrgID:           org.ID,
		Alias:           "tts-1",
		RoutingStrategy: domain.StrategyWeightedShuffle,
		IsActive:        true,
	}))
	require.NoError(t, repo.CreateDeployment(ctx, &domain.Deployment{
		ID:             "dep-tts-ct",
		ModelGroupID:   "mg-tts-ct",
		GlobalModelID:  ttsGM.ID,
		CredentialID:   cred.ID,
		DeploymentName: "tts-dep",
		Status:         domain.DeploymentStatusActive,
		GlobalModel:    ttsGM,
		Credential:     &cred,
	}))

	speechPayload := []byte(`{"model":"tts-1","input":"hello","voice":"alloy"}`)

	t.Run("rejects text/html from upstream and defaults to audio/mpeg", func(t *testing.T) {
		upstreamContentType = "text/html; charset=utf-8"
		req := httptest.NewRequest(http.MethodPost, "/v1/audio/speech", bytes.NewReader(speechPayload))
		req.Header.Set("Authorization", "Bearer "+issuedKey.RawKey)
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		require.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "audio/mpeg", rec.Header().Get("Content-Type"))
	})

	t.Run("preserves safe audio content-type from upstream", func(t *testing.T) {
		upstreamContentType = "audio/ogg"
		req := httptest.NewRequest(http.MethodPost, "/v1/audio/speech", bytes.NewReader(speechPayload))
		req.Header.Set("Authorization", "Bearer "+issuedKey.RawKey)
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		require.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "audio/ogg", rec.Header().Get("Content-Type"))
	})
}
