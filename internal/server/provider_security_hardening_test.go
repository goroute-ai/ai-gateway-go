// Provider security hardening tests cover gateway-wide data-plane and
// control-plane protections:
//   - Estimated-token fallback billing when upstream embedding responses omit usage.
//   - Platform-admin gating on loopback/insecure-HTTP custom BaseURLs plus
//     credential header validation and response/audit redaction.
//   - Bounded request bodies (413) and strict element typing across JSON endpoints.

package server_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/goroute-ai/ai-gateway-go/internal/auth"
	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/server"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGeminiEmbeddings_ZeroUsageFallbackBillingAndBodyLimits(t *testing.T) {
	ctx := context.Background()
	repo := storage.NewMemoryRepository()
	mr := miniredis.RunT(t)
	rf := storage.NewRedisFabric(mr.Addr(), "", 0)
	if c := rf.Client(); c != nil {
		defer c.Close()
	}

	// Mock Gemini :embedContent returning a valid vector with NO usageMetadata (matching live Google behavior).
	gemUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"embedding":{"values":[0.1,0.2,0.3,0.4]}}`))
	}))
	defer gemUpstream.Close()

	cfg := config.Default()
	cfg.Auth.MasterAdminKey = "sk-gw-master-gem-sec-test"
	cfg.RateLimit.Enabled = true
	cfg.Security.Network.OutboundSSRF.AllowPrivateNetworks = true
	cfg.Security.Network.OutboundSSRF.AllowInsecureHTTP = true

	// Seed an org with a 60,000 µ$ budget and a model priced at $100/1M (100 µ$/token):
	// call #1 (~516 bytes -> ~51,600 µ$ worst-case pre-flight lease <= 60,000 µ$) succeeds and settles
	// ~13,000 µ$ via estTokens fallback, leaving ~47,000 µ$, so call #2 (~51,600 µ$ lease) is rejected with 429.
	org := &domain.Organization{
		ID:              "org-gem-sec",
		Name:            "Gemini FinOps Org",
		Slug:            "org-gem-sec",
		MaxBudgetMicros: 60_000,
		IsActive:        true,
	}
	require.NoError(t, repo.CreateOrganization(ctx, org))
	require.NoError(t, repo.SetOrgProviderSubscription(ctx, &domain.OrgProviderSubscription{
		OrgID:     org.ID,
		Provider:  domain.ProviderGemini,
		IsEnabled: true,
	}))
	require.NoError(t, repo.UpsertGlobalModel(ctx, &domain.GlobalModel{
		ID:                   "gemini/gemini-embedding-001",
		Provider:             domain.ProviderGemini,
		ModelName:            "gemini-embedding-001",
		DisplayName:          "Gemini Embedding 001",
		MaxInputTokens:       2048,
		MaxOutputTokens:      3072,
		SupportsEmbeddings:   true,
		SupportsInference:    true,
		SupportedOperations:  []domain.OperationType{domain.OperationEmbedding},
		Capabilities:         domain.ModelCapabilities{Embeddings: domain.CapabilitySupported},
		InputCostMicrosPer1M: 100_000_000,
		PricingVersion:       1,
		PricingStatus:        domain.PricingStatusVerified,
		LifecycleStatus:      domain.ModelStatusActive,
	}))

	gw, err := server.New(cfg, repo, rf, nil)
	require.NoError(t, err)
	gw.StartWorkers(ctx)
	defer gw.Shutdown(ctx)

	// Create Gemini credential via admin API
	credBody, _ := json.Marshal(map[string]any{
		"org_id":   org.ID,
		"provider": "gemini",
		"name":     "gem-emb-cred",
		"base_url": gemUpstream.URL,
		"api_key":  "synthetic-gemini-key",
	})
	cReq := httptest.NewRequest(http.MethodPost, "/admin/v1/credentials", bytes.NewReader(credBody))
	cReq.Header.Set("Authorization", "Bearer "+cfg.Auth.MasterAdminKey)
	cRec := httptest.NewRecorder()
	gw.Handler().ServeHTTP(cRec, cReq)
	require.Equal(t, http.StatusCreated, cRec.Code, cRec.Body.String())

	// Create a data-plane virtual key
	rawVK := "sk-gw-gem-sec-embed-key-1234567890"
	require.NoError(t, repo.CreateVirtualKey(ctx, &domain.VirtualKey{
		ID:               "vk-gem-emb",
		OrgID:            org.ID,
		Name:             "gem-emb-vk",
		KeyPrefix:        rawVK[:14],
		KeyHash:          auth.HashKey(rawVK),
		Role:             domain.RoleDeveloper,
		AllowedModels:    []string{"*"},
		AllowedEndpoints: []string{"/v1/embeddings", "/v1/chat/completions"},
		IsActive:         true,
	}))

	// SEC-04: Oversized embedding body (> 10 MiB) rejected with 413 request_body_too_large
	hugeBody := `{"model":"gemini/gemini-embedding-001","input":"` + strings.Repeat("a", (10<<20)+1024) + `"}`
	bigReq := httptest.NewRequest(http.MethodPost, "/v1/embeddings", strings.NewReader(hugeBody))
	bigReq.Header.Set("Authorization", "Bearer "+rawVK)
	bigRec := httptest.NewRecorder()
	gw.Handler().ServeHTTP(bigRec, bigReq)
	assert.Equal(t, http.StatusRequestEntityTooLarge, bigRec.Code, bigRec.Body.String())

	// SEC-04: Batch > 2048 items rejected with 400 invalid_embedding_batch_size
	hugeBatch := make([]string, 2049)
	for i := range hugeBatch {
		hugeBatch[i] = "x"
	}
	batchBytes, _ := json.Marshal(map[string]any{
		"model": "gemini/gemini-embedding-001",
		"input": hugeBatch,
	})
	batchReq := httptest.NewRequest(http.MethodPost, "/v1/embeddings", bytes.NewReader(batchBytes))
	batchReq.Header.Set("Authorization", "Bearer "+rawVK)
	batchRec := httptest.NewRecorder()
	gw.Handler().ServeHTTP(batchRec, batchReq)
	assert.Equal(t, http.StatusBadRequest, batchRec.Code, batchRec.Body.String())
	assert.Contains(t, batchRec.Body.String(), "invalid_embedding_batch_size")

	// SEC-02: Valid Gemini embedding call with zero upstream usage falls back to estTokens and bills > 0 micro-dollars
	embPayload, _ := json.Marshal(map[string]any{
		"model": "gemini/gemini-embedding-001",
		"input": strings.Repeat("hello world embedding billing verification ", 12),
	})
	embReq := httptest.NewRequest(http.MethodPost, "/v1/embeddings", bytes.NewReader(embPayload))
	embReq.Header.Set("Authorization", "Bearer "+rawVK)
	embRec := httptest.NewRecorder()
	gw.Handler().ServeHTTP(embRec, embReq)
	require.Equal(t, http.StatusOK, embRec.Code, embRec.Body.String())

	costMicros, err := strconv.ParseInt(embRec.Header().Get("X-Gateway-Cost-Micros"), 10, 64)
	require.NoError(t, err)
	assert.Greater(t, costMicros, int64(0), "SEC-02: Gemini embedding must record non-zero micro-dollar cost via estTokens fallback")

	var embResp domain.CanonicalEmbeddingResponse
	require.NoError(t, json.Unmarshal(embRec.Body.Bytes(), &embResp))
	assert.Greater(t, embResp.Usage.PromptTokens, 0, "SEC-02: response usage.prompt_tokens must reflect estimated tokens")
	assert.Greater(t, embResp.Usage.TotalTokens, 0, "SEC-02: response usage.total_tokens must reflect estimated tokens")

	// Second call with a distinct input (avoids response cache) must now be blocked by the exhausted hard budget.
	embPayload2, _ := json.Marshal(map[string]any{
		"model": "gemini/gemini-embedding-001",
		"input": strings.Repeat("second distinct prompt exceeding remaining micro-dollar budget ", 12),
	})
	embReq2 := httptest.NewRequest(http.MethodPost, "/v1/embeddings", bytes.NewReader(embPayload2))
	embReq2.Header.Set("Authorization", "Bearer "+rawVK)
	embRec2 := httptest.NewRecorder()
	gw.Handler().ServeHTTP(embRec2, embReq2)
	assert.Equal(t, http.StatusTooManyRequests, embRec2.Code, "SEC-02: second call must fail closed once estimated embedding spend exhausts hard budget: %s", embRec2.Body.String())
}

func TestAdminCredentials_LoopbackRBAC_HeaderValidation_AndRedaction(t *testing.T) {
	ctx := context.Background()
	repo := storage.NewMemoryRepository()

	org := &domain.Organization{ID: "org-cred-sec", Name: "Cred Sec Org", Slug: "org-cred-sec", IsActive: true}
	require.NoError(t, repo.CreateOrganization(ctx, org))

	// Create org_admin and org_viewer virtual keys for RBAC testing
	orgAdminKey := "sk-gw-org-admin-sec-key-1234567890"
	require.NoError(t, repo.CreateVirtualKey(ctx, &domain.VirtualKey{
		ID:        "vk-org-admin",
		OrgID:     org.ID,
		Name:      "org-admin-vk",
		KeyPrefix: orgAdminKey[:14],
		KeyHash:   auth.HashKey(orgAdminKey),
		Role:      domain.RoleOrgAdmin,
		IsActive:  true,
	}))
	orgViewerKey := "sk-gw-org-viewer-sec-key-123456789"
	require.NoError(t, repo.CreateVirtualKey(ctx, &domain.VirtualKey{
		ID:        "vk-org-viewer",
		OrgID:     org.ID,
		Name:      "org-viewer-vk",
		KeyPrefix: orgViewerKey[:14],
		KeyHash:   auth.HashKey(orgViewerKey),
		Role:      domain.RoleOrgViewer,
		IsActive:  true,
	}))

	cfg := config.Default()
	cfg.Auth.MasterAdminKey = "sk-gw-master-cred-sec-test"
	cfg.Security.Network.OutboundSSRF.AllowLoopbackHTTP = true

	gw, err := server.New(cfg, repo, nil, nil)
	require.NoError(t, err)

	// SEC-05: org_admin MUST be rejected with 403 platform_admin_required when AllowLoopbackHTTP=true
	loopbackCredBody := `{"org_id":"org-cred-sec","provider":"gemini","name":"loopback-attempt","base_url":"http://127.0.0.1:9999","api_key":"synthetic-key"}`
	req := httptest.NewRequest(http.MethodPost, "/admin/v1/credentials", strings.NewReader(loopbackCredBody))
	req.Header.Set("Authorization", "Bearer "+orgAdminKey)
	rec := httptest.NewRecorder()
	gw.Handler().ServeHTTP(rec, req)
	assert.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
	assert.Contains(t, rec.Body.String(), "platform_admin_required")

	// SEC-05: platform_admin (MasterAdminKey) IS allowed to create loopback custom BaseURL when AllowLoopbackHTTP=true
	// SEC-08 & S2-02: Reserved/hop-by-hop/auth/CRLF headers are rejected with 400 invalid_credential_header
	for _, badHeaders := range []map[string]string{
		{"Host": "evil.example.com"},
		{"Transfer-Encoding": "chunked"},
		{"Content-Type": "text/plain"},
		{"traceparent": "00-evil-00"},
		{"X-Goog-Api-Key": "spoofed"},
		{"X-Api-Key": "spoofed-anthropic"},
		{"Api-Key": "spoofed-azure"},
		{"X-Injected": "val\r\nEvil: true"},
	} {
		payload, _ := json.Marshal(map[string]any{
			"org_id":   org.ID,
			"provider": "gemini",
			"name":     "bad-hdr-cred",
			"api_key":  "synthetic-key",
			"headers":  badHeaders,
		})
		hReq := httptest.NewRequest(http.MethodPost, "/admin/v1/credentials", bytes.NewReader(payload))
		hReq.Header.Set("Authorization", "Bearer "+cfg.Auth.MasterAdminKey)
		hRec := httptest.NewRecorder()
		gw.Handler().ServeHTTP(hRec, hReq)
		assert.Equal(t, http.StatusBadRequest, hRec.Code, "headers %v must be rejected: %s", badHeaders, hRec.Body.String())
		assert.Contains(t, hRec.Body.String(), "invalid_credential_header")
	}

	// SEC-08: Valid custom header is stored in repo, REDACTED in POST response, GET list (org_viewer), and audit log diffs
	secretHeaderVal := "super-secret-proxy-token-98765"
	validPayload, _ := json.Marshal(map[string]any{
		"org_id":   org.ID,
		"provider": "gemini",
		"name":     "valid-hdr-cred",
		"base_url": "http://127.0.0.1:9999",
		"api_key":  "synthetic-key",
		"headers":  map[string]string{"X-Corp-Proxy-Token": secretHeaderVal},
	})
	createReq := httptest.NewRequest(http.MethodPost, "/admin/v1/credentials", bytes.NewReader(validPayload))
	createReq.Header.Set("Authorization", "Bearer "+cfg.Auth.MasterAdminKey)
	createRec := httptest.NewRecorder()
	gw.Handler().ServeHTTP(createRec, createReq)
	require.Equal(t, http.StatusCreated, createRec.Code, createRec.Body.String())
	assert.NotContains(t, createRec.Body.String(), secretHeaderVal, "SEC-08: POST response must redact custom header values")
	assert.Contains(t, createRec.Body.String(), "[REDACTED]")

	// GET /admin/v1/credentials as org_viewer must NOT leak secretHeaderVal
	listReq := httptest.NewRequest(http.MethodGet, "/admin/v1/credentials?org_id="+org.ID, nil)
	listReq.Header.Set("Authorization", "Bearer "+orgViewerKey)
	listRec := httptest.NewRecorder()
	gw.Handler().ServeHTTP(listRec, listReq)
	require.Equal(t, http.StatusOK, listRec.Code, listRec.Body.String())
	assert.NotContains(t, listRec.Body.String(), secretHeaderVal, "SEC-08: org_viewer GET /credentials must redact custom header values")
	assert.Contains(t, listRec.Body.String(), "[REDACTED]")

	// Stored credential in repository retains real header value for upstream dispatch
	storedCreds, err := repo.ListProviderCredentials(ctx, org.ID)
	require.NoError(t, err)
	require.Len(t, storedCreds, 1)
	assert.Equal(t, secretHeaderVal, storedCreds[0].Headers["X-Corp-Proxy-Token"])

	// Audit log snapshot must also redact headers values
	auditLogs, err := repo.ListAuditLogs(ctx, org.ID, 20)
	require.NoError(t, err)
	require.NotEmpty(t, auditLogs)
	auditJSON, _ := json.Marshal(auditLogs)
	assert.NotContains(t, string(auditJSON), secretHeaderVal, "SEC-08: audit log snapshot must redact custom header values")
}

func TestDataPlaneEndpoints_BoundedBodiesAndStrictInputTypes(t *testing.T) {
	ctx := context.Background()
	repo := storage.NewMemoryRepository()
	org := &domain.Organization{ID: "org-s2-limits", Name: "Limits Org", Slug: "org-s2-limits", IsActive: true}
	require.NoError(t, repo.CreateOrganization(ctx, org))

	rawVK := "sk-gw-s2-limits-key-1234567890abcd"
	require.NoError(t, repo.CreateVirtualKey(ctx, &domain.VirtualKey{
		ID:               "vk-s2-limits",
		OrgID:            org.ID,
		Name:             "s2-limits-vk",
		KeyPrefix:        rawVK[:14],
		KeyHash:          auth.HashKey(rawVK),
		Role:             domain.RoleDeveloper,
		AllowedModels:    []string{"*"},
		AllowedEndpoints: []string{"*"},
		IsActive:         true,
	}))

	cfg := config.Default()
	cfg.Auth.MasterAdminKey = "sk-gw-master-s2-limits-test"
	gw, err := server.New(cfg, repo, nil, nil)
	require.NoError(t, err)

	// S2-01: Oversized bodies rejected with 413 across remaining JSON data-plane endpoints
	oversized2MiB := `{"model":"gpt-4o-mini","input":"` + strings.Repeat("a", (2<<20)+1024) + `"}`
	for _, ep := range []string{"/v1/moderations", "/v1/batches", "/v1/audio/speech", "/v1/images/generations"} {
		req := httptest.NewRequest(http.MethodPost, ep, strings.NewReader(oversized2MiB))
		req.Header.Set("Authorization", "Bearer "+rawVK)
		rec := httptest.NewRecorder()
		gw.Handler().ServeHTTP(rec, req)
		assert.Equal(t, http.StatusRequestEntityTooLarge, rec.Code, "S2-01: %s must enforce 2 MiB body cap: %s", ep, rec.Body.String())
	}

	oversized10MiB := `{"model":"gpt-4o-mini","prompt":"` + strings.Repeat("a", (10<<20)+1024) + `"}`
	for _, ep := range []string{"/v1/messages", "/v1/completions", "/v1/tokenize", "/v1/messages/count_tokens"} {
		req := httptest.NewRequest(http.MethodPost, ep, strings.NewReader(oversized10MiB))
		req.Header.Set("Authorization", "Bearer "+rawVK)
		rec := httptest.NewRecorder()
		gw.Handler().ServeHTTP(rec, req)
		assert.Equal(t, http.StatusRequestEntityTooLarge, rec.Code, "S2-01: %s must enforce 10 MiB body cap: %s", ep, rec.Body.String())
	}

	// S2-04: Non-string array elements rejected with 400 on /v1/embeddings and /v1/moderations
	for _, ep := range []string{"/v1/embeddings", "/v1/moderations"} {
		req := httptest.NewRequest(http.MethodPost, ep, strings.NewReader(`{"model":"gemini/gemini-embedding-001","input":["ok",{"nested":true}]}`))
		req.Header.Set("Authorization", "Bearer "+rawVK)
		rec := httptest.NewRecorder()
		gw.Handler().ServeHTTP(rec, req)
		assert.Equal(t, http.StatusBadRequest, rec.Code, "S2-04: %s must reject non-string input items: %s", ep, rec.Body.String())
	}
}
