package e2e_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/security/network"
	"github.com/goroute-ai/ai-gateway-go/internal/server"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
)

func TestSecurity_SSRFPolicyAndCrossTenantRBACIsolation(t *testing.T) {
	// 1. Network egress policy blocks metadata IP and RFC1918 private networks by default.
	strictNet := config.Default().Security.Network
	strictNet.OutboundSSRF.AllowPrivateNetworks = false
	strictNet.OutboundSSRF.AllowInsecureHTTP = false
	policy, err := network.NewPolicy(strictNet.OutboundSSRF)
	if err != nil {
		t.Fatalf("network.NewPolicy: %v", err)
	}

	blockedTargets := []string{
		"http://169.254.169.254/latest/meta-data/",
		"https://169.254.169.254/latest/meta-data/",
		"https://10.0.0.5:1234/v1/chat/completions",
		"https://127.0.0.1:11434/v1/chat/completions",
	}
	for _, target := range blockedTargets {
		u, parseErr := url.Parse(target)
		if parseErr != nil {
			t.Fatalf("parse url %s: %v", target, parseErr)
		}
		if err := policy.ValidateURL(u); err == nil {
			t.Fatalf("expected SSRF policy to block %s, but it was allowed", target)
		}
	}

	// 2. Cross-tenant & AllowedModels RBAC isolation against live Gateway + PG + Redis.
	ts, _, pgRepo, _, cleanup := setupLiveGateway(t)
	defer cleanup()

	ctx := context.Background()
	h := &httpClientHelper{t: t, ts: ts}
	adminHeaders := map[string]string{"Authorization": "Bearer sk-gw-master-admin-live-e2e-key"}

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"c1","object":"chat.completion","model":"m1","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}`))
	}))
	defer upstream.Close()

	var orgA, orgB map[string]any
	tsNano := time.Now().UnixNano()
	h.doJSON(http.MethodPost, "/admin/v1/organizations", adminHeaders, map[string]any{"name": "SecOrgA", "slug": fmt.Sprintf("sec-org-a-%d", tsNano)}, &orgA)
	h.doJSON(http.MethodPost, "/admin/v1/organizations", adminHeaders, map[string]any{"name": "SecOrgB", "slug": fmt.Sprintf("sec-org-b-%d", tsNano)}, &orgB)
	orgAID := orgA["id"].(string)
	orgBID := orgB["id"].(string)

	_ = pgRepo.UpsertGlobalModel(ctx, &domain.GlobalModel{
		ID: "openai/sec-model-a", Provider: domain.ProviderOpenAI, ModelName: "sec-model-a",
		SupportsInference: true, LifecycleStatus: domain.ModelStatusActive, PricingStatus: domain.PricingStatusVerified,
	})
	_ = pgRepo.UpsertGlobalModel(ctx, &domain.GlobalModel{
		ID: "openai/sec-model-b", Provider: domain.ProviderOpenAI, ModelName: "sec-model-b",
		SupportsInference: true, LifecycleStatus: domain.ModelStatusActive, PricingStatus: domain.PricingStatusVerified,
	})

	wire := func(orgID, alias, gmID string) {
		var cred, grp map[string]any
		h.doJSON(http.MethodPost, "/admin/v1/credentials", adminHeaders, map[string]any{
			"org_id": orgID, "provider": "openai", "name": alias + "-c", "api_key": "sk-m", "base_url": upstream.URL,
		}, &cred)
		h.doJSON(http.MethodPost, "/admin/v1/model-groups", adminHeaders, map[string]any{
			"org_id": orgID, "alias": alias, "routing_strategy": "weighted_shuffle",
		}, &grp)
		h.doJSON(http.MethodPost, "/admin/v1/deployments", adminHeaders, map[string]any{
			"model_group_id": grp["id"], "global_model_id": gmID,
			"credential_id": cred["id"], "deployment_name": alias + "-d", "weight": 1,
		}, nil)
	}
	wire(orgAID, "model-a-allowed", "openai/sec-model-a")
	wire(orgAID, "model-a-restricted", "openai/sec-model-a")
	wire(orgBID, "model-b-tenant", "openai/sec-model-b")

	var keyAResp domain.VirtualKey
	h.doJSON(http.MethodPost, "/admin/v1/keys", adminHeaders, map[string]any{
		"org_id":         orgAID,
		"name":           "scoped-key-a",
		"allowed_models": []string{"model-a-allowed"},
	}, &keyAResp)
	keyAHeaders := map[string]string{"Authorization": "Bearer " + keyAResp.RawKey}

	// Allowed model succeeds
	resp, raw := h.doJSON(http.MethodPost, "/v1/chat/completions", keyAHeaders, map[string]any{
		"model":    "model-a-allowed",
		"messages": []map[string]any{{"role": "user", "content": "hi"}},
	}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected allowed model 200, got %d: %s", resp.StatusCode, string(raw))
	}

	// Restricted model in same org fails 403
	resp, raw = h.doJSON(http.MethodPost, "/v1/chat/completions", keyAHeaders, map[string]any{
		"model":    "model-a-restricted",
		"messages": []map[string]any{{"role": "user", "content": "hi"}},
	}, nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for restricted model, got %d: %s", resp.StatusCode, string(raw))
	}

	// Other tenant's model fails (403/404, never 200)
	resp, raw = h.doJSON(http.MethodPost, "/v1/chat/completions", keyAHeaders, map[string]any{
		"model":    "model-b-tenant",
		"messages": []map[string]any{{"role": "user", "content": "hi"}},
	}, nil)
	if resp.StatusCode == http.StatusOK {
		t.Fatalf("expected cross-tenant model access to be denied, got 200: %s", string(raw))
	}
}

func TestSecurity_FileUploadQuotaEnforcement(t *testing.T) {
	t.Setenv("GOROUTE_FILES_DIR", t.TempDir())
	ctx := context.Background()
	pgDSN := getEnvOrDefault("GATEWAY_POSTGRES_DSN", "postgres://gateway:gateway@localhost:15432/aigateway_test?sslmode=disable")
	pool, err := storage.NewPostgresPool(ctx, pgDSN)
	if err != nil {
		if os.Getenv("GATEWAY_REQUIRE_LIVE_DEPS") == "1" {
			t.Fatalf("GATEWAY_REQUIRE_LIVE_DEPS=1 set, cannot connect to PostgreSQL: %v", err)
		}
		t.Skipf("skipping live test: cannot connect to PostgreSQL: %v", err)
	}
	defer pool.Close()
	if err := storage.RunMigrationsDir(ctx, pool, "../../migrations"); err != nil {
		t.Fatalf("run migrations: %v", err)
	}
	pgRepo, err := storage.NewPostgresRepository(ctx, pool)
	if err != nil {
		t.Fatalf("new postgres repo: %v", err)
	}

	cfg := config.Default()
	cfg.Auth.MasterAdminKey = "sk-gw-master-admin-file-quota-e2e"
	cfg.Auth.MasterEncryptionKey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	cfg.Server.MaxFileStorageBytesPerOrg = 450
	cfg.Server.MaxConcurrentFileUploads = 2

	gw, err := server.New(cfg, pgRepo, nil, nil)
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	defer gw.Shutdown(ctx)
	ts := httptest.NewServer(gw.Handler())
	defer ts.Close()

	h := &httpClientHelper{t: t, ts: ts}
	adminHeaders := map[string]string{"Authorization": "Bearer " + cfg.Auth.MasterAdminKey}

	var orgResp map[string]any
	resp, raw := h.doJSON(http.MethodPost, "/admin/v1/organizations", adminHeaders, map[string]any{
		"name": "FileQuotaOrg", "slug": fmt.Sprintf("file-quota-%d", time.Now().UnixNano()),
	}, &orgResp)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create org (%d): %s", resp.StatusCode, string(raw))
	}
	var vk domain.VirtualKey
	resp, raw = h.doJSON(http.MethodPost, "/admin/v1/keys", adminHeaders, map[string]any{
		"org_id": orgResp["id"], "name": "file-quota-key",
	}, &vk)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create key (%d): %s", resp.StatusCode, string(raw))
	}

	upload := func(data []byte) (*http.Response, []byte) {
		var body bytes.Buffer
		mw := multipart.NewWriter(&body)
		fw, _ := mw.CreateFormFile("file", "batch.jsonl")
		_, _ = fw.Write(data)
		_ = mw.WriteField("purpose", "batch")
		_ = mw.Close()
		req, _ := http.NewRequest(http.MethodPost, ts.URL+"/v1/files", bytes.NewReader(body.Bytes()))
		req.Header.Set("Authorization", "Bearer "+vk.RawKey)
		req.Header.Set("Content-Type", mw.FormDataContentType())
		r, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("upload request: %v", err)
		}
		defer r.Body.Close()
		var out bytes.Buffer
		_, _ = out.ReadFrom(r.Body)
		return r, out.Bytes()
	}

	// First small upload succeeds (201)
	r1, b1 := upload([]byte(`{"prompt":"ok"}`))
	if r1.StatusCode != http.StatusCreated {
		t.Fatalf("expected first upload 201, got %d: %s", r1.StatusCode, string(b1))
	}
	var created domain.CanonicalFile
	if err := json.Unmarshal(b1, &created); err != nil {
		t.Fatalf("decode file response: %v", err)
	}

	// Second upload exceeding remaining org storage quota fails with 413
	r2, b2 := upload(bytes.Repeat([]byte("a"), 450))
	if r2.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected quota-exceeding upload 413, got %d: %s", r2.StatusCode, string(b2))
	}

	// Delete first file and confirm quota is reclaimed
	resp, raw = h.doJSON(http.MethodDelete, "/v1/files/"+created.ID, map[string]string{"Authorization": "Bearer " + vk.RawKey}, nil, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected delete file 200, got %d: %s", resp.StatusCode, string(raw))
	}
}
