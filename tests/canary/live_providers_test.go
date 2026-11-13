//go:build canary

package canary_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/server"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
)

type canaryTarget struct {
	name     string
	envKey   string
	provider domain.ProviderType
	model    string
}

func TestCanary_LiveProviders(t *testing.T) {
	targets := []canaryTarget{
		// Tier 2: Single-key multi-provider & free-tier live checks
		{name: "openrouter", envKey: "OPENROUTER_API_KEY", provider: domain.ProviderOpenRouter, model: "openai/gpt-4o-mini"},
		{name: "gemini", envKey: "GEMINI_API_KEY", provider: domain.ProviderGemini, model: "gemini-2.5-flash"},
		{name: "groq", envKey: "GROQ_API_KEY", provider: domain.ProviderGroq, model: "llama-3.1-8b-instant"},
		// Tier 3: Direct provider 1-token checks
		{name: "openai", envKey: "OPENAI_API_KEY", provider: domain.ProviderOpenAI, model: "gpt-4o-mini"},
		{name: "anthropic", envKey: "ANTHROPIC_API_KEY", provider: domain.ProviderAnthropic, model: "claude-3-5-haiku-latest"},
	}

	ctx := context.Background()
	repo := storage.NewMemoryRepository()
	cfg := config.Default()
	cfg.Auth.MasterAdminKey = "sk-gw-canary-admin"
	cfg.Auth.MasterEncryptionKey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	gw, err := server.New(cfg, repo, nil, nil)
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	ts := httptest.NewServer(gw.Handler())
	defer ts.Close()

	adminHeaders := map[string]string{"Authorization": "Bearer " + cfg.Auth.MasterAdminKey}
	postJSON := func(path string, hdrs map[string]string, body any, out any) (int, []byte) {
		b, _ := json.Marshal(body)
		req, _ := http.NewRequest(http.MethodPost, ts.URL+path, bytes.NewReader(b))
		req.Header.Set("Content-Type", "application/json")
		for k, v := range hdrs {
			req.Header.Set(k, v)
		}
		client := &http.Client{Timeout: 20 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("post %s: %v", path, err)
		}
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if out != nil && len(raw) > 0 {
			_ = json.Unmarshal(raw, out)
		}
		return resp.StatusCode, raw
	}

	var org map[string]any
	status, raw := postJSON("/admin/v1/organizations", adminHeaders, map[string]any{"name": "CanaryOrg", "slug": "canary-org"}, &org)
	if status != http.StatusCreated {
		t.Fatalf("create org (%d): %s", status, string(raw))
	}
	orgID := org["id"].(string)

	var vk domain.VirtualKey
	status, raw = postJSON("/admin/v1/keys", adminHeaders, map[string]any{"org_id": orgID, "name": "canary-key"}, &vk)
	if status != http.StatusCreated {
		t.Fatalf("create key (%d): %s", status, string(raw))
	}
	vkHeaders := map[string]string{"Authorization": "Bearer " + vk.RawKey}

	for _, tgt := range targets {
		tgt := tgt
		t.Run(tgt.name, func(t *testing.T) {
			apiKey := os.Getenv(tgt.envKey)
			if apiKey == "" {
				t.Skipf("skipping %s canary: %s not set", tgt.name, tgt.envKey)
			}

			gmID := string(tgt.provider) + "/" + tgt.model
			_ = repo.UpsertGlobalModel(ctx, &domain.GlobalModel{
				ID: gmID, Provider: tgt.provider, ModelName: tgt.model,
				SupportsInference: true, LifecycleStatus: domain.ModelStatusActive, PricingStatus: domain.PricingStatusVerified,
			})

			var cred, grp map[string]any
			postJSON("/admin/v1/credentials", adminHeaders, map[string]any{
				"org_id": orgID, "provider": string(tgt.provider), "name": tgt.name + "-cred", "api_key": apiKey,
			}, &cred)
			postJSON("/admin/v1/model-groups", adminHeaders, map[string]any{
				"org_id": orgID, "alias": tgt.name + "-canary", "routing_strategy": "weighted_shuffle",
			}, &grp)
			postJSON("/admin/v1/deployments", adminHeaders, map[string]any{
				"model_group_id": grp["id"], "global_model_id": gmID,
				"credential_id": cred["id"], "deployment_name": tgt.name + "-dep", "weight": 1,
			}, nil)

			code, body := postJSON("/v1/chat/completions", vkHeaders, map[string]any{
				"model":      tgt.name + "-canary",
				"max_tokens": 1,
				"messages":   []map[string]any{{"role": "user", "content": "Say ok"}},
			}, nil)
			if code != http.StatusOK {
				t.Fatalf("%s canary failed (%d): %s", tgt.name, code, string(body))
			}
		})
	}
}
