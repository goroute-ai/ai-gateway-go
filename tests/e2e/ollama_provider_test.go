package e2e_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/domain"
)

// TestOllamaProvider_ClusterCoexistenceFailoverAndZeroRegression verifies Ollama end-to-end
// against real PostgreSQL 16 + Redis 8 alongside existing OpenAI routing:
//  1. Keyless Ollama vault credential creation & preflight/stored validation via /api/tags.
//  2. Sync chat, SSE streaming chat, legacy completions, and batch embeddings on Ollama.
//  3. Cross-provider failover between Ollama and OpenAI without affecting existing provider accounting.
//  4. $0 micro-dollar spend accounting for Ollama vs non-zero integer micro-dollar spend for OpenAI.
func TestOllamaProvider_ClusterCoexistenceFailoverAndZeroRegression(t *testing.T) {
	ts, _, repo, _, cleanup := setupLiveGateway(t)
	defer cleanup()

	client := &httpClientHelper{t: t, ts: ts}
	adminHeaders := map[string]string{"Authorization": "Bearer sk-gw-master-admin-live-e2e-key"}

	var ollamaFail atomic.Bool
	var ollamaAuthSeen atomic.Value
	ollamaAuthSeen.Store("")

	ollamaUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ollamaAuthSeen.Store(r.Header.Get("Authorization"))
		switch r.URL.Path {
		case "/api/tags":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"models":[{"name":"qwen2.5:0.5b","model":"qwen2.5:0.5b","modified_at":"2026-11-25T13:29:15Z"},{"name":"all-minilm:latest","model":"all-minilm:latest","modified_at":"2026-11-25T13:29:24Z"}]}`)
		case "/v1/chat/completions":
			if ollamaFail.Load() {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusServiceUnavailable)
				fmt.Fprint(w, `{"error":{"message":"ollama temporarily overloaded","type":"server_error"}}`)
				return
			}
			if strings.Contains(r.Header.Get("Accept"), "text/event-stream") {
				w.Header().Set("Content-Type", "text/event-stream")
				fmt.Fprint(w, "data: {\"id\":\"chatcmpl-ol-s1\",\"object\":\"chat.completion.chunk\",\"created\":1700000000,\"model\":\"qwen2.5:0.5b\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"Hello \"}}]}\n\n")
				fmt.Fprint(w, "data: {\"id\":\"chatcmpl-ol-s1\",\"object\":\"chat.completion.chunk\",\"created\":1700000000,\"model\":\"qwen2.5:0.5b\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"Ollama\"},\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":12,\"completion_tokens\":4,\"total_tokens\":16}}\n\n")
				fmt.Fprint(w, "data: [DONE]\n\n")
				return
			}
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"id":"chatcmpl-ol-1","object":"chat.completion","created":1700000000,"model":"qwen2.5:0.5b","choices":[{"index":0,"message":{"role":"assistant","content":"Ollama live e2e ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":20,"prompt_tokens_details":{"cached_tokens":5},"completion_tokens":8,"total_tokens":28}}`)
		case "/v1/completions":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"id":"cmpl-ol-1","object":"text_completion","created":1700000000,"model":"qwen2.5:0.5b","choices":[{"index":0,"text":"4","finish_reason":"stop"}],"usage":{"prompt_tokens":5,"completion_tokens":1,"total_tokens":6}}`)
		case "/v1/embeddings":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"object":"list","model":"all-minilm:latest","data":[{"object":"embedding","index":0,"embedding":[0.1,0.2,0.3]},{"object":"embedding","index":1,"embedding":[0.4,0.5,0.6]}],"usage":{"prompt_tokens":8,"total_tokens":8}}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer ollamaUpstream.Close()

	openaiUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/models":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"object":"list","data":[{"id":"gpt-4o-mini","object":"model","owned_by":"openai"}]}`)
		case "/chat/completions":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"id":"chatcmpl-oai-fb","object":"chat.completion","created":1700000000,"model":"gpt-4o-mini","choices":[{"index":0,"message":{"role":"assistant","content":"OpenAI failover ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":100,"completion_tokens":50,"total_tokens":150}}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer openaiUpstream.Close()

	// 1. Create Org subscribed to both ollama and openai
	var org domain.Organization
	client.doJSON(http.MethodPost, "/admin/v1/organizations", adminHeaders, map[string]any{
		"name":              "Ollama Coexistence E2E Org",
		"slug":              fmt.Sprintf("ollama-coexist-%d", time.Now().UnixNano()),
		"max_budget_micros": 50_000_000,
	}, &org)
	client.doJSON(http.MethodPost, "/admin/v1/organizations/"+org.ID+"/subscriptions", adminHeaders, map[string]any{"provider": "ollama", "is_enabled": true}, nil)
	client.doJSON(http.MethodPost, "/admin/v1/organizations/"+org.ID+"/subscriptions", adminHeaders, map[string]any{"provider": "openai", "is_enabled": true}, nil)

	// 2. Keyless preflight validation for Ollama must succeed (while OpenAI without key must fail 400)
	var preflightRes struct {
		Valid            bool `json:"valid"`
		DiscoveredModels int  `json:"discovered_models"`
	}
	resp, raw := client.doJSON(http.MethodPost, "/admin/v1/credentials/validate", adminHeaders, map[string]any{
		"org_id":   org.ID,
		"provider": "ollama",
		"api_key":  "",
		"base_url": ollamaUpstream.URL,
	}, &preflightRes)
	if resp.StatusCode != http.StatusOK || !preflightRes.Valid || preflightRes.DiscoveredModels != 2 {
		t.Fatalf("ollama keyless preflight failed: status=%d res=%+v raw=%s", resp.StatusCode, preflightRes, string(raw))
	}
	respNoKeyOAI, _ := client.doJSON(http.MethodPost, "/admin/v1/credentials/validate", adminHeaders, map[string]any{
		"org_id":   org.ID,
		"provider": "openai",
		"api_key":  "",
		"base_url": openaiUpstream.URL,
	}, nil)
	if respNoKeyOAI.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for keyless openai preflight, got %d", respNoKeyOAI.StatusCode)
	}

	// 3. Create keyless Ollama credential & keyed OpenAI credential in PostgreSQL Vault
	var ollamaCred, openaiCred domain.ProviderCredential
	client.doJSON(http.MethodPost, "/admin/v1/credentials", adminHeaders, map[string]any{
		"org_id": org.ID, "provider": "ollama", "name": "ollama-local-e2e", "base_url": ollamaUpstream.URL, "api_key": "",
	}, &ollamaCred)
	client.doJSON(http.MethodPost, "/admin/v1/credentials", adminHeaders, map[string]any{
		"org_id": org.ID, "provider": "openai", "name": "openai-fallback-e2e", "base_url": openaiUpstream.URL, "api_key": "sk-e2e-openai-key",
	}, &openaiCred)

	// Validate stored keyless Ollama credential round-trips through Postgres AES-256-GCM vault
	var storedVal struct {
		Valid            bool `json:"valid"`
		DiscoveredModels int  `json:"discovered_models"`
	}
	resp, raw = client.doJSON(http.MethodPost, "/admin/v1/credentials/"+ollamaCred.ID+"/validate", adminHeaders, nil, &storedVal)
	if resp.StatusCode != http.StatusOK || !storedVal.Valid || storedVal.DiscoveredModels != 2 {
		t.Fatalf("stored ollama credential validate failed: status=%d res=%+v raw=%s", resp.StatusCode, storedVal, string(raw))
	}

	// 4. Create ModelGroups: primary Ollama chat (with OpenAI fallback), Ollama embeddings
	var chatGroup, embedGroup, fallbackGroup domain.ModelGroup
	client.doJSON(http.MethodPost, "/admin/v1/model-groups", adminHeaders, map[string]any{
		"org_id": org.ID, "alias": "openai-backup", "routing_strategy": "round_robin",
	}, &fallbackGroup)
	client.doJSON(http.MethodPost, "/admin/v1/deployments", adminHeaders, map[string]any{
		"model_group_id": fallbackGroup.ID, "global_model_id": "openai/gpt-4o-mini", "credential_id": openaiCred.ID, "deployment_name": "oai-fb-dep", "weight": 100,
	}, nil)

	client.doJSON(http.MethodPost, "/admin/v1/model-groups", adminHeaders, map[string]any{
		"org_id": org.ID, "alias": "ollama-chat", "routing_strategy": "round_robin", "fallback_group_ids": []string{"openai-backup"},
	}, &chatGroup)
	client.doJSON(http.MethodPost, "/admin/v1/deployments", adminHeaders, map[string]any{
		"model_group_id": chatGroup.ID, "global_model_id": "ollama/qwen2.5:0.5b", "credential_id": ollamaCred.ID, "deployment_name": "ollama-chat-dep", "weight": 100,
	}, nil)

	client.doJSON(http.MethodPost, "/admin/v1/model-groups", adminHeaders, map[string]any{
		"org_id": org.ID, "alias": "ollama-embed", "routing_strategy": "round_robin",
	}, &embedGroup)
	client.doJSON(http.MethodPost, "/admin/v1/deployments", adminHeaders, map[string]any{
		"model_group_id": embedGroup.ID, "global_model_id": "ollama/all-minilm:latest", "credential_id": ollamaCred.ID, "deployment_name": "ollama-embed-dep", "weight": 100,
	}, nil)

	// 5. Mint Virtual Key permitting chat, completions, and embeddings
	var vk domain.VirtualKey
	client.doJSON(http.MethodPost, "/admin/v1/keys", adminHeaders, map[string]any{
		"org_id":            org.ID,
		"name":              "ollama-e2e-key",
		"rpm_limit":         60,
		"tpm_limit":         100000,
		"max_budget_micros": 10_000_000,
		"allowed_endpoints": []string{"/v1/chat/completions", "/v1/completions", "/v1/embeddings", "/v1/models"},
	}, &vk)
	vkHeaders := map[string]string{"Authorization": "Bearer " + vk.RawKey}

	// 6. Sync chat -> Ollama (and verify no bogus Authorization header was sent upstream)
	var chatResp domain.CanonicalChatResponse
	resp, raw = client.doJSON(http.MethodPost, "/v1/chat/completions", vkHeaders, domain.CanonicalChatRequest{
		Model:    "ollama-chat",
		Messages: []domain.CanonicalMessage{{Role: "user", Content: "ping"}},
	}, &chatResp)
	if resp.StatusCode != http.StatusOK || chatResp.Provider != domain.ProviderOllama || resp.Header.Get("X-Gateway-Provider") != "ollama" {
		t.Fatalf("ollama sync chat failed: status=%d hdr=%q resp=%+v raw=%s", resp.StatusCode, resp.Header.Get("X-Gateway-Provider"), chatResp, string(raw))
	}
	if gotAuth, _ := ollamaAuthSeen.Load().(string); gotAuth != "" {
		t.Fatalf("expected empty Authorization header to keyless Ollama upstream, got %q", gotAuth)
	}

	// 7. Streaming SSE chat -> Ollama
	resp, raw = client.doJSON(http.MethodPost, "/v1/chat/completions", vkHeaders, map[string]any{
		"model":          "ollama-chat",
		"messages":       []map[string]any{{"role": "user", "content": "stream ping"}},
		"stream":         true,
		"stream_options": map[string]any{"include_usage": true},
	}, nil)
	if resp.StatusCode != http.StatusOK || resp.Header.Get("X-Gateway-Provider") != "ollama" || !strings.Contains(string(raw), "Hello ") || !strings.Contains(string(raw), "data: [DONE]") {
		t.Fatalf("ollama stream chat failed: status=%d hdr=%q body=%s", resp.StatusCode, resp.Header.Get("X-Gateway-Provider"), string(raw))
	}

	// 8. Legacy Completion -> Ollama
	var compResp domain.CanonicalCompletionResponse
	resp, raw = client.doJSON(http.MethodPost, "/v1/completions", vkHeaders, map[string]any{
		"model": "ollama-chat", "prompt": "2+2=",
	}, &compResp)
	if resp.StatusCode != http.StatusOK || len(compResp.Choices) == 0 || compResp.Choices[0].Text != "4" {
		t.Fatalf("ollama completion failed: status=%d resp=%+v raw=%s", resp.StatusCode, compResp, string(raw))
	}

	// 9. Batch Embeddings -> Ollama
	var embResp domain.CanonicalEmbeddingResponse
	resp, raw = client.doJSON(http.MethodPost, "/v1/embeddings", vkHeaders, map[string]any{
		"model": "ollama-embed", "input": []string{"alpha", "beta"},
	}, &embResp)
	if resp.StatusCode != http.StatusOK || len(embResp.Data) != 2 || embResp.Provider != domain.ProviderOllama {
		t.Fatalf("ollama embeddings failed: status=%d resp=%+v raw=%s", resp.StatusCode, embResp, string(raw))
	}

	// 10. Cross-Provider Failover: Ollama 503 -> OpenAI fallback succeeds cleanly
	ollamaFail.Store(true)
	var fbResp domain.CanonicalChatResponse
	resp, raw = client.doJSON(http.MethodPost, "/v1/chat/completions", vkHeaders, domain.CanonicalChatRequest{
		Model:    "ollama-chat",
		Messages: []domain.CanonicalMessage{{Role: "user", Content: "failover test"}},
	}, &fbResp)
	if resp.StatusCode != http.StatusOK || fbResp.Provider != domain.ProviderOpenAI || resp.Header.Get("X-Gateway-Provider") != "openai" {
		t.Fatalf("ollama->openai failover failed: status=%d hdr=%q resp=%+v raw=%s", resp.StatusCode, resp.Header.Get("X-Gateway-Provider"), fbResp, string(raw))
	}

	// 11. Verify Postgres FinOps spend ledger: $0 for Ollama, >0 µ$ for OpenAI failover
	deadline := time.Now().Add(5 * time.Second)
	var sawOllamaZero, sawOpenAIPositive bool
	for time.Now().Before(deadline) {
		evts, err := repo.ListSpendLogs(t.Context(), org.ID, 50)
		if err == nil {
			for _, ev := range evts {
				if ev.Provider == domain.ProviderOllama && ev.CostMicros == 0 {
					sawOllamaZero = true
				}
				if ev.Provider == domain.ProviderOpenAI && ev.CostMicros > 0 {
					sawOpenAIPositive = true
				}
			}
			if sawOllamaZero && sawOpenAIPositive {
				break
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !sawOllamaZero || !sawOpenAIPositive {
		t.Fatalf("expected FinOps spend events for ollama ($0) and openai (>0 µ$), got ollamaZero=%v openaiPos=%v", sawOllamaZero, sawOpenAIPositive)
	}
}
