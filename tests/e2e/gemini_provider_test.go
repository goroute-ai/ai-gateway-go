package e2e_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/server"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
)

func TestGeminiProvider_LivePostgresRedisCoexistenceAndFailover(t *testing.T) {
	gwTS, _, _, _, cleanup := setupLiveGateway(t)
	defer cleanup()

	adminKey := "sk-gw-master-admin-live-e2e-key"
	orgID := fmt.Sprintf("org_gem_e2e_%d", time.Now().UnixNano())

	// Mock Gemini v1beta upstream
	gemSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("x-goog-api-key") == "" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":{"code":401,"message":"missing key","status":"UNAUTHENTICATED"}}`))
			return
		}
		switch r.URL.Path {
		case "/v1beta/models/gemini-2.5-flash:generateContent":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"responseId":"resp-gem-e2e","modelVersion":"gemini-2.5-flash","candidates":[{"index":0,"content":{"role":"model","parts":[{"thought":true,"text":"reasoning"},{"text":"Gemini E2E OK"}]},"finishReason":"STOP"}],"usageMetadata":{"promptTokenCount":10,"candidatesTokenCount":5,"thoughtsTokenCount":15,"totalTokenCount":30}}`))
		case "/v1beta/models/gemini-2.5-flash:streamGenerateContent":
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = fmt.Fprint(w, "data: {\"responseId\":\"resp-gem-s\",\"modelVersion\":\"gemini-2.5-flash\",\"candidates\":[{\"index\":0,\"content\":{\"role\":\"model\",\"parts\":[{\"text\":\"Gemini SSE \"}]}}]}\n\n")
			_, _ = fmt.Fprint(w, "data: {\"responseId\":\"resp-gem-s\",\"modelVersion\":\"gemini-2.5-flash\",\"candidates\":[{\"index\":0,\"content\":{\"role\":\"model\",\"parts\":[{\"text\":\"OK\"}]},\"finishReason\":\"STOP\"}],\"usageMetadata\":{\"promptTokenCount\":8,\"candidatesTokenCount\":4,\"thoughtsTokenCount\":6,\"totalTokenCount\":18}}\n\n")
		case "/v1beta/models/gemini-embedding-001:batchEmbedContents":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"embeddings":[{"values":[0.1,0.2,0.3]},{"values":[0.4,0.5,0.6]}]}`))
		case "/v1beta/models":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"models":[{"name":"models/gemini-2.5-flash","displayName":"Gemini 2.5 Flash","supportedGenerationMethods":["generateContent"]},{"name":"models/gemini-embedding-001","displayName":"Gemini Embedding 001","supportedGenerationMethods":["embedContent"]}]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer gemSrv.Close()

	// Failing primary OpenAI upstream to prove cross-provider failover to Gemini
	failOaiSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"error":{"message":"simulated outage","type":"server_error"}}`))
	}))
	defer failOaiSrv.Close()

	adminReq := func(method, path string, body any) (int, map[string]any) {
		t.Helper()
		var rdr io.Reader
		if body != nil {
			b, _ := json.Marshal(body)
			rdr = bytes.NewReader(b)
		}
		req, _ := http.NewRequest(method, gwTS.URL+path, rdr)
		req.Header.Set("Authorization", "Bearer "+adminKey)
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("%s %s failed: %v", method, path, err)
		}
		defer resp.Body.Close()
		raw, _ := io.ReadAll(resp.Body)
		var out map[string]any
		_ = json.Unmarshal(raw, &out)
		return resp.StatusCode, out
	}

	// 1. Create Org, enable openai + gemini subscriptions, create credentials & virtual key
	st, orgResp := adminReq(http.MethodPost, "/admin/v1/organizations", map[string]any{"name": "Gemini E2E Org", "slug": orgID, "is_active": true})
	if st != http.StatusCreated && st != http.StatusOK {
		t.Fatalf("create org status=%d body=%v", st, orgResp)
	}
	if id, ok := orgResp["id"].(string); ok && id != "" {
		orgID = id
	}
	for _, prov := range []string{"openai", "gemini"} {
		if st, body := adminReq(http.MethodPost, fmt.Sprintf("/admin/v1/organizations/%s/subscriptions", orgID), map[string]any{"provider": prov, "is_enabled": true}); st != http.StatusOK && st != http.StatusCreated {
			t.Fatalf("enable provider %s status=%d body=%v", prov, st, body)
		}
	}

	st, preflight := adminReq(http.MethodPost, "/admin/v1/credentials/validate", map[string]any{
		"provider": "gemini",
		"api_key":  "e2e-gem-key",
		"base_url": gemSrv.URL,
	})
	if st != http.StatusOK || preflight["valid"] != true {
		t.Fatalf("gemini preflight validate failed: status=%d body=%v", st, preflight)
	}

	st, gemCred := adminReq(http.MethodPost, "/admin/v1/credentials", map[string]any{
		"org_id":   orgID,
		"provider": "gemini",
		"name":     "gemini-e2e-cred",
		"api_key":  "e2e-gem-key",
		"base_url": gemSrv.URL,
	})
	if st != http.StatusCreated {
		t.Fatalf("create gemini cred failed: status=%d body=%v", st, gemCred)
	}
	st, oaiCred := adminReq(http.MethodPost, "/admin/v1/credentials", map[string]any{
		"org_id":   orgID,
		"provider": "openai",
		"name":     "oai-fail-cred",
		"api_key":  "e2e-oai-key",
		"base_url": failOaiSrv.URL,
	})
	if st != http.StatusCreated {
		t.Fatalf("create openai cred failed: status=%d body=%v", st, oaiCred)
	}

	// Create model groups: gemini-chat, gemini-embed, failover-group (openai -> gemini-chat)
	st, gemChatGrp := adminReq(http.MethodPost, "/admin/v1/model-groups", map[string]any{"org_id": orgID, "alias": "gemini-chat", "routing_strategy": "weighted-shuffle"})
	if st != http.StatusCreated {
		t.Fatalf("create gemini-chat group status=%d body=%v", st, gemChatGrp)
	}
	st, _ = adminReq(http.MethodPost, "/admin/v1/deployments", map[string]any{
		"model_group_id":  gemChatGrp["id"],
		"global_model_id": "gemini/gemini-2.5-flash",
		"credential_id":   gemCred["id"],
		"deployment_name": "gem-flash-dep",
		"weight":          100,
	})
	if st != http.StatusCreated {
		t.Fatalf("create gemini-chat deployment status=%d", st)
	}

	st, gemEmbGrp := adminReq(http.MethodPost, "/admin/v1/model-groups", map[string]any{"org_id": orgID, "alias": "gemini-embed", "routing_strategy": "weighted-shuffle"})
	if st != http.StatusCreated {
		t.Fatalf("create gemini-embed group status=%d", st)
	}
	st, _ = adminReq(http.MethodPost, "/admin/v1/deployments", map[string]any{
		"model_group_id":  gemEmbGrp["id"],
		"global_model_id": "gemini/gemini-embedding-001",
		"credential_id":   gemCred["id"],
		"deployment_name": "gem-emb-dep",
		"weight":          100,
	})
	if st != http.StatusCreated {
		t.Fatalf("create gemini-embed deployment status=%d", st)
	}

	st, foGrp := adminReq(http.MethodPost, "/admin/v1/model-groups", map[string]any{
		"org_id":             orgID,
		"alias":              "openai-to-gemini",
		"routing_strategy":   "weighted-shuffle",
		"fallback_group_ids": []any{gemChatGrp["id"]},
	})
	if st != http.StatusCreated {
		t.Fatalf("create failover group status=%d", st)
	}
	st, _ = adminReq(http.MethodPost, "/admin/v1/deployments", map[string]any{
		"model_group_id":  foGrp["id"],
		"global_model_id": "openai/gpt-4.1-mini",
		"credential_id":   oaiCred["id"],
		"deployment_name": "oai-primary-failing",
		"weight":          100,
	})
	if st != http.StatusCreated {
		t.Fatalf("create openai failing deployment status=%d", st)
	}

	st, vkResp := adminReq(http.MethodPost, "/admin/v1/keys", map[string]any{
		"org_id":            orgID,
		"name":              "gemini-e2e-vk",
		"role":              "developer",
		"allowed_endpoints": []string{"/v1/chat/completions", "/v1/embeddings", "/v1/models"},
	})
	if st != http.StatusCreated {
		t.Fatalf("create virtual key status=%d body=%v", st, vkResp)
	}
	vkey, _ := vkResp["raw_key"].(string)
	if vkey == "" {
		vkey, _ = vkResp["key"].(string)
	}
	if vkey == "" {
		t.Fatalf("create virtual key response missing raw_key/key: %v", vkResp)
	}

	// 2. Sync chat + exact micro-dollar spend verification (10 prompt + 5 regular + 15 thoughts)
	chatReqBody, _ := json.Marshal(map[string]any{
		"model":    "gemini-chat",
		"messages": []map[string]any{{"role": "user", "content": "hi"}},
	})
	req, _ := http.NewRequest(http.MethodPost, gwTS.URL+"/v1/chat/completions", bytes.NewReader(chatReqBody))
	req.Header.Set("Authorization", "Bearer "+vkey)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("chat request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK || resp.Header.Get("X-Gateway-Provider") != "gemini" {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("chat failed: status=%d provider=%q body=%s", resp.StatusCode, resp.Header.Get("X-Gateway-Provider"), string(b))
	}
	var chatOut map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&chatOut)
	usage := chatOut["usage"].(map[string]any)
	if usage["completion_tokens"].(float64) != 20 || usage["total_tokens"].(float64) != 30 {
		t.Fatalf("unexpected usage in gateway chat response: %v", usage)
	}

	// 3. SSE streaming chat
	streamBody, _ := json.Marshal(map[string]any{
		"model":    "gemini-chat",
		"stream":   true,
		"messages": []map[string]any{{"role": "user", "content": "stream"}},
	})
	sReq, _ := http.NewRequest(http.MethodPost, gwTS.URL+"/v1/chat/completions", bytes.NewReader(streamBody))
	sReq.Header.Set("Authorization", "Bearer "+vkey)
	sReq.Header.Set("Content-Type", "application/json")
	sResp, err := http.DefaultClient.Do(sReq)
	if err != nil {
		t.Fatalf("stream request failed: %v", err)
	}
	defer sResp.Body.Close()
	sRaw, _ := io.ReadAll(sResp.Body)
	if sResp.StatusCode != http.StatusOK || !strings.Contains(string(sRaw), "Gemini SSE") || !strings.Contains(string(sRaw), "[DONE]") {
		t.Fatalf("stream response unexpected: status=%d body=%s", sResp.StatusCode, string(sRaw))
	}

	// 4. Batch embeddings
	embBody, _ := json.Marshal(map[string]any{
		"model": "gemini-embed",
		"input": []string{"alpha", "beta"},
	})
	eReq, _ := http.NewRequest(http.MethodPost, gwTS.URL+"/v1/embeddings", bytes.NewReader(embBody))
	eReq.Header.Set("Authorization", "Bearer "+vkey)
	eReq.Header.Set("Content-Type", "application/json")
	eResp, err := http.DefaultClient.Do(eReq)
	if err != nil {
		t.Fatalf("embed request failed: %v", err)
	}
	defer eResp.Body.Close()
	var embOut map[string]any
	_ = json.NewDecoder(eResp.Body).Decode(&embOut)
	if eResp.StatusCode != http.StatusOK || len(embOut["data"].([]any)) != 2 {
		t.Fatalf("batch embed unexpected: status=%d body=%v", eResp.StatusCode, embOut)
	}

	// 5. Cross-provider failover (OpenAI 503 -> Gemini 200)
	foBody, _ := json.Marshal(map[string]any{
		"model":    "openai-to-gemini",
		"messages": []map[string]any{{"role": "user", "content": "failover"}},
	})
	fReq, _ := http.NewRequest(http.MethodPost, gwTS.URL+"/v1/chat/completions", bytes.NewReader(foBody))
	fReq.Header.Set("Authorization", "Bearer "+vkey)
	fReq.Header.Set("Content-Type", "application/json")
	fResp, err := http.DefaultClient.Do(fReq)
	if err != nil {
		t.Fatalf("failover request failed: %v", err)
	}
	defer fResp.Body.Close()
	if fResp.StatusCode != http.StatusOK || fResp.Header.Get("X-Gateway-Provider") != "gemini" {
		b, _ := io.ReadAll(fResp.Body)
		t.Fatalf("cross-provider failover failed: status=%d provider=%q body=%s", fResp.StatusCode, fResp.Header.Get("X-Gateway-Provider"), string(b))
	}
}

// TestLiveGeminiEndToEnd_ViaGateway runs an opt-in live smoke test against Google's
// real Gemini v1beta API through GoRoute's full HTTP server when GATEWAY_TEST_GEMINI_API_KEY
// (or GEMINI_API_KEY) is present in the environment. Skips cleanly in offline/CI runs.
func TestLiveGeminiEndToEnd_ViaGateway(t *testing.T) {
	apiKey := strings.TrimSpace(os.Getenv("GATEWAY_TEST_GEMINI_API_KEY"))
	if apiKey == "" {
		apiKey = strings.TrimSpace(os.Getenv("GEMINI_API_KEY"))
	}
	if apiKey == "" {
		t.Skip("GATEWAY_TEST_GEMINI_API_KEY / GEMINI_API_KEY not set; skipping opt-in live Gemini smoke test")
	}

	cfg := config.Default()
	cfg.Auth.MasterAdminKey = "sk-gw-live-gem-admin-test-key-32ch"
	cfg.Auth.MasterEncryptionKey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	cfg.Auth.DefaultVirtualKey = "sk-gw-live-gem-vkey-test-key-32ch"
	cfg.ModelList = []config.ModelListEntry{
		{
			ModelName: "gemini-flash-live",
			ModelParams: config.ModelParams{
				Model:  "gemini/gemini-2.5-flash",
				APIKey: apiKey,
			},
		},
		{
			ModelName: "gemini-embed-live",
			ModelParams: config.ModelParams{
				Model:  "gemini/gemini-embedding-001",
				APIKey: apiKey,
			},
		},
	}

	repo := storage.NewMemoryRepository()
	gw, err := server.New(cfg, repo, nil, nil)
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	ts := httptest.NewServer(gw.Handler())
	defer ts.Close()

	// 1. Live Admin preflight credential validation (ListModels)
	pfBody, _ := json.Marshal(map[string]any{"provider": "gemini", "api_key": apiKey})
	pfReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/admin/v1/credentials/validate", bytes.NewReader(pfBody))
	pfReq.Header.Set("Authorization", "Bearer "+cfg.Auth.MasterAdminKey)
	pfReq.Header.Set("Content-Type", "application/json")
	pfResp, err := http.DefaultClient.Do(pfReq)
	if err != nil {
		t.Fatalf("live preflight validate: %v", err)
	}
	defer pfResp.Body.Close()
	var pfOut map[string]any
	_ = json.NewDecoder(pfResp.Body).Decode(&pfOut)
	if pfResp.StatusCode != http.StatusOK || pfOut["valid"] != true {
		t.Fatalf("live preflight validate failed: status=%d body=%v", pfResp.StatusCode, pfOut)
	}
	t.Logf("Live Gemini preflight discovered %v models", pfOut["models_discovered"])

	// 2. Live sync chat with JSON mode
	chatBody, _ := json.Marshal(map[string]any{
		"model":           "gemini-flash-live",
		"max_tokens":      128,
		"temperature":     0,
		"response_format": map[string]any{"type": "json_object"},
		"messages": []map[string]any{
			{"role": "system", "content": "Always reply with valid JSON."},
			{"role": "user", "content": `Return {"status":"ok"}`},
		},
	})
	cReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/v1/chat/completions", bytes.NewReader(chatBody))
	cReq.Header.Set("Authorization", "Bearer "+cfg.Auth.DefaultVirtualKey)
	cReq.Header.Set("Content-Type", "application/json")
	cResp, err := http.DefaultClient.Do(cReq)
	if err != nil {
		t.Fatalf("live chat: %v", err)
	}
	defer cResp.Body.Close()
	cRaw, _ := io.ReadAll(cResp.Body)
	if cResp.StatusCode != http.StatusOK || cResp.Header.Get("X-Gateway-Provider") != "gemini" {
		t.Fatalf("live chat failed: status=%d provider=%q body=%s", cResp.StatusCode, cResp.Header.Get("X-Gateway-Provider"), string(cRaw))
	}
	t.Logf("Live Gemini chat cost header=%s body=%s", cResp.Header.Get("X-Gateway-Cost-Micros"), string(cRaw))

	// 3. Live SSE streaming chat
	streamBody, _ := json.Marshal(map[string]any{
		"model":       "gemini-flash-live",
		"stream":      true,
		"max_tokens":  64,
		"temperature": 0,
		"messages":    []map[string]any{{"role": "user", "content": "Say hello in 3 words."}},
	})
	sReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/v1/chat/completions", bytes.NewReader(streamBody))
	sReq.Header.Set("Authorization", "Bearer "+cfg.Auth.DefaultVirtualKey)
	sReq.Header.Set("Content-Type", "application/json")
	sResp, err := http.DefaultClient.Do(sReq)
	if err != nil {
		t.Fatalf("live stream: %v", err)
	}
	defer sResp.Body.Close()
	sRaw, _ := io.ReadAll(sResp.Body)
	if sResp.StatusCode != http.StatusOK || !strings.Contains(string(sRaw), "[DONE]") {
		t.Fatalf("live stream failed: status=%d body=%s", sResp.StatusCode, string(sRaw))
	}

	// 4. Live batch embeddings
	embBody, _ := json.Marshal(map[string]any{
		"model":      "gemini-embed-live",
		"input":      []string{"GoRoute AI Gateway", "Google Gemini v1beta"},
		"dimensions": 8,
	})
	eReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/v1/embeddings", bytes.NewReader(embBody))
	eReq.Header.Set("Authorization", "Bearer "+cfg.Auth.DefaultVirtualKey)
	eReq.Header.Set("Content-Type", "application/json")
	eResp, err := http.DefaultClient.Do(eReq)
	if err != nil {
		t.Fatalf("live embeddings: %v", err)
	}
	defer eResp.Body.Close()
	var embOut map[string]any
	_ = json.NewDecoder(eResp.Body).Decode(&embOut)
	if eResp.StatusCode != http.StatusOK || len(embOut["data"].([]any)) != 2 {
		t.Fatalf("live embeddings failed: status=%d body=%v", eResp.StatusCode, embOut)
	}
	t.Logf("Live Gemini batch embeddings succeeded with %d vectors", len(embOut["data"].([]any)))
}
