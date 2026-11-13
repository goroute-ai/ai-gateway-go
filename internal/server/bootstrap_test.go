package server_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/server"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
)

func TestDeclarativeModelListBootstrapAndDynamicRouting(t *testing.T) {
	ctx := context.Background()

	// 1. Mock upstream Gemini and Anthropic servers
	gemUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ":generateContent") {
			fmt.Fprint(w, `{"candidates":[{"index":0,"content":{"role":"model","parts":[{"text":"Declarative Gemini reply"}]},"finishReason":"STOP"}],"usageMetadata":{"promptTokenCount":10,"candidatesTokenCount":6,"totalTokenCount":16}}`)
		}
	}))
	defer gemUpstream.Close()

	antUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/messages" {
			fmt.Fprint(w, `{"id":"msg_boot","type":"message","role":"assistant","model":"claude-sonnet-4-20250514","content":[{"type":"text","text":"Declarative Claude reply"}],"stop_reason":"end_turn","usage":{"input_tokens":20,"output_tokens":15}}`)
		}
	}))
	defer antUpstream.Close()

	// 2. Set environment variables referenced via "os.environ/..." syntax
	t.Setenv("TEST_BOOT_GEMINI_KEY", "AIzaSyDeclarativeBootKey")
	t.Setenv("TEST_BOOT_ANTHROPIC_KEY", "sk-ant-DeclarativeBootKey")

	// 3. Configure Gateway purely via declarative `ModelList` (ZERO /admin/v1/* calls!)
	cfg := config.Default()
	cfg.Auth.MasterAdminKey = "sk-gw-master-declarative-key"
	cfg.Auth.DefaultVirtualKey = "sk-gw-bootstrap-default-key"
	cfg.Security.Network.OutboundSSRF.AllowPrivateNetworks = true
	cfg.Security.Network.OutboundSSRF.AllowInsecureHTTP = true
	cfg.ModelList = []config.ModelListEntry{
		{
			ModelName: "fast",
			ModelParams: config.ModelParams{
				Model:   "gemini/gemini-2.5-flash",
				APIKey:  "os.environ/TEST_BOOT_GEMINI_KEY",
				APIBase: gemUpstream.URL,
			},
		},
		{
			ModelName: "reasoning",
			ModelParams: config.ModelParams{
				Model:   "anthropic/claude-sonnet-4-20250514",
				APIKey:  "os.environ/TEST_BOOT_ANTHROPIC_KEY",
				APIBase: antUpstream.URL,
			},
		},
	}

	gw, err := server.New(cfg, storage.NewMemoryRepository(), nil, nil)
	if err != nil {
		t.Fatalf("server.New with declarative ModelList failed: %v", err)
	}
	gw.StartWorkers(ctx)
	defer gw.Shutdown(ctx)

	ts := httptest.NewServer(gw.Handler())
	defer ts.Close()

	callChat := func(model, prompt string) (*http.Response, domain.CanonicalChatResponse) {
		b, _ := json.Marshal(domain.CanonicalChatRequest{
			Model:    model,
			Messages: []domain.CanonicalMessage{{Role: "user", Content: prompt}},
		})
		req, _ := http.NewRequest(http.MethodPost, ts.URL+"/v1/chat/completions", bytes.NewReader(b))
		req.Header.Set("Authorization", "Bearer "+cfg.Auth.DefaultVirtualKey)
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("chat request (%s) failed: %v", model, err)
		}
		defer resp.Body.Close()
		var out domain.CanonicalChatResponse
		_ = json.NewDecoder(resp.Body).Decode(&out)
		return resp, out
	}

	// Test A: Logical alias ("fast") works immediately without any /admin/v1/* setup
	resp, out := callChat("fast", "Hello!")
	if resp.StatusCode != http.StatusOK || out.Provider != domain.ProviderGemini {
		t.Fatalf("expected 200 OK from Gemini on 'fast', got status=%d provider=%s", resp.StatusCode, out.Provider)
	}

	// Test B: Dynamic Catalogue Model ("gemini-2.5-flash" and "gemini/gemini-2.5-pro") resolves on the fly
	// even though only "fast" and "reasoning" were declared in ModelList!
	resp, out = callChat("gemini-2.5-flash", "Explain Go")
	if resp.StatusCode != http.StatusOK || resp.Header.Get("X-Gateway-Model") != "gemini-2.5-flash" {
		t.Fatalf("expected dynamic resolution for 'gemini-2.5-flash', got status=%d model=%s", resp.StatusCode, resp.Header.Get("X-Gateway-Model"))
	}

	resp, out = callChat("gemini/gemini-2.5-pro", "Explain Go deeply")
	if resp.StatusCode != http.StatusOK || resp.Header.Get("X-Gateway-Model") != "gemini-2.5-pro" {
		t.Fatalf("expected dynamic resolution for 'gemini/gemini-2.5-pro', got status=%d model=%s", resp.StatusCode, resp.Header.Get("X-Gateway-Model"))
	}

	// Test C: Smart Routing ("auto") routes complex prompt to Anthropic Claude ("reasoning")
	resp, out = callChat("auto", "Analyze step by step the distributed concurrency design and prove the mathematical trade-off:\n```go\nfunc solve() {}\n```")
	if resp.StatusCode != http.StatusOK || out.Provider != domain.ProviderAnthropic {
		t.Fatalf("expected 'auto' complex prompt to route to Anthropic, got status=%d provider=%s", resp.StatusCode, out.Provider)
	}
}

func TestMetricsRequiresMasterAdminCredential(t *testing.T) {
	cfg := config.Default()
	cfg.Auth.MasterAdminKey = "sk-gw-metrics-test-master"
	gateway, err := server.New(cfg, storage.NewMemoryRepository(), nil, nil)
	if err != nil {
		t.Fatalf("create gateway: %v", err)
	}

	unauthenticated := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	unauthenticatedRecorder := httptest.NewRecorder()
	gateway.Handler().ServeHTTP(unauthenticatedRecorder, unauthenticated)
	if unauthenticatedRecorder.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without credentials, got %d", unauthenticatedRecorder.Code)
	}

	queryCredential := httptest.NewRequest(http.MethodGet, "/metrics?token=sk-gw-metrics-test-master", nil)
	queryRecorder := httptest.NewRecorder()
	gateway.Handler().ServeHTTP(queryRecorder, queryCredential)
	if queryRecorder.Code != http.StatusUnauthorized {
		t.Fatalf("expected query credentials to be rejected, got %d", queryRecorder.Code)
	}

	authenticated := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	authenticated.Header.Set("Authorization", "Bearer sk-gw-metrics-test-master")
	authenticatedRecorder := httptest.NewRecorder()
	gateway.Handler().ServeHTTP(authenticatedRecorder, authenticated)
	metricsBody := authenticatedRecorder.Body.String()
	if authenticatedRecorder.Code != http.StatusOK || !strings.Contains(metricsBody, "gateway_requests_total") {
		t.Fatalf("expected 200 with metrics for admin credential, got %d: %s", authenticatedRecorder.Code, authenticatedRecorder.Body.String())
	}
	for _, metric := range []string{"gateway_go_heap_alloc_bytes", "gateway_go_gc_cycles_total", "gateway_model_catalog_size", "gateway_response_cache_epoch_lookup_seconds_sum"} {
		if !strings.Contains(metricsBody, metric) {
			t.Fatalf("expected runtime metric %q, got: %s", metric, metricsBody)
		}
	}
}
