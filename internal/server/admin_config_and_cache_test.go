package server_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/guardrails"
	"github.com/goroute-ai/ai-gateway-go/internal/logger"
	"github.com/goroute-ai/ai-gateway-go/internal/observability"
	"github.com/goroute-ai/ai-gateway-go/internal/security/network"
	"github.com/goroute-ai/ai-gateway-go/internal/server"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
)

func TestAdminGetConfigRedactsSecrets(t *testing.T) {
	cfg := config.Default()
	cfg.Server.Environment = "test"
	cfg.Auth.MasterAdminKey = "sk-gw-super-secret-admin-key-12345"
	cfg.Auth.MasterEncryptionKey = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
	cfg.Auth.JWTSecret = "super-secret-jwt-hmac-value"
	cfg.Auth.DefaultVirtualKey = "sk-gw-default-virtual-secret"
	cfg.Storage.PostgresDSN = "postgres://gwuser:super-db-password@db.internal:5432/gateway?sslmode=require"
	cfg.Storage.RedisPass = "super-redis-password"
	cfg.Security.Network.OutboundSSRF.EgressProxyURL = "http://proxyuser:proxy-pass-secret@proxy.internal:3128"
	cfg.Tracing.Headers = map[string]string{"Authorization": "Bearer otlp-secret"}
	cfg.Guardrails.Scanners = []config.GuardrailScannerConfig{
		{
			Name:      "scanner-1",
			URL:       "https://user:scanner-url-pass@scanner.example.com/scan",
			TimeoutMs: 1500,
			Headers:   map[string]string{"X-API-Key": "scanner-header-secret"},
		},
	}
	cfg.ModelList = []config.ModelListEntry{
		{
			ModelName: "fast",
			ModelParams: config.ModelParams{
				Model:   "openai/gpt-4o-mini",
				APIKey:  "sk-openai-secret-key",
				Headers: map[string]string{"X-Provider-Secret": "provider-header-secret"},
			},
		},
	}

	gw, err := server.New(cfg, storage.NewMemoryRepository(), nil, nil)
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	defer gw.Shutdown(context.Background())

	// Unauthenticated request must be rejected.
	unauthReq := httptest.NewRequest(http.MethodGet, "/admin/v1/config", nil)
	unauthRec := httptest.NewRecorder()
	gw.Handler().ServeHTTP(unauthRec, unauthReq)
	if unauthRec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for unauthenticated /admin/v1/config, got %d", unauthRec.Code)
	}

	// Authenticated platform admin request must succeed and redact all secrets.
	req := httptest.NewRequest(http.MethodGet, "/admin/v1/config", nil)
	req.Header.Set("Authorization", "Bearer "+cfg.Auth.MasterAdminKey)
	rec := httptest.NewRecorder()
	gw.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for /admin/v1/config, got %d: %s", rec.Code, rec.Body.String())
	}

	bodyStr := rec.Body.String()
	forbiddenSecrets := []string{
		cfg.Auth.MasterAdminKey,
		cfg.Auth.MasterEncryptionKey,
		cfg.Auth.JWTSecret,
		cfg.Auth.DefaultVirtualKey,
		"super-db-password",
		"super-redis-password",
		"proxy-pass-secret",
		"otlp-secret",
		"scanner-url-pass",
		"scanner-header-secret",
		"sk-openai-secret-key",
		"provider-header-secret",
	}
	for _, secret := range forbiddenSecrets {
		if strings.Contains(bodyStr, secret) {
			t.Fatalf("response leaked secret %q in body: %s", secret, bodyStr)
		}
	}

	var parsed map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &parsed); err != nil {
		t.Fatalf("decode /admin/v1/config response: %v", err)
	}
	authSection, _ := parsed["auth"].(map[string]any)
	if authSection["master_admin_key"] != "[REDACTED]" || authSection["jwt_secret"] != "[REDACTED]" {
		t.Fatalf("expected redacted auth secrets, got %+v", authSection)
	}
	storageSection, _ := parsed["storage"].(map[string]any)
	if storageSection["redis_pass"] != "[REDACTED]" {
		t.Fatalf("expected redacted redis_pass, got %+v", storageSection)
	}
	if dsn, _ := storageSection["postgres_dsn"].(string); !strings.Contains(dsn, "REDACTED@db.internal:5432") {
		t.Fatalf("expected redacted postgres_dsn password, got %q", dsn)
	}
}

func TestResponsesAndMessagesCacheHit(t *testing.T) {
	var upstreamCalls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/completions") && !strings.HasSuffix(r.URL.Path, "/chat/completions"):
			_, _ = w.Write([]byte(`{
				"id":"cmpl_cache_1",
				"object":"text_completion",
				"created":1730000000,
				"model":"gpt-4o-mini",
				"choices":[{"index":0,"text":"cached completion text","finish_reason":"stop"}],
				"usage":{"prompt_tokens":6,"completion_tokens":4,"total_tokens":10}
			}`))
		case strings.HasSuffix(r.URL.Path, "/embeddings"):
			_, _ = w.Write([]byte(`{
				"object":"list",
				"model":"gpt-4o-mini",
				"data":[{"object":"embedding","index":0,"embedding":[0.11,0.22,0.33]}],
				"usage":{"prompt_tokens":4,"total_tokens":4}
			}`))
		default:
			_, _ = w.Write([]byte(`{
				"id":"chatcmpl_cache_1",
				"object":"chat.completion",
				"created":1730000000,
				"model":"gpt-4o-mini",
				"choices":[{"index":0,"message":{"role":"assistant","content":"cached reply"},"finish_reason":"stop"}],
				"usage":{"prompt_tokens":10,"completion_tokens":5,"total_tokens":15}
			}`))
		}
	}))
	defer upstream.Close()

	cfg := config.Default()
	cfg.Server.Environment = "test"
	cfg.Cache.Enabled = true
	cfg.Security.Network.OutboundSSRF.AllowPrivateNetworks = true
	cfg.Security.Network.OutboundSSRF.AllowInsecureHTTP = true
	cfg.Auth.DefaultVirtualKey = "sk-gw-cache-test-key-123456"
	cfg.ModelList = []config.ModelListEntry{
		{
			ModelName: "gpt-4o-mini",
			ModelParams: config.ModelParams{
				Model:   "openai/gpt-4o-mini",
				APIKey:  "sk-upstream-test",
				APIBase: upstream.URL,
			},
		},
		{
			ModelName: "gpt-3.5-turbo-instruct",
			ModelParams: config.ModelParams{
				Model:   "openai/gpt-3.5-turbo-instruct",
				APIKey:  "sk-upstream-test",
				APIBase: upstream.URL,
			},
		},
		{
			ModelName: "text-embedding-3-small",
			ModelParams: config.ModelParams{
				Model:   "openai/text-embedding-3-small",
				APIKey:  "sk-upstream-test",
				APIBase: upstream.URL,
			},
		},
	}

	gw, err := server.New(cfg, storage.NewMemoryRepository(), nil, upstream.Client())
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	defer gw.Shutdown(context.Background())

	// Issue a virtual key with wildcard endpoint/model permissions.
	keyReq := httptest.NewRequest(http.MethodPost, "/admin/v1/keys", bytes.NewReader([]byte(`{"org_id":"org_default","name":"cache-test-key","allowed_endpoints":["*"],"allowed_models":["*"]}`)))
	keyReq.Header.Set("Authorization", "Bearer "+cfg.Auth.MasterAdminKey)
	keyReq.Header.Set("Content-Type", "application/json")
	keyRec := httptest.NewRecorder()
	gw.Handler().ServeHTTP(keyRec, keyReq)
	if keyRec.Code != http.StatusCreated {
		t.Fatalf("issue key failed (%d): %s", keyRec.Code, keyRec.Body.String())
	}
	var issuedKey struct {
		Key string `json:"raw_key"`
	}
	_ = json.Unmarshal(keyRec.Body.Bytes(), &issuedKey)

	// 1. /v1/responses cache miss then hit
	respPayload := []byte(`{"model":"gpt-4o-mini","input":"hello cache","temperature":0}`)
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodPost, "/v1/responses", bytes.NewReader(respPayload))
		req.Header.Set("Authorization", "Bearer "+issuedKey.Key)
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		gw.Handler().ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("/v1/responses call %d failed (%d): %s", i, rec.Code, rec.Body.String())
		}
		wantCache := "MISS"
		if i == 1 {
			wantCache = "HIT"
		}
		if got := rec.Header().Get("X-Gateway-Cache"); got != wantCache {
			t.Fatalf("/v1/responses call %d: expected X-Gateway-Cache=%s, got %q", i, wantCache, got)
		}
	}
	if calls := upstreamCalls.Load(); calls != 1 {
		t.Fatalf("expected 1 upstream call for /v1/responses miss+hit, got %d", calls)
	}

	// 2. /v1/messages cache miss then hit
	msgPayload := []byte(`{"model":"gpt-4o-mini","max_tokens":64,"temperature":0,"messages":[{"role":"user","content":"hello anthropic cache"}]}`)
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodPost, "/v1/messages", bytes.NewReader(msgPayload))
		req.Header.Set("Authorization", "Bearer "+issuedKey.Key)
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		gw.Handler().ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("/v1/messages call %d failed (%d): %s", i, rec.Code, rec.Body.String())
		}
		wantCache := "MISS"
		if i == 1 {
			wantCache = "HIT"
		}
		if got := rec.Header().Get("X-Gateway-Cache"); got != wantCache {
			t.Fatalf("/v1/messages call %d: expected X-Gateway-Cache=%s, got %q", i, wantCache, got)
		}
	}
	if calls := upstreamCalls.Load(); calls != 2 {
		t.Fatalf("expected 2 total upstream calls after /v1/messages miss+hit, got %d", calls)
	}

	// 3. /v1/completions cache miss then hit
	cmplPayload := []byte(`{"model":"gpt-3.5-turbo-instruct","prompt":"hello completion cache","temperature":0}`)
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodPost, "/v1/completions", bytes.NewReader(cmplPayload))
		req.Header.Set("Authorization", "Bearer "+issuedKey.Key)
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		gw.Handler().ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("/v1/completions call %d failed (%d): %s", i, rec.Code, rec.Body.String())
		}
		wantCache := "MISS"
		if i == 1 {
			wantCache = "HIT"
		}
		if got := rec.Header().Get("X-Gateway-Cache"); got != wantCache {
			t.Fatalf("/v1/completions call %d: expected X-Gateway-Cache=%s, got %q", i, wantCache, got)
		}
	}
	if calls := upstreamCalls.Load(); calls != 3 {
		t.Fatalf("expected 3 total upstream calls after /v1/completions miss+hit, got %d", calls)
	}

	// 4. /v1/embeddings cache miss then hit
	embPayload := []byte(`{"model":"text-embedding-3-small","input":"hello embedding cache"}`)
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodPost, "/v1/embeddings", bytes.NewReader(embPayload))
		req.Header.Set("Authorization", "Bearer "+issuedKey.Key)
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		gw.Handler().ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("/v1/embeddings call %d failed (%d): %s", i, rec.Code, rec.Body.String())
		}
		wantCache := "MISS"
		if i == 1 {
			wantCache = "HIT"
		}
		if got := rec.Header().Get("X-Gateway-Cache"); got != wantCache {
			t.Fatalf("/v1/embeddings call %d: expected X-Gateway-Cache=%s, got %q", i, wantCache, got)
		}
	}
	if calls := upstreamCalls.Load(); calls != 4 {
		t.Fatalf("expected 4 total upstream calls after /v1/embeddings miss+hit, got %d", calls)
	}
}

func TestHTTPGuardrailScanner(t *testing.T) {
	scannerSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Scanner-Token") != "resolved-secret" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		var payload struct {
			Content string `json:"content"`
		}
		_ = json.NewDecoder(r.Body).Decode(&payload)
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(payload.Content, "forbidden") {
			_, _ = w.Write([]byte(`{"decision":"block","violations":["external_policy_violation"]}`))
			return
		}
		_, _ = w.Write([]byte(`{"decision":"allow"}`))
	}))
	defer scannerSrv.Close()

	t.Setenv("TEST_SCANNER_TOKEN", "resolved-secret")

	ssrfPolicy, err := network.NewPolicy(config.OutboundSSRFConfig{
		AllowPrivateNetworks: true,
		AllowInsecureHTTP:    true,
	})
	if err != nil {
		t.Fatalf("network.NewPolicy: %v", err)
	}

	_, failClosed, scanners := server.NewHTTPGuardrailScanners(config.GuardrailsConfig{
		Scanners: []config.GuardrailScannerConfig{
			{
				Name:      "ext-1",
				URL:       scannerSrv.URL,
				TimeoutMs: 1000,
				FailOpen:  false,
				Headers:   map[string]string{"X-Scanner-Token": "os.environ/TEST_SCANNER_TOKEN"},
			},
		},
	}, ssrfPolicy)
	if !failClosed || len(scanners) != 1 {
		t.Fatalf("expected failClosed=true and 1 scanner, got failClosed=%v len=%d", failClosed, len(scanners))
	}

	res, err := scanners[0].Scan(context.Background(), guardrails.ScanRequest{
		OrgID:     "org_1",
		Direction: guardrails.ScanInput,
		Content:   "safe prompt",
	})
	if err != nil || res.Decision != guardrails.ScannerDecisionAllow {
		t.Fatalf("expected allow, got res=%+v err=%v", res, err)
	}

	res, err = scanners[0].Scan(context.Background(), guardrails.ScanRequest{
		OrgID:     "org_1",
		Direction: guardrails.ScanInput,
		Content:   "this is forbidden content",
	})
	if err != nil || res.Decision != guardrails.ScannerDecisionBlock || len(res.Violations) != 1 {
		t.Fatalf("expected block with violation, got res=%+v err=%v", res, err)
	}

	// FailOpen=true should allow on HTTP error; FailOpen=false should return error.
	errSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer errSrv.Close()

	_, _, failOpenScanners := server.NewHTTPGuardrailScanners(config.GuardrailsConfig{
		Scanners: []config.GuardrailScannerConfig{
			{Name: "open", URL: errSrv.URL, FailOpen: true},
			{Name: "closed", URL: errSrv.URL, FailOpen: false},
		},
	}, ssrfPolicy)

	openRes, openErr := failOpenScanners[0].Scan(context.Background(), guardrails.ScanRequest{OrgID: "org_1", Direction: guardrails.ScanInput, Content: "x"})
	if openErr != nil || openRes.Decision != guardrails.ScannerDecisionAllow {
		t.Fatalf("expected fail-open scanner to allow on 500, got res=%+v err=%v", openRes, openErr)
	}
	if _, closedErr := failOpenScanners[1].Scan(context.Background(), guardrails.ScanRequest{OrgID: "org_1", Direction: guardrails.ScanInput, Content: "x"}); closedErr == nil {
		t.Fatalf("expected fail-closed scanner to return error on 500")
	}
}

func TestServerOTLPMetricsExporterWiredWhenTracingEnabled(t *testing.T) {
	metricsReceived := make(chan string, 4)
	otlpSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if r.URL.Path == "/v1/metrics" {
			metricsReceived <- string(body)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer otlpSrv.Close()

	cfg := config.Default()
	cfg.Server.Environment = "test"
	cfg.Security.Network.OutboundSSRF.AllowPrivateNetworks = true
	cfg.Security.Network.OutboundSSRF.AllowInsecureHTTP = true
	cfg.Tracing.Enabled = true
	cfg.Tracing.OTLPEndpoint = otlpSrv.URL + "/v1/traces"
	cfg.Tracing.ServiceName = "gw-otlp-server-test"

	gw, err := server.New(cfg, storage.NewMemoryRepository(), nil, nil)
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	if gw.MetricsExporter() == nil {
		t.Fatalf("expected MetricsExporter() to be initialized when Tracing.Enabled && Tracing.OTLPEndpoint != \"\"")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	gw.StartWorkers(ctx)

	// Record a metric and trigger Shutdown, which flushes OTLPMetricsExporter.
	gw.Collector().Record(observability.RequestObservation{
		Provider:   "openai",
		Model:      "gpt-4o-mini",
		StatusCode: http.StatusOK,
	})
	gw.Shutdown(ctx)

	select {
	case payload := <-metricsReceived:
		if !strings.Contains(payload, "gw-otlp-server-test") || !strings.Contains(payload, "gateway_requests_total") {
			t.Fatalf("unexpected OTLP metrics payload: %s", payload)
		}
	case <-ctx.Done():
		t.Fatal("timed out waiting for OTLPMetricsExporter flush on GatewayServer Shutdown")
	}
}

func TestServerRateLimitFallbackToLocalOnOutageWired(t *testing.T) {
	cfg := config.Default()
	cfg.Server.Environment = "test"
	cfg.RateLimit.Enabled = true
	cfg.RateLimit.FallbackToLocalOnOutage = true

	gw, err := server.New(cfg, storage.NewMemoryRepository(), nil, nil)
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	defer gw.Shutdown(context.Background())

	// 1. Check /admin/v1/config includes rate_limit.fallback_to_local_on_outage = true
	req := httptest.NewRequest(http.MethodGet, "/admin/v1/config", nil)
	req.Header.Set("Authorization", "Bearer "+cfg.Auth.MasterAdminKey)
	rec := httptest.NewRecorder()
	gw.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 from /admin/v1/config, got %d", rec.Code)
	}
	var parsed map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &parsed); err != nil {
		t.Fatalf("decode /admin/v1/config: %v", err)
	}
	rlMap, _ := parsed["rate_limit"].(map[string]any)
	if rlMap["fallback_to_local_on_outage"] != true {
		t.Fatalf("expected fallback_to_local_on_outage=true in /admin/v1/config, got %+v", rlMap)
	}

	// 2. Verify Limiter enforces RPM locally without Redis when FallbackToLocalOnOutage=true
	idCtx := &domain.IdentityContext{
		VirtualKeyID: "vk_local_fallback",
		OrgID:        "org_default",
		KeyRPMLimit:  1,
	}
	rel, err := gw.Limiter().Acquire(context.Background(), idCtx, 10)
	if err != nil {
		t.Fatalf("expected first local fallback Acquire to succeed, got %v", err)
	}
	rel(10)
	if _, err := gw.Limiter().Acquire(context.Background(), idCtx, 10); err == nil {
		t.Fatal("expected second Acquire to be rejected by local RPM limit when FallbackToLocalOnOutage=true")
	}
}

type threadSafeBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *threadSafeBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *threadSafeBuffer) Reset() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.buf.Reset()
}

func (b *threadSafeBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func TestResponsesAndMessagesInferenceMetaPopulated(t *testing.T) {
	var logBuf threadSafeBuffer
	logger.Init(logger.Config{Level: "info", Format: "json", Output: &logBuf})
	defer logger.Init(logger.Config{Level: "info", Format: "text", Output: io.Discard})

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		if isStream, _ := body["stream"].(bool); isStream {
			w.Header().Set("Content-Type", "text/event-stream")
			fmt.Fprint(w, "data: {\"id\":\"chatcmpl_s1\",\"object\":\"chat.completion.chunk\",\"created\":1730000000,\"model\":\"gpt-4o-mini\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"streamed text\"}}]}\n\n")
			fmt.Fprint(w, "data: {\"id\":\"chatcmpl_s1\",\"object\":\"chat.completion.chunk\",\"created\":1730000000,\"model\":\"gpt-4o-mini\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":11,\"completion_tokens\":7,\"total_tokens\":18}}\n\n")
			fmt.Fprint(w, "data: [DONE]\n\n")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"id":"chatcmpl_meta_1",
			"object":"chat.completion",
			"created":1730000000,
			"model":"gpt-4o-mini",
			"choices":[{"index":0,"message":{"role":"assistant","content":"meta reply"},"finish_reason":"stop"}],
			"usage":{"prompt_tokens":12,"completion_tokens":6,"total_tokens":18}
		}`))
	}))
	defer upstream.Close()

	cfg := config.Default()
	cfg.Server.Environment = "test"
	cfg.Cache.Enabled = true
	cfg.Security.Network.OutboundSSRF.AllowPrivateNetworks = true
	cfg.Security.Network.OutboundSSRF.AllowInsecureHTTP = true
	cfg.ModelList = []config.ModelListEntry{
		{
			ModelName: "gpt-4o-mini",
			ModelParams: config.ModelParams{
				Model:   "openai/gpt-4o-mini",
				APIKey:  "sk-upstream-test",
				APIBase: upstream.URL,
			},
		},
	}

	gw, err := server.New(cfg, storage.NewMemoryRepository(), nil, upstream.Client())
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	defer gw.Shutdown(context.Background())

	keyReq := httptest.NewRequest(http.MethodPost, "/admin/v1/keys", bytes.NewReader([]byte(`{"org_id":"org_default","name":"meta-test-key","allowed_endpoints":["*"],"allowed_models":["*"]}`)))
	keyReq.Header.Set("Authorization", "Bearer "+cfg.Auth.MasterAdminKey)
	keyReq.Header.Set("Content-Type", "application/json")
	keyRec := httptest.NewRecorder()
	gw.Handler().ServeHTTP(keyRec, keyReq)
	var issuedKey struct {
		Key string `json:"raw_key"`
	}
	_ = json.Unmarshal(keyRec.Body.Bytes(), &issuedKey)

	assertHTTPMetaLog := func(path string, wantCacheHit bool) {
		t.Helper()
		lines := strings.Split(strings.TrimSpace(logBuf.String()), "\n")
		for i := len(lines) - 1; i >= 0; i-- {
			var entry map[string]any
			if err := json.Unmarshal([]byte(lines[i]), &entry); err != nil {
				continue
			}
			if entry["component"] != "http" || entry["path"] != path {
				continue
			}
			if entry["model"] != "gpt-4o-mini" || entry["provider"] != "openai" {
				t.Fatalf("expected InferenceMeta model=gpt-4o-mini provider=openai on %s, got log entry: %s", path, lines[i])
			}
			if entry["prompt_tokens"] == nil || entry["completion_tokens"] == nil {
				t.Fatalf("expected InferenceMeta token counts on %s, got log entry: %s", path, lines[i])
			}
			gotCache, _ := entry["cache_hit"].(bool)
			if gotCache != wantCacheHit {
				t.Fatalf("expected cache_hit=%v on %s, got log entry: %s", wantCacheHit, path, lines[i])
			}
			return
		}
		t.Fatalf("did not find http log entry for %s in logs:\n%s", path, logBuf.String())
	}

	// 1. /v1/responses non-streaming (cache MISS) + cache HIT + streaming
	for i := 0; i < 2; i++ {
		logBuf.Reset()
		req := httptest.NewRequest(http.MethodPost, "/v1/responses", bytes.NewReader([]byte(`{"model":"gpt-4o-mini","input":"hello meta","temperature":0}`)))
		req.Header.Set("Authorization", "Bearer "+issuedKey.Key)
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		gw.Handler().ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("/v1/responses call %d failed (%d): %s", i, rec.Code, rec.Body.String())
		}
		assertHTTPMetaLog("/v1/responses", i == 1)
	}

	logBuf.Reset()
	streamRespReq := httptest.NewRequest(http.MethodPost, "/v1/responses", bytes.NewReader([]byte(`{"model":"gpt-4o-mini","input":"hello stream meta","stream":true}`)))
	streamRespReq.Header.Set("Authorization", "Bearer "+issuedKey.Key)
	streamRespReq.Header.Set("Content-Type", "application/json")
	streamRespRec := httptest.NewRecorder()
	gw.Handler().ServeHTTP(streamRespRec, streamRespReq)
	if streamRespRec.Code != http.StatusOK {
		t.Fatalf("/v1/responses stream failed (%d): %s", streamRespRec.Code, streamRespRec.Body.String())
	}
	assertHTTPMetaLog("/v1/responses", false)

	// 2. /v1/messages non-streaming (cache MISS) + cache HIT + streaming
	for i := 0; i < 2; i++ {
		logBuf.Reset()
		req := httptest.NewRequest(http.MethodPost, "/v1/messages", bytes.NewReader([]byte(`{"model":"gpt-4o-mini","max_tokens":32,"temperature":0,"messages":[{"role":"user","content":"hello messages meta"}]}`)))
		req.Header.Set("Authorization", "Bearer "+issuedKey.Key)
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		gw.Handler().ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("/v1/messages call %d failed (%d): %s", i, rec.Code, rec.Body.String())
		}
		assertHTTPMetaLog("/v1/messages", i == 1)
	}

	logBuf.Reset()
	streamMsgReq := httptest.NewRequest(http.MethodPost, "/v1/messages", bytes.NewReader([]byte(`{"model":"gpt-4o-mini","max_tokens":32,"stream":true,"messages":[{"role":"user","content":"hello messages stream meta"}]}`)))
	streamMsgReq.Header.Set("Authorization", "Bearer "+issuedKey.Key)
	streamMsgReq.Header.Set("Content-Type", "application/json")
	streamMsgRec := httptest.NewRecorder()
	gw.Handler().ServeHTTP(streamMsgRec, streamMsgReq)
	if streamMsgRec.Code != http.StatusOK {
		t.Fatalf("/v1/messages stream failed (%d): %s", streamMsgRec.Code, streamMsgRec.Body.String())
	}
	assertHTTPMetaLog("/v1/messages", false)
}
