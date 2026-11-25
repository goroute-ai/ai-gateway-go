//go:build obsproddocker

package obsproddocker

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

const (
	obsLBBase         = "https://gateway.prod.test:20443"
	obsPod1Base       = "https://gateway.prod.test:20444"
	obsPod2Base       = "https://gateway.prod.test:20445"
	obsFixturesBase   = "https://fixtures.prod.test:20443"
	obsMasterKey      = "sk-gw-obs-prod-master-admin-key-2026-secure"
	obsOTelAuthHeader = "Bearer obs-prod-otel-collector-token-2026"
	obsSIEMSecret     = "obs-prod-siem-hmac-secret-2026"
	obsRedisPass      = "obs-prod-redis-pass-2026"
	obsPostgresPass   = "obs-prod-pg-password-2026"
)

func repoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	return filepath.Clean(filepath.Join(wd, "..", ".."))
}

func obsCertPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(repoRoot(t), ".tmp", "obs-prod-certs", "ca.crt")
}

func obsOTelOutDir(t *testing.T) string {
	t.Helper()
	return filepath.Join(repoRoot(t), ".tmp", "obs-prod-otel")
}

func obsComposeFile(t *testing.T) string {
	t.Helper()
	return filepath.Join(repoRoot(t), "deployments", "obs-prod-test", "docker-compose.obs-prod.yml")
}

func newObsHTTPClient(t *testing.T) *http.Client {
	t.Helper()
	caPEM, err := os.ReadFile(obsCertPath(t))
	if err != nil {
		t.Fatalf("read ephemeral CA cert: %v", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		t.Fatalf("failed to parse CA cert")
	}
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs:    pool,
			MinVersion: tls.VersionTLS13,
		},
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err == nil && (host == "gateway.prod.test" || host == "fixtures.prod.test" || host == "otel.prod.test") {
				addr = net.JoinHostPort("127.0.0.1", port)
			}
			return dialer.DialContext(ctx, network, addr)
		},
	}
	return &http.Client{Transport: tr, Timeout: 30 * time.Second}
}

type httpResult struct {
	StatusCode int
	Header     http.Header
}

func doReq(t *testing.T, client *http.Client, method, url string, body any, headers map[string]string) (httpResult, []byte) {
	t.Helper()
	var bodyReader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal %s %s: %v", method, url, err)
		}
		bodyReader = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, url, bodyReader)
	if err != nil {
		t.Fatalf("new request %s %s: %v", method, url, err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("%s %s failed: %v", method, url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read %s %s body: %v", method, url, err)
	}
	return httpResult{StatusCode: resp.StatusCode, Header: resp.Header.Clone()}, raw
}

func mustAdminJSON(t *testing.T, client *http.Client, method, url string, body any, out any, wantStatuses ...int) []byte {
	t.Helper()
	resp, raw := doReq(t, client, method, url, body, map[string]string{
		"Authorization": "Bearer " + obsMasterKey,
	})
	if !slices.Contains(wantStatuses, resp.StatusCode) {
		t.Fatalf("%s %s: got status %d, want %v; body=%s", method, url, resp.StatusCode, wantStatuses, string(raw))
	}
	if out != nil && len(raw) > 0 {
		if err := json.Unmarshal(raw, out); err != nil {
			t.Fatalf("%s %s: decode JSON: %v; body=%s", method, url, err, string(raw))
		}
	}
	return raw
}

func waitForCondition(t *testing.T, timeout time.Duration, desc string, fn func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if fn() {
			return
		}
		time.Sleep(250 * time.Millisecond)
	}
	t.Fatalf("timed out after %s waiting for: %s", timeout, desc)
}

func readFileText(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(b)
}

func runDockerCompose(t *testing.T, args ...string) string {
	t.Helper()
	full := append([]string{"compose", "-f", obsComposeFile(t)}, args...)
	cmd := exec.Command("docker", full...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("docker %s failed: %v\n%s", strings.Join(full, " "), err, string(out))
	}
	return string(out)
}

func seedGlobalModel(t *testing.T, id, provider, modelName string) string {
	t.Helper()
	q := fmt.Sprintf(`
INSERT INTO global_models (
	id, provider, model_name, display_name,
	input_cost_micros_per_1m, output_cost_micros_per_1m,
	pricing_status, pricing_version, pricing_provenance_source,
	max_input_tokens, max_output_tokens, supports_inference, capabilities
) VALUES (
	'%s', '%s', '%s', '%s',
	150000, 600000,
	'verified', 1, 'obs-prod-docker-test',
	128000, 16384, TRUE, '{"streaming":"supported","tools":"supported"}'::jsonb
)
ON CONFLICT (provider, model_name) DO UPDATE SET
	pricing_status = 'verified',
	supports_inference = TRUE
RETURNING id;`,
		strings.ReplaceAll(id, "'", "''"),
		strings.ReplaceAll(provider, "'", "''"),
		strings.ReplaceAll(modelName, "'", "''"),
		strings.ReplaceAll(modelName, "'", "''"),
	)
	out := runDockerCompose(t, "exec", "-T", "postgres", "psql", "-U", "gateway", "-d", "aigateway", "-t", "-A", "-c", q)
	for line := range strings.SplitSeq(strings.TrimSpace(out), "\n") {
		if trimmed := strings.TrimSpace(line); trimmed != "" {
			return trimmed
		}
	}
	return id
}

func TestObsProd_FullOTLPVerificationSuites(t *testing.T) {
	client := newObsHTTPClient(t)

	// -------------------------------------------------------------------------
	// 0. Verify removed Prometheus /metrics returns 404 on both pods and LB.
	// -------------------------------------------------------------------------
	for _, base := range []string{obsLBBase, obsPod1Base, obsPod2Base} {
		resp, _ := doReq(t, client, http.MethodGet, base+"/metrics", nil, map[string]string{
			"Authorization": "Bearer " + obsMasterKey,
		})
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("expected removed Prometheus %s/metrics to return 404, got %d", base, resp.StatusCode)
		}
	}

	// Reset fixture capture state
	doReq(t, client, http.MethodPost, obsFixturesBase+"/_inspect/reset", nil, nil)

	// -------------------------------------------------------------------------
	// 1. Provision Org, 6 Provider Credentials & Deployments (OpenAI, Anthropic,
	//    Groq, OpenRouter, Ollama, Gemini), MCP Server + Tools, A2A Agent, and Virtual Key.
	// -------------------------------------------------------------------------
	var org struct {
		ID string `json:"id"`
	}
	mustAdminJSON(t, client, http.MethodPost, obsPod1Base+"/admin/v1/organizations", map[string]any{
		"name": "Obs Prod Org",
	}, &org, http.StatusCreated)

	// Verify keyless Ollama preflight validation succeeds over TLS 1.3 in production mode
	var ollamaPreflight struct {
		Valid            bool `json:"valid"`
		DiscoveredModels int  `json:"discovered_models"`
	}
	mustAdminJSON(t, client, http.MethodPost, obsPod1Base+"/admin/v1/credentials/validate", map[string]any{
		"org_id":   org.ID,
		"provider": "ollama",
		"api_key":  "",
		"base_url": obsFixturesBase + "/ollama",
	}, &ollamaPreflight, http.StatusOK)
	if !ollamaPreflight.Valid || ollamaPreflight.DiscoveredModels < 2 {
		t.Fatalf("expected valid keyless Ollama preflight with >=2 models, got %+v", ollamaPreflight)
	}

	type providerSetup struct {
		provider string
		baseURL  string
		alias    string
		model    string
		credKey  string
	}
	providers := []providerSetup{
		{provider: "openai", baseURL: obsFixturesBase + "/openai/v1", alias: "obs-openai", model: "gpt-4.1-mini", credKey: "sk-obs-openai-fixture-secret"},
		{provider: "openai", baseURL: obsFixturesBase + "/openai/v1", alias: "obs-embed", model: "text-embedding-3-small", credKey: "sk-obs-openai-embed-secret"},
		{provider: "anthropic", baseURL: obsFixturesBase + "/anthropic", alias: "obs-anthropic", model: "claude-3-5-haiku-latest", credKey: "sk-ant-obs-fixture-secret"},
		{provider: "groq", baseURL: obsFixturesBase + "/groq/openai/v1", alias: "obs-groq", model: "llama-3.3-70b-versatile", credKey: "gsk_obs_fixture_secret"},
		{provider: "openrouter", baseURL: obsFixturesBase + "/openrouter/api/v1", alias: "obs-openrouter", model: "openai/gpt-4o-mini", credKey: "sk-or-obs-fixture-secret"},
		{provider: "ollama", baseURL: obsFixturesBase + "/ollama", alias: "obs-ollama", model: "qwen2.5:0.5b", credKey: ""},
		{provider: "ollama", baseURL: obsFixturesBase + "/ollama", alias: "obs-ollama-embed", model: "all-minilm:latest", credKey: ""},
		{provider: "gemini", baseURL: obsFixturesBase + "/gemini", alias: "obs-gemini", model: "gemini-2.5-flash", credKey: "gem-obs-fixture-secret"},
	}

	for _, ps := range providers {
		gmID := seedGlobalModel(t, ps.provider+"/"+ps.model, ps.provider, ps.model)
		var cred struct {
			ID string `json:"id"`
		}
		mustAdminJSON(t, client, http.MethodPost, obsPod1Base+"/admin/v1/credentials", map[string]any{
			"org_id":   org.ID,
			"provider": ps.provider,
			"name":     "cred-" + ps.alias,
			"api_key":  ps.credKey,
			"base_url": ps.baseURL,
		}, &cred, http.StatusCreated)

		var mg struct {
			ID string `json:"id"`
		}
		mustAdminJSON(t, client, http.MethodPost, obsPod1Base+"/admin/v1/model-groups", map[string]any{
			"org_id":           org.ID,
			"alias":            ps.alias,
			"routing_strategy": "round_robin",
		}, &mg, http.StatusCreated)

		mustAdminJSON(t, client, http.MethodPost, obsPod1Base+"/admin/v1/deployments", map[string]any{
			"model_group_id":  mg.ID,
			"global_model_id": gmID,
			"credential_id":   cred.ID,
			"deployment_name": "dep-" + ps.alias,
			"priority":        1,
			"weight":          100,
		}, nil, http.StatusCreated)
	}

	// Register MCP Server and sync tools
	var mcpSrv struct {
		Server struct {
			ID string `json:"id"`
		} `json:"server"`
	}
	mustAdminJSON(t, client, http.MethodPost, obsPod1Base+"/admin/v1/mcp/servers", map[string]any{
		"org_id":           org.ID,
		"name":             "Obs MCP Fixture",
		"slug":             "obs-mcp",
		"protocol_version": "2026-07-28",
		"transport_type":   "streamable_http",
		"endpoint_url":     obsFixturesBase + "/mcp",
		"auth_type":        "none",
	}, &mcpSrv, http.StatusCreated)
	mustAdminJSON(t, client, http.MethodPost, obsPod1Base+"/admin/v1/mcp/servers/"+mcpSrv.Server.ID+"/sync", nil, nil, http.StatusOK)

	// Register A2A Agent
	mustAdminJSON(t, client, http.MethodPost, obsPod1Base+"/admin/v1/a2a/agents", map[string]any{
		"org_id":               org.ID,
		"name":                 "Obs A2A Agent",
		"slug":                 "obs-agent",
		"endpoint_url":         obsFixturesBase + "/a2a",
		"auth_type":            "none",
		"task_visibility_mode": "key_strict",
	}, nil, http.StatusCreated)

	// Issue a virtual key with access to all models, MCP server, and A2A agent
	var vk struct {
		ID     string `json:"id"`
		RawKey string `json:"raw_key"`
	}
	mustAdminJSON(t, client, http.MethodPost, obsPod1Base+"/admin/v1/keys", map[string]any{
		"org_id":              org.ID,
		"name":                "obs-e2e-key",
		"allowed_mcp_servers": []string{"obs-mcp"},
		"allowed_a2a_agents":  []string{"obs-agent"},
	}, &vk, http.StatusCreated)

	vkHeaders := map[string]string{
		"Authorization": "Bearer " + vk.RawKey,
	}

	// Create an org-scoped local_content_filter guardrail so guardrail.evaluate spans & gateway.guardrail.* metrics fire deterministically.
	mustAdminJSON(t, client, http.MethodPost, obsPod1Base+"/admin/v1/organizations/"+org.ID+"/guardrail-definitions", map[string]any{
		"name":        "obs-pii-guard",
		"provider":    "local_content_filter",
		"event_hooks": []string{"pre_call"},
		"default_on":  true,
		"config": map[string]any{
			"action":        "block",
			"blocked_words": []string{"FORBIDDEN_OBS_BLOCK_TOKEN"},
		},
	}, nil, http.StatusCreated)

	// Trigger active health probe once to populate gateway.deployment.healthy
	mustAdminJSON(t, client, http.MethodPost, obsPod1Base+"/admin/v1/health/probe", nil, nil, http.StatusOK)

	// -------------------------------------------------------------------------
	// 2. Drive real traffic across all 4 adapters, streaming SSE, cache hit,
	//    embeddings, guardrail block, MCP tool execution, and A2A invocation!
	// -------------------------------------------------------------------------
	secretPromptCanary := "TOP_SECRET_PROMPT_CANARY_NEVER_EXPORT_IN_TRACES"
	piiEmailCanary := "private.user.canary@secret-corp.example"

	// 2a. OpenAI chat (MISS) + identical repeat (HIT) on pod1 so local cache hits!
	chatPayload := map[string]any{
		"model":       "obs-openai",
		"temperature": 0,
		"messages": []map[string]any{
			{"role": "user", "content": "Hello " + secretPromptCanary + " contact " + piiEmailCanary},
		},
	}
	r1, b1 := doReq(t, client, http.MethodPost, obsPod1Base+"/v1/chat/completions", chatPayload, vkHeaders)
	if r1.StatusCode != http.StatusOK || r1.Header.Get("X-Gateway-Cache") != "MISS" {
		t.Fatalf("openai chat #1 failed: status=%d cache=%s body=%s", r1.StatusCode, r1.Header.Get("X-Gateway-Cache"), string(b1))
	}
	if r1.Header.Get("traceparent") == "" {
		t.Fatalf("expected W3C traceparent response header on chat completion")
	}
	r2, b2 := doReq(t, client, http.MethodPost, obsPod1Base+"/v1/chat/completions", chatPayload, vkHeaders)
	if r2.StatusCode != http.StatusOK || r2.Header.Get("X-Gateway-Cache") != "HIT" {
		t.Fatalf("openai chat #2 expected cache HIT: status=%d cache=%s body=%s", r2.StatusCode, r2.Header.Get("X-Gateway-Cache"), string(b2))
	}

	// 2b. OpenAI streaming SSE (exercises TTFT + gen_ai.first_token span event)
	rStream, bStream := doReq(t, client, http.MethodPost, obsPod1Base+"/v1/chat/completions", map[string]any{
		"model":    "obs-openai",
		"stream":   true,
		"messages": []map[string]any{{"role": "user", "content": "stream telemetry test"}},
	}, vkHeaders)
	if rStream.StatusCode != http.StatusOK || !strings.Contains(string(bStream), "openai-obs-ok") {
		t.Fatalf("openai streaming failed: status=%d body=%s", rStream.StatusCode, string(bStream))
	}

	// 2c. OpenAI embeddings (exercises embeddings GenAI span)
	rEmb, bEmb := doReq(t, client, http.MethodPost, obsPod2Base+"/v1/embeddings", map[string]any{
		"model": "obs-embed",
		"input": []string{"otel embeddings trace verification"},
	}, vkHeaders)
	if rEmb.StatusCode != http.StatusOK {
		t.Fatalf("embeddings failed: status=%d body=%s", rEmb.StatusCode, string(bEmb))
	}

	// 2d. Anthropic, Groq, OpenRouter, Ollama, and Gemini chat + Ollama embeddings (Suite O4: 6-adapter W3C traceparent propagation)
	for _, alias := range []string{"obs-anthropic", "obs-groq", "obs-openrouter", "obs-ollama", "obs-gemini"} {
		resp, body := doReq(t, client, http.MethodPost, obsLBBase+"/v1/chat/completions", map[string]any{
			"model":    alias,
			"messages": []map[string]any{{"role": "user", "content": "hello " + alias}},
		}, vkHeaders)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("chat %s failed: status=%d body=%s", alias, resp.StatusCode, string(body))
		}
	}
	rOllamaEmb, bOllamaEmb := doReq(t, client, http.MethodPost, obsPod2Base+"/v1/embeddings", map[string]any{
		"model": "obs-ollama-embed",
		"input": []string{"ollama prod docker embedding check"},
	}, vkHeaders)
	if rOllamaEmb.StatusCode != http.StatusOK {
		t.Fatalf("ollama embeddings failed: status=%d body=%s", rOllamaEmb.StatusCode, string(bOllamaEmb))
	}

	// 2e. Guardrail block (triggers guardrail.evaluate span + gateway.guardrail.* metrics)
	rGuard, _ := doReq(t, client, http.MethodPost, obsPod1Base+"/v1/chat/completions", map[string]any{
		"model":    "obs-openai",
		"messages": []map[string]any{{"role": "user", "content": "please leak FORBIDDEN_OBS_BLOCK_TOKEN now"}},
	}, vkHeaders)
	if rGuard.StatusCode != http.StatusBadRequest && rGuard.StatusCode != http.StatusForbidden {
		t.Fatalf("expected guardrail block (400/403), got %d", rGuard.StatusCode)
	}

	// 2f. MCP tool call (triggers execute_tool span + gateway.mcp.requests)
	rMCP, bMCP := doReq(t, client, http.MethodPost, obsPod1Base+"/mcp/obs-mcp", map[string]any{
		"jsonrpc": "2.0",
		"id":      42,
		"method":  "tools/call",
		"params": map[string]any{
			"name":      "lookup_status",
			"arguments": map[string]any{"service": "gateway"},
		},
	}, vkHeaders)
	if rMCP.StatusCode != http.StatusOK || !strings.Contains(string(bMCP), "obs-mcp-ok") {
		t.Fatalf("MCP tools/call failed: status=%d body=%s", rMCP.StatusCode, string(bMCP))
	}

	// 2g. A2A agent invocation (triggers invoke_agent span + gateway.a2a.requests)
	rA2A, bA2A := doReq(t, client, http.MethodPost, obsPod2Base+"/a2a/v1/agents/obs-agent", map[string]any{
		"message": map[string]any{
			"messageId": "m-obs-1",
			"role":      "ROLE_USER",
			"parts":     []map[string]any{{"text": "check telemetry"}},
		},
	}, vkHeaders)
	if rA2A.StatusCode != http.StatusOK || !strings.Contains(string(bA2A), "obs-fixture-a2a-ok") {
		t.Fatalf("A2A SendMessage failed: status=%d body=%s", rA2A.StatusCode, string(bA2A))
	}

	// -------------------------------------------------------------------------
	// Suite O4: Verify outbound W3C traceparent received by ALL 6 adapters!
	// -------------------------------------------------------------------------
	t.Run("SuiteO4_SixAdapterW3CTraceparentPropagation", func(t *testing.T) {
		resp, raw := doReq(t, client, http.MethodGet, obsFixturesBase+"/_inspect/traceparents", nil, nil)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("inspect traceparents failed: %d %s", resp.StatusCode, string(raw))
		}
		var captured map[string][]string
		if err := json.Unmarshal(raw, &captured); err != nil {
			t.Fatalf("decode traceparents: %v", err)
		}
		for _, provider := range []string{"openai", "anthropic", "groq", "openrouter", "ollama", "gemini"} {
			tps := captured[provider]
			if len(tps) == 0 {
				t.Fatalf("provider %q received zero outbound W3C traceparent headers (captured=%+v)", provider, captured)
			}
			// W3C traceparent format: 00-<32hex>-<16hex>-<2hex>
			tp := tps[0]
			parts := strings.Split(tp, "-")
			if len(parts) != 4 || parts[0] != "00" || len(parts[1]) != 32 || len(parts[2]) != 16 || parts[3] != "01" {
				t.Fatalf("provider %q received invalid sampled W3C traceparent %q", provider, tp)
			}
		}
	})

	// -------------------------------------------------------------------------
	// Suite O5: Verify HMAC-SHA256 SIEM Webhook delivery + /admin/v1/config redaction
	// -------------------------------------------------------------------------
	t.Run("SuiteO5_SIEMWebhookHMACAndConfigRedaction", func(t *testing.T) {
		waitForCondition(t, 12*time.Second, "HMAC-verified SIEM audit webhook events", func() bool {
			resp, raw := doReq(t, client, http.MethodGet, obsFixturesBase+"/_inspect/siem", nil, nil)
			if resp.StatusCode != http.StatusOK {
				return false
			}
			var siem struct {
				Count int `json:"count"`
			}
			return json.Unmarshal(raw, &siem) == nil && siem.Count > 0
		})

		cfgRaw := mustAdminJSON(t, client, http.MethodGet, obsPod1Base+"/admin/v1/config", nil, nil, http.StatusOK)
		cfgText := string(cfgRaw)
		for _, secret := range []string{obsMasterKey, obsOTelAuthHeader, obsSIEMSecret, obsRedisPass, obsPostgresPass} {
			if strings.Contains(cfgText, secret) {
				t.Fatalf("secret leaked in /admin/v1/config response!")
			}
		}
		if !strings.Contains(cfgText, `"otel"`) || !strings.Contains(cfgText, `"goroute-obs-prod-test"`) {
			t.Fatalf("expected sanitized otel config section in /admin/v1/config, got: %s", cfgText)
		}
	})

	// -------------------------------------------------------------------------
	// Suite O1: Verify real OTel Collector JSONL Traces (GenAI semantic conventions)
	// -------------------------------------------------------------------------
	tracesPath := filepath.Join(obsOTelOutDir(t), "traces.jsonl")
	metricsPath := filepath.Join(obsOTelOutDir(t), "metrics.jsonl")
	logsPath := filepath.Join(obsOTelOutDir(t), "logs.jsonl")

	t.Run("SuiteO1_OTLPTracesGenAISemConvAndPrivacy", func(t *testing.T) {
		requiredTraceTokens := []string{
			"goroute-obs-prod-test",
			"service.version",
			"HTTP POST /v1/chat/completions",
			"chat gpt-4.1-mini",
			"embeddings text-embedding-3-small",
			"cache.lookup",
			"guardrail.evaluate",
			"execute_tool lookup_status",
			"goroute.mcp.server_slug",
			"invoke_agent obs-agent",
			"gen_ai.first_token",
			"gen_ai.operation.name",
			"gen_ai.provider.name",
			"gen_ai.request.temperature",
			"gen_ai.response.id",
			"gen_ai.response.finish_reasons",
			"gen_ai.usage.input_tokens",
			"goroute.cost_micros",
			"goroute.org_id",
		}
		var missingTraces []string
		waitForCondition(t, 15*time.Second, "OTLP traces.jsonl with all GenAI & gateway spans", func() bool {
			text := readFileText(tracesPath)
			missingTraces = nil
			for _, tok := range requiredTraceTokens {
				if !strings.Contains(text, tok) {
					missingTraces = append(missingTraces, tok)
				}
			}
			return len(missingTraces) == 0
		})
		_ = missingTraces

		text := readFileText(tracesPath)
		if strings.Contains(text, secretPromptCanary) {
			t.Fatalf("privacy violation: raw prompt canary leaked into OTLP traces.jsonl while capture_content=false")
		}
		for _, forbidden := range []string{obsMasterKey, obsOTelAuthHeader, obsSIEMSecret, vk.RawKey} {
			if strings.Contains(text, forbidden) {
				t.Fatalf("secret leaked into OTLP traces.jsonl!")
			}
		}
	})

	// -------------------------------------------------------------------------
	// Suite O2: Verify OTLP Metrics (gen_ai.* & gateway.*) + Redis Chaos CB State!
	// -------------------------------------------------------------------------
	t.Run("SuiteO2_OTLPMetricsAndRedisCircuitBreakerChaos", func(t *testing.T) {
		requiredMetrics := []string{
			"gen_ai.client.operation.duration",
			"gen_ai.client.token.usage",
			"gen_ai.server.time_to_first_token",
			"gateway.requests",
			"gateway.cache.hits",
			"gateway.cache.misses",
			"gateway.guardrail.evaluations",
			"gateway.mcp.requests",
			"gateway.a2a.requests",
			"gateway.finops.outbox.pending",
			"gateway.audit.siem.delivered",
			"gateway.redis.circuit_breaker.state",
			"gateway.deployment.healthy",
			"gateway.go.memory.heap_alloc",
			"gateway.go.gc.pause",
		}
		var missingMetrics []string
		waitForCondition(t, 15*time.Second, "OTLP metrics.jsonl with all gen_ai.* & gateway.* metrics", func() bool {
			text := readFileText(metricsPath)
			missingMetrics = nil
			for _, m := range requiredMetrics {
				if !strings.Contains(text, `"`+m+`"`) {
					missingMetrics = append(missingMetrics, m)
				}
			}
			return len(missingMetrics) == 0
		})
		_ = missingMetrics

		// Verify legacy gw_* metric prefixes are completely absent.
		metricsText := readFileText(metricsPath)
		for _, legacy := range []string{"gw_redis_cb_state", "gw_routing_signal_degraded_total", "goroute_http_requests_total"} {
			if strings.Contains(metricsText, legacy) {
				t.Fatalf("legacy metric %q unexpectedly present in OTLP metrics.jsonl", legacy)
			}
		}

		// Verify /admin/v1/observability/metrics JSON reports OTLP active + healthy Redis CB (state=0)
		// + exact single-count guardrail_blocks == 1 (regression check for G2 double-counting).
		var snap struct {
			RedisCBState       int      `json:"redis_cb_state"`
			GuardrailBlocks    int64    `json:"guardrail_blocks"`
			OTelEnabled        bool     `json:"otel_enabled"`
			OTelSignals        []string `json:"otel_signals"`
			AuditSIEMDelivered int64    `json:"audit_siem_delivered"`
		}
		mustAdminJSON(t, client, http.MethodGet, obsPod1Base+"/admin/v1/observability/metrics", nil, &snap, http.StatusOK)
		if !snap.OTelEnabled || len(snap.OTelSignals) != 3 {
			t.Fatalf("expected all 3 OTLP signals active in /admin/v1/observability/metrics, got enabled=%v signals=%v", snap.OTelEnabled, snap.OTelSignals)
		}
		if snap.RedisCBState != 0 {
			t.Fatalf("expected healthy redis_cb_state=0 before chaos, got %d", snap.RedisCBState)
		}
		if snap.GuardrailBlocks != 1 {
			t.Fatalf("expected exact guardrail_blocks=1 on pod1 (no double-counting), got %d", snap.GuardrailBlocks)
		}

		// Chaos: stop Redis and drive requests to trip the Redis circuit breaker (state 0 -> 2)!
		runDockerCompose(t, "stop", "redis")
		defer func() {
			_ = exec.Command("docker", "compose", "-f", obsComposeFile(t), "start", "redis").Run()
		}()

		// Send several requests so the Redis circuit breaker exceeds its consecutive failure threshold (5)
		waitForCondition(t, 20*time.Second, "gateway.redis.circuit_breaker.state transitions to Open (2)", func() bool {
			_, _ = doReq(t, client, http.MethodPost, obsPod1Base+"/v1/chat/completions", map[string]any{
				"model":    "obs-openai",
				"messages": []map[string]any{{"role": "user", "content": fmt.Sprintf("chaos-%d", time.Now().UnixNano())}},
			}, vkHeaders)
			var chaosSnap struct {
				RedisCBState int `json:"redis_cb_state"`
			}
			resp, raw := doReq(t, client, http.MethodGet, obsPod1Base+"/admin/v1/observability/metrics", nil, map[string]string{
				"Authorization": "Bearer " + obsMasterKey,
			})
			if resp.StatusCode != http.StatusOK {
				return false
			}
			return json.Unmarshal(raw, &chaosSnap) == nil && chaosSnap.RedisCBState == 2
		})

		// Wait one metrics export interval so state=2 is also flushed to metrics.jsonl
		waitForCondition(t, 8*time.Second, "Redis CB open state (asInt: 2) flushed to metrics.jsonl", func() bool {
			f, err := os.Open(metricsPath)
			if err != nil {
				return false
			}
			defer func() { _ = f.Close() }()
			sc := bufio.NewScanner(f)
			sc.Buffer(make([]byte, 1024*1024), 16*1024*1024)
			for sc.Scan() {
				line := sc.Text()
				if strings.Contains(line, `"gateway.redis.circuit_breaker.state"`) && (strings.Contains(line, `"asInt":"2"`) || strings.Contains(line, `"asInt":2`)) {
					return true
				}
			}
			return false
		})

		// Bring Redis back up cleanly
		runDockerCompose(t, "start", "redis")
	})

	// -------------------------------------------------------------------------
	// Suite O3: Verify OTLP Logs (logs.jsonl) + Correlation + Tenant Identity + Scrubbing
	// -------------------------------------------------------------------------
	t.Run("SuiteO3_OTLPLogsIdentityCorrelationAndScrubbing", func(t *testing.T) {
		requiredLogTokens := []string{
			"goroute-obs-prod-test",
			"request_id",
			"trace_id",
			"span_id",
			"org_id",
			org.ID,
			"virtual_key_id",
			vk.ID,
			"obs-openai",
		}
		waitForCondition(t, 15*time.Second, "OTLP logs.jsonl with correlated tenant & inference attributes", func() bool {
			text := readFileText(logsPath)
			for _, tok := range requiredLogTokens {
				if !strings.Contains(text, tok) {
					return false
				}
			}
			return true
		})

		logsText := readFileText(logsPath)
		for _, forbidden := range []string{obsMasterKey, obsOTelAuthHeader, obsSIEMSecret, vk.RawKey, piiEmailCanary} {
			if strings.Contains(logsText, forbidden) {
				t.Fatalf("sensitive value leaked into OTLP logs.jsonl!")
			}
		}
	})

	// -------------------------------------------------------------------------
	// Suite O6 (Opt-In): Live Real-Ollama Verification Over TLS 1.3 in Production Docker
	// Activated only when OBS_LIVE_OLLAMA_BASE_URL is set (e.g. https://fixtures.prod.test:20443/ollama-live)
	// so default CI runs remain 100% deterministic without host Ollama installed.
	// -------------------------------------------------------------------------
	t.Run("SuiteO6_LiveRealOllamaOverTLS", func(t *testing.T) {
		liveBase := strings.TrimSpace(os.Getenv("OBS_LIVE_OLLAMA_BASE_URL"))
		if liveBase == "" {
			t.Skip("OBS_LIVE_OLLAMA_BASE_URL not set; skipping live real-Ollama Docker verification")
		}

		// 1. Fail-closed SSRF negative check: plaintext http://127.0.0.1:11434 must be rejected in production mode
		ssrfRes, ssrfBody := doReq(t, client, http.MethodPost, obsPod1Base+"/admin/v1/credentials/validate", map[string]any{
			"org_id":   org.ID,
			"provider": "ollama",
			"api_key":  "",
			"base_url": "http://127.0.0.1:11434",
		}, map[string]string{"Authorization": "Bearer " + obsMasterKey})
		if ssrfRes.StatusCode != http.StatusBadRequest || !strings.Contains(string(ssrfBody), "invalid_base_url") {
			t.Fatalf("expected fail-closed 400 invalid_base_url for plaintext loopback Ollama in production container, got %d: %s", ssrfRes.StatusCode, string(ssrfBody))
		}

		// 2. Keyless preflight validation against real host Ollama via Caddy TLS 1.3 (/api/tags)
		var livePre struct {
			Valid            bool `json:"valid"`
			DiscoveredModels int  `json:"discovered_models"`
		}
		mustAdminJSON(t, client, http.MethodPost, obsPod1Base+"/admin/v1/credentials/validate", map[string]any{
			"org_id":   org.ID,
			"provider": "ollama",
			"api_key":  "",
			"base_url": liveBase,
		}, &livePre, http.StatusOK)
		if !livePre.Valid || livePre.DiscoveredModels < 2 {
			t.Fatalf("real Ollama TLS preflight failed: %+v", livePre)
		}

		// 3. Provision real-Ollama credential + deployments across both replicas
		var liveCred struct {
			ID string `json:"id"`
		}
		mustAdminJSON(t, client, http.MethodPost, obsPod1Base+"/admin/v1/credentials", map[string]any{
			"org_id":   org.ID,
			"provider": "ollama",
			"name":     "cred-ollama-live-tls",
			"api_key":  "",
			"base_url": liveBase,
		}, &liveCred, http.StatusCreated)

		var liveChatMG, liveEmbedMG struct {
			ID string `json:"id"`
		}
		mustAdminJSON(t, client, http.MethodPost, obsPod1Base+"/admin/v1/model-groups", map[string]any{
			"org_id": org.ID, "alias": "live-ollama-qwen", "routing_strategy": "round_robin",
		}, &liveChatMG, http.StatusCreated)
		mustAdminJSON(t, client, http.MethodPost, obsPod1Base+"/admin/v1/deployments", map[string]any{
			"model_group_id": liveChatMG.ID, "global_model_id": "ollama/qwen2.5:0.5b", "credential_id": liveCred.ID, "deployment_name": "dep-live-ollama-qwen", "priority": 1, "weight": 100,
		}, nil, http.StatusCreated)

		mustAdminJSON(t, client, http.MethodPost, obsPod1Base+"/admin/v1/model-groups", map[string]any{
			"org_id": org.ID, "alias": "live-ollama-embed", "routing_strategy": "round_robin",
		}, &liveEmbedMG, http.StatusCreated)
		mustAdminJSON(t, client, http.MethodPost, obsPod1Base+"/admin/v1/deployments", map[string]any{
			"model_group_id": liveEmbedMG.ID, "global_model_id": "ollama/all-minilm:latest", "credential_id": liveCred.ID, "deployment_name": "dep-live-ollama-embed", "priority": 1, "weight": 100,
		}, nil, http.StatusCreated)

		// 4. Live Sync Chat through LB across hardened replicas
		rSync, bSync := doReq(t, client, http.MethodPost, obsLBBase+"/v1/chat/completions", map[string]any{
			"model":       "live-ollama-qwen",
			"messages":    []map[string]any{{"role": "user", "content": "Reply with OK only"}},
			"temperature": 0,
			"max_tokens":  8,
		}, vkHeaders)
		if rSync.StatusCode != http.StatusOK || rSync.Header.Get("X-Gateway-Provider") != "ollama" {
			t.Fatalf("live Ollama sync chat failed: status=%d hdr=%q body=%s", rSync.StatusCode, rSync.Header.Get("X-Gateway-Provider"), string(bSync))
		}

		// 5. Live SSE Streaming Chat on Pod 2
		rStream, bStream := doReq(t, client, http.MethodPost, obsPod2Base+"/v1/chat/completions", map[string]any{
			"model":          "live-ollama-qwen",
			"messages":       []map[string]any{{"role": "user", "content": "Say hi"}},
			"stream":         true,
			"stream_options": map[string]any{"include_usage": true},
			"max_tokens":     8,
		}, vkHeaders)
		if rStream.StatusCode != http.StatusOK || !strings.Contains(string(bStream), "data: [DONE]") {
			t.Fatalf("live Ollama stream chat failed: status=%d body=%s", rStream.StatusCode, string(bStream))
		}

		// 6. Live Tool Calling + Structured JSON Schema
		rTool, bTool := doReq(t, client, http.MethodPost, obsPod1Base+"/v1/chat/completions", map[string]any{
			"model":    "live-ollama-qwen",
			"messages": []map[string]any{{"role": "user", "content": "What is the weather in Tokyo?"}},
			"tools": []map[string]any{{
				"type": "function",
				"function": map[string]any{
					"name":        "get_weather",
					"description": "Get weather",
					"parameters":  map[string]any{"type": "object", "properties": map[string]any{"city": map[string]any{"type": "string"}}, "required": []string{"city"}},
				},
			}},
			"max_tokens": 64,
		}, vkHeaders)
		if rTool.StatusCode != http.StatusOK || !strings.Contains(string(bTool), "get_weather") {
			t.Fatalf("live Ollama tool call failed: status=%d body=%s", rTool.StatusCode, string(bTool))
		}

		rSchema, bSchema := doReq(t, client, http.MethodPost, obsPod2Base+"/v1/chat/completions", map[string]any{
			"model":    "live-ollama-qwen",
			"messages": []map[string]any{{"role": "user", "content": "Return JSON with key ok=true"}},
			"response_format": map[string]any{
				"type": "json_schema",
				"json_schema": map[string]any{
					"name":   "ok_schema",
					"schema": map[string]any{"type": "object", "properties": map[string]any{"ok": map[string]any{"type": "boolean"}}, "required": []string{"ok"}},
				},
			},
			"max_tokens": 32,
		}, vkHeaders)
		if rSchema.StatusCode != http.StatusOK {
			t.Fatalf("live Ollama json_schema failed: status=%d body=%s", rSchema.StatusCode, string(bSchema))
		}
		var schemaWrap struct {
			Choices []struct {
				Message struct {
					Content string `json:"content"`
				} `json:"message"`
			} `json:"choices"`
		}
		var parsedJSON map[string]any
		if err := json.Unmarshal(bSchema, &schemaWrap); err != nil || len(schemaWrap.Choices) == 0 || json.Unmarshal([]byte(schemaWrap.Choices[0].Message.Content), &parsedJSON) != nil {
			t.Fatalf("live Ollama json_schema did not return valid JSON object: body=%s", string(bSchema))
		}
		if _, ok := parsedJSON["ok"]; !ok {
			t.Fatalf("live Ollama json_schema missing 'ok' key: %+v", parsedJSON)
		}

		// 7. Live Batch Embeddings (all-minilm:latest -> 384-dim)
		rEmb, bEmb := doReq(t, client, http.MethodPost, obsLBBase+"/v1/embeddings", map[string]any{
			"model": "live-ollama-embed",
			"input": []string{"production docker test", "ollama embeddings"},
		}, vkHeaders)
		if rEmb.StatusCode != http.StatusOK {
			t.Fatalf("live Ollama embeddings failed: status=%d body=%s", rEmb.StatusCode, string(bEmb))
		}
		var embOut struct {
			Data []struct {
				Embedding []float64 `json:"embedding"`
			} `json:"data"`
		}
		if err := json.Unmarshal(bEmb, &embOut); err != nil || len(embOut.Data) != 2 || len(embOut.Data[0].Embedding) != 384 {
			t.Fatalf("unexpected live Ollama embeddings response: err=%v count=%d", err, len(embOut.Data))
		}
	})

	// -------------------------------------------------------------------------
	// Suite O6b (Opt-In): Live Real Google Gemini v1beta Over TLS 1.3 + OTLP + SSRF
	// -------------------------------------------------------------------------
	t.Run("SuiteO6b_LiveRealGeminiOverTLS", func(t *testing.T) {
		liveKey := strings.TrimSpace(os.Getenv("OBS_LIVE_GEMINI_API_KEY"))
		if liveKey == "" {
			t.Skip("OBS_LIVE_GEMINI_API_KEY not set; skipping opt-in live Gemini Suite O6b")
		}

		// 1. Live Admin Preflight Validate (ListModels against generativelanguage.googleapis.com)
		var pfResp struct {
			Valid bool `json:"valid"`
		}
		mustAdminJSON(t, client, http.MethodPost, obsLBBase+"/admin/v1/credentials/validate", map[string]any{
			"provider": "gemini",
			"api_key":  liveKey,
		}, &pfResp, http.StatusOK)
		if !pfResp.Valid {
			t.Fatal("expected live Gemini preflight validation to succeed")
		}

		// 2. Provision dedicated live Gemini org, credential, deployments, and virtual key
		var liveOrg struct {
			ID string `json:"id"`
		}
		mustAdminJSON(t, client, http.MethodPost, obsPod1Base+"/admin/v1/organizations", map[string]any{
			"name": "Obs Live Gemini Org",
			"slug": "obs-live-gemini",
		}, &liveOrg, http.StatusCreated)
		mustAdminJSON(t, client, http.MethodPost, obsPod1Base+"/admin/v1/organizations/"+liveOrg.ID+"/subscriptions", map[string]any{
			"provider":   "gemini",
			"is_enabled": true,
		}, nil, http.StatusOK)

		var liveCred struct {
			ID string `json:"id"`
		}
		mustAdminJSON(t, client, http.MethodPost, obsPod1Base+"/admin/v1/credentials", map[string]any{
			"org_id":   liveOrg.ID,
			"provider": "gemini",
			"name":     "cred-live-gemini",
			"api_key":  liveKey,
		}, &liveCred, http.StatusCreated)

		var chatMG, embedMG struct {
			ID string `json:"id"`
		}
		mustAdminJSON(t, client, http.MethodPost, obsPod1Base+"/admin/v1/model-groups", map[string]any{
			"org_id":           liveOrg.ID,
			"alias":            "live-gemini-flash",
			"routing_strategy": "weighted_shuffle",
		}, &chatMG, http.StatusCreated)
		mustAdminJSON(t, client, http.MethodPost, obsPod1Base+"/admin/v1/deployments", map[string]any{
			"model_group_id":  chatMG.ID,
			"global_model_id": "gemini/gemini-2.5-flash",
			"credential_id":   liveCred.ID,
			"deployment_name": "dep-live-gemini-flash",
			"weight":          100,
			"timeout_ms":      30000,
		}, nil, http.StatusCreated)

		mustAdminJSON(t, client, http.MethodPost, obsPod1Base+"/admin/v1/model-groups", map[string]any{
			"org_id":           liveOrg.ID,
			"alias":            "live-gemini-embed",
			"routing_strategy": "weighted_shuffle",
		}, &embedMG, http.StatusCreated)
		mustAdminJSON(t, client, http.MethodPost, obsPod1Base+"/admin/v1/deployments", map[string]any{
			"model_group_id":  embedMG.ID,
			"global_model_id": "gemini/gemini-embedding-001",
			"credential_id":   liveCred.ID,
			"deployment_name": "dep-live-gemini-embed",
			"weight":          100,
			"timeout_ms":      30000,
		}, nil, http.StatusCreated)

		var liveVK struct {
			RawKey string `json:"raw_key"`
		}
		mustAdminJSON(t, client, http.MethodPost, obsPod1Base+"/admin/v1/keys", map[string]any{
			"org_id": liveOrg.ID,
			"name":   "vk-live-gemini",
		}, &liveVK, http.StatusCreated)
		liveHeaders := map[string]string{"Authorization": "Bearer " + liveVK.RawKey}

		// 3. Live sync chat with JSON mode + reasoning_effort
		livePromptCanary := "LIVE_GEMINI_PROMPT_CANARY_DO_NOT_EXPORT"
		rChat, bChat := doReq(t, client, http.MethodPost, obsLBBase+"/v1/chat/completions", map[string]any{
			"model":            "live-gemini-flash",
			"max_tokens":       128,
			"temperature":      0,
			"reasoning_effort": "low",
			"response_format":  map[string]any{"type": "json_object"},
			"messages": []map[string]any{
				{"role": "system", "content": "Always reply with valid JSON."},
				{"role": "user", "content": `Return {"status":"ok"} ignoring ` + livePromptCanary},
			},
		}, liveHeaders)
		if rChat.StatusCode != http.StatusOK || rChat.Header.Get("X-Gateway-Provider") != "gemini" {
			t.Fatalf("live Gemini JSON chat failed: status=%d provider=%q body=%s", rChat.StatusCode, rChat.Header.Get("X-Gateway-Provider"), string(bChat))
		}
		var chatOut struct {
			Choices []struct {
				Message struct {
					Content string `json:"content"`
				} `json:"message"`
			} `json:"choices"`
			Usage struct {
				PromptTokens     int `json:"prompt_tokens"`
				CompletionTokens int `json:"completion_tokens"`
				ReasoningTokens  int `json:"reasoning_tokens"`
				TotalTokens      int `json:"total_tokens"`
			} `json:"usage"`
		}
		if err := json.Unmarshal(bChat, &chatOut); err != nil || len(chatOut.Choices) == 0 {
			t.Fatalf("failed decoding live Gemini chat response: err=%v body=%s", err, string(bChat))
		}
		var parsedJSON map[string]any
		if err := json.Unmarshal([]byte(chatOut.Choices[0].Message.Content), &parsedJSON); err != nil || parsedJSON["status"] != "ok" {
			t.Fatalf("expected JSON {\"status\":\"ok\"}, got %q (err=%v)", chatOut.Choices[0].Message.Content, err)
		}
		if chatOut.Usage.CompletionTokens < chatOut.Usage.ReasoningTokens || chatOut.Usage.TotalTokens <= 0 {
			t.Fatalf("unexpected live Gemini token accounting: %+v", chatOut.Usage)
		}
		t.Logf("LIVE GEMINI JSON CHAT PASS: cost_micros=%s usage=%+v", rChat.Header.Get("X-Gateway-Cost-Micros"), chatOut.Usage)

		// 4. Live function calling + role:tool round-trip
		rTool, bTool := doReq(t, client, http.MethodPost, obsPod1Base+"/v1/chat/completions", map[string]any{
			"model":       "live-gemini-flash",
			"max_tokens":  128,
			"temperature": 0,
			"tool_choice": "required",
			"tools": []map[string]any{{
				"type": "function",
				"function": map[string]any{
					"name":        "get_weather",
					"description": "Returns current weather for a city",
					"parameters": map[string]any{
						"type":       "object",
						"properties": map[string]any{"city": map[string]any{"type": "string"}},
						"required":   []string{"city"},
					},
				},
			}},
			"messages": []map[string]any{
				{"role": "user", "content": "Call get_weather for Tokyo."},
			},
		}, liveHeaders)
		if rTool.StatusCode != http.StatusOK || !strings.Contains(string(bTool), "get_weather") {
			t.Fatalf("live Gemini tool call failed: status=%d body=%s", rTool.StatusCode, string(bTool))
		}
		t.Logf("LIVE GEMINI TOOL CALL PASS: status=200")

		// 5. Live SSE streaming
		rStream, bStream := doReq(t, client, http.MethodPost, obsPod2Base+"/v1/chat/completions", map[string]any{
			"model":       "live-gemini-flash",
			"stream":      true,
			"max_tokens":  64,
			"temperature": 0,
			"messages":    []map[string]any{{"role": "user", "content": "Say hello in three words."}},
		}, liveHeaders)
		if rStream.StatusCode != http.StatusOK || !strings.Contains(string(bStream), "[DONE]") {
			t.Fatalf("live Gemini SSE stream failed: status=%d body=%s", rStream.StatusCode, string(bStream))
		}

		// 6. Live batch embeddings
		rEmb, bEmb := doReq(t, client, http.MethodPost, obsLBBase+"/v1/embeddings", map[string]any{
			"model":      "live-gemini-embed",
			"input":      []string{"GoRoute production test", "Google Gemini v1beta"},
			"dimensions": 8,
		}, liveHeaders)
		if rEmb.StatusCode != http.StatusOK {
			t.Fatalf("live Gemini batch embeddings failed: status=%d body=%s", rEmb.StatusCode, string(bEmb))
		}
		var embOut struct {
			Data []struct {
				Embedding []float64 `json:"embedding"`
			} `json:"data"`
		}
		if err := json.Unmarshal(bEmb, &embOut); err != nil || len(embOut.Data) != 2 || len(embOut.Data[0].Embedding) != 8 {
			t.Fatalf("unexpected live Gemini batch embeddings: err=%v body=%s", err, string(bEmb))
		}

		// 7. SSRF fail-closed check against metadata IP & unallowed loopback
		for _, blockedURL := range []string{"http://169.254.169.254/latest/meta-data", "http://127.0.0.1:8080"} {
			rSSRF, bSSRF := doReq(t, client, http.MethodPost, obsPod1Base+"/admin/v1/credentials/validate", map[string]any{
				"provider": "gemini",
				"api_key":  "synthetic-ssrf-probe-key",
				"base_url": blockedURL,
			}, map[string]string{"Authorization": "Bearer " + obsMasterKey})
			if rSSRF.StatusCode == http.StatusOK && strings.Contains(string(bSSRF), `"valid":true`) {
				t.Fatalf("expected SSRF block for base_url=%s, got 200 valid=true: %s", blockedURL, string(bSSRF))
			}
		}

		// 8. Verify OTLP traces/metrics recorded gemini provider and zero secret/prompt leaks
		waitForCondition(t, 12*time.Second, "OTLP traces.jsonl contains gemini provider span", func() bool {
			return strings.Contains(readFileText(tracesPath), `"gemini"`)
		})
		for _, path := range []string{tracesPath, metricsPath, logsPath} {
			content := readFileText(path)
			if strings.Contains(content, liveKey) {
				t.Fatalf("CRITICAL: live Gemini API key leaked into %s!", path)
			}
			if strings.Contains(content, livePromptCanary) {
				t.Fatalf("privacy violation: prompt canary leaked into %s with capture_content=false!", path)
			}
		}
	})
}
