//go:build cacheproddocker

package cacheproddocker_test

import (
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
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const (
	cacheLBBase       = "https://gateway.prod.test:19443"
	cachePod1Base     = "https://gateway.prod.test:19444"
	cachePod2Base     = "https://gateway.prod.test:19445"
	cacheMasterKey    = "sk-gw-cache-prod-master-admin-key-2026-secure"
	cacheComposeFile  = "../../deployments/cache-prod-test/docker-compose.cache-prod.yml"
	cacheCertCAPath   = "../../.tmp/cache-prod-certs/ca.crt"
	cachePrimaryRPass = "prod-cache-primary-pass-2026"
	cacheDedRPass     = "prod-cache-dedicated-pass-2026"
	geminiOpenAIBase  = "https://generativelanguage.googleapis.com/v1beta/openai"
	geminiChatModel   = "gemini-3.5-flash-lite"
	geminiEmbedModel  = "gemini-embedding-001"
	geminiChatAlias   = "gemini-chat"
	geminiAltAlias    = "gemini-chat-alt"
)

func requireGeminiKey(t *testing.T) string {
	t.Helper()
	key := strings.TrimSpace(os.Getenv("GATEWAY_TEST_GEMINI_API_KEY"))
	if key == "" {
		t.Fatal("GATEWAY_TEST_GEMINI_API_KEY must be set to run live production Docker caching tests")
	}
	return key
}

func newCacheTLSClient(t *testing.T) *http.Client {
	t.Helper()
	caPEM, err := os.ReadFile(cacheCertCAPath)
	if err != nil {
		t.Fatalf("read cache-prod CA cert %s: %v", cacheCertCAPath, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		t.Fatal("failed to parse cache-prod CA cert")
	}
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs:    pool,
			MinVersion: tls.VersionTLS12,
		},
		MaxIdleConns:        64,
		MaxIdleConnsPerHost: 32,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err == nil && strings.HasSuffix(host, ".prod.test") {
				return dialer.DialContext(ctx, network, net.JoinHostPort("127.0.0.1", port))
			}
			return dialer.DialContext(ctx, network, addr)
		},
	}
	return &http.Client{
		Transport: tr,
		Timeout:   45 * time.Second,
	}
}

func doHTTP(t *testing.T, client *http.Client, method, rawURL string, body any, headers map[string]string) (*http.Response, []byte, time.Duration) {
	t.Helper()
	var rdr io.Reader
	if body != nil {
		switch v := body.(type) {
		case string:
			rdr = strings.NewReader(v)
		case []byte:
			rdr = bytes.NewReader(v)
		default:
			raw, err := json.Marshal(v)
			if err != nil {
				t.Fatalf("marshal body: %v", err)
			}
			rdr = bytes.NewReader(raw)
		}
	}
	req, err := http.NewRequest(method, rawURL, rdr)
	if err != nil {
		t.Fatalf("NewRequest(%s %s): %v", method, rawURL, err)
	}
	if body != nil && headers["Content-Type"] == "" {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	start := time.Now()
	resp, err := client.Do(req)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("%s %s failed: %v", method, rawURL, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response body for %s %s: %v", method, rawURL, err)
	}
	return resp, data, elapsed
}

func mustAdminJSON(t *testing.T, client *http.Client, method, urlStr string, body any, out any, wantStatuses ...int) []byte {
	t.Helper()
	resp, data, _ := doHTTP(t, client, method, urlStr, body, map[string]string{
		"Authorization": "Bearer " + cacheMasterKey,
	})
	matched := false
	for _, s := range wantStatuses {
		if resp.StatusCode == s {
			matched = true
			break
		}
	}
	if !matched {
		t.Fatalf("%s %s status=%d (want %v) body=%s", method, urlStr, resp.StatusCode, wantStatuses, string(data))
	}
	if out != nil {
		if err := json.Unmarshal(data, out); err != nil {
			t.Fatalf("unmarshal %s %s: %v (%s)", method, urlStr, err, string(data))
		}
	}
	return data
}

func composeExec(t *testing.T, args ...string) string {
	t.Helper()
	absCompose, err := filepath.Abs(cacheComposeFile)
	if err != nil {
		t.Fatalf("abs compose path: %v", err)
	}
	cmdArgs := append([]string{"compose", "-f", absCompose}, args...)
	out, err := exec.Command("docker", cmdArgs...).CombinedOutput()
	if err != nil {
		t.Fatalf("docker %v failed: %v\n%s", cmdArgs, err, string(out))
	}
	return string(out)
}

func redisExec(t *testing.T, service, pass string, args ...string) string {
	t.Helper()
	cmdArgs := append([]string{"exec", "-T", service, "redis-cli", "-a", pass, "--no-auth-warning"}, args...)
	return strings.TrimSpace(composeExec(t, cmdArgs...))
}

func psqlExec(t *testing.T, sql string) string {
	t.Helper()
	raw := strings.TrimSpace(composeExec(t, "exec", "-T", "postgres", "psql", "-U", "gateway", "-d", "aigateway", "-q", "-tAc", sql))
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "INSERT ") && !strings.HasPrefix(line, "UPDATE ") {
			return line
		}
	}
	return raw
}

func seedGeminiGlobalModels(t *testing.T) (chatGlobalID, embedGlobalID string) {
	t.Helper()
	seed := func(id, modelName, capsJSON string, inMicros, outMicros int64) string {
		q := fmt.Sprintf(`
INSERT INTO global_models (
	id, provider, model_name, display_name,
	input_cost_micros_per_1m, output_cost_micros_per_1m,
	pricing_status, pricing_version, pricing_provenance_source,
	max_input_tokens, max_output_tokens, supports_inference, capabilities
) VALUES (
	'%s', 'openai', '%s', '%s',
	%d, %d,
	'verified', 1, 'cache-prod-docker-test',
	128000, 16384, TRUE, '%s'::jsonb
)
ON CONFLICT (provider, model_name) DO UPDATE SET
	input_cost_micros_per_1m = EXCLUDED.input_cost_micros_per_1m,
	output_cost_micros_per_1m = EXCLUDED.output_cost_micros_per_1m,
	pricing_status = 'verified',
	supports_inference = TRUE,
	capabilities = EXCLUDED.capabilities
RETURNING id;`,
			id, modelName, modelName, inMicros, outMicros, capsJSON,
		)
		out := psqlExec(t, q)
		if out == "" {
			t.Fatalf("seed global_model %s returned empty id", modelName)
		}
		return out
	}
	chatGlobalID = seed("openai/"+geminiChatModel, geminiChatModel, `{"streaming":"supported","tools":"supported"}`, 100000, 400000)
	embedGlobalID = seed("openai/"+geminiEmbedModel, geminiEmbedModel, `{"embeddings":"supported"}`, 150000, 0)
	return chatGlobalID, embedGlobalID
}

type tenantFixture struct {
	OrgID     string
	Team1ID   string
	Team2ID   string
	KeyTeam1  string
	KeyTeam2  string
	CredID    string
	ChatAlias string
	AltAlias  string
}

func provisionTenant(t *testing.T, client *http.Client, prefix, apiKey, chatGlobalID, embedGlobalID string, withEmbeddings bool) tenantFixture {
	t.Helper()
	suffix := fmt.Sprintf("%s-%d", prefix, time.Now().UnixNano())

	var org struct {
		ID string `json:"id"`
	}
	mustAdminJSON(t, client, http.MethodPost, cachePod1Base+"/admin/v1/organizations", map[string]any{
		"name": "CacheProd " + suffix,
		"slug": strings.ToLower(suffix),
	}, &org, http.StatusCreated)

	mustAdminJSON(t, client, http.MethodPost, cachePod1Base+"/admin/v1/organizations/"+org.ID+"/subscriptions", map[string]any{
		"provider":   "openai",
		"is_enabled": true,
	}, nil, http.StatusOK)

	var cred struct {
		ID string `json:"id"`
	}
	mustAdminJSON(t, client, http.MethodPost, cachePod1Base+"/admin/v1/credentials", map[string]any{
		"org_id":   org.ID,
		"provider": "openai",
		"name":     "gemini-cred-" + suffix,
		"api_key":  apiKey,
		"base_url": geminiOpenAIBase,
	}, &cred, http.StatusCreated)

	createGroupAndDep := func(alias, globalID, depName string) {
		var mg struct {
			ID string `json:"id"`
		}
		mustAdminJSON(t, client, http.MethodPost, cachePod1Base+"/admin/v1/model-groups", map[string]any{
			"org_id":           org.ID,
			"alias":            alias,
			"routing_strategy": "weighted_shuffle",
		}, &mg, http.StatusCreated)

		mustAdminJSON(t, client, http.MethodPost, cachePod1Base+"/admin/v1/deployments", map[string]any{
			"model_group_id":  mg.ID,
			"global_model_id": globalID,
			"credential_id":   cred.ID,
			"deployment_name": depName,
			"weight":          100,
			"priority":        1,
			"timeout_ms":      30000,
		}, nil, http.StatusCreated)
	}

	createGroupAndDep(geminiChatAlias, chatGlobalID, "dep-chat-"+suffix)
	createGroupAndDep(geminiAltAlias, chatGlobalID, "dep-alt-"+suffix)
	if withEmbeddings {
		createGroupAndDep(geminiEmbedModel, embedGlobalID, "dep-embed-"+suffix)
	}

	var team1, team2 struct {
		ID string `json:"id"`
	}
	mustAdminJSON(t, client, http.MethodPost, cachePod1Base+"/admin/v1/teams", map[string]any{
		"org_id": org.ID,
		"name":   "team-1-" + suffix,
	}, &team1, http.StatusCreated)
	mustAdminJSON(t, client, http.MethodPost, cachePod1Base+"/admin/v1/teams", map[string]any{
		"org_id": org.ID,
		"name":   "team-2-" + suffix,
	}, &team2, http.StatusCreated)

	issueKey := func(name, teamID string, rpmLimit int) string {
		payload := map[string]any{
			"org_id":            org.ID,
			"team_id":           teamID,
			"name":              name,
			"allowed_endpoints": []string{"*"},
			"allowed_models":    []string{"*"},
		}
		if rpmLimit > 0 {
			payload["rpm_limit"] = rpmLimit
		}
		var vk struct {
			RawKey string `json:"raw_key"`
		}
		mustAdminJSON(t, client, http.MethodPost, cachePod1Base+"/admin/v1/keys", payload, &vk, http.StatusCreated)
		return vk.RawKey
	}

	return tenantFixture{
		OrgID:     org.ID,
		Team1ID:   team1.ID,
		Team2ID:   team2.ID,
		KeyTeam1:  issueKey("vk-t1-"+suffix, team1.ID, 0),
		KeyTeam2:  issueKey("vk-t2-"+suffix, team2.ID, 0),
		CredID:    cred.ID,
		ChatAlias: geminiChatAlias,
		AltAlias:  geminiAltAlias,
	}
}

func scrapeMetric(t *testing.T, client *http.Client, baseURL, metricName string) float64 {
	t.Helper()
	resp, data, _ := doHTTP(t, client, http.MethodGet, baseURL+"/metrics", nil, map[string]string{
		"Authorization": "Bearer " + cacheMasterKey,
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s/metrics status=%d body=%s", baseURL, resp.StatusCode, string(data))
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, metricName+" ") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				val, err := strconv.ParseFloat(parts[1], 64)
				if err != nil {
					t.Fatalf("parse metric %s=%q: %v", metricName, parts[1], err)
				}
				return val
			}
		}
	}
	t.Fatalf("metric %q not found in /metrics output from %s", metricName, baseURL)
	return 0
}

func getObservabilityMetrics(t *testing.T, client *http.Client, baseURL string) (hits, misses int64, hitRate float64) {
	t.Helper()
	var snap struct {
		CacheHits    int64   `json:"cache_hits"`
		CacheMisses  int64   `json:"cache_misses"`
		CacheHitRate float64 `json:"cache_hit_rate"`
	}
	mustAdminJSON(t, client, http.MethodGet, baseURL+"/admin/v1/observability/metrics", nil, &snap, http.StatusOK)
	return snap.CacheHits, snap.CacheMisses, snap.CacheHitRate
}

func invalidateCache(t *testing.T, client *http.Client, baseURL, orgID, model string) int {
	t.Helper()
	var res struct {
		PurgedEntries int `json:"purged_entries"`
	}
	mustAdminJSON(t, client, http.MethodPost, baseURL+"/admin/v1/cache/invalidate", map[string]any{
		"org_id": orgID,
		"model":  model,
	}, &res, http.StatusOK)
	return res.PurgedEntries
}

func chatCall(t *testing.T, client *http.Client, baseURL, apiKey string, payload map[string]any, extraHeaders map[string]string) (*http.Response, []byte, time.Duration) {
	t.Helper()
	hdrs := map[string]string{"Authorization": "Bearer " + apiKey}
	for k, v := range extraHeaders {
		hdrs[k] = v
	}
	for attempt := 0; attempt < 2; attempt++ {
		resp, body, dur := doHTTP(t, client, http.MethodPost, baseURL+"/v1/chat/completions", payload, hdrs)
		if (resp.StatusCode == http.StatusBadGateway || resp.StatusCode == http.StatusServiceUnavailable) && attempt == 0 {
			time.Sleep(500 * time.Millisecond)
			continue
		}
		return resp, body, dur
	}
	return doHTTP(t, client, http.MethodPost, baseURL+"/v1/chat/completions", payload, hdrs)
}

// =============================================================================
// SUITE C1: cache.type=local (Process-Local LRU, Headers, Exclusions & Metrics)
// =============================================================================

func TestCacheProd_SuiteC1_LocalMode(t *testing.T) {
	apiKey := requireGeminiKey(t)
	client := newCacheTLSClient(t)
	chatGlobal, embedGlobal := seedGeminiGlobalModels(t)
	tenant := provisionTenant(t, client, "c1-local", apiKey, chatGlobal, embedGlobal, true)

	// 1. Deterministic cold MISS -> warm HIT on pod 1, while pod 2 remains MISS (process-local).
	basePayload := map[string]any{
		"model":       tenant.ChatAlias,
		"temperature": 0,
		"max_tokens":  64,
		"messages":    []map[string]any{{"role": "user", "content": "What is 7 times 8? Reply with only the number."}},
	}
	r1, b1, d1 := chatCall(t, client, cachePod1Base, tenant.KeyTeam1, basePayload, nil)
	if r1.StatusCode != http.StatusOK || r1.Header.Get("X-Gateway-Cache") != "MISS" {
		t.Fatalf("C1 pod1 miss: status=%d cache=%q body=%s", r1.StatusCode, r1.Header.Get("X-Gateway-Cache"), string(b1))
	}
	r2, b2, d2 := chatCall(t, client, cachePod1Base, tenant.KeyTeam1, basePayload, nil)
	if r2.StatusCode != http.StatusOK ||
		r2.Header.Get("X-Gateway-Cache") != "HIT" ||
		r2.Header.Get("X-Gateway-Cache-Type") != "exact" ||
		r2.Header.Get("X-Gateway-Cost-Micros") != "0" {
		t.Fatalf("C1 pod1 hit: status=%d cache=%q type=%q cost=%q body=%s",
			r2.StatusCode, r2.Header.Get("X-Gateway-Cache"), r2.Header.Get("X-Gateway-Cache-Type"), r2.Header.Get("X-Gateway-Cost-Micros"), string(b2))
	}
	t.Logf("C1 local latency: MISS=%v -> HIT=%v (exact, cost=0)", d1.Round(time.Millisecond), d2.Round(time.Millisecond))

	// Pod 2 must MISS because local cache is process-local.
	rPod2, bPod2, _ := chatCall(t, client, cachePod2Base, tenant.KeyTeam1, basePayload, nil)
	if rPod2.StatusCode != http.StatusOK || rPod2.Header.Get("X-Gateway-Cache") != "MISS" {
		t.Fatalf("C1 pod2 expected MISS in local mode: status=%d cache=%q body=%s", rPod2.StatusCode, rPod2.Header.Get("X-Gateway-Cache"), string(bPod2))
	}

	// 2. Cache-Control: no-cache bypasses cached entry on pod 1 (omits HIT and incurs upstream call).
	rBypass, bBypass, _ := chatCall(t, client, cachePod1Base, tenant.KeyTeam1, basePayload, map[string]string{
		"Cache-Control": "no-cache",
	})
	if rBypass.StatusCode != http.StatusOK || rBypass.Header.Get("X-Gateway-Cache") == "HIT" {
		t.Fatalf("C1 no-cache bypass failed: status=%d cache=%q body=%s", rBypass.StatusCode, rBypass.Header.Get("X-Gateway-Cache"), string(bBypass))
	}

	// 3. Explicit opt-in caching at temperature > 0 via X-Gateway-Cache-Control: enabled.
	nonDetPayload := map[string]any{
		"model":       tenant.ChatAlias,
		"temperature": 0.7,
		"max_tokens":  64,
		"messages":    []map[string]any{{"role": "user", "content": "Name one primary color in one word."}},
	}
	rOpt1, _, _ := chatCall(t, client, cachePod1Base, tenant.KeyTeam1, nonDetPayload, map[string]string{"X-Gateway-Cache-Control": "enabled"})
	rOpt2, _, _ := chatCall(t, client, cachePod1Base, tenant.KeyTeam1, nonDetPayload, map[string]string{"X-Gateway-Cache-Control": "enabled"})
	if rOpt1.StatusCode != http.StatusOK || rOpt1.Header.Get("X-Gateway-Cache") != "MISS" ||
		rOpt2.StatusCode != http.StatusOK || rOpt2.Header.Get("X-Gateway-Cache") != "HIT" {
		t.Fatalf("C1 opt-in temp=0.7 failed: call1=(%d,%q) call2=(%d,%q)",
			rOpt1.StatusCode, rOpt1.Header.Get("X-Gateway-Cache"), rOpt2.StatusCode, rOpt2.Header.Get("X-Gateway-Cache"))
	}

	// 4. Streaming (stream=true) is never cached in v0.1.
	streamPayload := map[string]any{
		"model":       tenant.ChatAlias,
		"temperature": 0,
		"max_tokens":  64,
		"stream":      true,
		"messages":    []map[string]any{{"role": "user", "content": "Say hello in one word."}},
	}
	rStream, bStream, _ := chatCall(t, client, cachePod1Base, tenant.KeyTeam1, streamPayload, nil)
	if rStream.StatusCode != http.StatusOK || rStream.Header.Get("X-Gateway-Cache") == "HIT" || !strings.Contains(string(bStream), "data:") {
		t.Fatalf("C1 stream call unexpected: status=%d cache=%q body_prefix=%q", rStream.StatusCode, rStream.Header.Get("X-Gateway-Cache"), string(bStream[:min(120, len(bStream))]))
	}

	// 5. Default excluded_call_types=["embedding"] excludes /v1/embeddings from caching.
	embPayload := map[string]any{"model": geminiEmbedModel, "input": "default excluded embedding test"}
	for i := 1; i <= 2; i++ {
		re, be, _ := doHTTP(t, client, http.MethodPost, cachePod1Base+"/v1/embeddings", embPayload, map[string]string{
			"Authorization": "Bearer " + tenant.KeyTeam1,
		})
		if re.StatusCode != http.StatusOK || re.Header.Get("X-Gateway-Cache") == "HIT" {
			t.Fatalf("C1 embeddings call %d expected non-HIT (excluded by default), got status=%d cache=%q body=%s",
				i, re.StatusCode, re.Header.Get("X-Gateway-Cache"), string(be))
		}
	}

	// 6. LRU capacity bound (GATEWAY_CACHE_MAX_ENTRIES=4 in Phase 1) triggers eviction.
	for i := 0; i < 4; i++ {
		p := map[string]any{
			"model":       tenant.ChatAlias,
			"temperature": 0,
			"max_tokens":  32,
			"messages":    []map[string]any{{"role": "user", "content": fmt.Sprintf("What is %d + 1? Number only.", 100+i)}},
		}
		rp, bp, _ := chatCall(t, client, cachePod1Base, tenant.KeyTeam1, p, nil)
		if rp.StatusCode != http.StatusOK {
			t.Fatalf("C1 LRU fill %d failed (%d): %s", i, rp.StatusCode, string(bp))
		}
	}
	entries := scrapeMetric(t, client, cachePod1Base, "gateway_cache_entries")
	evictions := scrapeMetric(t, client, cachePod1Base, "gateway_cache_evictions_total")
	if entries > 4 || evictions < 1 {
		t.Fatalf("C1 LRU bound check failed: gateway_cache_entries=%v (want <=4) gateway_cache_evictions_total=%v (want >=1)", entries, evictions)
	}

	// 7. Operator UI telemetry snapshot matches Prometheus cache counters 100% (unaffected by streaming/no-cache/excluded embeddings).
	hits, misses, hitRate := getObservabilityMetrics(t, client, cachePod1Base)
	promHits := int64(scrapeMetric(t, client, cachePod1Base, "gateway_cache_hits_total"))
	promMisses := int64(scrapeMetric(t, client, cachePod1Base, "gateway_cache_misses_total"))
	if hits < 2 || misses < 2 || hitRate <= 0 {
		t.Fatalf("C1 observability metrics invalid: hits=%d misses=%d hit_rate=%v", hits, misses, hitRate)
	}
	if hits != promHits || misses != promMisses {
		t.Fatalf("C1 observability vs Prometheus cache metrics drift: obs=(%d,%d) prom=(%d,%d)", hits, misses, promHits, promMisses)
	}
	t.Logf("C1 PASS: entries=%.0f evictions=%.0f obs_hits=%d obs_misses=%d hit_rate=%.3f (exact Prometheus parity)", entries, evictions, hits, misses, hitRate)
}

// =============================================================================
// SUITE C2: cache.type=redis (2-Replica HA KV, Isolation, Multi-Endpoint, Purge)
// =============================================================================

func TestCacheProd_SuiteC2_RedisKV_HA(t *testing.T) {
	apiKey := requireGeminiKey(t)
	client := newCacheTLSClient(t)
	chatGlobal, embedGlobal := seedGeminiGlobalModels(t)
	orgA := provisionTenant(t, client, "c2-orga", apiKey, chatGlobal, embedGlobal, true)
	orgB := provisionTenant(t, client, "c2-orgb", apiKey, chatGlobal, embedGlobal, true)

	// 1. Cross-replica KV hit: write on pod 1 -> read HIT on pod 2!
	chatPayload := map[string]any{
		"model":       orgA.ChatAlias,
		"temperature": 0,
		"max_tokens":  64,
		"messages":    []map[string]any{{"role": "user", "content": "What is the chemical symbol for gold? Reply with only the symbol."}},
	}
	r1, b1, d1 := chatCall(t, client, cachePod1Base, orgA.KeyTeam1, chatPayload, nil)
	if r1.StatusCode != http.StatusOK || r1.Header.Get("X-Gateway-Cache") != "MISS" {
		t.Fatalf("C2 pod1 chat miss: status=%d cache=%q body=%s", r1.StatusCode, r1.Header.Get("X-Gateway-Cache"), string(b1))
	}
	r2, b2, d2 := chatCall(t, client, cachePod2Base, orgA.KeyTeam1, chatPayload, nil)
	if r2.StatusCode != http.StatusOK ||
		r2.Header.Get("X-Gateway-Cache") != "HIT" ||
		r2.Header.Get("X-Gateway-Cache-Type") != "exact" ||
		r2.Header.Get("X-Gateway-Cost-Micros") != "0" {
		t.Fatalf("C2 pod2 cross-replica chat HIT failed: status=%d cache=%q type=%q cost=%q body=%s",
			r2.StatusCode, r2.Header.Get("X-Gateway-Cache"), r2.Header.Get("X-Gateway-Cache-Type"), r2.Header.Get("X-Gateway-Cost-Micros"), string(b2))
	}
	t.Logf("C2 Redis KV cross-replica latency: pod1 MISS=%v -> pod2 HIT=%v", d1.Round(time.Millisecond), d2.Round(time.Millisecond))

	// 2. Multi-endpoint coverage across replicas: /v1/responses and /v1/messages.
	respPayload := map[string]any{
		"model":       orgA.ChatAlias,
		"temperature": 0,
		"input":       "What is 9 plus 10? Reply with only the number.",
	}
	rr1, br1, _ := doHTTP(t, client, http.MethodPost, cachePod1Base+"/v1/responses", respPayload, map[string]string{"Authorization": "Bearer " + orgA.KeyTeam1})
	rr2, br2, _ := doHTTP(t, client, http.MethodPost, cachePod2Base+"/v1/responses", respPayload, map[string]string{"Authorization": "Bearer " + orgA.KeyTeam1})
	if rr1.StatusCode != http.StatusOK || rr1.Header.Get("X-Gateway-Cache") != "MISS" ||
		rr2.StatusCode != http.StatusOK || rr2.Header.Get("X-Gateway-Cache") != "HIT" {
		t.Fatalf("C2 /v1/responses cross-replica failed: r1=(%d,%q,%s) r2=(%d,%q,%s)",
			rr1.StatusCode, rr1.Header.Get("X-Gateway-Cache"), string(br1), rr2.StatusCode, rr2.Header.Get("X-Gateway-Cache"), string(br2))
	}

	msgPayload := map[string]any{
		"model":       orgA.ChatAlias,
		"max_tokens":  64,
		"temperature": 0,
		"messages":    []map[string]any{{"role": "user", "content": "What is the largest planet in our solar system? One word."}},
	}
	rm1, bm1, _ := doHTTP(t, client, http.MethodPost, cachePod1Base+"/v1/messages", msgPayload, map[string]string{"Authorization": "Bearer " + orgA.KeyTeam1})
	rm2, bm2, _ := doHTTP(t, client, http.MethodPost, cachePod2Base+"/v1/messages", msgPayload, map[string]string{"Authorization": "Bearer " + orgA.KeyTeam1})
	if rm1.StatusCode != http.StatusOK || rm1.Header.Get("X-Gateway-Cache") != "MISS" ||
		rm2.StatusCode != http.StatusOK || rm2.Header.Get("X-Gateway-Cache") != "HIT" {
		t.Fatalf("C2 /v1/messages cross-replica failed: r1=(%d,%q,%s) r2=(%d,%q,%s)",
			rm1.StatusCode, rm1.Header.Get("X-Gateway-Cache"), string(bm1), rm2.StatusCode, rm2.Header.Get("X-Gateway-Cache"), string(bm2))
	}

	// 3. Multi-tenant (Org A vs Org B isolation), intra-org explicit-model sharing, and system prompt isolation.
	rOrgB, _, _ := chatCall(t, client, cachePod2Base, orgB.KeyTeam1, chatPayload, nil)
	if rOrgB.StatusCode != http.StatusOK || rOrgB.Header.Get("X-Gateway-Cache") != "MISS" {
		t.Fatalf("C2 Org B must not read Org A cache: status=%d cache=%q", rOrgB.StatusCode, rOrgB.Header.Get("X-Gateway-Cache"))
	}
	rTeam2, _, _ := chatCall(t, client, cachePod2Base, orgA.KeyTeam2, chatPayload, nil)
	if rTeam2.StatusCode != http.StatusOK || rTeam2.Header.Get("X-Gateway-Cache") != "HIT" {
		t.Fatalf("C2 Team 2 in same Org A should share explicit-model org cache: status=%d cache=%q", rTeam2.StatusCode, rTeam2.Header.Get("X-Gateway-Cache"))
	}
	diffSysPayload := map[string]any{
		"model":       orgA.ChatAlias,
		"temperature": 0,
		"max_tokens":  64,
		"messages": []map[string]any{
			{"role": "system", "content": "Answer in lowercase."},
			{"role": "user", "content": "What is the chemical symbol for gold? Reply with only the symbol."},
		},
	}
	rDiffSys, _, _ := chatCall(t, client, cachePod2Base, orgA.KeyTeam1, diffSysPayload, nil)
	if rDiffSys.StatusCode != http.StatusOK || rDiffSys.Header.Get("X-Gateway-Cache") != "MISS" {
		t.Fatalf("C2 different system prompt must MISS: status=%d cache=%q", rDiffSys.StatusCode, rDiffSys.Header.Get("X-Gateway-Cache"))
	}

	// 4. Dedicated Redis keyspace isolation check via redis-cli.
	cacheKeys := redisExec(t, "redis-cache", cacheDedRPass, "KEYS", "gw:cache:kv:*")
	primaryCacheKeys := redisExec(t, "redis-primary", cachePrimaryRPass, "KEYS", "gw:cache:*")
	cacheRLKeys := redisExec(t, "redis-cache", cacheDedRPass, "KEYS", "gw:dq:*")
	if cacheKeys == "" {
		t.Fatal("C2 expected gw:cache:kv:* keys on dedicated redis-cache, found none")
	}
	if primaryCacheKeys != "" {
		t.Fatalf("C2 unexpected gw:cache:* keys leaked onto redis-primary: %s", primaryCacheKeys)
	}
	if cacheRLKeys != "" {
		t.Fatalf("C2 unexpected rate-limit gw:dq:* keys leaked onto redis-cache: %s", cacheRLKeys)
	}
	t.Log("C2 PASS: Verified strict dedicated Redis keyspace separation (cache on redis-cache, auth/RL on redis-primary)")

	// 5. Strict AND admin invalidation: orgA + gemini-chat does NOT purge orgA + gemini-chat-alt or orgB + gemini-chat.
	altPayload := map[string]any{
		"model":       orgA.AltAlias,
		"temperature": 0,
		"max_tokens":  64,
		"messages":    []map[string]any{{"role": "user", "content": "What is the chemical symbol for gold? Reply with only the symbol."}},
	}
	rAlt1, _, _ := chatCall(t, client, cachePod1Base, orgA.KeyTeam1, altPayload, nil)
	if rAlt1.StatusCode != http.StatusOK {
		t.Fatalf("C2 seed alt model failed: %d", rAlt1.StatusCode)
	}

	purged := invalidateCache(t, client, cachePod1Base, orgA.OrgID, orgA.ChatAlias)
	if purged < 1 {
		t.Fatalf("C2 expected >=1 purged entry for orgA+chat, got %d", purged)
	}
	rAfterOrgA, _, _ := chatCall(t, client, cachePod2Base, orgA.KeyTeam1, chatPayload, nil)
	rAfterAlt, _, _ := chatCall(t, client, cachePod2Base, orgA.KeyTeam1, altPayload, nil)
	rAfterOrgB, _, _ := chatCall(t, client, cachePod2Base, orgB.KeyTeam1, chatPayload, nil)
	if rAfterOrgA.Header.Get("X-Gateway-Cache") != "MISS" {
		t.Fatalf("C2 orgA+chat should MISS after invalidation, got %q", rAfterOrgA.Header.Get("X-Gateway-Cache"))
	}
	if rAfterAlt.Header.Get("X-Gateway-Cache") != "HIT" {
		t.Fatalf("C2 orgA+alt should remain HIT (strict AND invalidation), got %q", rAfterAlt.Header.Get("X-Gateway-Cache"))
	}
	if rAfterOrgB.Header.Get("X-Gateway-Cache") != "HIT" {
		t.Fatalf("C2 orgB+chat should remain HIT (strict AND invalidation), got %q", rAfterOrgB.Header.Get("X-Gateway-Cache"))
	}
	t.Logf("C2 PASS: Strict AND invalidation purged=%d (orgA+chat=MISS, orgA+alt=HIT, orgB+chat=HIT)", purged)
}

func TestCacheProd_SuiteC2b_RedisKV_EmbeddingsOptIn(t *testing.T) {
	apiKey := requireGeminiKey(t)
	client := newCacheTLSClient(t)
	chatGlobal, embedGlobal := seedGeminiGlobalModels(t)
	tenant := provisionTenant(t, client, "c2b-emb", apiKey, chatGlobal, embedGlobal, true)

	embPayload := map[string]any{"model": geminiEmbedModel, "input": "opt-in live redis embeddings caching"}
	r1, b1, d1 := doHTTP(t, client, http.MethodPost, cachePod1Base+"/v1/embeddings", embPayload, map[string]string{
		"Authorization": "Bearer " + tenant.KeyTeam1,
	})
	r2, b2, d2 := doHTTP(t, client, http.MethodPost, cachePod2Base+"/v1/embeddings", embPayload, map[string]string{
		"Authorization": "Bearer " + tenant.KeyTeam1,
	})
	if r1.StatusCode != http.StatusOK || r1.Header.Get("X-Gateway-Cache") != "MISS" ||
		r2.StatusCode != http.StatusOK || r2.Header.Get("X-Gateway-Cache") != "HIT" ||
		r2.Header.Get("X-Gateway-Cost-Micros") != "0" {
		t.Fatalf("C2b embeddings opt-in failed: r1=(%d,%q,%s) r2=(%d,%q,cost=%q,%s)",
			r1.StatusCode, r1.Header.Get("X-Gateway-Cache"), string(b1),
			r2.StatusCode, r2.Header.Get("X-Gateway-Cache"), r2.Header.Get("X-Gateway-Cost-Micros"), string(b2))
	}
	t.Logf("C2b PASS: Opt-in /v1/embeddings cross-replica MISS=%v -> HIT=%v (cost=0)", d1.Round(time.Millisecond), d2.Round(time.Millisecond))
}

// =============================================================================
// SUITE C3: cache.type=redis-semantic (HNSW + Live Gemini + Isolation + Purge)
// =============================================================================

func TestCacheProd_SuiteC3_RedisSemantic_HNSW_LiveGemini(t *testing.T) {
	apiKey := requireGeminiKey(t)
	client := newCacheTLSClient(t)
	chatGlobal, embedGlobal := seedGeminiGlobalModels(t)
	orgA := provisionTenant(t, client, "c3-orga", apiKey, chatGlobal, embedGlobal, true)
	orgB := provisionTenant(t, client, "c3-orgb", apiKey, chatGlobal, embedGlobal, true)
	orgNoEmbed := provisionTenant(t, client, "c3-noemb", apiKey, chatGlobal, embedGlobal, false)

	// 1. Seed prompt on pod 1 -> live Gemini chat + live gemini-embedding-001 (3072-dim).
	rSeed, bSeed, dSeed := chatCall(t, client, cachePod1Base, orgA.KeyTeam1, map[string]any{
		"model":      orgA.ChatAlias,
		"max_tokens": 64,
		"messages":   []map[string]any{{"role": "user", "content": "What is the capital city of France? Answer in one short sentence."}},
	}, nil)
	if rSeed.StatusCode != http.StatusOK || rSeed.Header.Get("X-Gateway-Cache") != "MISS" {
		t.Fatalf("C3 seed call failed: status=%d cache=%q body=%s", rSeed.StatusCode, rSeed.Header.Get("X-Gateway-Cache"), string(bSeed))
	}
	if !strings.Contains(strings.ToLower(string(bSeed)), "paris") {
		t.Fatalf("C3 expected Paris in Gemini response, got: %s", string(bSeed))
	}

	// 2. Inspect live Redis 8 RediSearch index via FT.INFO.
	ftInfo := redisExec(t, "redis-cache", cacheDedRPass, "FT.INFO", "gw_semantic_cache_idx")
	for _, want := range []string{"gw_semantic_cache_idx", "scope", "org_id", "model", "embedding"} {
		if !strings.Contains(ftInfo, want) {
			t.Fatalf("C3 FT.INFO missing expected schema token %q:\n%s", want, ftInfo)
		}
	}
	t.Log("C3 PASS: Verified live Redis 8 RediSearch index gw_semantic_cache_idx via FT.INFO")

	// 3. Paraphrased query on POD 2 -> live cross-replica semantic HIT!
	paraphrasePayload := map[string]any{
		"model":      orgA.ChatAlias,
		"max_tokens": 64,
		"messages":   []map[string]any{{"role": "user", "content": "Tell me France's capital in a brief sentence."}},
	}
	rHit, bHit, dHit := chatCall(t, client, cachePod2Base, orgA.KeyTeam1, paraphrasePayload, nil)
	if rHit.StatusCode != http.StatusOK ||
		rHit.Header.Get("X-Gateway-Cache") != "HIT" ||
		rHit.Header.Get("X-Gateway-Cache-Type") != "semantic" ||
		rHit.Header.Get("X-Gateway-Cost-Micros") != "0" {
		t.Fatalf("C3 cross-replica semantic HIT failed: status=%d cache=%q type=%q sim=%q cost=%q body=%s",
			rHit.StatusCode, rHit.Header.Get("X-Gateway-Cache"), rHit.Header.Get("X-Gateway-Cache-Type"),
			rHit.Header.Get("X-Gateway-Cache-Similarity"), rHit.Header.Get("X-Gateway-Cost-Micros"), string(bHit))
	}
	simVal, err := strconv.ParseFloat(rHit.Header.Get("X-Gateway-Cache-Similarity"), 64)
	if err != nil || simVal < 0.85 {
		t.Fatalf("C3 unexpected similarity header %q (err=%v)", rHit.Header.Get("X-Gateway-Cache-Similarity"), err)
	}
	t.Logf("C3 PASS: Cross-replica semantic HIT on pod2 (sim=%.4f, seed=%v -> hit=%v, cost=0)",
		simVal, dSeed.Round(time.Millisecond), dHit.Round(time.Millisecond))

	// 4. Per-request X-Gateway-Cache-Similarity override: 0.99 forces MISS on a new paraphrase.
	strictParaphrase := map[string]any{
		"model":      orgA.ChatAlias,
		"max_tokens": 64,
		"messages":   []map[string]any{{"role": "user", "content": "Could you name the capital of France in one brief sentence?"}},
	}
	rStrict, _, _ := chatCall(t, client, cachePod2Base, orgA.KeyTeam1, strictParaphrase, map[string]string{
		"X-Gateway-Cache-Similarity": "0.99",
	})
	if rStrict.StatusCode != http.StatusOK || rStrict.Header.Get("X-Gateway-Cache") != "MISS" {
		t.Fatalf("C3 X-Gateway-Cache-Similarity=0.99 expected MISS, got status=%d cache=%q sim=%q",
			rStrict.StatusCode, rStrict.Header.Get("X-Gateway-Cache"), rStrict.Header.Get("X-Gateway-Cache-Similarity"))
	}

	// 5. Unrelated prompt -> MISS.
	rUnrel, bUnrel, _ := chatCall(t, client, cachePod2Base, orgA.KeyTeam1, map[string]any{
		"model":      orgA.ChatAlias,
		"max_tokens": 64,
		"messages":   []map[string]any{{"role": "user", "content": "What is the boiling point of water in Celsius at sea level? Reply in one short sentence."}},
	}, nil)
	if rUnrel.StatusCode != http.StatusOK || rUnrel.Header.Get("X-Gateway-Cache") != "MISS" || !strings.Contains(string(bUnrel), "100") {
		t.Fatalf("C3 unrelated prompt failed: status=%d cache=%q body=%s", rUnrel.StatusCode, rUnrel.Header.Get("X-Gateway-Cache"), string(bUnrel))
	}

	// 6. Strict multi-tenant isolation: Org B asking identical paraphrase -> MISS (and stores its own doc).
	rOrgB, _, _ := chatCall(t, client, cachePod2Base, orgB.KeyTeam1, paraphrasePayload, nil)
	if rOrgB.StatusCode != http.StatusOK || rOrgB.Header.Get("X-Gateway-Cache") != "MISS" {
		t.Fatalf("C3 Org B must MISS (TAG org_id/scope isolation), got status=%d cache=%q", rOrgB.StatusCode, rOrgB.Header.Get("X-Gateway-Cache"))
	}

	// 7. System prompt isolation: different system prompt -> MISS.
	rDiffSys, _, _ := chatCall(t, client, cachePod2Base, orgA.KeyTeam1, map[string]any{
		"model":      orgA.ChatAlias,
		"max_tokens": 64,
		"messages": []map[string]any{
			{"role": "system", "content": "Respond in pirate speak."},
			{"role": "user", "content": "Tell me France's capital in a brief sentence."},
		},
	}, nil)
	if rDiffSys.StatusCode != http.StatusOK || rDiffSys.Header.Get("X-Gateway-Cache") != "MISS" {
		t.Fatalf("C3 different system prompt must MISS, got status=%d cache=%q", rDiffSys.StatusCode, rDiffSys.Header.Get("X-Gateway-Cache"))
	}

	// 8. Multi-turn semantic isolation within max_messages=4: identical final user question under
	//    different prior turns (Python vs Rust) MUST NOT collide (H2).
	rPyTurn, bPyTurn, _ := chatCall(t, client, cachePod1Base, orgA.KeyTeam1, map[string]any{
		"model":      orgA.ChatAlias,
		"max_tokens": 64,
		"messages": []map[string]any{
			{"role": "user", "content": "We are working on a Python project."},
			{"role": "assistant", "content": "Got it, Python."},
			{"role": "user", "content": "What package manager command installs a library? Reply in one short sentence."},
		},
	}, nil)
	if rPyTurn.StatusCode != http.StatusOK || rPyTurn.Header.Get("X-Gateway-Cache") != "MISS" {
		t.Fatalf("C3 Python multi-turn seed failed: status=%d cache=%q body=%s", rPyTurn.StatusCode, rPyTurn.Header.Get("X-Gateway-Cache"), string(bPyTurn))
	}
	rRustTurn, bRustTurn, _ := chatCall(t, client, cachePod2Base, orgA.KeyTeam1, map[string]any{
		"model":      orgA.ChatAlias,
		"max_tokens": 64,
		"messages": []map[string]any{
			{"role": "user", "content": "We are working on a Rust project."},
			{"role": "assistant", "content": "Got it, Rust."},
			{"role": "user", "content": "What package manager command installs a library? Reply in one short sentence."},
		},
	}, nil)
	if rRustTurn.StatusCode != http.StatusOK || rRustTurn.Header.Get("X-Gateway-Cache") != "MISS" {
		t.Fatalf("C3 Rust multi-turn must MISS (prior turns isolated from Python): status=%d cache=%q body=%s",
			rRustTurn.StatusCode, rRustTurn.Header.Get("X-Gateway-Cache"), string(bRustTurn))
	}
	t.Log("C3 PASS: Multi-turn prior-turn semantic scope isolation verified (Python vs Rust did not collide)")

	// 8b. Multi-turn conversation exceeding max_messages=4 bypasses semantic lookup safely.
	rLongConv, _, _ := chatCall(t, client, cachePod2Base, orgA.KeyTeam1, map[string]any{
		"model":      orgA.ChatAlias,
		"max_tokens": 64,
		"messages": []map[string]any{
			{"role": "user", "content": "Hi"},
			{"role": "assistant", "content": "Hello"},
			{"role": "user", "content": "Let's talk geography"},
			{"role": "assistant", "content": "Sure"},
			{"role": "user", "content": "Tell me France's capital in a brief sentence."},
		},
	}, nil)
	if rLongConv.StatusCode != http.StatusOK || rLongConv.Header.Get("X-Gateway-Cache") != "MISS" {
		t.Fatalf("C3 >max_messages conversation expected safe MISS, got status=%d cache=%q", rLongConv.StatusCode, rLongConv.Header.Get("X-Gateway-Cache"))
	}

	// 9. Fail-open when a tenant lacks the configured semantic embedding model.
	errBefore := scrapeMetric(t, client, cachePod1Base, "gateway_cache_errors_total")
	rNoEmb, bNoEmb, _ := chatCall(t, client, cachePod1Base, orgNoEmbed.KeyTeam1, map[string]any{
		"model":      orgNoEmbed.ChatAlias,
		"max_tokens": 48,
		"messages":   []map[string]any{{"role": "user", "content": "Say ok in one word."}},
	}, nil)
	if rNoEmb.StatusCode != http.StatusOK || rNoEmb.Header.Get("X-Gateway-Cache") != "MISS" {
		t.Fatalf("C3 tenant without embedding model must fail open 200 MISS: status=%d cache=%q body=%s",
			rNoEmb.StatusCode, rNoEmb.Header.Get("X-Gateway-Cache"), string(bNoEmb))
	}
	errAfter := scrapeMetric(t, client, cachePod1Base, "gateway_cache_errors_total")
	if errAfter <= errBefore {
		t.Fatalf("C3 expected gateway_cache_errors_total to increment on missing embedding model (before=%v after=%v)", errBefore, errAfter)
	}

	// 10. Targeted admin invalidation purges Org A semantic docs while keeping Org B semantic docs alive!
	purged := invalidateCache(t, client, cachePod1Base, orgA.OrgID, orgA.ChatAlias)
	if purged < 1 {
		t.Fatalf("C3 expected >=1 purged semantic doc for orgA, got %d", purged)
	}
	rOrgAAfter, _, _ := chatCall(t, client, cachePod2Base, orgA.KeyTeam1, paraphrasePayload, nil)
	rOrgBAfter, _, _ := chatCall(t, client, cachePod2Base, orgB.KeyTeam1, map[string]any{
		"model":      orgB.ChatAlias,
		"max_tokens": 64,
		"messages":   []map[string]any{{"role": "user", "content": "What is France's capital city? Reply briefly."}},
	}, nil)
	if rOrgAAfter.Header.Get("X-Gateway-Cache") != "MISS" {
		t.Fatalf("C3 orgA paraphrase should MISS after targeted invalidation, got %q", rOrgAAfter.Header.Get("X-Gateway-Cache"))
	}
	if rOrgBAfter.Header.Get("X-Gateway-Cache") != "HIT" {
		t.Fatalf("C3 orgB paraphrase should remain HIT after orgA invalidation, got %q", rOrgBAfter.Header.Get("X-Gateway-Cache"))
	}
	t.Logf("C3 PASS: Targeted semantic invalidation purged=%d (orgA=MISS, orgB=HIT)", purged)
}

// =============================================================================
// SUITE C4: Chaos Engineering — Dedicated redis-cache Outage & Auto-Recovery
// =============================================================================

func TestCacheProd_SuiteC4_ChaosFailOpenAndRecovery(t *testing.T) {
	apiKey := requireGeminiKey(t)
	client := newCacheTLSClient(t)
	chatGlobal, embedGlobal := seedGeminiGlobalModels(t)
	tenant := provisionTenant(t, client, "c4-chaos", apiKey, chatGlobal, embedGlobal, true)

	// Issue a key with rpm_limit=1 to verify rate limiting on redis-primary stays active during redis-cache outage.
	var rlKey struct {
		RawKey string `json:"raw_key"`
	}
	mustAdminJSON(t, client, http.MethodPost, cachePod1Base+"/admin/v1/keys", map[string]any{
		"org_id":            tenant.OrgID,
		"team_id":           tenant.Team1ID,
		"name":              "vk-chaos-rpm1",
		"rpm_limit":         1,
		"allowed_endpoints": []string{"*"},
		"allowed_models":    []string{"*"},
	}, &rlKey, http.StatusCreated)

	errBefore := scrapeMetric(t, client, cachePod1Base, "gateway_cache_errors_total")

	// Ensure redis-cache is always restarted even if assertions fail mid-test.
	t.Cleanup(func() {
		_ = composeExec(t, "start", "redis-cache")
	})

	// 1. Stop dedicated redis-cache container mid-flight.
	composeExec(t, "stop", "redis-cache")
	t.Log("C4: Stopped redis-cache container; verifying /readyz fail-open degraded status + fail-open inference + unaffected primary rate limiting...")

	// 1b. /readyz must stay HTTP 200 (fail-open) while reporting cache_status="degraded".
	rReadyDeg, bReadyDeg, _ := doHTTP(t, client, http.MethodGet, cachePod1Base+"/readyz", nil, nil)
	var readyDeg map[string]any
	_ = json.Unmarshal(bReadyDeg, &readyDeg)
	if rReadyDeg.StatusCode != http.StatusOK || readyDeg["status"] != "ready" || readyDeg["cache_status"] != "degraded" {
		t.Fatalf("C4 /readyz during redis-cache outage expected 200 status=ready cache_status=degraded, got %d body=%s", rReadyDeg.StatusCode, string(bReadyDeg))
	}

	// 2. First call through pod 1 must succeed 200 OK (fail-open MISS) and increment gateway_cache_errors_total.
	rOutage, bOutage, _ := chatCall(t, client, cachePod1Base, rlKey.RawKey, map[string]any{
		"model":      tenant.ChatAlias,
		"max_tokens": 48,
		"messages":   []map[string]any{{"role": "user", "content": "What is 2 + 2? Number only."}},
	}, nil)
	if rOutage.StatusCode != http.StatusOK || rOutage.Header.Get("X-Gateway-Cache") != "MISS" {
		t.Fatalf("C4 fail-open during redis-cache outage failed: status=%d cache=%q body=%s",
			rOutage.StatusCode, rOutage.Header.Get("X-Gateway-Cache"), string(bOutage))
	}
	errAfter := scrapeMetric(t, client, cachePod1Base, "gateway_cache_errors_total")
	if errAfter <= errBefore {
		t.Fatalf("C4 expected gateway_cache_errors_total to increase during outage (before=%v after=%v)", errBefore, errAfter)
	}

	// 3. Subsequent calls with rpm_limit=1 must STILL be rejected with HTTP 429 from redis-primary!
	// Send up to 2 fast calls in case a 60s fixed-window minute boundary rolled over during call 1.
	got429 := false
	for attempt := 0; attempt < 2; attempt++ {
		rRL, _, _ := chatCall(t, client, cachePod2Base, rlKey.RawKey, map[string]any{
			"model":      tenant.ChatAlias,
			"max_tokens": 32,
			"messages":   []map[string]any{{"role": "user", "content": fmt.Sprintf("What is %d + %d?", attempt+3, attempt+3)}},
		}, nil)
		if rRL.StatusCode == http.StatusTooManyRequests {
			got429 = true
			break
		}
	}
	if !got429 {
		t.Fatal("C4 expected HTTP 429 from redis-primary while redis-cache is down, got none")
	}
	t.Log("C4 PASS: Fail-open 200 OK on cache outage AND 429 rate-limit enforcement on redis-primary verified!")

	// 4. Restart redis-cache and wait until healthy + past RedisFabric's 10s circuit breaker half-open timeout.
	composeExec(t, "start", "redis-cache")
	ready := false
	for i := 0; i < 20; i++ {
		if out, err := exec.Command("docker", "compose", "-f", mustAbs(t, cacheComposeFile),
			"exec", "-T", "redis-cache", "redis-cli", "-a", cacheDedRPass, "--no-auth-warning", "PING").CombinedOutput(); err == nil && strings.Contains(string(out), "PONG") {
			ready = true
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if !ready {
		t.Fatal("C4 redis-cache did not become ready after restart")
	}
	// Allow dedicated cache RedisFabric circuit breaker (Timeout=10s) to transition to half-open/closed.
	time.Sleep(11 * time.Second)

	// 4b. /readyz must report cache_status="ok" again once redis-cache is back up.
	rReadyOK, bReadyOK, _ := doHTTP(t, client, http.MethodGet, cachePod1Base+"/readyz", nil, nil)
	var readyOK map[string]any
	_ = json.Unmarshal(bReadyOK, &readyOK)
	if rReadyOK.StatusCode != http.StatusOK || readyOK["status"] != "ready" || readyOK["cache_status"] != "ok" {
		t.Fatalf("C4 /readyz after redis-cache recovery expected 200 status=ready cache_status=ok, got %d body=%s", rReadyOK.StatusCode, string(bReadyOK))
	}

	// 5. Verify automatic recovery & lazy RediSearch index recreation without restarting gateway pods!
	rRec1, bRec1, _ := chatCall(t, client, cachePod1Base, tenant.KeyTeam1, map[string]any{
		"model":      tenant.ChatAlias,
		"max_tokens": 64,
		"messages":   []map[string]any{{"role": "user", "content": "What is the capital city of Japan? One short sentence."}},
	}, nil)
	if rRec1.StatusCode != http.StatusOK || rRec1.Header.Get("X-Gateway-Cache") != "MISS" {
		t.Fatalf("C4 post-recovery seed failed: status=%d cache=%q body=%s", rRec1.StatusCode, rRec1.Header.Get("X-Gateway-Cache"), string(bRec1))
	}
	rRec2, bRec2, _ := chatCall(t, client, cachePod2Base, tenant.KeyTeam1, map[string]any{
		"model":      tenant.ChatAlias,
		"max_tokens": 64,
		"messages":   []map[string]any{{"role": "user", "content": "Tell me Japan's capital in one brief sentence."}},
	}, nil)
	if rRec2.StatusCode != http.StatusOK ||
		rRec2.Header.Get("X-Gateway-Cache") != "HIT" ||
		rRec2.Header.Get("X-Gateway-Cache-Type") != "semantic" {
		t.Fatalf("C4 post-recovery semantic HIT failed: status=%d cache=%q type=%q sim=%q body=%s",
			rRec2.StatusCode, rRec2.Header.Get("X-Gateway-Cache"), rRec2.Header.Get("X-Gateway-Cache-Type"), rRec2.Header.Get("X-Gateway-Cache-Similarity"), string(bRec2))
	}
	t.Logf("C4 PASS: Automatic semantic cache recovery verified after redis-cache restart (sim=%s)", rRec2.Header.Get("X-Gateway-Cache-Similarity"))
}

func mustAbs(t *testing.T, p string) string {
	t.Helper()
	abs, err := filepath.Abs(p)
	if err != nil {
		t.Fatalf("abs %s: %v", p, err)
	}
	return abs
}

// =============================================================================
// SUITE C5: Concurrency Burst, FinOps $0 Spend Audit & Telemetry Parity
// =============================================================================

func TestCacheProd_SuiteC5_ConcurrencyFinOpsAndMetrics(t *testing.T) {
	apiKey := requireGeminiKey(t)
	client := newCacheTLSClient(t)
	chatGlobal, embedGlobal := seedGeminiGlobalModels(t)
	tenant := provisionTenant(t, client, "c5-stress", apiKey, chatGlobal, embedGlobal, true)

	// 1. Seed a fresh deterministic prompt -> MISS, wait for FinOps outbox flush, verify >0 spend logged.
	seedPayload := map[string]any{
		"model":       tenant.ChatAlias,
		"temperature": 0,
		"max_tokens":  64,
		"messages":    []map[string]any{{"role": "user", "content": "What is the capital city of Italy? Answer in one short sentence."}},
	}
	rSeed, bSeed, _ := chatCall(t, client, cachePod1Base, tenant.KeyTeam1, seedPayload, nil)
	if rSeed.StatusCode != http.StatusOK || rSeed.Header.Get("X-Gateway-Cache") != "MISS" {
		t.Fatalf("C5 seed call failed: status=%d cache=%q body=%s", rSeed.StatusCode, rSeed.Header.Get("X-Gateway-Cache"), string(bSeed))
	}

	// Wait briefly for the async FinOps spend outbox worker (flush_interval=100ms).
	time.Sleep(600 * time.Millisecond)

	type spendRow struct {
		Endpoint   string `json:"endpoint"`
		Modality   string `json:"modality"`
		CostMicros int64  `json:"cost_micros"`
		CacheHit   bool   `json:"cache_hit"`
	}
	getSpendBreakdown := func() (chatRows int, chatCost int64, semEmbedRows int) {
		var resp struct {
			Data []spendRow `json:"data"`
		}
		raw := mustAdminJSON(t, client, http.MethodGet, cachePod1Base+"/admin/v1/spend/logs?org_id="+tenant.OrgID+"&limit=200", nil, nil, http.StatusOK)
		var rows []spendRow
		if err := json.Unmarshal(raw, &resp); err == nil && len(resp.Data) > 0 {
			rows = resp.Data
		} else if err := json.Unmarshal(raw, &rows); err != nil {
			t.Fatalf("decode /admin/v1/spend/logs: %v (%s)", err, string(raw))
		}
		for _, row := range rows {
			if row.Endpoint == "_internal/semantic_cache" {
				semEmbedRows++
				continue
			}
			chatRows++
			chatCost += row.CostMicros
		}
		return chatRows, chatCost, semEmbedRows
	}

	missRows, missCost, missSemRows := getSpendBreakdown()
	if missRows < 1 {
		t.Fatalf("C5 expected >=1 chat spend_logs row after MISS, got %d", missRows)
	}
	if missSemRows < 1 {
		t.Fatalf("C5 expected >=1 _internal/semantic_cache spend_logs row after semantic MISS, got %d", missSemRows)
	}

	// 2. Fire 20 concurrent requests across LB, pod 1, and pod 2 (10 exact + 10 semantic paraphrases).
	const workers = 20
	var wg sync.WaitGroup
	var hitCount, semHitCount, errCount atomic.Int32
	bases := []string{cacheLBBase, cachePod1Base, cachePod2Base}
	paraphrasePayload := map[string]any{
		"model":       tenant.ChatAlias,
		"temperature": 0,
		"max_tokens":  64,
		"messages":    []map[string]any{{"role": "user", "content": "Tell me Italy's capital in a brief sentence."}},
	}

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			payload := seedPayload
			if idx%2 == 1 {
				payload = paraphrasePayload
			}
			target := bases[idx%len(bases)]
			resp, body, _ := chatCall(t, client, target, tenant.KeyTeam1, payload, nil)
			if resp.StatusCode != http.StatusOK {
				errCount.Add(1)
				t.Errorf("C5 worker %d HTTP %d: %s", idx, resp.StatusCode, string(body))
				return
			}
			var parsed map[string]any
			if err := json.Unmarshal(body, &parsed); err != nil || parsed["choices"] == nil {
				errCount.Add(1)
				t.Errorf("C5 worker %d invalid JSON body: %s", idx, string(body))
				return
			}
			if resp.Header.Get("X-Gateway-Cache") == "HIT" {
				hitCount.Add(1)
				if resp.Header.Get("X-Gateway-Cost-Micros") != "0" {
					errCount.Add(1)
					t.Errorf("C5 worker %d HIT had non-zero cost %q", idx, resp.Header.Get("X-Gateway-Cost-Micros"))
				}
				if resp.Header.Get("X-Gateway-Cache-Type") == "semantic" {
					semHitCount.Add(1)
				}
			}
		}(i)
	}
	wg.Wait()

	if errCount.Load() != 0 {
		t.Fatalf("C5 concurrency burst encountered %d errors", errCount.Load())
	}
	if hitCount.Load() < workers {
		t.Fatalf("C5 expected all %d warm burst calls to HIT, got %d hits (%d semantic)", workers, hitCount.Load(), semHitCount.Load())
	}

	// 3. Re-check PostgreSQL spend_logs after 20 concurrent HITs: GoRoute records $0 audit rows
	// for chat cache hits while total chat billed cost stays strictly unchanged ($0 added across all 20 HITs),
	// and internal semantic-cache embedding calls are audited separately under "_internal/semantic_cache".
	time.Sleep(600 * time.Millisecond)
	afterRows, afterCost, afterSemRows := getSpendBreakdown()
	if afterCost != missCost {
		t.Fatalf("C5 chat cache HITs must add $0 billed chat spend: before=(%d rows, %d micros) after=(%d rows, %d micros)",
			missRows, missCost, afterRows, afterCost)
	}
	if afterRows < missRows {
		t.Fatalf("C5 unexpected chat spend_logs row shrinkage: before=%d after=%d", missRows, afterRows)
	}
	if afterSemRows <= missSemRows {
		t.Fatalf("C5 expected _internal/semantic_cache audit rows to reflect semantic lookup embeddings (before=%d after=%d)", missSemRows, afterSemRows)
	}

	// 4. Verify all 6 backend-agnostic Prometheus metrics & /admin/v1/observability/metrics.
	for _, base := range []string{cachePod1Base, cachePod2Base} {
		for _, metric := range []string{
			"gateway_cache_hits_total",
			"gateway_cache_misses_total",
			"gateway_cache_errors_total",
			"gateway_cache_semantic_hits_total",
			"gateway_cache_entries",
			"gateway_cache_evictions_total",
		} {
			_ = scrapeMetric(t, client, base, metric)
		}
	}
	totalPromHits := scrapeMetric(t, client, cachePod1Base, "gateway_cache_hits_total") +
		scrapeMetric(t, client, cachePod2Base, "gateway_cache_hits_total")
	totalSemHits := scrapeMetric(t, client, cachePod1Base, "gateway_cache_semantic_hits_total") +
		scrapeMetric(t, client, cachePod2Base, "gateway_cache_semantic_hits_total")
	if totalPromHits < float64(workers) || totalSemHits < 1 {
		t.Fatalf("C5 Prometheus hit counters too low: total_hits=%v sem_hits=%v", totalPromHits, totalSemHits)
	}
	h1, m1, hr1 := getObservabilityMetrics(t, client, cachePod1Base)
	h2, m2, hr2 := getObservabilityMetrics(t, client, cachePod2Base)
	if h1+h2 < workers || (hr1 <= 0 && hr2 <= 0) {
		t.Fatalf("C5 observability snapshot mismatch: pod1=(%d,%d,%.3f) pod2=(%d,%d,%.3f)", h1, m1, hr1, h2, m2, hr2)
	}
	t.Logf("C5 PASS: %d/20 concurrent HITs (%d semantic), spend unchanged (%d rows, %d micros), prom_hits=%.0f prom_sem_hits=%.0f",
		hitCount.Load(), semHitCount.Load(), afterRows, afterCost, totalPromHits, totalSemHits)
}

// =============================================================================
// SUITE C6: Config Redaction & CORS Header Exposure
// =============================================================================

func TestCacheProd_SuiteC6_ConfigRedactionAndCORS(t *testing.T) {
	client := newCacheTLSClient(t)

	// 1. Verify GET /admin/v1/config redacts cache.redis_pass and exposes clean cache schema.
	raw := mustAdminJSON(t, client, http.MethodGet, cachePod1Base+"/admin/v1/config", nil, nil, http.StatusOK)
	bodyStr := string(raw)
	for _, secret := range []string{cacheMasterKey, cachePrimaryRPass, cacheDedRPass, "prod-cache-pg-password-2026"} {
		if strings.Contains(bodyStr, secret) {
			t.Fatalf("C6 /admin/v1/config leaked secret %q", secret)
		}
	}
	var cfg map[string]any
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("C6 decode config: %v", err)
	}
	cacheSec, _ := cfg["cache"].(map[string]any)
	if cacheSec["type"] != "redis-semantic" || cacheSec["redis_pass"] != "[REDACTED]" {
		t.Fatalf("C6 unexpected cache config section: %+v", cacheSec)
	}

	// 2. Verify CORS Access-Control-Expose-Headers includes all 3 cache telemetry headers.
	resp, _, _ := doHTTP(t, client, http.MethodGet, cacheLBBase+"/healthz", nil, map[string]string{
		"Origin": "https://gateway.prod.test:19443",
	})
	exposed := resp.Header.Get("Access-Control-Expose-Headers")
	for _, hdr := range []string{"X-Gateway-Cache", "X-Gateway-Cache-Type", "X-Gateway-Cache-Similarity"} {
		if !strings.Contains(exposed, hdr) {
			t.Fatalf("C6 CORS Access-Control-Expose-Headers missing %q: %q", hdr, exposed)
		}
	}
	t.Log("C6 PASS: /admin/v1/config redaction and CORS cache header exposure verified")
}

// =============================================================================
// PHASE 4: cache.type=redis-semantic with vector_algorithm=FLAT
// =============================================================================

func TestCacheProd_Phase4_RedisSemantic_FLAT(t *testing.T) {
	apiKey := requireGeminiKey(t)
	client := newCacheTLSClient(t)
	chatGlobal, embedGlobal := seedGeminiGlobalModels(t)
	tenant := provisionTenant(t, client, "c3-flat", apiKey, chatGlobal, embedGlobal, true)

	r1, b1, _ := chatCall(t, client, cachePod1Base, tenant.KeyTeam1, map[string]any{
		"model":      tenant.ChatAlias,
		"max_tokens": 64,
		"messages":   []map[string]any{{"role": "user", "content": "What is the capital city of Spain? Answer in one short sentence."}},
	}, nil)
	if r1.StatusCode != http.StatusOK || r1.Header.Get("X-Gateway-Cache") != "MISS" {
		t.Fatalf("Phase4 FLAT seed failed: status=%d cache=%q body=%s", r1.StatusCode, r1.Header.Get("X-Gateway-Cache"), string(b1))
	}

	ftInfo := redisExec(t, "redis-cache", cacheDedRPass, "FT.INFO", "gw_semantic_flat_idx")
	if !strings.Contains(ftInfo, "gw_semantic_flat_idx") {
		t.Fatalf("Phase4 FT.INFO missing gw_semantic_flat_idx:\n%s", ftInfo)
	}

	r2, b2, _ := chatCall(t, client, cachePod2Base, tenant.KeyTeam1, map[string]any{
		"model":      tenant.ChatAlias,
		"max_tokens": 64,
		"messages":   []map[string]any{{"role": "user", "content": "Tell me Spain's capital in a brief sentence."}},
	}, nil)
	if r2.StatusCode != http.StatusOK ||
		r2.Header.Get("X-Gateway-Cache") != "HIT" ||
		r2.Header.Get("X-Gateway-Cache-Type") != "semantic" ||
		r2.Header.Get("X-Gateway-Cost-Micros") != "0" {
		t.Fatalf("Phase4 FLAT semantic HIT failed: status=%d cache=%q type=%q sim=%q body=%s",
			r2.StatusCode, r2.Header.Get("X-Gateway-Cache"), r2.Header.Get("X-Gateway-Cache-Type"), r2.Header.Get("X-Gateway-Cache-Similarity"), string(b2))
	}
	t.Logf("Phase4 PASS: Redis 8 FLAT vector index semantic HIT on pod2 (sim=%s)", r2.Header.Get("X-Gateway-Cache-Similarity"))
}
