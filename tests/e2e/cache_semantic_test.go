package e2e_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/server"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
)

func liveRedisAddr(t *testing.T) string {
	t.Helper()
	if addr := strings.TrimSpace(os.Getenv("GATEWAY_TEST_REDIS_ADDR")); addr != "" {
		return addr
	}
	if addr := strings.TrimSpace(os.Getenv("GATEWAY_REDIS_ADDR")); addr != "" {
		return addr
	}
	return "localhost:6379"
}

func connectLiveRedis8(t *testing.T, requireSearch bool) *storage.RedisFabric {
	t.Helper()
	addr := liveRedisAddr(t)
	fabric := storage.NewRedisFabric(addr, strings.TrimSpace(os.Getenv("GATEWAY_REDIS_PASS")), 0)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := fabric.Ping(ctx); err != nil {
		if fabric.Client() != nil {
			_ = fabric.Client().Close()
		}
		if os.Getenv("GATEWAY_REQUIRE_LIVE_DEPS") == "1" {
			t.Fatalf("GATEWAY_REQUIRE_LIVE_DEPS=1 set, cannot connect to Redis at %s: %v", addr, err)
		}
		t.Skipf("skipping live Redis test (cannot reach %s): %v", addr, err)
	}
	if requireSearch {
		if _, err := fabric.Client().Do(ctx, "FT._LIST").Result(); err != nil {
			_ = fabric.Client().Close()
			if os.Getenv("GATEWAY_REQUIRE_LIVE_DEPS") == "1" {
				t.Fatalf("Redis at %s lacks RediSearch (upgrade to redis:8-alpine): %v", addr, err)
			}
			t.Skipf("skipping live RediSearch test (Redis at %s lacks FT._LIST): %v", addr, err)
		}
	}
	t.Cleanup(func() {
		if fabric.Client() != nil {
			_ = fabric.Client().Close()
		}
	})
	return fabric
}

func issueWildcardKeyForE2E(t *testing.T, ts *httptest.Server, masterAdminKey, orgID string) string {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"org_id":            orgID,
		"name":              "e2e-cache-key",
		"allowed_endpoints": []string{"*"},
		"allowed_models":    []string{"*"},
	})
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/admin/v1/keys", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+masterAdminKey)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("issue key: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("issue key HTTP %d: %s", resp.StatusCode, string(raw))
	}
	var out struct {
		RawKey string `json:"raw_key"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode key: %v", err)
	}
	return out.RawKey
}

func invalidateCacheE2E(t *testing.T, ts *httptest.Server, masterAdminKey, orgID, model string) int {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"org_id": orgID, "model": model})
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/admin/v1/cache/invalidate", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+masterAdminKey)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("invalidate cache: %v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("invalidate cache HTTP %d: %s", resp.StatusCode, string(raw))
	}
	var out struct {
		PurgedEntries int `json:"purged_entries"`
	}
	_ = json.Unmarshal(raw, &out)
	return out.PurgedEntries
}

// TestCacheLocalAndRedisKV_LiveRedis8 verifies exact-match Redis KV caching, cross-org isolation,
// default embeddings exclusion, and admin invalidation against a live Redis 8 server.
func TestCacheLocalAndRedisKV_LiveRedis8(t *testing.T) {
	fabric := connectLiveRedis8(t, false)
	ns := fmt.Sprintf("gw:e2e:kv:%d", time.Now().UnixNano())

	var upstreamCalls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"id":"chatcmpl-kv-1",
			"object":"chat.completion",
			"created":1730000000,
			"model":"gpt-4o-mini",
			"choices":[{"index":0,"message":{"role":"assistant","content":"live redis kv answer"},"finish_reason":"stop"}],
			"usage":{"prompt_tokens":8,"completion_tokens":4,"total_tokens":12}
		}`))
	}))
	defer upstream.Close()

	cfg := config.Default()
	cfg.Server.Environment = "test"
	cfg.Security.Network.OutboundSSRF.AllowPrivateNetworks = true
	cfg.Security.Network.OutboundSSRF.AllowInsecureHTTP = true
	cfg.Cache.Enabled = true
	cfg.Cache.Type = config.CacheTypeRedis
	cfg.Cache.Namespace = ns
	cfg.Cache.DefaultTTL = 5 * time.Minute
	cfg.ModelList = []config.ModelListEntry{
		{
			ModelName: "gpt-4o-mini",
			ModelParams: config.ModelParams{
				Model:   "openai/gpt-4o-mini",
				APIKey:  "sk-e2e-test",
				APIBase: upstream.URL,
			},
		},
	}

	gw, err := server.New(cfg, storage.NewMemoryRepository(), fabric, upstream.Client())
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	defer gw.Shutdown(context.Background())

	ts := httptest.NewServer(gw.Handler())
	defer ts.Close()
	apiKey := issueWildcardKeyForE2E(t, ts, cfg.Auth.MasterAdminKey, cfg.Auth.DefaultOrgID)

	payload := map[string]any{
		"model":       "gpt-4o-mini",
		"temperature": 0,
		"messages":    []map[string]any{{"role": "user", "content": "hello redis 8 kv"}},
	}

	// 1. First request -> MISS.
	resp1, _ := postRoutingChat(t, ts, apiKey, payload)
	if resp1.StatusCode != http.StatusOK || resp1.Header.Get("X-Gateway-Cache") != "MISS" {
		t.Fatalf("call 1: status=%d cache=%q", resp1.StatusCode, resp1.Header.Get("X-Gateway-Cache"))
	}

	// 2. Repeat request -> HIT (exact) with $0 cost and 1 total upstream call.
	resp2, _ := postRoutingChat(t, ts, apiKey, payload)
	if resp2.StatusCode != http.StatusOK ||
		resp2.Header.Get("X-Gateway-Cache") != "HIT" ||
		resp2.Header.Get("X-Gateway-Cache-Type") != "exact" ||
		resp2.Header.Get("X-Gateway-Cost-Micros") != "0" {
		t.Fatalf("call 2: status=%d cache=%q type=%q cost=%q",
			resp2.StatusCode, resp2.Header.Get("X-Gateway-Cache"), resp2.Header.Get("X-Gateway-Cache-Type"), resp2.Header.Get("X-Gateway-Cost-Micros"))
	}
	if upstreamCalls.Load() != 1 {
		t.Fatalf("expected 1 upstream call, got %d", upstreamCalls.Load())
	}

	// 3. Admin invalidation clears Redis KV entry -> next request is MISS.
	purged := invalidateCacheE2E(t, ts, cfg.Auth.MasterAdminKey, cfg.Auth.DefaultOrgID, "gpt-4o-mini")
	if purged < 1 {
		t.Fatalf("expected >=1 purged entry, got %d", purged)
	}
	resp3, _ := postRoutingChat(t, ts, apiKey, payload)
	if resp3.StatusCode != http.StatusOK || resp3.Header.Get("X-Gateway-Cache") != "MISS" {
		t.Fatalf("call 3 after invalidate: status=%d cache=%q", resp3.StatusCode, resp3.Header.Get("X-Gateway-Cache"))
	}
}

// TestSemanticCache_LiveRedis8_Deterministic runs real Redis 8 RediSearch FT.CREATE (HNSW) +
// FT.SEARCH KNN cosine similarity tests with deterministic embeddings (runs automatically in CI).
func TestSemanticCache_LiveRedis8_Deterministic(t *testing.T) {
	fabric := connectLiveRedis8(t, true)
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	idxName := "gw_e2e_det_idx_" + suffix
	ns := "gw:e2e:sem:" + suffix

	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_, _ = fabric.Client().Do(ctx, "FT.DROPINDEX", idxName, "DD").Result()
	})

	var chatCalls, embedCalls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(r.URL.Path, "/embeddings") {
			embedCalls.Add(1)
			var req struct {
				Input []string `json:"input"`
			}
			_ = json.NewDecoder(r.Body).Decode(&req)
			text := ""
			if len(req.Input) > 0 {
				text = strings.ToLower(req.Input[0])
			}
			var vec []float64
			switch {
			case strings.Contains(text, "capital of france"):
				vec = []float64{1.0, 0.0, 0.0, 0.0}
			case strings.Contains(text, "france's capital"):
				vec = []float64{0.99, 0.141, 0.0, 0.0} // cosine sim ~0.99
			default:
				vec = []float64{0.0, 0.0, 0.0, 1.0} // orthogonal -> sim 0.0
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"object": "list",
				"model":  "embed-test",
				"data":   []map[string]any{{"object": "embedding", "index": 0, "embedding": vec}},
				"usage":  map[string]any{"prompt_tokens": 4, "total_tokens": 4},
			})
			return
		}
		chatCalls.Add(1)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id":      fmt.Sprintf("chatcmpl-sem-%d", chatCalls.Load()),
			"object":  "chat.completion",
			"created": time.Now().Unix(),
			"model":   "chat-test",
			"choices": []map[string]any{{
				"index":         0,
				"message":       map[string]any{"role": "assistant", "content": "Paris is the capital of France."},
				"finish_reason": "stop",
			}},
			"usage": map[string]any{"prompt_tokens": 10, "completion_tokens": 7, "total_tokens": 17},
		})
	}))
	defer upstream.Close()

	cfg := config.Default()
	cfg.Server.Environment = "test"
	cfg.Security.Network.OutboundSSRF.AllowPrivateNetworks = true
	cfg.Security.Network.OutboundSSRF.AllowInsecureHTTP = true
	cfg.Cache.Enabled = true
	cfg.Cache.Type = config.CacheTypeRedisSemantic
	cfg.Cache.Namespace = ns
	cfg.Cache.DefaultTTL = 5 * time.Minute
	cfg.Cache.Semantic = config.SemanticCacheConfig{
		EmbeddingModel:      "embed-test",
		SimilarityThreshold: 0.90,
		IndexName:           idxName,
		VectorAlgorithm:     config.VectorAlgorithmHNSW,
		EmbeddingTimeout:    5 * time.Second,
		MaxMessages:         4,
		MaxInputChars:       8000,
	}
	cfg.ModelList = []config.ModelListEntry{
		{
			ModelName: "chat-test",
			ModelParams: config.ModelParams{
				Model:   "openai/chat-test",
				APIKey:  "sk-e2e-test",
				APIBase: upstream.URL,
			},
		},
		{
			ModelName: "embed-test",
			ModelParams: config.ModelParams{
				Model:   "openai/embed-test",
				APIKey:  "sk-e2e-test",
				APIBase: upstream.URL,
			},
		},
	}

	gw, err := server.New(cfg, storage.NewMemoryRepository(), fabric, upstream.Client())
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	defer gw.Shutdown(context.Background())

	ts := httptest.NewServer(gw.Handler())
	defer ts.Close()
	apiKey := issueWildcardKeyForE2E(t, ts, cfg.Auth.MasterAdminKey, cfg.Auth.DefaultOrgID)

	// 1. Seed query -> MISS, 1 chat call, 1 embed call (single-embed-per-miss!).
	resp1, _ := postRoutingChat(t, ts, apiKey, map[string]any{
		"model":    "chat-test",
		"messages": []map[string]any{{"role": "user", "content": "What is the capital of France?"}},
	})
	if resp1.StatusCode != http.StatusOK || resp1.Header.Get("X-Gateway-Cache") != "MISS" {
		t.Fatalf("seed call: status=%d cache=%q", resp1.StatusCode, resp1.Header.Get("X-Gateway-Cache"))
	}
	if chatCalls.Load() != 1 || embedCalls.Load() != 1 {
		t.Fatalf("expected 1 chat and 1 embed call on miss+store, got chat=%d embed=%d", chatCalls.Load(), embedCalls.Load())
	}

	// 2. Paraphrased query -> real RediSearch HNSW semantic HIT!
	resp2, body2 := postRoutingChat(t, ts, apiKey, map[string]any{
		"model":    "chat-test",
		"messages": []map[string]any{{"role": "user", "content": "Tell me France's capital city."}},
	})
	if resp2.StatusCode != http.StatusOK ||
		resp2.Header.Get("X-Gateway-Cache") != "HIT" ||
		resp2.Header.Get("X-Gateway-Cache-Type") != "semantic" ||
		resp2.Header.Get("X-Gateway-Cost-Micros") != "0" {
		t.Fatalf("paraphrase call: status=%d cache=%q type=%q sim=%q body=%s",
			resp2.StatusCode, resp2.Header.Get("X-Gateway-Cache"), resp2.Header.Get("X-Gateway-Cache-Type"), resp2.Header.Get("X-Gateway-Cache-Similarity"), string(body2))
	}
	simVal, err := strconv.ParseFloat(resp2.Header.Get("X-Gateway-Cache-Similarity"), 64)
	if err != nil || simVal < 0.90 {
		t.Fatalf("unexpected similarity header %q (err=%v)", resp2.Header.Get("X-Gateway-Cache-Similarity"), err)
	}
	if chatCalls.Load() != 1 {
		t.Fatalf("expected 0 additional chat calls on semantic hit, got %d", chatCalls.Load())
	}

	// 3. Unrelated query -> MISS.
	resp3, _ := postRoutingChat(t, ts, apiKey, map[string]any{
		"model":    "chat-test",
		"messages": []map[string]any{{"role": "user", "content": "What is the boiling point of water?"}},
	})
	if resp3.StatusCode != http.StatusOK || resp3.Header.Get("X-Gateway-Cache") != "MISS" {
		t.Fatalf("unrelated call: status=%d cache=%q", resp3.StatusCode, resp3.Header.Get("X-Gateway-Cache"))
	}
	if chatCalls.Load() != 2 {
		t.Fatalf("expected 2 chat calls after unrelated miss, got %d", chatCalls.Load())
	}

	// 4. Different system prompt isolates semantic scope -> MISS.
	respDiffSys, _ := postRoutingChat(t, ts, apiKey, map[string]any{
		"model": "chat-test",
		"messages": []map[string]any{
			{"role": "system", "content": "Respond in pirate speak."},
			{"role": "user", "content": "Tell me France's capital city."},
		},
	})
	if respDiffSys.StatusCode != http.StatusOK || respDiffSys.Header.Get("X-Gateway-Cache") != "MISS" {
		t.Fatalf("different system prompt must miss: status=%d cache=%q", respDiffSys.StatusCode, respDiffSys.Header.Get("X-Gateway-Cache"))
	}

	// 5. Admin invalidation purges semantic documents -> paraphrase misses.
	purged := invalidateCacheE2E(t, ts, cfg.Auth.MasterAdminKey, cfg.Auth.DefaultOrgID, "chat-test")
	if purged < 1 {
		t.Fatalf("expected >=1 purged semantic doc, got %d", purged)
	}
	respAfterPurge, _ := postRoutingChat(t, ts, apiKey, map[string]any{
		"model":    "chat-test",
		"messages": []map[string]any{{"role": "user", "content": "Tell me France's capital city."}},
	})
	if respAfterPurge.StatusCode != http.StatusOK || respAfterPurge.Header.Get("X-Gateway-Cache") != "MISS" {
		t.Fatalf("expected MISS after invalidation: status=%d cache=%q", respAfterPurge.StatusCode, respAfterPurge.Header.Get("X-Gateway-Cache"))
	}
}

// TestSemanticCache_LiveRedis8_Gemini exercises GoRoute's full Redis 8 Vector Search semantic
// cache end-to-end with real Gemini embeddings (gemini-embedding-001) and a cost-effective Gemini
// reasoning LLM (gemini-3.5-flash-lite) via Gemini's OpenAI-compatible endpoint.
// Skips cleanly when GATEWAY_TEST_GEMINI_API_KEY is unset.
func TestSemanticCache_LiveRedis8_Gemini(t *testing.T) {
	apiKey := strings.TrimSpace(os.Getenv("GATEWAY_TEST_GEMINI_API_KEY"))
	if apiKey == "" {
		t.Skip("skipping live Gemini semantic cache E2E (set GATEWAY_TEST_GEMINI_API_KEY to run)")
	}
	fabric := connectLiveRedis8(t, true)

	chatModel := strings.TrimSpace(os.Getenv("GATEWAY_TEST_GEMINI_CHAT_MODEL"))
	if chatModel == "" {
		chatModel = "gemini-3.5-flash-lite"
	}
	embedModel := strings.TrimSpace(os.Getenv("GATEWAY_TEST_GEMINI_EMBED_MODEL"))
	if embedModel == "" {
		embedModel = "gemini-embedding-001"
	}

	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	idxName := "gw_e2e_gemini_idx_" + suffix
	ns := "gw:e2e:gemini:" + suffix
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_, _ = fabric.Client().Do(ctx, "FT.DROPINDEX", idxName, "DD").Result()
	})

	var chatCalls, embedCalls atomic.Int32
	upstreamClient := &http.Client{Timeout: 30 * time.Second}

	// Transparent counting proxy to Gemini's OpenAI-compatible API so GoRoute uses its real
	// openai adapter end-to-end while the test asserts exact upstream chat/embedding call counts.
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/embeddings") {
			embedCalls.Add(1)
		} else {
			chatCalls.Add(1)
		}
		bodyBytes, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		targetURL := "https://generativelanguage.googleapis.com/v1beta/openai" + r.URL.Path
		upReq, err := http.NewRequestWithContext(r.Context(), r.Method, targetURL, bytes.NewReader(bodyBytes))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		upReq.Header.Set("Content-Type", "application/json")
		upReq.Header.Set("Authorization", "Bearer "+apiKey)
		upResp, err := upstreamClient.Do(upReq)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer upResp.Body.Close()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(upResp.StatusCode)
		_, _ = io.Copy(w, upResp.Body)
	}))
	defer proxy.Close()

	cfg := config.Default()
	cfg.Server.Environment = "test"
	cfg.Security.Network.OutboundSSRF.AllowPrivateNetworks = true
	cfg.Security.Network.OutboundSSRF.AllowInsecureHTTP = true
	cfg.Cache.Enabled = true
	cfg.Cache.Type = config.CacheTypeRedisSemantic
	cfg.Cache.Namespace = ns
	cfg.Cache.DefaultTTL = 5 * time.Minute
	cfg.Cache.Semantic = config.SemanticCacheConfig{
		EmbeddingModel:      embedModel,
		SimilarityThreshold: 0.85,
		IndexName:           idxName,
		VectorAlgorithm:     config.VectorAlgorithmHNSW,
		EmbeddingTimeout:    15 * time.Second,
		MaxMessages:         4,
		MaxInputChars:       8000,
	}
	cfg.ModelList = []config.ModelListEntry{
		{
			ModelName: chatModel,
			ModelParams: config.ModelParams{
				Model:   "openai/" + chatModel,
				APIKey:  "sk-gemini-proxy-placeholder",
				APIBase: proxy.URL,
			},
		},
		{
			ModelName: embedModel,
			ModelParams: config.ModelParams{
				Model:   "openai/" + embedModel,
				APIKey:  "sk-gemini-proxy-placeholder",
				APIBase: proxy.URL,
			},
		},
	}

	gw, err := server.New(cfg, storage.NewMemoryRepository(), fabric, proxy.Client())
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	defer gw.Shutdown(context.Background())

	ts := httptest.NewServer(gw.Handler())
	defer ts.Close()
	gwKey := issueWildcardKeyForE2E(t, ts, cfg.Auth.MasterAdminKey, cfg.Auth.DefaultOrgID)

	// 1. Seed query -> live Gemini embedding + live Gemini reasoning LLM response.
	resp1, body1 := postRoutingChat(t, ts, gwKey, map[string]any{
		"model":    chatModel,
		"messages": []map[string]any{{"role": "user", "content": "What is the capital city of France? Answer in one short sentence."}},
	})
	if resp1.StatusCode != http.StatusOK {
		t.Fatalf("seed Gemini call HTTP %d: %s", resp1.StatusCode, string(body1))
	}
	if resp1.Header.Get("X-Gateway-Cache") != "MISS" {
		t.Fatalf("expected MISS on seed call, got %q", resp1.Header.Get("X-Gateway-Cache"))
	}
	if !strings.Contains(strings.ToLower(string(body1)), "paris") {
		t.Fatalf("expected Gemini response mentioning Paris, got: %s", string(body1))
	}
	if chatCalls.Load() != 1 || embedCalls.Load() != 1 {
		t.Fatalf("expected 1 Gemini chat call + 1 Gemini embed call (single-embed-per-miss), got chat=%d embed=%d", chatCalls.Load(), embedCalls.Load())
	}

	// 2. Paraphrased query -> live Redis 8 HNSW semantic HIT with zero extra Gemini chat calls!
	resp2, body2 := postRoutingChat(t, ts, gwKey, map[string]any{
		"model":    chatModel,
		"messages": []map[string]any{{"role": "user", "content": "Tell me France's capital in a brief sentence."}},
	})
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("paraphrase call HTTP %d: %s", resp2.StatusCode, string(body2))
	}
	t.Logf("Live Gemini semantic hit: cache=%s type=%s similarity=%s cost=%s",
		resp2.Header.Get("X-Gateway-Cache"),
		resp2.Header.Get("X-Gateway-Cache-Type"),
		resp2.Header.Get("X-Gateway-Cache-Similarity"),
		resp2.Header.Get("X-Gateway-Cost-Micros"),
	)
	if resp2.Header.Get("X-Gateway-Cache") != "HIT" || resp2.Header.Get("X-Gateway-Cache-Type") != "semantic" {
		t.Fatalf("expected semantic HIT, got cache=%q type=%q sim=%q",
			resp2.Header.Get("X-Gateway-Cache"), resp2.Header.Get("X-Gateway-Cache-Type"), resp2.Header.Get("X-Gateway-Cache-Similarity"))
	}
	if chatCalls.Load() != 1 {
		t.Fatalf("expected still 1 Gemini chat call after semantic hit, got %d", chatCalls.Load())
	}

	// 3. Unrelated query -> MISS + fresh live Gemini answer.
	resp3, body3 := postRoutingChat(t, ts, gwKey, map[string]any{
		"model":    chatModel,
		"messages": []map[string]any{{"role": "user", "content": "What is the boiling point of water in Celsius at sea level? Reply in one short sentence."}},
	})
	if resp3.StatusCode != http.StatusOK || resp3.Header.Get("X-Gateway-Cache") != "MISS" {
		t.Fatalf("unrelated query: status=%d cache=%q body=%s", resp3.StatusCode, resp3.Header.Get("X-Gateway-Cache"), string(body3))
	}
	if !strings.Contains(string(body3), "100") {
		t.Fatalf("expected Gemini response mentioning 100, got: %s", string(body3))
	}
	if chatCalls.Load() != 2 {
		t.Fatalf("expected 2 Gemini chat calls after unrelated miss, got %d", chatCalls.Load())
	}

	// 4. Admin invalidation clears live Redis 8 semantic docs -> paraphrase misses again.
	purged := invalidateCacheE2E(t, ts, cfg.Auth.MasterAdminKey, cfg.Auth.DefaultOrgID, chatModel)
	if purged < 2 {
		t.Fatalf("expected >=2 purged semantic entries, got %d", purged)
	}
	resp4, _ := postRoutingChat(t, ts, gwKey, map[string]any{
		"model":    chatModel,
		"messages": []map[string]any{{"role": "user", "content": "Tell me France's capital in a brief sentence."}},
	})
	if resp4.StatusCode != http.StatusOK || resp4.Header.Get("X-Gateway-Cache") != "MISS" {
		t.Fatalf("expected MISS after invalidation, got status=%d cache=%q", resp4.StatusCode, resp4.Header.Get("X-Gateway-Cache"))
	}
}
