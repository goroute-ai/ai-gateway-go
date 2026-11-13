package load_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/logger"
	"github.com/goroute-ai/ai-gateway-go/internal/server"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
)

func setupLoadGateway(t testing.TB) (*httptest.Server, string, func()) {
	t.Helper()
	logger.Init(logger.Config{Level: "error", Format: "text"})
	ctx := context.Background()
	repo := storage.NewMemoryRepository()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		if bytes.Contains(raw, []byte(`"stream":true`)) {
			w.Header().Set("Content-Type", "text/event-stream")
			flusher, _ := w.(http.Flusher)
			for i := 0; i < 5; i++ {
				select {
				case <-r.Context().Done():
					return
				default:
					fmt.Fprint(w, "data: {\"id\":\"c1\",\"object\":\"chat.completion.chunk\",\"model\":\"gpt-4o-mini\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"ok\"}}]}\n\n")
					if flusher != nil {
						flusher.Flush()
					}
					time.Sleep(20 * time.Millisecond)
				}
			}
			fmt.Fprint(w, "data: [DONE]\n\n")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"id":"c1","object":"chat.completion","model":"gpt-4o-mini","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":5,"completion_tokens":2,"total_tokens":7}}`)
	}))

	cfg := config.Default()
	cfg.Logging.Level = "warn"
	cfg.Auth.MasterAdminKey = "sk-gw-load-admin"
	cfg.Auth.MasterEncryptionKey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	cfg.Security.Network.OutboundSSRF.AllowPrivateNetworks = true
	cfg.Security.Network.OutboundSSRF.AllowInsecureHTTP = true

	gw, err := server.New(cfg, repo, nil, nil)
	if err != nil {
		upstream.Close()
		t.Fatalf("server.New: %v", err)
	}
	workerCtx, workerCancel := context.WithCancel(ctx)
	gw.StartWorkers(workerCtx)
	ts := httptest.NewServer(gw.Handler())

	adminHeaders := map[string]string{"Authorization": "Bearer " + cfg.Auth.MasterAdminKey}
	postJSON := func(path string, body any, out any) {
		b, _ := json.Marshal(body)
		req, _ := http.NewRequest(http.MethodPost, ts.URL+path, bytes.NewReader(b))
		req.Header.Set("Content-Type", "application/json")
		for k, v := range adminHeaders {
			req.Header.Set(k, v)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("post %s: %v", path, err)
		}
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode >= 300 {
			t.Fatalf("post %s status=%d: %s", path, resp.StatusCode, string(raw))
		}
		if out != nil {
			_ = json.Unmarshal(raw, out)
		}
	}

	var org map[string]any
	postJSON("/admin/v1/organizations", map[string]any{"name": "LoadOrg", "slug": "load-org"}, &org)
	orgID := org["id"].(string)

	_ = repo.UpsertGlobalModel(ctx, &domain.GlobalModel{
		ID: "openai/gpt-4o-mini", Provider: domain.ProviderOpenAI, ModelName: "gpt-4o-mini",
		SupportsInference: true, LifecycleStatus: domain.ModelStatusActive, PricingStatus: domain.PricingStatusVerified,
		MaxOutputTokens: 4096,
	})

	var cred, grp map[string]any
	postJSON("/admin/v1/credentials", map[string]any{
		"org_id": orgID, "provider": "openai", "name": "load-c", "api_key": "sk-load", "base_url": upstream.URL,
	}, &cred)
	postJSON("/admin/v1/model-groups", map[string]any{
		"org_id": orgID, "alias": "gpt-4o-mini", "routing_strategy": "weighted_shuffle",
	}, &grp)
	postJSON("/admin/v1/deployments", map[string]any{
		"model_group_id": grp["id"], "global_model_id": "openai/gpt-4o-mini",
		"credential_id": cred["id"], "deployment_name": "load-d", "weight": 1,
	}, nil)

	var vk domain.VirtualKey
	postJSON("/admin/v1/keys", map[string]any{
		"org_id": orgID, "name": "load-key",
	}, &vk)

	cleanup := func() {
		ts.Close()
		workerCancel()
		gw.Shutdown(context.Background())
		upstream.Close()
		logger.Init(logger.Config{Level: "info", Format: "text"})
	}
	return ts, vk.RawKey, cleanup
}

// TestGateway_LoadAndSoak validates 500 RPS + 50 concurrent SSE streams with p99 overhead < 15ms.
// Set GATEWAY_RUN_SOAK=1 for full 5-minute soak or GATEWAY_RUN_SOAK=smoke for a 3-second CI smoke check.
func TestGateway_LoadAndSoak(t *testing.T) {
	mode := os.Getenv("GATEWAY_RUN_SOAK")
	if mode == "" || mode == "0" {
		t.Skip("skipping soak test (set GATEWAY_RUN_SOAK=smoke or GATEWAY_RUN_SOAK=1 to run)")
	}

	duration := 5 * time.Minute
	if mode == "smoke" {
		duration = 3 * time.Second
	}
	const targetRPS = 500
	const sseWorkers = 50

	ts, apiKey, cleanup := setupLoadGateway(t)
	defer cleanup()

	client := &http.Client{
		Transport: &http.Transport{
			MaxIdleConns:        1000,
			MaxIdleConnsPerHost: 1000,
		},
		Timeout: 10 * time.Second,
	}

	reqBody := []byte(`{"model":"gpt-4o-mini","messages":[{"role":"user","content":"ping"}]}`)
	sseBody := []byte(`{"model":"gpt-4o-mini","stream":true,"messages":[{"role":"user","content":"ping"}]}`)

	var errCount atomic.Int64
	var mu sync.Mutex
	latencies := make([]time.Duration, 0, targetRPS*3)

	ctx, cancel := context.WithTimeout(context.Background(), duration)
	defer cancel()

	var wg sync.WaitGroup
	var firstErrOnce sync.Once
	var firstErrMsg string
	recordErr := func(msg string) {
		errCount.Add(1)
		firstErrOnce.Do(func() {
			firstErrMsg = msg
		})
	}

	// 50 concurrent SSE stream workers
	for w := 0; w < sseWorkers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ctx.Err() == nil {
				req, _ := http.NewRequestWithContext(ctx, http.MethodPost, ts.URL+"/v1/chat/completions", bytes.NewReader(sseBody))
				req.Header.Set("Authorization", "Bearer "+apiKey)
				req.Header.Set("Content-Type", "application/json")
				resp, err := client.Do(req)
				if err != nil {
					if ctx.Err() == nil {
						recordErr("sse client error: " + err.Error())
					}
					continue
				}
				if resp.StatusCode != http.StatusOK {
					b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
					resp.Body.Close()
					recordErr(fmt.Sprintf("sse status=%d body=%s", resp.StatusCode, string(b)))
					continue
				}
				_, _ = io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
			}
		}()
	}

	// 500 RPS steady-state non-streaming load
	ticker := time.NewTicker(time.Second / targetRPS)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			goto done
		case <-ticker.C:
			wg.Add(1)
			go func() {
				defer wg.Done()
				start := time.Now()
				req, _ := http.NewRequestWithContext(ctx, http.MethodPost, ts.URL+"/v1/chat/completions", bytes.NewReader(reqBody))
				req.Header.Set("Authorization", "Bearer "+apiKey)
				req.Header.Set("Content-Type", "application/json")
				resp, err := client.Do(req)
				elapsed := time.Since(start)
				if err != nil {
					if ctx.Err() == nil {
						recordErr("http client error: " + err.Error())
					}
					return
				}
				if resp.StatusCode != http.StatusOK {
					b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
					resp.Body.Close()
					recordErr(fmt.Sprintf("http status=%d body=%s", resp.StatusCode, string(b)))
					return
				}
				_, _ = io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
				mu.Lock()
				latencies = append(latencies, elapsed)
				mu.Unlock()
			}()
		}
	}

done:
	wg.Wait()
	if errCount.Load() > 0 {
		t.Fatalf("load/soak test observed %d failed requests (first: %s)", errCount.Load(), firstErrMsg)
	}
	if len(latencies) == 0 {
		t.Fatal("no latency samples recorded")
	}
	sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
	p99 := latencies[int(float64(len(latencies))*0.99)]
	t.Logf("Soak (%s): samples=%d p99=%s errors=%d", mode, len(latencies), p99, errCount.Load())
	if p99 > 15*time.Millisecond {
		t.Fatalf("p99 latency %s exceeded 15ms SLO", p99)
	}
}
