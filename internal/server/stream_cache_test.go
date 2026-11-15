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
	"sync/atomic"
	"testing"

	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/logger"
	"github.com/goroute-ai/ai-gateway-go/internal/server"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
)

func TestStreamingCacheOptInHitMissBlockedAndErrored(t *testing.T) {
	ctx := context.Background()

	var logBuf threadSafeBuffer
	logger.Init(logger.Config{Level: "info", Format: "json", Output: &logBuf})
	defer logger.Init(logger.Config{Level: "info", Format: "text", Output: io.Discard})

	var upstreamCalls atomic.Int32
	var streamMode atomic.Value
	streamMode.Store("normal")

	scannerSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload struct {
			Direction string `json:"direction"`
			Content   string `json:"content"`
		}
		_ = json.NewDecoder(r.Body).Decode(&payload)
		w.Header().Set("Content-Type", "application/json")
		if payload.Direction == "output" && strings.Contains(payload.Content, "BLOCK_THIS_STREAM") {
			_, _ = w.Write([]byte(`{"decision":"block","violations":["stream_output_blocked"]}`))
			return
		}
		_, _ = w.Write([]byte(`{"decision":"allow"}`))
	}))
	defer scannerSrv.Close()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls.Add(1)
		mode, _ := streamMode.Load().(string)
		if mode == "http_error" {
			http.Error(w, `{"error":{"message":"upstream failure"}}`, http.StatusBadGateway)
			return
		}

		w.Header().Set("Content-Type", "text/event-stream")
		isLegacyCompletion := strings.HasSuffix(r.URL.Path, "/completions") && !strings.HasSuffix(r.URL.Path, "/chat/completions")

		switch mode {
		case "blocked":
			pad := strings.Repeat("safe ", 30)
			if isLegacyCompletion {
				fmt.Fprintf(w, "data: {\"id\":\"cmpl-blk\",\"object\":\"text_completion\",\"model\":\"gpt-3.5-turbo-instruct\",\"choices\":[{\"index\":0,\"text\":%q,\"finish_reason\":\"stop\"}]}\n\n", pad+"BLOCK_THIS_STREAM")
			} else {
				fmt.Fprintf(w, "data: {\"id\":\"chatcmpl-blk\",\"object\":\"chat.completion.chunk\",\"model\":\"gpt-4o-mini\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":%q},\"finish_reason\":\"stop\"}]}\n\n", pad+"BLOCK_THIS_STREAM")
			}
			fmt.Fprint(w, "data: [DONE]\n\n")
		case "truncated_no_terminal":
			if isLegacyCompletion {
				fmt.Fprint(w, "data: {\"id\":\"cmpl-trunc\",\"object\":\"text_completion\",\"model\":\"gpt-3.5-turbo-instruct\",\"choices\":[{\"index\":0,\"text\":\"partial output without finish_reason\"}]}\n\n")
			} else {
				fmt.Fprint(w, "data: {\"id\":\"chatcmpl-trunc\",\"object\":\"chat.completion.chunk\",\"model\":\"gpt-4o-mini\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"partial output without finish_reason\"}}]}\n\n")
			}
			// Upstream closes stream without a terminal finish_reason chunk.
		default:
			if isLegacyCompletion {
				fmt.Fprint(w, "data: {\"id\":\"cmpl-ok-1\",\"object\":\"text_completion\",\"created\":1730000000,\"model\":\"gpt-3.5-turbo-instruct\",\"choices\":[{\"index\":0,\"text\":\"Cached completion mail alice@example.com\"}]}\n\n")
				fmt.Fprint(w, "data: {\"id\":\"cmpl-ok-1\",\"object\":\"text_completion\",\"created\":1730000000,\"model\":\"gpt-3.5-turbo-instruct\",\"choices\":[{\"index\":0,\"text\":\"!\",\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":6,\"completion_tokens\":5,\"total_tokens\":11}}\n\n")
				fmt.Fprint(w, "data: [DONE]\n\n")
				return
			}
			fmt.Fprint(w, "data: {\"id\":\"chatcmpl-ok-1\",\"object\":\"chat.completion.chunk\",\"created\":1730000000,\"model\":\"gpt-4o-mini\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"Cached stream mail alice@example.com\"}}]}\n\n")
			fmt.Fprint(w, "data: {\"id\":\"chatcmpl-ok-1\",\"object\":\"chat.completion.chunk\",\"created\":1730000000,\"model\":\"gpt-4o-mini\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"!\"},\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":8,\"completion_tokens\":6,\"total_tokens\":14}}\n\n")
			fmt.Fprint(w, "data: [DONE]\n\n")
		}
	}))
	defer upstream.Close()

	cfg := config.Default()
	cfg.Server.Environment = "test"
	cfg.Cache.Enabled = true
	cfg.Security.Network.OutboundSSRF.AllowPrivateNetworks = true
	cfg.Security.Network.OutboundSSRF.AllowInsecureHTTP = true
	cfg.Guardrails.Scanners = []config.GuardrailScannerConfig{
		{
			Name:      "stream-cache-scanner",
			URL:       scannerSrv.URL,
			TimeoutMs: 1000,
			FailOpen:  false,
		},
	}
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
	}

	repo := storage.NewMemoryRepository()
	if err := repo.SetGuardrailPolicy(ctx, &domain.GuardrailPolicy{
		OrgID:              "org_default",
		Mode:               domain.GuardrailModeEnforce,
		EnablePIIDetection: true,
		PIIAction:          domain.GuardrailActionRedact,
		RedactOutputPII:    true,
	}); err != nil {
		t.Fatalf("SetGuardrailPolicy: %v", err)
	}

	gw, err := server.New(cfg, repo, nil, upstream.Client())
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	defer gw.Shutdown(ctx)

	keyReq := httptest.NewRequest(http.MethodPost, "/admin/v1/keys", bytes.NewReader([]byte(`{"org_id":"org_default","name":"stream-cache-key","allowed_endpoints":["*"],"allowed_models":["*"]}`)))
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

	doStream := func(path, body, cacheControl string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+issuedKey.Key)
		req.Header.Set("Content-Type", "application/json")
		if cacheControl != "" {
			req.Header.Set("Cache-Control", cacheControl)
		}
		rec := httptest.NewRecorder()
		gw.Handler().ServeHTTP(rec, req)
		return rec
	}

	endpoints := []struct {
		name string
		path string
		body string
	}{
		{
			name: "chat_completions",
			path: "/v1/chat/completions",
			body: `{"model":"gpt-4o-mini","stream":true,"temperature":0,"messages":[{"role":"user","content":"opt-in test"}]}`,
		},
		{
			name: "legacy_completions",
			path: "/v1/completions",
			body: `{"model":"gpt-3.5-turbo-instruct","stream":true,"temperature":0,"prompt":"opt-in test"}`,
		},
		{
			name: "responses",
			path: "/v1/responses",
			body: `{"model":"gpt-4o-mini","stream":true,"temperature":0,"input":"opt-in test responses"}`,
		},
		{
			name: "anthropic_messages",
			path: "/v1/messages",
			body: `{"model":"gpt-4o-mini","stream":true,"temperature":0,"max_tokens":64,"messages":[{"role":"user","content":"opt-in test messages"}]}`,
		},
	}

	// 1. Non-opted-in requests are NEVER cached even when temperature == 0.
	for _, ep := range endpoints {
		t.Run("non_opted_in_"+ep.name, func(t *testing.T) {
			streamMode.Store("normal")
			before := upstreamCalls.Load()
			rec1 := doStream(ep.path, ep.body, "")
			rec2 := doStream(ep.path, ep.body, "")
			if rec1.Code != http.StatusOK || rec2.Code != http.StatusOK {
				t.Fatalf("%s expected 200 on both non-opted-in calls, got %d and %d", ep.name, rec1.Code, rec2.Code)
			}
			if got := rec1.Header().Get("X-Gateway-Cache"); got != "" {
				t.Fatalf("%s expected empty X-Gateway-Cache without opt-in, got %q", ep.name, got)
			}
			if got := rec2.Header().Get("X-Gateway-Cache"); got != "" {
				t.Fatalf("%s expected empty X-Gateway-Cache on second non-opted-in call, got %q", ep.name, got)
			}
			if after := upstreamCalls.Load(); after != before+2 {
				t.Fatalf("%s expected 2 upstream calls without opt-in, got %d", ep.name, after-before)
			}
			if ep.path == "/v1/chat/completions" {
				if got := rec1.Header().Get("X-Gateway-Provider"); got != "openai" {
					t.Fatalf("expected live streaming X-Gateway-Provider=openai, got %q", got)
				}
				if got := rec1.Header().Get("X-Gateway-Model"); got != "gpt-4o-mini" {
					t.Fatalf("expected live streaming X-Gateway-Model=gpt-4o-mini, got %q", got)
				}
			}
		})
	}

	// 2. Opted-in request caches sanitized chunks on MISS and replays with X-Gateway-Cache: HIT on second call.
	for _, ep := range endpoints {
		t.Run("opt_in_miss_then_hit_"+ep.name, func(t *testing.T) {
			streamMode.Store("normal")
			before := upstreamCalls.Load()

			recMiss := doStream(ep.path, ep.body, "gateway-stream-cache")
			if recMiss.Code != http.StatusOK {
				t.Fatalf("%s miss status = %d, body = %s", ep.name, recMiss.Code, recMiss.Body.String())
			}
			if got := recMiss.Header().Get("X-Gateway-Cache"); got != "MISS" {
				t.Fatalf("%s first opted-in call expected X-Gateway-Cache=MISS, got %q", ep.name, got)
			}
			if ep.path == "/v1/chat/completions" {
				if got := recMiss.Header().Get("X-Gateway-Provider"); got != "openai" {
					t.Fatalf("expected cache-miss streaming X-Gateway-Provider=openai, got %q", got)
				}
				if got := recMiss.Header().Get("X-Gateway-Model"); got != "gpt-4o-mini" {
					t.Fatalf("expected cache-miss streaming X-Gateway-Model=gpt-4o-mini, got %q", got)
				}
			}
			missBody := recMiss.Body.String()
			if strings.Contains(missBody, "alice@example.com") || !strings.Contains(missBody, "[REDACTED_EMAIL]") {
				t.Fatalf("%s expected PII redacted on miss stream, got: %s", ep.name, missBody)
			}

			logBuf.Reset()
			recHit := doStream(ep.path, ep.body, "max-age=60")
			if recHit.Code != http.StatusOK {
				t.Fatalf("%s hit status = %d, body = %s", ep.name, recHit.Code, recHit.Body.String())
			}
			if got := recHit.Header().Get("X-Gateway-Cache"); got != "HIT" {
				t.Fatalf("%s second opted-in call expected X-Gateway-Cache=HIT, got %q", ep.name, got)
			}
			if got := recHit.Header().Get("X-Gateway-Cost-Micros"); got != "0" {
				t.Fatalf("%s expected X-Gateway-Cost-Micros=0 on HIT, got %q", ep.name, got)
			}
			hitBody := recHit.Body.String()
			if strings.Contains(hitBody, "alice@example.com") || !strings.Contains(hitBody, "[REDACTED_EMAIL]") {
				t.Fatalf("%s expected sanitized chunks replayed on HIT, got: %s", ep.name, hitBody)
			}
			if after := upstreamCalls.Load(); after != before+1 {
				t.Fatalf("%s expected only 1 upstream call across miss+hit, got %d", ep.name, after-before)
			}

			// Verify logger.SetInferenceMeta recorded cache_hit=true on the replayed stream.
			foundCacheHitLog := false
			for _, line := range strings.Split(strings.TrimSpace(logBuf.String()), "\n") {
				var entry map[string]any
				if json.Unmarshal([]byte(line), &entry) == nil && entry["component"] == "http" && entry["path"] == ep.path {
					if hit, _ := entry["cache_hit"].(bool); hit {
						foundCacheHitLog = true
					}
				}
			}
			if !foundCacheHitLog {
				t.Fatalf("%s expected http access log with cache_hit=true on stream replay, logs:\n%s", ep.name, logBuf.String())
			}
		})
	}

	// 3. Blocked stream is NOT cached.
	t.Run("blocked_stream_not_cached", func(t *testing.T) {
		body := `{"model":"gpt-4o-mini","stream":true,"temperature":0,"messages":[{"role":"user","content":"blocked prompt case"}]}`
		streamMode.Store("blocked")
		before := upstreamCalls.Load()
		recBlocked := doStream("/v1/chat/completions", body, "gateway-stream-cache")
		if !strings.Contains(recBlocked.Body.String(), "guardrail_blocked") {
			t.Fatalf("expected guardrail_blocked SSE error, got: %s", recBlocked.Body.String())
		}

		// Now switch upstream back to normal; identical request must be a cache MISS, not a HIT.
		streamMode.Store("normal")
		recAfter := doStream("/v1/chat/completions", body, "gateway-stream-cache")
		if got := recAfter.Header().Get("X-Gateway-Cache"); got != "MISS" {
			t.Fatalf("expected X-Gateway-Cache=MISS after blocked stream, got %q", got)
		}
		if after := upstreamCalls.Load(); after != before+2 {
			t.Fatalf("expected blocked stream not to be cached (2 upstream calls), got %d", after-before)
		}
	})

	// 4. Errored stream and truncated stream (no terminal chunk) are NOT cached.
	t.Run("errored_and_truncated_streams_not_cached", func(t *testing.T) {
		errBody := `{"model":"gpt-4o-mini","stream":true,"temperature":0,"messages":[{"role":"user","content":"error prompt case"}]}`
		streamMode.Store("http_error")
		before := upstreamCalls.Load()
		recErr := doStream("/v1/chat/completions", errBody, "gateway-stream-cache")
		if recErr.Code == http.StatusOK {
			t.Fatalf("expected non-200 on upstream HTTP error, got 200")
		}

		// Truncated stream without terminal finish_reason chunk must also not be cached.
		streamMode.Store("truncated_no_terminal")
		recTrunc := doStream("/v1/chat/completions", errBody, "gateway-stream-cache")
		if got := recTrunc.Header().Get("X-Gateway-Cache"); got != "MISS" {
			t.Fatalf("expected X-Gateway-Cache=MISS on truncated stream, got %q", got)
		}

		// Next normal call must still be a MISS because neither errored nor truncated stream was cached.
		streamMode.Store("normal")
		recNormal := doStream("/v1/chat/completions", errBody, "gateway-stream-cache")
		if got := recNormal.Header().Get("X-Gateway-Cache"); got != "MISS" {
			t.Fatalf("expected X-Gateway-Cache=MISS after errored and truncated streams, got %q", got)
		}
		if after := upstreamCalls.Load(); after < before+3 {
			t.Fatalf("expected at least 3 upstream calls across errored+truncated+normal, got %d", after-before)
		}
	})
}
