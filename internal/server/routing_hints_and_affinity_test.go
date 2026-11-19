package server_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/router"
	"github.com/goroute-ai/ai-gateway-go/internal/server"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type routingTestHarness struct {
	t      *testing.T
	ctx    context.Context
	cfg    *config.Config
	repo   *storage.MemoryRepository
	redis  *storage.RedisFabric
	gw     *server.GatewayServer
	org    *domain.Organization
	rawKey string
}

func newRoutingHarness(t *testing.T, modifyCfg func(*config.Config)) *routingTestHarness {
	t.Helper()
	ctx := context.Background()
	cfg := config.Default()
	cfg.Auth.MasterAdminKey = "sk-gw-routing-admin-test-key"
	cfg.Security.Network.OutboundSSRF.AllowPrivateNetworks = true
	cfg.Security.Network.OutboundSSRF.AllowInsecureHTTP = true
	cfg.Router.BaseRetryDelay = time.Millisecond
	cfg.Router.MaxRetryDelay = 5 * time.Millisecond
	if modifyCfg != nil {
		modifyCfg(cfg)
	}

	mr := miniredis.RunT(t)
	rf := storage.NewRedisFabric(mr.Addr(), "", 0)
	t.Cleanup(func() {
		if rf.Client() != nil {
			_ = rf.Client().Close()
		}
	})

	repo := storage.NewMemoryRepository()
	gw, err := server.New(cfg, repo, rf, nil)
	require.NoError(t, err)
	gw.StartWorkers(ctx)
	t.Cleanup(func() {
		shutCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		gw.Shutdown(shutCtx)
	})

	org := &domain.Organization{
		ID:       "org-routing-" + strings.ReplaceAll(t.Name(), "/", "-"),
		Name:     "Routing Test Org",
		Slug:     "v120-org-" + strconv.FormatInt(time.Now().UnixNano(), 10),
		IsActive: true,
	}
	require.NoError(t, repo.CreateOrganization(ctx, org))
	require.NoError(t, repo.SetOrgProviderSubscription(ctx, &domain.OrgProviderSubscription{
		OrgID:     org.ID,
		Provider:  domain.ProviderOpenAI,
		IsEnabled: true,
	}))

	keyBody, _ := json.Marshal(map[string]any{
		"org_id": org.ID,
		"name":   "v120-key",
	})
	keyReq := httptest.NewRequest(http.MethodPost, "/admin/v1/keys", bytes.NewReader(keyBody))
	keyReq.Header.Set("Authorization", "Bearer "+cfg.Auth.MasterAdminKey)
	keyReq.Header.Set("Content-Type", "application/json")
	keyRec := httptest.NewRecorder()
	gw.Handler().ServeHTTP(keyRec, keyReq)
	require.Equal(t, http.StatusCreated, keyRec.Code, "issue key: %s", keyRec.Body.String())

	var issued domain.VirtualKey
	require.NoError(t, json.Unmarshal(keyRec.Body.Bytes(), &issued))
	require.NotEmpty(t, issued.RawKey)

	return &routingTestHarness{
		t:      t,
		ctx:    ctx,
		cfg:    cfg,
		repo:   repo,
		redis:  rf,
		gw:     gw,
		org:    org,
		rawKey: issued.RawKey,
	}
}

func (h *routingTestHarness) createOpenAICredential(name, baseURL string) *domain.ProviderCredential {
	h.t.Helper()
	credBody, _ := json.Marshal(map[string]any{
		"org_id":   h.org.ID,
		"provider": "openai",
		"name":     name,
		"base_url": strings.TrimRight(baseURL, "/") + "/v1",
		"api_key":  "sk-test-" + name,
	})
	req := httptest.NewRequest(http.MethodPost, "/admin/v1/credentials", bytes.NewReader(credBody))
	req.Header.Set("Authorization", "Bearer "+h.cfg.Auth.MasterAdminKey)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.gw.Handler().ServeHTTP(rec, req)
	require.Equal(h.t, http.StatusCreated, rec.Code, "create cred: %s", rec.Body.String())

	var cred domain.ProviderCredential
	require.NoError(h.t, json.Unmarshal(rec.Body.Bytes(), &cred))
	return &cred
}

func (h *routingTestHarness) registerModelAndDep(
	group *domain.ModelGroup,
	gm *domain.GlobalModel,
	cred *domain.ProviderCredential,
	dep *domain.Deployment,
) *domain.Deployment {
	h.t.Helper()
	require.NoError(h.t, h.repo.UpsertGlobalModel(h.ctx, gm))
	if existing, err := h.repo.GetModelGroupByAlias(h.ctx, h.org.ID, group.Alias); err != nil || existing == nil {
		group.OrgID = h.org.ID
		group.IsActive = true
		if group.RoutingStrategy == "" {
			group.RoutingStrategy = domain.StrategyWeightedShuffle
		}
		require.NoError(h.t, h.repo.CreateModelGroup(h.ctx, group))
	} else {
		group.ID = existing.ID
	}
	dep.ModelGroupID = group.ID
	dep.GlobalModelID = gm.ID
	dep.CredentialID = cred.ID
	dep.Status = domain.DeploymentStatusActive
	if dep.Weight <= 0 {
		dep.Weight = 100
	}
	dep.GlobalModel = gm
	dep.Credential = cred
	require.NoError(h.t, h.repo.CreateDeployment(h.ctx, dep))
	return dep
}

func (h *routingTestHarness) doRequest(method, path string, headers map[string]string, body any) *httptest.ResponseRecorder {
	h.t.Helper()
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		require.NoError(h.t, err)
		rdr = bytes.NewReader(b)
	}
	req := httptest.NewRequest(method, path, rdr)
	req.Header.Set("Authorization", "Bearer "+h.rawKey)
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.gw.Handler().ServeHTTP(rec, req)
	return rec
}

func mockOpenAIChatServer(t *testing.T, id string, calls *atomic.Int32) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls != nil {
			calls.Add(1)
		}
		var body map[string]any
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &body)
		isStream, _ := body["stream"].(bool)
		if isStream {
			w.Header().Set("Content-Type", "text/event-stream")
			flusher, _ := w.(http.Flusher)
			fmt.Fprintf(w, "data: {\"id\":\"chatcmpl-%s\",\"object\":\"chat.completion.chunk\",\"model\":\"gpt-4o-mini\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"from-%s\"}}]}\n\n", id, id)
			fmt.Fprintf(w, "data: {\"id\":\"chatcmpl-%s\",\"object\":\"chat.completion.chunk\",\"model\":\"gpt-4o-mini\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":8,\"completion_tokens\":3,\"total_tokens\":11}}\n\n", id)
			fmt.Fprint(w, "data: [DONE]\n\n")
			if flusher != nil {
				flusher.Flush()
			}
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"id":"chatcmpl-%s","object":"chat.completion","model":"gpt-4o-mini","choices":[{"index":0,"message":{"role":"assistant","content":"from-%s"},"finish_reason":"stop"}],"usage":{"prompt_tokens":8,"completion_tokens":3,"total_tokens":11}}`, id, id)
	}))
}

func TestRouting_ChatHeaderHintsAndSessionAffinity_SyncAndStream(t *testing.T) {
	h := newRoutingHarness(t, nil)

	var euCalls, usCalls, gpuCalls atomic.Int32
	srvEU := mockOpenAIChatServer(t, "eu-gpu", &euCalls)
	defer srvEU.Close()
	srvUS := mockOpenAIChatServer(t, "us-legacy", &usCalls)
	defer srvUS.Close()
	srvGPU := mockOpenAIChatServer(t, "us-gpu", &gpuCalls)
	defer srvGPU.Close()

	credEU := h.createOpenAICredential("eu", srvEU.URL)
	credUS := h.createOpenAICredential("us", srvUS.URL)
	credGPU := h.createOpenAICredential("gpu", srvGPU.URL)

	gm := &domain.GlobalModel{
		ID:                    "openai/gpt-4o-mini",
		Provider:              domain.ProviderOpenAI,
		ModelName:             "gpt-4o-mini",
		SupportsInference:     true,
		SupportsStreaming:     true,
		MaxInputTokens:        128000,
		InputCostMicrosPer1M:  150_000,
		OutputCostMicrosPer1M: 600_000,
		PricingStatus:         domain.PricingStatusVerified,
		LifecycleStatus:       domain.ModelStatusActive,
	}

	group := &domain.ModelGroup{
		Alias:           "hint-group",
		RoutingStrategy: domain.StrategyRoundRobin,
	}
	depEU := h.registerModelAndDep(group, gm, credEU, &domain.Deployment{
		DeploymentName: "dep-eu-gpu",
		Region:         "eu-west-1",
		Tags:           []string{"tier:fast", "gpu"},
	})
	_ = h.registerModelAndDep(group, gm, credUS, &domain.Deployment{
		DeploymentName: "dep-us-legacy",
		Region:         "us-east-1",
		Tags:           []string{"tier:slow", "legacy"},
	})
	depGPU := h.registerModelAndDep(group, gm, credGPU, &domain.Deployment{
		DeploymentName: "dep-us-gpu",
		Region:         "us-east-1",
		Tags:           []string{"tier:fast", "gpu"},
	})

	// 1. Sync X-Gateway-Allowed-Region + X-Gateway-Tag-* routes exclusively to depEU.
	rec := h.doRequest(http.MethodPost, "/v1/chat/completions", map[string]string{
		"X-Gateway-Allowed-Region": "eu-west-1",
		"X-Gateway-Tag-Tier":       "fast",
	}, map[string]any{
		"model":    "hint-group",
		"messages": []map[string]any{{"role": "user", "content": "hello eu"}},
	})
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Contains(t, rec.Body.String(), "from-eu-gpu")
	assert.Equal(t, "explicit_model", rec.Header().Get("X-Gateway-Route-Reason"))
	assert.Equal(t, "false", rec.Header().Get("X-Gateway-Fallback-Attempted"))
	assert.Equal(t, "0", rec.Header().Get("X-Gateway-Tier-Stepdowns"))
	assert.NotEmpty(t, rec.Header().Get("X-Gateway-Routing-Micros"))

	// 2. Stream X-Gateway-Allowed-Region + X-Gateway-Tags (&gpu,!legacy) routes to depGPU in us-east-1.
	streamRec := h.doRequest(http.MethodPost, "/v1/chat/completions", map[string]string{
		"X-Gateway-Allowed-Region": "us-east-1",
		"X-Gateway-Tags":           "&gpu, !legacy",
	}, map[string]any{
		"model":    "hint-group",
		"stream":   true,
		"messages": []map[string]any{{"role": "user", "content": "hello gpu stream"}},
	})
	require.Equal(t, http.StatusOK, streamRec.Code, streamRec.Body.String())
	assert.Contains(t, streamRec.Body.String(), "from-us-gpu")
	assert.Contains(t, streamRec.Body.String(), "data: [DONE]")
	assert.Equal(t, "explicit_model", streamRec.Header().Get("X-Gateway-Route-Reason"))
	assert.Equal(t, "false", streamRec.Header().Get("X-Gateway-Fallback-Attempted"))
	assert.Equal(t, "0", streamRec.Header().Get("X-Gateway-Tier-Stepdowns"))
	assert.NotEmpty(t, streamRec.Header().Get("X-Gateway-Routing-Micros"))

	// 3. Explicit JSON goroute_extensions fields are NOT overwritten by headers.
	noOverwriteRec := h.doRequest(http.MethodPost, "/v1/chat/completions", map[string]string{
		"X-Gateway-Allowed-Region": "us-east-1",
	}, map[string]any{
		"model":    "hint-group",
		"messages": []map[string]any{{"role": "user", "content": "json wins"}},
		"goroute_extensions": map[string]any{
			"allowed_region": "eu-west-1",
		},
	})
	require.Equal(t, http.StatusOK, noOverwriteRec.Code, noOverwriteRec.Body.String())
	assert.Contains(t, noOverwriteRec.Body.String(), "from-eu-gpu")

	// 4. X-Gateway-Preferred-Deployment-Id routes directly to the preferred deployment.
	prefRec := h.doRequest(http.MethodPost, "/v1/chat/completions", map[string]string{
		"X-Gateway-Preferred-Deployment-Id": depGPU.ID,
	}, map[string]any{
		"model":    "hint-group",
		"messages": []map[string]any{{"role": "user", "content": "prefer gpu"}},
	})
	require.Equal(t, http.StatusOK, prefRec.Code)
	assert.Contains(t, prefRec.Body.String(), "from-us-gpu")

	// 5. X-Gateway-Session-Id pins subsequent requests (despite round-robin) to the same deployment.
	firstRec := h.doRequest(http.MethodPost, "/v1/chat/completions", map[string]string{
		"X-Gateway-Session-Id": "sess-sticky-1",
	}, map[string]any{
		"model":    "hint-group",
		"messages": []map[string]any{{"role": "user", "content": "turn 1"}},
	})
	require.Equal(t, http.StatusOK, firstRec.Code)
	var firstResp domain.CanonicalChatResponse
	require.NoError(t, json.Unmarshal(firstRec.Body.Bytes(), &firstResp))
	require.NotEmpty(t, firstResp.Choices)
	pinnedContent := firstResp.Choices[0].Message.Content

	beforeEU := euCalls.Load()
	beforeUS := usCalls.Load()
	beforeGPU := gpuCalls.Load()
	for i := 0; i < 4; i++ {
		followRec := h.doRequest(http.MethodPost, "/v1/chat/completions", map[string]string{
			"X-Gateway-Session-Id": "sess-sticky-1",
		}, map[string]any{
			"model":    "hint-group",
			"messages": []map[string]any{{"role": "user", "content": "turn next"}},
		})
		require.Equal(t, http.StatusOK, followRec.Code)
		assert.Contains(t, followRec.Body.String(), pinnedContent)
	}
	assert.Equal(t, int32(4), (euCalls.Load()-beforeEU)+(usCalls.Load()-beforeUS)+(gpuCalls.Load()-beforeGPU))
	// Only the pinned deployment's call counter should have incremented by 4.
	assert.True(t,
		euCalls.Load()-beforeEU == 4 || usCalls.Load()-beforeUS == 4 || gpuCalls.Load()-beforeGPU == 4,
		"expected all 4 follow-up session requests to hit the same deployment",
	)
	_ = depEU
}

func TestRouting_OversizedPromptContextWindowFallback_ValidatorToReliability(t *testing.T) {
	t.Run("explicit_context_window_fallbacks", func(t *testing.T) {
		h := newRoutingHarness(t, nil)

		var smallCalls, largeCalls atomic.Int32
		srvSmall := mockOpenAIChatServer(t, "small-ctx", &smallCalls)
		defer srvSmall.Close()
		srvLarge := mockOpenAIChatServer(t, "large-ctx", &largeCalls)
		defer srvLarge.Close()

		credSmall := h.createOpenAICredential("small", srvSmall.URL)
		credLarge := h.createOpenAICredential("large", srvLarge.URL)

		smallGM := &domain.GlobalModel{
			ID:                "openai/small-4k",
			Provider:          domain.ProviderOpenAI,
			ModelName:         "small-4k",
			SupportsInference: true,
			SupportsStreaming: true,
			MaxInputTokens:    40,
			LifecycleStatus:   domain.ModelStatusActive,
		}
		largeGM := &domain.GlobalModel{
			ID:                "openai/large-128k",
			Provider:          domain.ProviderOpenAI,
			ModelName:         "large-128k",
			SupportsInference: true,
			SupportsStreaming: true,
			MaxInputTokens:    128000,
			LifecycleStatus:   domain.ModelStatusActive,
		}

		h.registerModelAndDep(&domain.ModelGroup{
			Alias: "small-model",
			ContextWindowFallbacks: []domain.FallbackTarget{
				{GroupAliasOrID: "large-model"},
			},
		}, smallGM, credSmall, &domain.Deployment{DeploymentName: "dep-small"})

		h.registerModelAndDep(&domain.ModelGroup{
			Alias: "large-model",
		}, largeGM, credLarge, &domain.Deployment{DeploymentName: "dep-large"})

		longPrompt := strings.Repeat("token ", 120)
		// Sync oversized prompt
		syncRec := h.doRequest(http.MethodPost, "/v1/chat/completions", nil, map[string]any{
			"model":    "small-model",
			"messages": []map[string]any{{"role": "user", "content": longPrompt}},
		})
		require.Equal(t, http.StatusOK, syncRec.Code, syncRec.Body.String())
		assert.Contains(t, syncRec.Body.String(), "from-large-ctx")
		assert.Equal(t, "true", syncRec.Header().Get("X-Gateway-Fallback-Attempted"))
		assert.Equal(t, "context_window_fallback", syncRec.Header().Get("X-Gateway-Route-Reason"))
		assert.Equal(t, "0", syncRec.Header().Get("X-Gateway-Tier-Stepdowns"))

		// Stream oversized prompt
		streamRec := h.doRequest(http.MethodPost, "/v1/chat/completions", nil, map[string]any{
			"model":    "small-model",
			"stream":   true,
			"messages": []map[string]any{{"role": "user", "content": longPrompt}},
		})
		require.Equal(t, http.StatusOK, streamRec.Code, streamRec.Body.String())
		assert.Contains(t, streamRec.Body.String(), "from-large-ctx")
		assert.Equal(t, "true", streamRec.Header().Get("X-Gateway-Fallback-Attempted"))
		assert.Equal(t, "context_window_fallback", streamRec.Header().Get("X-Gateway-Route-Reason"))

		assert.Equal(t, int32(0), smallCalls.Load(), "small-context deployment must not be called")
		assert.Equal(t, int32(2), largeCalls.Load())
	})

	t.Run("default_fallbacks_validator_handoff", func(t *testing.T) {
		h := newRoutingHarness(t, func(cfg *config.Config) {
			cfg.Router.DefaultFallbacks = []domain.FallbackTarget{
				{GroupAliasOrID: "default-large"},
			}
		})

		srvSmall := mockOpenAIChatServer(t, "tiny", nil)
		defer srvSmall.Close()
		srvLarge := mockOpenAIChatServer(t, "default-large", nil)
		defer srvLarge.Close()

		credSmall := h.createOpenAICredential("tiny", srvSmall.URL)
		credLarge := h.createOpenAICredential("default-large", srvLarge.URL)

		h.registerModelAndDep(&domain.ModelGroup{
			Alias: "tiny-no-local-fb",
		}, &domain.GlobalModel{
			ID:                "openai/tiny-32",
			Provider:          domain.ProviderOpenAI,
			ModelName:         "tiny-32",
			SupportsInference: true,
			MaxInputTokens:    32,
			LifecycleStatus:   domain.ModelStatusActive,
		}, credSmall, &domain.Deployment{DeploymentName: "dep-tiny"})

		h.registerModelAndDep(&domain.ModelGroup{
			Alias: "default-large",
		}, &domain.GlobalModel{
			ID:                "openai/default-128k",
			Provider:          domain.ProviderOpenAI,
			ModelName:         "default-128k",
			SupportsInference: true,
			MaxInputTokens:    128000,
			LifecycleStatus:   domain.ModelStatusActive,
		}, credLarge, &domain.Deployment{DeploymentName: "dep-default-large"})

		longPrompt := strings.Repeat("word ", 100)
		rec := h.doRequest(http.MethodPost, "/v1/chat/completions", nil, map[string]any{
			"model":    "tiny-no-local-fb",
			"messages": []map[string]any{{"role": "user", "content": longPrompt}},
		})
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		assert.Contains(t, rec.Body.String(), "from-default-large")
		assert.Equal(t, "true", rec.Header().Get("X-Gateway-Fallback-Attempted"))
		assert.Equal(t, "default_fallback", rec.Header().Get("X-Gateway-Route-Reason"))
	})
}

func TestRouting_PriorityTierStepdownsAndMidStreamContinuation(t *testing.T) {
	t.Run("priority_tier_stepdown_sync_and_stream", func(t *testing.T) {
		h := newRoutingHarness(t, nil)

		srvFail := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusServiceUnavailable)
			fmt.Fprint(w, `{"error":{"message":"tier 0 overloaded"}}`)
		}))
		defer srvFail.Close()

		srvBackup := mockOpenAIChatServer(t, "tier-1", nil)
		defer srvBackup.Close()

		cred0 := h.createOpenAICredential("tier0", srvFail.URL)
		cred1 := h.createOpenAICredential("tier1", srvBackup.URL)

		gm := &domain.GlobalModel{
			ID:                "openai/gpt-4o-mini",
			Provider:          domain.ProviderOpenAI,
			ModelName:         "gpt-4o-mini",
			SupportsInference: true,
			SupportsStreaming: true,
			LifecycleStatus:   domain.ModelStatusActive,
		}
		grp := &domain.ModelGroup{Alias: "tiered-group"}
		h.registerModelAndDep(grp, gm, cred0, &domain.Deployment{
			DeploymentName: "dep-p0",
			Priority:       0,
		})
		h.registerModelAndDep(grp, gm, cred1, &domain.Deployment{
			DeploymentName: "dep-p1",
			Priority:       1,
		})

		syncRec := h.doRequest(http.MethodPost, "/v1/chat/completions", nil, map[string]any{
			"model":    "tiered-group",
			"messages": []map[string]any{{"role": "user", "content": "hi"}},
		})
		require.Equal(t, http.StatusOK, syncRec.Code, syncRec.Body.String())
		assert.Contains(t, syncRec.Body.String(), "from-tier-1")
		assert.Equal(t, "1", syncRec.Header().Get("X-Gateway-Tier-Stepdowns"))
		assert.Equal(t, "priority_tier_stepdown", syncRec.Header().Get("X-Gateway-Route-Reason"))
	})

	t.Run("mid_stream_continuation_header_and_merged_sse", func(t *testing.T) {
		h := newRoutingHarness(t, func(cfg *config.Config) {
			cfg.Router.EnableMidStreamContinuation = true
			cfg.Router.MaxStreamContinuations = 1
		})

		srvDrop := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hj, ok := w.(http.Hijacker)
			require.True(t, ok)
			conn, buf, err := hj.Hijack()
			require.NoError(t, err)
			defer conn.Close()
			_, _ = buf.WriteString("HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n")
			sseBody := strings.Join([]string{
				`data: {"id":"c1","model":"gpt-4o-mini","choices":[{"index":0,"delta":{"content":"Hello "}}]}` + "\n\n",
				`data: {"id":"c2","model":"gpt-4o-mini","choices":[{"index":0,"delta":{"content":"world"}}],"usage":{"prompt_tokens":10,"completion_tokens":2,"total_tokens":12}}` + "\n\n",
			}, "")
			_, _ = fmt.Fprintf(buf, "%x\r\n%s\r\n", len(sseBody), sseBody)
			_ = buf.Flush()
		}))
		defer srvDrop.Close()

		var contSawPrefill atomic.Bool
		srvCont := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			raw, _ := io.ReadAll(r.Body)
			var payload map[string]any
			_ = json.Unmarshal(raw, &payload)
			if msgs, ok := payload["messages"].([]any); ok {
				for _, m := range msgs {
					if mm, ok := m.(map[string]any); ok && mm["role"] == "assistant" {
						if txt, _ := mm["content"].(string); strings.Contains(txt, "Hello world") {
							contSawPrefill.Store(true)
						}
					}
				}
			}
			w.Header().Set("Content-Type", "text/event-stream")
			flusher, _ := w.(http.Flusher)
			fmt.Fprint(w, "data: {\"id\":\"c3\",\"model\":\"gpt-4o-mini\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\" continued!\"}}],\"usage\":{\"prompt_tokens\":14,\"completion_tokens\":2,\"total_tokens\":16}}\n\n")
			fmt.Fprint(w, "data: [DONE]\n\n")
			if flusher != nil {
				flusher.Flush()
			}
		}))
		defer srvCont.Close()

		credA := h.createOpenAICredential("drop", srvDrop.URL)
		credB := h.createOpenAICredential("cont", srvCont.URL)
		gm := &domain.GlobalModel{
			ID:                "openai/gpt-4o-mini",
			Provider:          domain.ProviderOpenAI,
			ModelName:         "gpt-4o-mini",
			SupportsInference: true,
			SupportsStreaming: true,
			LifecycleStatus:   domain.ModelStatusActive,
		}
		grp := &domain.ModelGroup{
			Alias:           "cont-group",
			RoutingStrategy: domain.StrategyRoundRobin,
		}
		h.registerModelAndDep(grp, gm, credA, &domain.Deployment{
			DeploymentName: "dep-drop",
			Priority:       0,
		})
		h.registerModelAndDep(grp, gm, credB, &domain.Deployment{
			DeploymentName: "dep-cont",
			Priority:       1,
		})

		rec := h.doRequest(http.MethodPost, "/v1/chat/completions", nil, map[string]any{
			"model":    "cont-group",
			"stream":   true,
			"messages": []map[string]any{{"role": "user", "content": "Say hello world"}},
		})
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		body := rec.Body.String()
		assert.Contains(t, body, "Hello ")
		assert.Contains(t, body, "world")
		assert.Contains(t, body, " continued!")
		assert.Contains(t, body, "data: [DONE]")
		assert.True(t, contSawPrefill.Load(), "continuation upstream must receive prefill assistant turn")
		assert.Equal(t, "true", rec.Header().Get("X-Gateway-Stream-Continued"))
		assert.Equal(t, "0", rec.Header().Get("X-Gateway-Tier-Stepdowns"))
		assert.Equal(t, "explicit_model", rec.Header().Get("X-Gateway-Route-Reason"))
	})
}

type customTestPreRouter struct {
	name   string
	target string
	reason string
}

func (p *customTestPreRouter) Name() string { return p.name }

func (p *customTestPreRouter) Route(_ context.Context, _ string, _ *domain.CanonicalChatRequest) (string, string, float64, error) {
	return p.target, p.reason, 0.99, nil
}

func TestRouting_AddRoutingPluginAndRegisterPreRouter(t *testing.T) {
	h := newRoutingHarness(t, nil)
	require.NotNil(t, h.gw.ReliabilityManager())
	require.NotNil(t, h.gw.IntelligentRouter())

	var callsA, callsB atomic.Int32
	srvA := mockOpenAIChatServer(t, "plugin-a", &callsA)
	defer srvA.Close()
	srvB := mockOpenAIChatServer(t, "plugin-b", &callsB)
	defer srvB.Close()

	credA := h.createOpenAICredential("a", srvA.URL)
	credB := h.createOpenAICredential("b", srvB.URL)

	gm := &domain.GlobalModel{
		ID:                "openai/gpt-4o-mini",
		Provider:          domain.ProviderOpenAI,
		ModelName:         "gpt-4o-mini",
		SupportsInference: true,
		SupportsStreaming: true,
		LifecycleStatus:   domain.ModelStatusActive,
	}
	grp := &domain.ModelGroup{
		Alias:           "plugin-target",
		RoutingStrategy: domain.StrategyRoundRobin,
	}
	h.registerModelAndDep(grp, gm, credA, &domain.Deployment{DeploymentName: "dep-a"})
	h.registerModelAndDep(grp, gm, credB, &domain.Deployment{DeploymentName: "dep-b"})

	h.gw.RegisterPreRouter(&customTestPreRouter{
		name:   "custom_sdk",
		target: "plugin-target",
		reason: "custom_sdk:selected",
	})
	h.gw.IntelligentRouter().PreRouters().RegisterAlias("router/custom", "custom_sdk")

	h.gw.AddRoutingPlugin(router.RoutingPluginFunc{
		PluginName: "only-dep-b",
		Fn: func(_ context.Context, rc *router.RoutingContext) ([]*domain.Deployment, error) {
			var filtered []*domain.Deployment
			for _, d := range rc.Candidates {
				if d.DeploymentName == "dep-b" {
					filtered = append(filtered, d)
				}
			}
			return filtered, nil
		},
	})

	for i := 0; i < 3; i++ {
		rec := h.doRequest(http.MethodPost, "/v1/chat/completions", nil, map[string]any{
			"model":    "router/custom",
			"messages": []map[string]any{{"role": "user", "content": "route via custom prerouter"}},
		})
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		assert.Contains(t, rec.Body.String(), "from-plugin-b")
		assert.Equal(t, "custom_sdk:selected", rec.Header().Get("X-Gateway-Route-Reason"))
	}
	assert.Equal(t, int32(0), callsA.Load())
	assert.Equal(t, int32(3), callsB.Load())
}

func TestRouting_DeploymentBudgets_Semantic_QualityCache_Bandit_Scheduler(t *testing.T) {
	t.Run("deployment_budget_tracking_via_spend_worker", func(t *testing.T) {
		h := newRoutingHarness(t, nil)

		var cappedCalls, backupCalls atomic.Int32
		srvCapped := mockOpenAIChatServer(t, "capped", &cappedCalls)
		defer srvCapped.Close()
		srvOpen := mockOpenAIChatServer(t, "open", &backupCalls)
		defer srvOpen.Close()

		cred1 := h.createOpenAICredential("c1", srvCapped.URL)
		cred2 := h.createOpenAICredential("c2", srvOpen.URL)

		// 8 prompt + 3 completion tokens at 1_000_000 micros/1M = 11 micros per call.
		gm := &domain.GlobalModel{
			ID:                    "openai/gpt-4o-budget",
			Provider:              domain.ProviderOpenAI,
			ModelName:             "gpt-4o-budget",
			SupportsInference:     true,
			InputCostMicrosPer1M:  1_000_000,
			OutputCostMicrosPer1M: 1_000_000,
			PricingStatus:         domain.PricingStatusVerified,
			LifecycleStatus:       domain.ModelStatusActive,
		}
		grp := &domain.ModelGroup{Alias: "budget-group"}
		h.registerModelAndDep(grp, gm, cred1, &domain.Deployment{
			DeploymentName:    "dep-capped",
			Priority:          0,
			MaxBudgetMicros:   10, // Exhausted after 1st request (11 micros)
			BudgetResetPeriod: "daily",
		})
		h.registerModelAndDep(grp, gm, cred2, &domain.Deployment{
			DeploymentName: "dep-open",
			Priority:       1,
		})

		rec1 := h.doRequest(http.MethodPost, "/v1/chat/completions", nil, map[string]any{
			"model":    "budget-group",
			"messages": []map[string]any{{"role": "user", "content": "first"}},
		})
		require.Equal(t, http.StatusOK, rec1.Code, rec1.Body.String())
		assert.Contains(t, rec1.Body.String(), "from-capped")

		rec2 := h.doRequest(http.MethodPost, "/v1/chat/completions", nil, map[string]any{
			"model":    "budget-group",
			"messages": []map[string]any{{"role": "user", "content": "second"}},
		})
		require.Equal(t, http.StatusOK, rec2.Code, rec2.Body.String())
		assert.Contains(t, rec2.Body.String(), "from-open")
		assert.Equal(t, int32(1), cappedCalls.Load())
		assert.Equal(t, int32(1), backupCalls.Load())
	})

	t.Run("semantic_prerouter_warmup_and_routing", func(t *testing.T) {
		var embedCalls atomic.Int32
		embedSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			embedCalls.Add(1)
			var req map[string]any
			raw, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(raw, &req)
			var inputs []string
			switch v := req["input"].(type) {
			case string:
				inputs = []string{v}
			case []any:
				for _, item := range v {
					inputs = append(inputs, fmt.Sprintf("%v", item))
				}
			}
			data := make([]map[string]any, 0, len(inputs))
			for i, txt := range inputs {
				vec := []float64{0.0, 1.0}
				if strings.Contains(strings.ToLower(txt), "code") || strings.Contains(strings.ToLower(txt), "golang") {
					vec = []float64{1.0, 0.0}
				}
				data = append(data, map[string]any{
					"object":    "embedding",
					"index":     i,
					"embedding": vec,
				})
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"object": "list",
				"model":  "text-embedding-3-small",
				"data":   data,
				"usage":  map[string]int{"prompt_tokens": len(inputs) * 2, "total_tokens": len(inputs) * 2},
			})
		}))
		defer embedSrv.Close()

		srvCoding := mockOpenAIChatServer(t, "coding-sem", nil)
		defer srvCoding.Close()
		srvFast := mockOpenAIChatServer(t, "fast-sem", nil)
		defer srvFast.Close()

		h := newRoutingHarness(t, func(cfg *config.Config) {
			cfg.Router.PreRouterMode = router.PreRouterModeSemantic
			cfg.Router.SemanticRouter = config.SemanticRouterConfig{
				Enabled:             true,
				EmbeddingModel:      "embed-alias",
				SimilarityThreshold: 0.80,
				Timeout:             2 * time.Second,
				Routes: []config.SemanticRouteConfig{
					{
						Name:        "coding",
						TargetModel: "coding",
						Utterances:  []string{"write golang code"},
					},
				},
			}
		})

		credEmbed := h.createOpenAICredential("embed", embedSrv.URL)
		credCode := h.createOpenAICredential("code", srvCoding.URL)
		credFast := h.createOpenAICredential("fast", srvFast.URL)

		h.registerModelAndDep(&domain.ModelGroup{Alias: "embed-alias"}, &domain.GlobalModel{
			ID:                 "openai/text-embedding-3-small",
			Provider:           domain.ProviderOpenAI,
			ModelName:          "text-embedding-3-small",
			SupportsEmbeddings: true,
			LifecycleStatus:    domain.ModelStatusActive,
		}, credEmbed, &domain.Deployment{DeploymentName: "dep-embed"})

		chatGM := &domain.GlobalModel{
			ID:                "openai/gpt-4o-mini",
			Provider:          domain.ProviderOpenAI,
			ModelName:         "gpt-4o-mini",
			SupportsInference: true,
			LifecycleStatus:   domain.ModelStatusActive,
		}
		h.registerModelAndDep(&domain.ModelGroup{Alias: "coding"}, chatGM, credCode, &domain.Deployment{DeploymentName: "dep-code"})
		h.registerModelAndDep(&domain.ModelGroup{Alias: "fast"}, chatGM, credFast, &domain.Deployment{DeploymentName: "dep-fast"})

		// Trigger warmup via StartWorkers (since org & deployments were created after New).
		h.gw.StartWorkers(h.ctx)
		require.Eventually(t, func() bool {
			return embedCalls.Load() >= 1
		}, 2*time.Second, 10*time.Millisecond)

		rec := h.doRequest(http.MethodPost, "/v1/chat/completions", nil, map[string]any{
			"model":    "auto",
			"messages": []map[string]any{{"role": "user", "content": "Help me debug golang code"}},
		})
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		assert.Contains(t, rec.Body.String(), "from-coding-sem")
		assert.Equal(t, "semantic:route:coding", rec.Header().Get("X-Gateway-Route-Reason"))
	})

	t.Run("quality_cache_aware_bandit_and_scheduler", func(t *testing.T) {
		h := newRoutingHarness(t, func(cfg *config.Config) {
			cfg.Router.CacheAwareRouting = true
			cfg.Router.PromptCacheAffinity = true
			cfg.Router.Bandit = config.BanditConfig{
				Enabled:         true,
				CandidateModels: []string{"fast"},
				SyncInterval:    100 * time.Millisecond,
			}
			cfg.Router.Scheduler = config.SchedulerConfig{
				Enabled:         true,
				MaxQueueDepth:   4,
				MaxWaitTime:     2 * time.Second,
				DefaultPriority: 1,
			}
		})

		srv := mockOpenAIChatServer(t, "combo", nil)
		defer srv.Close()
		cred := h.createOpenAICredential("combo", srv.URL)
		gm := &domain.GlobalModel{
			ID:                "openai/gpt-4o-mini",
			Provider:          domain.ProviderOpenAI,
			ModelName:         "gpt-4o-mini",
			SupportsInference: true,
			LifecycleStatus:   domain.ModelStatusActive,
		}
		h.registerModelAndDep(&domain.ModelGroup{Alias: "fast"}, gm, cred, &domain.Deployment{DeploymentName: "dep-fast"})

		require.NotNil(t, h.gw.IntelligentRouter().Bandit())

		// 1. Seed exact cache on "router/quality" with temperature=0 and verify QualityPreRouter cache_hit resolution.
		zero := 0.0
		reqPayload := map[string]any{
			"model":       "router/quality",
			"temperature": zero,
			"messages":    []map[string]any{{"role": "user", "content": "Use reasoning to prove this theorem"}},
		}
		recMiss := h.doRequest(http.MethodPost, "/v1/chat/completions", map[string]string{
			"X-Gateway-Priority": "0",
		}, reqPayload)
		require.Equal(t, http.StatusOK, recMiss.Code, recMiss.Body.String())
		assert.Equal(t, "MISS", recMiss.Header().Get("X-Gateway-Cache"))

		dec, err := h.gw.IntelligentRouter().ResolveGroup(h.ctx, h.org.ID, &domain.CanonicalChatRequest{
			Model:       "router/quality",
			Temperature: &zero,
			Messages:    []domain.CanonicalMessage{{Role: "user", Content: "Use reasoning to prove this theorem"}},
		})
		require.NoError(t, err)
		assert.Equal(t, "quality:cache_hit", dec.Reason)

		// 2. Concurrent adaptive bandit requests under -race.
		var wg sync.WaitGroup
		for i := 0; i < 4; i++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				rec := h.doRequest(http.MethodPost, "/v1/chat/completions", nil, map[string]any{
					"model":    "router/adaptive",
					"messages": []map[string]any{{"role": "user", "content": fmt.Sprintf("adaptive %d", idx)}},
				})
				assert.Equal(t, http.StatusOK, rec.Code)
			}(i)
		}
		wg.Wait()
	})
}

func TestRouting_ResponsesPreviousResponseAffinityAndMessagesTelemetry(t *testing.T) {
	h := newRoutingHarness(t, nil)

	var callsA, callsB atomic.Int32
	srvA := mockOpenAIChatServer(t, "resp-a", &callsA)
	defer srvA.Close()
	srvB := mockOpenAIChatServer(t, "resp-b", &callsB)
	defer srvB.Close()

	credA := h.createOpenAICredential("a", srvA.URL)
	credB := h.createOpenAICredential("b", srvB.URL)

	gm := &domain.GlobalModel{
		ID:                "openai/gpt-4o-mini",
		Provider:          domain.ProviderOpenAI,
		ModelName:         "gpt-4o-mini",
		SupportsInference: true,
		SupportsStreaming: true,
		LifecycleStatus:   domain.ModelStatusActive,
	}
	grp := &domain.ModelGroup{
		Alias:           "resp-group",
		RoutingStrategy: domain.StrategyRoundRobin,
	}
	h.registerModelAndDep(grp, gm, credA, &domain.Deployment{
		DeploymentName: "dep-a",
		Region:         "us-east-1",
	})
	depB := h.registerModelAndDep(grp, gm, credB, &domain.Deployment{
		DeploymentName: "dep-b",
		Region:         "eu-west-1",
	})

	// 1. /v1/responses sync turn 1 pinned via X-Gateway-Preferred-Deployment-Id -> returns respID pinned in AffinityStore.
	rec1 := h.doRequest(http.MethodPost, "/v1/responses", map[string]string{
		"X-Gateway-Preferred-Deployment-Id": depB.ID,
	}, map[string]any{
		"model": "resp-group",
		"input": "Start conversation",
	})
	require.Equal(t, http.StatusOK, rec1.Code, rec1.Body.String())
	assert.Equal(t, "explicit_model", rec1.Header().Get("X-Gateway-Route-Reason"))
	assert.Equal(t, "false", rec1.Header().Get("X-Gateway-Fallback-Attempted"))
	assert.NotEmpty(t, rec1.Header().Get("X-Gateway-Routing-Micros"))

	var out1 domain.CanonicalResponseOutput
	require.NoError(t, json.Unmarshal(rec1.Body.Bytes(), &out1))
	require.NotEmpty(t, out1.ID)

	// 2. Follow-up /v1/responses calls with previous_response_id must stick to depB (despite round-robin).
	beforeA := callsA.Load()
	beforeB := callsB.Load()
	for i := 0; i < 3; i++ {
		rec2 := h.doRequest(http.MethodPost, "/v1/responses", nil, map[string]any{
			"model":                "resp-group",
			"input":                "Follow-up turn",
			"previous_response_id": out1.ID,
		})
		require.Equal(t, http.StatusOK, rec2.Code, rec2.Body.String())
		assert.Contains(t, rec2.Body.String(), "from-resp-b")
	}
	assert.Equal(t, beforeA, callsA.Load())
	assert.Equal(t, beforeB+3, callsB.Load())

	// 3. /v1/messages honors X-Gateway-Allowed-Region and emits routing telemetry headers.
	msgRec := h.doRequest(http.MethodPost, "/v1/messages", map[string]string{
		"X-Gateway-Allowed-Region": "eu-west-1",
	}, map[string]any{
		"model":      "resp-group",
		"max_tokens": 32,
		"messages":   []map[string]any{{"role": "user", "content": "Hello messages"}},
	})
	require.Equal(t, http.StatusOK, msgRec.Code, msgRec.Body.String())
	assert.Contains(t, msgRec.Body.String(), "from-resp-b")
	assert.Equal(t, "explicit_model", msgRec.Header().Get("X-Gateway-Route-Reason"))
	assert.Equal(t, "false", msgRec.Header().Get("X-Gateway-Fallback-Attempted"))
	assert.Equal(t, "0", msgRec.Header().Get("X-Gateway-Tier-Stepdowns"))
	assert.NotEmpty(t, msgRec.Header().Get("X-Gateway-Routing-Micros"))

	// 4. /v1/responses streaming emits routing telemetry headers and pins response ID.
	respStreamRec := h.doRequest(http.MethodPost, "/v1/responses", map[string]string{
		"X-Gateway-Allowed-Region": "eu-west-1",
	}, map[string]any{
		"model":  "resp-group",
		"stream": true,
		"input":  "Stream responses",
	})
	require.Equal(t, http.StatusOK, respStreamRec.Code, respStreamRec.Body.String())
	assert.Contains(t, respStreamRec.Body.String(), "from-resp-b")
	assert.Equal(t, "explicit_model", respStreamRec.Header().Get("X-Gateway-Route-Reason"))
	assert.Equal(t, "false", respStreamRec.Header().Get("X-Gateway-Fallback-Attempted"))
	assert.Equal(t, "0", respStreamRec.Header().Get("X-Gateway-Tier-Stepdowns"))
	assert.NotEmpty(t, respStreamRec.Header().Get("X-Gateway-Routing-Micros"))
}
