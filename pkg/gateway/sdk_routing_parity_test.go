package gateway_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/goroute-ai/ai-gateway-go/pkg/gateway"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSDK_RoutingHintsTelemetryAndCRUDParity(t *testing.T) {
	t.Parallel()

	t.Run("embedded router options and admin CRUD", func(t *testing.T) {
		gw, err := gateway.New(
			gateway.WithSilentLogs(),
			gateway.WithAllowPrivateNetworks(),
			gateway.WithRouterConfig(gateway.RouterOptions{
				LatencyTolerancePct:         0.25,
				MaxHonoredRetryAfter:        15 * time.Second,
				DisableCooldowns:            true,
				FallbackOnSaturation:        true,
				DropUnsupportedParams:       true,
				FallbackOnUnsupportedParams: true,
				AllowStrategyOverride:       true,
				DebugRoutingHeaders:         true,
				MaxParallelWaitMs:           120,
			}),
			gateway.WithModelList(gateway.ModelEntry{
				ModelName:             "sdk-p5",
				Model:                 "openai/gpt-4o-mini",
				APIKey:                "sk-test",
				DropUnsupportedParams: true,
				DisableCooldowns:      true,
				ITPM:                  4000,
				OTPM:                  2000,
				MaxParallelRequests:   6,
				SaturationFallbacks:   []gateway.FallbackTarget{{Target: "sdk-p5-fb"}},
			}),
		)
		require.NoError(t, err)
		defer gw.Close()

		ctx := context.Background()
		cfg, err := gw.GetConfig(ctx)
		require.NoError(t, err)
		rtr, ok := cfg["router"].(map[string]any)
		require.True(t, ok)
		assert.Equal(t, 0.25, rtr["latency_tolerance_pct"])
		assert.Equal(t, true, rtr["allow_strategy_override"])
		assert.Equal(t, true, rtr["debug_routing_headers"])
		assert.Equal(t, true, rtr["drop_unsupported_params"])

		// Create VirtualKey with MinPriorityRank and AllowedRoutingTags via pure SDK types.
		vk, err := gw.CreateVirtualKey(ctx, gateway.VirtualKeyRequest{
			Name:               "sdk-p5-key",
			MinPriorityRank:    5,
			AllowedRoutingTags: []string{"tier:*"},
		})
		require.NoError(t, err)
		assert.Equal(t, 5, vk.MinPriorityRank)
		assert.Equal(t, []string{"tier:*"}, vk.AllowedRoutingTags)

		// ModelGroup & Deployment CRUD via SDK client methods.
		groups, err := gw.ListModelGroups(ctx, "")
		require.NoError(t, err)
		var groupID string
		for _, g := range groups {
			if g.Alias == "sdk-p5" {
				groupID = g.ID
				break
			}
		}
		require.NotEmpty(t, groupID)

		mgCfg, err := gw.GetModelGroup(ctx, groupID)
		require.NoError(t, err)
		assert.Equal(t, "sdk-p5", mgCfg.Alias)
		assert.True(t, mgCfg.DropUnsupportedParams)
		assert.True(t, mgCfg.DisableCooldowns)

		newStrat := "least-busy"
		mgUpdated, err := gw.UpdateModelGroup(ctx, groupID, gateway.ModelGroupUpdateRequest{
			RoutingStrategy: &newStrat,
		})
		require.NoError(t, err)
		assert.Equal(t, "least-busy", mgUpdated.RoutingStrategy)

		deps, err := gw.ListDeployments(ctx, groupID)
		require.NoError(t, err)
		require.Len(t, deps, 1)
		depID := deps[0].ID

		depCfg, err := gw.GetDeployment(ctx, depID)
		require.NoError(t, err)
		assert.Equal(t, 6, depCfg.MaxParallelRequests)
		assert.Equal(t, 4000, depCfg.ITPMCapacity)
		assert.Equal(t, 2000, depCfg.OTPMCapacity)

		disabled := "disabled"
		patched, err := gw.PatchDeployment(ctx, depID, gateway.DeploymentPatchRequest{Status: &disabled})
		require.NoError(t, err)
		assert.Equal(t, "disabled", patched.Status)

		require.NoError(t, gw.DeleteDeployment(ctx, depID))
		require.NoError(t, gw.DeleteModelGroup(ctx, groupID))
	})

	t.Run("remote RoutingHints and ChatResult RetryCount/DroppedParams headers", func(t *testing.T) {
		var seenBody map[string]any
		mockGW := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewDecoder(r.Body).Decode(&seenBody)
			w.Header().Set("X-Gateway-Provider", "openai")
			w.Header().Set("X-Gateway-Model", "gpt-4o-mini")
			w.Header().Set("X-Gateway-Deployment-Id", "dep-p5-remote")
			w.Header().Set("X-Gateway-Retry-Count", "3")
			w.Header().Set("X-Gateway-Dropped-Params", "tools, response_format")
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"id":"c1","model":"gpt-4o-mini","provider":"openai","choices":[{"index":0,"message":{"role":"assistant","content":"ok"}}],"usage":{"prompt_tokens":2,"completion_tokens":1,"total_tokens":3}}`))
		}))
		defer mockGW.Close()

		client, err := gateway.New(gateway.WithRemote(mockGW.URL, "sk-remote"))
		require.NoError(t, err)
		defer client.Close()

		dropTrue := true
		res, err := client.ChatWithMessages(context.Background(), gateway.ChatRequest{
			Model:    "fast",
			Messages: []gateway.Message{{Role: "user", Content: "hi"}},
			RoutingHints: &gateway.RoutingHints{
				RoutingStrategy:       "latency-based",
				DropUnsupportedParams: &dropTrue,
			},
		})
		require.NoError(t, err)
		ext, ok := seenBody["goroute_extensions"].(map[string]any)
		require.True(t, ok)
		assert.Equal(t, "latency-based", ext["routing_strategy"])
		assert.Equal(t, true, ext["drop_unsupported_params"])
		assert.Equal(t, "dep-p5-remote", res.WinningDeployment)
		assert.Equal(t, 3, res.RetryCount)
		assert.Equal(t, []string{"tools", "response_format"}, res.DroppedParams)
	})

	t.Run("non-chat SDK requests and Realtime WS emit RoutingHints as goroute_extensions", func(t *testing.T) {
		var seen []map[string]any
		var seenPaths []string
		var wsRegionHeader string
		mockGW := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/v1/realtime" {
				wsRegionHeader = r.Header.Get("X-Gateway-Allowed-Region")
				w.WriteHeader(http.StatusSwitchingProtocols)
				return
			}
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			seen = append(seen, body)
			seenPaths = append(seenPaths, r.URL.Path)
			w.Header().Set("Content-Type", "application/json")
			switch r.URL.Path {
			case "/v1/embeddings":
				_, _ = w.Write([]byte(`{"object":"list","data":[{"object":"embedding","index":0,"embedding":[0.1]}],"model":"text-embedding-3-small","usage":{"prompt_tokens":1,"total_tokens":1}}`))
			case "/v1/moderations":
				_, _ = w.Write([]byte(`{"id":"mod1","model":"omni","provider":"openai","results":[{"flagged":false}]}`))
			case "/v1/responses":
				_, _ = w.Write([]byte(`{"id":"resp1","object":"response","created_at":1,"model":"gpt-4o","status":"completed","output":[]}`))
			case "/v1/images/generations":
				_, _ = w.Write([]byte(`{"created":1,"provider":"openai","model":"dall-e-3","data":[{"url":"https://example.com/1.png"}]}`))
			case "/v1/audio/speech":
				_, _ = w.Write([]byte("MP3"))
			}
		}))
		defer mockGW.Close()

		client, err := gateway.New(gateway.WithRemote(mockGW.URL, "sk-remote"))
		require.NoError(t, err)
		defer client.Close()

		hints := &gateway.RoutingHints{AllowedRegion: "eu-west-1", Tags: []string{"tier:vip"}}
		ctx := context.Background()
		_, err = client.CreateEmbedding(ctx, gateway.EmbeddingRequest{Model: "m", Input: []string{"a"}, RoutingHints: hints})
		require.NoError(t, err)
		_, err = client.CreateModeration(ctx, gateway.ModerationRequest{Model: "m", Input: []string{"hi"}, RoutingHints: hints})
		require.NoError(t, err)
		_, err = client.CreateResponse(ctx, gateway.ResponseRequest{Model: "m", Input: "hi", RoutingHints: hints})
		require.NoError(t, err)
		_, err = client.CreateImage(ctx, gateway.ImageGenerationRequest{Model: "m", Prompt: "cat", RoutingHints: hints})
		require.NoError(t, err)
		_, err = client.CreateSpeech(ctx, gateway.SpeechRequest{Model: "m", Input: "hi", Voice: "alloy", RoutingHints: hints})
		require.NoError(t, err)

		require.Len(t, seen, 5)
		for i, body := range seen {
			ext, ok := body["goroute_extensions"].(map[string]any)
			require.True(t, ok, "path=%s missing goroute_extensions", seenPaths[i])
			assert.Equal(t, "eu-west-1", ext["allowed_region"], "path=%s", seenPaths[i])
		}
		// ConnectRealtimeWithHints sends upgrade headers (even though httptest mock rejects non-WS hijack here, it inspects headers).
		_, _ = client.ConnectRealtimeWithHints(ctx, "gpt-4o-realtime", hints)
		assert.Equal(t, "eu-west-1", wsRegionHeader)
	})
}
