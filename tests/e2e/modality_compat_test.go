package e2e_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/domain"
)

func TestLiveStack_ModalityCompatAndOperationEnforcement(t *testing.T) {
	ts, _, pgRepo, _, cleanup := setupLiveGateway(t)
	defer cleanup()

	ctx := context.Background()
	h := &httpClientHelper{t: t, ts: ts}
	adminHeaders := map[string]string{"Authorization": "Bearer sk-gw-master-admin-live-e2e-key"}

	// Mock Anthropic upstream verifying document + cache_control preservation
	var anthropicGotDoc bool
	anthropicSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		bodyStr := string(raw)
		if strings.Contains(bodyStr, `"type":"document"`) && strings.Contains(bodyStr, `"ephemeral"`) {
			anthropicGotDoc = true
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"id":"msg_1","type":"message","role":"assistant","model":"claude-3-7-sonnet","content":[{"type":"text","text":"doc ok"}],"stop_reason":"end_turn","usage":{"input_tokens":12,"output_tokens":4,"cache_creation_input_tokens":10,"cache_read_input_tokens":2}}`)
	}))
	defer anthropicSrv.Close()

	// Mock OpenAI-compatible upstream (chat SSE tool-only, rerank, audio/speech)
	openaiSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/chat/completions", "/chat/completions":
			w.Header().Set("Content-Type", "text/event-stream")
			fmt.Fprint(w, "data: {\"id\":\"chatcmpl-1\",\"object\":\"chat.completion.chunk\",\"model\":\"gpt-4o-mini\",\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"call_1\",\"type\":\"function\",\"function\":{\"name\":\"lookup\",\"arguments\":\"{\\\"k\\\":\\\"v\\\"}\"}}]},\"finish_reason\":\"tool_calls\"}]}\n\n")
			fmt.Fprint(w, "data: [DONE]\n\n")
		case "/v1/rerank", "/rerank", "/v2/rerank":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"id":"rk_1","results":[{"index":0,"relevance_score":0.99}],"meta":{"billed_units":{"search_units":1}},"usage":{"total_tokens":5}}`)
		case "/v1/audio/speech", "/audio/speech":
			w.Header().Set("Content-Type", "audio/mpeg")
			_, _ = w.Write([]byte("MP3DATA"))
		default:
			http.Error(w, "unexpected path: "+r.URL.Path, http.StatusNotFound)
		}
	}))
	defer openaiSrv.Close()

	// 1. Create Org + Virtual Key with active budget
	var orgResp map[string]any
	resp, raw := h.doJSON(http.MethodPost, "/admin/v1/organizations", adminHeaders, map[string]any{
		"name": "ModalityCompatOrg",
		"slug": fmt.Sprintf("modality-compat-org-%d", time.Now().UnixNano()),
	}, &orgResp)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create org failed (%d): %s", resp.StatusCode, string(raw))
	}
	orgID := orgResp["id"].(string)

	var vk domain.VirtualKey
	resp, raw = h.doJSON(http.MethodPost, "/admin/v1/keys", adminHeaders, map[string]any{
		"org_id":            orgID,
		"name":              "budgeted-key",
		"max_budget_micros": 10_000_000,
	}, &vk)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create key failed (%d): %s", resp.StatusCode, string(raw))
	}
	apiHeaders := map[string]string{"Authorization": "Bearer " + vk.RawKey}

	// 2. Seed verified models in PostgreSQL
	models := []*domain.GlobalModel{
		{
			ID: "anthropic/claude-doc", Provider: domain.ProviderAnthropic, ModelName: "claude-3-7-sonnet",
			SupportsInference: true, LifecycleStatus: domain.ModelStatusActive, PricingStatus: domain.PricingStatusVerified,
			InputCostMicrosPer1M: 3_000_000, OutputCostMicrosPer1M: 15_000_000,
			CacheWriteCostMicrosPer1M: 3_750_000, CachedInputCostMicrosPer1M: 300_000,
			SupportedOperations: []domain.OperationType{domain.OperationChat},
		},
		{
			ID: "openai/gpt-4o-mini", Provider: domain.ProviderOpenAI, ModelName: "gpt-4o-mini",
			SupportsInference: true, LifecycleStatus: domain.ModelStatusActive, PricingStatus: domain.PricingStatusVerified,
			MaxOutputTokens: 4096, InputCostMicrosPer1M: 150_000, OutputCostMicrosPer1M: 600_000,
			SupportedOperations: []domain.OperationType{domain.OperationChat, domain.OperationResponses},
		},
		{
			ID: "cohere/rerank-v3.5", Provider: domain.ProviderCohere, ModelName: "rerank-v3.5",
			SupportsInference: true, LifecycleStatus: domain.ModelStatusActive, PricingStatus: domain.PricingStatusVerified,
			RerankCostMicrosPerSearchUnit: 2000,
			SupportedOperations:           []domain.OperationType{domain.OperationRerank},
		},
		{
			ID: "openai/tts-1", Provider: domain.ProviderOpenAI, ModelName: "tts-1",
			SupportsInference: true, LifecycleStatus: domain.ModelStatusActive, PricingStatus: domain.PricingStatusVerified,
			AudioTTSCostMicrosPer1KChars: 15000,
			SupportedOperations:          []domain.OperationType{domain.OperationAudioTTS},
		},
		{
			ID: "openai/unverified-chat", Provider: domain.ProviderOpenAI, ModelName: "unverified-chat",
			SupportsInference: true, LifecycleStatus: domain.ModelStatusActive, PricingStatus: domain.PricingStatusUnknown,
			SupportedOperations: []domain.OperationType{domain.OperationChat},
		},
	}
	for _, m := range models {
		if err := pgRepo.UpsertGlobalModel(ctx, m); err != nil {
			t.Fatalf("upsert model %s: %v", m.ID, err)
		}
	}

	// Helper to wire credential -> model group -> deployment
	wire := func(provider, baseURL, alias, globalModelID string) {
		var credResp map[string]any
		r, b := h.doJSON(http.MethodPost, "/admin/v1/credentials", adminHeaders, map[string]any{
			"org_id": orgID, "provider": provider, "name": alias + "-cred",
			"api_key": "sk-mock", "base_url": baseURL,
		}, &credResp)
		if r.StatusCode != http.StatusCreated {
			t.Fatalf("create cred %s (%d): %s", alias, r.StatusCode, string(b))
		}
		var grpResp map[string]any
		r, b = h.doJSON(http.MethodPost, "/admin/v1/model-groups", adminHeaders, map[string]any{
			"org_id": orgID, "alias": alias, "routing_strategy": "weighted_shuffle",
		}, &grpResp)
		if r.StatusCode != http.StatusCreated {
			t.Fatalf("create group %s (%d): %s", alias, r.StatusCode, string(b))
		}
		r, b = h.doJSON(http.MethodPost, "/admin/v1/deployments", adminHeaders, map[string]any{
			"model_group_id": grpResp["id"], "global_model_id": globalModelID,
			"credential_id": credResp["id"], "deployment_name": alias + "-dep", "weight": 1,
		}, nil)
		if r.StatusCode != http.StatusCreated {
			t.Fatalf("create deployment %s (%d): %s", alias, r.StatusCode, string(b))
		}
	}

	wire("anthropic", anthropicSrv.URL, "claude-doc", "anthropic/claude-doc")
	wire("openai", openaiSrv.URL, "gpt-4o-mini", "openai/gpt-4o-mini")
	wire("cohere", openaiSrv.URL, "rerank-v3.5", "cohere/rerank-v3.5")
	wire("openai", openaiSrv.URL, "tts-1", "openai/tts-1")
	wire("openai", openaiSrv.URL, "unverified-chat", "openai/unverified-chat")

	// A. /v1/messages with PDF document + cache_control
	resp, raw = h.doJSON(http.MethodPost, "/v1/messages", apiHeaders, map[string]any{
		"model":      "claude-doc",
		"max_tokens": 64,
		"messages": []any{
			map[string]any{
				"role": "user",
				"content": []any{
					map[string]any{
						"type":          "document",
						"source":        map[string]any{"type": "base64", "media_type": "application/pdf", "data": "JVBERi0="},
						"cache_control": map[string]any{"type": "ephemeral", "ttl": "5m"},
					},
				},
			},
		},
	}, nil)
	if resp.StatusCode != http.StatusOK || !anthropicGotDoc {
		t.Fatalf("expected /v1/messages 200 with document+cache_control forwarded, status=%d gotDoc=%v body=%s", resp.StatusCode, anthropicGotDoc, string(raw))
	}

	// B. /v1/responses tool-only stream + multimodal input
	resp, lines := h.doStream(http.MethodPost, "/v1/responses", apiHeaders, map[string]any{
		"model":  "gpt-4o-mini",
		"stream": true,
		"input": []any{
			map[string]any{
				"role": "user",
				"content": []any{
					map[string]any{"type": "input_text", "text": "check"},
					map[string]any{"type": "input_image", "image_url": "https://example.com/x.png"},
				},
			},
		},
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected /v1/responses 200, got %d: %s", resp.StatusCode, strings.Join(lines, "\n"))
	}
	joined := strings.Join(lines, "\n")
	if !strings.Contains(joined, `"type":"function_call"`) {
		t.Fatalf("expected function_call in /v1/responses stream:\n%s", joined)
	}
	if strings.Contains(joined, `"type":"message"`) || strings.Contains(joined, `response.output_text.done`) {
		t.Fatalf("expected no empty message item or output_text.done in tool-only stream:\n%s", joined)
	}

	// C. /v1/rerank via native cohere adapter
	var rkOut map[string]any
	resp, raw = h.doJSON(http.MethodPost, "/v1/rerank", apiHeaders, map[string]any{
		"model":     "rerank-v3.5",
		"query":     "hello",
		"documents": []string{"hello world"},
	}, &rkOut)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected /v1/rerank 200, got %d: %s", resp.StatusCode, string(raw))
	}

	// D. Operation enforcement: chat on rerank-only model must fail
	resp, raw = h.doJSON(http.MethodPost, "/v1/chat/completions", apiHeaders, map[string]any{
		"model":    "rerank-v3.5",
		"messages": []map[string]any{{"role": "user", "content": "hi"}},
	}, nil)
	if resp.StatusCode == http.StatusOK {
		t.Fatalf("expected chat on rerank-only model to fail, got 200: %s", string(raw))
	}

	// E. /v1/audio/speech with non-ASCII runes ("こんにちは")
	resp, raw = h.doJSON(http.MethodPost, "/v1/audio/speech", apiHeaders, map[string]any{
		"model": "tts-1",
		"input": "こんにちは",
		"voice": "alloy",
	}, nil)
	if resp.StatusCode != http.StatusOK || string(raw) != "MP3DATA" {
		t.Fatalf("expected /v1/audio/speech 200 MP3DATA, got %d (%q)", resp.StatusCode, string(raw))
	}

	// F. Fail-closed budget checks: unverified pricing & unsupported budgeted modality
	resp, raw = h.doJSON(http.MethodPost, "/v1/chat/completions", apiHeaders, map[string]any{
		"model":    "unverified-chat",
		"messages": []map[string]any{{"role": "user", "content": "hi"}},
	}, nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for unverified-chat with active budget, got %d: %s", resp.StatusCode, string(raw))
	}

	var errBody map[string]any
	resp, raw = h.doJSON(http.MethodPost, "/v1/moderations", apiHeaders, map[string]any{
		"model": "gpt-4o-mini",
		"input": "hello",
	}, &errBody)
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 budget_estimate_unavailable for /v1/moderations, got %d: %s", resp.StatusCode, string(raw))
	}
	if errObj, _ := errBody["error"].(map[string]any); errObj == nil || errObj["code"] != "budget_estimate_unavailable" {
		encoded, _ := json.Marshal(errBody)
		t.Fatalf("expected budget_estimate_unavailable code, got %s", string(encoded))
	}
}
