package openaicompat

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/goroute-ai/ai-gateway-go/internal/domain"
)

func TestDialect_StreamOptionsAndStrippedParams(t *testing.T) {
	reg := NewProfileRegistry(nil, nil)

	perplexityAdp, err := reg.CreateAdapter(domain.ProviderPerplexity)
	if err != nil {
		t.Fatalf("CreateAdapter(perplexity): %v", err)
	}
	adp := perplexityAdp.(*Adapter)
	req := &domain.CanonicalChatRequest{
		Model:           "sonar-pro",
		Messages:        []domain.CanonicalMessage{{Role: "user", Content: "hi"}},
		ReasoningEffort: "medium",
		ExtraParams:     map[string]any{"service_tier": "auto", "custom_flag": true},
	}
	b, err := adp.BuildUpstreamPayload(req, "sonar-pro", true)
	if err != nil {
		t.Fatalf("BuildUpstreamPayload: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, ok := m["stream_options"]; ok {
		t.Errorf("expected stream_options omitted for perplexity, got %v", m["stream_options"])
	}
	if _, ok := m["service_tier"]; ok {
		t.Errorf("expected service_tier stripped for perplexity")
	}
	if m["custom_flag"] != true {
		t.Errorf("expected custom_flag preserved, got %v", m["custom_flag"])
	}
}

func TestDialect_OptInDropUnsupportedParamsAndObservability(t *testing.T) {
	reg := NewProfileRegistry(nil, nil)
	dsAdp, err := reg.CreateAdapter(domain.ProviderDeepSeek)
	if err != nil {
		t.Fatalf("CreateAdapter(deepseek): %v", err)
	}
	base := dsAdp.(*Adapter)
	// Default profile preserves strict 400 rejection; opt-in copy enables parameter dropping
	optInProfile := *base.profile
	optInProfile.DropUnsupportedParams = true
	adp := NewAdapter(&optInProfile, nil)
	temp := 0.7
	topP := 0.9
	req := &domain.CanonicalChatRequest{
		Model:       "deepseek-reasoner",
		Messages:    []domain.CanonicalMessage{{Role: "user", Content: "solve"}},
		Temperature: &temp,
		TopP:        &topP,
	}
	shaped, dropped, err := adp.validator.ShapeRequest(req, "deepseek-reasoner")
	if err != nil {
		t.Fatalf("ShapeRequest failed: %v", err)
	}
	if shaped.Temperature != nil || shaped.TopP != nil {
		t.Errorf("expected temperature and top_p stripped on deepseek-reasoner")
	}
	if len(dropped) != 2 {
		t.Errorf("expected 2 dropped params, got %v", dropped)
	}
	// Original request must not be mutated
	if req.Temperature == nil || req.TopP == nil {
		t.Errorf("expected caller's request to remain unmutated")
	}
}

func TestDialect_ReasoningMappings(t *testing.T) {
	reg := NewProfileRegistry(nil, nil)
	cases := []struct {
		provider domain.ProviderType
		key      string
	}{
		{domain.ProviderOpenRouter, "reasoning"},
		{domain.ProviderDashScope, "enable_thinking"},
		{domain.ProviderDeepSeek, "thinking"},
		{domain.ProviderNvidia, "chat_template_kwargs"},
	}
	for _, tc := range cases {
		rawAdp, err := reg.CreateAdapter(tc.provider)
		if err != nil {
			t.Fatalf("CreateAdapter(%s): %v", tc.provider, err)
		}
		adp := rawAdp.(*Adapter)
		b, err := adp.BuildUpstreamPayload(&domain.CanonicalChatRequest{
			Model:           "test-model",
			Messages:        []domain.CanonicalMessage{{Role: "user", Content: "hi"}},
			ReasoningEffort: "high",
		}, "test-model", false)
		if err != nil {
			t.Fatalf("BuildUpstreamPayload(%s): %v", tc.provider, err)
		}
		var m map[string]any
		_ = json.Unmarshal(b, &m)
		if _, ok := m[tc.key]; !ok {
			t.Errorf("provider %s: expected key %q in payload %s", tc.provider, tc.key, string(b))
		}
	}
}

func TestDialect_OperationSupportSeparationAndExtendedProfiles(t *testing.T) {
	reg := NewProfileRegistry(nil, nil)

	voyageAdp, err := reg.CreateAdapter(domain.ProviderVoyage)
	if err != nil {
		t.Fatalf("CreateAdapter(voyage): %v", err)
	}
	v := voyageAdp.(*Adapter)
	if v.SupportsOperation(domain.OperationChat) {
		t.Errorf("voyage should not declare chat operation support")
	}
	if !v.SupportsOperation(domain.OperationEmbedding) {
		t.Errorf("voyage should declare embedding operation support")
	}
	if !v.SupportsOperation(domain.OperationRerank) {
		t.Errorf("voyage should declare rerank operation support when the generic rerank adapter is wired")
	}

	sarvamAdp, err := reg.CreateAdapter(domain.ProviderSarvam)
	if err != nil {
		t.Fatalf("CreateAdapter(sarvam): %v", err)
	}
	httpReq, _ := http.NewRequest(http.MethodPost, "https://api.sarvam.ai/v1/chat/completions", nil)
	if err := sarvamAdp.(*Adapter).profile.AuthStrategy.ApplyAuth(httpReq, &domain.ProviderCredential{DecryptedAPIKey: "sk-sarvam"}); err != nil {
		t.Fatalf("sarvam ApplyAuth: %v", err)
	}
	if got := httpReq.Header.Get("api-subscription-key"); got != "sk-sarvam" {
		t.Errorf("sarvam header api-subscription-key = %q, want sk-sarvam", got)
	}
}
