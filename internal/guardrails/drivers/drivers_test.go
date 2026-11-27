package drivers

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync"
	"testing"

	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/guardrails"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
)

func TestRegistryPreRegisteredProvidersAndConcurrentBuild(t *testing.T) {
	reg := NewRegistry(WithHTTPClient(&http.Client{}))
	expected := []string{
		DriverNameGenericHTTP,
		ProviderOpenAIModeration,
	}
	slices.Sort(expected)

	got := reg.Providers()
	if !slices.Equal(got, expected) {
		t.Fatalf("registered providers = %v, want %v", got, expected)
	}
	for _, p := range expected {
		if !reg.Has(p) {
			t.Fatalf("expected registry.Has(%q) == true", p)
		}
	}

	// Register custom provider and build concurrently under -race.
	reg.Register("custom_echo", func(cfg guardrails.DriverConfig, hc *http.Client) (guardrails.Driver, error) {
		return NewGenericHTTPDriver(cfg, hc)
	})

	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			if idx%2 == 0 {
				reg.Register("dynamic_hook", func(cfg guardrails.DriverConfig, hc *http.Client) (guardrails.Driver, error) {
					return NewGenericHTTPDriver(cfg, hc)
				})
			}
			drv, err := reg.Build(context.Background(), guardrails.DriverConfig{
				Definition: &domain.GuardrailDefinition{
					ID:       "def-http",
					Name:     "http-guard",
					Provider: DriverNameGenericHTTP,
					Config:   map[string]any{"url": "https://guardrails.example.com/evaluate"},
				},
				EffectiveConfig: map[string]any{"url": "https://guardrails.example.com/evaluate"},
			})
			if err != nil {
				t.Errorf("concurrent Build failed: %v", err)
				return
			}
			if drv.Name() != DriverNameGenericHTTP {
				t.Errorf("unexpected driver name %q", drv.Name())
			}
		}(i)
	}
	wg.Wait()
}

func TestRegistryDefaultHTTPClientBlocksLoopbackAndMetadataSSRF(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("SSRF-protected client should never reach loopback test server: %s", r.URL.String())
	}))
	defer srv.Close()

	// Default NewRegistry uses network.NewHTTPClient(nil) with strict SSRF policy.
	reg := NewRegistry()

	cases := []struct {
		name     string
		provider string
		cfg      map[string]any
		secrets  map[string]any
	}{
		{
			name:     "openai_moderation_loopback",
			provider: ProviderOpenAIModeration,
			cfg:      map[string]any{"base_url": srv.URL},
			secrets:  map[string]any{"api_key": "sk-test"},
		},
		{
			name:     "generic_http_loopback",
			provider: DriverNameGenericHTTP,
			cfg:      map[string]any{"url": srv.URL},
		},
		{
			name:     "generic_http_metadata_ip",
			provider: DriverNameGenericHTTP,
			cfg:      map[string]any{"url": "http://169.254.169.254/latest/meta-data/"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			drv, err := reg.Build(context.Background(), guardrails.DriverConfig{
				Definition: &domain.GuardrailDefinition{
					ID:       "ssrf-" + tc.name,
					Name:     tc.name,
					Provider: tc.provider,
					Config:   tc.cfg,
				},
				EffectiveConfig:  tc.cfg,
				DecryptedSecrets: tc.secrets,
			})
			if err != nil {
				t.Fatalf("Build(%s): %v", tc.name, err)
			}
			_, evalErr := drv.Evaluate(context.Background(), &domain.GuardrailEvalInput{
				Texts: []string{"hello world"},
			})
			if evalErr == nil {
				t.Fatalf("expected SSRF policy error for %s, got nil", tc.name)
			}
		})
	}
}

func TestOpenAIModerationDriver(t *testing.T) {
	var seenAuth, seenOrg, seenProj, seenPath string
	var seenBody map[string]any

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenAuth = r.Header.Get("Authorization")
		seenOrg = r.Header.Get("OpenAI-Organization")
		seenProj = r.Header.Get("OpenAI-Project")
		seenPath = r.URL.Path
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &seenBody)

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"id": "modr-123",
			"model": "omni-moderation-latest",
			"results": [{
				"flagged": false,
				"categories": {"harassment": false, "violence": false},
				"category_scores": {"harassment": 0.72, "violence": 0.10}
			}]
		}`))
	}))
	defer srv.Close()

	reg := NewRegistry(WithHTTPClient(srv.Client()))
	drv, err := reg.Build(context.Background(), guardrails.DriverConfig{
		Definition: &domain.GuardrailDefinition{
			ID:       "oa-1",
			Name:     "openai-mod",
			Provider: ProviderOpenAIModeration,
		},
		EffectiveConfig: map[string]any{
			"action":              "block",
			"base_url":            srv.URL + "/v1",
			"model":               "omni-moderation-latest",
			"organization":        "org-abc",
			"project":             "proj-xyz",
			"category_thresholds": map[string]any{"harassment": 0.65, "violence": 0.80},
		},
		DecryptedSecrets: map[string]any{
			"api_key": "secret-openai-key",
		},
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	res, err := drv.Evaluate(context.Background(), &domain.GuardrailEvalInput{
		Texts:  []string{"check this prompt"},
		Images: []domain.ImageURL{{URL: "https://example.com/img.png"}},
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if seenPath != "/v1/moderations" {
		t.Fatalf("path = %q, want /v1/moderations", seenPath)
	}
	if seenAuth != "Bearer secret-openai-key" || seenOrg != "org-abc" || seenProj != "proj-xyz" {
		t.Fatalf("unexpected headers: auth=%q org=%q proj=%q", seenAuth, seenOrg, seenProj)
	}
	items, ok := seenBody["input"].([]any)
	if !ok || len(items) != 2 {
		t.Fatalf("expected multimodal input array with 2 items, got %#v", seenBody["input"])
	}
	if res.Decision != domain.GuardrailDecisionBlock {
		t.Fatalf("decision = %q, want block", res.Decision)
	}
	if len(res.Violations) != 1 || res.Violations[0].Category != "harassment" {
		t.Fatalf("unexpected violations: %+v", res.Violations)
	}

	// Verify audit action maps to Flag.
	auditDrv, err := reg.Build(context.Background(), guardrails.DriverConfig{
		Definition: &domain.GuardrailDefinition{
			ID:       "oa-2",
			Name:     "openai-audit",
			Provider: ProviderOpenAIModeration,
		},
		EffectiveConfig: map[string]any{
			"action":    "audit",
			"base_url":  srv.URL,
			"threshold": 0.50,
		},
		DecryptedSecrets: map[string]any{"api_key": "k"},
	})
	if err != nil {
		t.Fatalf("Build audit: %v", err)
	}
	auditRes, err := auditDrv.Evaluate(context.Background(), &domain.GuardrailEvalInput{Texts: []string{"test"}})
	if err != nil {
		t.Fatalf("Evaluate audit: %v", err)
	}
	if auditRes.Decision != domain.GuardrailDecisionFlag {
		t.Fatalf("expected Flag decision, got %q", auditRes.Decision)
	}
}

func TestPipelineIntegrationWithRegistryAndFailOpen(t *testing.T) {
	// Upstream mock returning HTTP 500 to test fail-open alongside built-in PII redaction.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "upstream down", http.StatusInternalServerError)
	}))
	defer srv.Close()

	repo := storage.NewMemoryRepository()
	ctx := context.Background()
	if err := repo.CreateOrganization(ctx, &domain.Organization{ID: "org-1", Name: "Org 1"}); err != nil {
		t.Fatalf("CreateOrganization: %v", err)
	}
	if err := repo.SetGuardrailPolicy(ctx, &domain.GuardrailPolicy{
		OrgID:              "org-1",
		Mode:               domain.GuardrailModeEnforce,
		EnablePIIDetection: true,
		PIIAction:          domain.GuardrailActionRedact,
	}); err != nil {
		t.Fatalf("SetGuardrailPolicy: %v", err)
	}

	if err := repo.CreateGuardrailDefinition(ctx, &domain.GuardrailDefinition{
		ID:         "def-failopen",
		OrgID:      "org-1",
		Name:       "openai-mod-failopen",
		Provider:   ProviderOpenAIModeration,
		EventHooks: []domain.GuardrailHook{domain.GuardrailHookPreCall},
		FailOpen:   true,
		Enabled:    true,
		Config: map[string]any{
			"base_url": srv.URL,
			"api_key":  "sk-test",
		},
	}); err != nil {
		t.Fatalf("CreateGuardrailDefinition: %v", err)
	}

	reg := NewRegistry(WithHTTPClient(srv.Client()))
	pipeline := guardrails.NewPipeline(guardrails.NewEngine(repo), repo)
	pipeline.SetDriverLookup(reg.Build)

	req := &domain.CanonicalChatRequest{
		Model: "gpt-4o",
		Messages: []domain.CanonicalMessage{
			{Role: "user", Content: "Reach me at alice@example.com"},
		},
	}

	outcome, err := pipeline.EvaluatePreCall(ctx, guardrails.PipelineRequestContext{OrgID: "org-1"}, req)
	if err != nil {
		t.Fatalf("expected fail-open + built-in PII redaction to succeed, got err: %v", err)
	}
	if !outcome.Redacted || req.Messages[0].Content != "Reach me at [REDACTED_EMAIL]" {
		t.Fatalf("expected built-in PII redaction through Pipeline, got content=%q outcome=%+v", req.Messages[0].Content, outcome)
	}
}
