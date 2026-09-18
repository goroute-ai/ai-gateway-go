package catalog_test

import (
	"testing"

	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	catalog "github.com/goroute-ai/ai-gateway-go/internal/modelcatalog"
)

func TestCatalog_LoadingAndCount(t *testing.T) {
	count := catalog.Count()
	if count < 200 {
		t.Fatalf("expected at least 200 curated models in catalog, got %d", count)
	}
	allModels := catalog.All()
	if len(allModels) != count {
		t.Fatalf("catalog.Count()=%d does not match len(catalog.All())=%d", count, len(allModels))
	}
	for _, m := range allModels {
		if !catalog.IsCallableProvider(m.Provider) {
			t.Fatalf("unexpected non-callable provider %q in catalog entry %q", m.Provider, m.ID)
		}
	}
	t.Logf("Embedded catalog loaded with %d curated callable models", count)
}

func TestCatalog_IsCallableProvider(t *testing.T) {
	callableProviders := []domain.ProviderType{
		domain.ProviderOpenAI,
		domain.ProviderAnthropic,
		domain.ProviderGroq,
		domain.ProviderOpenRouter,
	}
	for _, p := range callableProviders {
		if !catalog.IsCallableProvider(p) {
			t.Errorf("expected provider %q to be callable", p)
		}
	}

	uncallableProviders := []domain.ProviderType{
		"gemini",
		"bedrock",
		"vertex",
		"cohere",
		"mistral",
		"ollama",
		"azure",
		"deepseek",
		"apiserpent",
		"duckduckgo",
	}
	for _, p := range uncallableProviders {
		if catalog.IsCallableProvider(p) {
			t.Errorf("expected provider %q to NOT be callable", p)
		}
	}
}

func TestCatalog_LookupKnownModels(t *testing.T) {
	tests := []struct {
		globalID       string
		expectProvider domain.ProviderType
		expectMinIn    int64
		expectMinOut   int64
	}{
		{
			globalID:       "openai/gpt-4o-mini",
			expectProvider: domain.ProviderOpenAI,
			expectMinIn:    100_000,
			expectMinOut:   100_000,
		},
		{
			globalID:       "anthropic/claude-haiku-4-5-20251001",
			expectProvider: domain.ProviderAnthropic,
			expectMinIn:    100_000,
			expectMinOut:   100_000,
		},
		{
			globalID:       "groq/openai/gpt-oss-20b",
			expectProvider: domain.ProviderGroq,
			expectMinIn:    10_000,
			expectMinOut:   10_000,
		},
	}

	for _, tc := range tests {
		m, ok := catalog.Lookup(tc.globalID)
		if !ok || m == nil {
			t.Errorf("model %q not found in catalog", tc.globalID)
			continue
		}
		if m.Provider != tc.expectProvider {
			t.Errorf("[%s] expected provider %q, got %q", tc.globalID, tc.expectProvider, m.Provider)
		}
		if m.InputCostMicrosPer1M < tc.expectMinIn {
			t.Errorf("[%s] expected input cost >= %d, got %d", tc.globalID, tc.expectMinIn, m.InputCostMicrosPer1M)
		}
		if m.OutputCostMicrosPer1M < tc.expectMinOut {
			t.Errorf("[%s] expected output cost >= %d, got %d", tc.globalID, tc.expectMinOut, m.OutputCostMicrosPer1M)
		}
		if m.PricingStatus != domain.PricingStatusUnknown {
			t.Errorf("[%s] expected un-audited catalog model to have PricingStatusUnknown, got %q", tc.globalID, m.PricingStatus)
		}
		if m.PricingProvenanceSource != "upstream-model-catalog-v1.1" {
			t.Errorf("[%s] expected provenance 'upstream-model-catalog-v1.1', got %q", tc.globalID, m.PricingProvenanceSource)
		}
		if m.LifecycleStatus != domain.ModelStatusActive {
			t.Errorf("[%s] expected LifecycleStatusActive for visibility, got %q", tc.globalID, m.LifecycleStatus)
		}
		caps := m.ResolveCapabilities()
		if caps.Streaming != domain.CapabilitySupported {
			t.Errorf("[%s] expected Streaming=supported, got %s", tc.globalID, caps.Streaming)
		}
	}
}

func TestCatalog_LookupProviderAliases(t *testing.T) {
	tests := []struct {
		name           string
		lookupFn       func() (*domain.GlobalModel, bool)
		expectProvider domain.ProviderType
	}{
		{
			name: "claude alias to anthropic",
			lookupFn: func() (*domain.GlobalModel, bool) {
				return catalog.LookupByProviderAndModel("claude", "claude-haiku-4-5-20251001")
			},
			expectProvider: domain.ProviderAnthropic,
		},
		{
			name: "chatgpt alias to openai",
			lookupFn: func() (*domain.GlobalModel, bool) {
				return catalog.LookupByProviderAndModel("chatgpt", "gpt-4o-mini")
			},
			expectProvider: domain.ProviderOpenAI,
		},
		{
			name: "bare model lookup fallback",
			lookupFn: func() (*domain.GlobalModel, bool) {
				return catalog.Lookup("gpt-4o")
			},
			expectProvider: domain.ProviderOpenAI,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m, ok := tc.lookupFn()
			if !ok || m == nil {
				t.Fatalf("expected model to be found in catalog for %s", tc.name)
			}
			if m.Provider != tc.expectProvider {
				t.Fatalf("expected provider %q, got %q", tc.expectProvider, m.Provider)
			}
		})
	}
}

func TestCatalog_LookupAppliesFamilyGeneralizationsOnMiss(t *testing.T) {
	m, ok := catalog.LookupByProviderAndModel(domain.ProviderOpenAI, "gpt-5.99-future")
	if !ok || m == nil {
		t.Fatal("expected an inferred model for an unknown supported GPT-5 family ID")
	}
	if m.Provider != domain.ProviderOpenAI || m.ModelName != "gpt-5.99-future" {
		t.Fatalf("unexpected inferred identity: provider=%q model=%q", m.Provider, m.ModelName)
	}
	if m.PricingStatus != domain.PricingStatusUnknown || m.InputCostMicrosPer1M != 0 || m.OutputCostMicrosPer1M != 0 {
		t.Fatalf("family inference must not invent verified pricing: %+v", m)
	}
	if m.MaxInputTokens <= 0 || m.MaxOutputTokens <= 0 || m.Capabilities.Reasoning != domain.CapabilitySupported {
		t.Fatalf("expected inferred context and reasoning capability, got %+v", m)
	}

	groqInferred, ok := catalog.LookupByProviderAndModel(domain.ProviderGroq, "llama-3.1-8b-instant")
	if !ok || groqInferred == nil || groqInferred.Provider != domain.ProviderGroq {
		t.Fatalf("expected family inference for groq llama-3.1-8b-instant, got %+v (ok=%v)", groqInferred, ok)
	}

	if _, ok := catalog.LookupByProviderAndModel("unknown-provider", "gpt-5.99-future"); ok {
		t.Fatal("family inference must not make unknown providers callable")
	}
	if _, ok := catalog.LookupByProviderAndModel("gemini", "gemini-2.5-flash"); ok {
		t.Fatal("family inference must not make pruned providers callable")
	}
}

func TestCatalog_Search(t *testing.T) {
	groqModels := catalog.Search(domain.ProviderGroq, "whisper")
	if len(groqModels) == 0 {
		t.Fatal("expected at least one groq whisper model in search results")
	}
	t.Logf("Found %d groq whisper models", len(groqModels))
}

func TestCatalog_QualityTierInference(t *testing.T) {
	catalogCases := []struct {
		id       string
		wantTier int
	}{
		{id: "openai/gpt-4o-mini", wantTier: catalog.QualityTierEconomy},
		{id: "openai/gpt-4.1-nano", wantTier: catalog.QualityTierEconomy},
		{id: "anthropic/claude-haiku-4-5-20251001", wantTier: catalog.QualityTierStandard},
		{id: "openai/gpt-4o", wantTier: catalog.QualityTierFrontier},
		{id: "openai/gpt-4.1", wantTier: catalog.QualityTierFrontier},
		{id: "openai/o3-mini", wantTier: catalog.QualityTierReasoning},
		{id: "openai/o1", wantTier: catalog.QualityTierReasoning},
	}

	for _, tc := range catalogCases {
		m, ok := catalog.Lookup(tc.id)
		if !ok || m == nil {
			t.Fatalf("expected %q to exist in catalog", tc.id)
		}
		if m.QualityTier != tc.wantTier {
			t.Errorf("%s: QualityTier = %d, want %d", tc.id, m.QualityTier, tc.wantTier)
		}
	}

	gen, ok := catalog.LookupByProviderAndModel(domain.ProviderOpenAI, "gpt-5.99-future")
	if !ok || gen == nil {
		t.Fatal("expected generalized gpt-5.99-future")
	}
	if gen.QualityTier != catalog.QualityTierReasoning {
		t.Errorf("generalized gpt-5.99-future QualityTier = %d, want %d", gen.QualityTier, catalog.QualityTierReasoning)
	}

	explicit := &domain.GlobalModel{
		ModelName:   "gpt-4o-mini",
		QualityTier: catalog.QualityTierFrontier,
	}
	if got := catalog.InferQualityTier(explicit); got != catalog.QualityTierFrontier {
		t.Errorf("explicit QualityTier overwritten: got %d, want %d", got, catalog.QualityTierFrontier)
	}
	if got := catalog.InferQualityTier(nil); got != catalog.QualityTierUnknown {
		t.Errorf("nil model QualityTier = %d, want %d", got, catalog.QualityTierUnknown)
	}
	if got := catalog.InferQualityTier(&domain.GlobalModel{ModelName: "custom-model"}); got != catalog.QualityTierStandard {
		t.Errorf("unclassified custom model QualityTier = %d, want %d", got, catalog.QualityTierStandard)
	}
}

func BenchmarkCatalog_Lookup(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m, ok := catalog.Lookup("openai/gpt-4o-mini")
		if !ok || m == nil {
			b.Fatal("model not found")
		}
	}
}
