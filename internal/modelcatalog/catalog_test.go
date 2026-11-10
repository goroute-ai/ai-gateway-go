package catalog_test

import (
	"testing"

	"github.com/goroute-ai/ai-gateway-go/internal/modelcatalog"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
)

func TestCatalog_LoadingAndCount(t *testing.T) {
	count := catalog.Count()
	if count != 4627 {
		t.Fatalf("expected exactly 4627 unique models in catalog, got %d", count)
	}
	allModels := catalog.All()
	if len(allModels) != count {
		t.Fatalf("catalog.Count()=%d does not match len(catalog.All())=%d", count, len(allModels))
	}
	t.Logf("Embedded catalog loaded with %d unique models", count)
}

func TestCatalog_IsCallableProvider(t *testing.T) {
	// Native and certified providers MUST be callable
	callableProviders := []domain.ProviderType{
		domain.ProviderOpenAI,
		domain.ProviderAnthropic,
		domain.ProviderGemini,
		domain.ProviderBedrock,
		domain.ProviderVertex,
		domain.ProviderCohere,
		domain.ProviderGroq,
		domain.ProviderDeepSeek,
		domain.ProviderTogether,
		domain.ProviderFireworks,
		domain.ProviderCerebras,
		domain.ProviderSambaNova,
		domain.ProviderXAI,
	}
	for _, p := range callableProviders {
		if !catalog.IsCallableProvider(p) {
			t.Errorf("expected provider %q to be callable", p)
		}
	}

	// Tool / non-LLM providers in upstream catalog MUST NOT be callable
	uncallableProviders := []domain.ProviderType{
		"apiserpent",
		"duckduckgo",
		"elevenlabs",
		"assemblyai",
		"aws_polly",
	}
	for _, p := range uncallableProviders {
		if catalog.IsCallableProvider(p) {
			t.Errorf("expected third-party tool %q to NOT be callable as an inference provider", p)
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
			globalID:       "deepseek/deepseek-chat",
			expectProvider: domain.ProviderType("deepseek"),
			expectMinIn:    10, // micro-USD
			expectMinOut:   10,
		},
		{
			globalID:       "cerebras/llama-3.1-70b",
			expectProvider: domain.ProviderType("cerebras"),
			expectMinIn:    100,
			expectMinOut:   100,
		},
		{
			globalID:       "openai/gpt-3.5-turbo",
			expectProvider: domain.ProviderOpenAI,
			expectMinIn:    100_000,
			expectMinOut:   100_000,
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
		if m.PricingProvenanceSource != "global-model-catalog-v1.0" {
			t.Errorf("[%s] expected provenance 'global-model-catalog-v1.0', got %q", tc.globalID, m.PricingProvenanceSource)
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
			name: "vertex_ai slashed alias",
			lookupFn: func() (*domain.GlobalModel, bool) {
				return catalog.Lookup("vertex_ai/gemini-3-pro-preview")
			},
			expectProvider: domain.ProviderVertex,
		},
		{
			name: "vertex_ai provider lookup",
			lookupFn: func() (*domain.GlobalModel, bool) {
				return catalog.LookupByProviderAndModel("vertex_ai", "gemini-3-pro-preview")
			},
			expectProvider: domain.ProviderVertex,
		},
		{
			name: "bedrock_converse provider lookup",
			lookupFn: func() (*domain.GlobalModel, bool) {
				return catalog.LookupByProviderAndModel("bedrock_converse", "anthropic.claude-3-5-sonnet-20241022-v2:0")
			},
			expectProvider: domain.ProviderBedrock,
		},
		{
			name: "together_ai provider lookup",
			lookupFn: func() (*domain.GlobalModel, bool) {
				return catalog.Lookup("together_ai/meta-llama/Llama-3.3-70B-Instruct-Turbo")
			},
			expectProvider: domain.ProviderTogether,
		},
		{
			name: "bare model lookup fallback",
			lookupFn: func() (*domain.GlobalModel, bool) {
				return catalog.Lookup("gpt-4o")
			},
			expectProvider: domain.ProviderOpenAI,
		},
		{
			name: "amazon-nova hyphenated alias to bedrock",
			lookupFn: func() (*domain.GlobalModel, bool) {
				return catalog.Lookup("amazon-nova/nova-pro-v1")
			},
			expectProvider: domain.ProviderBedrock,
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

func TestCatalog_Search(t *testing.T) {
	groqModels := catalog.Search(domain.ProviderType("groq"), "llama")
	if len(groqModels) == 0 {
		t.Fatal("expected at least one groq llama model in search results")
	}
	t.Logf("Found %d groq llama models", len(groqModels))
}

func BenchmarkCatalog_Lookup(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m, ok := catalog.Lookup("deepseek/deepseek-chat")
		if !ok || m == nil {
			b.Fatal("model not found")
		}
	}
}
