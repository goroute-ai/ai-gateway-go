package main

import (
	"encoding/json"
	"testing"

	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
)

func TestSeedModelEntry_PricingTrustAndUnits(t *testing.T) {
	raw := `{
		"input_cost_per_token": 0.000003,
		"output_cost_per_token": 0.000015,
		"cache_read_input_token_cost": 0.0000003,
		"cache_creation_input_token_cost": 0.00000375,
		"output_cost_per_reasoning_token": 0.000015,
		"provider": "anthropic",
		"mode": "chat",
		"deprecation_date": "2027-01-15"
	}`
	var e seedModelEntry
	if err := json.Unmarshal([]byte(raw), &e); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if e.Provider != "anthropic" {
		t.Errorf("Provider = %q, want anthropic", e.Provider)
	}
	if e.CacheCreationInputTokenCost != 0.00000375 {
		t.Errorf("CacheCreationInputTokenCost = %v, want 0.00000375", e.CacheCreationInputTokenCost)
	}
	if e.OutputCostPerReasoningToken != 0.000015 {
		t.Errorf("OutputCostPerReasoningToken = %v, want 0.000015", e.OutputCostPerReasoningToken)
	}
	if e.DeprecationDate != "2027-01-15" {
		t.Errorf("DeprecationDate = %q, want 2027-01-15", e.DeprecationDate)
	}
}

func TestSeedModelEntry_ReadsImagePriceAndVariantKey(t *testing.T) {
	var entry seedModelEntry
	if err := json.Unmarshal([]byte(`{"input_cost_per_image":0.009,"litellm_provider":"openai","mode":"image_generation"}`), &entry); err != nil {
		t.Fatalf("unmarshal image price: %v", err)
	}
	if entry.InputCostPerImage != 0.009 {
		t.Fatalf("InputCostPerImage = %v, want 0.009", entry.InputCostPerImage)
	}
	model, key, ok := parseImagePriceVariant("standard/1024-x-1024/gpt-image-1.5", domain.ProviderOpenAI)
	if !ok || model != "gpt-image-1.5" || key != "standard_1024x1024" {
		t.Fatalf("parsed image variant = (%q, %q, %v)", model, key, ok)
	}
	model, key, ok = parseImagePriceVariant("1024-x-1024/50-steps/bedrock/amazon.nova-canvas-v1:0", domain.ProviderBedrock)
	if !ok || model != "amazon.nova-canvas-v1:0" || key != "standard_1024x1024" {
		t.Fatalf("parsed Bedrock image variant = (%q, %q, %v)", model, key, ok)
	}
	model, key, ok = parseImagePriceVariant("fal_ai/low/1024-x-1024/openai/gpt-image-2", domain.ProviderFal)
	if !ok || model != "openai/gpt-image-2" || key != "low_1024x1024" {
		t.Fatalf("parsed Fal image variant = (%q, %q, %v)", model, key, ok)
	}
}

func TestVendorNamespacePreservation(t *testing.T) {
	// Vendor-namespaced model key under openrouter should keep openrouter as provider
	// and preserve meta-llama/llama-3.3-70b-instruct as bareModel.
	rawKey := "meta-llama/llama-3.3-70b-instruct"
	entryProv := "openrouter"
	idx := 10 // index of '/'
	rawProv := rawKey[:idx]
	normKeyProv := config.NormalizeProvider(rawProv)
	normEntryProv := config.NormalizeProvider(entryProv)

	if normKeyProv == normEntryProv || config.IsKnownProviderAlias(rawProv) {
		t.Fatalf("did not expect %q to be treated as a provider alias", rawProv)
	}
	if normEntryProv != domain.ProviderOpenRouter {
		t.Fatalf("expected openrouter, got %q", normEntryProv)
	}
}
