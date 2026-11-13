package storage

import (
	"context"
	"testing"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/domain"
)

func TestMemoryRepository_GlobalModelModalityAndOperationsRoundTrip(t *testing.T) {
	repo := NewMemoryRepository()
	ctx := context.Background()
	depDate := time.Date(2027, 6, 1, 0, 0, 0, 0, time.UTC)

	gm := &domain.GlobalModel{
		ID:                            "openai/gpt-test-omni",
		Provider:                      domain.ProviderOpenAI,
		ModelName:                     "gpt-test-omni",
		DisplayName:                   "GPT Test Omni",
		MaxInputTokens:                128000,
		MaxOutputTokens:               16384,
		SupportedOperations:           []domain.OperationType{domain.OperationChat, domain.OperationResponses, domain.OperationImageGeneration},
		SupportsStreaming:             true,
		SupportsTools:                 true,
		SupportsInference:             true,
		InputCostMicrosPer1M:          2500000,
		OutputCostMicrosPer1M:         10000000,
		CachedInputCostMicrosPer1M:    1250000,
		CacheWriteCostMicrosPer1M:     3125000,
		ReasoningCostMicrosPer1M:      15000000,
		RerankCostMicrosPerSearchUnit: 2000,
		ImageCostMicrosBase:           40000,
		ImageCostMicrosHD:             80000,
		AudioSTTCostMicrosPerSecond:   100,
		AudioTTSCostMicrosPer1KChars:  15000,
		ModalityPricingJSON:           map[string]any{"hd_1024x1024": float64(80000)},
		PricingStatus:                 domain.PricingStatusCustom,
		PricingProvenanceSource:       "operator-verified",
		LifecycleStatus:               domain.ModelStatusActive,
		DeprecationDate:               &depDate,
	}

	if err := repo.UpsertGlobalModel(ctx, gm); err != nil {
		t.Fatalf("UpsertGlobalModel failed: %v", err)
	}

	// Mutate caller's slice/map after upsert to ensure repository deep-copied them.
	gm.SupportedOperations[0] = domain.OperationRerank
	gm.ModalityPricingJSON["hd_1024x1024"] = float64(999)

	got, err := repo.GetGlobalModel(ctx, "openai/gpt-test-omni")
	if err != nil {
		t.Fatalf("GetGlobalModel failed: %v", err)
	}
	if got.CacheWriteCostMicrosPer1M != 3125000 {
		t.Errorf("CacheWriteCostMicrosPer1M = %d, want 3125000", got.CacheWriteCostMicrosPer1M)
	}
	if got.RerankCostMicrosPerSearchUnit != 2000 || got.ImageCostMicrosBase != 40000 || got.ImageCostMicrosHD != 80000 {
		t.Errorf("unexpected modality rates: %+v", got)
	}
	if got.AudioSTTCostMicrosPerSecond != 100 || got.AudioTTSCostMicrosPer1KChars != 15000 {
		t.Errorf("unexpected audio rates: stt=%d tts=%d", got.AudioSTTCostMicrosPerSecond, got.AudioTTSCostMicrosPer1KChars)
	}
	if got.DeprecationDate == nil || !got.DeprecationDate.Equal(depDate) {
		t.Errorf("DeprecationDate = %v, want %v", got.DeprecationDate, depDate)
	}
	if !got.SupportsOperation(domain.OperationChat) || !got.SupportsOperation(domain.OperationImageGeneration) || got.SupportsOperation(domain.OperationRerank) {
		t.Errorf("unexpected SupportedOperations: %v", got.SupportedOperations)
	}
	if v, ok := got.ModalityPricingJSON["hd_1024x1024"].(float64); !ok || v != 80000 {
		t.Errorf("ModalityPricingJSON mutated or missing: %v", got.ModalityPricingJSON)
	}

	list, err := repo.ListGlobalModels(ctx)
	if err != nil {
		t.Fatalf("ListGlobalModels failed: %v", err)
	}
	found := false
	for _, m := range list {
		if m.ID == "openai/gpt-test-omni" {
			found = true
			if m.CacheWriteCostMicrosPer1M != 3125000 {
				t.Errorf("ListGlobalModels CacheWriteCostMicrosPer1M = %d, want 3125000", m.CacheWriteCostMicrosPer1M)
			}
		}
	}
	if !found {
		t.Errorf("expected openai/gpt-test-omni in ListGlobalModels")
	}
}
