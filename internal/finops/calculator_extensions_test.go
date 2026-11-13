package finops

import (
	"testing"

	"github.com/goroute-ai/ai-gateway-go/internal/domain"
)

func TestCalculateCostMicros_CacheCreationTokens(t *testing.T) {
	gm := &domain.GlobalModel{
		InputCostMicrosPer1M:       3_000_000, // $3.00 / 1M
		CachedInputCostMicrosPer1M: 300_000,   // $0.30 / 1M
		CacheWriteCostMicrosPer1M:  3_750_000, // $3.75 / 1M
		OutputCostMicrosPer1M:      15_000_000,
	}
	usage := domain.TokenUsage{
		PromptTokens:        1000, // 800 non-cached + 200 cached read
		CachedPromptTokens:  200,
		CacheCreationTokens: 400,
		CompletionTokens:    100,
	}
	// Expected pico-dollars:
	// 800 * 3_000_000 = 2_400_000_000
	// 200 * 300_000   =    60_000_000
	// 400 * 3_750_000 = 1_500_000_000
	// 100 * 15_000_000 = 1_500_000_000
	// Total = 5_460_000_000 -> 5460 micro-dollars
	got := CalculateCostMicros(gm, usage)
	if got != 5460 {
		t.Fatalf("CalculateCostMicros = %d, want 5460", got)
	}
}

func TestModalityBudgetUpperBounds_FailClosedOnUnknown(t *testing.T) {
	unverified := &domain.GlobalModel{
		PricingStatus:                 domain.PricingStatusUnknown,
		RerankCostMicrosPerSearchUnit: 2000,
		ImageCostMicrosBase:           40000,
		AudioTTSCostMicrosPer1KChars:  15000,
	}
	if _, ok := EstimateRerankCostUpperBound(unverified, 1); ok {
		t.Errorf("expected EstimateRerankCostUpperBound to fail closed on PricingStatusUnknown")
	}
	if _, ok := EstimateImageCostUpperBound(unverified, "standard", "1024x1024", 1); ok {
		t.Errorf("expected EstimateImageCostUpperBound to fail closed on PricingStatusUnknown")
	}
	if _, ok := EstimateAudioTTSCostUpperBound(unverified, 500); ok {
		t.Errorf("expected EstimateAudioTTSCostUpperBound to fail closed on PricingStatusUnknown")
	}

	verified := &domain.GlobalModel{
		PricingStatus:                 domain.PricingStatusVerified,
		RerankCostMicrosPerSearchUnit: 2000,
		ImageCostMicrosBase:           40000,
		ImageCostMicrosHD:             80000,
		AudioTTSCostMicrosPer1KChars:  15000,
	}
	if cost, ok := EstimateRerankCostUpperBound(verified, 2); !ok || cost != 4000 {
		t.Errorf("EstimateRerankCostUpperBound = (%d, %v), want (4000, true)", cost, ok)
	}
	if cost, ok := EstimateImageCostUpperBound(verified, "hd", "1024x1024", 2); !ok || cost != 160000 {
		t.Errorf("EstimateImageCostUpperBound = (%d, %v), want (160000, true)", cost, ok)
	}
	if cost, ok := EstimateAudioTTSCostUpperBound(verified, 1000); !ok || cost != 15000 {
		t.Errorf("EstimateAudioTTSCostUpperBound = (%d, %v), want (15000, true)", cost, ok)
	}
}

func TestImageBudgetUpperBoundRejectsOverflow(t *testing.T) {
	gm := &domain.GlobalModel{
		PricingStatus:       domain.PricingStatusVerified,
		ImageCostMicrosBase: int64(^uint64(0) >> 1),
	}
	if _, ok := EstimateImageCostUpperBound(gm, "standard", "1024x1024", 2); ok {
		t.Fatal("expected image budget estimator to reject an overflowing amount")
	}
	if got := CalculateImageCostMicros(gm, "standard", "1024x1024", 2); got != int64(^uint64(0)>>1) {
		t.Fatalf("overflowed image cost = %d, want saturated MaxInt64", got)
	}
}

func TestImageBudgetUpperBoundRequiresExactVariantWhenVariantsExist(t *testing.T) {
	gm := &domain.GlobalModel{
		PricingStatus: domain.PricingStatusVerified,
		ModalityPricingJSON: map[string]any{
			"standard_1024x1024": int64(9000),
			"high_1024x1024":     int64(45000),
		},
		ImageCostMicrosBase: 9000,
	}
	if cost, ok := EstimateImageCostUpperBound(gm, "", "1024x1024", 1); !ok || cost != 9000 {
		t.Fatalf("default quality estimate = (%d, %v), want (9000, true)", cost, ok)
	}
	if _, ok := EstimateImageCostUpperBound(gm, "high", "1024x1536", 1); ok {
		t.Fatal("expected estimator to reject a size without an exact variant price")
	}
}

func TestSettlementCalculatorsSaturateOnOverflow(t *testing.T) {
	gm := &domain.GlobalModel{
		InputCostMicrosPer1M:          maxInt64,
		OutputCostMicrosPer1M:         maxInt64,
		RerankCostMicrosPerSearchUnit: maxInt64,
		AudioSTTCostMicrosPerSecond:   maxInt64,
		AudioTTSCostMicrosPer1KChars:  maxInt64,
	}
	if got := CalculateCostMicros(gm, domain.TokenUsage{PromptTokens: 2}); got != maxInt64 {
		t.Fatalf("token cost = %d, want saturated MaxInt64", got)
	}
	if got := CalculateRerankCostMicros(gm, 2); got != maxInt64 {
		t.Fatalf("rerank cost = %d, want saturated MaxInt64", got)
	}
	if got := CalculateAudioSTTCostMicros(gm, maxInt64); got != maxInt64 {
		t.Fatalf("STT cost = %d, want saturated MaxInt64", got)
	}
	if got := CalculateAudioTTSCostMicros(gm, int(^uint(0)>>1)); got != maxInt64 {
		t.Fatalf("TTS cost = %d, want saturated MaxInt64", got)
	}
}
