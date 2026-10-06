package finops

import (
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
)

// CalculateCostMicros computes the exact financial cost in micro-dollars ($1.00 = 1,000,000 micro-dollars)
// using 64-bit integer arithmetic to avoid floating-point rounding drift.
func CalculateCostMicros(gm *domain.GlobalModel, usage domain.TokenUsage) int64 {
	if gm == nil {
		return 0
	}

	nonCachedPrompt := usage.PromptTokens - usage.CachedPromptTokens
	if nonCachedPrompt < 0 {
		nonCachedPrompt = 0
	}

	regularCompletion := usage.CompletionTokens - usage.ReasoningTokens
	if regularCompletion < 0 {
		regularCompletion = 0
	}

	reasoningRate := gm.ReasoningCostMicrosPer1M
	if reasoningRate == 0 {
		reasoningRate = gm.OutputCostMicrosPer1M
	}

	// Numerator is in (tokens * micro-dollars per 1M tokens) = pico-dollars (1e-12 USD)
	numerator := int64(nonCachedPrompt)*gm.InputCostMicrosPer1M +
		int64(usage.CachedPromptTokens)*gm.CachedInputCostMicrosPer1M +
		int64(regularCompletion)*gm.OutputCostMicrosPer1M +
		int64(usage.ReasoningTokens)*reasoningRate

	if numerator <= 0 {
		return 0
	}

	// Ceiling division by 1,000,000 so non-zero token usage on paid models never rounds down to 0 micro-dollars
	return (numerator + 999_999) / 1_000_000
}
