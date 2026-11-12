package finops

import (
	"fmt"
	"strings"

	"github.com/goroute-ai/ai-gateway-go/internal/domain"
)

// EstimateTokenCostUpperBound prices a token request using the higher input,
// cached-input, output, and reasoning rates. It returns false when pricing is
// unverified or a requested token dimension cannot be priced safely.
func EstimateTokenCostUpperBound(gm *domain.GlobalModel, inputTokens, outputTokens int) (int64, bool) {
	status := domain.ResolvePricingStatus(gm)
	if gm == nil || status == domain.PricingStatusUnknown || status == domain.PricingStatusUnrecorded {
		return 0, false
	}
	if inputTokens < 0 || outputTokens < 0 {
		return 0, false
	}
	inputRate := gm.InputCostMicrosPer1M
	if gm.CachedInputCostMicrosPer1M > inputRate {
		inputRate = gm.CachedInputCostMicrosPer1M
	}
	outputRate := gm.OutputCostMicrosPer1M
	if gm.ReasoningCostMicrosPer1M > outputRate {
		outputRate = gm.ReasoningCostMicrosPer1M
	}
	if inputTokens > 0 && inputRate <= 0 || outputTokens > 0 && outputRate <= 0 {
		return 0, false
	}
	// Bound overflow before multiplying; rates and token counts are non-negative.
	if inputTokens > 0 && int64(inputTokens) > (int64(^uint64(0)>>1)-999_999)/inputRate {
		return 0, false
	}
	inputNumerator := int64(inputTokens) * inputRate
	if outputTokens > 0 && int64(outputTokens) > (int64(^uint64(0)>>1)-inputNumerator-999_999)/outputRate {
		return 0, false
	}
	numerator := inputNumerator + int64(outputTokens)*outputRate
	return (numerator + 999_999) / 1_000_000, true
}

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

// CalculateRerankCostMicros calculates rerank cost using explicit per-search-unit integer rate.
func CalculateRerankCostMicros(gm *domain.GlobalModel, searchUnits int) int64 {
	if gm == nil || searchUnits <= 0 {
		return 0
	}
	rate := gm.RerankCostMicrosPerSearchUnit
	if rate <= 0 {
		return 0
	}
	return int64(searchUnits) * rate
}

// CalculateImageCostMicros calculates image cost strictly according to model, resolution, and quality.
func CalculateImageCostMicros(gm *domain.GlobalModel, quality string, size string, count int) int64 {
	if gm == nil || count <= 0 {
		return 0
	}
	// Check if detailed modality pricing JSON has an exact model/quality/size rate
	if len(gm.ModalityPricingJSON) > 0 {
		key := fmt.Sprintf("%s_%s", strings.ToLower(quality), strings.ToLower(size))
		if v, ok := gm.ModalityPricingJSON[key]; ok {
			switch val := v.(type) {
			case float64:
				if int64(val) > 0 {
					return int64(val) * int64(count)
				}
			case int64:
				if val > 0 {
					return val * int64(count)
				}
			}
		}
	}

	base := gm.ImageCostMicrosBase
	if strings.EqualFold(quality, "hd") && gm.ImageCostMicrosHD > 0 {
		base = gm.ImageCostMicrosHD
	}
	return base * int64(count)
}

// CalculateAudioSTTCostMicros calculates STT cost based on duration in integer milliseconds.
func CalculateAudioSTTCostMicros(gm *domain.GlobalModel, durationMs int64) int64 {
	if gm == nil || durationMs <= 0 {
		return 0
	}
	ratePerSec := gm.AudioSTTCostMicrosPerSecond
	if ratePerSec <= 0 {
		return 0
	}
	// Integer ceiling division: (durationMs * ratePerSec + 999) / 1000
	return (durationMs*ratePerSec + 999) / 1000
}

// CalculateAudioTTSCostMicros calculates TTS cost based on character count.
func CalculateAudioTTSCostMicros(gm *domain.GlobalModel, charCount int) int64 {
	if gm == nil || charCount <= 0 {
		return 0
	}
	ratePer1K := gm.AudioTTSCostMicrosPer1KChars
	if ratePer1K <= 0 {
		return 0
	}
	// Integer ceiling division by 1,000: (chars * ratePer1K + 999) / 1000
	return (int64(charCount)*ratePer1K + 999) / 1000
}
