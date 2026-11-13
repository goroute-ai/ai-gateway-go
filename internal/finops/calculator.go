package finops

import (
	"fmt"
	"strings"

	"github.com/goroute-ai/ai-gateway-go/internal/domain"
)

const maxInt64 = int64(^uint64(0) >> 1)

func addProductSaturated(sum, amount, rate int64) (int64, bool) {
	if amount <= 0 || rate <= 0 {
		return sum, false
	}
	if amount > (maxInt64-sum)/rate {
		return maxInt64, true
	}
	return sum + amount*rate, false
}

func ceilDivPositive(numerator, denominator int64) int64 {
	if numerator <= 0 || denominator <= 0 {
		return 0
	}
	q := numerator / denominator
	if numerator%denominator != 0 {
		q++
	}
	return q
}

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
	if gm.CacheWriteCostMicrosPer1M > inputRate {
		inputRate = gm.CacheWriteCostMicrosPer1M
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

	promptTokens := int64(usage.PromptTokens)
	if promptTokens < 0 {
		promptTokens = 0
	}
	cachedPromptTokens := int64(usage.CachedPromptTokens)
	if cachedPromptTokens < 0 {
		cachedPromptTokens = 0
	}
	if cachedPromptTokens > promptTokens {
		cachedPromptTokens = promptTokens
	}
	nonCachedPrompt := promptTokens - cachedPromptTokens
	completionTokens := int64(usage.CompletionTokens)
	if completionTokens < 0 {
		completionTokens = 0
	}
	reasoningTokens := int64(usage.ReasoningTokens)
	if reasoningTokens < 0 {
		reasoningTokens = 0
	}
	if reasoningTokens > completionTokens {
		reasoningTokens = completionTokens
	}
	regularCompletion := completionTokens - reasoningTokens

	reasoningRate := gm.ReasoningCostMicrosPer1M
	if reasoningRate == 0 {
		reasoningRate = gm.OutputCostMicrosPer1M
	}

	cacheWriteRate := gm.CacheWriteCostMicrosPer1M
	if cacheWriteRate == 0 {
		cacheWriteRate = gm.InputCostMicrosPer1M
	}

	// Numerator is in (tokens * micro-dollars per 1M tokens) = pico-dollars (1e-12 USD)
	numerator := int64(0)
	overflow := false
	for _, charge := range [][2]int64{
		{nonCachedPrompt, gm.InputCostMicrosPer1M},
		{cachedPromptTokens, gm.CachedInputCostMicrosPer1M},
		{maxInt64SafeUsage(usage.CacheCreationTokens), cacheWriteRate},
		{regularCompletion, gm.OutputCostMicrosPer1M},
		{reasoningTokens, reasoningRate},
	} {
		var itemOverflow bool
		numerator, itemOverflow = addProductSaturated(numerator, charge[0], charge[1])
		overflow = overflow || itemOverflow
	}
	if overflow {
		return maxInt64
	}
	if numerator <= 0 {
		return 0
	}

	// Ceiling division by 1,000,000 so non-zero token usage on paid models never rounds down to 0 micro-dollars
	return ceilDivPositive(numerator, 1_000_000)
}

func maxInt64SafeUsage(value int) int64 {
	if value <= 0 {
		return 0
	}
	return int64(value)
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
	amount := int64(searchUnits)
	if amount > maxInt64/rate {
		return maxInt64
	}
	return amount * rate
}

// CalculateImageCostMicros calculates image cost strictly according to model, resolution, and quality.
func CalculateImageCostMicros(gm *domain.GlobalModel, quality string, size string, count int) int64 {
	if gm == nil || count <= 0 {
		return 0
	}
	unitCost := imageCostPerUnit(gm, quality, size)
	if unitCost <= 0 {
		return 0
	}
	if int64(count) > int64(^uint64(0)>>1)/unitCost {
		return int64(^uint64(0) >> 1)
	}
	return unitCost * int64(count)
}

func imageCostPerUnit(gm *domain.GlobalModel, quality, size string) int64 {
	if gm == nil {
		return 0
	}
	quality = strings.ToLower(strings.TrimSpace(quality))
	if quality == "" {
		quality = "standard"
	}
	// Check if detailed modality pricing JSON has an exact model/quality/size rate
	if len(gm.ModalityPricingJSON) > 0 {
		key := fmt.Sprintf("%s_%s", quality, strings.ToLower(strings.TrimSpace(size)))
		if v, ok := gm.ModalityPricingJSON[key]; ok {
			switch val := v.(type) {
			case float64:
				if val > 0 && val < float64(int64(^uint64(0)>>1)) {
					return int64(val)
				}
			case int64:
				if val > 0 {
					return val
				}
			}
		}
		for key := range gm.ModalityPricingJSON {
			if strings.HasPrefix(key, "standard_") || strings.HasPrefix(key, "high_") || strings.HasPrefix(key, "medium_") || strings.HasPrefix(key, "low_") || strings.HasPrefix(key, "hd_") || strings.HasPrefix(key, "xhigh_") || strings.HasPrefix(key, "max_") {
				// Variant pricing is known, but there is no exact quote for this
				// requested quality/size. Do not reuse a different variant's rate.
				return 0
			}
		}
	}

	base := gm.ImageCostMicrosBase
	if strings.EqualFold(quality, "hd") && gm.ImageCostMicrosHD > 0 {
		base = gm.ImageCostMicrosHD
	}
	return base
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
	if durationMs > (maxInt64-999)/ratePerSec {
		return maxInt64
	}
	return ceilDivPositive(durationMs*ratePerSec, 1000)
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
	amount := int64(charCount)
	if amount > (maxInt64-999)/ratePer1K {
		return maxInt64
	}
	return ceilDivPositive(amount*ratePer1K, 1000)
}

// EstimateRerankCostUpperBound computes a deterministic pre-dispatch budget bound for rerank requests.
// Returns false when pricing is unverified or the rerank rate is non-positive.
func EstimateRerankCostUpperBound(gm *domain.GlobalModel, searchUnits int) (int64, bool) {
	status := domain.ResolvePricingStatus(gm)
	if gm == nil || status == domain.PricingStatusUnknown || status == domain.PricingStatusUnrecorded {
		return 0, false
	}
	if searchUnits <= 0 || gm.RerankCostMicrosPerSearchUnit <= 0 {
		return 0, false
	}
	if int64(searchUnits) > (int64(^uint64(0)>>1))/gm.RerankCostMicrosPerSearchUnit {
		return 0, false
	}
	return int64(searchUnits) * gm.RerankCostMicrosPerSearchUnit, true
}

// EstimateImageCostUpperBound computes a deterministic pre-dispatch budget bound for image generation.
// Returns false when pricing is unverified or no positive image rate applies.
func EstimateImageCostUpperBound(gm *domain.GlobalModel, quality, size string, count int) (int64, bool) {
	status := domain.ResolvePricingStatus(gm)
	if gm == nil || status == domain.PricingStatusUnknown || status == domain.PricingStatusUnrecorded {
		return 0, false
	}
	if count <= 0 {
		return 0, false
	}
	unitCost := imageCostPerUnit(gm, quality, size)
	if unitCost <= 0 || int64(count) > int64(^uint64(0)>>1)/unitCost {
		return 0, false
	}
	return unitCost * int64(count), true
}

// EstimateAudioTTSCostUpperBound computes a deterministic pre-dispatch budget bound for TTS requests.
// Returns false when pricing is unverified or the TTS rate is non-positive.
func EstimateAudioTTSCostUpperBound(gm *domain.GlobalModel, charCount int) (int64, bool) {
	status := domain.ResolvePricingStatus(gm)
	if gm == nil || status == domain.PricingStatusUnknown || status == domain.PricingStatusUnrecorded {
		return 0, false
	}
	if charCount <= 0 || gm.AudioTTSCostMicrosPer1KChars <= 0 {
		return 0, false
	}
	return CalculateAudioTTSCostMicros(gm, charCount), true
}
