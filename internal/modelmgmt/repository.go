package modelmgmt

import (
	"fmt"
	"strings"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/domain"
)

// EnrichDiscoveredModel populates capability flags, context window sizes, and default micro-dollar pricing
// for models discovered automatically from OpenAI, Anthropic, Gemini, Mistral, and Ollama.
func EnrichDiscoveredModel(dm domain.DiscoveredModel, autoApprove bool) *domain.GlobalModel {
	now := time.Now().UTC()
	status := domain.ModelStatusDiscovered
	if autoApprove {
		status = domain.ModelStatusActive
	}

	gm := &domain.GlobalModel{
		ID:                fmt.Sprintf("%s/%s", dm.Provider, dm.ModelName),
		Provider:          dm.Provider,
		ModelName:         dm.ModelName,
		DisplayName:       dm.DisplayName,
		MaxInputTokens:    128000,
		MaxOutputTokens:   16384,
		SupportsStreaming: true,
		SupportsTools:     true,
		LifecycleStatus:   status,
		DiscoveredAt:      now,
		UpdatedAt:         now,
	}
	if gm.DisplayName == "" {
		gm.DisplayName = dm.ModelName
	}

	lower := strings.ToLower(dm.ModelName)

	// Capability heuristics
	if strings.Contains(lower, "embed") {
		gm.SupportsEmbeddings = true
		gm.SupportsStreaming = false
		gm.SupportsTools = false
		gm.MaxInputTokens = 8192
		gm.MaxOutputTokens = 1536
	}
	if strings.Contains(lower, "gpt-4") || strings.Contains(lower, "claude") || strings.Contains(lower, "gemini") || strings.Contains(lower, "pixtral") {
		gm.SupportsVision = true
	}
	if strings.HasPrefix(lower, "o1") || strings.HasPrefix(lower, "o3") || strings.HasPrefix(lower, "o4") ||
		strings.Contains(lower, "sonnet-4") || strings.Contains(lower, "opus-4") ||
		strings.Contains(lower, "2.5-pro") || strings.Contains(lower, "deepseek-r1") {
		gm.SupportsReasoning = true
	}

	// Default pricing table (micro-USD per 1M tokens)
	switch dm.Provider {
	case domain.ProviderOpenAI:
		switch {
		case strings.Contains(lower, "mini"):
			gm.InputCostMicrosPer1M = 400000
			gm.OutputCostMicrosPer1M = 1600000
			gm.CachedInputCostMicrosPer1M = 100000
		case strings.HasPrefix(lower, "o3") || strings.HasPrefix(lower, "o1"):
			gm.InputCostMicrosPer1M = 1100000
			gm.OutputCostMicrosPer1M = 4400000
			gm.ReasoningCostMicrosPer1M = 4400000
		case strings.Contains(lower, "embed"):
			gm.InputCostMicrosPer1M = 20000
		default:
			gm.InputCostMicrosPer1M = 2000000
			gm.OutputCostMicrosPer1M = 8000000
			gm.CachedInputCostMicrosPer1M = 500000
		}
	case domain.ProviderAnthropic:
		if strings.Contains(lower, "haiku") {
			gm.InputCostMicrosPer1M = 800000
			gm.OutputCostMicrosPer1M = 4000000
		} else {
			gm.InputCostMicrosPer1M = 3000000
			gm.OutputCostMicrosPer1M = 15000000
			gm.CachedInputCostMicrosPer1M = 300000
		}
	case domain.ProviderGemini:
		gm.MaxInputTokens = 1048576
		if strings.Contains(lower, "flash") {
			gm.InputCostMicrosPer1M = 150000
			gm.OutputCostMicrosPer1M = 600000
		} else if strings.Contains(lower, "embed") {
			gm.InputCostMicrosPer1M = 10000
		} else {
			gm.InputCostMicrosPer1M = 1250000
			gm.OutputCostMicrosPer1M = 10000000
		}
	case domain.ProviderMistral:
		if strings.Contains(lower, "embed") {
			gm.InputCostMicrosPer1M = 100000
		} else {
			gm.InputCostMicrosPer1M = 2000000
			gm.OutputCostMicrosPer1M = 6000000
		}
	case domain.ProviderOllama:
		gm.InputCostMicrosPer1M = 0
		gm.OutputCostMicrosPer1M = 0
	}

	return gm
}
