package main

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
)

type seedModelEntry struct {
	MaxTokens                    int     `json:"max_tokens"`
	MaxInputTokens               int     `json:"max_input_tokens"`
	MaxOutputTokens              int     `json:"max_output_tokens"`
	InputCostPerToken            float64 `json:"input_cost_per_token"`
	OutputCostPerToken           float64 `json:"output_cost_per_token"`
	CacheReadInputTokenCost      float64 `json:"cache_read_input_token_cost"`
	Provider                     string  `json:"-"`
	Mode                         string  `json:"mode"`
	SupportsFunctionCalling      *bool   `json:"supports_function_calling"`
	SupportsParallelFunctionCall *bool   `json:"supports_parallel_function_calling"`
	SupportsVision               *bool   `json:"supports_vision"`
	SupportsReasoning            *bool   `json:"supports_reasoning"`
	SupportsPromptCaching        *bool   `json:"supports_prompt_caching"`
	SupportsResponseSchema       *bool   `json:"supports_response_schema"`
	Source                       string  `json:"source"`
	DeprecationDate              string  `json:"deprecation_date"`
}

func (e *seedModelEntry) UnmarshalJSON(b []byte) error {
	type alias seedModelEntry
	var a alias
	if err := json.Unmarshal(b, &a); err != nil {
		return err
	}
	*e = seedModelEntry(a)

	var rawFields map[string]any
	if err := json.Unmarshal(b, &rawFields); err == nil {
		for k, v := range rawFields {
			if strings.HasSuffix(k, "_provider") || k == "provider" {
				if s, ok := v.(string); ok && s != "" {
					e.Provider = s
					break
				}
			}
		}
	}
	return nil
}

func main() {
	sourcePath := flag.String("source", "model_prices_and_context_window.json", "Path to source model definitions JSON")
	outPath := flag.String("out", "internal/catalog/catalog.json.gz", "Path to output catalog.json.gz")
	flag.Parse()

	data, err := os.ReadFile(*sourcePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to read source file: %v\n", err)
		os.Exit(1)
	}

	var rawMap map[string]json.RawMessage
	if err := json.Unmarshal(data, &rawMap); err != nil {
		fmt.Fprintf(os.Stderr, "failed to parse source JSON: %v\n", err)
		os.Exit(1)
	}

	catalogModels := make(map[string]*domain.GlobalModel)
	now := time.Now().UTC()

	for rawKey, rawVal := range rawMap {
		if rawKey == "sample_spec" || strings.HasPrefix(rawKey, "1024-x-1024") || strings.HasPrefix(rawKey, "512-x-512") {
			continue
		}
		var entry seedModelEntry
		if err := json.Unmarshal(rawVal, &entry); err != nil {
			continue
		}

		var prov domain.ProviderType
		var bareModel string
		var globalID string

		qualityOrDimPrefixes := []string{"1024-x-", "512-x-", "1536-x-", "high/", "low/", "medium/", "standard/", "xhigh/", "max/"}
		isQualityOrDim := false
		for _, pfx := range qualityOrDimPrefixes {
			if strings.HasPrefix(rawKey, pfx) {
				isQualityOrDim = true
				break
			}
		}

		if isQualityOrDim && entry.Provider != "" {
			prov = config.NormalizeProvider(entry.Provider)
			bareModel = rawKey
		} else if idx := strings.IndexByte(rawKey, '/'); idx > 0 {
			rawProv := rawKey[:idx]
			bareModel = rawKey[idx+1:]
			prov = config.NormalizeProvider(rawProv)
		} else if entry.Provider != "" {
			prov = config.NormalizeProvider(entry.Provider)
			bareModel = rawKey
		} else {
			prov, bareModel, _ = config.ParseProviderModel(rawKey)
		}

		if prov == "" {
			continue
		}
		if bareModel == "" {
			bareModel = rawKey
		}
		globalID = fmt.Sprintf("%s/%s", prov, bareModel)

		maxIn := entry.MaxInputTokens
		if maxIn <= 0 {
			maxIn = entry.MaxTokens
		}
		if maxIn <= 0 {
			maxIn = 8192
		}
		maxOut := entry.MaxOutputTokens
		if maxOut <= 0 {
			maxOut = 4096
		}

		inCostMicros := int64(math.Round(entry.InputCostPerToken * 1e12))
		outCostMicros := int64(math.Round(entry.OutputCostPerToken * 1e12))
		cachedCostMicros := int64(math.Round(entry.CacheReadInputTokenCost * 1e12))

		pricingStatus := domain.PricingStatusUnknown
		if inCostMicros == 0 && outCostMicros == 0 {
			pricingStatus = domain.PricingStatusUnrecorded
		}

		caps := domain.ModelCapabilities{
			Tools:             domain.CapabilityUnknown,
			Streaming:         domain.CapabilitySupported,
			Vision:            domain.CapabilityUnknown,
			Reasoning:         domain.CapabilityUnknown,
			StructuredOutputs: domain.CapabilityUnknown,
			Embeddings:        domain.CapabilityUnknown,
		}
		if entry.SupportsFunctionCalling != nil {
			if *entry.SupportsFunctionCalling {
				caps.Tools = domain.CapabilitySupported
			} else {
				caps.Tools = domain.CapabilityUnsupported
			}
		}
		if entry.SupportsParallelFunctionCall != nil && *entry.SupportsParallelFunctionCall {
			caps.Tools = domain.CapabilitySupported
		}
		if entry.SupportsVision != nil {
			if *entry.SupportsVision {
				caps.Vision = domain.CapabilitySupported
			} else {
				caps.Vision = domain.CapabilityUnsupported
			}
		}
		if entry.SupportsReasoning != nil {
			if *entry.SupportsReasoning {
				caps.Reasoning = domain.CapabilitySupported
			} else {
				caps.Reasoning = domain.CapabilityUnsupported
			}
		}
		if entry.SupportsResponseSchema != nil {
			if *entry.SupportsResponseSchema {
				caps.StructuredOutputs = domain.CapabilitySupported
			} else {
				caps.StructuredOutputs = domain.CapabilityUnsupported
			}
		}
		if entry.Mode == "embedding" {
			caps.Embeddings = domain.CapabilitySupported
		}

		supportsInference := entry.Mode == "chat" || entry.Mode == "completion" || entry.Mode == "embedding" || entry.Mode == ""

		gm := &domain.GlobalModel{
			ID:                         globalID,
			Provider:                   prov,
			ModelName:                  bareModel,
			DisplayName:                fmt.Sprintf("%s (%s)", bareModel, strings.ToUpper(string(prov))),
			MaxInputTokens:             maxIn,
			MaxOutputTokens:            maxOut,
			Capabilities:               caps,
			SupportsStreaming:          caps.Streaming == domain.CapabilitySupported,
			SupportsTools:              caps.Tools == domain.CapabilitySupported,
			SupportsVision:             caps.Vision == domain.CapabilitySupported,
			SupportsReasoning:          caps.Reasoning == domain.CapabilitySupported,
			SupportsEmbeddings:         caps.Embeddings == domain.CapabilitySupported,
			SupportsInference:          supportsInference,
			InputCostMicrosPer1M:       inCostMicros,
			OutputCostMicrosPer1M:      outCostMicros,
			CachedInputCostMicrosPer1M: cachedCostMicros,
			PricingVersion:             1,
			PricingStatus:              pricingStatus,
			PricingProvenanceSource:    "global-model-catalog-v1.0",
			PricingEffectiveDate:       "2025-11-01",
			LifecycleStatus:            domain.ModelStatusActive,
			DiscoveredAt:               now,
			UpdatedAt:                  now,
		}

		if existing, exists := catalogModels[globalID]; exists {
			if existing.InputCostMicrosPer1M == 0 && inCostMicros > 0 {
				catalogModels[globalID] = gm
			}
			continue
		}
		catalogModels[globalID] = gm
	}

	fmt.Printf("Normalized %d models from source.\n", len(catalogModels))

	marshaled, err := json.Marshal(catalogModels)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to marshal catalog JSON: %v\n", err)
		os.Exit(1)
	}

	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	if _, err := gw.Write(marshaled); err != nil {
		fmt.Fprintf(os.Stderr, "failed to gzip catalog: %v\n", err)
		os.Exit(1)
	}
	if err := gw.Close(); err != nil {
		fmt.Fprintf(os.Stderr, "failed to close gzip: %v\n", err)
		os.Exit(1)
	}

	if err := os.MkdirAll(filepath.Dir(*outPath), 0755); err != nil {
		fmt.Fprintf(os.Stderr, "failed to create out dir: %v\n", err)
		os.Exit(1)
	}

	if err := os.WriteFile(*outPath, buf.Bytes(), 0644); err != nil {
		fmt.Fprintf(os.Stderr, "failed to write output file: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Successfully generated %s (%d bytes, compressed from %d bytes raw).\n", *outPath, buf.Len(), len(marshaled))
}
